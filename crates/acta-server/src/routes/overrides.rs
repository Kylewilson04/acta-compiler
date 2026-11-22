use std::collections::{BTreeMap, BTreeSet};

use acta_crypto::{
    compute_logical_claim_group_key, compute_override_client_intent_hash, to_canonical_bytes,
    verify_client_content_signature,
};
use acta_policy::PolicyAction;
use acta_store::{
    claims_repo, evidence_repo,
    overrides_repo::{self, NewOverrideInput},
};
use acta_types::{
    validate_identifier, validate_justification, validate_scope, AttestOverrideRequest,
    AttestOverrideResponse, ClaimStatus, KnowledgeClaim, OverriddenClaimRef, OverrideAttestation,
    PolicyDecision, PolicyResultTag,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, VerifiedKeyInfo};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OverridesQueryParams {
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantOverridesResponse {
    pub tenant_id: String,
    pub active_scope_filter: Option<String>,
    pub count: usize,
    pub overrides: Vec<OverrideAttestation>,
}

fn value_type_tag(v: &Value) -> u8 {
    match v {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Object(_) => 5,
    }
}

fn same_typed_value(a: &KnowledgeClaim, b: &KnowledgeClaim) -> bool {
    if value_type_tag(&a.object_val) != value_type_tag(&b.object_val) {
        return false;
    }
    let ja = to_canonical_bytes(&a.object_val).unwrap_or_default();
    let jb = to_canonical_bytes(&b.object_val).unwrap_or_default();
    ja == jb
}

fn is_signature_mandatory_scope(scope: &str) -> bool {
    let lower = scope.trim().to_ascii_lowercase();
    lower == "regulated"
        || lower.starts_with("regulated/")
        || lower == "compliance"
        || lower.starts_with("compliance/")
        || lower == "governance"
        || lower.starts_with("governance/")
}

/// `POST /v1/overrides` -> Enforces Policy-Before-Attest (`Action::"attest"`), binds `adjudicator_id`
/// to the authenticated GitHub OAuth 2.1 principal (`<tenant>::oauth:<github_login>`) or verifies
/// a mandatory 64-byte Ed25519 `client_signature_hex` (`acta:override_client_sig:v1`) whenever a
/// custom/committee adjudicator or `regulated/*` / `compliance/*` / `governance/*` scope is targeted,
/// and atomically notarizes the `OverrideAttestation` + `EvidenceEntry`.
pub async fn handle_attest_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AttestOverrideRequest>,
) -> Result<(StatusCode, Json<AttestOverrideResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() || req.scope.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id and scope must be non-empty"));
    }

    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "attest_override")
        .await
        .map_err(ApiError::unauthorized)?;

    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    validate_justification(&req.justification)?;

    let raw_adjudicator = req
        .adjudicator_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (effective_actor, matches_caller_principal) = match raw_adjudicator {
        None => {
            let actor = match &caller_auth {
                VerifiedKeyInfo::TenantBound {
                    verified_principal: Some(gh),
                    ..
                } => format!("{}::oauth:{gh}", req.tenant_id),
                VerifiedKeyInfo::Master { .. } => format!("{}::master-admin", req.tenant_id),
                _ => format!("{}::session", req.tenant_id),
            };
            (actor, true)
        }
        Some(raw) => {
            validate_identifier("adjudicator_id", raw)?;
            let local_part = if let Some((adj_tenant, local)) = raw.split_once("::") {
                if adj_tenant != req.tenant_id {
                    let msg = format!(
                        "adjudicator_id '{raw}' belongs to tenant '{adj_tenant}', cannot attest in tenant '{}'",
                        req.tenant_id
                    );
                    let suffix = state
                        .append_refusal_audit_with_scope(
                            &headers,
                            Some(&req.tenant_id),
                            PolicyResultTag::Block,
                            "attest_override",
                            "adjudicator_tenant_mismatch",
                            Some(&req.scope),
                            &msg,
                        )
                        .await
                        .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                        .unwrap_or_default();
                    return Err(ApiError::forbidden(format!("{msg}{suffix}")));
                }
                local
            } else {
                raw
            };

            match &caller_auth {
                VerifiedKeyInfo::TenantBound {
                    verified_principal: Some(gh),
                    ..
                } => {
                    let local_lc = local_part.to_ascii_lowercase();
                    let oauth_tag = format!("oauth:{gh}");
                    if local_lc == *gh || local_lc == oauth_tag {
                        (format!("{}::oauth:{gh}", req.tenant_id), true)
                    } else {
                        (format!("{}::{local_part}", req.tenant_id), false)
                    }
                }
                VerifiedKeyInfo::Master { .. } => {
                    if local_part == "master-admin" {
                        (format!("{}::master-admin", req.tenant_id), true)
                    } else {
                        (format!("{}::{local_part}", req.tenant_id), false)
                    }
                }
                _ => {
                    if local_part == "session" {
                        (format!("{}::session", req.tenant_id), true)
                    } else {
                        (format!("{}::{local_part}", req.tenant_id), false)
                    }
                }
            }
        }
    };

    // 1. Cedar Policy-Before-Attest (`Action::"attest"`) runs BEFORE touching SQL!
    let (policy_decision, _perm_root) = state.policy_gate.evaluate_action(
        &req.tenant_id,
        &effective_actor,
        "attest_override",
        &req.scope,
        PolicyAction::Attest,
    );

    match policy_decision {
        PolicyDecision::Allow => {}
        PolicyDecision::Block { reason } => {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "attest_override",
                    "attest_policy_block",
                    Some(&req.scope),
                    &format!("attest denied on scope '{}': {reason}", req.scope),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy denied on override attestation for scope '{}': {reason}{suffix}",
                req.scope
            )));
        }
        PolicyDecision::Escalate { reason } => {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Escalate,
                    "attest_override",
                    "attest_policy_escalate",
                    Some(&req.scope),
                    &format!("attest escalated on restricted scope '{}': {reason}", req.scope),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy escalation required on override attestation for restricted scope '{}': {reason}{suffix}",
                req.scope
            )));
        }
    }

    // 2. Parse & enforce Ed25519 client signature (`acta:override_client_sig:v1`) / OAuth principal binding!
    let client_signature: Option<Vec<u8>> = match req
        .client_signature_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => {
            let bytes = hex::decode(s)
                .map_err(|e| ApiError::bad_request(format!("invalid client_signature_hex: {e}")))?;
            if bytes.len() != 64 {
                return Err(ApiError::bad_request(
                    "client_signature_hex must be 64 bytes (128 hex chars)",
                ));
            }
            Some(bytes)
        }
        None => None,
    };

    let client_public_key: Option<[u8; 32]> = match req
        .client_public_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => {
            let bytes = hex::decode(s).map_err(|e| {
                ApiError::bad_request(format!("invalid client_public_key_hex: {e}"))
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                ApiError::bad_request("client_public_key_hex must be 32 bytes (64 hex chars)")
            })?;
            Some(arr)
        }
        None => None,
    };

    if client_signature.is_some() != client_public_key.is_some() {
        return Err(ApiError::bad_request(
            "client_signature_hex and client_public_key_hex must both be provided together",
        ));
    }

    let adjudicator_auth_kind = match (&client_signature, &client_public_key) {
        (Some(sig_vec), Some(pk_arr)) => {
            let sig_arr: [u8; 64] = sig_vec.as_slice().try_into().unwrap();
            let intent_digest = compute_override_client_intent_hash(
                &req.tenant_id,
                &req.scope,
                req.winning_claim_id,
                &effective_actor,
                &req.justification,
            );
            if !verify_client_content_signature(pk_arr, &intent_digest, &sig_arr) {
                let msg = format!(
                    "invalid Ed25519 client_signature_hex for adjudicator_id '{effective_actor}' over acta:override_client_sig:v1"
                );
                let suffix = state
                    .append_refusal_audit_with_scope(
                        &headers,
                        Some(&req.tenant_id),
                        PolicyResultTag::Block,
                        "attest_override",
                        "invalid_adjudicator_client_signature",
                        Some(&req.scope),
                        &msg,
                    )
                    .await
                    .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                    .unwrap_or_default();
                return Err(ApiError::forbidden(format!("{msg}{suffix}")));
            }
            "ed25519_client_sig".to_string()
        }
        _ => {
            if is_signature_mandatory_scope(&req.scope) {
                let msg = format!(
                    "high-assurance scope '{}' requires an Ed25519 client_signature_hex + client_public_key_hex on override attestations",
                    req.scope
                );
                let suffix = state
                    .append_refusal_audit_with_scope(
                        &headers,
                        Some(&req.tenant_id),
                        PolicyResultTag::Block,
                        "attest_override",
                        "adjudicator_signature_required",
                        Some(&req.scope),
                        &msg,
                    )
                    .await
                    .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                    .unwrap_or_default();
                return Err(ApiError::forbidden(format!("{msg}{suffix}")));
            }

            if !matches_caller_principal {
                let msg = format!(
                    "custom adjudicator_id '{effective_actor}' requires a valid 64-byte Ed25519 client_signature_hex + client_public_key_hex over acta:override_client_sig:v1 (omit adjudicator_id to attest as your verified session identity)"
                );
                let suffix = state
                    .append_refusal_audit_with_scope(
                        &headers,
                        Some(&req.tenant_id),
                        PolicyResultTag::Block,
                        "attest_override",
                        "adjudicator_signature_required",
                        Some(&req.scope),
                        &msg,
                    )
                    .await
                    .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                    .unwrap_or_default();
                return Err(ApiError::forbidden(format!("{msg}{suffix}")));
            }

            match caller_auth {
                VerifiedKeyInfo::TenantBound {
                    verified_principal: Some(_),
                    ..
                } => "oauth_github_principal".to_string(),
                VerifiedKeyInfo::Master { .. } => "master_admin".to_string(),
                _ => "tenant_session".to_string(),
            }
        }
    };

    let now = Utc::now().trunc_subsecs(6);

    let source_bundle_hash: Option<[u8; 32]> = match req
        .source_bundle_hash_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_hex) => {
            let decoded = hex::decode(raw_hex).map_err(|e| {
                ApiError::bad_request(format!("invalid source_bundle_hash_hex: {e}"))
            })?;
            let arr: [u8; 32] = decoded.try_into().map_err(|_| {
                ApiError::bad_request("source_bundle_hash_hex must be 32 bytes (64 hex chars)")
            })?;
            let (orig_bundle, _) =
                evidence_repo::fetch_bundle_with_evidence_slice(&state.pool, &arr).await?;
            if orig_bundle.tenant_id != req.tenant_id || orig_bundle.scope != req.scope {
                return Err(ApiError::bad_request(format!(
                    "source_bundle_hash belongs to ({}, {}), not ({}, {})",
                    orig_bundle.tenant_id, orig_bundle.scope, req.tenant_id, req.scope
                )));
            }
            let in_dispute = orig_bundle.dispute_records.iter().any(|d| {
                d.competing_claims
                    .iter()
                    .any(|c| c.id == req.winning_claim_id)
            });
            if !in_dispute {
                return Err(ApiError::bad_request(format!(
                    "winning_claim_id {} did not appear as a disputed candidate in source_bundle_hash {raw_hex}",
                    req.winning_claim_id
                )));
            }
            Some(arr)
        }
        None => None,
    };

    let (scoped_claims, _) =
        claims_repo::fetch_scoped_claims(&state.pool, &req.tenant_id, &req.scope).await?;

    let active_claims: Vec<KnowledgeClaim> = scoped_claims
        .into_iter()
        .filter(|c| {
            c.status == ClaimStatus::Active
                && c.valid_from.map_or(true, |vf| now >= vf)
                && c.valid_to.map_or(true, |vt| now <= vt)
        })
        .collect();

    let Some(winner) = active_claims
        .iter()
        .find(|c| c.id == req.winning_claim_id)
        .cloned()
    else {
        let msg = format!(
            "active winning_claim_id {} not found in scope '{}'",
            req.winning_claim_id, req.scope
        );
        let suffix = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "attest_override",
                "attest_winning_claim_not_found",
                Some(&req.scope),
                &msg,
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("{msg}{suffix}"),
        });
    };

    let logical_group_key = compute_logical_claim_group_key(
        &winner.tenant_id,
        &winner.subject,
        &winner.predicate,
        &winner.scope,
    );

    let mut by_source: BTreeMap<String, Vec<KnowledgeClaim>> = BTreeMap::new();
    for c in active_claims {
        let lkey = compute_logical_claim_group_key(&c.tenant_id, &c.subject, &c.predicate, &c.scope);
        if lkey == logical_group_key {
            by_source
                .entry(c.source_descriptor.clone())
                .or_default()
                .push(c);
        }
    }

    let mut group_heads = Vec::with_capacity(by_source.len());
    for (_src, mut vec_c) in by_source {
        if let Some(pos) = vec_c.iter().position(|c| c.id == winner.id) {
            group_heads.push(vec_c.swap_remove(pos));
            continue;
        }
        vec_c.sort_by(|a, b| {
            b.version
                .cmp(&a.version)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id))
        });
        if let Some(head) = vec_c.into_iter().next() {
            group_heads.push(head);
        }
    }

    let active_ids: BTreeSet<Uuid> = group_heads.iter().map(|c| c.id).collect();
    let has_contradiction = group_heads.iter().any(|c| {
        c.contradiction_ids
            .iter()
            .any(|tid| active_ids.contains(tid))
    });

    let mut overridden_claims = Vec::new();
    for peer in &group_heads {
        if peer.id != winner.id && !same_typed_value(peer, &winner) {
            overridden_claims.push(OverriddenClaimRef {
                id: peer.id,
                content_hash: peer.content_hash,
            });
        }
    }
    overridden_claims.sort_unstable();

    let min_conf = state.pipeline.config().resolver.min_confidence;
    let is_sub_threshold_override =
        overridden_claims.is_empty() && winner.confidence + 1e-9 < min_conf;

    if overridden_claims.is_empty() && !has_contradiction && !is_sub_threshold_override {
        let msg = format!(
            "cannot attest override for '{}':'{}' in scope '{}': claim {} has no competing claims or sub-threshold dispute to adjudicate",
            winner.subject, winner.predicate, req.scope, winner.id
        );
        let suffix = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "attest_override",
                "attest_no_active_dispute",
                Some(&req.scope),
                &msg,
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::bad_request(format!("{msg}{suffix}")));
    }

    let (att, _ev, was_noop) = overrides_repo::attest_override_tx(
        &state.pool,
        &state.host_signing_key,
        NewOverrideInput {
            id: req.id.unwrap_or_else(Uuid::new_v4),
            tenant_id: req.tenant_id,
            scope: req.scope,
            claim_group_key: logical_group_key,
            subject: winner.subject,
            predicate: winner.predicate,
            source_bundle_hash,
            winning_claim_id: winner.id,
            winning_claim_content_hash: winner.content_hash,
            overridden_claims,
            adjudicator_id: effective_actor,
            justification: req.justification,
            client_signature,
            client_public_key,
            created_at: now,
        },
    )
    .await?;

    let status = if was_noop {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((
        status,
        Json(AttestOverrideResponse {
            id: att.id,
            version: att.version,
            claim_group_key: hex::encode(att.claim_group_key),
            subject: att.subject,
            predicate: att.predicate,
            winning_claim_id: att.winning_claim_id,
            winning_claim_content_hash: hex::encode(att.winning_claim_content_hash),
            overridden_claim_ids: att.overridden_claims.iter().map(|c| c.id).collect(),
            adjudicator_id: att.adjudicator_id,
            adjudicator_auth_kind,
            justification: att.justification,
            attestation_hash: hex::encode(att.attestation_hash),
            evidence_seq_num: att.evidence_seq_num,
            host_signature: hex::encode(att.host_signature),
            client_public_key_hex: att.client_public_key.map(hex::encode),
            was_idempotent_noop: was_noop,
            created_at: att.created_at,
        }),
    ))
}

/// `GET /v1/tenants/:tenant_id/overrides` -> Lists signed `OverrideAttestation` records for `tenant_id`.
pub async fn handle_list_overrides(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<OverridesQueryParams>,
    headers: HeaderMap,
) -> Result<Json<TenantOverridesResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "list_overrides")
        .await
        .map_err(ApiError::unauthorized)?;

    let scope_filter = query
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let pairs = overrides_repo::fetch_tenant_overrides(
        &state.pool,
        clean_tenant,
        scope_filter.as_deref(),
    )
    .await?;
    let overrides: Vec<OverrideAttestation> = pairs.into_iter().map(|(a, _)| a).collect();

    Ok(Json(TenantOverridesResponse {
        tenant_id: clean_tenant.to_string(),
        active_scope_filter: scope_filter,
        count: overrides.len(),
        overrides,
    }))
}
