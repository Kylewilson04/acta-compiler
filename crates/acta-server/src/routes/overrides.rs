use std::collections::{BTreeMap, BTreeSet};

use acta_crypto::{compute_logical_claim_group_key, to_canonical_bytes};
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
use crate::state::AppState;

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

/// `POST /v1/overrides` -> Enforces Policy-Before-Attest (`Action::"attest"`), verifies that an
/// active dispute actually exists for `winning_claim_id` in `(tenant_id, scope)` (and optionally
/// in `source_bundle_hash`), and atomically notarizes the signed `OverrideAttestation` + `EvidenceEntry`.
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

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    validate_identifier("adjudicator_id", &req.adjudicator_id)?;
    validate_justification(&req.justification)?;

    let effective_actor = if req.adjudicator_id.contains("::") {
        let (adj_tenant, _) = req.adjudicator_id.split_once("::").unwrap();
        if adj_tenant != req.tenant_id {
            let msg = format!(
                "adjudicator_id '{}' belongs to tenant '{}', cannot attest in tenant '{}'",
                req.adjudicator_id, adj_tenant, req.tenant_id
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
        req.adjudicator_id.clone()
    } else {
        format!("{}::{}", req.tenant_id, req.adjudicator_id)
    };

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

    let now = Utc::now().trunc_subsecs(6);

    let source_bundle_hash: Option<[u8; 32]> = match req
        .source_bundle_hash_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_hex) => {
            let decoded = hex::decode(raw_hex)
                .map_err(|e| ApiError::bad_request(format!("invalid source_bundle_hash_hex: {e}")))?;
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

    let client_signature = match req
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
            let bytes = hex::decode(s)
                .map_err(|e| ApiError::bad_request(format!("invalid client_public_key_hex: {e}")))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                ApiError::bad_request("client_public_key_hex must be 32 bytes (64 hex chars)")
            })?;
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

    // Deduplicate same-source heads inside this logical group (keeping `winner` if present).
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
            justification: att.justification,
            attestation_hash: hex::encode(att.attestation_hash),
            evidence_seq_num: att.evidence_seq_num,
            host_signature: hex::encode(att.host_signature),
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
