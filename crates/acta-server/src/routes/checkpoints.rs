use acta_crypto::{
    compute_merkle_consistency_proof, merkle_empty_root, verify_merkle_consistency_proof,
    verify_witness_anchor_signature,
};
use acta_policy::PolicyAction;
use acta_store::evidence_repo::{self, WitnessRegistrationOutcome, WitnessRevocationOutcome};
use acta_types::{
    validate_identifier, validate_justification, AnchorCheckpointRequest, ExternalWitnessAnchor,
    PolicyDecision, PolicyResultTag, QuarantinedAnchorRecord, RegisterWitnessRequest,
    RegisterWitnessResponse, RevokeWitnessRequest, RevokeWitnessResponse, SignedTreeHead,
    TrustedWitness,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{SubsecRound, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, VerifiedKeyInfo};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CheckpointQueryParams {
    pub tree_size: Option<i64>,
    pub since_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointResponse {
    pub tenant_id: String,
    pub tree_size: i64,
    pub host_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_merkle_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_witnessed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_anchored_checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof_from_latest_anchor: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_anchor_consistency_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantAnchorsResponse {
    pub tenant_id: String,
    pub count: usize,
    pub anchors: Vec<ExternalWitnessAnchor>,
    pub quarantined_count: usize,
    pub quarantined_anchors: Vec<QuarantinedAnchorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantWitnessesResponse {
    pub tenant_id: String,
    pub count: usize,
    pub active_count: usize,
    pub revoked_count: usize,
    pub compromised_count: usize,
    pub retired_count: usize,
    pub witnesses: Vec<TrustedWitness>,
}

/// `POST /v1/witnesses` -> Enrolls an immutable trusted external witness Ed25519 public key
/// (`trusted_witnesses`) after enforcing Cedar `Action::"attest"` and notarizing the principal- and
/// description-bound registration commitment (`b"acta:witness_reg:v3"`) in `evidence_history`.
pub async fn handle_register_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterWitnessRequest>,
) -> Result<(StatusCode, Json<RegisterWitnessResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() || req.witness_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            "tenant_id and witness_id must be non-empty",
        ));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "register_witness")
        .await
        .map_err(ApiError::unauthorized)?;

    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_identifier("witness_id", &req.witness_id)?;

    let clean_desc = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(d) = clean_desc {
        if d.len() > 512 || d.chars().any(char::is_control) {
            return Err(ApiError::bad_request(
                "description must be <= 512 printable characters",
            ));
        }
    }

    let pk_bytes = hex::decode(req.witness_public_key_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid witness_public_key_hex: {e}")))?;
    let witness_public_key: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        ApiError::bad_request("witness_public_key_hex must be 32 bytes (64 hex chars)")
    })?;
    let vk = VerifyingKey::from_bytes(&witness_public_key).map_err(|e| {
        ApiError::bad_request(format!("invalid Ed25519 witness_public_key_hex: {e}"))
    })?;
    if vk.is_weak() {
        return Err(ApiError::bad_request(
            "rejected weak low-order Ed25519 witness_public_key_hex",
        ));
    }

    let effective_actor = match &caller_auth {
        VerifiedKeyInfo::TenantBound {
            verified_principal: Some(gh),
            ..
        } => format!("{}::oauth:{gh}", req.tenant_id),
        VerifiedKeyInfo::Master { .. } => format!("{}::master-admin", req.tenant_id),
        _ => format!("{}::session", req.tenant_id),
    };

    let (policy_decision, _perm_root) = state.policy_gate.evaluate_action(
        &req.tenant_id,
        &effective_actor,
        "register_witness",
        "witness-registry",
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
                    "register_witness",
                    "witness_policy_block",
                    Some("witness-registry"),
                    &format!("register_witness denied: {reason}"),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy denied on witness registration: {reason}{suffix}"
            )));
        }
        PolicyDecision::Escalate { reason } => {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Escalate,
                    "register_witness",
                    "witness_policy_escalate",
                    Some("witness-registry"),
                    &format!("register_witness escalated: {reason}"),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy escalation required on witness registration: {reason}{suffix}"
            )));
        }
    }

    let now = Utc::now().trunc_subsecs(6);
    let active_sk = state.signing_key_for_tenant(&req.tenant_id);
    let outcome = evidence_repo::register_trusted_witness_tx(
        &state.pool,
        &active_sk,
        &req.tenant_id,
        &req.witness_id,
        &witness_public_key,
        clean_desc,
        &effective_actor,
        now,
    )
    .await?;

    match outcome {
        WitnessRegistrationOutcome::Registered {
            witness,
            registration_domain,
            registration_preimage,
            registration_commitment,
            was_idempotent_noop,
        } => {
            let status = if was_idempotent_noop {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            Ok((
                status,
                Json(RegisterWitnessResponse {
                    tenant_id: witness.tenant_id,
                    witness_id: witness.witness_id,
                    witness_public_key_hex: hex::encode(witness.public_key),
                    description: witness.description,
                    registered_by: witness.registered_by,
                    registration_domain,
                    registration_blake3_preimage_hex: hex::encode(registration_preimage),
                    registration_commitment_hex: hex::encode(registration_commitment),
                    evidence_seq_num: witness.evidence_seq_num,
                    active: witness.active,
                    was_idempotent_noop,
                    created_at: witness.created_at,
                }),
            ))
        }
        WitnessRegistrationOutcome::Conflict {
            existing_witness_id,
            existing_public_key,
            existing_revoked,
        } => {
            let reason_code = if existing_revoked && existing_witness_id == req.witness_id {
                "witness_already_revoked"
            } else {
                "witness_key_already_pinned"
            };
            let msg = format!(
                "witness registration conflict for '{}': key/id already pinned (existing witness_id='{}', public_key={}, revoked={existing_revoked})",
                req.witness_id,
                existing_witness_id,
                hex::encode(existing_public_key)
            );
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "register_witness",
                    reason_code,
                    Some("witness-registry"),
                    &msg,
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            Err(ApiError::forbidden(format!("{msg}{suffix}")))
        }
    }
}

/// `POST /v1/witnesses/revoke` -> Appends an immutable revocation entry (`witness_revocations`)
/// and notarizes `b"acta:witness_revoke:v1"` in `evidence_history` without mutating `trusted_witnesses`.
pub async fn handle_revoke_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeWitnessRequest>,
) -> Result<(StatusCode, Json<RevokeWitnessResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() || req.witness_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            "tenant_id and witness_id must be non-empty",
        ));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "revoke_witness")
        .await
        .map_err(ApiError::unauthorized)?;

    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_identifier("witness_id", &req.witness_id)?;
    let clean_mode = match req.mode.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("compromise") => "compromise",
        Some("retire") => "retire",
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "invalid witness revocation mode '{other}' (expected 'compromise' or 'retire')"
            )));
        }
    };
    let clean_reason = req.reason.trim();
    validate_justification(clean_reason)?;

    let effective_actor = match &caller_auth {
        VerifiedKeyInfo::TenantBound {
            verified_principal: Some(gh),
            ..
        } => format!("{}::oauth:{gh}", req.tenant_id),
        VerifiedKeyInfo::Master { .. } => format!("{}::master-admin", req.tenant_id),
        _ => format!("{}::session", req.tenant_id),
    };

    let (policy_decision, _perm_root) = state.policy_gate.evaluate_action(
        &req.tenant_id,
        &effective_actor,
        "revoke_witness",
        "witness-registry",
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
                    "revoke_witness",
                    "witness_policy_block",
                    Some("witness-registry"),
                    &format!("revoke_witness denied: {reason}"),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy denied on witness revocation: {reason}{suffix}"
            )));
        }
        PolicyDecision::Escalate { reason } => {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Escalate,
                    "revoke_witness",
                    "witness_policy_escalate",
                    Some("witness-registry"),
                    &format!("revoke_witness escalated: {reason}"),
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::forbidden(format!(
                "policy escalation required on witness revocation: {reason}{suffix}"
            )));
        }
    }

    let now = Utc::now().trunc_subsecs(6);
    let active_sk = state.signing_key_for_tenant(&req.tenant_id);
    let outcome = evidence_repo::revoke_trusted_witness_tx(
        &state.pool,
        &active_sk,
        &req.tenant_id,
        &req.witness_id,
        &effective_actor,
        clean_mode,
        clean_reason,
        now,
    )
    .await?;

    match outcome {
        WitnessRevocationOutcome::Revoked {
            witness,
            revocation_domain,
            revocation_preimage,
            revocation_commitment,
            revocation_seq_num,
            revoked_at,
            was_idempotent_noop,
        } => {
            let status = if was_idempotent_noop {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            let eff_size = witness.effective_from_tree_size;
            let rev_mode = witness
                .revocation_mode
                .unwrap_or_else(|| clean_mode.to_string());
            Ok((
                status,
                Json(RevokeWitnessResponse {
                    tenant_id: witness.tenant_id,
                    witness_id: witness.witness_id,
                    witness_public_key_hex: hex::encode(witness.public_key),
                    revoked_by: effective_actor,
                    revocation_mode: rev_mode,
                    effective_from_tree_size: eff_size,
                    reason: clean_reason.to_string(),
                    revocation_domain,
                    revocation_blake3_preimage_hex: hex::encode(revocation_preimage),
                    revocation_commitment_hex: hex::encode(revocation_commitment),
                    evidence_seq_num: revocation_seq_num,
                    active: false,
                    was_idempotent_noop,
                    revoked_at,
                }),
            ))
        }
        WitnessRevocationOutcome::NotFound => {
            let msg = format!(
                "witness '{}' is not enrolled in trusted_witnesses for tenant '{}'",
                req.witness_id, req.tenant_id
            );
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "revoke_witness",
                    "witness_not_found",
                    Some("witness-registry"),
                    &msg,
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            Err(ApiError::not_found(format!("{msg}{suffix}")))
        }
        WitnessRevocationOutcome::AlreadyRevokedConflict {
            revoked_by,
            revocation_mode,
            effective_from_tree_size,
            reason,
            revocation_seq_num,
        } => {
            let eff_note = match effective_from_tree_size {
                Some(eff) => format!(", effective_from_tree_size={eff}"),
                None => String::new(),
            };
            let msg = format!(
                "witness '{}' is already inactive at evidence seq_num={} by '{}' (mode={}{eff_note}, reason='{}')",
                req.witness_id, revocation_seq_num, revoked_by, revocation_mode, reason
            );
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "revoke_witness",
                    "witness_already_revoked",
                    Some("witness-registry"),
                    &msg,
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            Err(ApiError::forbidden(format!("{msg}{suffix}")))
        }
    }
}

/// `GET /v1/tenants/:tenant_id/witnesses` -> Lists enrolled trusted witnesses (active + revoked) for `tenant_id`.
pub async fn handle_list_witnesses(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TenantWitnessesResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "list_witnesses")
        .await
        .map_err(ApiError::unauthorized)?;

    let witnesses =
        evidence_repo::fetch_tenant_trusted_witnesses(&state.pool, clean_tenant).await?;
    let active_count = witnesses.iter().filter(|w| w.active).count();
    let revoked_count = witnesses.iter().filter(|w| !w.active).count();
    let retired_count = witnesses
        .iter()
        .filter(|w| !w.active && w.revocation_mode.as_deref() == Some("retire"))
        .count();
    let compromised_count = revoked_count.saturating_sub(retired_count);
    Ok(Json(TenantWitnessesResponse {
        tenant_id: clean_tenant.to_string(),
        count: witnesses.len(),
        active_count,
        revoked_count,
        compromised_count,
        retired_count,
        witnesses,
    }))
}

/// `GET /v1/tenants/:tenant_id/checkpoint` -> Computes a deterministic RFC 6962 §2.1 SHA-256
/// `SignedTreeHead` checkpoint and optional `O(log N)` consistency proof from `since_size` to `tree_size`.
pub async fn handle_get_checkpoint(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<CheckpointQueryParams>,
    headers: HeaderMap,
) -> Result<Json<CheckpointResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "get_checkpoint")
        .await
        .map_err(ApiError::unauthorized)?;

    if let Some(req_n) = query.tree_size {
        if req_n < 1 {
            return Err(ApiError::bad_request("tree_size must be >= 1"));
        }
    }

    let active_sk = state.signing_key_for_tenant(clean_tenant);
    let active_pk = active_sk.verifying_key().to_bytes();
    let head_opt = evidence_repo::build_signed_tree_head(
        &state.pool,
        &active_sk,
        clean_tenant,
        query.tree_size,
    )
    .await?;

    let Some((sth, leaves)) = head_opt else {
        if query.tree_size.is_some() || query.since_size.is_some() {
            return Err(ApiError::not_found(format!(
                "tenant '{clean_tenant}' has an empty evidence ledger (tree_size=0)"
            )));
        }
        return Ok(Json(CheckpointResponse {
            tenant_id: clean_tenant.to_string(),
            tree_size: 0,
            host_public_key: hex::encode(active_pk),
            empty_merkle_root: Some(hex::encode(merkle_empty_root())),
            head_witnessed: Some(false),
            checkpoint: None,
            latest_anchored_checkpoint: None,
            consistency_proof_from_latest_anchor: None,
            latest_anchor_consistency_verified: None,
            since_size: None,
            prior_checkpoint: None,
            consistency_proof: None,
            consistency_verified: None,
        }));
    };

    let (prior_checkpoint, consistency_proof, consistency_verified) = match query.since_size {
        Some(first_n) => {
            if first_n < 1 || first_n > sth.tree_size {
                return Err(ApiError::bad_request(format!(
                    "since_size={first_n} must satisfy 1 <= since_size <= tree_size ({})",
                    sth.tree_size
                )));
            }
            let (prior_sth, _) = evidence_repo::build_signed_tree_head(
                &state.pool,
                &active_sk,
                clean_tenant,
                Some(first_n),
            )
            .await?
            .ok_or_else(|| ApiError::bad_request("prior_checkpoint missing"))?;

            let nodes = compute_merkle_consistency_proof(
                &leaves,
                first_n as usize,
                sth.tree_size as usize,
            )?;
            let ok = verify_merkle_consistency_proof(
                first_n,
                &prior_sth.merkle_root,
                sth.tree_size,
                &sth.merkle_root,
                &nodes,
            );
            let hex_nodes = nodes.into_iter().map(hex::encode).collect();
            (Some(prior_sth), Some(hex_nodes), Some(ok))
        }
        None => (None, None, None),
    };

    let head_witnessed = !sth.witness_anchors.is_empty();
    let (
        latest_anchored_checkpoint,
        consistency_proof_from_latest_anchor,
        latest_anchor_consistency_verified,
    ) = evidence_repo::resolve_latest_anchored_for_head(
        &state.pool,
        &active_sk,
        clean_tenant,
        &sth,
        &leaves,
    )
    .await?;

    Ok(Json(CheckpointResponse {
        tenant_id: clean_tenant.to_string(),
        tree_size: sth.tree_size,
        host_public_key: hex::encode(active_pk),
        empty_merkle_root: None,
        head_witnessed: Some(head_witnessed),
        checkpoint: Some(sth),
        latest_anchored_checkpoint,
        consistency_proof_from_latest_anchor,
        latest_anchor_consistency_verified,
        since_size: query.since_size,
        prior_checkpoint,
        consistency_proof,
        consistency_verified,
    }))
}

/// `POST /v1/anchors` -> Verifies that `(tenant_id, witness_id)` is an active, non-revoked entry
/// in `trusted_witnesses` with matching `public_key`, verifies the external witness Ed25519
/// cosignature (`b"acta:witness_sig:v1"`), and records an immutable `ExternalWitnessAnchor`.
pub async fn handle_anchor_checkpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AnchorCheckpointRequest>,
) -> Result<(StatusCode, Json<ExternalWitnessAnchor>), ApiError> {
    if req.tenant_id.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "anchor_checkpoint")
        .await
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_identifier("witness_id", &req.witness_id)?;
    if req.tree_size < 1 {
        return Err(ApiError::bad_request("tree_size must be >= 1"));
    }
    if let Some(ref uri) = req.external_uri {
        if uri.len() > 512 || uri.chars().any(char::is_control) {
            return Err(ApiError::bad_request(
                "external_uri must be <= 512 printable characters",
            ));
        }
    }

    let cp_bytes = hex::decode(req.checkpoint_hash_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid checkpoint_hash_hex: {e}")))?;
    let checkpoint_hash: [u8; 32] = cp_bytes.try_into().map_err(|_| {
        ApiError::bad_request("checkpoint_hash_hex must be 32 bytes (64 hex chars)")
    })?;

    let pk_bytes = hex::decode(req.witness_public_key_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid witness_public_key_hex: {e}")))?;
    let witness_public_key: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        ApiError::bad_request("witness_public_key_hex must be 32 bytes (64 hex chars)")
    })?;

    let sig_bytes = hex::decode(req.witness_signature_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid witness_signature_hex: {e}")))?;
    let witness_signature: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        ApiError::bad_request("witness_signature_hex must be 64 bytes (128 hex chars)")
    })?;

    let enrolled_opt =
        evidence_repo::fetch_trusted_witness(&state.pool, &req.tenant_id, &req.witness_id).await?;
    let Some(enrolled) = enrolled_opt else {
        let msg = format!(
            "witness '{}' is not enrolled in trusted_witnesses for tenant '{}' (attempted_tree_size={}); register via acta_register_witness / POST /v1/witnesses first",
            req.witness_id, req.tenant_id, req.tree_size
        );
        let suffix = state
            .append_anchor_refusal_audit(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "unregistered_witness",
                Some("witness-registry"),
                &msg,
                Some(checkpoint_hash),
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::forbidden(format!("{msg}{suffix}")));
    };

    if !enrolled.active {
        let mode_label = enrolled
            .revocation_mode
            .as_deref()
            .unwrap_or("compromise");
        let verb = if mode_label == "retire" {
            "retired"
        } else {
            "revoked"
        };
        let seq_part = match enrolled.revocation_evidence_seq_num {
            Some(seq) => format!("revocation_seq={seq}, "),
            None => String::new(),
        };
        let eff_part = match enrolled.effective_from_tree_size {
            Some(eff) => format!("effective_from_tree_size={eff}, "),
            None => String::new(),
        };
        let reason_detail = enrolled
            .revocation_reason
            .as_deref()
            .unwrap_or("inactive witness");
        let msg = format!(
            "witness '{}' has been {verb} for tenant '{}' (attempted_tree_size={}, mode={mode_label}, {seq_part}{eff_part}reason='{reason_detail}')",
            req.witness_id, req.tenant_id, req.tree_size
        );
        let suffix = state
            .append_anchor_refusal_audit(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "revoked_witness",
                Some("witness-registry"),
                &msg,
                Some(checkpoint_hash),
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::forbidden(format!("{msg}{suffix}")));
    }

    if enrolled.public_key != witness_public_key {
        let msg = format!(
            "witness_public_key_hex mismatch for enrolled witness '{}' at attempted_tree_size={}: submitted {}, pinned {}",
            req.witness_id,
            req.tree_size,
            hex::encode(witness_public_key),
            hex::encode(enrolled.public_key)
        );
        let suffix = state
            .append_anchor_refusal_audit(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "witness_key_mismatch",
                Some("witness-registry"),
                &msg,
                Some(checkpoint_hash),
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::forbidden(format!("{msg}{suffix}")));
    }

    let active_sk = state.signing_key_for_tenant(&req.tenant_id);
    let (sth, _) = evidence_repo::build_signed_tree_head(
        &state.pool,
        &active_sk,
        &req.tenant_id,
        Some(req.tree_size),
    )
    .await?
    .ok_or_else(|| {
        ApiError::not_found(format!(
            "no checkpoint exists at tree_size={} for tenant '{}'",
            req.tree_size, req.tenant_id
        ))
    })?;

    if sth.checkpoint_hash != checkpoint_hash {
        let msg = format!(
            "checkpoint_hash mismatch at tree_size={}: witness signed {}, ledger head is {}",
            req.tree_size,
            hex::encode(checkpoint_hash),
            hex::encode(sth.checkpoint_hash)
        );
        let suffix = state
            .append_anchor_refusal_audit(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "anchor_checkpoint_hash_mismatch",
                Some("witness-registry"),
                &msg,
                Some(checkpoint_hash),
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::bad_request(format!("{msg}{suffix}")));
    }

    if !verify_witness_anchor_signature(
        &witness_public_key,
        &req.tenant_id,
        req.tree_size,
        &checkpoint_hash,
        &witness_signature,
    ) {
        let msg = format!(
            "invalid Ed25519 witness_signature_hex from witness '{}' at attempted_tree_size={} over acta:witness_sig:v1",
            req.witness_id, req.tree_size
        );
        let suffix = state
            .append_anchor_refusal_audit(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "invalid_witness_signature",
                Some("witness-registry"),
                &msg,
                Some(checkpoint_hash),
            )
            .await
            .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
            .unwrap_or_default();
        return Err(ApiError::forbidden(format!("{msg}{suffix}")));
    }

    let anchor = ExternalWitnessAnchor {
        id: req.id.unwrap_or_else(Uuid::new_v4),
        tenant_id: req.tenant_id,
        tree_size: req.tree_size,
        checkpoint_hash,
        witness_id: req.witness_id,
        witness_public_key,
        witness_signature,
        external_uri: req
            .external_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        anchored_at: Utc::now().trunc_subsecs(6),
    };

    let saved = evidence_repo::insert_witness_anchor(
        &state.pool,
        &sth.head_event_hash,
        &sth.merkle_root,
        anchor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(saved)))
}

/// `GET /v1/tenants/:tenant_id/anchors` -> Lists active and quarantined external witness anchors for `tenant_id`.
pub async fn handle_list_anchors(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TenantAnchorsResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "list_anchors")
        .await
        .map_err(ApiError::unauthorized)?;

    let (anchors, quarantined_anchors) = tokio::try_join!(
        evidence_repo::fetch_recent_witness_anchors(&state.pool, clean_tenant),
        evidence_repo::fetch_quarantined_witness_anchors(&state.pool, clean_tenant),
    )?;
    Ok(Json(TenantAnchorsResponse {
        tenant_id: clean_tenant.to_string(),
        count: anchors.len(),
        anchors,
        quarantined_count: quarantined_anchors.len(),
        quarantined_anchors,
    }))
}
