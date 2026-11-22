use acta_crypto::{
    compute_merkle_consistency_proof, merkle_empty_root, verify_merkle_consistency_proof,
    verify_witness_anchor_signature,
};
use acta_store::evidence_repo;
use acta_types::{
    validate_identifier, AnchorCheckpointRequest, ExternalWitnessAnchor, PolicyResultTag,
    SignedTreeHead,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::AppState;

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
    pub checkpoint: Option<SignedTreeHead>,
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
}

/// `GET /v1/tenants/:tenant_id/checkpoint` -> Computes a deterministic RFC 6962 `SignedTreeHead`
/// checkpoint (pinned to the head entry's timestamp) and optional `O(log N)` consistency proof
/// from `since_size` to `tree_size`.
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

    let head_opt = evidence_repo::build_signed_tree_head(
        &state.pool,
        &state.host_signing_key,
        clean_tenant,
        query.tree_size,
    )
    .await?;

    let Some((sth, leaves)) = head_opt else {
        if query.tree_size.is_some() || query.since_size.is_some() {
            return Err(ApiError {
                status: StatusCode::NOT_FOUND,
                message: format!("tenant '{clean_tenant}' has an empty evidence ledger (tree_size=0)"),
            });
        }
        return Ok(Json(CheckpointResponse {
            tenant_id: clean_tenant.to_string(),
            tree_size: 0,
            host_public_key: hex::encode(state.host_public_key),
            empty_merkle_root: Some(hex::encode(merkle_empty_root())),
            checkpoint: None,
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
                &state.host_signing_key,
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

    Ok(Json(CheckpointResponse {
        tenant_id: clean_tenant.to_string(),
        tree_size: sth.tree_size,
        host_public_key: hex::encode(state.host_public_key),
        empty_merkle_root: None,
        checkpoint: Some(sth),
        since_size: query.since_size,
        prior_checkpoint,
        consistency_proof,
        consistency_verified,
    }))
}

/// `POST /v1/anchors` -> Verifies an external witness Ed25519 cosignature (`b"acta:witness_sig:v1"`)
/// over `(tenant_id, tree_size, checkpoint_hash)` and records an immutable `ExternalWitnessAnchor`.
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

    let (sth, _) = evidence_repo::build_signed_tree_head(
        &state.pool,
        &state.host_signing_key,
        &req.tenant_id,
        Some(req.tree_size),
    )
    .await?
    .ok_or_else(|| ApiError {
        status: StatusCode::NOT_FOUND,
        message: format!(
            "no checkpoint exists at tree_size={} for tenant '{}'",
            req.tree_size, req.tenant_id
        ),
    })?;

    if sth.checkpoint_hash != checkpoint_hash {
        let msg = format!(
            "checkpoint_hash mismatch at tree_size={}: witness signed {}, ledger head is {}",
            req.tree_size,
            hex::encode(checkpoint_hash),
            hex::encode(sth.checkpoint_hash)
        );
        let suffix = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "anchor_checkpoint_hash_mismatch",
                None,
                &msg,
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
            "invalid Ed25519 witness_signature_hex from witness '{}' over acta:witness_sig:v1",
            req.witness_id
        );
        let suffix = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "anchor_checkpoint",
                "invalid_witness_signature",
                None,
                &msg,
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

/// `GET /v1/tenants/:tenant_id/anchors` -> Lists external witness anchors for `tenant_id`.
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

    let anchors = evidence_repo::fetch_recent_witness_anchors(&state.pool, clean_tenant).await?;
    Ok(Json(TenantAnchorsResponse {
        tenant_id: clean_tenant.to_string(),
        count: anchors.len(),
        anchors,
    }))
}
