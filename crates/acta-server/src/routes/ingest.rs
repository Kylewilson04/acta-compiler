use acta_crypto::{
    compute_claim_content_hash, compute_logical_claim_group_key, compute_object_content_hash,
    hash_length_delimited, verify_client_content_signature,
};
use acta_policy::PolicyAction;
use acta_store::{claims_repo, objects_repo};
use acta_types::{
    validate_confidence, validate_identifier, validate_importance, validate_json_payload_size,
    validate_priority, validate_provenance_class, validate_scope, validate_tags,
    IngestClaimRequest, IngestClaimResponse, IngestObjectRequest, IngestObjectResponse,
    KnowledgeClaim, PolicyDecision, PolicyResultTag, StoredObject,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{SubsecRound, Utc};
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::AppState;

fn resolve_ingest_actor(headers: &HeaderMap, tenant_id: &str) -> Result<String, ApiError> {
    if let Some(raw) = headers
        .get("x-acta-actor")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_identifier("x-acta-actor", raw)?;
        Ok(raw.to_string())
    } else {
        Ok(format!("{tenant_id}::ingest-writer"))
    }
}

async fn enforce_policy_before_write(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: &str,
    scope: &str,
    write_kind: &str,
) -> Result<(), ApiError> {
    let actor_id = resolve_ingest_actor(headers, tenant_id)?;
    let (decision, _perm_root) = state.policy_gate.evaluate_action(
        tenant_id,
        &actor_id,
        write_kind,
        scope,
        PolicyAction::Ingest,
    );

    match decision {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Block { reason } => {
            let ev_opt = state
                .append_refusal_audit_with_scope(
                    headers,
                    Some(tenant_id),
                    PolicyResultTag::Block,
                    write_kind,
                    "ingest_policy_block",
                    Some(scope),
                    &format!("{write_kind} denied on scope '{scope}': {reason}"),
                )
                .await;
            let suffix = ev_opt
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            Err(ApiError::forbidden(format!(
                "policy denied on ingest to scope '{scope}': {reason}{suffix}"
            )))
        }
        PolicyDecision::Escalate { reason } => {
            let ev_opt = state
                .append_refusal_audit_with_scope(
                    headers,
                    Some(tenant_id),
                    PolicyResultTag::Escalate,
                    write_kind,
                    "ingest_policy_escalate",
                    Some(scope),
                    &format!("{write_kind} escalated on restricted scope '{scope}': {reason}"),
                )
                .await;
            let suffix = ev_opt
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            Err(ApiError::forbidden(format!(
                "policy escalation required on ingest to restricted scope '{scope}': {reason}{suffix}"
            )))
        }
    }
}

fn validate_optional_client_sig(
    sig_hex: Option<&str>,
    pubkey_hex: Option<&str>,
    content_hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(raw_sig_hex) = sig_hex else {
        return Ok(None);
    };
    let sig_vec = hex::decode(raw_sig_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid client_signature_hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_vec
        .clone()
        .try_into()
        .map_err(|_| ApiError::bad_request("client_signature_hex must be 64 bytes (128 hex chars)"))?;

    if let Some(raw_pk_hex) = pubkey_hex {
        let pk_vec = hex::decode(raw_pk_hex.trim())
            .map_err(|e| ApiError::bad_request(format!("invalid client_public_key_hex: {e}")))?;
        let pk_arr: [u8; 32] = pk_vec.try_into().map_err(|_| {
            ApiError::bad_request("client_public_key_hex must be 32 bytes (64 hex chars)")
        })?;
        if !verify_client_content_signature(&pk_arr, content_hash, &sig_arr) {
            return Err(ApiError::bad_request(
                "client Ed25519 signature verification failed over content_hash",
            ));
        }
    }

    Ok(Some(sig_vec))
}

/// `POST /v1/objects` -> enforces Policy-Before-Write + anti-forgery validation, computes
/// `content_hash`, validates optional `client_signature`, and inserts row.
pub async fn handle_ingest_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestObjectRequest>,
) -> Result<(StatusCode, Json<IngestObjectResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() || req.scope.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id and scope must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "ingest_object")
        .await
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    let _ = validate_priority(i64::from(req.priority))?;
    validate_importance(req.importance)?;
    validate_tags(&req.tags)?;
    validate_json_payload_size("body", &req.body)?;

    enforce_policy_before_write(&state, &headers, &req.tenant_id, &req.scope, "ingest_object")
        .await?;

    if let Some(ref emb) = req.embedding {
        if emb.len() != 1536 {
            return Err(ApiError::bad_request(
                "embedding must have exactly 1536 dimensions",
            ));
        }
        if emb.iter().any(|x| !x.is_finite()) {
            return Err(ApiError::bad_request("embedding values must be finite"));
        }
    }

    let version = if let Some(pred_id) = req.predecessor_id {
        let pred = objects_repo::fetch_object_by_id(&state.pool, &req.tenant_id, pred_id)
            .await?
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "predecessor object {pred_id} not found for tenant {}",
                    req.tenant_id
                ))
            })?;
        pred.version + 1
    } else {
        1
    };

    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let created_at = Utc::now().trunc_subsecs(6);

    let mut obj = StoredObject {
        id,
        tenant_id: req.tenant_id,
        obj_type: req.obj_type,
        scope: req.scope,
        lifecycle_status: req.lifecycle_status,
        priority: req.priority,
        importance: req.importance,
        tags: req.tags,
        body: req.body,
        content_hash: [0u8; 32],
        embedding: req.embedding,
        version,
        predecessor_id: req.predecessor_id,
        client_signature: None,
        created_at,
    };

    let content_hash = compute_object_content_hash(&obj)?;
    obj.content_hash = content_hash;
    obj.client_signature = validate_optional_client_sig(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
        &content_hash,
    )?;

    objects_repo::insert_object(&state.pool, &obj).await?;

    Ok((
        StatusCode::CREATED,
        Json(IngestObjectResponse {
            id: obj.id,
            version: obj.version,
            content_hash: hex::encode(obj.content_hash),
            created_at: obj.created_at,
        }),
    ))
}

/// `POST /v1/claims` -> enforces Policy-Before-Write + anti-forgery validation, computes
/// type-unified `claim_group_key` + `content_hash`, and atomically auto-supersedes / deduplicates
/// prior active claims from the same `source_descriptor`.
pub async fn handle_ingest_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestClaimRequest>,
) -> Result<(StatusCode, Json<IngestClaimResponse>), ApiError> {
    if req.tenant_id.trim().is_empty()
        || req.scope.trim().is_empty()
        || req.subject.trim().is_empty()
        || req.predicate.trim().is_empty()
        || req.object_type.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "tenant_id, scope, subject, predicate, and object_type must be non-empty",
        ));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "ingest_claim")
        .await
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    validate_identifier("subject", &req.subject)?;
    validate_identifier("predicate", &req.predicate)?;
    validate_identifier("object_type", &req.object_type)?;
    validate_identifier("source_descriptor", &req.source_descriptor)?;
    validate_confidence(req.confidence)?;
    let _ = validate_provenance_class(i64::from(req.source_provenance_class))?;
    validate_json_payload_size("object_val", &req.object_val)?;

    enforce_policy_before_write(&state, &headers, &req.tenant_id, &req.scope, "ingest_claim")
        .await?;

    let version = if let Some(pred_id) = req.predecessor_id {
        let pred = claims_repo::fetch_claim_by_id(&state.pool, &req.tenant_id, pred_id)
            .await?
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "predecessor claim {pred_id} not found for tenant {}",
                    req.tenant_id
                ))
            })?;
        pred.version + 1
    } else {
        1
    };

    let source_commitment: [u8; 32] = match req.source_commitment_hex {
        Some(ref hex_str) => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| ApiError::bad_request(format!("invalid source_commitment_hex: {e}")))?;
            bytes.try_into().map_err(|_| {
                ApiError::bad_request("source_commitment_hex must be 32 bytes (64 hex chars)")
            })?
        }
        None => hash_length_delimited(&[b"acta:source:v1", req.source_descriptor.as_bytes()]),
    };

    let claim_group_key = compute_logical_claim_group_key(
        &req.tenant_id,
        &req.subject,
        &req.predicate,
        &req.scope,
    );

    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let created_at = Utc::now().trunc_subsecs(6);
    let allow_auto_supersede = req.predecessor_id.is_none() && req.client_signature_hex.is_none();

    let mut claim = KnowledgeClaim {
        id,
        tenant_id: req.tenant_id,
        claim_group_key,
        scope: req.scope,
        subject: req.subject,
        predicate: req.predicate,
        object_val: req.object_val,
        object_type: req.object_type,
        confidence: req.confidence,
        source_provenance_class: req.source_provenance_class,
        source_descriptor: req.source_descriptor,
        source_commitment,
        content_hash: [0u8; 32],
        status: req.status,
        contradiction_ids: req.contradiction_ids,
        valid_from: req.valid_from.map(|t| t.trunc_subsecs(6)),
        valid_to: req.valid_to.map(|t| t.trunc_subsecs(6)),
        version,
        predecessor_id: req.predecessor_id,
        created_at,
    };

    let content_hash = compute_claim_content_hash(&claim)?;
    claim.content_hash = content_hash;

    let _ = validate_optional_client_sig(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
        &content_hash,
    )?;

    let (persisted, was_idempotent_noop) =
        claims_repo::insert_or_supersede_claim_tx(&state.pool, claim, allow_auto_supersede).await?;

    let http_status = if was_idempotent_noop {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((
        http_status,
        Json(IngestClaimResponse {
            id: persisted.id,
            version: persisted.version,
            claim_group_key: hex::encode(persisted.claim_group_key),
            content_hash: hex::encode(persisted.content_hash),
            created_at: persisted.created_at,
        }),
    ))
}
