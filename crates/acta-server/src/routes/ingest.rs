use acta_crypto::{
    compute_claim_client_intent_hash, compute_claim_content_hash, compute_logical_claim_group_key,
    compute_object_client_intent_hash, compute_object_content_hash,
    compute_retract_claim_client_intent_hash, compute_source_content_commitment,
    hash_length_delimited, verify_client_content_signature,
};
use acta_policy::PolicyAction;
use acta_store::{claims_repo, objects_repo};
use acta_types::{
    validate_claim_value_type, validate_confidence, validate_identifier, validate_importance,
    validate_json_payload_size, validate_justification, validate_priority,
    validate_provenance_class, validate_scope, validate_tags, IngestClaimRequest,
    IngestClaimResponse, IngestObjectRequest, IngestObjectResponse, KnowledgeClaim, PolicyDecision,
    PolicyResultTag, RetractClaimRequest, RetractClaimResponse, StoredObject,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{SubsecRound, Utc};
use ed25519_dalek::VerifyingKey;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, VerifiedKeyInfo};

const MAX_SOURCE_CONTENT_BYTES: usize = 64 * 1024;
const MAX_CONTRADICTION_IDS: usize = 64;

fn resolve_ingest_actor(headers: &HeaderMap, tenant_id: &str) -> Result<String, ApiError> {
    if let Some(raw) = headers
        .get("x-acta-actor")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_identifier("x-acta-actor", raw)?;
        if let Some((explicit_tenant, _)) = raw.split_once("::") {
            if explicit_tenant != tenant_id {
                return Err(ApiError::forbidden(format!(
                    "x-acta-actor '{raw}' belongs to tenant '{explicit_tenant}', cannot write in tenant '{tenant_id}'"
                )));
            }
            Ok(raw.to_string())
        } else {
            Ok(format!("{tenant_id}::{raw}"))
        }
    } else {
        Ok(format!("{tenant_id}::ingest-writer"))
    }
}

pub(crate) fn resolve_writer_identity(
    caller_auth: &VerifiedKeyInfo,
    tenant_id: &str,
    has_client_signature: bool,
) -> (String, &'static str) {
    let written_by = match caller_auth {
        VerifiedKeyInfo::TenantBound {
            verified_principal: Some(gh),
            ..
        } => format!("{tenant_id}::oauth:{gh}"),
        VerifiedKeyInfo::Master { .. } => format!("{tenant_id}::master-admin"),
        _ => format!("{tenant_id}::session"),
    };
    let auth_kind = if has_client_signature {
        "ed25519_client_sig"
    } else if written_by.contains("::oauth:") {
        "oauth_github_principal"
    } else if written_by.ends_with("::master-admin") {
        "master_admin"
    } else {
        "tenant_session"
    };
    (written_by, auth_kind)
}

pub(crate) async fn enforce_policy_before_write(
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

/// Parses `(client_signature_hex, client_public_key_hex)` syntactically BEFORE logging any refusal.
/// Malformed hex, wrong byte lengths, weak torsion keys, or supplying only one half of the pair
/// return `400 Bad Request` with zero `evidence_history` mutation.
pub(crate) fn parse_optional_client_sig_pair(
    sig_hex: Option<&str>,
    pubkey_hex: Option<&str>,
) -> Result<Option<([u8; 64], [u8; 32])>, ApiError> {
    let clean_sig = sig_hex.map(str::trim).filter(|s| !s.is_empty());
    let clean_pk = pubkey_hex.map(str::trim).filter(|s| !s.is_empty());

    match (clean_sig, clean_pk) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(ApiError::bad_request(
            "client_signature_hex and client_public_key_hex must be provided together",
        )),
        (Some(raw_sig), Some(raw_pk)) => {
            let sig_vec = hex::decode(raw_sig)
                .map_err(|e| ApiError::bad_request(format!("invalid client_signature_hex: {e}")))?;
            let sig_arr: [u8; 64] = sig_vec.try_into().map_err(|_| {
                ApiError::bad_request("client_signature_hex must be 64 bytes (128 hex chars)")
            })?;
            let pk_vec = hex::decode(raw_pk).map_err(|e| {
                ApiError::bad_request(format!("invalid client_public_key_hex: {e}"))
            })?;
            let pk_arr: [u8; 32] = pk_vec.try_into().map_err(|_| {
                ApiError::bad_request("client_public_key_hex must be 32 bytes (64 hex chars)")
            })?;
            let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                ApiError::bad_request(format!("invalid Ed25519 client_public_key_hex: {e}"))
            })?;
            if vk.is_weak() {
                return Err(ApiError::bad_request(
                    "rejected weak low-order Ed25519 client_public_key_hex",
                ));
            }
            Ok(Some((sig_arr, pk_arr)))
        }
    }
}

/// `POST /v1/objects` -> enforces Policy-Before-Write + anti-forgery validation, verifies optional
/// Ed25519 author signature (`acta:object_client_sig:v1` or `content_hash`), and atomically appends
/// both `objects` and a strip-proof `WriteLedgerSummary` (`acta:evidence_event:v3`) on `evidence_history`.
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
    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    let _ = validate_priority(i64::from(req.priority))?;
    validate_importance(req.importance)?;
    validate_tags(&req.tags)?;
    validate_json_payload_size("body", &req.body)?;

    let parsed_sig_pair = parse_optional_client_sig_pair(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
    )?;

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

    enforce_policy_before_write(&state, &headers, &req.tenant_id, &req.scope, "ingest_object")
        .await?;

    let version = if let Some(pred_id) = req.predecessor_id {
        let pred = objects_repo::fetch_object_by_id(&state.pool, &req.tenant_id, pred_id)
            .await?
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "predecessor object {pred_id} not found for tenant {}",
                    req.tenant_id
                ))
            })?;
        if pred.scope != req.scope || pred.obj_type != req.obj_type {
            return Err(ApiError::bad_request(format!(
                "predecessor object {pred_id} belongs to ({}, {}), expected ({}, {})",
                pred.scope,
                pred.obj_type.as_str(),
                req.scope,
                req.obj_type.as_str()
            )));
        }
        pred.version + 1
    } else {
        1
    };

    let id = req.id.unwrap_or_else(Uuid::new_v4);
    let created_at = Utc::now().trunc_subsecs(6);

    let mut obj = StoredObject {
        id,
        tenant_id: req.tenant_id.clone(),
        obj_type: req.obj_type,
        scope: req.scope.clone(),
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
        client_public_key: None,
        written_by: None,
        evidence_seq_num: None,
        created_at,
    };

    let content_hash = compute_object_content_hash(&obj)?;
    obj.content_hash = content_hash;

    if let Some((sig_arr, pk_arr)) = parsed_sig_pair {
        let intent_hash = compute_object_client_intent_hash(
            &obj.tenant_id,
            obj.obj_type,
            &obj.scope,
            obj.lifecycle_status,
            obj.priority,
            obj.importance,
            &obj.tags,
            &obj.body,
            obj.predecessor_id,
        )?;
        if !verify_client_content_signature(&pk_arr, &intent_hash, &sig_arr)
            && !verify_client_content_signature(&pk_arr, &content_hash, &sig_arr)
        {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "ingest_object",
                    "invalid_client_content_signature",
                    Some(&req.scope),
                    "client Ed25519 signature verification failed on ingest_object",
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::bad_request(format!(
                "client Ed25519 signature verification failed over object intent digest or content_hash{suffix}"
            )));
        }
        obj.client_signature = Some(sig_arr.to_vec());
        obj.client_public_key = Some(pk_arr);
    }

    let (written_by, writer_auth_kind) =
        resolve_writer_identity(&caller_auth, &req.tenant_id, obj.client_signature.is_some());

    let (persisted, ev) = objects_repo::insert_object_with_evidence_tx(
        &state.pool,
        &state.host_signing_key,
        obj,
        &written_by,
        writer_auth_kind,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(IngestObjectResponse {
            id: persisted.id,
            version: persisted.version,
            content_hash: hex::encode(persisted.content_hash),
            predecessor_id: persisted.predecessor_id,
            evidence_seq_num: Some(ev.seq_num),
            evidence_event_hash: Some(hex::encode(ev.event_hash)),
            host_signature: Some(hex::encode(ev.host_signature)),
            client_public_key_hex: persisted.client_public_key.map(hex::encode),
            written_by: persisted.written_by,
            created_at: persisted.created_at,
        }),
    ))
}

/// `POST /v1/claims` -> enforces Policy-Before-Write + anti-forgery validation, verifies optional
/// Ed25519 author signature (`acta:claim_client_sig:v1` or `content_hash`), validates explicit
/// `predecessor_id`, `contradiction_ids`, and `valid_from <= valid_to`, and atomically chains the
/// write onto `evidence_history` (`acta:evidence_event:v3`).
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
    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    validate_identifier("subject", &req.subject)?;
    validate_identifier("predicate", &req.predicate)?;
    validate_identifier("object_type", &req.object_type)?;
    validate_claim_value_type(&req.object_type, &req.object_val)?;
    validate_identifier("source_descriptor", &req.source_descriptor)?;
    validate_confidence(req.confidence)?;
    let _ = validate_provenance_class(i64::from(req.source_provenance_class))?;
    validate_json_payload_size("object_val", &req.object_val)?;

    if req.contradiction_ids.len() > MAX_CONTRADICTION_IDS {
        return Err(ApiError::bad_request(format!(
            "contradiction_ids count {} exceeds maximum of {MAX_CONTRADICTION_IDS}",
            req.contradiction_ids.len()
        )));
    }

    let valid_from = req.valid_from.map(|t| t.trunc_subsecs(6));
    let valid_to = req.valid_to.map(|t| t.trunc_subsecs(6));
    if let (Some(vf), Some(vt)) = (valid_from, valid_to) {
        if vt < vf {
            return Err(ApiError::bad_request(format!(
                "valid_to ({vt}) must be >= valid_from ({vf})"
            )));
        }
    }

    let parsed_sig_pair = parse_optional_client_sig_pair(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
    )?;

    let clean_hex_opt = req
        .source_commitment_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let clean_content_opt = req.source_content.as_deref().filter(|s| !s.is_empty());

    if let Some(raw_text) = clean_content_opt {
        if raw_text.len() > MAX_SOURCE_CONTENT_BYTES {
            return Err(ApiError::bad_request(format!(
                "source_content exceeds maximum size of {MAX_SOURCE_CONTENT_BYTES} bytes"
            )));
        }
    }

    let source_commitment: [u8; 32] = match (clean_hex_opt, clean_content_opt) {
        (Some(hex_str), Some(raw_text)) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| ApiError::bad_request(format!("invalid source_commitment_hex: {e}")))?;
            let explicit_arr: [u8; 32] = bytes.try_into().map_err(|_| {
                ApiError::bad_request("source_commitment_hex must be 32 bytes (64 hex chars)")
            })?;
            let computed =
                compute_source_content_commitment(&req.source_descriptor, raw_text.as_bytes());
            if explicit_arr != computed {
                return Err(ApiError::bad_request(format!(
                    "source_commitment_hex {} does not match acta:source_content:v1 digest {} over source_content",
                    hex::encode(explicit_arr),
                    hex::encode(computed)
                )));
            }
            explicit_arr
        }
        (Some(hex_str), None) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| ApiError::bad_request(format!("invalid source_commitment_hex: {e}")))?;
            bytes.try_into().map_err(|_| {
                ApiError::bad_request("source_commitment_hex must be 32 bytes (64 hex chars)")
            })?
        }
        (None, Some(raw_text)) => {
            compute_source_content_commitment(&req.source_descriptor, raw_text.as_bytes())
        }
        (None, None) => hash_length_delimited(&[b"acta:source:v1", req.source_descriptor.as_bytes()]),
    };

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
        if pred.scope != req.scope || pred.subject != req.subject || pred.predicate != req.predicate
        {
            return Err(ApiError::bad_request(format!(
                "predecessor claim {pred_id} belongs to ({}, {}, {}), expected ({}, {}, {})",
                pred.scope, pred.subject, pred.predicate, req.scope, req.subject, req.predicate
            )));
        }
        pred.version + 1
    } else {
        1
    };

    let mut contradiction_ids = req.contradiction_ids;
    contradiction_ids.sort_unstable();
    contradiction_ids.dedup();

    let id = req.id.unwrap_or_else(Uuid::new_v4);
    if contradiction_ids.contains(&id) {
        return Err(ApiError::bad_request(
            "claim cannot reference its own id in contradiction_ids",
        ));
    }
    if !contradiction_ids.is_empty() {
        let found_contra =
            claims_repo::fetch_claims_by_ids(&state.pool, &req.tenant_id, &contradiction_ids)
                .await?;
        for cid in &contradiction_ids {
            match found_contra.iter().find(|c| c.id == *cid) {
                None => {
                    return Err(ApiError::bad_request(format!(
                        "contradicted claim {cid} not found in scope '{}'",
                        req.scope
                    )));
                }
                Some(c) if c.scope != req.scope => {
                    return Err(ApiError::bad_request(format!(
                        "contradicted claim {cid} not found in scope '{}'",
                        req.scope
                    )));
                }
                Some(_) => {}
            }
        }
    }

    let claim_group_key = compute_logical_claim_group_key(
        &req.tenant_id,
        &req.subject,
        &req.predicate,
        &req.scope,
    );

    let created_at = Utc::now().trunc_subsecs(6);
    let allow_auto_supersede = req.predecessor_id.is_none() && parsed_sig_pair.is_none();

    let mut claim = KnowledgeClaim {
        id,
        tenant_id: req.tenant_id.clone(),
        claim_group_key,
        scope: req.scope.clone(),
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
        contradiction_ids,
        valid_from,
        valid_to,
        version,
        predecessor_id: req.predecessor_id,
        client_signature: None,
        client_public_key: None,
        retraction_reason: None,
        written_by: None,
        evidence_seq_num: None,
        created_at,
    };

    let content_hash = compute_claim_content_hash(&claim)?;
    claim.content_hash = content_hash;

    if let Some((sig_arr, pk_arr)) = parsed_sig_pair {
        let intent_hash = compute_claim_client_intent_hash(
            &claim.tenant_id,
            &claim.scope,
            &claim.subject,
            &claim.predicate,
            &claim.object_val,
            &claim.object_type,
            claim.confidence,
            claim.source_provenance_class,
            &claim.source_descriptor,
            &claim.source_commitment,
            claim.status,
            &claim.contradiction_ids,
            claim.valid_from,
            claim.valid_to,
            claim.predecessor_id,
        )?;
        if !verify_client_content_signature(&pk_arr, &intent_hash, &sig_arr)
            && !verify_client_content_signature(&pk_arr, &content_hash, &sig_arr)
        {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "ingest_claim",
                    "invalid_client_content_signature",
                    Some(&req.scope),
                    "client Ed25519 signature verification failed on ingest_claim",
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::bad_request(format!(
                "client Ed25519 signature verification failed over claim intent digest or content_hash{suffix}"
            )));
        }
        claim.client_signature = Some(sig_arr.to_vec());
        claim.client_public_key = Some(pk_arr);
    }

    let (written_by, writer_auth_kind) =
        resolve_writer_identity(&caller_auth, &req.tenant_id, claim.client_signature.is_some());

    let (persisted, ev_opt, was_idempotent_noop) =
        claims_repo::insert_or_supersede_claim_with_evidence_tx(
            &state.pool,
            &state.host_signing_key,
            claim,
            allow_auto_supersede,
            &written_by,
            writer_auth_kind,
        )
        .await?;

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
            status: persisted.status,
            claim_group_key: hex::encode(persisted.claim_group_key),
            source_commitment: hex::encode(persisted.source_commitment),
            content_hash: hex::encode(persisted.content_hash),
            predecessor_id: persisted.predecessor_id,
            contradiction_ids: persisted.contradiction_ids,
            valid_from: persisted.valid_from,
            valid_to: persisted.valid_to,
            evidence_seq_num: ev_opt.as_ref().map(|e| e.seq_num).or(persisted.evidence_seq_num),
            evidence_event_hash: ev_opt.as_ref().map(|e| hex::encode(e.event_hash)),
            host_signature: ev_opt.as_ref().map(|e| hex::encode(e.host_signature)),
            client_public_key_hex: persisted.client_public_key.map(hex::encode),
            written_by: persisted.written_by,
            was_idempotent_noop,
            created_at: persisted.created_at,
        }),
    ))
}

/// `POST /v1/claims/retract` -> Appends an immutable `status='revoked'` tombstone retiring `claim_id`
/// (`predecessor_id = claim_id`) and notarizing `WriteOperationKind::RetractClaim` on `evidence_history`.
pub async fn handle_retract_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RetractClaimRequest>,
) -> Result<(StatusCode, Json<RetractClaimResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "retract_claim")
        .await
        .map_err(ApiError::unauthorized)?;
    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_justification(&req.reason)?;

    let parsed_sig_pair = parse_optional_client_sig_pair(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
    )?;

    let target_claim = claims_repo::fetch_claim_by_id(&state.pool, &req.tenant_id, req.claim_id)
        .await?
        .ok_or_else(|| {
            ApiError::from(acta_types::ActaError::NotFound(format!(
                "claim {} not found",
                req.claim_id
            )))
        })?;

    enforce_policy_before_write(
        &state,
        &headers,
        &req.tenant_id,
        &target_claim.scope,
        "retract_claim",
    )
    .await?;

    let mut client_signature = None;
    let mut client_public_key = None;
    if let Some((sig_arr, pk_arr)) = parsed_sig_pair {
        let retract_intent =
            compute_retract_claim_client_intent_hash(&req.tenant_id, req.claim_id, &req.reason);
        if !verify_client_content_signature(&pk_arr, &retract_intent, &sig_arr) {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "retract_claim",
                    "invalid_client_content_signature",
                    Some(&target_claim.scope),
                    "client Ed25519 signature verification failed on retract_claim",
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::bad_request(format!(
                "client Ed25519 signature verification failed over retract_claim intent digest{suffix}"
            )));
        }
        client_signature = Some(sig_arr.to_vec());
        client_public_key = Some(pk_arr);
    }

    let (retracted_by, writer_auth_kind) =
        resolve_writer_identity(&caller_auth, &req.tenant_id, client_signature.is_some());

    let tombstone_id = req.id.unwrap_or_else(Uuid::new_v4);
    let created_at = Utc::now().trunc_subsecs(6);

    let (tombstone, ev, was_idempotent_noop) = claims_repo::retract_claim_with_evidence_tx(
        &state.pool,
        &state.host_signing_key,
        &req.tenant_id,
        req.claim_id,
        tombstone_id,
        &req.reason,
        &retracted_by,
        writer_auth_kind,
        client_signature,
        client_public_key,
        created_at,
    )
    .await?;

    let status_code = if was_idempotent_noop {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((
        status_code,
        Json(RetractClaimResponse {
            tombstone_id: tombstone.id,
            retracted_claim_id: req.claim_id,
            scope: tombstone.scope,
            subject: tombstone.subject,
            predicate: tombstone.predicate,
            version: tombstone.version,
            status: tombstone.status,
            reason: req.reason,
            content_hash: hex::encode(tombstone.content_hash),
            evidence_seq_num: ev.seq_num,
            evidence_event_hash: hex::encode(ev.event_hash),
            host_signature: hex::encode(ev.host_signature),
            client_public_key_hex: tombstone.client_public_key.map(hex::encode),
            retracted_by,
            was_idempotent_noop,
            created_at: tombstone.created_at,
        }),
    ))
}
