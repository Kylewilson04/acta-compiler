use acta_crypto::{
    compute_answer_cache_client_intent_hash, compute_answer_text_hash, compute_query_text_hash,
    verify_answer_cache_signature, verify_client_content_signature,
};
use acta_policy::PolicyAction;
use acta_store::{
    answer_cache_repo::{self, NewCachedAnswerInput},
    evidence_repo::{self, TenantLookupScope},
    impact_repo,
};
use acta_types::{
    validate_identifier, validate_json_payload_size, validate_query_text, validate_scope,
    CacheAnswerRequest, CacheAnswerResponse, LedgerStateRebuildResponse, LookupCachedAnswerRequest,
    LookupCachedAnswerResponse, PolicyDecision, PolicyResultTag, TraceItemImpactResponse,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{Duration, SubsecRound, Utc};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::{
    ingest::{
        enforce_policy_before_write, parse_optional_client_sig_pair, resolve_writer_identity,
    },
    ApiError,
};
use crate::state::AppState;

const MAX_ANSWER_TEXT_BYTES: usize = 128 * 1024;
const MAX_TTL_SECONDS: u64 = 365 * 86_400;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RebuildStateQueryParams {
    pub scope: Option<String>,
    pub up_to_seq: Option<i64>,
    #[serde(default)]
    pub include_proof_archive: Option<bool>,
}

/// `POST /v1/answers/cache` -> Persists a state- or dependency-conditioned cached answer bound to a
/// verified `ContextBundle` and notarizes `AnswerCacheLedgerSummary` on `evidence_history` (PPA 1 Claims 19–27).
/// In `v1.7.1+`, `validity_mode` defaults to `"dependency_subset"` (PPA 1 Claim 25) so unrelated writes
/// in the same scope do not invalidate cached answers; callers may also select `"scope_root"`.
pub async fn handle_cache_answer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CacheAnswerRequest>,
) -> Result<(StatusCode, Json<CacheAnswerResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "cache_answer")
        .await
        .map_err(ApiError::unauthorized)?;
    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    if let Some(ref sc) = req.scope {
        if !sc.trim().is_empty() {
            validate_scope(sc)?;
        }
    }
    if let Some(ref tid) = req.task_id {
        if !tid.trim().is_empty() {
            validate_identifier("task_id", tid)?;
        }
    }
    let query_text = req.query_text.as_deref().unwrap_or("");
    validate_query_text(query_text)?;

    let validity_mode = match req
        .validity_mode
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None | Some("dependency_subset") => "dependency_subset",
        Some("scope_root") => "scope_root",
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "invalid validity_mode '{other}' (expected 'dependency_subset' or 'scope_root')"
            )))
        }
    };

    if req.answer_text.is_empty() {
        return Err(ApiError::bad_request("answer_text must be non-empty"));
    }
    if req.answer_text.len() > MAX_ANSWER_TEXT_BYTES {
        return Err(ApiError::bad_request(format!(
            "answer_text exceeds maximum size of {MAX_ANSWER_TEXT_BYTES} bytes"
        )));
    }
    if req.answer_text.contains('\0') {
        return Err(ApiError::bad_request(
            "answer_text must not contain NUL bytes",
        ));
    }
    if let Some(ref meta) = req.answer_metadata {
        validate_json_payload_size("answer_metadata", meta)?;
    }

    let expires_offset = match req.ttl_seconds {
        Some(0) => {
            return Err(ApiError::bad_request(
                "ttl_seconds must be >= 1 when specified",
            ))
        }
        Some(secs) if secs > MAX_TTL_SECONDS => {
            return Err(ApiError::bad_request(format!(
                "ttl_seconds ({secs}) exceeds maximum of {MAX_TTL_SECONDS}"
            )))
        }
        Some(secs) => Some(Duration::seconds(secs as i64)),
        None => None,
    };

    let raw_bh = hex::decode(req.source_bundle_hash.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid source_bundle_hash hex: {e}")))?;
    let source_bundle_hash: [u8; 32] = raw_bh.try_into().map_err(|_| {
        ApiError::bad_request("source_bundle_hash must be 32 bytes (64 hex chars)")
    })?;

    let parsed_sig_pair = parse_optional_client_sig_pair(
        req.client_signature_hex.as_deref(),
        req.client_public_key_hex.as_deref(),
    )?;

    // Zero-oracle bundle lookup scoped strictly to req.tenant_id!
    let (source_bundle, _) = evidence_repo::fetch_bundle_with_evidence_slice_scoped(
        &state.pool,
        TenantLookupScope::Exact(&req.tenant_id),
        &source_bundle_hash,
    )
    .await?;

    enforce_policy_before_write(
        &state,
        &headers,
        &req.tenant_id,
        &source_bundle.scope,
        "cache_answer",
    )
    .await?;

    let query_hash = compute_query_text_hash(query_text);
    let answer_hash = compute_answer_text_hash(&req.answer_text);

    let mut client_signature = None;
    let mut client_public_key = None;
    if let Some((sig_arr, pk_arr)) = parsed_sig_pair {
        let intent_hash = compute_answer_cache_client_intent_hash(
            &req.tenant_id,
            &source_bundle.scope,
            &source_bundle.task_id,
            &query_hash,
            &source_bundle_hash,
            &source_bundle.state_commitment,
            &answer_hash,
        );
        if !verify_client_content_signature(&pk_arr, &intent_hash, &sig_arr)
            && !verify_client_content_signature(&pk_arr, &answer_hash, &sig_arr)
        {
            let suffix = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "cache_answer",
                    "invalid_client_content_signature",
                    Some(&source_bundle.scope),
                    "client Ed25519 signature verification failed on cache_answer",
                )
                .await
                .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                .unwrap_or_default();
            return Err(ApiError::bad_request(format!(
                "client Ed25519 signature verification failed over answer cache intent digest or answer_hash{suffix}"
            )));
        }
        client_signature = Some(sig_arr.to_vec());
        client_public_key = Some(pk_arr);
    }

    let (cached_by, cacher_auth_kind) =
        resolve_writer_identity(&caller_auth, &req.tenant_id, client_signature.is_some());
    let created_at = Utc::now().trunc_subsecs(6);
    let expires_at = expires_offset.map(|d| created_at + d);
    let permission_root = state.policy_gate.permission_root();

    let (receipt, evidence, was_idempotent_noop) = answer_cache_repo::cache_answer_tx(
        &state.pool,
        &state.host_signing_key,
        NewCachedAnswerInput {
            id: req.id.unwrap_or_else(Uuid::new_v4),
            tenant_id: &req.tenant_id,
            explicit_scope: req.scope.as_deref(),
            explicit_task_id: req.task_id.as_deref(),
            query_text,
            source_bundle_hash: &source_bundle_hash,
            validity_mode,
            explicit_dependency_ids: req.dependency_ids.as_deref(),
            permission_root: &permission_root,
            answer_text: &req.answer_text,
            answer_metadata: req.answer_metadata,
            cached_by: &cached_by,
            cacher_auth_kind,
            client_public_key,
            client_signature,
            expires_at,
            created_at,
        },
    )
    .await?;

    let status_code = if was_idempotent_noop {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    Ok((status_code, Json(CacheAnswerResponse { receipt, evidence })))
}

/// `POST /v1/answers/lookup` -> Enforces Policy-Before-Read, evaluates Claim 25 `dependency_subset`
/// or `scope_root` validity without scanning historical bundles, re-verifies `answer_hash` and
/// `host_signature`, and atomically chains a one-time invalidation receipt (`event_kind = "invalidated"`)
/// on `evidence_history` when a cached answer becomes stale or TTL-expired (`v1.7.1+`).
pub async fn handle_lookup_cached_answer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LookupCachedAnswerRequest>,
) -> Result<(StatusCode, Json<LookupCachedAnswerResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "lookup_cached_answer")
        .await
        .map_err(ApiError::unauthorized)?;
    let caller_auth = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_scope(&req.scope)?;
    validate_identifier("task_id", &req.task_id)?;

    let actor_id = match req.actor_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            validate_identifier("actor_id", raw)?;
            if let Some((explicit_tenant, _)) = raw.split_once("::") {
                if explicit_tenant != req.tenant_id {
                    let ev = state
                        .append_refusal_audit_with_scope(
                            &headers,
                            Some(&req.tenant_id),
                            PolicyResultTag::Block,
                            "lookup_cached_answer",
                            "actor_tenant_mismatch",
                            Some(&req.scope),
                            &format!(
                                "actor_id '{raw}' belongs to tenant '{explicit_tenant}', cannot lookup in '{}'",
                                req.tenant_id
                            ),
                        )
                        .await;
                    let suffix = ev
                        .map(|e| format!(" [logged at evidence seq_num={}]", e.seq_num))
                        .unwrap_or_default();
                    return Err(ApiError::forbidden(format!(
                        "actor_id '{raw}' belongs to tenant '{explicit_tenant}'{suffix}"
                    )));
                }
                raw.to_string()
            } else {
                format!("{}::{raw}", req.tenant_id)
            }
        }
        None => format!("{}::cache-reader", req.tenant_id),
    };

    let query_text = req.query_text.as_deref().unwrap_or("");
    validate_query_text(query_text)?;

    // Policy-Before-Read gate!
    let (policy_decision, permission_root) = state.policy_gate.evaluate_action(
        &req.tenant_id,
        &actor_id,
        &req.task_id,
        &req.scope,
        PolicyAction::Compile,
    );

    match &policy_decision {
        PolicyDecision::Block { reason } => {
            let ev_seq = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Block,
                    "lookup_cached_answer",
                    "lookup_cached_answer_policy_block",
                    Some(&req.scope),
                    &format!(
                        "policy denied cached answer lookup on scope '{}': {reason}",
                        req.scope
                    ),
                )
                .await
                .map(|e| e.seq_num);
            return Ok((
                StatusCode::FORBIDDEN,
                Json(LookupCachedAnswerResponse {
                    cache_hit: false,
                    status: "policy_blocked".to_string(),
                    policy_decision,
                    validity_mode: None,
                    current_state_commitment: None,
                    stored_state_commitment: None,
                    state_commitment_matches: None,
                    current_task_dependency_commitment: None,
                    stored_task_dependency_commitment: None,
                    task_dependency_commitment_matches: None,
                    answer_hash_verified: None,
                    answer_text: None,
                    answer_metadata: None,
                    receipt: None,
                    invalidation_evidence_seq_num: None,
                    invalidation_newly_recorded: None,
                    refusal_evidence_seq_num: ev_seq,
                }),
            ));
        }
        PolicyDecision::Escalate { reason } => {
            let ev_seq = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.tenant_id),
                    PolicyResultTag::Escalate,
                    "lookup_cached_answer",
                    "lookup_cached_answer_policy_escalate",
                    Some(&req.scope),
                    &format!(
                        "policy escalated cached answer lookup on restricted scope '{}': {reason}",
                        req.scope
                    ),
                )
                .await
                .map(|e| e.seq_num);
            return Ok((
                StatusCode::ACCEPTED,
                Json(LookupCachedAnswerResponse {
                    cache_hit: false,
                    status: "policy_escalated".to_string(),
                    policy_decision,
                    validity_mode: None,
                    current_state_commitment: None,
                    stored_state_commitment: None,
                    state_commitment_matches: None,
                    current_task_dependency_commitment: None,
                    stored_task_dependency_commitment: None,
                    task_dependency_commitment_matches: None,
                    answer_hash_verified: None,
                    answer_text: None,
                    answer_metadata: None,
                    receipt: None,
                    invalidation_evidence_seq_num: None,
                    invalidation_newly_recorded: None,
                    refusal_evidence_seq_num: ev_seq,
                }),
            ));
        }
        PolicyDecision::Allow => {}
    }

    let now = Utc::now().trunc_subsecs(6);
    let current_sc = answer_cache_repo::compute_live_scope_state_commitment(
        &state.pool,
        &req.tenant_id,
        &req.scope,
        &permission_root,
        now,
    )
    .await?;
    let current_sc_hex = hex::encode(current_sc);

    let Some(stored) = answer_cache_repo::lookup_latest_cached_answer(
        &state.pool,
        &req.tenant_id,
        &req.scope,
        &req.task_id,
        query_text,
    )
    .await?
    else {
        return Ok((
            StatusCode::OK,
            Json(LookupCachedAnswerResponse {
                cache_hit: false,
                status: "miss_not_found".to_string(),
                policy_decision: PolicyDecision::Allow,
                validity_mode: None,
                current_state_commitment: Some(current_sc_hex),
                stored_state_commitment: None,
                state_commitment_matches: None,
                current_task_dependency_commitment: None,
                stored_task_dependency_commitment: None,
                task_dependency_commitment_matches: None,
                answer_hash_verified: None,
                answer_text: None,
                answer_metadata: None,
                receipt: None,
                invalidation_evidence_seq_num: None,
                invalidation_newly_recorded: None,
                refusal_evidence_seq_num: None,
            }),
        ));
    };

    // PPA 1 Claim 22 & Claim 23: Recompute answer_hash and verify host receipt signature before serving!
    let recomputed_ah = compute_answer_text_hash(&stored.answer_text);
    let vk = VerifyingKey::from_bytes(&state.host_public_key)
        .map_err(|e| ApiError::bad_request(format!("host key error: {e}")))?;
    let receipt_sig_ok = verify_answer_cache_signature(
        &vk,
        &req.tenant_id,
        stored.receipt.evidence_seq_num,
        &stored.cache_commitment_bytes,
        &stored.host_signature_bytes,
    );

    let mode = stored.receipt.validity_mode.clone();
    let sc_matches = stored.state_commitment_bytes == current_sc;

    if recomputed_ah != stored.answer_hash_bytes || !receipt_sig_ok {
        let ev_seq = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&req.tenant_id),
                PolicyResultTag::Block,
                "lookup_cached_answer",
                "answer_cache_hash_mismatch",
                Some(&req.scope),
                &format!(
                    "cached answer {} failed cryptographic integrity check (hash_ok={}, sig_ok={})",
                    stored.receipt.cache_id,
                    recomputed_ah == stored.answer_hash_bytes,
                    receipt_sig_ok
                ),
            )
            .await
            .map(|e| e.seq_num);
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(LookupCachedAnswerResponse {
                cache_hit: false,
                status: "rejected_answer_hash_mismatch".to_string(),
                policy_decision: PolicyDecision::Allow,
                validity_mode: Some(mode),
                current_state_commitment: Some(current_sc_hex),
                stored_state_commitment: Some(stored.receipt.state_commitment),
                state_commitment_matches: Some(sc_matches),
                current_task_dependency_commitment: None,
                stored_task_dependency_commitment: stored.receipt.task_dependency_commitment,
                task_dependency_commitment_matches: None,
                answer_hash_verified: Some(false),
                answer_text: None,
                answer_metadata: None,
                receipt: None,
                invalidation_evidence_seq_num: None,
                invalidation_newly_recorded: None,
                refusal_evidence_seq_num: ev_seq,
            }),
        ));
    }

    let (invalidated_by, invalidator_auth_kind) =
        resolve_writer_identity(&caller_auth, &req.tenant_id, false);

    let (current_tdc_opt, tdc_matches_opt) = if mode == "dependency_subset" {
        if let (Some(stored_tdc), Some(ref spec)) =
            (stored.task_dependency_commitment_bytes, &stored.dependency_spec)
        {
            let live_tdc = answer_cache_repo::compute_scoped_task_dependency_commitment_as_of(
                &state.pool,
                &req.tenant_id,
                &req.scope,
                &permission_root,
                spec,
                now,
                None,
            )
            .await?;
            (Some(live_tdc), Some(stored_tdc == live_tdc))
        } else {
            (None, Some(sc_matches))
        }
    } else {
        (None, None)
    };

    let current_tdc_hex = current_tdc_opt.map(hex::encode);
    let stored_tdc_hex = stored.receipt.task_dependency_commitment.clone();
    let stored_sc_hex = stored.receipt.state_commitment.clone();

    if mode == "dependency_subset" && tdc_matches_opt == Some(false) {
        let (inv_seq, inv_new) = answer_cache_repo::record_cache_invalidation_once_tx(
            &state.pool,
            &state.host_signing_key,
            &stored,
            "stale_dependency_commitment",
            &current_sc,
            current_tdc_opt.as_ref(),
            &invalidated_by,
            invalidator_auth_kind,
            now,
        )
        .await?;
        return Ok((
            StatusCode::OK,
            Json(LookupCachedAnswerResponse {
                cache_hit: false,
                status: "stale_dependency_commitment".to_string(),
                policy_decision: PolicyDecision::Allow,
                validity_mode: Some(mode),
                current_state_commitment: Some(current_sc_hex),
                stored_state_commitment: Some(stored_sc_hex),
                state_commitment_matches: Some(sc_matches),
                current_task_dependency_commitment: current_tdc_hex,
                stored_task_dependency_commitment: stored_tdc_hex,
                task_dependency_commitment_matches: Some(false),
                answer_hash_verified: Some(true),
                answer_text: None,
                answer_metadata: None,
                receipt: None,
                invalidation_evidence_seq_num: Some(inv_seq),
                invalidation_newly_recorded: Some(inv_new),
                refusal_evidence_seq_num: None,
            }),
        ));
    }

    if mode != "dependency_subset" && !sc_matches {
        let (inv_seq, inv_new) = answer_cache_repo::record_cache_invalidation_once_tx(
            &state.pool,
            &state.host_signing_key,
            &stored,
            "stale_state_commitment",
            &current_sc,
            None,
            &invalidated_by,
            invalidator_auth_kind,
            now,
        )
        .await?;
        return Ok((
            StatusCode::OK,
            Json(LookupCachedAnswerResponse {
                cache_hit: false,
                status: "stale_state_commitment".to_string(),
                policy_decision: PolicyDecision::Allow,
                validity_mode: Some(mode),
                current_state_commitment: Some(current_sc_hex),
                stored_state_commitment: Some(stored_sc_hex),
                state_commitment_matches: Some(false),
                current_task_dependency_commitment: None,
                stored_task_dependency_commitment: None,
                task_dependency_commitment_matches: None,
                answer_hash_verified: Some(true),
                answer_text: None,
                answer_metadata: None,
                receipt: None,
                invalidation_evidence_seq_num: Some(inv_seq),
                invalidation_newly_recorded: Some(inv_new),
                refusal_evidence_seq_num: None,
            }),
        ));
    }

    if stored.receipt.expires_at.is_some_and(|exp| now > exp) {
        let (inv_seq, inv_new) = answer_cache_repo::record_cache_invalidation_once_tx(
            &state.pool,
            &state.host_signing_key,
            &stored,
            "expired_ttl",
            &current_sc,
            current_tdc_opt.as_ref(),
            &invalidated_by,
            invalidator_auth_kind,
            now,
        )
        .await?;
        return Ok((
            StatusCode::OK,
            Json(LookupCachedAnswerResponse {
                cache_hit: false,
                status: "expired_ttl".to_string(),
                policy_decision: PolicyDecision::Allow,
                validity_mode: Some(mode),
                current_state_commitment: Some(current_sc_hex),
                stored_state_commitment: Some(stored_sc_hex),
                state_commitment_matches: Some(sc_matches),
                current_task_dependency_commitment: current_tdc_hex,
                stored_task_dependency_commitment: stored_tdc_hex,
                task_dependency_commitment_matches: tdc_matches_opt,
                answer_hash_verified: Some(true),
                answer_text: None,
                answer_metadata: None,
                receipt: None,
                invalidation_evidence_seq_num: Some(inv_seq),
                invalidation_newly_recorded: Some(inv_new),
                refusal_evidence_seq_num: None,
            }),
        ));
    }

    Ok((
        StatusCode::OK,
        Json(LookupCachedAnswerResponse {
            cache_hit: true,
            status: "hit".to_string(),
            policy_decision: PolicyDecision::Allow,
            validity_mode: Some(mode),
            current_state_commitment: Some(current_sc_hex),
            stored_state_commitment: Some(stored_sc_hex),
            state_commitment_matches: Some(sc_matches),
            current_task_dependency_commitment: current_tdc_hex,
            stored_task_dependency_commitment: stored_tdc_hex,
            task_dependency_commitment_matches: tdc_matches_opt,
            answer_hash_verified: Some(true),
            answer_text: Some(stored.answer_text),
            answer_metadata: stored.answer_metadata,
            receipt: Some(stored.receipt),
            invalidation_evidence_seq_num: None,
            invalidation_newly_recorded: None,
            refusal_evidence_seq_num: None,
        }),
    ))
}

/// `GET /v1/tenants/:tenant_id/impact/:item_id` -> Indexed reverse decision-recall (`bundle_dependencies`).
pub async fn handle_trace_item_impact(
    State(state): State<AppState>,
    Path((tenant_id, raw_item_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<TraceItemImpactResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "trace_item_impact")
        .await
        .map_err(ApiError::unauthorized)?;
    validate_identifier("tenant_id", clean_tenant)?;

    let item_id = Uuid::parse_str(raw_item_id.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid item_id UUID '{raw_item_id}': {e}")))?;

    let report = impact_repo::trace_item_impact(
        &state.pool,
        clean_tenant,
        item_id,
        &state.policy_gate.permission_root(),
    )
    .await?;
    Ok(Json(report))
}

/// `GET /v1/tenants/:tenant_id/state-rebuild?scope=...&up_to_seq=...&include_proof_archive=...` ->
/// Cryptographically verifies `evidence_history` and rebuilds `scope` state + `state_commitment`
/// from chain events alone, optionally returning a portable `StateRebuildArchive` (`v1.7.1+`).
pub async fn handle_rebuild_scope_state(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<RebuildStateQueryParams>,
    headers: HeaderMap,
) -> Result<Json<LedgerStateRebuildResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "rebuild_scope_state")
        .await
        .map_err(ApiError::unauthorized)?;
    validate_identifier("tenant_id", clean_tenant)?;

    let scope = query
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing required query parameter 'scope'"))?;
    validate_scope(scope)?;

    if let Some(seq) = query.up_to_seq {
        if seq < 1 {
            return Err(ApiError::bad_request("up_to_seq must be >= 1"));
        }
    }

    let report = impact_repo::rebuild_scope_state_from_ledger(
        &state.pool,
        &state.host_signing_key,
        &state.host_public_key,
        clean_tenant,
        scope,
        &state.policy_gate.permission_root(),
        query.up_to_seq,
        query.include_proof_archive.unwrap_or(false),
    )
    .await?;
    Ok(Json(report))
}
