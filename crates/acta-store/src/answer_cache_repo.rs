use std::collections::BTreeSet;

use acta_crypto::{
    compute_answer_cache_summary_commitment, compute_answer_text_hash,
    compute_evidence_event_hash_full, compute_logical_claim_group_key, compute_query_text_hash,
    compute_state_commitment, compute_sub_commitment, compute_task_dependency_commitment,
    sign_answer_cache_receipt, sign_evidence_entry,
};
pub use acta_types::CacheDependencySpec;
use acta_types::{
    ActaError, ActaResult, AnswerCacheLedgerSummary, CachedAnswerReceipt, ClaimStatus,
    ContextBundle, EvidenceEntry, ObjectType, PolicyResultTag, ANSWER_CACHE_DOMAIN_V1,
    SCHEMA_VERSION,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    claims_repo,
    evidence_repo::{fetch_evidence_by_seq, lock_and_read_latest_evidence_tx},
    objects_repo, overrides_repo,
};


pub struct NewCachedAnswerInput<'a> {
    pub id: Uuid,
    pub tenant_id: &'a str,
    pub explicit_scope: Option<&'a str>,
    pub explicit_task_id: Option<&'a str>,
    pub query_text: &'a str,
    pub source_bundle_hash: &'a [u8; 32],
    pub validity_mode: &'a str,
    pub explicit_dependency_ids: Option<&'a [Uuid]>,
    pub permission_root: &'a [u8; 32],
    pub answer_text: &'a str,
    pub answer_metadata: Option<Value>,
    pub cached_by: &'a str,
    pub cacher_auth_kind: &'a str,
    pub client_public_key: Option<[u8; 32]>,
    pub client_signature: Option<Vec<u8>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct StoredCachedAnswer {
    pub receipt: CachedAnswerReceipt,
    pub query_hash_bytes: [u8; 32],
    pub source_bundle_hash_bytes: [u8; 32],
    pub state_commitment_bytes: [u8; 32],
    pub task_dependency_commitment_bytes: Option<[u8; 32]>,
    pub dependency_spec: Option<CacheDependencySpec>,
    pub answer_hash_bytes: [u8; 32],
    pub cache_commitment_bytes: [u8; 32],
    pub host_signature_bytes: [u8; 64],
    pub answer_text: String,
    pub answer_metadata: Option<Value>,
}

#[derive(FromRow)]
struct CachedAnswerRow {
    id: Uuid,
    tenant_id: String,
    scope: String,
    task_id: String,
    query_hash: Vec<u8>,
    source_bundle_hash: Vec<u8>,
    state_commitment: Vec<u8>,
    validity_mode: String,
    task_dependency_commitment: Option<Vec<u8>>,
    dependency_spec: Option<Value>,
    answer_hash: Vec<u8>,
    answer_text: String,
    answer_metadata: Option<Value>,
    cached_by: String,
    cacher_auth_kind: String,
    client_public_key: Option<Vec<u8>>,
    cache_domain: String,
    cache_commitment: Vec<u8>,
    evidence_seq_num: i64,
    host_signature: Vec<u8>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl CachedAnswerRow {
    fn into_stored(self) -> ActaResult<StoredCachedAnswer> {
        let qh: [u8; 32] = self
            .query_hash
            .try_into()
            .map_err(|_| ActaError::Storage("cached_answers.query_hash not 32 bytes".to_string()))?;
        let sbh: [u8; 32] = self.source_bundle_hash.try_into().map_err(|_| {
            ActaError::Storage("cached_answers.source_bundle_hash not 32 bytes".to_string())
        })?;
        let sc: [u8; 32] = self.state_commitment.try_into().map_err(|_| {
            ActaError::Storage("cached_answers.state_commitment not 32 bytes".to_string())
        })?;
        let tdc: Option<[u8; 32]> = self
            .task_dependency_commitment
            .map(|raw| {
                raw.try_into().map_err(|_| {
                    ActaError::Storage(
                        "cached_answers.task_dependency_commitment not 32 bytes".to_string(),
                    )
                })
            })
            .transpose()?;
        let dep_spec: Option<CacheDependencySpec> = self
            .dependency_spec
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ActaError::Storage(format!("cached_answers.dependency_spec parse failed: {e}"))
                })
            })
            .transpose()?;
        let ah: [u8; 32] = self
            .answer_hash
            .try_into()
            .map_err(|_| ActaError::Storage("cached_answers.answer_hash not 32 bytes".to_string()))?;
        let cc: [u8; 32] = self.cache_commitment.try_into().map_err(|_| {
            ActaError::Storage("cached_answers.cache_commitment not 32 bytes".to_string())
        })?;
        let hsig: [u8; 64] = self.host_signature.try_into().map_err(|_| {
            ActaError::Storage("cached_answers.host_signature not 64 bytes".to_string())
        })?;
        let cpk_hex = match self.client_public_key {
            Some(raw) => {
                let arr: [u8; 32] = raw.try_into().map_err(|_| {
                    ActaError::Storage("cached_answers.client_public_key not 32 bytes".to_string())
                })?;
                Some(hex::encode(arr))
            }
            None => None,
        };

        Ok(StoredCachedAnswer {
            receipt: CachedAnswerReceipt {
                cache_id: self.id,
                tenant_id: self.tenant_id,
                scope: self.scope,
                task_id: self.task_id,
                query_hash: hex::encode(qh),
                source_bundle_hash: hex::encode(sbh),
                state_commitment: hex::encode(sc),
                validity_mode: self.validity_mode,
                task_dependency_commitment: tdc.map(hex::encode),
                answer_hash: hex::encode(ah),
                cache_domain: self.cache_domain,
                cache_commitment: hex::encode(cc),
                evidence_seq_num: self.evidence_seq_num,
                host_signature: hex::encode(hsig),
                cached_by: self.cached_by,
                cacher_auth_kind: self.cacher_auth_kind,
                client_public_key_hex: cpk_hex,
                expires_at: self.expires_at,
                created_at: self.created_at,
            },
            query_hash_bytes: qh,
            source_bundle_hash_bytes: sbh,
            state_commitment_bytes: sc,
            task_dependency_commitment_bytes: tdc,
            dependency_spec: dep_spec,
            answer_hash_bytes: ah,
            cache_commitment_bytes: cc,
            host_signature_bytes: hsig,
            answer_text: self.answer_text,
            answer_metadata: self.answer_metadata,
        })
    }
}

/// Extracts the canonical `CacheDependencySpec` from `source_bundle` (optionally narrowed by `explicit_dependency_ids`).
pub fn build_dependency_spec_from_bundle(
    source_bundle: &ContextBundle,
    explicit_dependency_ids: Option<&[Uuid]>,
) -> ActaResult<CacheDependencySpec> {
    let explicit_filter: Option<BTreeSet<Uuid>> = explicit_dependency_ids
        .filter(|ids| !ids.is_empty())
        .map(|ids| ids.iter().copied().collect());

    let mut bundle_item_ids = BTreeSet::new();
    for sel in &source_bundle.selected_objects {
        bundle_item_ids.insert(sel.id);
    }
    for res in &source_bundle.resolution_records {
        bundle_item_ids.insert(res.winning_claim.id);
        for &sid in &res.suppressed_claim_ids {
            bundle_item_ids.insert(sid);
        }
    }
    for disp in &source_bundle.dispute_records {
        for cand in &disp.competing_claims {
            bundle_item_ids.insert(cand.id);
        }
    }

    if let Some(ref fset) = explicit_filter {
        for id in fset {
            if !bundle_item_ids.contains(id) {
                return Err(ActaError::Validation(format!(
                    "dependency_ids item {id} was not referenced in source_bundle_hash"
                )));
            }
        }
    }

    let mut group_keys = BTreeSet::new();
    for res in &source_bundle.resolution_records {
        let include = match explicit_filter {
            Some(ref fset) => {
                fset.contains(&res.winning_claim.id)
                    || res.suppressed_claim_ids.iter().any(|id| fset.contains(id))
            }
            None => true,
        };
        if include {
            group_keys.insert(compute_logical_claim_group_key(
                &source_bundle.tenant_id,
                &res.winning_claim.subject,
                &res.winning_claim.predicate,
                &source_bundle.scope,
            ));
        }
    }
    for disp in &source_bundle.dispute_records {
        let include = match explicit_filter {
            Some(ref fset) => disp.competing_claims.iter().any(|c| fset.contains(&c.id)),
            None => true,
        };
        if include {
            if let Some(first) = disp.competing_claims.first() {
                group_keys.insert(compute_logical_claim_group_key(
                    &source_bundle.tenant_id,
                    &first.subject,
                    &first.predicate,
                    &source_bundle.scope,
                ));
            }
        }
    }

    let mut memory_ids: Vec<Uuid> = source_bundle
        .selected_objects
        .iter()
        .filter(|o| o.obj_type == ObjectType::Memory)
        .filter(|o| explicit_filter.as_ref().map_or(true, |fset| fset.contains(&o.id)))
        .map(|o| o.id)
        .collect();
    memory_ids.sort_unstable();
    memory_ids.dedup();

    let empty_knowledge_fallback = explicit_filter.is_none()
        && source_bundle.resolution_records.is_empty()
        && source_bundle.dispute_records.is_empty();

    Ok(CacheDependencySpec {
        claim_group_keys_hex: group_keys.into_iter().map(hex::encode).collect(),
        memory_ids,
        empty_knowledge_fallback,
    })
}

/// Computes the PPA 1 Claim 25 `task_dependency_commitment` (`b"acta:cache_dep_root:v1"`)
/// as-of `as_of` (`None` for live vault state, `Some(bundle.issued_at)` when pinning at bundle compile time).
pub async fn compute_scoped_task_dependency_commitment_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    permission_root: &[u8; 32],
    spec: &CacheDependencySpec,
    eval_ts: DateTime<Utc>,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<[u8; 32]> {
    let eval_ts = eval_ts.trunc_subsecs(6);
    let as_of = as_of.map(|t| t.trunc_subsecs(6));
    let group_set = spec.parsed_group_keys()?;
    let mem_id_set: BTreeSet<Uuid> = spec.memory_ids.iter().copied().collect();

    let (intents, obj_scan, (scoped_claims, _sup), active_overrides) = tokio::try_join!(
        objects_repo::fetch_scoped_intents_as_of(pool, tenant_id, scope, as_of),
        objects_repo::fetch_all_active_hashes_in_scope_as_of(pool, tenant_id, scope, as_of),
        claims_repo::fetch_scoped_claims_as_of(pool, tenant_id, scope, as_of),
        overrides_repo::fetch_active_scoped_overrides_as_of(pool, tenant_id, scope, as_of),
    )?;

    let intent_hashes: Vec<[u8; 32]> = intents.iter().map(|i| i.content_hash).collect();
    let intent_root = compute_sub_commitment(&intent_hashes);

    let selected_memory_hashes: Vec<[u8; 32]> = if mem_id_set.is_empty() {
        Vec::new()
    } else {
        let active_mem_set: BTreeSet<Uuid> = obj_scan.active_memory_ids.iter().copied().collect();
        let live_ids: Vec<Uuid> = mem_id_set
            .into_iter()
            .filter(|id| active_mem_set.contains(id))
            .collect();
        let fetched = objects_repo::fetch_objects_by_ids(pool, tenant_id, &live_ids).await?;
        fetched.into_iter().map(|o| o.content_hash).collect()
    };
    let selected_memory_root = compute_sub_commitment(&selected_memory_hashes);

    let mut relevant_hashes: Vec<[u8; 32]> = Vec::new();
    if spec.empty_knowledge_fallback {
        for c in &scoped_claims {
            if c.status == ClaimStatus::Active
                && c.valid_from.map_or(true, |vf| vf <= eval_ts)
                && c.valid_to.map_or(true, |vt| vt >= eval_ts)
            {
                relevant_hashes.push(c.content_hash);
            }
        }
        for ovr in &active_overrides {
            if ovr.created_at <= eval_ts {
                relevant_hashes.push(ovr.attestation_hash);
            }
        }
    } else if !group_set.is_empty() {
        let mut active_in_group_ids = BTreeSet::new();
        for c in &scoped_claims {
            if c.status == ClaimStatus::Active
                && c.valid_from.map_or(true, |vf| vf <= eval_ts)
                && c.valid_to.map_or(true, |vt| vt >= eval_ts)
            {
                let lkey = compute_logical_claim_group_key(tenant_id, &c.subject, &c.predicate, scope);
                if group_set.contains(&lkey) {
                    active_in_group_ids.insert(c.id);
                    relevant_hashes.push(c.content_hash);
                }
            }
        }
        // Also include any active claim anywhere in `scope` whose `contradiction_ids` target an active claim in `group_set`!
        for c in &scoped_claims {
            if !active_in_group_ids.contains(&c.id)
                && c.status == ClaimStatus::Active
                && c.valid_from.map_or(true, |vf| vf <= eval_ts)
                && c.valid_to.map_or(true, |vt| vt >= eval_ts)
                && c.contradiction_ids
                    .iter()
                    .any(|tid| active_in_group_ids.contains(tid))
            {
                relevant_hashes.push(c.content_hash);
            }
        }
        for ovr in &active_overrides {
            if ovr.created_at <= eval_ts {
                let lkey =
                    compute_logical_claim_group_key(tenant_id, &ovr.subject, &ovr.predicate, scope);
                if group_set.contains(&lkey) {
                    relevant_hashes.push(ovr.attestation_hash);
                }
            }
        }
    }
    let relevant_knowledge_root = compute_sub_commitment(&relevant_hashes);

    Ok(compute_task_dependency_commitment(
        tenant_id,
        scope,
        permission_root,
        &intent_root,
        &selected_memory_root,
        &relevant_knowledge_root,
    ))
}

/// Computes the live `state_commitment` for `(tenant_id, scope)` directly from indexed sub-commitments
/// in `O(active_items)` without scanning historical `context_bundles` (PPA 1 Claim 20).
pub async fn compute_live_scope_state_commitment(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    permission_root: &[u8; 32],
    now: DateTime<Utc>,
) -> ActaResult<[u8; 32]> {
    let now = now.trunc_subsecs(6);
    let (obj_scan, (scoped_claims, _sup), active_overrides) = tokio::try_join!(
        objects_repo::fetch_all_active_hashes_in_scope(pool, tenant_id, scope),
        claims_repo::fetch_scoped_claims(pool, tenant_id, scope),
        overrides_repo::fetch_active_scoped_overrides(pool, tenant_id, scope),
    )?;

    let mut active_claim_hashes: Vec<[u8; 32]> = scoped_claims
        .iter()
        .filter(|c| {
            c.status == ClaimStatus::Active
                && c.valid_from.map_or(true, |vf| vf <= now)
                && c.valid_to.map_or(true, |vt| vt >= now)
        })
        .map(|c| c.content_hash)
        .collect();
    for ovr in &active_overrides {
        active_claim_hashes.push(ovr.attestation_hash);
    }

    let intent_root = compute_sub_commitment(&obj_scan.active_intent_hashes);
    let memory_root = compute_sub_commitment(&obj_scan.active_memory_hashes);
    let knowledge_root = compute_sub_commitment(&active_claim_hashes);

    Ok(compute_state_commitment(
        SCHEMA_VERSION,
        tenant_id,
        scope,
        &intent_root,
        &knowledge_root,
        &memory_root,
        permission_root,
    ))
}

/// Persists a state- or dependency-conditioned cached answer bound to a verified `ContextBundle` and emits
/// a signed `AnswerCacheLedgerSummary` on `evidence_history` (`acta:evidence_event:v3`, PPA 1 Claims 19–27).
pub async fn cache_answer_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    inp: NewCachedAnswerInput<'_>,
) -> ActaResult<(CachedAnswerReceipt, EvidenceEntry, bool)> {
    let created_at = inp.created_at.trunc_subsecs(6);
    let expires_at = inp.expires_at.map(|t| t.trunc_subsecs(6));

    let bundle_row: Option<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT bundle_canonical
        FROM context_bundles
        WHERE tenant_id = $1 AND bundle_hash = $2
        "#,
    )
    .bind(inp.tenant_id)
    .bind(inp.source_bundle_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("lookup source_bundle_hash failed: {e}")))?;

    let (canonical_bytes,) = bundle_row.ok_or_else(|| {
        ActaError::NotFound(format!(
            "context_bundle not found for hash {}",
            hex::encode(inp.source_bundle_hash)
        ))
    })?;
    let source_bundle: ContextBundle = serde_json::from_slice(&canonical_bytes).map_err(|e| {
        ActaError::Storage(format!("stored source ContextBundle parse failed: {e}"))
    })?;

    if let Some(exp_scope) = inp.explicit_scope.filter(|s| !s.trim().is_empty()) {
        if exp_scope != source_bundle.scope {
            return Err(ActaError::Validation(format!(
                "explicit scope '{exp_scope}' does not match source_bundle_hash scope '{}'",
                source_bundle.scope
            )));
        }
    }
    if let Some(exp_task) = inp.explicit_task_id.filter(|s| !s.trim().is_empty()) {
        if exp_task != source_bundle.task_id {
            return Err(ActaError::Validation(format!(
                "explicit task_id '{exp_task}' does not match source_bundle_hash task_id '{}'",
                source_bundle.task_id
            )));
        }
    }

    let validity_mode = match inp.validity_mode {
        "dependency_subset" | "scope_root" => inp.validity_mode,
        other => {
            return Err(ActaError::Validation(format!(
                "unsupported validity_mode '{other}' (expected 'dependency_subset' or 'scope_root')"
            )))
        }
    };

    let (task_dep_comm_opt, dep_spec_json_opt) = if validity_mode == "dependency_subset" {
        let spec = build_dependency_spec_from_bundle(&source_bundle, inp.explicit_dependency_ids)?;
        let bundle_perm_root = source_bundle
            .resolver_manifest
            .as_ref()
            .map(|m| m.permission_root)
            .unwrap_or(*inp.permission_root);
        let dep_comm = compute_scoped_task_dependency_commitment_as_of(
            pool,
            inp.tenant_id,
            &source_bundle.scope,
            &bundle_perm_root,
            &spec,
            source_bundle.issued_at,
            Some(source_bundle.issued_at),
        )
        .await?;
        let spec_val = serde_json::to_value(&spec)
            .map_err(|e| ActaError::Storage(format!("serialize dependency_spec failed: {e}")))?;
        (Some(dep_comm), Some(spec_val))
    } else {
        (None, None)
    };

    let scope = source_bundle.scope;
    let task_id = source_bundle.task_id;
    let state_commitment = source_bundle.state_commitment;
    let query_hash = compute_query_text_hash(inp.query_text);
    let answer_hash = compute_answer_text_hash(inp.answer_text);

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin cache_answer tx failed: {e}")))?;

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, inp.tenant_id).await?;

    let existing_opt = sqlx::query_as::<_, CachedAnswerRow>(
        r#"
        SELECT id, tenant_id, scope, task_id, query_hash, source_bundle_hash,
               state_commitment, validity_mode, task_dependency_commitment, dependency_spec,
               answer_hash, answer_text, answer_metadata,
               cached_by, cacher_auth_kind, client_public_key,
               cache_domain, cache_commitment, evidence_seq_num, host_signature,
               expires_at, created_at
        FROM cached_answers
        WHERE tenant_id = $1
          AND scope = $2
          AND task_id = $3
          AND query_hash = $4
          AND source_bundle_hash = $5
          AND answer_hash = $6
          AND cached_by = $7
          AND validity_mode = $8
        ORDER BY created_at DESC, evidence_seq_num DESC
        LIMIT 1
        "#,
    )
    .bind(inp.tenant_id)
    .bind(&scope)
    .bind(&task_id)
    .bind(query_hash.as_slice())
    .bind(inp.source_bundle_hash.as_slice())
    .bind(answer_hash.as_slice())
    .bind(inp.cached_by)
    .bind(validity_mode)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("check existing cached_answer failed: {e}")))?;

    if let Some(ex_row) = existing_opt {
        let stored = ex_row.into_stored()?;
        if stored.receipt.expires_at.map_or(true, |exp| created_at <= exp)
            && stored.task_dependency_commitment_bytes == task_dep_comm_opt
        {
            if let Some(ex_ev) =
                fetch_evidence_by_seq(pool, inp.tenant_id, stored.receipt.evidence_seq_num).await?
            {
                tx.rollback().await.ok();
                return Ok((stored.receipt, ex_ev, true));
            }
        }
    }

    let seq_num = prev_seq + 1;
    let acs = AnswerCacheLedgerSummary {
        cache_domain: ANSWER_CACHE_DOMAIN_V1.to_string(),
        event_kind: Some("cached".to_string()),
        cache_id: inp.id,
        scope: scope.clone(),
        task_id: task_id.clone(),
        query_hash,
        source_bundle_hash: *inp.source_bundle_hash,
        state_commitment,
        validity_mode: Some(validity_mode.to_string()),
        task_dependency_commitment: task_dep_comm_opt,
        answer_hash,
        cached_by: inp.cached_by.to_string(),
        cacher_auth_kind: inp.cacher_auth_kind.to_string(),
        client_public_key: inp.client_public_key,
        client_signature: inp.client_signature.clone(),
        expires_at,
        invalidation_reason: None,
        observed_state_commitment: None,
        observed_dependency_commitment: None,
    };

    let cache_commitment = compute_answer_cache_summary_commitment(&acs)?;
    let receipt_host_sig =
        sign_answer_cache_receipt(host_key, inp.tenant_id, seq_num, &cache_commitment);
    let event_hash = compute_evidence_event_hash_full(
        inp.tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&cache_commitment),
        PolicyResultTag::Allow,
        created_at.timestamp_micros(),
        None,
        None,
        None,
        Some(&acs),
    )?;
    let ev_host_sig =
        sign_evidence_entry(host_key, inp.tenant_id, seq_num, &prev_hash, &event_hash);
    let ac_meta_json = serde_json::to_value(&acs)
        .map_err(|e| ActaError::Storage(format!("serialize answer_cache_meta failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, write_meta, answer_cache_meta,
            host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, NULL, $6, $7, $8)
        "#,
    )
    .bind(inp.tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(cache_commitment.as_slice())
    .bind(ac_meta_json)
    .bind(ev_host_sig.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert answer_cache evidence_history failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO cached_answers (
            id, tenant_id, scope, task_id, query_hash, query_text,
            source_bundle_hash, state_commitment, validity_mode,
            task_dependency_commitment, dependency_spec, answer_hash,
            answer_text, answer_metadata, cached_by, cacher_auth_kind,
            client_public_key, client_signature, cache_domain,
            cache_commitment, evidence_seq_num, host_signature,
            expires_at, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9,
            $10, $11, $12,
            $13, $14, $15, $16,
            $17, $18, $19,
            $20, $21, $22,
            $23, $24
        )
        "#,
    )
    .bind(inp.id)
    .bind(inp.tenant_id)
    .bind(&scope)
    .bind(&task_id)
    .bind(query_hash.as_slice())
    .bind(inp.query_text)
    .bind(inp.source_bundle_hash.as_slice())
    .bind(state_commitment.as_slice())
    .bind(validity_mode)
    .bind(task_dep_comm_opt.as_ref().map(|d| d.as_slice()))
    .bind(dep_spec_json_opt)
    .bind(answer_hash.as_slice())
    .bind(inp.answer_text)
    .bind(inp.answer_metadata)
    .bind(inp.cached_by)
    .bind(inp.cacher_auth_kind)
    .bind(inp.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(inp.client_signature.as_deref())
    .bind(ANSWER_CACHE_DOMAIN_V1)
    .bind(cache_commitment.as_slice())
    .bind(seq_num)
    .bind(receipt_host_sig.as_slice())
    .bind(expires_at)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert cached_answers failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit cache_answer tx failed: {e}")))?;

    let receipt = CachedAnswerReceipt {
        cache_id: inp.id,
        tenant_id: inp.tenant_id.to_string(),
        scope,
        task_id,
        query_hash: hex::encode(query_hash),
        source_bundle_hash: hex::encode(inp.source_bundle_hash),
        state_commitment: hex::encode(state_commitment),
        validity_mode: validity_mode.to_string(),
        task_dependency_commitment: task_dep_comm_opt.map(hex::encode),
        answer_hash: hex::encode(answer_hash),
        cache_domain: ANSWER_CACHE_DOMAIN_V1.to_string(),
        cache_commitment: hex::encode(cache_commitment),
        evidence_seq_num: seq_num,
        host_signature: hex::encode(receipt_host_sig),
        cached_by: inp.cached_by.to_string(),
        cacher_auth_kind: inp.cacher_auth_kind.to_string(),
        client_public_key_hex: inp.client_public_key.map(hex::encode),
        expires_at,
        created_at,
    };

    let ev = EvidenceEntry {
        tenant_id: inp.tenant_id.to_string(),
        seq_num,
        event_domain: Some("acta:evidence_event:v3".to_string()),
        prev_hash,
        event_hash,
        bundle_hash: None,
        state_commitment: Some(cache_commitment),
        policy_result: PolicyResultTag::Allow,
        refusal_metadata: None,
        override_summary: None,
        write_summary: None,
        answer_cache_summary: Some(acs),
        witness_reg_summary: None,
        witness_revoke_summary: None,
        host_signature: ev_host_sig,
        created_at,
    };

    Ok((receipt, ev, false))
}

/// Atomically records at most ONE chained invalidation receipt (`event_kind = "invalidated"`)
/// in `cached_answer_invalidations` + `evidence_history` (`acta:evidence_event:v3`) for `stored.receipt.cache_id`.
/// Repeat lookups of an already-invalidated `cache_id` return `(existing_seq_num, false)` without
/// acquiring locks or mutating `evidence_history`.
#[allow(clippy::too_many_arguments)]
pub async fn record_cache_invalidation_once_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    stored: &StoredCachedAnswer,
    invalidation_reason: &str,
    observed_state_commitment: &[u8; 32],
    observed_dependency_commitment: Option<&[u8; 32]>,
    invalidated_by: &str,
    invalidator_auth_kind: &str,
    now: DateTime<Utc>,
) -> ActaResult<(i64, bool)> {
    let fast_existing: Option<(i64,)> = sqlx::query_as(
        "SELECT evidence_seq_num FROM cached_answer_invalidations WHERE tenant_id = $1 AND cache_id = $2",
    )
    .bind(&stored.receipt.tenant_id)
    .bind(stored.receipt.cache_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("check cached_answer_invalidations failed: {e}")))?;

    if let Some((seq,)) = fast_existing {
        return Ok((seq, false));
    }

    let created_at = now.trunc_subsecs(6);
    let mut tx = pool.begin().await.map_err(|e| {
        ActaError::Storage(format!("begin cached_answer_invalidations tx failed: {e}"))
    })?;

    let (prev_seq, prev_hash) =
        lock_and_read_latest_evidence_tx(&mut tx, &stored.receipt.tenant_id).await?;

    let locked_existing: Option<(i64,)> = sqlx::query_as(
        "SELECT evidence_seq_num FROM cached_answer_invalidations WHERE tenant_id = $1 AND cache_id = $2",
    )
    .bind(&stored.receipt.tenant_id)
    .bind(stored.receipt.cache_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        ActaError::Storage(format!(
            "re-check cached_answer_invalidations under lock failed: {e}"
        ))
    })?;

    if let Some((seq,)) = locked_existing {
        tx.rollback().await.ok();
        return Ok((seq, false));
    }

    let seq_num = prev_seq + 1;
    let acs = AnswerCacheLedgerSummary {
        cache_domain: ANSWER_CACHE_DOMAIN_V1.to_string(),
        event_kind: Some("invalidated".to_string()),
        cache_id: stored.receipt.cache_id,
        scope: stored.receipt.scope.clone(),
        task_id: stored.receipt.task_id.clone(),
        query_hash: stored.query_hash_bytes,
        source_bundle_hash: stored.source_bundle_hash_bytes,
        state_commitment: stored.state_commitment_bytes,
        validity_mode: Some(stored.receipt.validity_mode.clone()),
        task_dependency_commitment: stored.task_dependency_commitment_bytes,
        answer_hash: stored.answer_hash_bytes,
        cached_by: invalidated_by.to_string(),
        cacher_auth_kind: invalidator_auth_kind.to_string(),
        client_public_key: None,
        client_signature: None,
        expires_at: stored.receipt.expires_at,
        invalidation_reason: Some(invalidation_reason.to_string()),
        observed_state_commitment: Some(*observed_state_commitment),
        observed_dependency_commitment: observed_dependency_commitment.copied(),
    };

    let cache_comm = compute_answer_cache_summary_commitment(&acs)?;
    let event_hash = compute_evidence_event_hash_full(
        &stored.receipt.tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&cache_comm),
        PolicyResultTag::Allow,
        created_at.timestamp_micros(),
        None,
        None,
        None,
        Some(&acs),
    )?;
    let ev_host_sig = sign_evidence_entry(
        host_key,
        &stored.receipt.tenant_id,
        seq_num,
        &prev_hash,
        &event_hash,
    );
    let ac_meta_json = serde_json::to_value(&acs).map_err(|e| {
        ActaError::Storage(format!("serialize invalidation answer_cache_meta failed: {e}"))
    })?;

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, write_meta, answer_cache_meta,
            host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, NULL, $6, $7, $8)
        "#,
    )
    .bind(&stored.receipt.tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(cache_comm.as_slice())
    .bind(ac_meta_json)
    .bind(ev_host_sig.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        ActaError::Storage(format!(
            "insert cache invalidation evidence_history failed: {e}"
        ))
    })?;

    sqlx::query(
        r#"
        INSERT INTO cached_answer_invalidations (
            cache_id, tenant_id, scope, task_id, invalidation_reason,
            observed_state_commitment, observed_dependency_commitment,
            invalidated_by, invalidator_auth_kind, cache_commitment,
            evidence_seq_num, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(stored.receipt.cache_id)
    .bind(&stored.receipt.tenant_id)
    .bind(&stored.receipt.scope)
    .bind(&stored.receipt.task_id)
    .bind(invalidation_reason)
    .bind(observed_state_commitment.as_slice())
    .bind(observed_dependency_commitment.map(|d| d.as_slice()))
    .bind(invalidated_by)
    .bind(invalidator_auth_kind)
    .bind(cache_comm.as_slice())
    .bind(seq_num)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert cached_answer_invalidations failed: {e}")))?;

    tx.commit().await.map_err(|e| {
        ActaError::Storage(format!("commit cached_answer_invalidations tx failed: {e}"))
    })?;

    Ok((seq_num, true))
}

/// Fetches the latest cached answer for `(tenant_id, scope, task_id, query_hash)` via `idx_cached_answers_lookup`.
pub async fn lookup_latest_cached_answer(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    task_id: &str,
    query_text: &str,
) -> ActaResult<Option<StoredCachedAnswer>> {
    let query_hash = compute_query_text_hash(query_text);
    let row = sqlx::query_as::<_, CachedAnswerRow>(
        r#"
        SELECT id, tenant_id, scope, task_id, query_hash, source_bundle_hash,
               state_commitment, validity_mode, task_dependency_commitment, dependency_spec,
               answer_hash, answer_text, answer_metadata,
               cached_by, cacher_auth_kind, client_public_key,
               cache_domain, cache_commitment, evidence_seq_num, host_signature,
               expires_at, created_at
        FROM cached_answers
        WHERE tenant_id = $1
          AND scope = $2
          AND task_id = $3
          AND query_hash = $4
        ORDER BY created_at DESC, evidence_seq_num DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(task_id)
    .bind(query_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("lookup_latest_cached_answer failed: {e}")))?;

    row.map(CachedAnswerRow::into_stored).transpose()
}
