use std::collections::{BTreeSet, HashMap};

use acta_crypto::{
    compute_evidence_event_hash_full, compute_rebuild_archive_header_hash,
    compute_write_summary_commitment, sign_evidence_entry, sign_rebuild_archive_header,
    verify_and_rebuild_scope_state_offline,
};
use acta_types::{
    ActaError, ActaResult, ClaimStatus, ContextBundle, ImpactBundleRecord,
    ImpactedCachedAnswerRecord, KnowledgeClaim, LedgerStateRebuildResponse, LifecycleStatus,
    ObjectType, PolicyResultTag, StateRebuildArchive, StoredObject, TraceItemImpactResponse,
    WriteLedgerSummary, WriteOperationKind, SCHEMA_VERSION_V1, SCHEMA_VERSION_V2,
    STATE_REBUILD_ARCHIVE_SCHEMA_V1, STATE_REBUILD_ARCHIVE_SCHEMA_V2, WRITE_EVENT_DOMAIN_V1,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    answer_cache_repo::{
        compute_live_scope_state_commitment_for_schema,
        compute_scoped_task_dependency_commitment_as_of, CacheDependencySpec,
    },
    claims_repo, evidence_repo, objects_repo, overrides_repo,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplicitRebuildClock {
    ChainTailDefault,
    WallClockNow,
    Explicit(DateTime<Utc>),
}

#[derive(Debug, Clone)]
struct DepEdge {
    item_id: Uuid,
    item_kind: &'static str,
    dependency_role: &'static str,
}

/// Extracts all reverse-index dependency edges from a compiled `ContextBundle` and inserts them
/// into `bundle_dependencies` (`ON CONFLICT DO NOTHING`) inside the bundle's write transaction.
pub(crate) async fn insert_bundle_dependencies_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    bundle_hash: &[u8; 32],
    bundle: &ContextBundle,
    created_at: DateTime<Utc>,
) -> ActaResult<()> {
    let mut edges: Vec<DepEdge> = Vec::new();

    for sel in &bundle.selected_objects {
        let role = match sel.obj_type {
            ObjectType::Intent => "selected_intent",
            ObjectType::Memory => "selected_memory",
        };
        edges.push(DepEdge {
            item_id: sel.id,
            item_kind: "object",
            dependency_role: role,
        });
    }

    for res in &bundle.resolution_records {
        edges.push(DepEdge {
            item_id: res.winning_claim.id,
            item_kind: "claim",
            dependency_role: "resolved_winner",
        });
        for &sup_id in &res.suppressed_claim_ids {
            edges.push(DepEdge {
                item_id: sup_id,
                item_kind: "claim",
                dependency_role: "suppressed_candidate",
            });
        }
        if let Some(ref ovr) = res.override_attestation {
            edges.push(DepEdge {
                item_id: ovr.attestation_id,
                item_kind: "override",
                dependency_role: "applied_override",
            });
        }
    }

    for disp in &bundle.dispute_records {
        for cand in &disp.competing_claims {
            edges.push(DepEdge {
                item_id: cand.id,
                item_kind: "claim",
                dependency_role: "disputed_candidate",
            });
        }
        if let Some(ref lapsed) = disp.lapsed_override {
            edges.push(DepEdge {
                item_id: lapsed.attestation_id,
                item_kind: "override",
                dependency_role: "lapsed_override",
            });
        }
    }

    for edge in edges {
        sqlx::query(
            r#"
            INSERT INTO bundle_dependencies (
                tenant_id, item_id, item_kind, dependency_role,
                bundle_hash, scope, task_id, state_commitment,
                bundle_issued_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, item_id, dependency_role, bundle_hash) DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(edge.item_id)
        .bind(edge.item_kind)
        .bind(edge.dependency_role)
        .bind(bundle_hash.as_slice())
        .bind(&bundle.scope)
        .bind(&bundle.task_id)
        .bind(bundle.state_commitment.as_slice())
        .bind(bundle.issued_at)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert bundle_dependencies failed: {e}")))?;
    }

    Ok(())
}

#[derive(FromRow)]
struct BundleDepRow {
    bundle_hash: Vec<u8>,
    evidence_seq_num: Option<i64>,
    scope: String,
    task_id: String,
    dependency_role: String,
    state_commitment: Vec<u8>,
    bundle_schema_version: Option<String>,
    bundle_issued_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ImpactedCacheRow {
    id: Uuid,
    scope: String,
    task_id: String,
    query_hash: Vec<u8>,
    source_bundle_hash: Vec<u8>,
    state_commitment: Vec<u8>,
    validity_mode: String,
    task_dependency_commitment: Option<Vec<u8>>,
    dependency_spec: Option<Value>,
    answer_hash: Vec<u8>,
    evidence_seq_num: i64,
    expires_at: Option<DateTime<Utc>>,
    invalidation_evidence_seq_num: Option<i64>,
    recorded_invalidation_reason: Option<String>,
    created_at: DateTime<Utc>,
}

/// Indexed `O(k)` reverse blast-radius lookup (`acta_trace_claim_impact`) returning every historical
/// `ContextBundle` and cached answer that relied on `item_id` (claim, object, or override), without
/// scanning `context_bundles`. Enforces strict zero-oracle tenant isolation.
pub async fn trace_item_impact(
    pool: &PgPool,
    tenant_id: &str,
    item_id: Uuid,
    permission_root: &[u8; 32],
) -> ActaResult<TraceItemImpactResponse> {
    let now = Utc::now().trunc_subsecs(6);

    let (
        item_kind,
        scope,
        subject,
        predicate,
        version,
        lifecycle_state,
        successor_ids,
        retracted_by_id,
        retraction_reason,
        write_evidence_seq_num,
    ) = if let Some(clm) = claims_repo::fetch_claim_by_id(pool, tenant_id, item_id).await? {
        let succ_rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, status, retraction_reason
            FROM knowledge_claims
            WHERE tenant_id = $1 AND predecessor_id = $2
            ORDER BY version ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(item_id)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("query claim successors failed: {e}")))?;

        let succ_ids: Vec<Uuid> = succ_rows.iter().map(|(id, _, _)| *id).collect();
        let retract_succ = succ_rows
            .iter()
            .find(|(_, st, _)| st == "revoked")
            .map(|(id, _, r)| (*id, r.clone()));

        let state = if let Some((_, ref r)) = retract_succ {
            let _ = r;
            "retracted".to_string()
        } else if !succ_ids.is_empty() || clm.status == ClaimStatus::Superseded {
            "superseded".to_string()
        } else if clm.status == ClaimStatus::Revoked {
            "revoked_tombstone".to_string()
        } else if clm.status != ClaimStatus::Active
            || clm.valid_from.is_some_and(|vf| now < vf)
            || clm.valid_to.is_some_and(|vt| now > vt)
        {
            "expired".to_string()
        } else {
            "active".to_string()
        };

        let (ret_id, ret_reason) = match retract_succ {
            Some((rid, rreason)) => (Some(rid), rreason),
            None => (None, clm.retraction_reason),
        };

        (
            "claim".to_string(),
            clm.scope,
            Some(clm.subject),
            Some(clm.predicate),
            clm.version,
            state,
            succ_ids,
            ret_id,
            ret_reason,
            clm.evidence_seq_num,
        )
    } else if let Some(obj) = objects_repo::fetch_object_by_id(pool, tenant_id, item_id).await? {
        let succ_rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, lifecycle_status
            FROM objects
            WHERE tenant_id = $1 AND predecessor_id = $2
            ORDER BY version ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(item_id)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("query object successors failed: {e}")))?;
        let succ_ids: Vec<Uuid> = succ_rows.iter().map(|(id, _)| *id).collect();
        let rev_id = succ_rows
            .iter()
            .find(|(_, st)| st == "revoked")
            .map(|(id, _)| *id);
        let state = if rev_id.is_some() {
            "retracted".to_string()
        } else if !succ_ids.is_empty() || obj.lifecycle_status == LifecycleStatus::Superseded {
            "superseded".to_string()
        } else if obj.lifecycle_status != LifecycleStatus::Active {
            obj.lifecycle_status.as_str().to_string()
        } else {
            "active".to_string()
        };
        (
            "object".to_string(),
            obj.scope,
            None,
            None,
            obj.version,
            state,
            succ_ids,
            rev_id,
            None,
            obj.evidence_seq_num,
        )
    } else {
        let ov_list = overrides_repo::fetch_overrides_by_ids(pool, tenant_id, &[item_id]).await?;
        let Some(ovr) = ov_list.into_iter().next() else {
            return Err(ActaError::NotFound(format!("item {item_id} not found")));
        };
        let succ_rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM override_attestations WHERE tenant_id = $1 AND predecessor_id = $2 ORDER BY version ASC",
        )
        .bind(tenant_id)
        .bind(item_id)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("query override successors failed: {e}")))?;
        let succ_ids: Vec<Uuid> = succ_rows.into_iter().map(|(id,)| id).collect();
        let state = if succ_ids.is_empty() {
            "active".to_string()
        } else {
            "superseded".to_string()
        };
        (
            "override".to_string(),
            ovr.scope,
            Some(ovr.subject),
            Some(ovr.predicate),
            ovr.version,
            state,
            succ_ids,
            None,
            None,
            Some(ovr.evidence_seq_num),
        )
    };

    let dep_rows = sqlx::query_as::<_, BundleDepRow>(
        r#"
        SELECT bd.bundle_hash,
               (
                   SELECT MIN(eh.seq_num)
                   FROM evidence_history eh
                   WHERE eh.tenant_id = bd.tenant_id
                     AND eh.bundle_hash = bd.bundle_hash
               ) AS evidence_seq_num,
               bd.scope,
               bd.task_id,
               bd.dependency_role,
               bd.state_commitment,
               (
                   SELECT convert_from(cb.bundle_canonical, 'UTF8')::jsonb ->> 'schema_version'
                   FROM context_bundles cb
                   WHERE cb.tenant_id = bd.tenant_id
                     AND cb.bundle_hash = bd.bundle_hash
               ) AS bundle_schema_version,
               bd.bundle_issued_at
        FROM bundle_dependencies bd
        WHERE bd.tenant_id = $1 AND bd.item_id = $2
        ORDER BY bd.bundle_issued_at DESC, bd.bundle_hash ASC, bd.dependency_role ASC
        "#,
    )
    .bind(tenant_id)
    .bind(item_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("query bundle_dependencies failed: {e}")))?;

    let mut scope_commitments: HashMap<(String, String), [u8; 32]> = HashMap::new();
    for r in &dep_rows {
        let b_schema = r
            .bundle_schema_version
            .clone()
            .unwrap_or_else(|| SCHEMA_VERSION_V1.to_string());
        let key = (r.scope.clone(), b_schema.clone());
        if !scope_commitments.contains_key(&key) {
            let live_sc = compute_live_scope_state_commitment_for_schema(
                pool,
                &b_schema,
                tenant_id,
                &r.scope,
                permission_root,
                now,
            )
            .await?;
            scope_commitments.insert(key, live_sc);
        }
    }

    let mut impacted_bundles = Vec::with_capacity(dep_rows.len());
    let mut bundle_hash_bytes_list: Vec<Vec<u8>> = Vec::new();
    let mut seen_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut stale_bundle_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();

    for r in dep_rows {
        let bh_arr: [u8; 32] = r
            .bundle_hash
            .clone()
            .try_into()
            .map_err(|_| ActaError::Storage("bundle_dependencies.bundle_hash not 32 bytes".to_string()))?;
        let sc_arr: [u8; 32] = r.state_commitment.try_into().map_err(|_| {
            ActaError::Storage("bundle_dependencies.state_commitment not 32 bytes".to_string())
        })?;
        let b_schema = r
            .bundle_schema_version
            .unwrap_or_else(|| SCHEMA_VERSION_V1.to_string());
        let live_sc = scope_commitments
            .get(&(r.scope.clone(), b_schema))
            .copied()
            .unwrap_or([0u8; 32]);
        let is_stale_now = sc_arr != live_sc;

        if seen_hashes.insert(bh_arr) {
            bundle_hash_bytes_list.push(r.bundle_hash);
        }
        if is_stale_now {
            stale_bundle_hashes.insert(bh_arr);
        }

        impacted_bundles.push(ImpactBundleRecord {
            bundle_hash: hex::encode(bh_arr),
            evidence_seq_num: r.evidence_seq_num,
            scope: r.scope,
            task_id: r.task_id,
            dependency_role: r.dependency_role,
            bundle_state_commitment: hex::encode(sc_arr),
            current_scope_state_commitment: hex::encode(live_sc),
            is_stale_now,
            bundle_issued_at: r.bundle_issued_at,
        });
    }

    let impacted_cached_answers = if bundle_hash_bytes_list.is_empty() {
        Vec::new()
    } else {
        let cache_rows = sqlx::query_as::<_, ImpactedCacheRow>(
            r#"
            SELECT ca.id, ca.scope, ca.task_id, ca.query_hash, ca.source_bundle_hash,
                   ca.state_commitment, ca.validity_mode, ca.task_dependency_commitment,
                   ca.dependency_spec, ca.answer_hash, ca.evidence_seq_num, ca.expires_at,
                   cai.evidence_seq_num AS invalidation_evidence_seq_num,
                   cai.invalidation_reason AS recorded_invalidation_reason,
                   ca.created_at
            FROM cached_answers ca
            LEFT JOIN cached_answer_invalidations cai
                ON cai.tenant_id = ca.tenant_id
               AND cai.cache_id = ca.id
            WHERE ca.tenant_id = $1 AND ca.source_bundle_hash = ANY($2)
            ORDER BY ca.created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(&bundle_hash_bytes_list)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("query impacted cached_answers failed: {e}")))?;

        let mut out = Vec::with_capacity(cache_rows.len());
        for cr in cache_rows {
            let cache_bundle_schema: String = cr
                .dependency_spec
                .as_ref()
                .and_then(|v| v.get("state_schema_version"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if scope_commitments.contains_key(&(cr.scope.clone(), SCHEMA_VERSION_V2.to_string())) {
                        SCHEMA_VERSION_V2.to_string()
                    } else {
                        SCHEMA_VERSION_V1.to_string()
                    }
                });
            let sc_key = (cr.scope.clone(), cache_bundle_schema.clone());
            let live_sc = match scope_commitments.get(&sc_key) {
                Some(sc) => *sc,
                None => {
                    let computed = compute_live_scope_state_commitment_for_schema(
                        pool,
                        &cache_bundle_schema,
                        tenant_id,
                        &cr.scope,
                        permission_root,
                        now,
                    )
                    .await?;
                    scope_commitments.insert(sc_key, computed);
                    computed
                }
            };
            let stored_sc: [u8; 32] = cr.state_commitment.try_into().map_err(|_| {
                ActaError::Storage("cached_answers.state_commitment not 32 bytes".to_string())
            })?;
            let (is_invalidated, invalidation_reason) = if cr.invalidation_evidence_seq_num.is_some()
            {
                (true, cr.recorded_invalidation_reason)
            } else if cr.expires_at.is_some_and(|exp| now > exp) {
                (true, Some("expired_ttl".to_string()))
            } else if cr.validity_mode == "dependency_subset" {
                match (cr.task_dependency_commitment, cr.dependency_spec) {
                    (Some(raw_tdc), Some(raw_spec)) => {
                        let stored_tdc: [u8; 32] = raw_tdc.try_into().map_err(|_| {
                            ActaError::Storage(
                                "cached_answers.task_dependency_commitment not 32 bytes".to_string(),
                            )
                        })?;
                        let spec: CacheDependencySpec = serde_json::from_value(raw_spec)
                            .map_err(|e| ActaError::Storage(format!("parse dep spec: {e}")))?;
                        let live_tdc = compute_scoped_task_dependency_commitment_as_of(
                            pool,
                            tenant_id,
                            &cr.scope,
                            permission_root,
                            &spec,
                            now,
                            None,
                        )
                        .await?;
                        if stored_tdc != live_tdc {
                            (true, Some("stale_dependency_commitment".to_string()))
                        } else {
                            (false, None)
                        }
                    }
                    _ => {
                        if stored_sc != live_sc {
                            (true, Some("stale_state_commitment".to_string()))
                        } else {
                            (false, None)
                        }
                    }
                }
            } else if stored_sc != live_sc {
                (true, Some("stale_state_commitment".to_string()))
            } else {
                (false, None)
            };

            out.push(ImpactedCachedAnswerRecord {
                cache_id: cr.id,
                scope: cr.scope,
                task_id: cr.task_id,
                query_hash: hex::encode(cr.query_hash),
                source_bundle_hash: hex::encode(cr.source_bundle_hash),
                validity_mode: cr.validity_mode,
                answer_hash: hex::encode(cr.answer_hash),
                evidence_seq_num: cr.evidence_seq_num,
                invalidated_by_state_change: is_invalidated,
                invalidation_reason,
                invalidation_evidence_seq_num: cr.invalidation_evidence_seq_num,
                created_at: cr.created_at,
            });
        }
        out
    };

    Ok(TraceItemImpactResponse {
        tenant_id: tenant_id.to_string(),
        item_id,
        item_kind,
        scope,
        subject,
        predicate,
        version,
        lifecycle_state,
        successor_ids,
        retracted_by_id,
        retraction_reason,
        write_evidence_seq_num,
        impacted_bundle_count: seen_hashes.len(),
        stale_bundle_count: stale_bundle_hashes.len(),
        impacted_bundles,
        impacted_cached_answer_count: impacted_cached_answers.len(),
        impacted_cached_answers,
    })
}

/// Verifies `evidence_history[1..=up_to_seq]` cryptographically (plus SignedTreeHead + witness anchors
/// + host-signed `StateRebuildArchive` header binding `(scope, up_to_seq, evaluated_at, permission_root)`)
/// via standalone `verify_and_rebuild_scope_state_offline` and optionally returns the portable
/// `StateRebuildArchive` for third-party offline verification (`acta-verify`, Python/TS SDKs).
#[allow(clippy::too_many_arguments)]
pub async fn rebuild_scope_state_from_ledger(
    pool: &PgPool,
    host_key: &SigningKey,
    host_public_key: &[u8; 32],
    tenant_id: &str,
    scope: &str,
    permission_root: &[u8; 32],
    up_to_seq: Option<i64>,
    include_proof_archive: bool,
) -> ActaResult<LedgerStateRebuildResponse> {
    rebuild_scope_state_from_ledger_v173(
        pool,
        host_key,
        host_public_key,
        tenant_id,
        scope,
        permission_root,
        up_to_seq,
        ExplicitRebuildClock::ChainTailDefault,
        None,
        include_proof_archive,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn rebuild_scope_state_from_ledger_v173(
    pool: &PgPool,
    host_key: &SigningKey,
    host_public_key: &[u8; 32],
    tenant_id: &str,
    scope: &str,
    permission_root: &[u8; 32],
    up_to_seq: Option<i64>,
    clock_mode: ExplicitRebuildClock,
    explicit_state_schema: Option<&str>,
    include_proof_archive: bool,
) -> ActaResult<LedgerStateRebuildResponse> {
    let chain = evidence_repo::fetch_tenant_evidence_chain(pool, tenant_id, up_to_seq).await?;
    if let Some(req_seq) = up_to_seq {
        if (chain.len() as i64) != req_seq {
            return Err(ActaError::Validation(format!(
                "up_to_seq={req_seq} exceeds tenant ledger head {}",
                chain.len()
            )));
        }
    }

    let effective_seq = chain.len() as i64;

    // v1.7.3 Part A Fix 5: Pin BOTH prefix (`up_to_seq`) AND head exports deterministically
    // to `evidence_chain.last().created_at` unless an explicit clock (`"now"` or RFC 3339) was requested!
    let evaluated_at = match clock_mode {
        ExplicitRebuildClock::ChainTailDefault => match chain.last() {
            Some(tail) => tail.created_at.trunc_subsecs(6),
            None => DateTime::<Utc>::UNIX_EPOCH,
        },
        ExplicitRebuildClock::WallClockNow => Utc::now().trunc_subsecs(6),
        ExplicitRebuildClock::Explicit(ts) => ts.trunc_subsecs(6),
    };

    // v1.7.3 Part A Fix 6: Select `v1` (`acta-state-rebuild-archive/v1`) when explicitly requested OR
    // when the latest compiled bundle in `(tenant_id, scope)` at `<= effective_seq` used `"acta-context-bundle/v1"`
    // (preserving `seq 1..219` bit-for-bit, e.g. `d0bf0212...` at `seq 184` and `e44a5111...` at `seq 219`),
    // and `v2` (`b"acta:state:v2"` + `b"acta:sub_commitment:v2"`) for all new `v1.7.3+` scopes and bundles!
    let (archive_schema, bundle_state_schema) = match explicit_state_schema
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some("v1")
        | Some(SCHEMA_VERSION_V1)
        | Some(STATE_REBUILD_ARCHIVE_SCHEMA_V1) => {
            (STATE_REBUILD_ARCHIVE_SCHEMA_V1, SCHEMA_VERSION_V1)
        }
        Some("v2")
        | Some(SCHEMA_VERSION_V2)
        | Some(STATE_REBUILD_ARCHIVE_SCHEMA_V2) => {
            (STATE_REBUILD_ARCHIVE_SCHEMA_V2, SCHEMA_VERSION_V2)
        }
        Some(other) => {
            return Err(ActaError::Validation(format!(
                "unsupported state_schema_version '{other}' (expected 'v1' or 'v2')"
            )));
        }
        None => {
            let latest_bundle_schema: Option<(Option<String>,)> = sqlx::query_as(
                r#"
                SELECT convert_from(cb.bundle_canonical, 'UTF8')::jsonb ->> 'schema_version'
                FROM evidence_history eh
                INNER JOIN context_bundles cb
                    ON cb.tenant_id = eh.tenant_id
                   AND cb.bundle_hash = eh.bundle_hash
                WHERE eh.tenant_id = $1
                  AND eh.seq_num <= $2
                  AND (convert_from(cb.bundle_canonical, 'UTF8')::jsonb ->> 'scope') = $3
                ORDER BY eh.seq_num DESC
                LIMIT 1
                "#,
            )
            .bind(tenant_id)
            .bind(effective_seq)
            .bind(scope)
            .fetch_optional(pool)
            .await
            .map_err(|e| ActaError::Storage(format!("detect scope bundle schema failed: {e}")))?;

            match latest_bundle_schema.and_then(|(s,)| s).as_deref() {
                Some(SCHEMA_VERSION_V1) => (STATE_REBUILD_ARCHIVE_SCHEMA_V1, SCHEMA_VERSION_V1),
                _ => (STATE_REBUILD_ARCHIVE_SCHEMA_V2, SCHEMA_VERSION_V2),
            }
        }
    };

    let genesis_pk_opt = evidence_repo::fetch_tenant_genesis_public_key(pool, tenant_id)
        .await?
        .or_else(|| {
            chain
                .iter()
                .find_map(|e| e.host_key_rotation_summary.as_ref().map(|r| r.old_public_key))
        });

    let effective_tail_pk = if let Some(last_rot) = chain
        .iter()
        .rev()
        .find_map(|e| e.host_key_rotation_summary.as_ref())
    {
        last_rot.new_public_key
    } else {
        genesis_pk_opt.unwrap_or(*host_public_key)
    };

    let genesis_host_public_key = genesis_pk_opt.filter(|gpk| gpk != &effective_tail_pk);

    let scoped_overrides = overrides_repo::fetch_all_scoped_overrides_up_to_seq(
        pool,
        tenant_id,
        scope,
        Some(effective_seq),
    )
    .await?;

    let (checkpoint, latest_anchored_checkpoint, consistency_proof_from_latest_anchor) =
        if effective_seq >= 1 {
            if let Some((sth, leaves)) =
                evidence_repo::build_signed_tree_head(pool, host_key, tenant_id, Some(effective_seq))
                    .await?
            {
                let (anch_opt, cons_opt, _ok) =
                    evidence_repo::resolve_latest_anchored_for_head(
                        pool,
                        host_key,
                        tenant_id,
                        &sth,
                        &leaves,
                    )
                    .await?;
                let prior_only = match anch_opt {
                    Some(ref a) if a.tree_size == sth.tree_size => None,
                    other => other,
                };
                (Some(sth), prior_only, cons_opt.unwrap_or_default())
            } else {
                (None, None, Vec::new())
            }
        } else {
            (None, None, Vec::new())
        };

    let header_hash = compute_rebuild_archive_header_hash(
        archive_schema,
        tenant_id,
        scope,
        effective_seq,
        evaluated_at.timestamp_micros(),
        permission_root,
    );
    let host_header_signature = sign_rebuild_archive_header(host_key, tenant_id, &header_hash);

    let archive = StateRebuildArchive {
        schema_version: archive_schema.to_string(),
        tenant_id: tenant_id.to_string(),
        scope: scope.to_string(),
        up_to_seq: effective_seq,
        evaluated_at,
        genesis_host_public_key,
        host_public_key: *host_public_key,
        permission_root: *permission_root,
        header_hash,
        host_header_signature,
        override_attestations: scoped_overrides,
        evidence_chain: chain,
        checkpoint,
        latest_anchored_checkpoint,
        consistency_proof_from_latest_anchor,
    };

    let offline = verify_and_rebuild_scope_state_offline(&archive, host_public_key, Some(scope))
        .map_err(ActaError::VerificationFailed)?;

    let live_sc = compute_live_scope_state_commitment_for_schema(
        pool,
        bundle_state_schema,
        tenant_id,
        scope,
        permission_root,
        evaluated_at,
    )
    .await?;
    let live_sc_hex = hex::encode(live_sc);

    let (legacy_objs,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint
        FROM objects o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND o.evidence_seq_num IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM legacy_backfilled_items lb
              WHERE lb.tenant_id = o.tenant_id
                AND lb.item_id = o.id
                AND lb.evidence_seq_num <= $3
          )
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(effective_seq)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("count unchained objects failed: {e}")))?;

    let (legacy_clms,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.scope = $2
          AND c.evidence_seq_num IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM legacy_backfilled_items lb
              WHERE lb.tenant_id = c.tenant_id
                AND lb.item_id = c.id
                AND lb.evidence_seq_num <= $3
          )
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(effective_seq)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("count unchained claims failed: {e}")))?;

    // v1.7.3 Part A Fix 1: Exact commitment equality regardless of whether `up_to_seq` was passed!
    let matches_live_store_bit_for_bit = offline.reconstructed_state_commitment_hex == live_sc_hex;

    Ok(LedgerStateRebuildResponse {
        tenant_id: offline.tenant_id,
        scope: offline.scope,
        state_schema_version: bundle_state_schema.to_string(),
        verified_up_to_seq: offline.verified_up_to_seq,
        chain_cryptographically_verified: true,
        write_events_replayed: offline.write_events_replayed,
        reconstructed_active_intents: offline.reconstructed_active_intents,
        reconstructed_active_memories: offline.reconstructed_active_memories,
        reconstructed_active_claims: offline.reconstructed_active_claims,
        reconstructed_superseded_or_retracted_items: offline
            .reconstructed_superseded_or_retracted_items,
        reconstructed_active_overrides: offline.reconstructed_active_overrides,
        legacy_pre_v17_unchained_objects: usize::try_from(legacy_objs.max(0)).unwrap_or(0),
        legacy_pre_v17_unchained_claims: usize::try_from(legacy_clms.max(0)).unwrap_or(0),
        reconstructed_intent_root: offline.reconstructed_intent_root_hex,
        reconstructed_knowledge_root: offline.reconstructed_knowledge_root_hex,
        reconstructed_memory_root: offline.reconstructed_memory_root_hex,
        permission_root: offline.permission_root_hex,
        reconstructed_state_commitment: offline.reconstructed_state_commitment_hex.clone(),
        live_store_state_commitment: live_sc_hex,
        matches_live_store_bit_for_bit,
        evaluated_at,
        header_hash: Some(hex::encode(header_hash)),
        host_header_signature: Some(hex::encode(host_header_signature)),
        merkle_root: offline.merkle_root_hex,
        latest_anchored_tree_size: offline.anchored_tree_size,
        rebuild_proof_archive: if include_proof_archive {
            Some(archive)
        } else {
            None
        },
    })
}

#[derive(Debug, Clone)]
pub struct BackfillLegacyScopeResponse {
    pub tenant_id: String,
    pub scope: String,
    pub imported_objects: usize,
    pub imported_claims: usize,
    pub first_evidence_seq_num: Option<i64>,
    pub last_evidence_seq_num: Option<i64>,
}

/// Opt-in migration helper (`POST /v1/tenants/:tenant_id/backfill-legacy-scope`, SPEC §10.5):
/// Appends `WriteOperationKind::LegacyImportObject` and `WriteOperationKind::LegacyImportClaim` entries
/// onto the tail of `evidence_history` (and `legacy_backfilled_items`) for any unchained pre-`v1.7.0` rows
/// in `(tenant_id, scope)` WITHOUT issuing UPDATEs against immutable `objects` or `knowledge_claims`.
pub async fn backfill_legacy_scope_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    scope: &str,
    imported_by: &str,
    writer_auth_kind: &str,
    now: DateTime<Utc>,
) -> ActaResult<BackfillLegacyScopeResponse> {
    let now = now.trunc_subsecs(6);

    let obj_ids: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT o.id
        FROM objects o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND o.evidence_seq_num IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM legacy_backfilled_items lb
              WHERE lb.tenant_id = o.tenant_id AND lb.item_id = o.id
          )
        ORDER BY o.created_at ASC, o.version ASC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("query unchained legacy objects failed: {e}")))?;

    let clm_ids: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT c.id
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.scope = $2
          AND c.evidence_seq_num IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM legacy_backfilled_items lb
              WHERE lb.tenant_id = c.tenant_id AND lb.item_id = c.id
          )
        ORDER BY c.created_at ASC, c.version ASC, c.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("query unchained legacy claims failed: {e}")))?;

    if obj_ids.is_empty() && clm_ids.is_empty() {
        return Ok(BackfillLegacyScopeResponse {
            tenant_id: tenant_id.to_string(),
            scope: scope.to_string(),
            imported_objects: 0,
            imported_claims: 0,
            first_evidence_seq_num: None,
            last_evidence_seq_num: None,
        });
    }

    let obj_id_vec: Vec<Uuid> = obj_ids.into_iter().map(|(id,)| id).collect();
    let clm_id_vec: Vec<Uuid> = clm_ids.into_iter().map(|(id,)| id).collect();
    let mut legacy_objs: Vec<StoredObject> =
        objects_repo::fetch_objects_by_ids(pool, tenant_id, &obj_id_vec).await?;
    legacy_objs.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut legacy_clms: Vec<KnowledgeClaim> =
        claims_repo::fetch_claims_by_ids(pool, tenant_id, &clm_id_vec).await?;
    legacy_clms.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin backfill_legacy_scope tx failed: {e}")))?;

    let (mut cur_seq, mut cur_prev_hash) =
        evidence_repo::lock_and_read_latest_evidence_tx(&mut tx, tenant_id).await?;
    let mut first_seq = None;
    let mut last_seq = None;
    let mut imported_objects = 0usize;
    let mut imported_claims = 0usize;

    for mut obj in legacy_objs {
        obj.embedding = None;
        let has_sig = obj.client_signature.is_some() && obj.client_public_key.is_some();
        if !has_sig {
            obj.client_signature = None;
            obj.client_public_key = None;
        }
        let eff_auth = if has_sig {
            "ed25519_client_sig"
        } else {
            writer_auth_kind
        };
        cur_seq += 1;
        if first_seq.is_none() {
            first_seq = Some(cur_seq);
        }
        last_seq = Some(cur_seq);
        let snap = serde_json::to_value(&obj)
            .map_err(|e| ActaError::Storage(format!("serialize legacy StoredObject failed: {e}")))?;
        let ws = WriteLedgerSummary {
            write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
            operation: WriteOperationKind::LegacyImportObject,
            item_id: obj.id,
            scope: obj.scope.clone(),
            version: obj.version,
            predecessor_id: obj.predecessor_id,
            content_hash: obj.content_hash,
            written_by: imported_by.to_string(),
            writer_auth_kind: eff_auth.to_string(),
            client_public_key: obj.client_public_key,
            client_signature: obj.client_signature.clone(),
            retraction_reason: None,
            record_snapshot: snap,
        };
        let ws_comm = compute_write_summary_commitment(&ws)?;
        let ev_hash = compute_evidence_event_hash_full(
            tenant_id,
            cur_seq,
            &cur_prev_hash,
            None,
            Some(&ws_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
            Some(&ws),
            None,
        )?;
        let ev_sig = sign_evidence_entry(host_key, tenant_id, cur_seq, &cur_prev_hash, &ev_hash);
        let ws_json = serde_json::to_value(&ws).map_err(|e| {
            ActaError::Storage(format!("serialize legacy write_meta failed: {e}"))
        })?;

        sqlx::query(
            r#"
            INSERT INTO evidence_history (
                tenant_id, seq_num, prev_hash, event_hash,
                bundle_hash, state_commitment, policy_result,
                write_meta, host_signature, created_at
            )
            VALUES ($1, $2, $3, $4, NULL, $5, 'allow', $6, $7, $8)
            "#,
        )
        .bind(tenant_id)
        .bind(cur_seq)
        .bind(cur_prev_hash.as_slice())
        .bind(ev_hash.as_slice())
        .bind(ws_comm.as_slice())
        .bind(ws_json)
        .bind(ev_sig.as_slice())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert legacy object evidence failed: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO legacy_backfilled_items (
                tenant_id, item_id, item_kind, scope, evidence_seq_num, created_at
            )
            VALUES ($1, $2, 'object', $3, $4, $5)
            "#,
        )
        .bind(tenant_id)
        .bind(obj.id)
        .bind(&obj.scope)
        .bind(cur_seq)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert legacy_backfilled_items failed: {e}")))?;

        cur_prev_hash = ev_hash;
        imported_objects += 1;
    }

    for mut clm in legacy_clms {
        let has_sig = clm.client_signature.is_some() && clm.client_public_key.is_some();
        if !has_sig {
            clm.client_signature = None;
            clm.client_public_key = None;
        }
        let eff_auth = if has_sig {
            "ed25519_client_sig"
        } else {
            writer_auth_kind
        };
        cur_seq += 1;
        if first_seq.is_none() {
            first_seq = Some(cur_seq);
        }
        last_seq = Some(cur_seq);
        let snap = serde_json::to_value(&clm).map_err(|e| {
            ActaError::Storage(format!("serialize legacy KnowledgeClaim failed: {e}"))
        })?;
        let ws = WriteLedgerSummary {
            write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
            operation: WriteOperationKind::LegacyImportClaim,
            item_id: clm.id,
            scope: clm.scope.clone(),
            version: clm.version,
            predecessor_id: clm.predecessor_id,
            content_hash: clm.content_hash,
            written_by: imported_by.to_string(),
            writer_auth_kind: eff_auth.to_string(),
            client_public_key: clm.client_public_key,
            client_signature: clm.client_signature.clone(),
            retraction_reason: clm.retraction_reason.clone(),
            record_snapshot: snap,
        };
        let ws_comm = compute_write_summary_commitment(&ws)?;
        let ev_hash = compute_evidence_event_hash_full(
            tenant_id,
            cur_seq,
            &cur_prev_hash,
            None,
            Some(&ws_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
            Some(&ws),
            None,
        )?;
        let ev_sig = sign_evidence_entry(host_key, tenant_id, cur_seq, &cur_prev_hash, &ev_hash);
        let ws_json = serde_json::to_value(&ws).map_err(|e| {
            ActaError::Storage(format!("serialize legacy claim write_meta failed: {e}"))
        })?;

        sqlx::query(
            r#"
            INSERT INTO evidence_history (
                tenant_id, seq_num, prev_hash, event_hash,
                bundle_hash, state_commitment, policy_result,
                write_meta, host_signature, created_at
            )
            VALUES ($1, $2, $3, $4, NULL, $5, 'allow', $6, $7, $8)
            "#,
        )
        .bind(tenant_id)
        .bind(cur_seq)
        .bind(cur_prev_hash.as_slice())
        .bind(ev_hash.as_slice())
        .bind(ws_comm.as_slice())
        .bind(ws_json)
        .bind(ev_sig.as_slice())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert legacy claim evidence failed: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO legacy_backfilled_items (
                tenant_id, item_id, item_kind, scope, evidence_seq_num, created_at
            )
            VALUES ($1, $2, 'claim', $3, $4, $5)
            "#,
        )
        .bind(tenant_id)
        .bind(clm.id)
        .bind(&clm.scope)
        .bind(cur_seq)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert legacy_backfilled_items failed: {e}")))?;

        cur_prev_hash = ev_hash;
        imported_claims += 1;
    }

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit backfill_legacy_scope tx failed: {e}")))?;

    Ok(BackfillLegacyScopeResponse {
        tenant_id: tenant_id.to_string(),
        scope: scope.to_string(),
        imported_objects,
        imported_claims,
        first_evidence_seq_num: first_seq,
        last_evidence_seq_num: last_seq,
    })
}
