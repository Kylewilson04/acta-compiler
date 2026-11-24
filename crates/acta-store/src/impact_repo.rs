use std::collections::{BTreeSet, HashMap};

use acta_crypto::{
    compute_rebuild_archive_header_hash, sign_rebuild_archive_header,
    verify_and_rebuild_scope_state_offline,
};
use acta_types::{
    ActaError, ActaResult, ClaimStatus, ContextBundle, ImpactBundleRecord,
    ImpactedCachedAnswerRecord, LedgerStateRebuildResponse, LifecycleStatus, ObjectType,
    StateRebuildArchive, TraceItemImpactResponse, STATE_REBUILD_ARCHIVE_SCHEMA_V1,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    answer_cache_repo::{
        compute_live_scope_state_commitment, compute_scoped_task_dependency_commitment_as_of,
        CacheDependencySpec,
    },
    claims_repo, evidence_repo, objects_repo, overrides_repo,
};

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

    let mut scope_commitments: HashMap<String, [u8; 32]> = HashMap::new();
    scope_commitments.insert(
        scope.clone(),
        compute_live_scope_state_commitment(pool, tenant_id, &scope, permission_root, now).await?,
    );
    for r in &dep_rows {
        if !scope_commitments.contains_key(&r.scope) {
            let live_sc = compute_live_scope_state_commitment(
                pool,
                tenant_id,
                &r.scope,
                permission_root,
                now,
            )
            .await?;
            scope_commitments.insert(r.scope.clone(), live_sc);
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
        let live_sc = scope_commitments
            .get(&r.scope)
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
            let live_sc = match scope_commitments.get(&cr.scope) {
                Some(sc) => *sc,
                None => {
                    let computed = compute_live_scope_state_commitment(
                        pool,
                        tenant_id,
                        &cr.scope,
                        permission_root,
                        now,
                    )
                    .await?;
                    scope_commitments.insert(cr.scope.clone(), computed);
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
    let chain = evidence_repo::fetch_tenant_evidence_chain(pool, tenant_id, up_to_seq).await?;
    if let Some(req_seq) = up_to_seq {
        if (chain.len() as i64) != req_seq {
            return Err(ActaError::Validation(format!(
                "up_to_seq={req_seq} exceeds tenant ledger head {}",
                chain.len()
            )));
        }
    }

    // When `up_to_seq` is specified, deterministically pin `evaluated_at` to `evidence_chain[up_to_seq - 1].created_at`
    // so historical state rebuilds (`e.g. up_to_seq = 184`) are 100% clock-independent (`v1.7.2+`, Should-Fix 4)!
    let evaluated_at = match (up_to_seq, chain.last()) {
        (Some(_), Some(tail)) => tail.created_at.trunc_subsecs(6),
        _ => Utc::now().trunc_subsecs(6),
    };

    let effective_seq = chain.len() as i64;
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
        STATE_REBUILD_ARCHIVE_SCHEMA_V1,
        tenant_id,
        scope,
        effective_seq,
        evaluated_at.timestamp_micros(),
        permission_root,
    );
    let host_header_signature = sign_rebuild_archive_header(host_key, tenant_id, &header_hash);

    let archive = StateRebuildArchive {
        schema_version: STATE_REBUILD_ARCHIVE_SCHEMA_V1.to_string(),
        tenant_id: tenant_id.to_string(),
        scope: scope.to_string(),
        up_to_seq: effective_seq,
        evaluated_at,
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

    let live_sc = compute_live_scope_state_commitment(
        pool,
        tenant_id,
        scope,
        permission_root,
        evaluated_at,
    )
    .await?;
    let live_sc_hex = hex::encode(live_sc);

    let (legacy_objs,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM objects WHERE tenant_id = $1 AND scope = $2 AND evidence_seq_num IS NULL",
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("count unchained objects failed: {e}")))?;

    let (legacy_clms,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM knowledge_claims WHERE tenant_id = $1 AND scope = $2 AND evidence_seq_num IS NULL",
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("count unchained claims failed: {e}")))?;

    Ok(LedgerStateRebuildResponse {
        tenant_id: offline.tenant_id,
        scope: offline.scope,
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
        live_store_state_commitment: live_sc_hex.clone(),
        matches_live_store_bit_for_bit: up_to_seq.is_none()
            && offline.reconstructed_state_commitment_hex == live_sc_hex,
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
