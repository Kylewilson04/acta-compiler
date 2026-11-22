use acta_crypto::{
    compute_checkpoint_hash, compute_evidence_event_hash_with_meta, compute_merkle_inclusion_proof,
    compute_merkle_root_from_leaves, compute_refusal_metadata_commitment, merkle_leaf_hash,
    sign_checkpoint_head, sign_evidence_entry,
};
use acta_types::{
    ActaError, ActaResult, ContextBundle, EntryInclusionProof, EvidenceEntry,
    ExternalWitnessAnchor, MerkleBundleProof, OverrideLedgerSummary, PolicyResultTag,
    RefusalMetadata, SignedTreeHead,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BundleWritePayload<'a> {
    pub bundle_hash: &'a [u8; 32],
    pub state_commitment: &'a [u8; 32],
    pub dependency_commitment: &'a [u8; 32],
    pub bundle_canonical: &'a [u8],
}

#[derive(FromRow)]
struct EvidenceRow {
    tenant_id: String,
    seq_num: i64,
    prev_hash: Vec<u8>,
    event_hash: Vec<u8>,
    bundle_hash: Option<Vec<u8>>,
    state_commitment: Option<Vec<u8>>,
    policy_result: String,
    refusal_meta: Option<Value>,
    override_meta: Option<Value>,
    host_signature: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl EvidenceRow {
    pub(crate) fn into_domain(self) -> ActaResult<EvidenceEntry> {
        let prev_hash: [u8; 32] = self
            .prev_hash
            .try_into()
            .map_err(|_| ActaError::Storage("prev_hash is not 32 bytes".to_string()))?;
        let event_hash: [u8; 32] = self
            .event_hash
            .try_into()
            .map_err(|_| ActaError::Storage("event_hash is not 32 bytes".to_string()))?;
        let bundle_hash: Option<[u8; 32]> = self
            .bundle_hash
            .map(|v| {
                v.try_into()
                    .map_err(|_| ActaError::Storage("bundle_hash is not 32 bytes".to_string()))
            })
            .transpose()?;
        let state_commitment: Option<[u8; 32]> = self
            .state_commitment
            .map(|v| {
                v.try_into()
                    .map_err(|_| ActaError::Storage("state_commitment is not 32 bytes".to_string()))
            })
            .transpose()?;
        let policy_result =
            PolicyResultTag::from_db_str(&self.policy_result).map_err(ActaError::Storage)?;
        let refusal_metadata: Option<RefusalMetadata> = self
            .refusal_meta
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ActaError::Storage(format!("refusal_meta deserialization failed: {e}"))
                })
            })
            .transpose()?;
        let override_summary: Option<OverrideLedgerSummary> = self
            .override_meta
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ActaError::Storage(format!("override_meta deserialization failed: {e}"))
                })
            })
            .transpose()?;
        let host_signature: [u8; 64] = self
            .host_signature
            .try_into()
            .map_err(|_| ActaError::Storage("host_signature is not 64 bytes".to_string()))?;

        Ok(EvidenceEntry {
            tenant_id: self.tenant_id,
            seq_num: self.seq_num,
            prev_hash,
            event_hash,
            bundle_hash,
            state_commitment,
            policy_result,
            refusal_metadata,
            override_summary,
            host_signature,
            created_at: self.created_at,
        })
    }
}

#[derive(FromRow)]
struct AnchorRow {
    id: Uuid,
    tenant_id: String,
    tree_size: i64,
    checkpoint_hash: Vec<u8>,
    witness_id: String,
    witness_public_key: Vec<u8>,
    witness_signature: Vec<u8>,
    external_uri: Option<String>,
    anchored_at: DateTime<Utc>,
}

impl AnchorRow {
    fn into_domain(self) -> ActaResult<ExternalWitnessAnchor> {
        let checkpoint_hash: [u8; 32] = self
            .checkpoint_hash
            .try_into()
            .map_err(|_| ActaError::Storage("anchor checkpoint_hash is not 32 bytes".to_string()))?;
        let witness_public_key: [u8; 32] = self.witness_public_key.try_into().map_err(|_| {
            ActaError::Storage("anchor witness_public_key is not 32 bytes".to_string())
        })?;
        let witness_signature: [u8; 64] = self.witness_signature.try_into().map_err(|_| {
            ActaError::Storage("anchor witness_signature is not 64 bytes".to_string())
        })?;
        Ok(ExternalWitnessAnchor {
            id: self.id,
            tenant_id: self.tenant_id,
            tree_size: self.tree_size,
            checkpoint_hash,
            witness_id: self.witness_id,
            witness_public_key,
            witness_signature,
            external_uri: self.external_uri,
            anchored_at: self.anchored_at,
        })
    }
}

/// Atomically appends an entry to `evidence_history` (and `context_bundles` when `bundle` is `Some`),
/// optionally binding `explicit_state_commitment` and structured `refusal_metadata`.
pub async fn append_evidence_full_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    policy_result: PolicyResultTag,
    bundle: Option<BundleWritePayload<'_>>,
    explicit_state_commitment: Option<&[u8; 32]>,
    refusal_metadata: Option<RefusalMetadata>,
    created_at: DateTime<Utc>,
) -> ActaResult<EvidenceEntry> {
    let created_at = created_at.trunc_subsecs(6);
    let computed_refusal_comm = match refusal_metadata {
        Some(ref rmeta) => Some(compute_refusal_metadata_commitment(rmeta)?),
        None => None,
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin evidence transaction failed: {e}")))?;

    let latest: (Option<i64>, Option<Vec<u8>>) = sqlx::query_as(
        r#"
        WITH _lock AS MATERIALIZED (
            SELECT pg_advisory_xact_lock(hashtext($1)::bigint)
        )
        SELECT e.seq_num, e.event_hash
        FROM _lock
        LEFT JOIN LATERAL (
            SELECT seq_num, event_hash
            FROM evidence_history
            WHERE tenant_id = $1
            ORDER BY seq_num DESC
            LIMIT 1
        ) e ON TRUE
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("lock + read latest evidence_history failed: {e}")))?;

    let (prev_seq, prev_hash): (i64, [u8; 32]) = match latest {
        (Some(seq), Some(raw_hash)) => {
            let arr: [u8; 32] = raw_hash.try_into().map_err(|_| {
                ActaError::Storage("corrupt prev event_hash length in evidence_history".to_string())
            })?;
            (seq, arr)
        }
        _ => (0, [0u8; 32]),
    };

    let seq_num = prev_seq + 1;

    if let Some(ref b) = bundle {
        sqlx::query(
            r#"
            INSERT INTO context_bundles (
                bundle_hash, tenant_id, state_commitment,
                dependency_commitment, bundle_canonical, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (bundle_hash) DO NOTHING
            "#,
        )
        .bind(b.bundle_hash.as_slice())
        .bind(tenant_id)
        .bind(b.state_commitment.as_slice())
        .bind(b.dependency_commitment.as_slice())
        .bind(b.bundle_canonical)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("insert context_bundle failed: {e}")))?;
    }

    let bundle_hash_opt = bundle.as_ref().map(|b| b.bundle_hash);
    let state_commitment_opt: Option<[u8; 32]> = bundle
        .as_ref()
        .map(|b| *b.state_commitment)
        .or(computed_refusal_comm)
        .or_else(|| explicit_state_commitment.copied());

    let event_hash = compute_evidence_event_hash_with_meta(
        tenant_id,
        seq_num,
        &prev_hash,
        bundle_hash_opt,
        state_commitment_opt.as_ref(),
        policy_result,
        created_at.timestamp_micros(),
        refusal_metadata.as_ref(),
        None,
    )?;

    let host_signature = sign_evidence_entry(host_key, tenant_id, seq_num, &prev_hash, &event_hash);

    let refusal_json: Option<Value> = match refusal_metadata {
        Some(ref rmeta) => Some(
            serde_json::to_value(rmeta)
                .map_err(|e| ActaError::Storage(format!("serialize refusal_meta failed: {e}")))?,
        ),
        None => None,
    };

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10)
        "#,
    )
    .bind(tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(bundle_hash_opt.map(|h| h.as_slice()))
    .bind(state_commitment_opt.as_ref().map(|h| h.as_slice()))
    .bind(policy_result.as_str())
    .bind(refusal_json)
    .bind(host_signature.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert evidence_history failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit evidence transaction failed: {e}")))?;

    Ok(EvidenceEntry {
        tenant_id: tenant_id.to_string(),
        seq_num,
        prev_hash,
        event_hash,
        bundle_hash: bundle_hash_opt.copied(),
        state_commitment: state_commitment_opt,
        policy_result,
        refusal_metadata,
        override_summary: None,
        host_signature,
        created_at,
    })
}

pub async fn append_refusal_metadata_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    policy_result: PolicyResultTag,
    meta: RefusalMetadata,
    created_at: DateTime<Utc>,
) -> ActaResult<EvidenceEntry> {
    append_evidence_full_tx(
        pool,
        host_key,
        tenant_id,
        policy_result,
        None,
        None,
        Some(meta),
        created_at,
    )
    .await
}

pub async fn append_evidence_with_commitment_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    policy_result: PolicyResultTag,
    bundle: Option<BundleWritePayload<'_>>,
    explicit_state_commitment: Option<&[u8; 32]>,
    created_at: DateTime<Utc>,
) -> ActaResult<EvidenceEntry> {
    append_evidence_full_tx(
        pool,
        host_key,
        tenant_id,
        policy_result,
        bundle,
        explicit_state_commitment,
        None,
        created_at,
    )
    .await
}

pub async fn append_evidence_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    policy_result: PolicyResultTag,
    bundle: Option<BundleWritePayload<'_>>,
    created_at: DateTime<Utc>,
) -> ActaResult<EvidenceEntry> {
    append_evidence_full_tx(
        pool,
        host_key,
        tenant_id,
        policy_result,
        bundle,
        None,
        None,
        created_at,
    )
    .await
}

pub async fn fetch_evidence_by_seq(
    pool: &PgPool,
    tenant_id: &str,
    seq_num: i64,
) -> ActaResult<Option<EvidenceEntry>> {
    let row = sqlx::query_as::<_, EvidenceRow>(
        r#"
        SELECT tenant_id, seq_num, prev_hash, event_hash,
               bundle_hash, state_commitment, policy_result,
               refusal_meta, override_meta, host_signature, created_at
        FROM evidence_history
        WHERE tenant_id = $1 AND seq_num = $2
        "#,
    )
    .bind(tenant_id)
    .bind(seq_num)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_evidence_by_seq failed: {e}")))?;

    row.map(EvidenceRow::into_domain).transpose()
}

pub async fn fetch_evidence_by_seqs(
    pool: &PgPool,
    tenant_id: &str,
    seq_nums: &[i64],
) -> ActaResult<Vec<EvidenceEntry>> {
    if seq_nums.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, EvidenceRow>(
        r#"
        SELECT tenant_id, seq_num, prev_hash, event_hash,
               bundle_hash, state_commitment, policy_result,
               refusal_meta, override_meta, host_signature, created_at
        FROM evidence_history
        WHERE tenant_id = $1 AND seq_num = ANY($2)
        ORDER BY seq_num ASC
        "#,
    )
    .bind(tenant_id)
    .bind(seq_nums)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_evidence_by_seqs failed: {e}")))?;

    rows.into_iter().map(EvidenceRow::into_domain).collect()
}

pub async fn fetch_tenant_evidence_chain(
    pool: &PgPool,
    tenant_id: &str,
    up_to_seq_num: Option<i64>,
) -> ActaResult<Vec<EvidenceEntry>> {
    let rows = match up_to_seq_num {
        Some(max_seq) => {
            sqlx::query_as::<_, EvidenceRow>(
                r#"
                SELECT tenant_id, seq_num, prev_hash, event_hash,
                       bundle_hash, state_commitment, policy_result,
                       refusal_meta, override_meta, host_signature, created_at
                FROM evidence_history
                WHERE tenant_id = $1 AND seq_num <= $2
                ORDER BY seq_num ASC
                "#,
            )
            .bind(tenant_id)
            .bind(max_seq)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, EvidenceRow>(
                r#"
                SELECT tenant_id, seq_num, prev_hash, event_hash,
                       bundle_hash, state_commitment, policy_result,
                       refusal_meta, override_meta, host_signature, created_at
                FROM evidence_history
                WHERE tenant_id = $1
                ORDER BY seq_num ASC
                "#,
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(|e| ActaError::Storage(format!("fetch_tenant_evidence_chain failed: {e}")))?;

    rows.into_iter().map(EvidenceRow::into_domain).collect()
}

/// Fetches lightweight `(seq_num, event_hash, created_at)` leaf headers for a tenant up to `up_to_size`
/// and computes a deterministic `SignedTreeHead` pinned to the head entry's `created_at` watermark.
pub async fn build_signed_tree_head(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    up_to_size: Option<i64>,
) -> ActaResult<Option<(SignedTreeHead, Vec<[u8; 32]>)>> {
    let rows: Vec<(i64, Vec<u8>, DateTime<Utc>)> = match up_to_size {
        Some(limit_n) => {
            sqlx::query_as(
                r#"
                SELECT seq_num, event_hash, created_at
                FROM evidence_history
                WHERE tenant_id = $1 AND seq_num <= $2
                ORDER BY seq_num ASC
                "#,
            )
            .bind(tenant_id)
            .bind(limit_n)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as(
                r#"
                SELECT seq_num, event_hash, created_at
                FROM evidence_history
                WHERE tenant_id = $1
                ORDER BY seq_num ASC
                "#,
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(|e| ActaError::Storage(format!("fetch merkle leaf headers failed: {e}")))?;

    if rows.is_empty() {
        return Ok(None);
    }

    if let Some(requested_n) = up_to_size {
        if (rows.len() as i64) != requested_n {
            return Err(ActaError::Validation(format!(
                "requested tree_size={requested_n} exceeds ledger head {} for tenant '{tenant_id}'",
                rows.len()
            )));
        }
    }

    let mut leaves = Vec::with_capacity(rows.len());
    let mut head_event_hash = [0u8; 32];
    let mut head_created_at = rows[0].2;

    for (idx, (seq_num, raw_ev, created_at)) in rows.into_iter().enumerate() {
        let expected_seq = (idx + 1) as i64;
        if seq_num != expected_seq {
            return Err(ActaError::Storage(format!(
                "gap detected in evidence_history at expected seq_num={expected_seq}, got {seq_num}"
            )));
        }
        let ev_arr: [u8; 32] = raw_ev.try_into().map_err(|_| {
            ActaError::Storage("corrupt 32-byte event_hash in evidence_history".to_string())
        })?;
        leaves.push(merkle_leaf_hash(seq_num, &ev_arr));
        head_event_hash = ev_arr;
        head_created_at = created_at.trunc_subsecs(6);
    }

    let tree_size = leaves.len() as i64;
    let merkle_root = compute_merkle_root_from_leaves(&leaves);
    let checkpoint_hash = compute_checkpoint_hash(
        tenant_id,
        tree_size,
        &head_event_hash,
        &merkle_root,
        head_created_at.timestamp_micros(),
    );
    let host_signature = sign_checkpoint_head(host_key, tenant_id, &checkpoint_hash);
    let witness_anchors = fetch_witness_anchors_for_size(pool, tenant_id, tree_size).await?;

    let sth = SignedTreeHead {
        tenant_id: tenant_id.to_string(),
        tree_size,
        head_event_hash,
        merkle_root,
        issued_at: head_created_at,
        checkpoint_hash,
        host_signature,
        witness_anchors,
    };

    Ok(Some((sth, leaves)))
}

/// Fetches a persisted `ContextBundle`, its notarizing `EvidenceEntry`, and either:
/// - `include_full_chain = true`: both `evidence_chain[1..=target_seq]` AND `MerkleBundleProof`
/// - `include_full_chain = false`: ONLY the `O(log N)` `MerkleBundleProof` (`evidence_chain = []`)!
pub async fn fetch_bundle_with_merkle_or_chain(
    pool: &PgPool,
    host_key: &SigningKey,
    bundle_hash: &[u8; 32],
    override_seq_nums: &[i64],
    include_full_chain: bool,
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>, MerkleBundleProof)> {
    let bundle_row: Option<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT tenant_id, bundle_canonical
        FROM context_bundles
        WHERE bundle_hash = $1
        "#,
    )
    .bind(bundle_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch context_bundle failed: {e}")))?;

    let (tenant_id, canonical_bytes) = bundle_row.ok_or_else(|| {
        ActaError::NotFound(format!(
            "context_bundle not found for hash {}",
            acta_crypto_hex(bundle_hash)
        ))
    })?;

    let bundle: ContextBundle = serde_json::from_slice(&canonical_bytes).map_err(|e| {
        ActaError::Storage(format!("stored bundle_canonical deserialization failed: {e}"))
    })?;

    let max_seq: Option<(Option<i64>,)> = sqlx::query_as(
        r#"
        SELECT MAX(seq_num)
        FROM evidence_history
        WHERE tenant_id = $1 AND bundle_hash = $2
        "#,
    )
    .bind(&tenant_id)
    .bind(bundle_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("lookup bundle evidence seq_num failed: {e}")))?;

    let target_seq = max_seq.and_then(|(s,)| s).ok_or_else(|| {
        ActaError::NotFound(format!(
            "no evidence_history entry found binding bundle_hash {}",
            acta_crypto_hex(bundle_hash)
        ))
    })?;

    let (sth, leaves) = build_signed_tree_head(pool, host_key, &tenant_id, Some(target_seq))
        .await?
        .ok_or_else(|| ActaError::Storage("empty evidence_history for existing bundle".to_string()))?;

    let bundle_entry = fetch_evidence_by_seq(pool, &tenant_id, target_seq)
        .await?
        .ok_or_else(|| ActaError::Storage(format!("missing evidence seq_num={target_seq}")))?;

    let bundle_path = compute_merkle_inclusion_proof(&leaves, (target_seq - 1) as usize)?
        .into_iter()
        .map(|h| acta_crypto_hex(&h))
        .collect();

    let mut unique_ovr_seqs: Vec<i64> = override_seq_nums.to_vec();
    for res in &bundle.resolution_records {
        if let Some(ref ovr) = res.override_attestation {
            unique_ovr_seqs.push(ovr.evidence_seq_num);
        }
    }
    for disp in &bundle.dispute_records {
        if let Some(ref lapsed) = disp.lapsed_override {
            unique_ovr_seqs.push(lapsed.evidence_seq_num);
        }
    }
    unique_ovr_seqs.retain(|&s| s >= 1 && s <= target_seq);
    unique_ovr_seqs.sort_unstable();
    unique_ovr_seqs.dedup();

    let ovr_entries = fetch_evidence_by_seqs(pool, &tenant_id, &unique_ovr_seqs).await?;
    let mut override_entry_proofs = Vec::with_capacity(ovr_entries.len());
    for oe in ovr_entries {
        let p = compute_merkle_inclusion_proof(&leaves, (oe.seq_num - 1) as usize)?
            .into_iter()
            .map(|h| acta_crypto_hex(&h))
            .collect();
        override_entry_proofs.push(EntryInclusionProof {
            entry: oe,
            audit_path: p,
        });
    }

    let merkle_proof = MerkleBundleProof {
        checkpoint: sth,
        bundle_entry_proof: EntryInclusionProof {
            entry: bundle_entry,
            audit_path: bundle_path,
        },
        override_entry_proofs,
    };

    let chain = if include_full_chain {
        fetch_tenant_evidence_chain(pool, &tenant_id, Some(target_seq)).await?
    } else {
        Vec::new()
    };

    Ok((bundle, chain, merkle_proof))
}

/// Fetches a persisted `ContextBundle` and its tenant's evidence chain slice up to the latest
/// evidence entry referencing `bundle_hash`.
pub async fn fetch_bundle_with_evidence_slice(
    pool: &PgPool,
    bundle_hash: &[u8; 32],
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>)> {
    let bundle_row: Option<(String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT tenant_id, bundle_canonical
        FROM context_bundles
        WHERE bundle_hash = $1
        "#,
    )
    .bind(bundle_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch context_bundle failed: {e}")))?;

    let (tenant_id, canonical_bytes) = bundle_row.ok_or_else(|| {
        ActaError::NotFound(format!(
            "context_bundle not found for hash {}",
            acta_crypto_hex(bundle_hash)
        ))
    })?;

    let bundle: ContextBundle = serde_json::from_slice(&canonical_bytes).map_err(|e| {
        ActaError::Storage(format!("stored bundle_canonical deserialization failed: {e}"))
    })?;

    let max_seq: Option<(Option<i64>,)> = sqlx::query_as(
        r#"
        SELECT MAX(seq_num)
        FROM evidence_history
        WHERE tenant_id = $1 AND bundle_hash = $2
        "#,
    )
    .bind(&tenant_id)
    .bind(bundle_hash.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("lookup bundle evidence seq_num failed: {e}")))?;

    let target_seq = max_seq.and_then(|(s,)| s);
    let chain = fetch_tenant_evidence_chain(pool, &tenant_id, target_seq).await?;

    Ok((bundle, chain))
}

/// Persists an immutable external witness cosignature over `(tenant_id, tree_size, checkpoint_hash)`.
pub async fn insert_witness_anchor(
    pool: &PgPool,
    head_event_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    anchor: ExternalWitnessAnchor,
) -> ActaResult<ExternalWitnessAnchor> {
    let anchored_at = anchor.anchored_at.trunc_subsecs(6);
    let row = sqlx::query_as::<_, AnchorRow>(
        r#"
        INSERT INTO checkpoint_anchors (
            id, tenant_id, tree_size, head_event_hash, merkle_root, checkpoint_hash,
            witness_id, witness_public_key, witness_signature, external_uri, anchored_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (tenant_id, tree_size, witness_public_key) DO UPDATE
            SET id = checkpoint_anchors.id
        RETURNING id, tenant_id, tree_size, checkpoint_hash, witness_id,
                  witness_public_key, witness_signature, external_uri, anchored_at
        "#,
    )
    .bind(anchor.id)
    .bind(&anchor.tenant_id)
    .bind(anchor.tree_size)
    .bind(head_event_hash.as_slice())
    .bind(merkle_root.as_slice())
    .bind(anchor.checkpoint_hash.as_slice())
    .bind(&anchor.witness_id)
    .bind(anchor.witness_public_key.as_slice())
    .bind(anchor.witness_signature.as_slice())
    .bind(anchor.external_uri.as_deref())
    .bind(anchored_at)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("immutable") {
            ActaError::Validation("__EXISTING_ANCHOR__".to_string())
        } else {
            ActaError::Storage(format!("insert checkpoint_anchors failed: {e}"))
        }
    });

    match row {
        Ok(r) => r.into_domain(),
        Err(ActaError::Validation(ref s)) if s == "__EXISTING_ANCHOR__" => {
            let existing = sqlx::query_as::<_, AnchorRow>(
                r#"
                SELECT id, tenant_id, tree_size, checkpoint_hash, witness_id,
                       witness_public_key, witness_signature, external_uri, anchored_at
                FROM checkpoint_anchors
                WHERE tenant_id = $1 AND tree_size = $2 AND witness_public_key = $3
                "#,
            )
            .bind(&anchor.tenant_id)
            .bind(anchor.tree_size)
            .bind(anchor.witness_public_key.as_slice())
            .fetch_one(pool)
            .await
            .map_err(|e| ActaError::Storage(format!("fetch existing checkpoint_anchor failed: {e}")))?;
            existing.into_domain()
        }
        Err(other) => Err(other),
    }
}

pub async fn fetch_witness_anchors_for_size(
    pool: &PgPool,
    tenant_id: &str,
    tree_size: i64,
) -> ActaResult<Vec<ExternalWitnessAnchor>> {
    let rows = sqlx::query_as::<_, AnchorRow>(
        r#"
        SELECT id, tenant_id, tree_size, checkpoint_hash, witness_id,
               witness_public_key, witness_signature, external_uri, anchored_at
        FROM checkpoint_anchors
        WHERE tenant_id = $1 AND tree_size = $2
        ORDER BY anchored_at ASC, id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(tree_size)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_witness_anchors_for_size failed: {e}")))?;

    rows.into_iter().map(AnchorRow::into_domain).collect()
}

pub async fn fetch_recent_witness_anchors(
    pool: &PgPool,
    tenant_id: &str,
) -> ActaResult<Vec<ExternalWitnessAnchor>> {
    let rows = sqlx::query_as::<_, AnchorRow>(
        r#"
        SELECT id, tenant_id, tree_size, checkpoint_hash, witness_id,
               witness_public_key, witness_signature, external_uri, anchored_at
        FROM checkpoint_anchors
        WHERE tenant_id = $1
        ORDER BY tree_size DESC, anchored_at DESC
        LIMIT 50
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_recent_witness_anchors failed: {e}")))?;

    rows.into_iter().map(AnchorRow::into_domain).collect()
}

fn acta_crypto_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}
