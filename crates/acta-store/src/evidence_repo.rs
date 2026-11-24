use acta_crypto::{
    compute_checkpoint_hash, compute_evidence_event_hash_with_meta,
    compute_legacy_blake3_merkle_root_from_events,
    compute_merkle_consistency_proof, compute_merkle_inclusion_proof,
    compute_merkle_root_from_leaves, compute_refusal_metadata_commitment,
    compute_witness_registration_by_domain, compute_witness_registration_v3_commitment,
    compute_witness_revocation_by_domain, compute_witness_revocation_v2_commitment,
    merkle_leaf_hash,
    sign_checkpoint_head,
    sign_evidence_entry, witness_registration_preimage_bytes, witness_revocation_preimage_bytes,
};
use acta_types::{
    ActaError, ActaResult, AnswerCacheLedgerSummary, ContextBundle, EntryInclusionProof, EvidenceEntry, WriteLedgerSummary,
    ExternalWitnessAnchor, MerkleBundleProof, OverrideLedgerSummary, PolicyResultTag,
    QuarantinedAnchorRecord, RefusalMetadata, SignedTreeHead, TrustedWitness,
    WitnessRegistrationSummary, WitnessRevocationSummary, WITNESS_REG_DOMAIN_V1,
    WITNESS_REG_DOMAIN_V3, WITNESS_REVOKE_DOMAIN_V1, WITNESS_REVOKE_DOMAIN_V2,
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
    write_meta: Option<Value>,
    answer_cache_meta: Option<Value>,
    host_signature: Vec<u8>,
    created_at: DateTime<Utc>,
    witness_reg_id: Option<String>,
    witness_reg_public_key: Option<Vec<u8>>,
    witness_reg_by: Option<String>,
    witness_reg_desc: Option<String>,
    witness_reg_domain: Option<String>,
    witness_rev_id: Option<String>,
    witness_rev_public_key: Option<Vec<u8>>,
    witness_rev_by: Option<String>,
    witness_rev_mode: Option<String>,
    witness_rev_eff_tree_size: Option<i64>,
    witness_rev_reason: Option<String>,
    witness_rev_domain: Option<String>,
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
        let write_summary: Option<WriteLedgerSummary> = self
            .write_meta
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ActaError::Storage(format!("write_meta deserialization failed: {e}"))
                })
            })
            .transpose()?;
        let answer_cache_summary: Option<AnswerCacheLedgerSummary> = self
            .answer_cache_meta
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ActaError::Storage(format!("answer_cache_meta deserialization failed: {e}"))
                })
            })
            .transpose()?;
        let host_signature: [u8; 64] = self
            .host_signature
            .try_into()
            .map_err(|_| ActaError::Storage("host_signature is not 64 bytes".to_string()))?;

        let witness_reg_summary = match (
            self.witness_reg_id,
            self.witness_reg_public_key,
            self.witness_reg_by,
        ) {
            (Some(wid), Some(raw_pk), Some(reg_by)) => {
                let pk_arr: [u8; 32] = raw_pk.try_into().map_err(|_| {
                    ActaError::Storage(
                        "trusted_witnesses.public_key join column is not 32 bytes".to_string(),
                    )
                })?;
                let reg_domain = self
                    .witness_reg_domain
                    .unwrap_or_else(|| WITNESS_REG_DOMAIN_V1.to_string());
                let preimage = witness_registration_preimage_bytes(
                    &reg_domain,
                    &self.tenant_id,
                    &wid,
                    &pk_arr,
                    &reg_by,
                    self.witness_reg_desc.as_deref(),
                )
                .map_err(ActaError::Storage)?;
                Some(WitnessRegistrationSummary {
                    witness_id: wid,
                    public_key: pk_arr,
                    registered_by: reg_by,
                    description: self.witness_reg_desc,
                    registration_domain: reg_domain,
                    registration_blake3_preimage_hex: acta_crypto_hex(&preimage),
                })
            }
            _ => None,
        };

        let witness_revoke_summary = match (
            self.witness_rev_id,
            self.witness_rev_public_key,
            self.witness_rev_by,
            self.witness_rev_reason,
        ) {
            (Some(wid), Some(raw_pk), Some(rev_by), Some(reason)) => {
                let pk_arr: [u8; 32] = raw_pk.try_into().map_err(|_| {
                    ActaError::Storage(
                        "witness_revocations.public_key join column is not 32 bytes".to_string(),
                    )
                })?;
                let rev_domain = self
                    .witness_rev_domain
                    .unwrap_or_else(|| WITNESS_REVOKE_DOMAIN_V1.to_string());
                let rev_mode = self
                    .witness_rev_mode
                    .unwrap_or_else(|| "compromise".to_string());
                let rev_eff = self.witness_rev_eff_tree_size;
                let preimage = witness_revocation_preimage_bytes(
                    &rev_domain,
                    &self.tenant_id,
                    &wid,
                    &pk_arr,
                    &rev_by,
                    &rev_mode,
                    rev_eff,
                    &reason,
                )
                .map_err(ActaError::Storage)?;
                Some(WitnessRevocationSummary {
                    witness_id: wid,
                    public_key: pk_arr,
                    revoked_by: rev_by,
                    revocation_mode: rev_mode,
                    effective_from_tree_size: rev_eff,
                    reason,
                    revocation_domain: rev_domain,
                    revocation_blake3_preimage_hex: acta_crypto_hex(&preimage),
                })
            }
            _ => None,
        };

        let event_domain = Some(
            EvidenceEntry::inferred_event_domain_v17(
                refusal_metadata.is_some(),
                override_summary.is_some(),
                write_summary.is_some(),
                answer_cache_summary.is_some(),
            )
            .to_string(),
        );

        Ok(EvidenceEntry {
            tenant_id: self.tenant_id,
            seq_num: self.seq_num,
            event_domain,
            prev_hash,
            event_hash,
            bundle_hash,
            state_commitment,
            policy_result,
            refusal_metadata,
            override_summary,
            write_summary,
            answer_cache_summary,
            witness_reg_summary,
            witness_revoke_summary,
            host_signature,
            created_at: self.created_at,
        })
    }
}

#[derive(FromRow)]
struct TrustedWitnessRow {
    tenant_id: String,
    witness_id: String,
    public_key: Vec<u8>,
    description: Option<String>,
    registered_by: String,
    reg_domain: String,
    evidence_seq_num: i64,
    active: bool,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<String>,
    revocation_mode: Option<String>,
    effective_from_tree_size: Option<i64>,
    revocation_reason: Option<String>,
    revocation_evidence_seq_num: Option<i64>,
    revocation_domain: Option<String>,
}

impl TrustedWitnessRow {
    fn into_domain(self) -> ActaResult<(TrustedWitness, Option<String>)> {
        let public_key: [u8; 32] = self.public_key.try_into().map_err(|_| {
            ActaError::Storage("trusted_witness public_key is not 32 bytes".to_string())
        })?;
        let is_revoked = self.revoked_at.is_some();
        Ok((
            TrustedWitness {
                tenant_id: self.tenant_id,
                witness_id: self.witness_id,
                public_key,
                description: self.description,
                registered_by: self.registered_by,
                reg_domain: self.reg_domain,
                evidence_seq_num: self.evidence_seq_num,
                active: self.active && !is_revoked,
                created_at: self.created_at,
                revoked_at: self.revoked_at,
                revoked_by: self.revoked_by,
                revocation_mode: self.revocation_mode,
                effective_from_tree_size: self.effective_from_tree_size,
                revocation_reason: self.revocation_reason,
                revocation_evidence_seq_num: self.revocation_evidence_seq_num,
            },
            self.revocation_domain,
        ))
    }
}

#[derive(Debug, Clone)]
pub enum WitnessRegistrationOutcome {
    Registered {
        witness: TrustedWitness,
        registration_domain: String,
        registration_preimage: Vec<u8>,
        registration_commitment: [u8; 32],
        was_idempotent_noop: bool,
    },
    Conflict {
        existing_witness_id: String,
        existing_public_key: [u8; 32],
        existing_revoked: bool,
    },
}

#[derive(Debug, Clone)]
pub enum WitnessRevocationOutcome {
    Revoked {
        witness: TrustedWitness,
        revocation_domain: String,
        revocation_preimage: Vec<u8>,
        revocation_commitment: [u8; 32],
        revocation_seq_num: i64,
        revoked_at: DateTime<Utc>,
        was_idempotent_noop: bool,
    },
    NotFound,
    AlreadyRevokedConflict {
        revoked_by: String,
        revocation_mode: String,
        effective_from_tree_size: Option<i64>,
        reason: String,
        revocation_seq_num: i64,
    },
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

#[derive(FromRow)]
struct QuarantinedAnchorRow {
    id: Uuid,
    tenant_id: String,
    tree_size: i64,
    head_event_hash: Vec<u8>,
    merkle_root: Vec<u8>,
    checkpoint_hash: Vec<u8>,
    witness_id: String,
    witness_public_key: Vec<u8>,
    witness_signature: Vec<u8>,
    external_uri: Option<String>,
    anchored_at: DateTime<Utc>,
    quarantine_reason: String,
}

impl QuarantinedAnchorRow {
    fn into_domain(self) -> ActaResult<QuarantinedAnchorRecord> {
        let head_event_hash: [u8; 32] = self.head_event_hash.try_into().map_err(|_| {
            ActaError::Storage("quarantined anchor head_event_hash is not 32 bytes".to_string())
        })?;
        let merkle_root: [u8; 32] = self.merkle_root.try_into().map_err(|_| {
            ActaError::Storage("quarantined anchor merkle_root is not 32 bytes".to_string())
        })?;
        let checkpoint_hash: [u8; 32] = self.checkpoint_hash.try_into().map_err(|_| {
            ActaError::Storage("quarantined anchor checkpoint_hash is not 32 bytes".to_string())
        })?;
        let witness_public_key: [u8; 32] = self.witness_public_key.try_into().map_err(|_| {
            ActaError::Storage("quarantined anchor witness_public_key is not 32 bytes".to_string())
        })?;
        let witness_signature: [u8; 64] = self.witness_signature.try_into().map_err(|_| {
            ActaError::Storage("quarantined anchor witness_signature is not 64 bytes".to_string())
        })?;
        Ok(QuarantinedAnchorRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            tree_size: self.tree_size,
            head_event_hash,
            merkle_root,
            checkpoint_hash,
            witness_id: self.witness_id,
            witness_public_key,
            witness_signature,
            external_uri: self.external_uri,
            anchored_at: self.anchored_at,
            merkle_scheme: "rfc6962-sha256-v1".to_string(),
            quarantine_reason: self.quarantine_reason,
        })
    }
}

/// Atomically appends an entry to `evidence_history` (and `context_bundles` when `bundle` is `Some`),
/// optionally binding `explicit_state_commitment` and structured `refusal_metadata`.
/// Acquires an exclusive 64-bit BLAKE3-keyed per-tenant PostgreSQL advisory transaction lock
/// (`pg_advisory_xact_lock`) as a standalone statement FIRST, and ONLY THEN executes a second
/// `SELECT` statement to read the latest `(seq_num, event_hash)` head (`v1.6.7+`).
///
/// Under PostgreSQL `READ COMMITTED`, a single-statement `WITH _lock AS MATERIALIZED (SELECT pg_advisory_xact_lock(...))`
/// acquires its MVCC snapshot *before* blocking on the advisory lock, causing concurrent writers to
/// read a stale pre-lock `seq_num` and collide on `evidence_history_pkey`. Splitting the lock and
/// head read into two separate statements forces a fresh post-lock MVCC snapshot on every transaction.
pub(crate) async fn lock_and_read_latest_evidence_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
) -> ActaResult<(i64, [u8; 32])> {
    let lock_digest = acta_crypto::hash_length_delimited(&[b"acta:evidence_lock:v1", tenant_id.as_bytes()]);
    let lock_id = i64::from_le_bytes(
        lock_digest[..8]
            .try_into()
            .expect("8-byte slice"),
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            ActaError::Storage(format!("acquire tenant evidence advisory lock failed: {e}"))
        })?;

    let latest_opt: Option<(i64, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT seq_num, event_hash
        FROM evidence_history
        WHERE tenant_id = $1
        ORDER BY seq_num DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        ActaError::Storage(format!("read post-lock latest evidence_history failed: {e}"))
    })?;

    match latest_opt {
        Some((seq, raw_hash)) => {
            let arr: [u8; 32] = raw_hash.try_into().map_err(|_| {
                ActaError::Storage("corrupt prev event_hash length in evidence_history".to_string())
            })?;
            Ok((seq, arr))
        }
        None => Ok((0, [0u8; 32])),
    }
}

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

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, tenant_id).await?;

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

        if let Ok(parsed_bundle) = serde_json::from_slice::<ContextBundle>(b.bundle_canonical) {
            crate::impact_repo::insert_bundle_dependencies_in_tx(
                &mut tx,
                tenant_id,
                b.bundle_hash,
                &parsed_bundle,
                created_at,
            )
            .await?;
        }
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

    let event_domain = Some(
        EvidenceEntry::inferred_event_domain(refusal_metadata.is_some(), false).to_string(),
    );

    Ok(EvidenceEntry {
        tenant_id: tenant_id.to_string(),
        seq_num,
        event_domain,
        prev_hash,
        event_hash,
        bundle_hash: bundle_hash_opt.copied(),
        state_commitment: state_commitment_opt,
        policy_result,
        refusal_metadata,
        override_summary: None,
        write_summary: None,
        answer_cache_summary: None,
        witness_reg_summary: None,
        witness_revoke_summary: None,
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
        SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
               e.bundle_hash, e.state_commitment, e.policy_result,
               e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
               tw.witness_id AS witness_reg_id,
               tw.public_key AS witness_reg_public_key,
               tw.registered_by AS witness_reg_by,
               tw.description AS witness_reg_desc,
               tw.reg_domain AS witness_reg_domain,
               wr.witness_id AS witness_rev_id,
               wr.public_key AS witness_rev_public_key,
               wr.revoked_by AS witness_rev_by,
               wr.revocation_mode AS witness_rev_mode,
               wr.effective_from_tree_size AS witness_rev_eff_tree_size,
               wr.reason AS witness_rev_reason,
               wr.revoke_domain AS witness_rev_domain
        FROM evidence_history e
        LEFT JOIN trusted_witnesses tw
            ON tw.tenant_id = e.tenant_id
           AND tw.evidence_seq_num = e.seq_num
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = e.tenant_id
           AND wr.evidence_seq_num = e.seq_num
        WHERE e.tenant_id = $1 AND e.seq_num = $2
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
        SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
               e.bundle_hash, e.state_commitment, e.policy_result,
               e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
               tw.witness_id AS witness_reg_id,
               tw.public_key AS witness_reg_public_key,
               tw.registered_by AS witness_reg_by,
               tw.description AS witness_reg_desc,
               tw.reg_domain AS witness_reg_domain,
               wr.witness_id AS witness_rev_id,
               wr.public_key AS witness_rev_public_key,
               wr.revoked_by AS witness_rev_by,
               wr.revocation_mode AS witness_rev_mode,
               wr.effective_from_tree_size AS witness_rev_eff_tree_size,
               wr.reason AS witness_rev_reason,
               wr.revoke_domain AS witness_rev_domain
        FROM evidence_history e
        LEFT JOIN trusted_witnesses tw
            ON tw.tenant_id = e.tenant_id
           AND tw.evidence_seq_num = e.seq_num
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = e.tenant_id
           AND wr.evidence_seq_num = e.seq_num
        WHERE e.tenant_id = $1 AND e.seq_num = ANY($2)
        ORDER BY e.seq_num ASC
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
                SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
                       e.bundle_hash, e.state_commitment, e.policy_result,
                       e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
                       tw.witness_id AS witness_reg_id,
                       tw.public_key AS witness_reg_public_key,
                       tw.registered_by AS witness_reg_by,
                       tw.description AS witness_reg_desc,
                       tw.reg_domain AS witness_reg_domain,
                       wr.witness_id AS witness_rev_id,
                       wr.public_key AS witness_rev_public_key,
                       wr.revoked_by AS witness_rev_by,
                       wr.revocation_mode AS witness_rev_mode,
                       wr.effective_from_tree_size AS witness_rev_eff_tree_size,
                       wr.reason AS witness_rev_reason,
                       wr.revoke_domain AS witness_rev_domain
                FROM evidence_history e
                LEFT JOIN trusted_witnesses tw
                    ON tw.tenant_id = e.tenant_id
                   AND tw.evidence_seq_num = e.seq_num
                LEFT JOIN witness_revocations wr
                    ON wr.tenant_id = e.tenant_id
                   AND wr.evidence_seq_num = e.seq_num
                WHERE e.tenant_id = $1 AND e.seq_num <= $2
                ORDER BY e.seq_num ASC
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
                SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
                       e.bundle_hash, e.state_commitment, e.policy_result,
                       e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
                       tw.witness_id AS witness_reg_id,
                       tw.public_key AS witness_reg_public_key,
                       tw.registered_by AS witness_reg_by,
                       tw.description AS witness_reg_desc,
                       tw.reg_domain AS witness_reg_domain,
                       wr.witness_id AS witness_rev_id,
                       wr.public_key AS witness_rev_public_key,
                       wr.revoked_by AS witness_rev_by,
                       wr.revocation_mode AS witness_rev_mode,
                       wr.effective_from_tree_size AS witness_rev_eff_tree_size,
                       wr.reason AS witness_rev_reason,
                       wr.revoke_domain AS witness_rev_domain
                FROM evidence_history e
                LEFT JOIN trusted_witnesses tw
                    ON tw.tenant_id = e.tenant_id
                   AND tw.evidence_seq_num = e.seq_num
                LEFT JOIN witness_revocations wr
                    ON wr.tenant_id = e.tenant_id
                   AND wr.evidence_seq_num = e.seq_num
                WHERE e.tenant_id = $1
                ORDER BY e.seq_num ASC
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

/// Fetches a bounded page (`from_seq`, `limit` in `1..=500`) of `evidence_history` entries for `tenant_id`,
/// returning `(total_count, page_entries)` (`v1.6.7+`).
pub async fn fetch_tenant_evidence_page(
    pool: &PgPool,
    tenant_id: &str,
    from_seq: i64,
    limit: i64,
    up_to_seq_num: Option<i64>,
) -> ActaResult<(usize, Vec<EvidenceEntry>)> {
    if from_seq < 1 {
        return Err(ActaError::Validation(format!(
            "from_seq must be >= 1 (got {from_seq})"
        )));
    }
    if !(1..=500).contains(&limit) {
        return Err(ActaError::Validation(format!(
            "limit must be between 1 and 500 (got {limit})"
        )));
    }

    let total_i64: i64 = match up_to_seq_num {
        Some(max_seq) => sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM evidence_history WHERE tenant_id = $1 AND seq_num <= $2",
        )
        .bind(tenant_id)
        .bind(max_seq)
        .fetch_one(pool)
        .await,
        None => sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM evidence_history WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await,
    }
    .map_err(|e| ActaError::Storage(format!("count tenant evidence_history failed: {e}")))?;

    let rows = match up_to_seq_num {
        Some(max_seq) => {
            sqlx::query_as::<_, EvidenceRow>(
                r#"
                SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
                       e.bundle_hash, e.state_commitment, e.policy_result,
                       e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
                       tw.witness_id AS witness_reg_id,
                       tw.public_key AS witness_reg_public_key,
                       tw.registered_by AS witness_reg_by,
                       tw.description AS witness_reg_desc,
                       tw.reg_domain AS witness_reg_domain,
                       wr.witness_id AS witness_rev_id,
                       wr.public_key AS witness_rev_public_key,
                       wr.revoked_by AS witness_rev_by,
                       wr.revocation_mode AS witness_rev_mode,
                       wr.effective_from_tree_size AS witness_rev_eff_tree_size,
                       wr.reason AS witness_rev_reason,
                       wr.revoke_domain AS witness_rev_domain
                FROM evidence_history e
                LEFT JOIN trusted_witnesses tw
                    ON tw.tenant_id = e.tenant_id
                   AND tw.evidence_seq_num = e.seq_num
                LEFT JOIN witness_revocations wr
                    ON wr.tenant_id = e.tenant_id
                   AND wr.evidence_seq_num = e.seq_num
                WHERE e.tenant_id = $1 AND e.seq_num >= $2 AND e.seq_num <= $3
                ORDER BY e.seq_num ASC
                LIMIT $4
                "#,
            )
            .bind(tenant_id)
            .bind(from_seq)
            .bind(max_seq)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, EvidenceRow>(
                r#"
                SELECT e.tenant_id, e.seq_num, e.prev_hash, e.event_hash,
                       e.bundle_hash, e.state_commitment, e.policy_result,
                       e.refusal_meta, e.override_meta, e.write_meta, e.answer_cache_meta, e.host_signature, e.created_at,
                       tw.witness_id AS witness_reg_id,
                       tw.public_key AS witness_reg_public_key,
                       tw.registered_by AS witness_reg_by,
                       tw.description AS witness_reg_desc,
                       tw.reg_domain AS witness_reg_domain,
                       wr.witness_id AS witness_rev_id,
                       wr.public_key AS witness_rev_public_key,
                       wr.revoked_by AS witness_rev_by,
                       wr.revocation_mode AS witness_rev_mode,
                       wr.effective_from_tree_size AS witness_rev_eff_tree_size,
                       wr.reason AS witness_rev_reason,
                       wr.revoke_domain AS witness_rev_domain
                FROM evidence_history e
                LEFT JOIN trusted_witnesses tw
                    ON tw.tenant_id = e.tenant_id
                   AND tw.evidence_seq_num = e.seq_num
                LEFT JOIN witness_revocations wr
                    ON wr.tenant_id = e.tenant_id
                   AND wr.evidence_seq_num = e.seq_num
                WHERE e.tenant_id = $1 AND e.seq_num >= $2
                ORDER BY e.seq_num ASC
                LIMIT $3
                "#,
            )
            .bind(tenant_id)
            .bind(from_seq)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(|e| ActaError::Storage(format!("fetch_tenant_evidence_page failed: {e}")))?;

    let entries: Vec<EvidenceEntry> = rows
        .into_iter()
        .map(EvidenceRow::into_domain)
        .collect::<ActaResult<Vec<_>>>()?;
    Ok((usize::try_from(total_i64.max(0)).unwrap_or(0), entries))
}

/// Zero-oracle tenant filter for `context_bundles` hash lookups (`v1.6.7+`): ensures a foreign
/// tenant's `bundle_hash` returns the exact same `NotFound` error as a nonexistent hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantLookupScope<'a> {
    Any,
    Exact(&'a str),
    SandboxPrefix(&'a str),
}

async fn fetch_scoped_bundle_row(
    pool: &PgPool,
    tenant_scope: TenantLookupScope<'_>,
    bundle_hash: &[u8; 32],
) -> ActaResult<(String, Vec<u8>)> {
    let bundle_row: Option<(String, Vec<u8>)> = match tenant_scope {
        TenantLookupScope::Exact(tid) => sqlx::query_as(
            r#"
            SELECT tenant_id, bundle_canonical
            FROM context_bundles
            WHERE tenant_id = $1 AND bundle_hash = $2
            "#,
        )
        .bind(tid)
        .bind(bundle_hash.as_slice())
        .fetch_optional(pool)
        .await,
        TenantLookupScope::SandboxPrefix(pfx) => sqlx::query_as(
            r#"
            SELECT tenant_id, bundle_canonical
            FROM context_bundles
            WHERE tenant_id LIKE ($1 || '%') AND bundle_hash = $2
            "#,
        )
        .bind(pfx)
        .bind(bundle_hash.as_slice())
        .fetch_optional(pool)
        .await,
        TenantLookupScope::Any => sqlx::query_as(
            r#"
            SELECT tenant_id, bundle_canonical
            FROM context_bundles
            WHERE bundle_hash = $1
            "#,
        )
        .bind(bundle_hash.as_slice())
        .fetch_optional(pool)
        .await,
    }
    .map_err(|e| ActaError::Storage(format!("fetch context_bundle failed: {e}")))?;

    bundle_row.ok_or_else(|| {
        ActaError::NotFound(format!(
            "context_bundle not found for hash {}",
            acta_crypto_hex(bundle_hash)
        ))
    })
}

/// Fetches lightweight `(seq_num, event_hash, created_at)` leaf headers for a tenant up to `up_to_size`
/// and computes a deterministic RFC 6962 §2.1 SHA-256 `SignedTreeHead` pinned to the head entry's `created_at`.
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
    let witness_anchors =
        fetch_witness_anchors_for_size(pool, tenant_id, tree_size, &checkpoint_hash).await?;

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

/// Fetches a persisted `ContextBundle`, its notarizing `EvidenceEntry`, optional linear `evidence_chain`,
/// and `MerkleBundleProof` — automatically attaching `anchored_checkpoint` + `consistency_proof_to_anchor`
/// when `anchor_tree_size` is requested or when a newer active witness-anchored checkpoint exists (`v1.6.2+`).
pub async fn fetch_bundle_with_merkle_options(
    pool: &PgPool,
    host_key: &SigningKey,
    bundle_hash: &[u8; 32],
    override_seq_nums: &[i64],
    include_full_chain: bool,
    anchor_tree_size: Option<i64>,
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>, MerkleBundleProof)> {
    fetch_bundle_with_merkle_options_scoped(
        pool,
        host_key,
        TenantLookupScope::Any,
        bundle_hash,
        override_seq_nums,
        include_full_chain,
        anchor_tree_size,
    )
    .await
}

pub async fn fetch_bundle_with_merkle_options_scoped(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_scope: TenantLookupScope<'_>,
    bundle_hash: &[u8; 32],
    override_seq_nums: &[i64],
    include_full_chain: bool,
    anchor_tree_size: Option<i64>,
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>, MerkleBundleProof)> {
    let (tenant_id, canonical_bytes) =
        fetch_scoped_bundle_row(pool, tenant_scope, bundle_hash).await?;

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

    if let Some(req_m) = anchor_tree_size {
        if req_m < target_seq {
            return Err(ActaError::Validation(format!(
                "anchor_tree_size={req_m} must be >= bundle evidence seq_num={target_seq}"
            )));
        }
    }

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

    let sel_obj_ids: Vec<Uuid> = bundle.selected_objects.iter().map(|o| o.id).collect();
    let mut sel_claim_ids: Vec<Uuid> = Vec::new();
    for res in &bundle.resolution_records {
        sel_claim_ids.push(res.winning_claim.id);
    }
    for disp in &bundle.dispute_records {
        for cand in &disp.competing_claims {
            sel_claim_ids.push(cand.id);
        }
    }
    let mut unique_write_seqs: Vec<i64> = Vec::new();
    if !sel_obj_ids.is_empty() {
        let obj_seqs: Vec<(Option<i64>,)> = sqlx::query_as(
            "SELECT evidence_seq_num FROM objects WHERE tenant_id = $1 AND id = ANY($2) AND evidence_seq_num IS NOT NULL",
        )
        .bind(&tenant_id)
        .bind(&sel_obj_ids)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("lookup object evidence_seq_num failed: {e}")))?;
        for (s_opt,) in obj_seqs {
            if let Some(s) = s_opt {
                unique_write_seqs.push(s);
            }
        }
    }
    if !sel_claim_ids.is_empty() {
        let clm_seqs: Vec<(Option<i64>,)> = sqlx::query_as(
            "SELECT evidence_seq_num FROM knowledge_claims WHERE tenant_id = $1 AND id = ANY($2) AND evidence_seq_num IS NOT NULL",
        )
        .bind(&tenant_id)
        .bind(&sel_claim_ids)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("lookup claim evidence_seq_num failed: {e}")))?;
        for (s_opt,) in clm_seqs {
            if let Some(s) = s_opt {
                unique_write_seqs.push(s);
            }
        }
    }
    unique_write_seqs.retain(|&s| s >= 1 && s <= target_seq);
    unique_write_seqs.sort_unstable();
    unique_write_seqs.dedup();

    let wr_entries = fetch_evidence_by_seqs(pool, &tenant_id, &unique_write_seqs).await?;
    let mut write_entry_proofs = Vec::with_capacity(wr_entries.len());
    for we in wr_entries {
        let p = compute_merkle_inclusion_proof(&leaves, (we.seq_num - 1) as usize)?
            .into_iter()
            .map(|h| acta_crypto_hex(&h))
            .collect();
        write_entry_proofs.push(EntryInclusionProof {
            entry: we,
            audit_path: p,
        });
    }

    let mut anchored_checkpoint = None;
    let mut consistency_proof_to_anchor = Vec::new();

    match anchor_tree_size {
        Some(explicit_m) if explicit_m > target_seq => {
            let (asth, aleaves) =
                build_signed_tree_head(pool, host_key, &tenant_id, Some(explicit_m))
                    .await?
                    .ok_or_else(|| {
                        ActaError::Validation(format!(
                            "missing checkpoint at anchor_tree_size={explicit_m}"
                        ))
                    })?;
            if asth.witness_anchors.is_empty() {
                return Err(ActaError::Validation(format!(
                    "checkpoint at anchor_tree_size={explicit_m} has no active witness anchors"
                )));
            }
            consistency_proof_to_anchor =
                compute_merkle_consistency_proof(&aleaves, target_seq as usize, explicit_m as usize)?
                    .into_iter()
                    .map(|h| acta_crypto_hex(&h))
                    .collect();
            anchored_checkpoint = Some(asth);
        }
        Some(explicit_m) => {
            if sth.witness_anchors.is_empty() {
                return Err(ActaError::Validation(format!(
                    "checkpoint at anchor_tree_size={explicit_m} has no active witness anchors"
                )));
            }
        }
        None if sth.witness_anchors.is_empty() => {
            let candidate_sizes: Vec<(i64,)> = sqlx::query_as(
                r#"
                SELECT DISTINCT ca.tree_size
                FROM checkpoint_anchors ca
                INNER JOIN trusted_witnesses tw
                    ON tw.tenant_id = ca.tenant_id
                   AND tw.witness_id = ca.witness_id
                   AND tw.public_key = ca.witness_public_key
                   AND tw.active = TRUE
                WHERE ca.tenant_id = $1
                  AND ca.tree_size > $2
                  AND NOT EXISTS (
                      SELECT 1
                      FROM witness_revocations wr
                      WHERE wr.tenant_id = tw.tenant_id
                        AND wr.witness_id = tw.witness_id
                        AND (
                            wr.revocation_mode = 'compromise'
                            OR wr.effective_from_tree_size IS NULL
                            OR ca.tree_size >= wr.effective_from_tree_size
                        )
                  )
                ORDER BY ca.tree_size DESC
                LIMIT 5
                "#,
            )
            .bind(&tenant_id)
            .bind(target_seq)
            .fetch_all(pool)
            .await
            .map_err(|e| ActaError::Storage(format!("lookup anchored checkpoint sizes failed: {e}")))?;

            for (cand_m,) in candidate_sizes {
                if let Some((asth, aleaves)) =
                    build_signed_tree_head(pool, host_key, &tenant_id, Some(cand_m)).await?
                {
                    if !asth.witness_anchors.is_empty() {
                        consistency_proof_to_anchor = compute_merkle_consistency_proof(
                            &aleaves,
                            target_seq as usize,
                            cand_m as usize,
                        )?
                        .into_iter()
                        .map(|h| acta_crypto_hex(&h))
                        .collect();
                        anchored_checkpoint = Some(asth);
                        break;
                    }
                }
            }
        }
        None => {}
    }

    let merkle_proof = MerkleBundleProof {
        checkpoint: sth,
        bundle_entry_proof: EntryInclusionProof {
            entry: bundle_entry,
            audit_path: bundle_path,
        },
        override_entry_proofs,
        write_entry_proofs,
        anchored_checkpoint,
        consistency_proof_to_anchor,
    };

    let chain = if include_full_chain {
        fetch_tenant_evidence_chain(pool, &tenant_id, Some(target_seq)).await?
    } else {
        Vec::new()
    };

    Ok((bundle, chain, merkle_proof))
}

pub async fn fetch_bundle_with_merkle_or_chain(
    pool: &PgPool,
    host_key: &SigningKey,
    bundle_hash: &[u8; 32],
    override_seq_nums: &[i64],
    include_full_chain: bool,
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>, MerkleBundleProof)> {
    fetch_bundle_with_merkle_options(
        pool,
        host_key,
        bundle_hash,
        override_seq_nums,
        include_full_chain,
        None,
    )
    .await
}

pub async fn fetch_bundle_with_evidence_slice(
    pool: &PgPool,
    bundle_hash: &[u8; 32],
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>)> {
    fetch_bundle_with_evidence_slice_scoped(pool, TenantLookupScope::Any, bundle_hash).await
}

pub async fn fetch_bundle_with_evidence_slice_scoped(
    pool: &PgPool,
    tenant_scope: TenantLookupScope<'_>,
    bundle_hash: &[u8; 32],
) -> ActaResult<(ContextBundle, Vec<EvidenceEntry>)> {
    let (tenant_id, canonical_bytes) =
        fetch_scoped_bundle_row(pool, tenant_scope, bundle_hash).await?;

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

/// Atomically registers an immutable trusted witness Ed25519 key in `trusted_witnesses` and
/// notarizes its principal- and description-bound commitment (`b"acta:witness_reg:v3"`) in `evidence_history`.
pub async fn register_trusted_witness_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    description: Option<&str>,
    registered_by: &str,
    created_at: DateTime<Utc>,
) -> ActaResult<WitnessRegistrationOutcome> {
    let created_at = created_at.trunc_subsecs(6);
    let (reg_preimage, reg_comm) = compute_witness_registration_v3_commitment(
        tenant_id,
        witness_id,
        public_key,
        registered_by,
        description,
    );

    let mut tx = pool.begin().await.map_err(|e| {
        ActaError::Storage(format!("begin trusted_witness registration tx failed: {e}"))
    })?;

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, tenant_id).await?;

    let existing_rows = sqlx::query_as::<_, TrustedWitnessRow>(
        r#"
        SELECT tw.tenant_id, tw.witness_id, tw.public_key, tw.description, tw.registered_by,
               tw.reg_domain, tw.evidence_seq_num, tw.active, tw.created_at,
               wr.created_at AS revoked_at, wr.revoked_by,
               wr.revocation_mode, wr.effective_from_tree_size,
               wr.reason AS revocation_reason, wr.evidence_seq_num AS revocation_evidence_seq_num,
               wr.revoke_domain AS revocation_domain
        FROM trusted_witnesses tw
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = tw.tenant_id
           AND wr.witness_id = tw.witness_id
        WHERE tw.tenant_id = $1 AND (tw.witness_id = $2 OR tw.public_key = $3)
        ORDER BY tw.created_at ASC
        "#,
    )
    .bind(tenant_id)
    .bind(witness_id)
    .bind(public_key.as_slice())
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("query trusted_witnesses failed: {e}")))?;

    if let Some(first_row) = existing_rows.into_iter().next() {
        let (existing, _) = first_row.into_domain()?;
        tx.rollback().await.ok();
        if existing.witness_id == witness_id
            && &existing.public_key == public_key
            && existing.active
            && (existing.reg_domain != WITNESS_REG_DOMAIN_V3
                || existing.description.as_deref() == description)
        {
            let (ex_preimage, ex_comm) = compute_witness_registration_by_domain(
                &existing.reg_domain,
                &existing.tenant_id,
                &existing.witness_id,
                &existing.public_key,
                &existing.registered_by,
                existing.description.as_deref(),
            )
            .map_err(ActaError::Storage)?;
            let ex_domain = existing.reg_domain.clone();
            return Ok(WitnessRegistrationOutcome::Registered {
                witness: existing,
                registration_domain: ex_domain,
                registration_preimage: ex_preimage,
                registration_commitment: ex_comm,
                was_idempotent_noop: true,
            });
        }
        return Ok(WitnessRegistrationOutcome::Conflict {
            existing_witness_id: existing.witness_id,
            existing_public_key: existing.public_key,
            existing_revoked: existing.revoked_at.is_some(),
        });
    }


    let seq_num = prev_seq + 1;

    let ev_hash = compute_evidence_event_hash_with_meta(
        tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&reg_comm),
        PolicyResultTag::Allow,
        created_at.timestamp_micros(),
        None,
        None,
    )?;
    let ev_sig = sign_evidence_entry(host_key, tenant_id, seq_num, &prev_hash, &ev_hash);

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, $6, $7)
        "#,
    )
    .bind(tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(ev_hash.as_slice())
    .bind(reg_comm.as_slice())
    .bind(ev_sig.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert witness registration evidence failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO trusted_witnesses (
            tenant_id, witness_id, public_key, description,
            registered_by, reg_domain, evidence_seq_num, active, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)
        "#,
    )
    .bind(tenant_id)
    .bind(witness_id)
    .bind(public_key.as_slice())
    .bind(description)
    .bind(registered_by)
    .bind(WITNESS_REG_DOMAIN_V3)
    .bind(seq_num)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert trusted_witnesses failed: {e}")))?;

    tx.commit().await.map_err(|e| {
        ActaError::Storage(format!("commit trusted_witness registration tx failed: {e}"))
    })?;

    Ok(WitnessRegistrationOutcome::Registered {
        witness: TrustedWitness {
            tenant_id: tenant_id.to_string(),
            witness_id: witness_id.to_string(),
            public_key: *public_key,
            description: description.map(str::to_string),
            registered_by: registered_by.to_string(),
            reg_domain: WITNESS_REG_DOMAIN_V3.to_string(),
            evidence_seq_num: seq_num,
            active: true,
            created_at,
            revoked_at: None,
            revoked_by: None,
            revocation_mode: None,
            effective_from_tree_size: None,
            revocation_reason: None,
            revocation_evidence_seq_num: None,
        },
        registration_domain: WITNESS_REG_DOMAIN_V3.to_string(),
        registration_preimage: reg_preimage,
        registration_commitment: reg_comm,
        was_idempotent_noop: false,
    })
}

/// Atomically revokes (`mode = "compromise"`) or retires (`mode = "retire"`) an enrolled witness via
/// append-only `witness_revocations` + `evidence_history` (`b"acta:witness_revoke:v2"`) without mutating
/// `trusted_witnesses` or `checkpoint_anchors`.
pub async fn revoke_trusted_witness_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    witness_id: &str,
    revoked_by: &str,
    revocation_mode: &str,
    reason: &str,
    created_at: DateTime<Utc>,
) -> ActaResult<WitnessRevocationOutcome> {
    if revocation_mode != "compromise" && revocation_mode != "retire" {
        return Err(ActaError::Validation(format!(
            "unsupported witness revocation_mode '{revocation_mode}' (expected 'compromise' or 'retire')"
        )));
    }
    let created_at = created_at.trunc_subsecs(6);

    let mut tx = pool.begin().await.map_err(|e| {
        ActaError::Storage(format!("begin trusted_witness revocation tx failed: {e}"))
    })?;

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, tenant_id).await?;

    let row_opt = sqlx::query_as::<_, TrustedWitnessRow>(
        r#"
        SELECT tw.tenant_id, tw.witness_id, tw.public_key, tw.description, tw.registered_by,
               tw.reg_domain, tw.evidence_seq_num, tw.active, tw.created_at,
               wr.created_at AS revoked_at, wr.revoked_by,
               wr.revocation_mode, wr.effective_from_tree_size,
               wr.reason AS revocation_reason, wr.evidence_seq_num AS revocation_evidence_seq_num,
               wr.revoke_domain AS revocation_domain
        FROM trusted_witnesses tw
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = tw.tenant_id
           AND wr.witness_id = tw.witness_id
        WHERE tw.tenant_id = $1 AND tw.witness_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(witness_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("query witness for revocation failed: {e}")))?;

    let Some(row) = row_opt else {
        tx.rollback().await.ok();
        return Ok(WitnessRevocationOutcome::NotFound);
    };

    let (mut existing, ex_rev_domain) = row.into_domain()?;
    if let (Some(ex_at), Some(ref ex_by), Some(ref ex_reason), Some(ex_seq)) = (
        existing.revoked_at,
        &existing.revoked_by,
        &existing.revocation_reason,
        existing.revocation_evidence_seq_num,
    ) {
        let ex_mode = existing
            .revocation_mode
            .clone()
            .unwrap_or_else(|| "compromise".to_string());
        let ex_eff = existing.effective_from_tree_size;
        tx.rollback().await.ok();
        if ex_by == revoked_by && ex_reason == reason && ex_mode == revocation_mode {
            let rdom = ex_rev_domain.unwrap_or_else(|| WITNESS_REVOKE_DOMAIN_V1.to_string());
            let (preimage, comm) = compute_witness_revocation_by_domain(
                &rdom,
                &existing.tenant_id,
                &existing.witness_id,
                &existing.public_key,
                ex_by,
                &ex_mode,
                ex_eff,
                ex_reason,
            )
            .map_err(ActaError::Storage)?;
            return Ok(WitnessRevocationOutcome::Revoked {
                witness: existing,
                revocation_domain: rdom,
                revocation_preimage: preimage,
                revocation_commitment: comm,
                revocation_seq_num: ex_seq,
                revoked_at: ex_at,
                was_idempotent_noop: true,
            });
        }
        return Ok(WitnessRevocationOutcome::AlreadyRevokedConflict {
            revoked_by: ex_by.clone(),
            revocation_mode: ex_mode,
            effective_from_tree_size: ex_eff,
            reason: ex_reason.clone(),
            revocation_seq_num: ex_seq,
        });
    }


    let seq_num = prev_seq + 1;
    let effective_from_tree_size = if revocation_mode == "retire" {
        Some(seq_num)
    } else {
        None
    };

    let (rev_preimage, rev_comm) = compute_witness_revocation_v2_commitment(
        tenant_id,
        witness_id,
        &existing.public_key,
        revoked_by,
        revocation_mode,
        effective_from_tree_size,
        reason,
    )
    .map_err(ActaError::Validation)?;

    let ev_hash = compute_evidence_event_hash_with_meta(
        tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&rev_comm),
        PolicyResultTag::Allow,
        created_at.timestamp_micros(),
        None,
        None,
    )?;
    let ev_sig = sign_evidence_entry(host_key, tenant_id, seq_num, &prev_hash, &ev_hash);

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, $6, $7)
        "#,
    )
    .bind(tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(ev_hash.as_slice())
    .bind(rev_comm.as_slice())
    .bind(ev_sig.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert witness revocation evidence failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO witness_revocations (
            tenant_id, witness_id, public_key, revoked_by,
            revocation_mode, effective_from_tree_size,
            reason, revoke_domain, evidence_seq_num, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(tenant_id)
    .bind(witness_id)
    .bind(existing.public_key.as_slice())
    .bind(revoked_by)
    .bind(revocation_mode)
    .bind(effective_from_tree_size)
    .bind(reason)
    .bind(WITNESS_REVOKE_DOMAIN_V2)
    .bind(seq_num)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert witness_revocations failed: {e}")))?;

    tx.commit().await.map_err(|e| {
        ActaError::Storage(format!("commit trusted_witness revocation tx failed: {e}"))
    })?;

    existing.active = false;
    existing.revoked_at = Some(created_at);
    existing.revoked_by = Some(revoked_by.to_string());
    existing.revocation_mode = Some(revocation_mode.to_string());
    existing.effective_from_tree_size = effective_from_tree_size;
    existing.revocation_reason = Some(reason.to_string());
    existing.revocation_evidence_seq_num = Some(seq_num);

    Ok(WitnessRevocationOutcome::Revoked {
        witness: existing,
        revocation_domain: WITNESS_REVOKE_DOMAIN_V2.to_string(),
        revocation_preimage: rev_preimage,
        revocation_commitment: rev_comm,
        revocation_seq_num: seq_num,
        revoked_at: created_at,
        was_idempotent_noop: false,
    })
}

pub async fn fetch_trusted_witness(
    pool: &PgPool,
    tenant_id: &str,
    witness_id: &str,
) -> ActaResult<Option<TrustedWitness>> {
    let row = sqlx::query_as::<_, TrustedWitnessRow>(
        r#"
        SELECT tw.tenant_id, tw.witness_id, tw.public_key, tw.description, tw.registered_by,
               tw.reg_domain, tw.evidence_seq_num, tw.active, tw.created_at,
               wr.created_at AS revoked_at, wr.revoked_by,
               wr.revocation_mode, wr.effective_from_tree_size,
               wr.reason AS revocation_reason, wr.evidence_seq_num AS revocation_evidence_seq_num,
               wr.revoke_domain AS revocation_domain
        FROM trusted_witnesses tw
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = tw.tenant_id
           AND wr.witness_id = tw.witness_id
        WHERE tw.tenant_id = $1 AND tw.witness_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(witness_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_trusted_witness failed: {e}")))?;

    match row {
        Some(r) => {
            let (w, _) = r.into_domain()?;
            Ok(Some(w))
        }
        None => Ok(None),
    }
}

pub async fn fetch_tenant_trusted_witnesses(
    pool: &PgPool,
    tenant_id: &str,
) -> ActaResult<Vec<TrustedWitness>> {
    let rows = sqlx::query_as::<_, TrustedWitnessRow>(
        r#"
        SELECT tw.tenant_id, tw.witness_id, tw.public_key, tw.description, tw.registered_by,
               tw.reg_domain, tw.evidence_seq_num, tw.active, tw.created_at,
               wr.created_at AS revoked_at, wr.revoked_by,
               wr.revocation_mode, wr.effective_from_tree_size,
               wr.reason AS revocation_reason, wr.evidence_seq_num AS revocation_evidence_seq_num,
               wr.revoke_domain AS revocation_domain
        FROM trusted_witnesses tw
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = tw.tenant_id
           AND wr.witness_id = tw.witness_id
        WHERE tw.tenant_id = $1
        ORDER BY tw.created_at DESC, tw.witness_id ASC
        LIMIT 200
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_tenant_trusted_witnesses failed: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let (w, _) = r.into_domain()?;
        out.push(w);
    }
    Ok(out)
}

/// Fetches all append-only `checkpoint_anchors` rows quarantined because their witness/key is not
/// currently active in `trusted_witnesses` (e.g. legacy `v1.6.0` throwaway rows or revoked witnesses).
pub async fn fetch_quarantined_witness_anchors(
    pool: &PgPool,
    tenant_id: &str,
) -> ActaResult<Vec<QuarantinedAnchorRecord>> {
    let rows = sqlx::query_as::<_, QuarantinedAnchorRow>(
        r#"
        SELECT ca.id, ca.tenant_id, ca.tree_size, ca.head_event_hash, ca.merkle_root,
               ca.checkpoint_hash, ca.witness_id, ca.witness_public_key,
               ca.witness_signature, ca.external_uri, ca.anchored_at,
               CASE
                   WHEN wr.witness_id IS NOT NULL AND wr.revocation_mode = 'retire' THEN 'retired_witness'
                   WHEN wr.witness_id IS NOT NULL THEN 'revoked_witness'
                   WHEN tw.witness_id IS NOT NULL AND tw.public_key <> ca.witness_public_key THEN 'witness_key_mismatch'
                   WHEN tw.witness_id IS NOT NULL AND tw.active = FALSE THEN 'inactive_witness'
                   ELSE 'unregistered_witness'
               END AS quarantine_reason
        FROM checkpoint_anchors ca
        LEFT JOIN trusted_witnesses tw
            ON tw.tenant_id = ca.tenant_id
           AND tw.witness_id = ca.witness_id
        LEFT JOIN witness_revocations wr
            ON wr.tenant_id = ca.tenant_id
           AND wr.witness_id = ca.witness_id
           AND (
               wr.revocation_mode = 'compromise'
               OR wr.effective_from_tree_size IS NULL
               OR ca.tree_size >= wr.effective_from_tree_size
           )
        WHERE ca.tenant_id = $1
          AND (
              tw.witness_id IS NULL
              OR tw.public_key <> ca.witness_public_key
              OR tw.active = FALSE
              OR wr.witness_id IS NOT NULL
          )
        ORDER BY ca.tree_size ASC, ca.anchored_at ASC, ca.id ASC
        LIMIT 100
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_quarantined_witness_anchors failed: {e}")))?;

    let mut records: Vec<QuarantinedAnchorRecord> = rows
        .into_iter()
        .map(QuarantinedAnchorRow::into_domain)
        .collect::<ActaResult<Vec<_>>>()?;

    if let Some(max_sz) = records.iter().map(|r| r.tree_size).max() {
        let leaf_rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT seq_num, event_hash
            FROM evidence_history
            WHERE tenant_id = $1 AND seq_num <= $2
            ORDER BY seq_num ASC
            "#,
        )
        .bind(tenant_id)
        .bind(max_sz)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("fetch quarantined merkle leaves failed: {e}")))?;

        let mut events: Vec<(i64, [u8; 32])> = Vec::with_capacity(leaf_rows.len());
        let mut rfc_leaves: Vec<[u8; 32]> = Vec::with_capacity(leaf_rows.len());
        for (seq, raw_ev) in leaf_rows {
            if let Ok(arr) = raw_ev.try_into() {
                rfc_leaves.push(merkle_leaf_hash(seq, &arr));
                events.push((seq, arr));
            }
        }

        for rec in &mut records {
            let sz = rec.tree_size as usize;
            if sz >= 1 && sz <= events.len() && events[sz - 1].0 == rec.tree_size {
                let rfc_root = compute_merkle_root_from_leaves(&rfc_leaves[..sz]);
                if rec.merkle_root == rfc_root {
                    rec.merkle_scheme = "rfc6962-sha256-v1".to_string();
                } else {
                    let leg_root = compute_legacy_blake3_merkle_root_from_events(&events[..sz]);
                    if rec.merkle_root == leg_root {
                        rec.merkle_scheme = "acta-blake3-merkle-v1".to_string();
                    } else {
                        rec.merkle_scheme = "unrecognized".to_string();
                    }
                }
            } else {
                rec.merkle_scheme = "unrecognized".to_string();
            }
        }
    }

    Ok(records)
}

pub async fn count_quarantined_witness_anchors(pool: &PgPool, tenant_id: &str) -> ActaResult<i64> {
    let (cnt,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint
        FROM checkpoint_anchors ca
        WHERE ca.tenant_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM trusted_witnesses tw
              WHERE tw.tenant_id = ca.tenant_id
                AND tw.witness_id = ca.witness_id
                AND tw.public_key = ca.witness_public_key
                AND tw.active = TRUE
                AND NOT EXISTS (
                    SELECT 1
                    FROM witness_revocations wr
                    WHERE wr.tenant_id = tw.tenant_id
                      AND wr.witness_id = tw.witness_id
                      AND (
                          wr.revocation_mode = 'compromise'
                          OR wr.effective_from_tree_size IS NULL
                          OR ca.tree_size >= wr.effective_from_tree_size
                      )
                )
          )
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("count_quarantined_witness_anchors failed: {e}")))?;

    Ok(cnt)
}

/// Persists an immutable external witness cosignature over `(tenant_id, tree_size, checkpoint_hash)`.
pub async fn insert_witness_anchor(
    pool: &PgPool,
    head_event_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    anchor: ExternalWitnessAnchor,
) -> ActaResult<ExternalWitnessAnchor> {
    let anchored_at = anchor.anchored_at.trunc_subsecs(6);
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
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("check existing checkpoint_anchor failed: {e}")))?;

    if let Some(ex) = existing {
        return ex.into_domain();
    }

    let row = sqlx::query_as::<_, AnchorRow>(
        r#"
        INSERT INTO checkpoint_anchors (
            id, tenant_id, tree_size, head_event_hash, merkle_root, checkpoint_hash,
            witness_id, witness_public_key, witness_signature, external_uri, anchored_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
    .map_err(|e| ActaError::Storage(format!("insert checkpoint_anchors failed: {e}")))?;

    row.into_domain()
}

/// Fetches verified witness anchors for `(tenant_id, tree_size, checkpoint_hash)` strictly
/// matching active (non-revoked) enrolled witnesses in `trusted_witnesses`.
pub async fn fetch_witness_anchors_for_size(
    pool: &PgPool,
    tenant_id: &str,
    tree_size: i64,
    checkpoint_hash: &[u8; 32],
) -> ActaResult<Vec<ExternalWitnessAnchor>> {
    let rows = sqlx::query_as::<_, AnchorRow>(
        r#"
        SELECT ca.id, ca.tenant_id, ca.tree_size, ca.checkpoint_hash, ca.witness_id,
               ca.witness_public_key, ca.witness_signature, ca.external_uri, ca.anchored_at
        FROM checkpoint_anchors ca
        INNER JOIN trusted_witnesses tw
            ON tw.tenant_id = ca.tenant_id
           AND tw.witness_id = ca.witness_id
           AND tw.public_key = ca.witness_public_key
           AND tw.active = TRUE
        WHERE ca.tenant_id = $1
          AND ca.tree_size = $2
          AND ca.checkpoint_hash = $3
          AND NOT EXISTS (
              SELECT 1
              FROM witness_revocations wr
              WHERE wr.tenant_id = tw.tenant_id
                AND wr.witness_id = tw.witness_id
                AND (
                    wr.revocation_mode = 'compromise'
                    OR wr.effective_from_tree_size IS NULL
                    OR ca.tree_size >= wr.effective_from_tree_size
                )
          )
        ORDER BY ca.anchored_at ASC, ca.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(tree_size)
    .bind(checkpoint_hash.as_slice())
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
        SELECT ca.id, ca.tenant_id, ca.tree_size, ca.checkpoint_hash, ca.witness_id,
               ca.witness_public_key, ca.witness_signature, ca.external_uri, ca.anchored_at
        FROM checkpoint_anchors ca
        INNER JOIN trusted_witnesses tw
            ON tw.tenant_id = ca.tenant_id
           AND tw.witness_id = ca.witness_id
           AND tw.public_key = ca.witness_public_key
           AND tw.active = TRUE
        WHERE ca.tenant_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM witness_revocations wr
              WHERE wr.tenant_id = tw.tenant_id
                AND wr.witness_id = tw.witness_id
                AND (
                    wr.revocation_mode = 'compromise'
                    OR wr.effective_from_tree_size IS NULL
                    OR ca.tree_size >= wr.effective_from_tree_size
                )
          )
        ORDER BY ca.tree_size DESC, ca.anchored_at DESC
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

/// Resolves the latest active witness-anchored `SignedTreeHead` at or before `head_sth.tree_size`,
/// along with the RFC 6962 consistency proof (`anchor_size -> head_sth.tree_size`) and verification flag (`v1.7.1+`).
pub async fn resolve_latest_anchored_for_head(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    head_sth: &SignedTreeHead,
    head_leaves: &[[u8; 32]],
) -> ActaResult<(Option<SignedTreeHead>, Option<Vec<String>>, Option<bool>)> {
    if !head_sth.witness_anchors.is_empty() {
        return Ok((Some(head_sth.clone()), Some(Vec::new()), Some(true)));
    }
    if head_sth.tree_size <= 1 {
        return Ok((None, None, None));
    }

    let candidate_sizes: Vec<(i64,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT ca.tree_size
        FROM checkpoint_anchors ca
        INNER JOIN trusted_witnesses tw
            ON tw.tenant_id = ca.tenant_id
           AND tw.witness_id = ca.witness_id
           AND tw.public_key = ca.witness_public_key
           AND tw.active = TRUE
        WHERE ca.tenant_id = $1
          AND ca.tree_size < $2
          AND NOT EXISTS (
              SELECT 1
              FROM witness_revocations wr
              WHERE wr.tenant_id = tw.tenant_id
                AND wr.witness_id = tw.witness_id
                AND (
                    wr.revocation_mode = 'compromise'
                    OR wr.effective_from_tree_size IS NULL
                    OR ca.tree_size >= wr.effective_from_tree_size
                )
          )
        ORDER BY ca.tree_size DESC
        LIMIT 5
        "#,
    )
    .bind(tenant_id)
    .bind(head_sth.tree_size)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("lookup prior anchored checkpoint sizes failed: {e}")))?;

    for (cand_m,) in candidate_sizes {
        if let Some((asth, _)) =
            build_signed_tree_head(pool, host_key, tenant_id, Some(cand_m)).await?
        {
            if !asth.witness_anchors.is_empty() {
                let raw_nodes = compute_merkle_consistency_proof(
                    head_leaves,
                    cand_m as usize,
                    head_sth.tree_size as usize,
                )?;
                let ok = acta_crypto::verify_merkle_consistency_proof(
                    cand_m,
                    &asth.merkle_root,
                    head_sth.tree_size,
                    &head_sth.merkle_root,
                    &raw_nodes,
                );
                let hex_nodes = raw_nodes.into_iter().map(|h| acta_crypto_hex(&h)).collect();
                return Ok((Some(asth), Some(hex_nodes), Some(ok)));
            }
        }
    }

    Ok((None, None, None))
}
