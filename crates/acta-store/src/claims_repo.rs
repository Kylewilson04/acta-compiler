use acta_crypto::{
    compute_claim_content_hash, compute_evidence_event_hash_full, compute_write_summary_commitment,
    sign_evidence_entry, to_canonical_bytes,
};
use acta_types::{
    ActaError, ActaResult, ClaimStatus, EvidenceEntry, KnowledgeClaim, OmissionReason,
    PolicyResultTag, WriteLedgerSummary, WriteOperationKind, WRITE_EVENT_DOMAIN_V1,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::evidence_repo::{fetch_evidence_by_seq, lock_and_read_latest_evidence_tx};

#[derive(FromRow)]
struct ClaimRow {
    id: Uuid,
    tenant_id: String,
    claim_group_key: Vec<u8>,
    scope: String,
    subject: String,
    predicate: String,
    object_val: serde_json::Value,
    object_type: String,
    confidence: f64,
    source_provenance_class: i32,
    source_descriptor: String,
    source_commitment: Vec<u8>,
    content_hash: Vec<u8>,
    status: String,
    contradiction_ids: Vec<Uuid>,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    version: i32,
    predecessor_id: Option<Uuid>,
    client_signature: Option<Vec<u8>>,
    client_public_key: Option<Vec<u8>>,
    retraction_reason: Option<String>,
    written_by: Option<String>,
    evidence_seq_num: Option<i64>,
    created_at: DateTime<Utc>,
    is_superseded: bool,
    is_retracted: bool,
}

impl ClaimRow {
    fn into_domain(self) -> ActaResult<(KnowledgeClaim, bool, bool)> {
        let claim_group_key: [u8; 32] = self
            .claim_group_key
            .try_into()
            .map_err(|_| ActaError::Storage("claim_group_key is not 32 bytes".to_string()))?;
        let source_commitment: [u8; 32] = self
            .source_commitment
            .try_into()
            .map_err(|_| ActaError::Storage("source_commitment is not 32 bytes".to_string()))?;
        let content_hash: [u8; 32] = self
            .content_hash
            .try_into()
            .map_err(|_| ActaError::Storage("claim content_hash is not 32 bytes".to_string()))?;
        let client_public_key: Option<[u8; 32]> = self
            .client_public_key
            .map(|v| {
                v.try_into().map_err(|_| {
                    ActaError::Storage("claim client_public_key is not 32 bytes".to_string())
                })
            })
            .transpose()?;
        let status = ClaimStatus::from_db_str(&self.status).map_err(ActaError::Storage)?;

        Ok((
            KnowledgeClaim {
                id: self.id,
                tenant_id: self.tenant_id,
                claim_group_key,
                scope: self.scope,
                subject: self.subject,
                predicate: self.predicate,
                object_val: self.object_val,
                object_type: self.object_type,
                confidence: self.confidence,
                source_provenance_class: self.source_provenance_class,
                source_descriptor: self.source_descriptor,
                source_commitment,
                content_hash,
                status,
                contradiction_ids: self.contradiction_ids,
                valid_from: self.valid_from,
                valid_to: self.valid_to,
                version: self.version,
                predecessor_id: self.predecessor_id,
                client_signature: self.client_signature,
                client_public_key,
                retraction_reason: self.retraction_reason,
                written_by: self.written_by,
                evidence_seq_num: self.evidence_seq_num,
                created_at: self.created_at,
            },
            self.is_superseded,
            self.is_retracted,
        ))
    }
}

/// Appends a new versioned knowledge claim row directly (helper retained for benchmarks/fixtures).
pub async fn insert_claim(pool: &PgPool, claim: &KnowledgeClaim) -> ActaResult<()> {
    sqlx::query(
        r#"
        INSERT INTO knowledge_claims (
            id, tenant_id, claim_group_key, scope, subject, predicate,
            object_val, object_type, confidence, source_provenance_class,
            source_descriptor, source_commitment, content_hash, status,
            contradiction_ids, valid_from, valid_to, version, predecessor_id,
            client_signature, client_public_key, retraction_reason,
            written_by, write_domain, evidence_seq_num, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25, $26
        )
        "#,
    )
    .bind(claim.id)
    .bind(&claim.tenant_id)
    .bind(claim.claim_group_key.as_slice())
    .bind(&claim.scope)
    .bind(&claim.subject)
    .bind(&claim.predicate)
    .bind(&claim.object_val)
    .bind(&claim.object_type)
    .bind(claim.confidence)
    .bind(claim.source_provenance_class)
    .bind(&claim.source_descriptor)
    .bind(claim.source_commitment.as_slice())
    .bind(claim.content_hash.as_slice())
    .bind(claim.status.as_str())
    .bind(&claim.contradiction_ids)
    .bind(claim.valid_from)
    .bind(claim.valid_to)
    .bind(claim.version)
    .bind(claim.predecessor_id)
    .bind(claim.client_signature.as_deref())
    .bind(claim.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(claim.retraction_reason.as_deref())
    .bind(claim.written_by.as_deref())
    .bind(claim.evidence_seq_num.map(|_| WRITE_EVENT_DOMAIN_V1))
    .bind(claim.evidence_seq_num)
    .bind(claim.created_at)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_claim failed: {e}")))?;

    Ok(())
}

/// Atomically ingests or auto-supersedes a `KnowledgeClaim` AND notarizes its strip-proof
/// `WriteLedgerSummary` (`acta:write_event:v1` -> `acta:evidence_event:v3`) on `evidence_history` (`v1.7.0+`).
/// Same-source idempotent retries return `(prev_head, existing_evidence, true)` without duplicating ledger entries.
pub async fn insert_or_supersede_claim_with_evidence_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    mut claim: KnowledgeClaim,
    allow_auto_supersede: bool,
    written_by: &str,
    writer_auth_kind: &str,
) -> ActaResult<(KnowledgeClaim, Option<EvidenceEntry>, bool)> {
    let lock_key = format!(
        "acta:claim_head:{}\x1f{}\x1f{}\x1f{}\x1f{}",
        claim.tenant_id, claim.scope, claim.subject, claim.predicate, claim.source_descriptor
    );

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin claim transaction failed: {e}")))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(&lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("claim advisory lock failed: {e}")))?;

    if allow_auto_supersede && claim.predecessor_id.is_none() && claim.status == ClaimStatus::Active
    {
        let existing_row = sqlx::query_as::<_, ClaimRow>(
            r#"
            SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
                   c.object_val, c.object_type, c.confidence, c.source_provenance_class,
                   c.source_descriptor, c.source_commitment, c.content_hash, c.status,
                   c.contradiction_ids, c.valid_from, c.valid_to, c.version,
                   c.predecessor_id, c.client_signature, c.client_public_key,
                   c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
                   FALSE AS is_superseded,
                   FALSE AS is_retracted
            FROM knowledge_claims c
            WHERE c.tenant_id = $1
              AND c.scope = $2
              AND c.subject = $3
              AND c.predicate = $4
              AND c.source_descriptor = $5
              AND c.status = 'active'
              AND NOT EXISTS (
                  SELECT 1 FROM knowledge_claims succ
                  WHERE succ.tenant_id = c.tenant_id
                    AND succ.predecessor_id = c.id
              )
            ORDER BY c.version DESC, c.created_at DESC, c.id DESC
            LIMIT 1
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(&claim.scope)
        .bind(&claim.subject)
        .bind(&claim.predicate)
        .bind(&claim.source_descriptor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ActaError::Storage(format!("query active source head failed: {e}")))?;

        if let Some(row) = existing_row {
            let (prev_head, _, _) = row.into_domain()?;
            let prev_val_bytes = to_canonical_bytes(&prev_head.object_val)?;
            let new_val_bytes = to_canonical_bytes(&claim.object_val)?;

            let same_payload = prev_val_bytes == new_val_bytes
                && prev_head.object_type == claim.object_type
                && (prev_head.confidence - claim.confidence).abs() < 1e-12
                && prev_head.source_provenance_class == claim.source_provenance_class
                && prev_head.valid_from == claim.valid_from
                && prev_head.valid_to == claim.valid_to
                && prev_head.contradiction_ids == claim.contradiction_ids
                && prev_head.client_public_key == claim.client_public_key;

            if same_payload {
                tx.commit().await.map_err(|e| {
                    ActaError::Storage(format!("commit idempotent claim noop failed: {e}"))
                })?;
                let existing_ev = match prev_head.evidence_seq_num {
                    Some(seq) => fetch_evidence_by_seq(pool, &prev_head.tenant_id, seq).await?,
                    None => None,
                };
                return Ok((prev_head, existing_ev, true));
            }

            claim.predecessor_id = Some(prev_head.id);
            claim.version = prev_head.version + 1;
            claim.content_hash = compute_claim_content_hash(&claim)?;
        }
    }

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, &claim.tenant_id).await?;
    let seq_num = prev_seq + 1;

    claim.written_by = Some(written_by.to_string());
    claim.evidence_seq_num = Some(seq_num);

    let record_snapshot = serde_json::to_value(&claim)
        .map_err(|e| ActaError::Storage(format!("serialize KnowledgeClaim snapshot failed: {e}")))?;

    let write_summary = WriteLedgerSummary {
        write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
        operation: WriteOperationKind::IngestClaim,
        item_id: claim.id,
        scope: claim.scope.clone(),
        version: claim.version,
        predecessor_id: claim.predecessor_id,
        content_hash: claim.content_hash,
        written_by: written_by.to_string(),
        writer_auth_kind: writer_auth_kind.to_string(),
        client_public_key: claim.client_public_key,
        client_signature: claim.client_signature.clone(),
        retraction_reason: claim.retraction_reason.clone(),
        record_snapshot,
    };

    let write_comm = compute_write_summary_commitment(&write_summary)?;
    let event_hash = compute_evidence_event_hash_full(
        &claim.tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&write_comm),
        PolicyResultTag::Allow,
        claim.created_at.timestamp_micros(),
        None,
        None,
        Some(&write_summary),
        None,
    )?;
    let host_signature =
        sign_evidence_entry(host_key, &claim.tenant_id, seq_num, &prev_hash, &event_hash);
    let write_meta_json = serde_json::to_value(&write_summary)
        .map_err(|e| ActaError::Storage(format!("serialize claim write_meta failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, write_meta, answer_cache_meta,
            host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, $6, NULL, $7, $8)
        "#,
    )
    .bind(&claim.tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(write_comm.as_slice())
    .bind(write_meta_json)
    .bind(host_signature.as_slice())
    .bind(claim.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert claim evidence_history failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO knowledge_claims (
            id, tenant_id, claim_group_key, scope, subject, predicate,
            object_val, object_type, confidence, source_provenance_class,
            source_descriptor, source_commitment, content_hash, status,
            contradiction_ids, valid_from, valid_to, version, predecessor_id,
            client_signature, client_public_key, retraction_reason,
            written_by, write_domain, evidence_seq_num, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25, $26
        )
        "#,
    )
    .bind(claim.id)
    .bind(&claim.tenant_id)
    .bind(claim.claim_group_key.as_slice())
    .bind(&claim.scope)
    .bind(&claim.subject)
    .bind(&claim.predicate)
    .bind(&claim.object_val)
    .bind(&claim.object_type)
    .bind(claim.confidence)
    .bind(claim.source_provenance_class)
    .bind(&claim.source_descriptor)
    .bind(claim.source_commitment.as_slice())
    .bind(claim.content_hash.as_slice())
    .bind(claim.status.as_str())
    .bind(&claim.contradiction_ids)
    .bind(claim.valid_from)
    .bind(claim.valid_to)
    .bind(claim.version)
    .bind(claim.predecessor_id)
    .bind(claim.client_signature.as_deref())
    .bind(claim.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(claim.retraction_reason.as_deref())
    .bind(claim.written_by.as_deref())
    .bind(WRITE_EVENT_DOMAIN_V1)
    .bind(seq_num)
    .bind(claim.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_claim in tx failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit claim transaction failed: {e}")))?;

    let ev = EvidenceEntry {
        tenant_id: claim.tenant_id.clone(),
        seq_num,
        event_domain: Some("acta:evidence_event:v3".to_string()),
        prev_hash,
        event_hash,
        bundle_hash: None,
        state_commitment: Some(write_comm),
        policy_result: PolicyResultTag::Allow,
        refusal_metadata: None,
        override_summary: None,
        write_summary: Some(write_summary),
        answer_cache_summary: None,
        witness_reg_summary: None,
        witness_revoke_summary: None,
        host_signature,
        created_at: claim.created_at,
    };

    Ok((claim, Some(ev), false))
}

/// Appends an immutable `status = 'revoked'` tombstone retiring an active `KnowledgeClaim` (`predecessor_id = claim_id`)
/// and notarizing `WriteOperationKind::RetractClaim` on `evidence_history` (`v1.7.0+`).
#[allow(clippy::too_many_arguments)]
pub async fn retract_claim_with_evidence_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    tenant_id: &str,
    target_claim_id: Uuid,
    tombstone_id: Uuid,
    reason: &str,
    retracted_by: &str,
    writer_auth_kind: &str,
    client_signature: Option<Vec<u8>>,
    client_public_key: Option<[u8; 32]>,
    created_at: DateTime<Utc>,
) -> ActaResult<(KnowledgeClaim, EvidenceEntry, bool)> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin claim retraction tx failed: {e}")))?;

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, tenant_id).await?;

    let target_row = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.client_signature, c.client_public_key,
               c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
               FALSE AS is_superseded,
               FALSE AS is_retracted
        FROM knowledge_claims c
        WHERE c.tenant_id = $1 AND c.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(target_claim_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("query target claim for retraction failed: {e}")))?;

    let Some(t_row) = target_row else {
        tx.rollback().await.ok();
        return Err(ActaError::NotFound(format!(
            "claim {target_claim_id} not found"
        )));
    };
    let (target_claim, _, _) = t_row.into_domain()?;

    let succ_row = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.client_signature, c.client_public_key,
               c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
               FALSE AS is_superseded,
               FALSE AS is_retracted
        FROM knowledge_claims c
        WHERE c.tenant_id = $1 AND c.predecessor_id = $2
        ORDER BY c.version DESC, c.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(target_claim_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("query claim successor failed: {e}")))?;

    if let Some(s_row) = succ_row {
        let (succ_claim, _, _) = s_row.into_domain()?;
        tx.rollback().await.ok();
        if succ_claim.status == ClaimStatus::Revoked
            && succ_claim.retraction_reason.as_deref() == Some(reason)
            && succ_claim.written_by.as_deref() == Some(retracted_by)
            && succ_claim.client_public_key == client_public_key
        {
            if let Some(ex_seq) = succ_claim.evidence_seq_num {
                if let Some(ex_ev) = fetch_evidence_by_seq(pool, tenant_id, ex_seq).await? {
                    return Ok((succ_claim, ex_ev, true));
                }
            }
        }
        return Err(ActaError::Validation(format!(
            "claim {target_claim_id} is already superseded or retracted by {}",
            succ_claim.id
        )));
    }

    if target_claim.status != ClaimStatus::Active {
        tx.rollback().await.ok();
        return Err(ActaError::Validation(format!(
            "claim {target_claim_id} is not active (status='{}')",
            target_claim.status.as_str()
        )));
    }

    let seq_num = prev_seq + 1;
    let mut tombstone = KnowledgeClaim {
        id: tombstone_id,
        tenant_id: tenant_id.to_string(),
        claim_group_key: target_claim.claim_group_key,
        scope: target_claim.scope.clone(),
        subject: target_claim.subject.clone(),
        predicate: target_claim.predicate.clone(),
        object_val: target_claim.object_val.clone(),
        object_type: target_claim.object_type.clone(),
        confidence: target_claim.confidence,
        source_provenance_class: target_claim.source_provenance_class,
        source_descriptor: target_claim.source_descriptor.clone(),
        source_commitment: target_claim.source_commitment,
        content_hash: [0u8; 32],
        status: ClaimStatus::Revoked,
        contradiction_ids: Vec::new(),
        valid_from: target_claim.valid_from,
        valid_to: target_claim.valid_to,
        version: target_claim.version + 1,
        predecessor_id: Some(target_claim.id),
        client_signature: client_signature.clone(),
        client_public_key,
        retraction_reason: Some(reason.to_string()),
        written_by: Some(retracted_by.to_string()),
        evidence_seq_num: Some(seq_num),
        created_at,
    };
    tombstone.content_hash = compute_claim_content_hash(&tombstone)?;

    let record_snapshot = serde_json::to_value(&tombstone)
        .map_err(|e| ActaError::Storage(format!("serialize retraction tombstone failed: {e}")))?;

    let write_summary = WriteLedgerSummary {
        write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
        operation: WriteOperationKind::RetractClaim,
        item_id: tombstone.id,
        scope: tombstone.scope.clone(),
        version: tombstone.version,
        predecessor_id: tombstone.predecessor_id,
        content_hash: tombstone.content_hash,
        written_by: retracted_by.to_string(),
        writer_auth_kind: writer_auth_kind.to_string(),
        client_public_key,
        client_signature,
        retraction_reason: Some(reason.to_string()),
        record_snapshot,
    };

    let write_comm = compute_write_summary_commitment(&write_summary)?;
    let event_hash = compute_evidence_event_hash_full(
        tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&write_comm),
        PolicyResultTag::Allow,
        created_at.timestamp_micros(),
        None,
        None,
        Some(&write_summary),
        None,
    )?;
    let host_signature =
        sign_evidence_entry(host_key, tenant_id, seq_num, &prev_hash, &event_hash);
    let write_meta_json = serde_json::to_value(&write_summary)
        .map_err(|e| ActaError::Storage(format!("serialize retraction write_meta failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, write_meta, answer_cache_meta,
            host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, NULL, $6, NULL, $7, $8)
        "#,
    )
    .bind(tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(write_comm.as_slice())
    .bind(write_meta_json)
    .bind(host_signature.as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert retraction evidence_history failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO knowledge_claims (
            id, tenant_id, claim_group_key, scope, subject, predicate,
            object_val, object_type, confidence, source_provenance_class,
            source_descriptor, source_commitment, content_hash, status,
            contradiction_ids, valid_from, valid_to, version, predecessor_id,
            client_signature, client_public_key, retraction_reason,
            written_by, write_domain, evidence_seq_num, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25, $26
        )
        "#,
    )
    .bind(tombstone.id)
    .bind(&tombstone.tenant_id)
    .bind(tombstone.claim_group_key.as_slice())
    .bind(&tombstone.scope)
    .bind(&tombstone.subject)
    .bind(&tombstone.predicate)
    .bind(&tombstone.object_val)
    .bind(&tombstone.object_type)
    .bind(tombstone.confidence)
    .bind(tombstone.source_provenance_class)
    .bind(&tombstone.source_descriptor)
    .bind(tombstone.source_commitment.as_slice())
    .bind(tombstone.content_hash.as_slice())
    .bind(tombstone.status.as_str())
    .bind(&tombstone.contradiction_ids)
    .bind(tombstone.valid_from)
    .bind(tombstone.valid_to)
    .bind(tombstone.version)
    .bind(tombstone.predecessor_id)
    .bind(tombstone.client_signature.as_deref())
    .bind(tombstone.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(tombstone.retraction_reason.as_deref())
    .bind(tombstone.written_by.as_deref())
    .bind(WRITE_EVENT_DOMAIN_V1)
    .bind(seq_num)
    .bind(tombstone.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert retraction tombstone failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit claim retraction tx failed: {e}")))?;

    let ev = EvidenceEntry {
        tenant_id: tenant_id.to_string(),
        seq_num,
        event_domain: Some("acta:evidence_event:v3".to_string()),
        prev_hash,
        event_hash,
        bundle_hash: None,
        state_commitment: Some(write_comm),
        policy_result: PolicyResultTag::Allow,
        refusal_metadata: None,
        override_summary: None,
        write_summary: Some(write_summary),
        answer_cache_summary: None,
        witness_reg_summary: None,
        witness_revoke_summary: None,
        host_signature,
        created_at,
    };

    Ok((tombstone, ev, false))
}

/// Fetches a single claim by `(tenant_id, id)` for predecessor version lookup.
pub async fn fetch_claim_by_id(
    pool: &PgPool,
    tenant_id: &str,
    id: Uuid,
) -> ActaResult<Option<KnowledgeClaim>> {
    let row = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.client_signature, c.client_public_key,
               c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
               FALSE AS is_superseded,
               FALSE AS is_retracted
        FROM knowledge_claims c
        WHERE c.tenant_id = $1 AND c.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_claim_by_id failed: {e}")))?;

    Ok(row.map(ClaimRow::into_domain).transpose()?.map(|(c, _, _)| c))
}

/// Fetches multiple claims by ID for offline archive export.
pub async fn fetch_claims_by_ids(
    pool: &PgPool,
    tenant_id: &str,
    ids: &[Uuid],
) -> ActaResult<Vec<KnowledgeClaim>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.client_signature, c.client_public_key,
               c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
               FALSE AS is_superseded,
               FALSE AS is_retracted
        FROM knowledge_claims c
        WHERE c.tenant_id = $1 AND c.id = ANY($2)
        ORDER BY c.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_claims_by_ids failed: {e}")))?;

    rows.into_iter()
        .map(|r| r.into_domain().map(|(c, _, _)| c))
        .collect()
}

pub async fn fetch_scoped_claims(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
) -> ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)> {
    fetch_scoped_claims_as_of(pool, tenant_id, scope, None).await
}

pub async fn fetch_scoped_claims_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)> {
    let rows = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.client_signature, c.client_public_key,
               c.retraction_reason, c.written_by, c.evidence_seq_num, c.created_at,
               EXISTS (
                   SELECT 1 FROM knowledge_claims succ
                   WHERE succ.tenant_id = c.tenant_id
                     AND succ.predecessor_id = c.id
                     AND succ.status <> 'revoked'
                     AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
               ) AS is_superseded,
               EXISTS (
                   SELECT 1 FROM knowledge_claims succ
                   WHERE succ.tenant_id = c.tenant_id
                     AND succ.predecessor_id = c.id
                     AND succ.status = 'revoked'
                     AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
               ) AS is_retracted
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.scope = $2
          AND ($3::timestamptz IS NULL OR c.created_at <= $3)
        ORDER BY c.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(as_of)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_scoped_claims failed: {e}")))?;

    let mut head_claims = Vec::new();
    let mut superseded = Vec::new();

    for row in rows {
        let (claim, is_superseded, is_retracted) = row.into_domain()?;
        if is_retracted {
            superseded.push((claim.id, OmissionReason::Retracted));
        } else if is_superseded || claim.status == ClaimStatus::Superseded {
            superseded.push((claim.id, OmissionReason::Superseded));
        } else {
            head_claims.push(claim);
        }
    }

    Ok((head_claims, superseded))
}

pub async fn fetch_all_active_claim_hashes_in_scope(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    now: DateTime<Utc>,
) -> ActaResult<Vec<[u8; 32]>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT c.content_hash
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.scope = $2
          AND c.status = 'active'
          AND (c.valid_from IS NULL OR c.valid_from <= $3)
          AND (c.valid_to IS NULL OR c.valid_to >= $3)
          AND NOT EXISTS (
              SELECT 1 FROM knowledge_claims succ
              WHERE succ.tenant_id = c.tenant_id
                AND succ.predecessor_id = c.id
          )
        ORDER BY c.content_hash ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_all_active_claim_hashes_in_scope failed: {e}")))?;

    let mut hashes = Vec::with_capacity(rows.len());
    for (raw,) in rows {
        let arr: [u8; 32] = raw.try_into().map_err(|_| {
            ActaError::Storage("active claim content_hash is not 32 bytes".to_string())
        })?;
        hashes.push(arr);
    }
    Ok(hashes)
}
