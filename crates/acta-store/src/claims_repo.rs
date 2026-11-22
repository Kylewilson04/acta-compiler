use acta_crypto::{compute_claim_content_hash, to_canonical_bytes};
use acta_types::{ActaError, ActaResult, ClaimStatus, KnowledgeClaim, OmissionReason};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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
    created_at: DateTime<Utc>,
    is_superseded: bool,
}

impl ClaimRow {
    fn into_domain(self) -> ActaResult<(KnowledgeClaim, bool)> {
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
                created_at: self.created_at,
            },
            self.is_superseded,
        ))
    }
}

/// Appends a new versioned knowledge claim row (strictly append-only).
pub async fn insert_claim(pool: &PgPool, claim: &KnowledgeClaim) -> ActaResult<()> {
    sqlx::query(
        r#"
        INSERT INTO knowledge_claims (
            id, tenant_id, claim_group_key, scope, subject, predicate,
            object_val, object_type, confidence, source_provenance_class,
            source_descriptor, source_commitment, content_hash, status,
            contradiction_ids, valid_from, valid_to, version, predecessor_id, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19, $20
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
    .bind(claim.created_at)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_claim failed: {e}")))?;

    Ok(())
}

/// Atomically ingests an unsigned claim while enforcing same-source idempotency and
/// automatic append-only supersession (`predecessor_id = prev_head.id`, `version = prev_head.version + 1`)
/// when `claim.predecessor_id` is `None`. Returns `(persisted_claim, was_idempotent_noop)`.
pub async fn insert_or_supersede_claim_tx(
    pool: &PgPool,
    mut claim: KnowledgeClaim,
    allow_auto_supersede: bool,
) -> ActaResult<(KnowledgeClaim, bool)> {
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
                   c.predecessor_id, c.created_at,
                   FALSE AS is_superseded
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
            let (prev_head, _) = row.into_domain()?;
            let prev_val_bytes = to_canonical_bytes(&prev_head.object_val)?;
            let new_val_bytes = to_canonical_bytes(&claim.object_val)?;

            let same_payload = prev_val_bytes == new_val_bytes
                && prev_head.object_type == claim.object_type
                && (prev_head.confidence - claim.confidence).abs() < 1e-12
                && prev_head.source_provenance_class == claim.source_provenance_class
                && prev_head.valid_from == claim.valid_from
                && prev_head.valid_to == claim.valid_to
                && prev_head.contradiction_ids == claim.contradiction_ids;

            if same_payload {
                tx.commit().await.map_err(|e| {
                    ActaError::Storage(format!("commit idempotent claim noop failed: {e}"))
                })?;
                return Ok((prev_head, true));
            }

            claim.predecessor_id = Some(prev_head.id);
            claim.version = prev_head.version + 1;
            claim.content_hash = compute_claim_content_hash(&claim)?;
        }
    }

    sqlx::query(
        r#"
        INSERT INTO knowledge_claims (
            id, tenant_id, claim_group_key, scope, subject, predicate,
            object_val, object_type, confidence, source_provenance_class,
            source_descriptor, source_commitment, content_hash, status,
            contradiction_ids, valid_from, valid_to, version, predecessor_id, created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13, $14,
            $15, $16, $17, $18, $19, $20
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
    .bind(claim.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_claim failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit claim transaction failed: {e}")))?;

    Ok((claim, false))
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
               c.predecessor_id, c.created_at,
               FALSE AS is_superseded
        FROM knowledge_claims c
        WHERE c.tenant_id = $1 AND c.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_claim_by_id failed: {e}")))?;

    Ok(row.map(ClaimRow::into_domain).transpose()?.map(|(c, _)| c))
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
               c.predecessor_id, c.created_at,
               FALSE AS is_superseded
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
        .map(|r| r.into_domain().map(|(c, _)| c))
        .collect()
}

/// Fetches all scoped claims in `(tenant_id, scope)`, separating head claims passed to the
/// resolver from predecessor-superseded historical versions (`OmissionReason::Superseded`).
pub async fn fetch_scoped_claims(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
) -> ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)> {
    let rows = sqlx::query_as::<_, ClaimRow>(
        r#"
        SELECT c.id, c.tenant_id, c.claim_group_key, c.scope, c.subject, c.predicate,
               c.object_val, c.object_type, c.confidence, c.source_provenance_class,
               c.source_descriptor, c.source_commitment, c.content_hash, c.status,
               c.contradiction_ids, c.valid_from, c.valid_to, c.version,
               c.predecessor_id, c.created_at,
               EXISTS (
                   SELECT 1 FROM knowledge_claims succ
                   WHERE succ.tenant_id = c.tenant_id
                     AND succ.predecessor_id = c.id
               ) AS is_superseded
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.scope = $2
        ORDER BY c.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_scoped_claims failed: {e}")))?;

    let mut head_claims = Vec::new();
    let mut superseded = Vec::new();

    for row in rows {
        let (claim, is_superseded) = row.into_domain()?;
        if is_superseded || claim.status == ClaimStatus::Superseded {
            superseded.push((claim.id, OmissionReason::Superseded));
        } else {
            head_claims.push(claim);
        }
    }

    Ok((head_claims, superseded))
}

/// Returns `content_hash` values of all active, non-superseded, temporally-valid claims
/// in `(tenant_id, scope)` for computing `knowledge_root`.
pub async fn fetch_all_active_claim_hashes_in_scope(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    now: DateTime<Utc>,
) -> ActaResult<Vec<[u8; 32]>> {
    let raw_hashes: Vec<(Vec<u8>,)> = sqlx::query_as(
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
        ORDER BY c.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_all_active_claim_hashes_in_scope failed: {e}")))?;

    raw_hashes
        .into_iter()
        .map(|(v,)| {
            v.try_into()
                .map_err(|_| ActaError::Storage("claim content_hash is not 32 bytes".to_string()))
        })
        .collect()
}
