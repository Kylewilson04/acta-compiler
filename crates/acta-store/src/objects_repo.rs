use acta_crypto::{
    compute_evidence_event_hash_full, compute_write_summary_commitment, sign_evidence_entry,
};
use acta_types::{
    ActaError, ActaResult, EvidenceEntry, LifecycleStatus, ObjectType, OmissionReason,
    PolicyResultTag, RankedMemory, StoredObject, WriteLedgerSummary, WriteOperationKind,
    WRITE_EVENT_DOMAIN_V1,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use pgvector::Vector;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::evidence_repo::lock_and_read_latest_evidence_tx;

#[derive(Debug, Clone, Default)]
pub struct ScopedObjectScan {
    pub active_intent_hashes: Vec<[u8; 32]>,
    pub active_memory_hashes: Vec<[u8; 32]>,
    pub active_memory_ids: Vec<Uuid>,
    pub excluded_objects: Vec<(Uuid, OmissionReason)>,
}

#[derive(FromRow)]
struct ObjectRow {
    id: Uuid,
    tenant_id: String,
    obj_type: String,
    scope: String,
    lifecycle_status: String,
    priority: i32,
    importance: f32,
    tags: Vec<String>,
    body: serde_json::Value,
    content_hash: Vec<u8>,
    embedding: Option<Vector>,
    version: i32,
    predecessor_id: Option<Uuid>,
    client_signature: Option<Vec<u8>>,
    client_public_key: Option<Vec<u8>>,
    written_by: Option<String>,
    evidence_seq_num: Option<i64>,
    created_at: DateTime<Utc>,
}

impl ObjectRow {
    fn into_domain(self) -> ActaResult<StoredObject> {
        let obj_type = ObjectType::from_db_str(&self.obj_type).map_err(ActaError::Storage)?;
        let lifecycle_status =
            LifecycleStatus::from_db_str(&self.lifecycle_status).map_err(ActaError::Storage)?;
        let content_hash: [u8; 32] = self
            .content_hash
            .try_into()
            .map_err(|_| ActaError::Storage("object content_hash is not 32 bytes".to_string()))?;
        let client_public_key: Option<[u8; 32]> = self
            .client_public_key
            .map(|v| {
                v.try_into().map_err(|_| {
                    ActaError::Storage("object client_public_key is not 32 bytes".to_string())
                })
            })
            .transpose()?;

        Ok(StoredObject {
            id: self.id,
            tenant_id: self.tenant_id,
            obj_type,
            scope: self.scope,
            lifecycle_status,
            priority: self.priority,
            importance: self.importance,
            tags: self.tags,
            body: self.body,
            content_hash,
            embedding: self.embedding.map(|v| v.to_vec()),
            version: self.version,
            predecessor_id: self.predecessor_id,
            client_signature: self.client_signature,
            client_public_key,
            written_by: self.written_by,
            evidence_seq_num: self.evidence_seq_num,
            created_at: self.created_at,
        })
    }
}

#[derive(FromRow)]
struct RankedMemoryRow {
    id: Uuid,
    tenant_id: String,
    obj_type: String,
    scope: String,
    lifecycle_status: String,
    priority: i32,
    importance: f32,
    tags: Vec<String>,
    body: serde_json::Value,
    content_hash: Vec<u8>,
    version: i32,
    predecessor_id: Option<Uuid>,
    client_signature: Option<Vec<u8>>,
    client_public_key: Option<Vec<u8>>,
    written_by: Option<String>,
    evidence_seq_num: Option<i64>,
    created_at: DateTime<Utc>,
    hybrid_score: f64,
}

#[derive(FromRow)]
struct AggregatedScopeScanRow {
    active_intent_hashes: Option<Vec<u8>>,
    active_memory_hashes: Option<Vec<u8>>,
    active_memory_ids: Option<Vec<Uuid>>,
    retracted_ids: Option<Vec<Uuid>>,
    superseded_ids: Option<Vec<Uuid>>,
    retraction_tombstone_ids: Option<Vec<Uuid>>,
    expired_ids: Option<Vec<Uuid>>,
}

/// Appends a new versioned object row directly (helper retained for tests/fixtures).
pub async fn insert_object(pool: &PgPool, obj: &StoredObject) -> ActaResult<()> {
    let embedding_vec = obj.embedding.as_ref().map(|v| Vector::from(v.clone()));

    sqlx::query(
        r#"
        INSERT INTO objects (
            id, tenant_id, obj_type, scope, lifecycle_status,
            priority, importance, tags, body, content_hash,
            embedding, version, predecessor_id, client_signature,
            client_public_key, written_by, write_domain, evidence_seq_num, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
        "#,
    )
    .bind(obj.id)
    .bind(&obj.tenant_id)
    .bind(obj.obj_type.as_str())
    .bind(&obj.scope)
    .bind(obj.lifecycle_status.as_str())
    .bind(obj.priority)
    .bind(obj.importance)
    .bind(&obj.tags)
    .bind(&obj.body)
    .bind(obj.content_hash.as_slice())
    .bind(embedding_vec)
    .bind(obj.version)
    .bind(obj.predecessor_id)
    .bind(obj.client_signature.as_deref())
    .bind(obj.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(obj.written_by.as_deref())
    .bind(obj.evidence_seq_num.map(|_| WRITE_EVENT_DOMAIN_V1))
    .bind(obj.evidence_seq_num)
    .bind(obj.created_at)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_object failed: {e}")))?;

    Ok(())
}

/// Atomically persists an immutable `StoredObject` AND notarizes its strip-proof `WriteLedgerSummary`
/// (`acta:write_event:v1` -> `acta:evidence_event:v3`) on `evidence_history` under the two-statement
/// per-tenant advisory lock (`v1.7.0+`, PPA 1 Claim 1 & Claim 8).
pub async fn insert_object_with_evidence_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    mut obj: StoredObject,
    written_by: &str,
    writer_auth_kind: &str,
) -> ActaResult<(StoredObject, EvidenceEntry)> {
    let embedding_vec = obj.embedding.as_ref().map(|v| Vector::from(v.clone()));

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin object write transaction failed: {e}")))?;

    let (prev_seq, prev_hash) = lock_and_read_latest_evidence_tx(&mut tx, &obj.tenant_id).await?;
    let seq_num = prev_seq + 1;

    obj.written_by = Some(written_by.to_string());
    obj.evidence_seq_num = Some(seq_num);

    let mut snap_obj = obj.clone();
    snap_obj.embedding = None;
    let record_snapshot = serde_json::to_value(&snap_obj)
        .map_err(|e| ActaError::Storage(format!("serialize StoredObject snapshot failed: {e}")))?;

    let write_summary = WriteLedgerSummary {
        write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
        operation: WriteOperationKind::IngestObject,
        item_id: obj.id,
        scope: obj.scope.clone(),
        version: obj.version,
        predecessor_id: obj.predecessor_id,
        content_hash: obj.content_hash,
        written_by: written_by.to_string(),
        writer_auth_kind: writer_auth_kind.to_string(),
        client_public_key: obj.client_public_key,
        client_signature: obj.client_signature.clone(),
        retraction_reason: None,
        record_snapshot,
    };

    let write_comm = compute_write_summary_commitment(&write_summary)?;
    let event_hash = compute_evidence_event_hash_full(
        &obj.tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&write_comm),
        PolicyResultTag::Allow,
        obj.created_at.timestamp_micros(),
        None,
        None,
        Some(&write_summary),
        None,
    )?;
    let host_signature = sign_evidence_entry(host_key, &obj.tenant_id, seq_num, &prev_hash, &event_hash);
    let write_meta_json = serde_json::to_value(&write_summary)
        .map_err(|e| ActaError::Storage(format!("serialize write_meta failed: {e}")))?;

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
    .bind(&obj.tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(event_hash.as_slice())
    .bind(write_comm.as_slice())
    .bind(write_meta_json)
    .bind(host_signature.as_slice())
    .bind(obj.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert object evidence_history failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO objects (
            id, tenant_id, obj_type, scope, lifecycle_status,
            priority, importance, tags, body, content_hash,
            embedding, version, predecessor_id, client_signature,
            client_public_key, written_by, write_domain, evidence_seq_num, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
        "#,
    )
    .bind(obj.id)
    .bind(&obj.tenant_id)
    .bind(obj.obj_type.as_str())
    .bind(&obj.scope)
    .bind(obj.lifecycle_status.as_str())
    .bind(obj.priority)
    .bind(obj.importance)
    .bind(&obj.tags)
    .bind(&obj.body)
    .bind(obj.content_hash.as_slice())
    .bind(embedding_vec)
    .bind(obj.version)
    .bind(obj.predecessor_id)
    .bind(obj.client_signature.as_deref())
    .bind(obj.client_public_key.as_ref().map(|k| k.as_slice()))
    .bind(obj.written_by.as_deref())
    .bind(WRITE_EVENT_DOMAIN_V1)
    .bind(seq_num)
    .bind(obj.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_object in tx failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit object write transaction failed: {e}")))?;

    let ev = EvidenceEntry {
        tenant_id: obj.tenant_id.clone(),
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
        host_key_rotation_summary: None,
        host_signature,
        created_at: obj.created_at,
    };

    Ok((obj, ev))
}

/// Fetches a single object by `(tenant_id, id)` for predecessor resolution.
pub async fn fetch_object_by_id(
    pool: &PgPool,
    tenant_id: &str,
    id: Uuid,
) -> ActaResult<Option<StoredObject>> {
    let row = sqlx::query_as::<_, ObjectRow>(
        r#"
        SELECT id, tenant_id, obj_type, scope, lifecycle_status,
               priority, importance, tags, body, content_hash,
               embedding, version, predecessor_id, client_signature,
               client_public_key, written_by, evidence_seq_num, created_at
        FROM objects
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_object_by_id failed: {e}")))?;

    row.map(ObjectRow::into_domain).transpose()
}

/// Fetches multiple objects by ID for offline archive export (`GET /v1/bundles/:hash/export`).
pub async fn fetch_objects_by_ids(
    pool: &PgPool,
    tenant_id: &str,
    ids: &[Uuid],
) -> ActaResult<Vec<StoredObject>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows = sqlx::query_as::<_, ObjectRow>(
        r#"
        SELECT id, tenant_id, obj_type, scope, lifecycle_status,
               priority, importance, tags, body, content_hash,
               embedding, version, predecessor_id, client_signature,
               client_public_key, written_by, evidence_seq_num, created_at
        FROM objects
        WHERE tenant_id = $1 AND id = ANY($2)
        ORDER BY id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_objects_by_ids failed: {e}")))?;

    rows.into_iter().map(ObjectRow::into_domain).collect()
}

/// Fetches all active, non-superseded intents in `(tenant_id, scope)` ordered by priority DESC.
pub async fn fetch_scoped_intents(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
) -> ActaResult<Vec<StoredObject>> {
    fetch_scoped_intents_as_of(pool, tenant_id, scope, None).await
}

/// Time-pinned variant of `fetch_scoped_intents`.
pub async fn fetch_scoped_intents_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<Vec<StoredObject>> {
    let rows = sqlx::query_as::<_, ObjectRow>(
        r#"
        SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
               o.priority, o.importance, o.tags, o.body, o.content_hash,
               NULL::vector AS embedding, o.version, o.predecessor_id,
               o.client_signature, o.client_public_key, o.written_by,
               o.evidence_seq_num, o.created_at
        FROM objects o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND o.obj_type = 'intent'
          AND o.lifecycle_status = 'active'
          AND ($3::timestamptz IS NULL OR o.created_at <= $3)
          AND NOT EXISTS (
              SELECT 1 FROM objects succ
              WHERE succ.tenant_id = o.tenant_id
                AND succ.predecessor_id = o.id
                AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
          )
        ORDER BY o.priority DESC, o.created_at DESC, o.version DESC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(as_of)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_scoped_intents failed: {e}")))?;

    rows.into_iter().map(ObjectRow::into_domain).collect()
}

pub async fn fetch_scoped_memories_ranked(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    query_embedding: Option<&[f32]>,
    now: DateTime<Utc>,
    limit: i64,
) -> ActaResult<Vec<RankedMemory>> {
    fetch_scoped_memories_ranked_as_of(pool, tenant_id, scope, query_embedding, now, limit, None)
        .await
}

pub async fn fetch_scoped_memories_ranked_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    query_embedding: Option<&[f32]>,
    now: DateTime<Utc>,
    limit: i64,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<Vec<RankedMemory>> {
    let rows = if let Some(emb) = query_embedding {
        let query_vec = Vector::from(emb.to_vec());
        let ann_limit = (limit.saturating_mul(2)).clamp(40, 128);

        let mut hnsw_rows = if as_of.is_none() {
            sqlx::query_as::<_, RankedMemoryRow>(
                r#"
                WITH ann_candidates AS MATERIALIZED (
                    SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
                           o.priority, o.importance, o.tags, o.body, o.content_hash,
                           o.version, o.predecessor_id, o.client_signature,
                           o.client_public_key, o.written_by, o.evidence_seq_num, o.created_at,
                           (o.embedding <=> $3) AS cosine_dist
                    FROM objects o
                    WHERE o.tenant_id = $1
                      AND o.scope = $2
                      AND o.obj_type = 'memory'
                      AND o.lifecycle_status = 'active'
                      AND o.embedding IS NOT NULL
                    ORDER BY o.embedding <=> $3
                    LIMIT $6
                )
                SELECT c.id, c.tenant_id, c.obj_type, c.scope, c.lifecycle_status,
                       c.priority, c.importance, c.tags, c.body, c.content_hash,
                       c.version, c.predecessor_id, c.client_signature,
                       c.client_public_key, c.written_by, c.evidence_seq_num, c.created_at,
                       (
                           0.60 * (1.0 - c.cosine_dist)
                           + 0.25 * (c.importance::double precision)
                           + 0.15 * (1.0 / (1.0 + GREATEST(EXTRACT(EPOCH FROM ($4 - c.created_at)), 0.0) / 86400.0))
                       ) AS hybrid_score
                FROM ann_candidates c
                WHERE NOT EXISTS (
                    SELECT 1 FROM objects succ
                    WHERE succ.tenant_id = c.tenant_id
                      AND succ.predecessor_id = c.id
                )
                ORDER BY hybrid_score DESC, c.importance DESC, c.created_at DESC, c.version DESC, c.id ASC
                LIMIT $5
                "#,
            )
            .bind(tenant_id)
            .bind(scope)
            .bind(query_vec.clone())
            .bind(now)
            .bind(limit)
            .bind(ann_limit)
            .fetch_all(pool)
            .await
            .map_err(|e| ActaError::Storage(format!("fetch_scoped_memories_ranked (hnsw) failed: {e}")))?
        } else {
            Vec::new()
        };

        if hnsw_rows.is_empty() {
            hnsw_rows = sqlx::query_as::<_, RankedMemoryRow>(
                r#"
                SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
                       o.priority, o.importance, o.tags, o.body, o.content_hash,
                       o.version, o.predecessor_id, o.client_signature,
                       o.client_public_key, o.written_by, o.evidence_seq_num, o.created_at,
                       (
                           0.60 * COALESCE(1.0 - (o.embedding <=> $3), 0.0)
                           + 0.25 * (o.importance::double precision)
                           + 0.15 * (1.0 / (1.0 + GREATEST(EXTRACT(EPOCH FROM ($4 - c.created_at)), 0.0) / 86400.0))
                       ) AS hybrid_score
                FROM objects o
                WHERE o.tenant_id = $1
                  AND o.scope = $2
                  AND o.obj_type = 'memory'
                  AND o.lifecycle_status = 'active'
                  AND ($6::timestamptz IS NULL OR o.created_at <= $6)
                  AND NOT EXISTS (
                      SELECT 1 FROM objects succ
                      WHERE succ.tenant_id = o.tenant_id
                        AND succ.predecessor_id = o.id
                        AND ($6::timestamptz IS NULL OR succ.created_at <= $6)
                  )
                ORDER BY hybrid_score DESC, o.importance DESC, o.created_at DESC, o.version DESC, o.id ASC
                LIMIT $5
                "#,
            )
            .bind(tenant_id)
            .bind(scope)
            .bind(query_vec)
            .bind(now)
            .bind(limit)
            .bind(as_of)
            .fetch_all(pool)
            .await
            .map_err(|e| ActaError::Storage(format!("fetch_scoped_memories_ranked (fallback) failed: {e}")))?;
        }
        hnsw_rows
    } else {
        sqlx::query_as::<_, RankedMemoryRow>(
            r#"
            SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
                   o.priority, o.importance, o.tags, o.body, o.content_hash,
                   o.version, o.predecessor_id, o.client_signature,
                   o.client_public_key, o.written_by, o.evidence_seq_num, o.created_at,
                   (
                       0.70 * (o.importance::double precision)
                       + 0.30 * (1.0 / (1.0 + GREATEST(EXTRACT(EPOCH FROM ($3 - o.created_at)), 0.0) / 86400.0))
                   ) AS hybrid_score
            FROM objects o
            WHERE o.tenant_id = $1
               AND o.scope = $2
               AND o.obj_type = 'memory'
               AND o.lifecycle_status = 'active'
               AND ($5::timestamptz IS NULL OR o.created_at <= $5)
               AND NOT EXISTS (
                   SELECT 1 FROM objects succ
                   WHERE succ.tenant_id = o.tenant_id
                     AND succ.predecessor_id = o.id
                     AND ($5::timestamptz IS NULL OR succ.created_at <= $5)
               )
            ORDER BY hybrid_score DESC, o.importance DESC, o.created_at DESC, o.version DESC, o.id ASC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(scope)
        .bind(now)
        .bind(limit)
        .bind(as_of)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("fetch_scoped_memories_ranked (scalar) failed: {e}")))?
    };
    rows.into_iter()
        .map(|r| {
            let content_hash: [u8; 32] = r
                .content_hash
                .try_into()
                .map_err(|_| ActaError::Storage("memory content_hash is not 32 bytes".to_string()))?;
            let client_public_key: Option<[u8; 32]> = r
                .client_public_key
                .map(|v| {
                    v.try_into().map_err(|_| {
                        ActaError::Storage("memory client_public_key is not 32 bytes".to_string())
                    })
                })
                .transpose()?;
            let obj_type = ObjectType::from_db_str(&r.obj_type).map_err(ActaError::Storage)?;
            let lifecycle_status =
                LifecycleStatus::from_db_str(&r.lifecycle_status).map_err(ActaError::Storage)?;
            Ok(RankedMemory {
                object: StoredObject {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    obj_type,
                    scope: r.scope,
                    lifecycle_status,
                    priority: r.priority,
                    importance: r.importance,
                    tags: r.tags,
                    body: r.body,
                    content_hash,
                    embedding: None,
                    version: r.version,
                    predecessor_id: r.predecessor_id,
                    client_signature: r.client_signature,
                    client_public_key,
                    written_by: r.written_by,
                    evidence_seq_num: r.evidence_seq_num,
                    created_at: r.created_at,
                },
                hybrid_score: r.hybrid_score,
            })
        })
        .collect()
}

fn unpack_hash32_concat(opt_bytes: Option<Vec<u8>>) -> ActaResult<Vec<[u8; 32]>> {
    let Some(bytes) = opt_bytes else {
        return Ok(Vec::new());
    };
    if bytes.len() % 32 != 0 {
        return Err(ActaError::Storage(format!(
            "aggregated content_hash buffer length {} is not a multiple of 32",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        out.push(arr);
    }
    out.sort_unstable();
    Ok(out)
}

pub async fn fetch_all_active_hashes_in_scope(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
) -> ActaResult<ScopedObjectScan> {
    fetch_all_active_hashes_in_scope_as_of(pool, tenant_id, scope, None).await
}

pub async fn fetch_all_active_hashes_in_scope_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<ScopedObjectScan> {
    let agg = sqlx::query_as::<_, AggregatedScopeScanRow>(
        r#"
        WITH scoped AS (
            SELECT o.id,
                   o.obj_type,
                   o.lifecycle_status,
                   o.content_hash,
                   EXISTS (
                       SELECT 1 FROM objects succ
                       WHERE succ.tenant_id = o.tenant_id
                         AND succ.predecessor_id = o.id
                         AND succ.lifecycle_status <> 'revoked'
                         AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
                   ) AS is_superseded,
                   EXISTS (
                       SELECT 1 FROM objects succ
                       WHERE succ.tenant_id = o.tenant_id
                         AND succ.predecessor_id = o.id
                         AND succ.lifecycle_status = 'revoked'
                         AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
                   ) AS is_retracted
            FROM objects o
            WHERE o.tenant_id = $1
              AND o.scope = $2
              AND ($3::timestamptz IS NULL OR o.created_at <= $3)
        )
        SELECT
            string_agg(content_hash, ''::bytea ORDER BY content_hash ASC)
                FILTER (WHERE NOT is_superseded AND NOT is_retracted AND lifecycle_status = 'active' AND obj_type = 'intent')
                AS active_intent_hashes,
            string_agg(content_hash, ''::bytea ORDER BY content_hash ASC)
                FILTER (WHERE NOT is_superseded AND NOT is_retracted AND lifecycle_status = 'active' AND obj_type = 'memory')
                AS active_memory_hashes,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_superseded AND NOT is_retracted AND lifecycle_status = 'active' AND obj_type = 'memory')
                AS active_memory_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE is_retracted)
                AS retracted_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_retracted AND (is_superseded OR lifecycle_status = 'superseded'))
                AS superseded_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_retracted AND NOT is_superseded AND lifecycle_status = 'revoked')
                AS retraction_tombstone_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_retracted AND NOT is_superseded AND lifecycle_status NOT IN ('active', 'superseded', 'revoked'))
                AS expired_ids
        FROM scoped
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(as_of)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_all_active_hashes_in_scope failed: {e}")))?;

    let active_intent_hashes = unpack_hash32_concat(agg.active_intent_hashes)?;
    let active_memory_hashes = unpack_hash32_concat(agg.active_memory_hashes)?;
    let active_memory_ids = agg.active_memory_ids.unwrap_or_default();

    let ret_ids = agg.retracted_ids.unwrap_or_default();
    let sup_ids = agg.superseded_ids.unwrap_or_default();
    let tomb_ids = agg.retraction_tombstone_ids.unwrap_or_default();
    let exp_ids = agg.expired_ids.unwrap_or_default();
    let mut excluded_objects =
        Vec::with_capacity(ret_ids.len() + sup_ids.len() + tomb_ids.len() + exp_ids.len());
    for id in ret_ids {
        excluded_objects.push((id, OmissionReason::Retracted));
    }
    for id in sup_ids {
        excluded_objects.push((id, OmissionReason::Superseded));
    }
    for id in tomb_ids {
        excluded_objects.push((id, OmissionReason::RetractionTombstone));
    }
    for id in exp_ids {
        excluded_objects.push((id, OmissionReason::LifecycleExpired));
    }

    Ok(ScopedObjectScan {
        active_intent_hashes,
        active_memory_hashes,
        active_memory_ids,
        excluded_objects,
    })
}
