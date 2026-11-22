use acta_types::{
    ActaError, ActaResult, LifecycleStatus, ObjectType, OmissionReason, RankedMemory, StoredObject,
};
use chrono::{DateTime, Utc};
use pgvector::Vector;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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
    created_at: DateTime<Utc>,
    hybrid_score: f64,
}

#[derive(FromRow)]
struct AggregatedScopeScanRow {
    active_intent_hashes: Option<Vec<u8>>,
    active_memory_hashes: Option<Vec<u8>>,
    active_memory_ids: Option<Vec<Uuid>>,
    superseded_ids: Option<Vec<Uuid>>,
    expired_ids: Option<Vec<Uuid>>,
}

/// Appends a new versioned object row (strictly append-only; never mutates existing rows).
pub async fn insert_object(pool: &PgPool, obj: &StoredObject) -> ActaResult<()> {
    let embedding_vec = obj.embedding.as_ref().map(|v| Vector::from(v.clone()));

    sqlx::query(
        r#"
        INSERT INTO objects (
            id, tenant_id, obj_type, scope, lifecycle_status,
            priority, importance, tags, body, content_hash,
            embedding, version, predecessor_id, client_signature, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
    .bind(obj.created_at)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("insert_object failed: {e}")))?;

    Ok(())
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
               embedding, version, predecessor_id, client_signature, created_at
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
               embedding, version, predecessor_id, client_signature, created_at
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
    let rows = sqlx::query_as::<_, ObjectRow>(
        r#"
        SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
               o.priority, o.importance, o.tags, o.body, o.content_hash,
               NULL::vector AS embedding, o.version, o.predecessor_id,
               o.client_signature, o.created_at
        FROM objects o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND o.obj_type = 'intent'
          AND o.lifecycle_status = 'active'
          AND NOT EXISTS (
              SELECT 1 FROM objects succ
              WHERE succ.tenant_id = o.tenant_id
                AND succ.predecessor_id = o.id
          )
        ORDER BY o.priority DESC, o.created_at DESC, o.version DESC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_scoped_intents failed: {e}")))?;

    rows.into_iter().map(ObjectRow::into_domain).collect()
}

/// Fetches active, non-superseded memories ranked deterministically via pgvector HNSW
/// cosine ANN retrieval (`ORDER BY o.embedding <=> $3 LIMIT ...`) followed by exact
/// hybrid re-ranking (`0.60 * cosine + 0.25 * importance + 0.15 * recency_decay`).
pub async fn fetch_scoped_memories_ranked(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    query_embedding: Option<&[f32]>,
    now: DateTime<Utc>,
    limit: i64,
) -> ActaResult<Vec<RankedMemory>> {
    let rows = if let Some(emb) = query_embedding {
        let query_vec = Vector::from(emb.to_vec());
        let ann_limit = (limit.saturating_mul(2)).clamp(40, 128);

        // Two-stage HNSW ANN retrieval: inner CTE keeps `ORDER BY o.embedding <=> $3 LIMIT $6`
        // unadorned so PostgreSQL uses `idx_objects_embedding_hnsw` directly instead of
        // decompressing all TOASTed 1536-dim vectors across 10k+ rows.
        let mut hnsw_rows = sqlx::query_as::<_, RankedMemoryRow>(
            r#"
            WITH ann_candidates AS MATERIALIZED (
                SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
                       o.priority, o.importance, o.tags, o.body, o.content_hash,
                       o.version, o.predecessor_id, o.client_signature, o.created_at,
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
                   c.version, c.predecessor_id, c.client_signature, c.created_at,
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
        .map_err(|e| ActaError::Storage(format!("fetch_scoped_memories_ranked (hnsw) failed: {e}")))?;

        // Fallback for sparse multi-tenant scopes (or memories stored with NULL embeddings)
        // when HNSW post-filtering yields zero candidates.
        if hnsw_rows.is_empty() {
            hnsw_rows = sqlx::query_as::<_, RankedMemoryRow>(
                r#"
                SELECT o.id, o.tenant_id, o.obj_type, o.scope, o.lifecycle_status,
                       o.priority, o.importance, o.tags, o.body, o.content_hash,
                       o.version, o.predecessor_id, o.client_signature, o.created_at,
                       (
                           0.60 * COALESCE(1.0 - (o.embedding <=> $3), 0.0)
                           + 0.25 * (o.importance::double precision)
                           + 0.15 * (1.0 / (1.0 + GREATEST(EXTRACT(EPOCH FROM ($4 - o.created_at)), 0.0) / 86400.0))
                       ) AS hybrid_score
                FROM objects o
                WHERE o.tenant_id = $1
                  AND o.scope = $2
                  AND o.obj_type = 'memory'
                  AND o.lifecycle_status = 'active'
                  AND NOT EXISTS (
                      SELECT 1 FROM objects succ
                      WHERE succ.tenant_id = o.tenant_id
                        AND succ.predecessor_id = o.id
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
                   o.version, o.predecessor_id, o.client_signature, o.created_at,
                   (
                       0.70 * (o.importance::double precision)
                       + 0.30 * (1.0 / (1.0 + GREATEST(EXTRACT(EPOCH FROM ($3 - o.created_at)), 0.0) / 86400.0))
                   ) AS hybrid_score
            FROM objects o
            WHERE o.tenant_id = $1
              AND o.scope = $2
              AND o.obj_type = 'memory'
              AND o.lifecycle_status = 'active'
              AND NOT EXISTS (
                  SELECT 1 FROM objects succ
                  WHERE succ.tenant_id = o.tenant_id
                    AND succ.predecessor_id = o.id
              )
            ORDER BY hybrid_score DESC, o.importance DESC, o.created_at DESC, o.version DESC, o.id ASC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(scope)
        .bind(now)
        .bind(limit)
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

/// Single-row index-only covering scan returning all active intent/memory hashes in `(tenant_id, scope)`
/// along with pre-filtered lifecycle/supersession omissions.
pub async fn fetch_all_active_hashes_in_scope(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
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
                   ) AS is_superseded
            FROM objects o
            WHERE o.tenant_id = $1
              AND o.scope = $2
        )
        SELECT
            string_agg(content_hash, ''::bytea ORDER BY content_hash ASC)
                FILTER (WHERE NOT is_superseded AND lifecycle_status = 'active' AND obj_type = 'intent')
                AS active_intent_hashes,
            string_agg(content_hash, ''::bytea ORDER BY content_hash ASC)
                FILTER (WHERE NOT is_superseded AND lifecycle_status = 'active' AND obj_type = 'memory')
                AS active_memory_hashes,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_superseded AND lifecycle_status = 'active' AND obj_type = 'memory')
                AS active_memory_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE is_superseded OR lifecycle_status = 'superseded')
                AS superseded_ids,
            array_agg(id ORDER BY id ASC)
                FILTER (WHERE NOT is_superseded AND lifecycle_status NOT IN ('active', 'superseded'))
                AS expired_ids
        FROM scoped
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_all_active_hashes_in_scope failed: {e}")))?;

    let active_intent_hashes = unpack_hash32_concat(agg.active_intent_hashes)?;
    let active_memory_hashes = unpack_hash32_concat(agg.active_memory_hashes)?;
    let active_memory_ids = agg.active_memory_ids.unwrap_or_default();

    let sup_ids = agg.superseded_ids.unwrap_or_default();
    let exp_ids = agg.expired_ids.unwrap_or_default();
    let mut excluded_objects = Vec::with_capacity(sup_ids.len() + exp_ids.len());
    for id in sup_ids {
        excluded_objects.push((id, OmissionReason::Superseded));
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
