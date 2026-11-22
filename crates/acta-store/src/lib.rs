pub mod claims_repo;
pub mod evidence_repo;
pub mod objects_repo;
pub mod overrides_repo;
pub mod pool;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use acta_crypto::{
    compute_evidence_event_hash_with_meta, compute_refusal_metadata_commitment, sign_evidence_entry,
};
use acta_types::{
    ActaError, ActaResult, EvidenceEntry, KnowledgeClaim, OmissionReason, OverrideAttestation,
    PolicyResultTag, RankedMemory, RefusalMetadata, StoredObject,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use evidence_repo::BundleWritePayload;
use objects_repo::ScopedObjectScan;
use sqlx::PgPool;
use uuid::Uuid;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Storage abstraction enforcing Policy-Before-Read testability and query instrumentation.
pub trait CompileStore: Send + Sync {
    fn fetch_scoped_intents<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<StoredObject>>>;

    fn fetch_scoped_memories_ranked<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        query_embedding: Option<&'a [f32]>,
        now: DateTime<Utc>,
        limit: i64,
    ) -> BoxFuture<'a, ActaResult<Vec<RankedMemory>>>;

    fn fetch_all_active_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<ScopedObjectScan>>;

    fn fetch_scoped_claims<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)>>;

    fn fetch_all_active_claim_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<Vec<[u8; 32]>>>;

    fn fetch_scoped_overrides<'a>(
        &'a self,
        _tenant_id: &'a str,
        _scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<OverrideAttestation>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn append_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        bundle: Option<BundleWritePayload<'a>>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>>;

    fn append_refusal_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        _state_commitment: Option<&'a [u8; 32]>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        self.append_evidence(host_key, tenant_id, policy_result, None, created_at)
    }

    fn append_refusal_metadata<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        meta: RefusalMetadata,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        Box::pin(async move {
            let comm = compute_refusal_metadata_commitment(&meta)?;
            let mut ev = self
                .append_refusal_evidence(
                    host_key,
                    tenant_id,
                    policy_result,
                    Some(&comm),
                    created_at,
                )
                .await?;
            ev.state_commitment = Some(comm);
            ev.refusal_metadata = Some(meta);
            ev.event_hash = compute_evidence_event_hash_with_meta(
                &ev.tenant_id,
                ev.seq_num,
                &ev.prev_hash,
                ev.bundle_hash.as_ref(),
                ev.state_commitment.as_ref(),
                ev.policy_result,
                ev.created_at.timestamp_micros(),
                ev.refusal_metadata.as_ref(),
                ev.override_summary.as_ref(),
            )?;
            ev.host_signature = sign_evidence_entry(
                host_key,
                &ev.tenant_id,
                ev.seq_num,
                &ev.prev_hash,
                &ev.event_hash,
            );
            Ok(ev)
        })
    }
}

type ScopeScanCacheMap = BTreeMap<(String, String), (i64, Arc<ScopedObjectScan>)>;

/// Production PostgreSQL store implementing `CompileStore`.
#[derive(Clone)]
pub struct PgActaStore {
    pool: PgPool,
    scope_scan_cache: Arc<RwLock<ScopeScanCacheMap>>,
}

impl PgActaStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            scope_scan_cache: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl CompileStore for PgActaStore {
    fn fetch_scoped_intents<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<StoredObject>>> {
        Box::pin(objects_repo::fetch_scoped_intents(&self.pool, tenant_id, scope))
    }

    fn fetch_scoped_memories_ranked<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        query_embedding: Option<&'a [f32]>,
        now: DateTime<Utc>,
        limit: i64,
    ) -> BoxFuture<'a, ActaResult<Vec<RankedMemory>>> {
        Box::pin(objects_repo::fetch_scoped_memories_ranked(
            &self.pool,
            tenant_id,
            scope,
            query_embedding,
            now,
            limit,
        ))
    }

    fn fetch_all_active_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<ScopedObjectScan>> {
        let pool = self.pool.clone();
        let cache = self.scope_scan_cache.clone();
        Box::pin(async move {
            let (row_count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*)::bigint FROM objects WHERE tenant_id = $1 AND scope = $2",
            )
            .bind(tenant_id)
            .bind(scope)
            .fetch_one(&pool)
            .await
            .map_err(|e| ActaError::Storage(format!("count scoped objects failed: {e}")))?;

            if row_count == 0 {
                return Ok(ScopedObjectScan::default());
            }

            let key = (tenant_id.to_string(), scope.to_string());
            if let Ok(guard) = cache.read() {
                if let Some((cached_count, cached_scan)) = guard.get(&key) {
                    if *cached_count == row_count {
                        return Ok((**cached_scan).clone());
                    }
                }
            }

            let fresh =
                objects_repo::fetch_all_active_hashes_in_scope(&pool, tenant_id, scope).await?;
            if let Ok(mut guard) = cache.write() {
                if guard.len() >= 64 && !guard.contains_key(&key) {
                    guard.clear();
                }
                guard.insert(key, (row_count, Arc::new(fresh.clone())));
            }
            Ok(fresh)
        })
    }

    fn fetch_scoped_claims<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)>> {
        Box::pin(claims_repo::fetch_scoped_claims(&self.pool, tenant_id, scope))
    }

    fn fetch_all_active_claim_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<Vec<[u8; 32]>>> {
        Box::pin(claims_repo::fetch_all_active_claim_hashes_in_scope(
            &self.pool, tenant_id, scope, now,
        ))
    }

    fn fetch_scoped_overrides<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<OverrideAttestation>>> {
        Box::pin(overrides_repo::fetch_active_scoped_overrides(
            &self.pool, tenant_id, scope,
        ))
    }

    fn append_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        bundle: Option<BundleWritePayload<'a>>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        Box::pin(evidence_repo::append_evidence_tx(
            &self.pool,
            host_key,
            tenant_id,
            policy_result,
            bundle,
            created_at,
        ))
    }

    fn append_refusal_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        state_commitment: Option<&'a [u8; 32]>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        Box::pin(evidence_repo::append_evidence_with_commitment_tx(
            &self.pool,
            host_key,
            tenant_id,
            policy_result,
            None,
            state_commitment,
            created_at,
        ))
    }

    fn append_refusal_metadata<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        meta: RefusalMetadata,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        Box::pin(evidence_repo::append_refusal_metadata_tx(
            &self.pool,
            host_key,
            tenant_id,
            policy_result,
            meta,
            created_at,
        ))
    }
}

#[derive(Clone)]
pub struct QueryCountingStore<S> {
    inner: S,
    objects_queries: Arc<AtomicUsize>,
    claims_queries: Arc<AtomicUsize>,
    evidence_writes: Arc<AtomicUsize>,
}

impl<S> QueryCountingStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            objects_queries: Arc::new(AtomicUsize::new(0)),
            claims_queries: Arc::new(AtomicUsize::new(0)),
            evidence_writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn objects_query_count(&self) -> usize {
        self.objects_queries.load(Ordering::SeqCst)
    }

    pub fn claims_query_count(&self) -> usize {
        self.claims_queries.load(Ordering::SeqCst)
    }

    pub fn evidence_write_count(&self) -> usize {
        self.evidence_writes.load(Ordering::SeqCst)
    }
}

impl<S: CompileStore> CompileStore for QueryCountingStore<S> {
    fn fetch_scoped_intents<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<StoredObject>>> {
        self.objects_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_scoped_intents(tenant_id, scope)
    }

    fn fetch_scoped_memories_ranked<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        query_embedding: Option<&'a [f32]>,
        now: DateTime<Utc>,
        limit: i64,
    ) -> BoxFuture<'a, ActaResult<Vec<RankedMemory>>> {
        self.objects_queries.fetch_add(1, Ordering::SeqCst);
        self.inner
            .fetch_scoped_memories_ranked(tenant_id, scope, query_embedding, now, limit)
    }

    fn fetch_all_active_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<ScopedObjectScan>> {
        self.objects_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_all_active_hashes_in_scope(tenant_id, scope)
    }

    fn fetch_scoped_claims<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)>> {
        self.claims_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_scoped_claims(tenant_id, scope)
    }

    fn fetch_all_active_claim_hashes_in_scope<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<Vec<[u8; 32]>>> {
        self.claims_queries.fetch_add(1, Ordering::SeqCst);
        self.inner
            .fetch_all_active_claim_hashes_in_scope(tenant_id, scope, now)
    }

    fn fetch_scoped_overrides<'a>(
        &'a self,
        tenant_id: &'a str,
        scope: &'a str,
    ) -> BoxFuture<'a, ActaResult<Vec<OverrideAttestation>>> {
        self.claims_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_scoped_overrides(tenant_id, scope)
    }

    fn append_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        bundle: Option<BundleWritePayload<'a>>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        self.evidence_writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .append_evidence(host_key, tenant_id, policy_result, bundle, created_at)
    }

    fn append_refusal_evidence<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        state_commitment: Option<&'a [u8; 32]>,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        self.evidence_writes.fetch_add(1, Ordering::SeqCst);
        self.inner.append_refusal_evidence(
            host_key,
            tenant_id,
            policy_result,
            state_commitment,
            created_at,
        )
    }

    fn append_refusal_metadata<'a>(
        &'a self,
        host_key: &'a SigningKey,
        tenant_id: &'a str,
        policy_result: PolicyResultTag,
        meta: RefusalMetadata,
        created_at: DateTime<Utc>,
    ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
        self.evidence_writes.fetch_add(1, Ordering::SeqCst);
        self.inner.append_refusal_metadata(
            host_key,
            tenant_id,
            policy_result,
            meta,
            created_at,
        )
    }
}
