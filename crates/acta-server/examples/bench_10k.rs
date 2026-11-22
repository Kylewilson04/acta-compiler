use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use acta_crypto::{compute_claim_content_hash, compute_claim_group_key, compute_object_content_hash};
use acta_engine::{CompilePipeline, PipelineConfig};
use acta_policy::PolicyGate;
use acta_store::{
    claims_repo, objects_repo,
    pool::{create_pool, run_migrations},
    PgActaStore,
};
use acta_types::{
    CompileRequest, ContextBudget, KnowledgeClaim, LifecycleStatus, ObjectType, StoredObject,
};
use chrono::{SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;
use uuid::Uuid;

const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

/// Task 12 Benchmark Harness:
/// Seeds a 10,000-row tenant (intents + vector-indexed memories + claims) into Postgres
/// and verifies p99 compile latency < 15ms (excluding external embedding calls).
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://acta:acta_dev_password@127.0.0.1:5432/acta".to_string());

    let pool = create_pool(&database_url, 8).await?;
    run_migrations(&pool).await?;

    let tenant_id = format!("bench-10k-{}", Uuid::new_v4());
    let scope = "benchmark";
    let now = Utc::now().trunc_subsecs(6);

    println!("Seeding 10,000 rows for tenant={tenant_id}...");

    // Seed 25 active intents
    for i in 0..25i32 {
        let mut obj = StoredObject {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            obj_type: ObjectType::Intent,
            scope: scope.to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority: 100 - i,
            importance: 0.95,
            tags: vec!["bench".to_string()],
            body: json!({"intent_idx": i, "rule": "Maintain deterministic latency"}),
            content_hash: [0u8; 32],
            embedding: None,
            version: 1,
            predecessor_id: None,
            client_signature: None,
            created_at: now,
        };
        obj.content_hash = compute_object_content_hash(&obj)?;
        objects_repo::insert_object(&pool, &obj).await?;
    }

    // Seed 9,875 memories (batched concurrently in chunks of 50)
    let mut base_emb = vec![0.005f32; 1536];
    base_emb[0] = 0.9;

    for chunk_start in (0..9_875usize).step_by(50) {
        let mut futs = Vec::with_capacity(50);
        for offset in 0..50usize {
            let idx = chunk_start + offset;
            if idx >= 9_875 {
                break;
            }
            let pool_ref = pool.clone();
            let t_id = tenant_id.clone();
            let mut emb = base_emb.clone();
            emb[idx % 1536] = 0.5;
            futs.push(tokio::spawn(async move {
                let mut mem = StoredObject {
                    id: Uuid::new_v4(),
                    tenant_id: t_id,
                    obj_type: ObjectType::Memory,
                    scope: scope.to_string(),
                    lifecycle_status: LifecycleStatus::Active,
                    priority: 0,
                    importance: ((idx % 100) as f32) / 100.0,
                    tags: vec!["telemetry".to_string()],
                    body: json!({"idx": idx, "summary": "Cached operational snapshot"}),
                    content_hash: [0u8; 32],
                    embedding: Some(emb),
                    version: 1,
                    predecessor_id: None,
                    client_signature: None,
                    created_at: now,
                };
                mem.content_hash = compute_object_content_hash(&mem).unwrap();
                objects_repo::insert_object(&pool_ref, &mem).await.unwrap();
            }));
        }
        for f in futs {
            f.await?;
        }
    }

    // Seed 100 claims (total = 25 + 9,875 + 100 = 10,000 rows)
    for i in 0..100usize {
        let subj = format!("svc-{}", i / 2);
        let group_key = compute_claim_group_key(&tenant_id, &subj, "healthy", "bool", scope);
        let conf = if i % 2 == 0 { 0.92 } else { 0.60 };
        let mut claim = KnowledgeClaim {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            claim_group_key: group_key,
            scope: scope.to_string(),
            subject: subj,
            predicate: "healthy".to_string(),
            object_val: json!(i % 2 == 0),
            object_type: "bool".to_string(),
            confidence: conf,
            source_provenance_class: 2,
            source_descriptor: "health-monitor".to_string(),
            source_commitment: [0x22; 32],
            content_hash: [0u8; 32],
            status: LifecycleStatus::Active,
            contradiction_ids: vec![],
            valid_from: None,
            valid_to: None,
            version: 1,
            predecessor_id: None,
            created_at: now,
        };
        claim.content_hash = compute_claim_content_hash(&claim)?;
        claims_repo::insert_claim(&pool, &claim).await?;
    }

    sqlx::query("ANALYZE objects").execute(&pool).await?;
    sqlx::query("ANALYZE knowledge_claims").execute(&pool).await?;

    let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new())?);
    let host_key = Arc::new(SigningKey::from_bytes(&[0xABu8; 32]));
    let pipeline = CompilePipeline::new(
        gate,
        PgActaStore::new(pool),
        host_key,
        PipelineConfig {
            candidate_memory_fetch_limit: 40,
            ..PipelineConfig::default()
        },
    );

    let req_template = CompileRequest {
        tenant_id: tenant_id.clone(),
        actor_id: "bench-agent".to_string(),
        task_id: "bench-task".to_string(),
        scope: scope.to_string(),
        query_text: "Check fleet health".to_string(),
        query_embedding: Some(base_emb),
        budget: ContextBudget::Tokens(2048),
        evaluation_time: None,
    };

    // Warmup (tokenizer + all 8 pooled connections' prepared statements + HNSW index pages)
    for _ in 0..30 {
        pipeline.compile(req_template.clone()).await?;
    }

    let iterations = 300usize;
    let mut latencies_us = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let resp = pipeline.compile(req_template.clone()).await?;
        assert!(resp.bundle_hash.is_some());
        latencies_us.push(t0.elapsed().as_micros() as u64);
    }

    latencies_us.sort_unstable();
    let p50_ms = (latencies_us[iterations * 50 / 100] as f64) / 1000.0;
    let p95_ms = (latencies_us[iterations * 95 / 100] as f64) / 1000.0;
    let p99_ms = (latencies_us[iterations * 99 / 100] as f64) / 1000.0;

    println!(
        "10,000-row Compile Benchmark ({iterations} runs): p50={p50_ms:.2}ms p95={p95_ms:.2}ms p99={p99_ms:.2}ms"
    );
    assert!(
        p99_ms < 15.0,
        "SLO breach: expected p99 < 15.0ms, measured {p99_ms:.2}ms"
    );

    Ok(())
}
