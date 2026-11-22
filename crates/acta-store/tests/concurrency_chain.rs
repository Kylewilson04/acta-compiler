use std::sync::Arc;

use acta_crypto::verify_evidence_signature;
use acta_store::{
    evidence_repo::{append_evidence_tx, fetch_tenant_evidence_chain, BundleWritePayload},
    pool::{create_pool, run_migrations},
};
use acta_types::PolicyResultTag;
use chrono::{SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use uuid::Uuid;

/// Task 8 Verification Gate:
/// Spawns 20 concurrent compile writes for the same tenant and asserts zero sequence
/// gaps (`1..=20`) and an unbroken `prev_hash` chain signed by `host_key`.
#[tokio::test]
async fn test_20_concurrent_tenant_evidence_writes_unbroken_chain() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping Postgres integration test: DATABASE_URL not set");
        return;
    };

    let pool = create_pool(&database_url, 25).await.expect("connect pool");
    run_migrations(&pool).await.expect("migrations");

    let tenant_id = format!("tenant-concurrency-{}", Uuid::new_v4());
    let host_key = Arc::new(SigningKey::from_bytes(&[0x5Au8; 32]));
    let verifying_key = host_key.verifying_key();

    let mut handles = Vec::with_capacity(20);
    for idx in 0..20u8 {
        let pool_clone = pool.clone();
        let key_clone = host_key.clone();
        let tenant_clone = tenant_id.clone();

        handles.push(tokio::spawn(async move {
            let mut bundle_hash = [0u8; 32];
            bundle_hash[0] = idx;
            bundle_hash[31] = 0xEE;
            let state_commitment = [idx; 32];
            let dep_commitment = [idx.wrapping_add(1); 32];
            let canonical_json = format!(r#"{{"idx":{idx}}}"#).into_bytes();

            let payload = BundleWritePayload {
                bundle_hash: &bundle_hash,
                state_commitment: &state_commitment,
                dependency_commitment: &dep_commitment,
                bundle_canonical: &canonical_json,
            };

            append_evidence_tx(
                &pool_clone,
                &key_clone,
                &tenant_clone,
                PolicyResultTag::Allow,
                Some(payload),
                Utc::now().trunc_subsecs(6),
            )
            .await
            .expect("concurrent append_evidence_tx")
        }));
    }

    for h in handles {
        h.await.expect("join concurrent task");
    }

    let chain = fetch_tenant_evidence_chain(&pool, &tenant_id, None)
        .await
        .expect("fetch chain");

    assert_eq!(chain.len(), 20, "expected exactly 20 evidence entries");

    let mut expected_prev = [0u8; 32];
    for (i, entry) in chain.iter().enumerate() {
        let expected_seq = (i as i64) + 1;
        assert_eq!(entry.seq_num, expected_seq, "zero sequence gaps allowed");
        assert_eq!(entry.prev_hash, expected_prev, "unbroken prev_hash link");
        assert!(
            verify_evidence_signature(
                &verifying_key,
                &entry.tenant_id,
                entry.seq_num,
                &entry.prev_hash,
                &entry.event_hash,
                &entry.host_signature
            ),
            "valid Ed25519 signature required at seq_num={expected_seq}"
        );
        expected_prev = entry.event_hash;
    }
}
