use std::sync::Arc;

use acta_crypto::{
    compute_erasable_claim_commitment, compute_source_content_commitment, compute_state_commitment,
    compute_sub_commitment, compute_sub_commitment_v2, mint_user_tenant_api_key,
    sign_witness_anchor, verify_and_rebuild_scope_state_offline, verify_export_archive,
};
use std::collections::BTreeMap;
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{routes::build_router, state::AppState};
use acta_store::pool::run_migrations;
use acta_types::{
    ExportArchive, StateRebuildArchive, SCHEMA_VERSION_V1, SCHEMA_VERSION_V2,
    STATE_REBUILD_ARCHIVE_SCHEMA_V1, STATE_REBUILD_ARCHIVE_SCHEMA_V2,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    bearer_or_api_key: &str,
    use_bearer: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if use_bearer {
        builder = builder.header("Authorization", format!("Bearer {bearer_or_api_key}"));
    } else {
        builder = builder.header("X-Acta-Api-Key", bearer_or_api_key);
    }
    let req = if let Some(b) = body {
        builder
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        json!({ "raw": String::from_utf8_lossy(&bytes).to_string() })
    });
    (status, val)
}

async fn mcp_tool(
    app: &Router,
    bearer: &str,
    name: &str,
    arguments: Value,
) -> Value {
    let (st, rpc) = http_json(
        app,
        "POST",
        "/mcp",
        bearer,
        true,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "MCP transport failed for {name}: {rpc}");
    rpc["result"].clone()
}

#[tokio::test]
async fn test_v173_part_a_and_part_c_postgres_end_to_end() {
    let Ok(db_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping PostgreSQL E2E test (DATABASE_URL not set)");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&db_url)
        .await
        .expect("connect PostgreSQL");
    run_migrations(&pool).await.expect("run migrations 0001..0011");

    let cedar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/default.cedar");
    let gate = Arc::new(PolicyGate::from_file(&cedar_path, BTreeMap::new()).expect("load default.cedar"));
    let k0_seed = [0x41u8; 32];
    let k0_sk = SigningKey::from_bytes(&k0_seed);
    let k0_pk = k0_sk.verifying_key().to_bytes();
    let master_key = "test-master-v173-secret";

    let state = AppState::new(
        pool.clone(),
        gate.clone(),
        Arc::new(k0_sk),
        PipelineConfig::default(),
    )
    .with_auth(Some(master_key.to_string()), "sandbox".to_string());
    let app = build_router(state);

    let tenant = format!("v173-e2e-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let bearer = mint_user_tenant_api_key(master_key, &tenant, "kylewilson04").unwrap();
    let scope = "acta-test/v173-e2e";

    // 1. Ingest object + two agreeing 0.60 claims -> compile v2 bundle (`acta-context-bundle/v2`, `resolver_version: "v1.7.3"`)
    let o1 = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 95,
            "importance": 1.0,
            "tags": ["v173"],
            "body": {"directive": "Verify v1.7.3 proof layer and pilot readiness"}
        }),
    )
    .await;
    assert_ne!(o1["isError"], json!(true), "o1 failed: {o1}");

    let a1 = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.60,
            "source_provenance_class": 2,
            "source_descriptor": "erp-a",
            "source_content": "Apex lead_days = 14"
        }),
    )
    .await["structuredContent"]
        .clone();

    let a2 = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.60,
            "source_provenance_class": 2,
            "source_descriptor": "bol-b",
            "source_content": "BOL lead_days = 14"
        }),
    )
    .await["structuredContent"]
        .clone();

    let b1 = mcp_tool(
        &app,
        &bearer,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "po-v173",
            "query_text": "Check supplier:apex lead_days",
            "token_budget": 2048
        }),
    )
    .await["structuredContent"]
        .clone();

    assert_eq!(b1["bundle"]["schema_version"], json!(SCHEMA_VERSION_V2));
    assert_eq!(
        b1["bundle"]["resolver_manifest"]["resolver_version"],
        json!("v1.7.3")
    );
    let b1_hash = b1["bundle_hash"].as_str().unwrap().to_string();
    let b1_seq = b1["evidence"]["seq_num"].as_i64().unwrap();
    let b1_sc = b1["bundle"]["state_commitment"].as_str().unwrap().to_string();

    // Verify Part A.6: v2 state commitment matches domain-tagged `b"acta:sub_commitment:v2"` + `b"acta:state:v2"`!
    let o1_ch: [u8; 32] = hex::decode(o1["structuredContent"]["content_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let a1_ch: [u8; 32] = hex::decode(a1["content_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let a2_ch: [u8; 32] = hex::decode(a2["content_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let expected_b1_sc = compute_state_commitment(
        SCHEMA_VERSION_V2,
        &tenant,
        scope,
        &compute_sub_commitment_v2(&[o1_ch]),
        &compute_sub_commitment_v2(&[a1_ch, a2_ch]),
        &compute_sub_commitment_v2(&[]),
        &gate.permission_root(),
    );
    assert_eq!(hex::encode(expected_b1_sc), b1_sc);

    // Verify Part A.4: replay exposes recorded_resolver_version + reproducing_resolver == "v173_current"
    let rep1 = mcp_tool(
        &app,
        &bearer,
        "acta_replay_counterfactual",
        json!({ "source_bundle_hash": b1_hash }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(rep1["reproduced_source_bundle_bit_for_bit"], json!(true));
    assert_eq!(rep1["recorded_resolver_version"], json!("v1.7.3"));
    assert_eq!(rep1["reproducing_resolver"], json!("v173_current"));
    assert_eq!(rep1["resolver_compat"], json!("v173_current"));

    // 2. Verify Part A.3: Narrowed `dependency_ids` recorded in AnswerCacheLedgerSummary & CachedAnswerReceipt;
    //    un-narrowed omits `dependency_ids`!
    let ca_unnarrowed = mcp_tool(
        &app,
        &bearer,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "Unnarrowed query",
            "answer_text": "14 days corroborated"
        }),
    )
    .await["structuredContent"]
        .clone();
    assert!(
        ca_unnarrowed["evidence"]["answer_cache_summary"]
            .get("dependency_ids")
            .is_none(),
        "un-narrowed cache summary must omit dependency_ids: {ca_unnarrowed}"
    );

    let a1_id_str = a1["id"].as_str().unwrap().to_string();
    let ca_narrowed = mcp_tool(
        &app,
        &bearer,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "Narrowed to A1",
            "answer_text": "Pinned to A1",
            "validity_mode": "dependency_subset",
            "dependency_ids": [a1_id_str]
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(
        ca_narrowed["receipt"]["dependency_ids"],
        json!([a1_id_str])
    );
    assert_eq!(
        ca_narrowed["evidence"]["answer_cache_summary"]["dependency_ids"],
        json!([a1_id_str])
    );

    // 3. Verify Part A.2: Mutate `A2` -> caching un-narrowed or `scope_root` against stale `b1` MUST refuse with `bundle_stale_at_cache_time` (409),
    //    whereas caching narrowed to unchanged `[A1.id]` succeeds!
    let _a2_v2 = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "predecessor_id": a2["id"],
            "object_val": 16,
            "object_type": "int",
            "confidence": 0.55,
            "source_provenance_class": 2,
            "source_descriptor": "bol-b"
        }),
    )
    .await;

    let stale_dep = mcp_tool(
        &app,
        &bearer,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "Stale unnarrowed attempt",
            "answer_text": "Should fail",
            "validity_mode": "dependency_subset"
        }),
    )
    .await;
    assert_eq!(stale_dep["isError"], json!(true));
    assert!(
        stale_dep["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("bundle_stale_at_cache_time"),
        "expected bundle_stale_at_cache_time, got {stale_dep}"
    );

    let stale_root = mcp_tool(
        &app,
        &bearer,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "Stale scope_root attempt",
            "answer_text": "Should fail",
            "validity_mode": "scope_root"
        }),
    )
    .await;
    assert_eq!(stale_root["isError"], json!(true));
    assert!(
        stale_root["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("bundle_stale_at_cache_time")
    );

    // Narrowed to A1 (which is still active & un-superseded) still succeeds!
    let ok_narrow_still_fresh = mcp_tool(
        &app,
        &bearer,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "Still fresh A1 narrow",
            "answer_text": "A1 untouched",
            "validity_mode": "dependency_subset",
            "dependency_ids": [a1_id_str]
        }),
    )
    .await;
    assert_ne!(ok_narrow_still_fresh["isError"], json!(true));

    // Now supersede A1 -> lookup `Narrowed to A1` -> invalidation receipt ALSO preserves `dependency_ids: [A1.id]`!
    let _a1_v2 = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "predecessor_id": a1["id"],
            "object_val": 18,
            "object_type": "int",
            "confidence": 0.91,
            "source_provenance_class": 2,
            "source_descriptor": "erp-a"
        }),
    )
    .await;

    let inv_lookup = mcp_tool(
        &app,
        &bearer,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "po-v173",
            "query_text": "Narrowed to A1"
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(inv_lookup["status"], json!("stale_dependency_commitment"));
    assert_eq!(
        inv_lookup["invalidation_evidence"]["answer_cache_summary"]["dependency_ids"],
        json!([a1_id_str])
    );

    // 4. Verify Part A.1 & Part A.5:
    //    - Seed a scope `acta-test/v173-frozen` at `S_frozen`, then write to `scope` (`seq > S_frozen`),
    //      and confirm `up_to_seq: S_frozen` on `acta-test/v173-frozen` returns `matches_live_store_bit_for_bit == true`!
    //    - Also confirm `up_to_seq: b1_seq` on `scope` (which WAS mutated later) reconstructs `b1_sc` and reports `matches_live_store_bit_for_bit == false`!
    let frozen_clm = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": "acta-test/v173-frozen",
            "subject": "audit:v171-sim",
            "predicate": "pinned",
            "object_val": true,
            "object_type": "bool",
            "confidence": 0.95,
            "source_provenance_class": 2,
            "source_descriptor": "audit-log"
        }),
    )
    .await["structuredContent"]
        .clone();
    let s_frozen = frozen_clm["evidence_seq_num"].as_i64().unwrap();
    // Advance ledger in ANOTHER scope so `s_frozen < chain_head`
    mcp_tool(
        &app,
        &bearer,
        "acta_ingest_object",
        json!({
            "obj_type": "memory",
            "scope": "acta-test/v173-other",
            "priority": 10,
            "importance": 0.5,
            "tags": [],
            "body": {"note": "Advances tenant chain head past s_frozen"}
        }),
    )
    .await;
    let reb_frozen_prefix = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({
            "scope": "acta-test/v173-frozen",
            "up_to_seq": s_frozen,
            "include_proof_archive": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_frozen_prefix["matches_live_store_bit_for_bit"], json!(true));

    let reb_at_b1 = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({
            "scope": scope,
            "up_to_seq": b1_seq,
            "include_proof_archive": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_at_b1["matches_live_store_bit_for_bit"], json!(false));
    assert_eq!(reb_at_b1["reconstructed_state_commitment"], json!(b1_sc));
    assert_eq!(
        reb_at_b1["rebuild_proof_archive"]["schema_version"],
        json!(STATE_REBUILD_ARCHIVE_SCHEMA_V2)
    );

    let reb_head = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({
            "scope": scope,
            "include_proof_archive": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_head["matches_live_store_bit_for_bit"], json!(true));
    let head_chain = reb_head["rebuild_proof_archive"]["evidence_chain"]
        .as_array()
        .unwrap();
    let tail_ts = head_chain.last().unwrap()["created_at"].as_str().unwrap();
    assert_eq!(reb_head["evaluated_at"].as_str().unwrap(), tail_ts);

    // 5. Verify Part C.4: Salted-Commitment Cryptographic Erasure (`erasable: true` -> secret resolve -> `erase_secret: true`)
    let pii_text = "Patient John Doe DOB 1980-01-01 MRN-44910";
    let pii_claim = mcp_tool(
        &app,
        &bearer,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "patient:44910",
            "predicate": "phi_record",
            "object_val": {"full_name": "John Doe", "mrn": "44910"},
            "object_type": "object",
            "confidence": 0.96,
            "source_provenance_class": 2,
            "source_descriptor": "ehr-intake",
            "source_content": pii_text,
            "erasable": true
        }),
    )
    .await["structuredContent"]
        .clone();
    let pii_id = Uuid::parse_str(pii_claim["id"].as_str().unwrap()).unwrap();

    // Verify immutable DB tables do NOT contain "John Doe" or "MRN-44910"!
    let stored_val_str: String = sqlx::query_scalar(
        "SELECT object_val::text FROM knowledge_claims WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant)
    .bind(pii_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!stored_val_str.contains("John Doe"));
    assert!(stored_val_str.contains("$acta_erasable_commitment"));

    // Resolve secret via REST while active
    let (st_sec1, sec1) = http_json(
        &app,
        "GET",
        &format!("/v1/tenants/{tenant}/claims/{pii_id}/secret"),
        &bearer,
        true,
        None,
    )
    .await;
    assert_eq!(st_sec1, StatusCode::OK);
    assert_eq!(sec1["is_erasable"], json!(true));
    assert_eq!(sec1["erased"], json!(false));
    assert_eq!(sec1["commitment_verified"], json!(true));
    assert_eq!(sec1["object_val"]["full_name"], json!("John Doe"));
    let salt_arr: [u8; 32] = hex::decode(sec1["salt_32_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let src_comm = compute_source_content_commitment("ehr-intake", pii_text.as_bytes());
    let recomputed_erasure = compute_erasable_claim_commitment(
        pii_id,
        &salt_arr,
        &json!({"full_name": "John Doe", "mrn": "44910"}),
        &src_comm,
    )
    .unwrap();
    assert_eq!(
        hex::encode(recomputed_erasure),
        sec1["erasure_commitment_hex"].as_str().unwrap()
    );

    // Retract with `erase_secret: true` -> cleartext & salt purged, chain & rebuild remain 100% verifiable!
    let ret_pii = mcp_tool(
        &app,
        &bearer,
        "acta_retract_claim",
        json!({
            "claim_id": pii_id,
            "scope": scope,
            "reason": "GDPR Art. 17 erasure request",
            "erase_secret": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(ret_pii["secret_erased"], json!(true));

    let (st_sec2, sec2) = http_json(
        &app,
        "GET",
        &format!("/v1/tenants/{tenant}/claims/{pii_id}/secret"),
        &bearer,
        true,
        None,
    )
    .await;
    assert_eq!(st_sec2, StatusCode::OK);
    assert_eq!(sec2["erased"], json!(true));
    assert!(sec2["object_val"].is_null());
    assert!(sec2["salt_32_hex"].is_null());

    // 6. Verify Part C.3: Witness Anchor + Scheduled Host Key Rotation (K0 -> K1) + Compromise Recovery (K1 -> K2)
    let wit_sk = SigningKey::from_bytes(&[0x77u8; 32]);
    let wit_pk_hex = hex::encode(wit_sk.verifying_key().to_bytes());
    mcp_tool(
        &app,
        &bearer,
        "acta_register_witness",
        json!({
            "witness_id": "pilot-witness-1",
            "witness_public_key_hex": wit_pk_hex,
            "description": "Pilot witness"
        }),
    )
    .await;

    let cp0 = mcp_tool(&app, &bearer, "acta_get_checkpoint", json!({}))
        .await["structuredContent"]["checkpoint"]
        .clone();
    let anchored_m = cp0["tree_size"].as_i64().unwrap();
    let cp0_hash_arr: [u8; 32] = hex::decode(cp0["checkpoint_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let wit_sig = sign_witness_anchor(&wit_sk, &tenant, anchored_m, &cp0_hash_arr);
    mcp_tool(
        &app,
        &bearer,
        "acta_anchor_checkpoint",
        json!({
            "tree_size": anchored_m,
            "checkpoint_hash": hex::encode(cp0_hash_arr),
            "witness_id": "pilot-witness-1",
            "witness_public_key_hex": wit_pk_hex,
            "witness_signature_hex": hex::encode(wit_sig)
        }),
    )
    .await;

    // Scheduled rotation K0 -> K1
    let k1_seed = [0x42u8; 32];
    let k1_pk = SigningKey::from_bytes(&k1_seed).verifying_key().to_bytes();
    let (st_rot1, rot1_resp) = http_json(
        &app,
        "POST",
        "/v1/admin/rotate-host-key",
        master_key,
        false,
        Some(json!({
            "tenant_id": tenant,
            "new_signing_key_seed_hex": hex::encode(k1_seed),
            "rotation_mode": "scheduled",
            "reason": "Scheduled rotation K0 -> K1"
        })),
    )
    .await;
    assert_eq!(st_rot1, StatusCode::CREATED, "rot1 failed: {rot1_resp}");

    // Compile a bundle under K1 and verify multi-key ExportArchive offline!
    let b_k1 = mcp_tool(
        &app,
        &bearer,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "post-k1",
            "query_text": "Post rotation compile",
            "token_budget": 2048
        }),
    )
    .await["structuredContent"]
        .clone();
    let b_k1_seq = b_k1["evidence"]["seq_num"].as_i64().unwrap();
    let (_, exp_k1_val) = http_json(
        &app,
        "GET",
        &format!("/v1/bundles/{}/export", b_k1["bundle_hash"].as_str().unwrap()),
        &bearer,
        true,
        None,
    )
    .await;
    let exp_k1: ExportArchive = serde_json::from_value(exp_k1_val).unwrap();
    let sum_k1 = verify_export_archive(&exp_k1, &k1_pk).expect("multi-key ExportArchive verify");
    assert_eq!(sum_k1.bundle_hash_hex, b_k1["bundle_hash"].as_str().unwrap());

    // Compromise recovery K1 -> K2 (with old_signing_key_lost: true, quarantining b_k1_seq while preserving anchored prefix 1..=anchored_m)
    let k2_seed = [0x43u8; 32];
    let k2_pk = SigningKey::from_bytes(&k2_seed).verifying_key().to_bytes();
    let (st_rot2, rot2_resp) = http_json(
        &app,
        "POST",
        "/v1/admin/rotate-host-key",
        master_key,
        false,
        Some(json!({
            "tenant_id": tenant,
            "new_signing_key_seed_hex": hex::encode(k2_seed),
            "rotation_mode": "compromise_recovery",
            "compromised_from_seq": b_k1_seq,
            "old_signing_key_lost": true,
            "reason": "Rehearse K1 compromise recovery"
        })),
    )
    .await;
    assert_eq!(st_rot2, StatusCode::CREATED, "rot2 failed: {rot2_resp}");

    let reb_after_rot2 = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({
            "scope": scope,
            "include_proof_archive": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_after_rot2["matches_live_store_bit_for_bit"], json!(true));
    let archive_rot2: StateRebuildArchive =
        serde_json::from_value(reb_after_rot2["rebuild_proof_archive"].clone()).unwrap();
    assert_eq!(archive_rot2.genesis_host_public_key, Some(k0_pk));
    assert_eq!(archive_rot2.host_public_key, k2_pk);
    let offline_rot2 =
        verify_and_rebuild_scope_state_offline(&archive_rot2, &k2_pk, None).expect("offline multi-key rebuild");
    assert_eq!(
        offline_rot2.reconstructed_state_commitment_hex,
        reb_after_rot2["reconstructed_state_commitment"].as_str().unwrap()
    );
    assert_eq!(offline_rot2.anchored_tree_size, Some(anchored_m));
    assert_eq!(offline_rot2.quarantined_compromised_seqs, vec![b_k1_seq]);

    // 7. Verify Part C.6: Opt-in Legacy Scope Backfill (`POST /v1/tenants/:id/backfill-legacy-scope`)
    //    AND historical `v1` scope auto-detection (`acta-state-rebuild-archive/v1`)!
    let legacy_scope = "acta-test/pre-v170-legacy";
    let leg_obj_id = Uuid::new_v4();
    let leg_ts = chrono::Utc::now();
    let leg_obj = acta_types::StoredObject {
        id: leg_obj_id,
        tenant_id: tenant.clone(),
        obj_type: acta_types::ObjectType::Intent,
        scope: legacy_scope.to_string(),
        lifecycle_status: acta_types::LifecycleStatus::Active,
        priority: 50,
        importance: 0.8,
        tags: vec!["legacy".to_string()],
        body: json!({"note": "Pre-v1.7.0 unchained intent"}),
        content_hash: [0u8; 32],
        embedding: None,
        version: 1,
        predecessor_id: None,
        client_signature: None,
        client_public_key: None,
        written_by: None,
        evidence_seq_num: None,
        created_at: leg_ts,
    };
    let mut leg_obj = leg_obj;
    leg_obj.content_hash = acta_crypto::compute_object_content_hash(&leg_obj).unwrap();
    sqlx::query(
        r#"
        INSERT INTO objects (
            id, tenant_id, obj_type, scope, lifecycle_status, priority, importance,
            tags, body, content_hash, version, created_at
        ) VALUES ($1, $2, 'intent', $3, 'active', 50, 0.8, $4, $5, $6, 1, $7)
        "#,
    )
    .bind(leg_obj.id)
    .bind(&tenant)
    .bind(legacy_scope)
    .bind(&leg_obj.tags)
    .bind(&leg_obj.body)
    .bind(leg_obj.content_hash.as_slice())
    .bind(leg_obj.created_at)
    .execute(&pool)
    .await
    .unwrap();

    let reb_before_bf = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({ "scope": legacy_scope }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_before_bf["legacy_pre_v17_unchained_objects"], json!(1));
    assert_eq!(reb_before_bf["matches_live_store_bit_for_bit"], json!(false));

    let (st_bf, bf_resp) = http_json(
        &app,
        "POST",
        &format!("/v1/tenants/{tenant}/backfill-legacy-scope"),
        &bearer,
        true,
        Some(json!({ "scope": legacy_scope })),
    )
    .await;
    assert_eq!(st_bf, StatusCode::OK, "backfill failed: {bf_resp}");
    assert_eq!(bf_resp["imported_objects"], json!(1));

    let reb_after_bf = mcp_tool(
        &app,
        &bearer,
        "acta_verify_state_rebuild",
        json!({
            "scope": legacy_scope,
            "state_schema_version": SCHEMA_VERSION_V1,
            "include_proof_archive": true
        }),
    )
    .await["structuredContent"]
        .clone();
    assert_eq!(reb_after_bf["matches_live_store_bit_for_bit"], json!(true));
    assert_eq!(reb_after_bf["legacy_pre_v17_unchained_objects"], json!(0));
    assert_eq!(
        reb_after_bf["rebuild_proof_archive"]["schema_version"],
        json!(STATE_REBUILD_ARCHIVE_SCHEMA_V1)
    );
    let expected_v1_leg = compute_state_commitment(
        SCHEMA_VERSION_V1,
        &tenant,
        legacy_scope,
        &compute_sub_commitment(&[leg_obj.content_hash]),
        &compute_sub_commitment(&[]),
        &compute_sub_commitment(&[]),
        &gate.permission_root(),
    );
    assert_eq!(
        reb_after_bf["reconstructed_state_commitment"].as_str().unwrap(),
        hex::encode(expected_v1_leg)
    );
}
