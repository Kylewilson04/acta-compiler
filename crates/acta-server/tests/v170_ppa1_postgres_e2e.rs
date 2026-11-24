use std::collections::BTreeMap;
use std::sync::Arc;

use acta_crypto::{
    compute_answer_cache_client_intent_hash, compute_answer_text_hash,
    compute_claim_client_intent_hash, compute_claim_content_hash, compute_logical_claim_group_key,
    compute_object_client_intent_hash, compute_object_content_hash, compute_query_text_hash,
    compute_retract_claim_client_intent_hash, compute_source_content_commitment,
    mint_user_tenant_api_key, verify_export_archive,
};
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{routes::build_router, state::AppState};
use acta_store::{
    claims_repo, evidence_repo, objects_repo,
    pool::{create_pool, run_migrations},
};
use acta_types::{
    CompileResponse, ExportArchive, KnowledgeClaim, LifecycleStatus, ObjectType, StoredObject,
};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use chrono::{SubsecRound, Utc};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

async fn mcp_rpc(app: &Router, bearer_tok: &str, tool_name: &str, args: Value) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {bearer_tok}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": args
                }
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&raw).unwrap()
}

#[tokio::test]
async fn test_v170_ppa1_full_postgres_legacy_compat_write_chain_answer_cache_retraction_and_impact()
{
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping v1.7.0 PostgreSQL E2E test: DATABASE_URL not set");
        return;
    };

    let pool = create_pool(&database_url, 16).await.expect("connect pool");

    // -----------------------------------------------------------------------
    // Phase 0: Simulate pre-v1.7.0 vault rows BEFORE 0008 backfill (or direct
    // unchained legacy inserts) to prove seq 1..153 bit-for-bit compatibility
    // AND retroactive bundle_dependencies backfill!
    // -----------------------------------------------------------------------
    run_migrations(&pool).await.expect("run migrations 0001..0008");

    let master_secret = "v170-test-master-secret";
    let tenant_id = format!("kw04-v170-{}", Uuid::new_v4().simple());
    let token = mint_user_tenant_api_key(master_secret, &tenant_id, "kylewilson04").unwrap();

    let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new()).unwrap());
    let host_key = Arc::new(SigningKey::from_bytes(&[0x77u8; 32]));
    let state = AppState::new(pool.clone(), gate, host_key.clone(), PipelineConfig::default())
        .with_auth(Some(master_secret.to_string()), "sandbox".to_string());
    let app = build_router(state);

    // Seed an unchained pre-v1.7.0 object & claim (`evidence_seq_num = NULL`) and compile `seq 1` (`v1` event)
    let legacy_ts = Utc::now().trunc_subsecs(6) - chrono::Duration::seconds(30);
    let mut legacy_obj = StoredObject {
        id: Uuid::new_v4(),
        tenant_id: tenant_id.clone(),
        obj_type: ObjectType::Intent,
        scope: "legacy/v166-scope".to_string(),
        lifecycle_status: LifecycleStatus::Active,
        priority: 100,
        importance: 1.0,
        tags: vec!["pre-v170".to_string()],
        body: json!({"directive": "Historical pre-v1.7.0 unchained object"}),
        content_hash: [0u8; 32],
        embedding: None,
        version: 1,
        predecessor_id: None,
        client_signature: None,
        client_public_key: None,
        written_by: None,
        evidence_seq_num: None,
        created_at: legacy_ts,
    };
    legacy_obj.content_hash = compute_object_content_hash(&legacy_obj).unwrap();
    objects_repo::insert_object(&pool, &legacy_obj)
        .await
        .unwrap();

    let leg_grp = compute_logical_claim_group_key(
        &tenant_id,
        "legacy:sku-1",
        "price_usd",
        "legacy/v166-scope",
    );
    let mut legacy_claim = KnowledgeClaim {
        id: Uuid::new_v4(),
        tenant_id: tenant_id.clone(),
        claim_group_key: leg_grp,
        scope: "legacy/v166-scope".to_string(),
        subject: "legacy:sku-1".to_string(),
        predicate: "price_usd".to_string(),
        object_val: json!(99.0),
        object_type: "number".to_string(),
        confidence: 0.91,
        source_provenance_class: 1,
        source_descriptor: "legacy-erp".to_string(),
        source_commitment: [0x11; 32],
        content_hash: [0u8; 32],
        status: LifecycleStatus::Active,
        contradiction_ids: vec![],
        valid_from: None,
        valid_to: None,
        version: 1,
        predecessor_id: None,
        client_signature: None,
        client_public_key: None,
        retraction_reason: None,
        written_by: None,
        evidence_seq_num: None,
        created_at: legacy_ts,
    };
    legacy_claim.content_hash = compute_claim_content_hash(&legacy_claim).unwrap();
    claims_repo::insert_claim(&pool, &legacy_claim)
        .await
        .unwrap();

    // Compile legacy scope -> seq 1 (`acta:evidence_event:v1`)
    let leg_comp = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": "legacy/v166-scope",
            "query_text": "check legacy sku price"
        }),
    )
    .await;
    assert_eq!(leg_comp["result"]["isError"], json!(false));
    let leg_bundle_hash = leg_comp["result"]["structuredContent"]["bundle_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        leg_comp["result"]["structuredContent"]["evidence"]["seq_num"],
        json!(1)
    );
    assert_eq!(
        leg_comp["result"]["structuredContent"]["evidence"]["event_domain"],
        json!("acta:evidence_event:v1")
    );

    // Verify bundle_dependencies append-only trigger blocks DELETE AND 0008 SQL is idempotent!
    let del_err = sqlx::query("DELETE FROM bundle_dependencies WHERE tenant_id = $1")
        .bind(&tenant_id)
        .execute(&pool)
        .await;
    assert!(
        del_err.is_err(),
        "bundle_dependencies must enforce acta_prevent_mutation append-only trigger!"
    );
    let mig_sql = include_str!("../../../migrations/0008_v1_7_0_ppa1_parity.sql");
    sqlx::raw_sql(mig_sql).execute(&pool).await.unwrap();

    // Verify legacy bundle still verifies in BOTH full and merkle modes AND replay reproduces bit-for-bit!
    for mode in ["full", "merkle"] {
        let ver_leg = mcp_rpc(
            &app,
            &token,
            "acta_verify_bundle",
            json!({
                "bundle_hash": leg_bundle_hash,
                "proof_mode": mode
            }),
        )
        .await;
        assert_eq!(ver_leg["result"]["isError"], json!(false), "mode={mode}");
        assert_eq!(ver_leg["result"]["structuredContent"]["verified"], json!(true));
    }
    let leg_replay = mcp_rpc(
        &app,
        &token,
        "acta_replay_counterfactual",
        json!({ "source_bundle_hash": leg_bundle_hash }),
    )
    .await;
    assert_eq!(
        leg_replay["result"]["structuredContent"]["reproduced_source_bundle_bit_for_bit"],
        json!(true)
    );

    // Verify backfilled bundle_dependencies finds `leg_bundle_hash` on `legacy_claim.id`!
    let leg_impact = mcp_rpc(
        &app,
        &token,
        "acta_trace_claim_impact",
        json!({ "item_id": legacy_claim.id.to_string() }),
    )
    .await;
    assert_eq!(leg_impact["result"]["isError"], json!(false));
    assert_eq!(
        leg_impact["result"]["structuredContent"]["impacted_bundle_count"],
        json!(1)
    );
    assert_eq!(
        leg_impact["result"]["structuredContent"]["impacted_bundles"][0]["bundle_hash"],
        json!(leg_bundle_hash)
    );

    // -----------------------------------------------------------------------
    // Phase 1: Full v1.7.0 PPA 1 Write-Chained Scope, Client Ed25519 Author
    // Signatures, Explicit Contradictions, Retraction, Answer Cache & Rebuild!
    // -----------------------------------------------------------------------
    let scope = "ppa1/v170-live";
    let author_sk = SigningKey::from_bytes(&[0x55u8; 32]);
    let author_pk_hex = hex::encode(author_sk.verifying_key().to_bytes());

    // 1A. Client-signed Intent Object -> seq 2 (`acta:evidence_event:v3`)
    let obj_body = json!({"policy": "Quote only verified active supplier lead times"});
    let obj_intent_digest = compute_object_client_intent_hash(
        &tenant_id,
        ObjectType::Intent,
        scope,
        LifecycleStatus::Active,
        95,
        0.9,
        &["procurement".to_string()],
        &obj_body,
        None,
    )
    .unwrap();
    let obj_sig_hex = hex::encode(author_sk.sign(&obj_intent_digest).to_bytes());

    let ing_obj = mcp_rpc(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 95,
            "importance": 0.9,
            "tags": ["procurement"],
            "body": obj_body,
            "client_signature_hex": obj_sig_hex,
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(ing_obj["result"]["isError"], json!(false));
    let obj_sc = &ing_obj["result"]["structuredContent"];
    assert_eq!(obj_sc["evidence_seq_num"], json!(2));
    assert_eq!(obj_sc["client_public_key_hex"], json!(author_pk_hex));

    // 1B. Forged client signature on ingest_claim MUST fail & append refusal at seq 3!
    let bad_ing = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.92,
            "source_descriptor": "apex-portal",
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(bad_ing["result"]["isError"], json!(true));
    assert!(bad_ing["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("seq_num=3"));

    // 1C. Valid client-signed Claim 1 (`lead_days = 14`, conf 0.92) -> seq 4
    let src1_text = "Apex Quote #401: lead_days = 14";
    let src1_comm = compute_source_content_commitment("apex-quote-401", src1_text.as_bytes());
    let vf = (Utc::now() - chrono::Duration::hours(2)).trunc_subsecs(6);
    let vt = (Utc::now() + chrono::Duration::days(60)).trunc_subsecs(6);
    let c1_digest = compute_claim_client_intent_hash(
        &tenant_id,
        scope,
        "supplier:apex",
        "lead_days",
        &json!(14),
        "int",
        0.92,
        1,
        "apex-quote-401",
        &src1_comm,
        LifecycleStatus::Active,
        &[],
        Some(vf),
        Some(vt),
        None,
    )
    .unwrap();
    let c1_sig_hex = hex::encode(author_sk.sign(&c1_digest).to_bytes());

    let ing_c1 = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.92,
            "source_provenance_class": 1,
            "source_descriptor": "apex-quote-401",
            "source_content": src1_text,
            "valid_from": vf.to_rfc3339(),
            "valid_to": vt.to_rfc3339(),
            "client_signature_hex": c1_sig_hex,
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(ing_c1["result"]["isError"], json!(false));
    let claim1_id_str = ing_c1["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let claim1_uuid = Uuid::parse_str(&claim1_id_str).unwrap();
    assert_eq!(ing_c1["result"]["structuredContent"]["evidence_seq_num"], json!(4));

    // 1D. Compile Bundle B1 (`lead_days = 14` resolved as [FACT]) -> seq 5
    let comp_b1 = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    assert_eq!(comp_b1["result"]["isError"], json!(false));
    let b1_sc = &comp_b1["result"]["structuredContent"];
    let b1_hash = b1_sc["bundle_hash"].as_str().unwrap().to_string();
    let b1_state_comm = b1_sc["bundle"]["state_commitment"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(b1_sc["context_text"].as_str().unwrap().contains("[FACT "));

    // Verify B1 in BOTH `full` and `merkle` modes (`write_entry_proofs` proves seq 2 & seq 4!)
    let ver_b1_merkle = mcp_rpc(
        &app,
        &token,
        "acta_verify_bundle",
        json!({
            "bundle_hash": b1_hash,
            "proof_mode": "merkle"
        }),
    )
    .await;
    assert_eq!(ver_b1_merkle["result"]["isError"], json!(false));
    assert_eq!(
        ver_b1_merkle["result"]["structuredContent"]["summary"]["verified_writes"],
        json!(2)
    );

    // -----------------------------------------------------------------------
    // Phase 2: PPA 1 Claims 19–27 State-Conditioned Answer Cache
    // -----------------------------------------------------------------------
    let miss_res = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    assert_eq!(miss_res["result"]["structuredContent"]["cache_hit"], json!(false));
    assert_eq!(
        miss_res["result"]["structuredContent"]["status"],
        json!("miss_not_found")
    );

    // Cache client-signed answer against B1 -> seq 6 (`AnswerCacheLedgerSummary`)
    let answer_txt = "Apex supplier lead time is 14 days per Quote #401.";
    let q_hash = compute_query_text_hash("What is supplier:apex lead_days?");
    let a_hash = compute_answer_text_hash(answer_txt);
    let b1_hash_bytes: [u8; 32] = hex::decode(&b1_hash).unwrap().try_into().unwrap();
    let b1_sc_bytes: [u8; 32] = hex::decode(&b1_state_comm).unwrap().try_into().unwrap();
    let ans_intent = compute_answer_cache_client_intent_hash(
        &tenant_id,
        scope,
        "quote-bot",
        &q_hash,
        &b1_hash_bytes,
        &b1_sc_bytes,
        &a_hash,
    );
    let ans_sig_hex = hex::encode(author_sk.sign(&ans_intent).to_bytes());

    let cache_res = mcp_rpc(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "What is supplier:apex lead_days?",
            "answer_text": answer_txt,
            "answer_metadata": {"model": "claude-opus-4-6"},
            "ttl_seconds": 3600,
            "client_signature_hex": ans_sig_hex,
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(cache_res["result"]["isError"], json!(false));
    assert_eq!(
        cache_res["result"]["structuredContent"]["receipt"]["evidence_seq_num"],
        json!(6)
    );

    // Lookup while state_commitment matches -> HIT!
    let hit_res = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    assert_eq!(hit_res["result"]["structuredContent"]["cache_hit"], json!(true));
    assert_eq!(hit_res["result"]["structuredContent"]["status"], json!("hit"));
    assert_eq!(
        hit_res["result"]["structuredContent"]["answer_text"],
        json!(answer_txt)
    );
    assert_eq!(
        hit_res["result"]["structuredContent"]["answer_hash_verified"],
        json!(true)
    );

    // Policy-Before-Read check on restricted/* lookup -> policy_escalated + logged at seq 7!
    let pol_lookup = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": "restricted/secret-cache",
            "task_id": "quote-bot",
            "query_text": "probe"
        }),
    )
    .await;
    assert_eq!(
        pol_lookup["result"]["structuredContent"]["cache_hit"],
        json!(false)
    );
    assert_eq!(
        pol_lookup["result"]["structuredContent"]["status"],
        json!("policy_escalated")
    );

    // -----------------------------------------------------------------------
    // Phase 3: Explicit Contradiction -> Stale Cache Invalidation -> Retraction!
    // -----------------------------------------------------------------------
    // Ingest Claim 2 (`lead_days = 28`, conf 0.65 — normally wouldn't block 0.92 by margin,
    // EXCEPT `contradiction_ids: [claim1_id]` forces EXPLICIT_CONTRADICTION!) -> seq 8
    let ing_c2 = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:apex",
            "predicate": "lead_days",
            "object_val": 28,
            "object_type": "int",
            "confidence": 0.72,
            "source_provenance_class": 2,
            "source_descriptor": "logistics-notice-9",
            "contradiction_ids": [claim1_id_str],
        }),
    )
    .await;
    assert_eq!(ing_c2["result"]["isError"], json!(false));

    // O(1) Answer Cache Lookup MUST now automatically invalidate (`stale_state_commitment`)!
    let stale_res = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    assert_eq!(stale_res["result"]["structuredContent"]["cache_hit"], json!(false));
    assert_eq!(
        stale_res["result"]["structuredContent"]["status"],
        json!("stale_dependency_commitment")
    );
    assert_eq!(
        stale_res["result"]["structuredContent"]["state_commitment_matches"],
        json!(false)
    );
    assert_eq!(
        stale_res["result"]["structuredContent"]["invalidation_newly_recorded"],
        json!(true)
    );

    // Compile Bundle B2 -> MUST surface `[DISPUTE: BLOCKING_CONTRADICTION]`!
    let comp_b2 = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    let b2_sc = &comp_b2["result"]["structuredContent"];
    let b2_hash = b2_sc["bundle_hash"].as_str().unwrap().to_string();
    assert!(b2_sc["context_text"]
        .as_str()
        .unwrap()
        .contains("[DISPUTE: BLOCKING_CONTRADICTION]"));

    // Now client-signed `acta_retract_claim` on `claim1_uuid` -> appends `status='revoked'` tombstone!
    let ret_reason = "Quote #401 withdrawn after port delay notice";
    let ret_digest = compute_retract_claim_client_intent_hash(&tenant_id, claim1_uuid, ret_reason);
    let ret_sig_hex = hex::encode(author_sk.sign(&ret_digest).to_bytes());
    let ret_res = mcp_rpc(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "claim_id": claim1_id_str,
            "reason": ret_reason,
            "client_signature_hex": ret_sig_hex,
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(ret_res["result"]["isError"], json!(false));
    let ret_sc = &ret_res["result"]["structuredContent"];
    assert_eq!(ret_sc["status"], json!("revoked"));
    assert_eq!(ret_sc["version"], json!(2));
    let tombstone_id = ret_sc["tombstone_id"].as_str().unwrap().to_string();

    // Compile Bundle B3 -> Claim 1 is retracted, so Claim 2's contradiction edge clears and `28` resolves as [FACT]!
    let comp_b3 = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "quote-bot",
            "query_text": "What is supplier:apex lead_days?"
        }),
    )
    .await;
    let b3_sc = &comp_b3["result"]["structuredContent"];
    let b3_ctx = b3_sc["context_text"].as_str().unwrap();
    assert!(
        !b3_ctx.contains("[DISPUTE"),
        "contradiction_ids to retracted claim must clear: {b3_ctx}"
    );
    assert!(b3_ctx.contains("28"));

    // -----------------------------------------------------------------------
    // Phase 4: Indexed Reverse Decision Recall (`acta_trace_claim_impact`)
    // & Ledger-Alone State Reconstruction (`acta_verify_state_rebuild`)!
    // -----------------------------------------------------------------------
    let trace_res = mcp_rpc(
        &app,
        &token,
        "acta_trace_claim_impact",
        json!({ "item_id": claim1_id_str }),
    )
    .await;
    assert_eq!(trace_res["result"]["isError"], json!(false));
    let tr = &trace_res["result"]["structuredContent"];
    assert_eq!(tr["lifecycle_state"], json!("retracted"));
    assert_eq!(tr["retracted_by_id"], json!(tombstone_id));
    assert_eq!(tr["retraction_reason"], json!(ret_reason));
    assert_eq!(tr["impacted_bundle_count"], json!(2)); // B1 (winning_fact) + B2 (disputed_candidate)
    assert_eq!(tr["stale_bundle_count"], json!(2));
    let impacted_hashes: Vec<&str> = tr["impacted_bundles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["bundle_hash"].as_str().unwrap())
        .collect();
    assert!(impacted_hashes.contains(&b1_hash.as_str()));
    assert!(impacted_hashes.contains(&b2_hash.as_str()));
    assert!(tr["impacted_bundles"]
        .as_array()
        .unwrap()
        .iter()
        .all(|b| b["is_stale_now"] == json!(true)));
    assert_eq!(tr["impacted_cached_answer_count"], json!(1));
    assert_eq!(
        tr["impacted_cached_answers"][0]["invalidated_by_state_change"],
        json!(true)
    );

    // Verify full ledger-alone state rebuild on `ppa1/v170-live` matches live PostgreSQL bit-for-bit!
    let rebuild_res = mcp_rpc(
        &app,
        &token,
        "acta_verify_state_rebuild",
        json!({ "scope": scope }),
    )
    .await;
    assert_eq!(rebuild_res["result"]["isError"], json!(false));
    let rb = &rebuild_res["result"]["structuredContent"];
    assert_eq!(rb["legacy_pre_v17_unchained_objects"], json!(0));
    assert_eq!(rb["legacy_pre_v17_unchained_claims"], json!(0));
    assert_eq!(rb["chain_cryptographically_verified"], json!(true));
    assert_eq!(rb["matches_live_store_bit_for_bit"], json!(true));
    assert_eq!(
        rb["reconstructed_state_commitment"],
        rb["live_store_state_commitment"]
    );
    assert_eq!(rb["reconstructed_active_intents"], json!(1));
    assert_eq!(rb["reconstructed_active_claims"], json!(1)); // Only Claim 2 (28) remains active!
    assert_eq!(rb["reconstructed_superseded_or_retracted_items"], json!(2)); // Claim 1 + its revoked tombstone

    // Also verify prefix state rebuild at `up_to_seq = 5` (when Claim 1 was active and Claim 2 didn't exist yet!)
    let rebuild_at_5 = mcp_rpc(
        &app,
        &token,
        "acta_verify_state_rebuild",
        json!({ "scope": scope, "up_to_seq": 5 }),
    )
    .await;
    let rb5 = &rebuild_at_5["result"]["structuredContent"];
    assert_eq!(rb5["reconstructed_state_commitment"], json!(b1_state_comm));
    assert_eq!(rb5["reconstructed_active_claims"], json!(1));
    assert_eq!(rb5["reconstructed_superseded_or_retracted_items"], json!(0));

    // Verify whole tenant chain cryptographically
    let chain = evidence_repo::fetch_tenant_evidence_chain(&pool, &tenant_id, None)
        .await
        .unwrap();
    let vk = host_key.verifying_key();
    for entry in &chain {
        acta_crypto::verify_single_evidence_entry_public(entry, &tenant_id, &vk).unwrap();
    }

    // Export B3 and verify via `verify_export_archive`
    let exp_res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/bundles/{}/export",
                    b3_sc["bundle_hash"].as_str().unwrap()
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp_res.status(), StatusCode::OK);
    let b3_arch: ExportArchive =
        serde_json::from_slice(&exp_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let b3_sum = verify_export_archive(&b3_arch, &vk.to_bytes()).unwrap();
    assert!(b3_sum.verified_writes >= 4);
    assert_eq!(b3_sum.verified_answer_caches, 2);

    let _ = CompileResponse {
        policy_decision: acta_types::PolicyDecision::Allow,
        context_text: None,
        context_token_count: None,
        context_token_ids: None,
        context_token_bytes_hex: None,
        resolved_facts_omitted: None,
        bundle_hash: None,
        bundle: None,
        evidence: chain[0].clone(),
    };
}
