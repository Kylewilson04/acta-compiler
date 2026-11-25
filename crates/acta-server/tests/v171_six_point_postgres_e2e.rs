use std::collections::BTreeMap;
use std::sync::Arc;

use acta_crypto::{
    mint_user_tenant_api_key, sign_witness_anchor, verify_and_rebuild_scope_state_offline,
};
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{routes::build_router, state::AppState};
use acta_store::pool::{create_pool, run_migrations};
use acta_types::StateRebuildArchive;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn mcp_rpc(app: &axum::Router, bearer: &str, tool: &str, args: Value) -> Value {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args
        }
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn test_v171_all_six_open_items_and_offline_rebuild_e2e() {
    let Ok(db_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping v1.7.1 PostgreSQL E2E test: DATABASE_URL not set");
        return;
    };

    let pool = create_pool(&db_url, 12).await.unwrap();
    run_migrations(&pool).await.unwrap();

    let host_key = SigningKey::from_bytes(&[0x71; 32]);
    let host_pk = host_key.verifying_key().to_bytes();
    let master_key = "test-master-v171-secret";
    let policy_path = format!("{}/../../policies/default.cedar", env!("CARGO_MANIFEST_DIR"));
    let policy_gate = Arc::new(PolicyGate::from_file(&policy_path, BTreeMap::new()).unwrap());

    let state = AppState::new(
        pool.clone(),
        policy_gate,
        Arc::new(host_key),
        PipelineConfig::default(),
    )
    .with_auth(Some(master_key.to_string()), "public-".to_string());
    let app = build_router(state);

    let tenant_id = format!("v171-audit-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let token = mint_user_tenant_api_key(master_key, &tenant_id, "kylewilson04").unwrap();
    let scope = "acta-test/v171-six-point";

    // 0. Check acta_whoami -> version 1.7.1
    let who0 = mcp_rpc(&app, &token, "acta_whoami", json!({})).await;
    assert_eq!(who0["result"]["structuredContent"]["version"], json!("1.7.3"));
    assert_eq!(who0["result"]["structuredContent"]["head_witnessed"], json!(false));

    // =========================================================================
    // ITEM 1: Post-corroboration `min_confidence` (0.60 + 0.60 -> 0.72 >= 0.70)
    // =========================================================================
    let c_60_a = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.60,
            "source_provenance_class": 2,
            "source_descriptor": "erp-feed-east",
        }),
    )
    .await;
    assert_eq!(c_60_a["result"]["isError"], json!(false));

    let c_60_b = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.60,
            "source_provenance_class": 2,
            "source_descriptor": "carrier-edi-west",
        }),
    )
    .await;
    assert_eq!(c_60_b["result"]["isError"], json!(false));

    let comp_1 = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "What is supplier:titan lead_days?",
        }),
    )
    .await;
    let b1_sc = &comp_1["result"]["structuredContent"];
    let b1_ctx = b1_sc["context_text"].as_str().unwrap();
    let b1_hash = b1_sc["bundle_hash"].as_str().unwrap().to_string();
    assert!(
        !b1_ctx.contains("[DISPUTE"),
        "two agreeing 0.60 independent sources must corroborate to 0.72 and resolve: {b1_ctx}"
    );
    assert!(
        b1_ctx.contains("effective_confidence=0.7200") && b1_ctx.contains("corroborated_by=2"),
        "context_text must surface corroborated 0.7200: {b1_ctx}"
    );
    assert_eq!(
        b1_sc["bundle"]["resolution_records"][0]["winning_claim"]["effective_confidence"],
        json!(0.72)
    );

    // =========================================================================
    // ITEM 4 & ITEM 3: Claim 25 Dependency-Scoped Cache Validity + Chained One-Time Invalidation
    // =========================================================================
    let cache_1 = mcp_rpc(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "What is supplier:titan lead_days?",
            "answer_text": "Titan lead time is 14 days (corroborated 0.72 across erp-feed-east and carrier-edi-west).",
            "ttl_seconds": 3600,
        }),
    )
    .await;
    assert_eq!(cache_1["result"]["isError"], json!(false));
    assert_eq!(
        cache_1["result"]["structuredContent"]["receipt"]["validity_mode"],
        json!("dependency_subset")
    );
    let stored_tdc = cache_1["result"]["structuredContent"]["receipt"]["task_dependency_commitment"]
        .as_str()
        .unwrap()
        .to_string();

    // Now ingest an UNRELATED claim AND an UNRELATED memory in the SAME scope!
    let unrel_claim = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "warehouse:phoenix",
            "predicate": "dock_count",
            "object_val": 8,
            "object_type": "int",
            "confidence": 0.91,
            "source_descriptor": "facilities-roster",
        }),
    )
    .await;
    assert_eq!(unrel_claim["result"]["isError"], json!(false));
    let unrel_claim_id = unrel_claim["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let unrel_mem = mcp_rpc(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "memory",
            "scope": scope,
            "importance": 0.7,
            "body": {"note": "Unrelated warehouse dock painting scheduled next month"},
        }),
    )
    .await;
    assert_eq!(unrel_mem["result"]["isError"], json!(false));

    // Lookup cached answer on `supplier:titan / lead_days`:
    // Whole-scope `state_commitment` CHANGED (`state_commitment_matches == false`),
    // YET `task_dependency_commitment` STILL MATCHES (`cache_hit == true`)!
    let hit_after_unrel = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "What is supplier:titan lead_days?",
        }),
    )
    .await;
    let hu = &hit_after_unrel["result"]["structuredContent"];
    assert_eq!(hu["cache_hit"], json!(true), "got: {hu}");
    assert_eq!(hu["status"], json!("hit"));
    assert_eq!(hu["validity_mode"], json!("dependency_subset"));
    assert_eq!(
        hu["state_commitment_matches"],
        json!(false),
        "whole-scope state_commitment must have changed after unrelated writes"
    );
    assert_eq!(hu["task_dependency_commitment_matches"], json!(true));
    assert_eq!(hu["current_task_dependency_commitment"], json!(stored_tdc));

    // =========================================================================
    // ITEM 2: Explicit Retraction Omission Labels (`retracted` + `retraction_tombstone`)
    // =========================================================================
    // Retract the unrelated claim `warehouse:phoenix / dock_count` first (also leaves Titan cache intact!)
    let ret_unrel = mcp_rpc(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "claim_id": unrel_claim_id,
            "reason": "Entered wrong facility dock count",
        }),
    )
    .await;
    assert_eq!(ret_unrel["result"]["isError"], json!(false));
    let tombstone_id = ret_unrel["result"]["structuredContent"]["tombstone_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Also supersede `erp-feed-east` on `supplier:titan / lead_days` -> 21 (which WILL invalidate Titan cache!)
    let sup_titan = mcp_rpc(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 21,
            "object_type": "int",
            "confidence": 0.92,
            "source_provenance_class": 3,
            "source_descriptor": "erp-feed-east",
        }),
    )
    .await;
    assert_eq!(sup_titan["result"]["isError"], json!(false));
    let old_titan_a_id = c_60_a["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Compile B2 -> check `omission_record.inline_items`:
    // - `unrel_claim_id` MUST have `reason == "retracted"`
    // - `tombstone_id` MUST have `reason == "retraction_tombstone"`
    // - `old_titan_a_id` MUST have `reason == "superseded"`
    let comp_2 = mcp_rpc(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "What is supplier:titan lead_days?",
        }),
    )
    .await;
    let b2_sc = &comp_2["result"]["structuredContent"];
    let b2_hash = b2_sc["bundle_hash"].as_str().unwrap().to_string();
    let inline_omissions = b2_sc["bundle"]["omission_record"]["inline_items"]
        .as_array()
        .unwrap();
    let reason_by_id: std::collections::HashMap<String, String> = inline_omissions
        .iter()
        .map(|it| {
            (
                it["id"].as_str().unwrap().to_string(),
                it["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        reason_by_id.get(&unrel_claim_id).map(String::as_str),
        Some("retracted"),
        "retracted claim must be omitted as 'retracted': {reason_by_id:?}"
    );
    assert_eq!(
        reason_by_id.get(&tombstone_id).map(String::as_str),
        Some("retraction_tombstone"),
        "revoked tombstone row must be omitted as 'retraction_tombstone': {reason_by_id:?}"
    );
    assert_eq!(
        reason_by_id.get(&old_titan_a_id).map(String::as_str),
        Some("superseded"),
        "replaced versioned claim must still be omitted as 'superseded': {reason_by_id:?}"
    );

    // Verify counterfactual replay of BOTH B1 (0.60+0.60 corroborated) and B2 (retraction labels) reproduces bit-for-bit!
    for bh in [&b1_hash, &b2_hash] {
        let rep = mcp_rpc(
            &app,
            &token,
            "acta_replay_counterfactual",
            json!({ "source_bundle_hash": bh }),
        )
        .await;
        assert_eq!(
            rep["result"]["structuredContent"]["reproduced_source_bundle_bit_for_bit"],
            json!(true),
            "replay failed for {bh}: {rep}"
        );
    }

    // =========================================================================
    // ITEM 3: One-Time Chained Cache Invalidation Receipt (Idempotent on Repeat Lookups)
    // =========================================================================
    let who_before_inv = mcp_rpc(&app, &token, "acta_whoami", json!({})).await;
    let seq_before_inv = who_before_inv["result"]["structuredContent"]["evidence_entry_count"]
        .as_i64()
        .unwrap();

    // 1st stale lookup -> records ONE chained invalidation entry at `seq_before_inv + 1`!
    let stale_1 = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "What is supplier:titan lead_days?",
        }),
    )
    .await;
    let st1 = &stale_1["result"]["structuredContent"];
    assert_eq!(st1["cache_hit"], json!(false));
    assert_eq!(st1["status"], json!("stale_dependency_commitment"));
    assert_eq!(st1["invalidation_evidence_seq_num"], json!(seq_before_inv + 1));
    assert_eq!(st1["invalidation_newly_recorded"], json!(true));

    // 2nd stale lookup -> idempotent! Same seq_num, `invalidation_newly_recorded == false`, ZERO new chain entries!
    let stale_2 = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "What is supplier:titan lead_days?",
        }),
    )
    .await;
    let st2 = &stale_2["result"]["structuredContent"];
    assert_eq!(st2["cache_hit"], json!(false));
    assert_eq!(st2["invalidation_evidence_seq_num"], json!(seq_before_inv + 1));
    assert_eq!(st2["invalidation_newly_recorded"], json!(false));

    // `miss_not_found` lookup -> ZERO chain entries!
    let miss_res = mcp_rpc(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "Never cached query?",
        }),
    )
    .await;
    assert_eq!(
        miss_res["result"]["structuredContent"]["status"],
        json!("miss_not_found")
    );
    let who_after_inv = mcp_rpc(&app, &token, "acta_whoami", json!({})).await;
    assert_eq!(
        who_after_inv["result"]["structuredContent"]["evidence_entry_count"],
        json!(seq_before_inv + 1),
        "repeat stale lookup and miss_not_found must add zero extra chain entries"
    );

    // =========================================================================
    // ITEM 5: `latest_anchored_checkpoint` Visibility When Head Moves Ahead of Witness
    // =========================================================================
    let wit_sk = SigningKey::from_bytes(&[0x88; 32]);
    let wit_pk_hex = hex::encode(wit_sk.verifying_key().to_bytes());
    let reg_w = mcp_rpc(
        &app,
        &token,
        "acta_register_witness",
        json!({
            "witness_id": "audit-witness-v171",
            "witness_public_key_hex": wit_pk_hex,
            "description": "v1.7.1 Witness",
        }),
    )
    .await;
    assert_eq!(reg_w["result"]["isError"], json!(false));

    let cp_at_m = mcp_rpc(&app, &token, "acta_get_checkpoint", json!({})).await;
    let m_size = cp_at_m["result"]["structuredContent"]["tree_size"]
        .as_i64()
        .unwrap();
    let m_cp_hash_hex = cp_at_m["result"]["structuredContent"]["checkpoint"]["checkpoint_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let m_cp_bytes: [u8; 32] = hex::decode(&m_cp_hash_hex).unwrap().try_into().unwrap();
    let w_sig = sign_witness_anchor(&wit_sk, &tenant_id, m_size, &m_cp_bytes);

    let anch_res = mcp_rpc(
        &app,
        &token,
        "acta_anchor_checkpoint",
        json!({
            "tree_size": m_size,
            "checkpoint_hash": m_cp_hash_hex,
            "witness_id": "audit-witness-v171",
            "witness_public_key_hex": wit_pk_hex,
            "witness_signature_hex": hex::encode(w_sig),
        }),
    )
    .await;
    assert_eq!(anch_res["result"]["isError"], json!(false));

    // At tree_size == M, head IS witnessed!
    let cp_witnessed = mcp_rpc(&app, &token, "acta_get_checkpoint", json!({})).await;
    assert_eq!(
        cp_witnessed["result"]["structuredContent"]["head_witnessed"],
        json!(true)
    );
    assert_eq!(
        cp_witnessed["result"]["structuredContent"]["latest_anchored_checkpoint"]["tree_size"],
        json!(m_size)
    );

    // Append one more object write so head advances to M + 1 (unwitnessed head, witnessed prefix at M!)
    let post_anchor_obj = mcp_rpc(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 90,
            "body": {"directive": "Verify supplier lead times via dual-source corroboration"},
        }),
    )
    .await;
    assert_eq!(post_anchor_obj["result"]["isError"], json!(false));

    let cp_unwit_head = mcp_rpc(&app, &token, "acta_get_checkpoint", json!({})).await;
    let cp_uh = &cp_unwit_head["result"]["structuredContent"];
    assert_eq!(cp_uh["tree_size"], json!(m_size + 1));
    assert_eq!(cp_uh["head_witnessed"], json!(false));
    assert_eq!(cp_uh["latest_anchored_checkpoint"]["tree_size"], json!(m_size));
    assert_eq!(cp_uh["latest_anchor_consistency_verified"], json!(true));
    assert!(
        !cp_uh["consistency_proof_from_latest_anchor"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let who_final = mcp_rpc(&app, &token, "acta_whoami", json!({})).await;
    assert_eq!(
        who_final["result"]["structuredContent"]["head_witnessed"],
        json!(false)
    );
    assert_eq!(
        who_final["result"]["structuredContent"]["latest_anchored_checkpoint"]["tree_size"],
        json!(m_size)
    );

    // =========================================================================
    // ITEM 6: Standalone Offline `StateRebuildArchive` Verification & Reconstruction
    // =========================================================================
    let rb_res = mcp_rpc(
        &app,
        &token,
        "acta_verify_state_rebuild",
        json!({
            "scope": scope,
            "include_proof_archive": true,
        }),
    )
    .await;
    assert_eq!(rb_res["result"]["isError"], json!(false));
    let rb_sc = &rb_res["result"]["structuredContent"];
    assert_eq!(rb_sc["matches_live_store_bit_for_bit"], json!(true));
    assert_eq!(rb_sc["latest_anchored_tree_size"], json!(m_size));

    let proof_archive: StateRebuildArchive =
        serde_json::from_value(rb_sc["rebuild_proof_archive"].clone()).unwrap();
    let offline_summary =
        verify_and_rebuild_scope_state_offline(&proof_archive, &host_pk, None).unwrap();
    assert_eq!(
        offline_summary.reconstructed_state_commitment_hex,
        rb_sc["live_store_state_commitment"].as_str().unwrap()
    );
    assert_eq!(offline_summary.anchored_tree_size, Some(m_size));
    assert_eq!(offline_summary.verified_witness_anchors, 1);

    // Adversarial tamper check: modifying an active claim value inside write_summary MUST fail offline rebuild!
    let mut tampered = proof_archive.clone();
    for ev in &mut tampered.evidence_chain {
        if let Some(ref mut ws) = ev.write_summary {
            ws.record_snapshot["object_val"] = json!(9999);
            break;
        }
    }
    assert!(
        verify_and_rebuild_scope_state_offline(&tampered, &host_pk, None).is_err(),
        "tampered write_summary snapshot must fail offline verification"
    );
}
