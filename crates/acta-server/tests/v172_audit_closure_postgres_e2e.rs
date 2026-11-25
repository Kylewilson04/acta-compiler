use std::collections::BTreeMap;
use std::sync::Arc;

use acta_crypto::{
    compute_answer_cache_client_intent_hash, compute_answer_text_hash,
    compute_object_client_intent_hash, compute_query_text_hash, compute_state_commitment,
    compute_sub_commitment, hash_length_delimited, mint_user_tenant_api_key, sign_witness_anchor,
    verify_and_rebuild_scope_state_offline, verify_export_archive,
};
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{routes::build_router, state::AppState};
use acta_store::pool::{create_pool, run_migrations};
use acta_types::{ExportArchive, LifecycleStatus, ObjectType, StateRebuildArchive, SCHEMA_VERSION};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use chrono::{Duration, SubsecRound, Utc};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn mcp_call_raw(app: &Router, bearer: &str, method: &str, params: Value) -> (axum::http::HeaderMap, Value) {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
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
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (headers, serde_json::from_slice(&bytes).unwrap())
}

async fn mcp_tool(app: &Router, bearer: &str, tool: &str, args: Value) -> Value {
    let (_h, body) = mcp_call_raw(
        app,
        bearer,
        "tools/call",
        json!({ "name": tool, "arguments": args }),
    )
    .await;
    body
}

/// Independent implementation written strictly from SPEC.md §2.5 (Must-Fix 1).
fn spec_s25_sub_commitment(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = hashes.to_vec();
    sorted.sort_unstable();
    let slices: Vec<&[u8]> = sorted.iter().map(|h| h.as_slice()).collect();
    hash_length_delimited(&slices)
}

fn spec_s25_state_commitment(
    schema_version: &str,
    tenant_id: &str,
    scope: &str,
    intent_root: &[u8; 32],
    knowledge_root: &[u8; 32],
    memory_root: &[u8; 32],
    permission_root: &[u8; 32],
) -> [u8; 32] {
    if schema_version == "acta-context-bundle/v2" {
        hash_length_delimited(&[
            b"acta:state:v2",
            schema_version.as_bytes(),
            tenant_id.as_bytes(),
            scope.as_bytes(),
            intent_root,
            knowledge_root,
            memory_root,
            permission_root,
        ])
    } else {
        hash_length_delimited(&[
            schema_version.as_bytes(),
            tenant_id.as_bytes(),
            scope.as_bytes(),
            intent_root,
            knowledge_root,
            memory_root,
            permission_root,
        ])
    }
}

#[tokio::test]
async fn test_v172_all_must_fixes_should_fixes_and_seven_audit_probes_e2e() {
    let Ok(db_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping v1.7.2 PostgreSQL E2E test: DATABASE_URL not set");
        return;
    };

    let pool = create_pool(&db_url, 16).await.unwrap();
    run_migrations(&pool).await.unwrap();

    let host_key = SigningKey::from_bytes(&[0x72; 32]);
    let host_pk = host_key.verifying_key().to_bytes();
    let host_pk_hex = hex::encode(host_pk);
    let master_key = "test-master-v172-secret";
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

    let tenant_id = format!("v172-audit-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let token = mint_user_tenant_api_key(master_key, &tenant_id, "kylewilson04").unwrap();
    let scope = "acta-test/v172-audit";

    let author_sk = SigningKey::from_bytes(&[0xA1; 32]);
    let author_pk_hex = hex::encode(author_sk.verifying_key().to_bytes());

    // =========================================================================
    // MUST-FIX 1: SPEC.md §2.5 Exact Layout Parity
    // =========================================================================
    let empty_sub = spec_s25_sub_commitment(&[]);
    assert_eq!(
        hex::encode(empty_sub),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(empty_sub, compute_sub_commitment(&[]));

    // =========================================================================
    // SHOULD-FIX 9: MCP Schema Refresh, listChanged & GET /mcp SSE Stream
    // =========================================================================
    let (init_headers, init_rpc) = mcp_call_raw(
        &app,
        &token,
        "initialize",
        json!({"protocolVersion": "2025-06-18"}),
    )
    .await;
    assert_eq!(
        init_headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        init_rpc["result"]["serverInfo"]["version"],
        json!("1.7.3")
    );
    assert_eq!(
        init_rpc["result"]["capabilities"]["tools"]["listChanged"],
        json!(true)
    );

    let sse_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    assert!(
        sse_resp
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("no-store")
    );
    let sse_text = String::from_utf8(
        sse_resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(
        sse_text.contains("notifications/tools/list_changed"),
        "GET /mcp SSE must emit notifications/tools/list_changed: {sse_text}"
    );

    let (_tl_h, tools_list) = mcp_call_raw(&app, &token, "tools/list", json!({})).await;
    let tools_arr = tools_list["result"]["tools"].as_array().unwrap();
    let schema_by_name: std::collections::HashMap<String, Value> = tools_arr
        .iter()
        .map(|t| (t["name"].as_str().unwrap().to_string(), t["inputSchema"].clone()))
        .collect();
    assert!(schema_by_name["acta_cache_answer"]["properties"].get("validity_mode").is_some());
    assert!(schema_by_name["acta_cache_answer"]["properties"].get("dependency_ids").is_some());
    assert!(schema_by_name["acta_verify_state_rebuild"]["properties"].get("include_proof_archive").is_some());
    assert!(schema_by_name["acta_retract_claim"]["properties"].get("scope").is_some());
    assert_eq!(
        schema_by_name["acta_ingest_object"]["properties"]["lifecycle_status"]["enum"],
        json!(["active", "revoked", "expired", "superseded"])
    );
    assert_eq!(
        schema_by_name["acta_ingest_claim"]["properties"]["status"]["enum"],
        json!(["active", "revoked", "expired", "superseded"])
    );

    // =========================================================================
    // SHOULD-FIX 1 & 2: Specific Signature Refusal Codes + expected_intent_digest_hex
    // =========================================================================
    // 1. Forged signature on ingest_object -> returns invalid_object_client_signature + expected_intent_digest_hex!
    let intent_body = json!({"directive": "Verify corroborated lead times before issuing PO"});
    let forged_obj = mcp_tool(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 90,
            "importance": 1.0,
            "tags": ["v172"],
            "body": intent_body,
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(forged_obj["result"]["isError"], json!(true));
    assert_eq!(
        forged_obj["result"]["structuredContent"]["reason_code"],
        json!("invalid_object_client_signature")
    );
    assert_eq!(
        forged_obj["result"]["structuredContent"]["signing_domain"],
        json!("acta:object_client_sig:v1")
    );
    let returned_obj_digest_hex = forged_obj["result"]["structuredContent"]["expected_intent_digest_hex"]
        .as_str()
        .unwrap()
        .to_string();
    let local_obj_digest = compute_object_client_intent_hash(
        &tenant_id,
        ObjectType::Intent,
        scope,
        LifecycleStatus::Active,
        90,
        1.0,
        &["v172".to_string()],
        &intent_body,
        None,
    )
    .unwrap();
    assert_eq!(returned_obj_digest_hex, hex::encode(local_obj_digest));

    // Sign using the returned expected_intent_digest_hex directly -> succeeds!
    let obj_sig_hex = hex::encode(author_sk.sign(&local_obj_digest).to_bytes());
    let ing_obj_1 = mcp_tool(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 90,
            "importance": 1.0,
            "tags": ["v172"],
            "body": intent_body,
            "client_signature_hex": obj_sig_hex,
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(ing_obj_1["result"]["isError"], json!(false));
    let obj_1_id = ing_obj_1["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // PROBE 6: Signed object with predecessor_id + lifecycle_status: "revoked"
    let rev_obj_body = json!({"directive": "Revoked intent predecessor"});
    let rev_obj_digest = compute_object_client_intent_hash(
        &tenant_id,
        ObjectType::Intent,
        scope,
        LifecycleStatus::Revoked,
        90,
        1.0,
        &["v172".to_string()],
        &rev_obj_body,
        Some(Uuid::parse_str(&obj_1_id).unwrap()),
    )
    .unwrap();
    let rev_obj_res = mcp_tool(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "lifecycle_status": "revoked",
            "priority": 90,
            "importance": 1.0,
            "tags": ["v172"],
            "body": rev_obj_body,
            "predecessor_id": obj_1_id,
            "client_signature_hex": hex::encode(author_sk.sign(&rev_obj_digest).to_bytes()),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(
        rev_obj_res["result"]["isError"],
        json!(false),
        "signed revoked object with predecessor_id must succeed: {rev_obj_res}"
    );
    assert_eq!(rev_obj_res["result"]["structuredContent"]["version"], json!(2));

    // Re-ingest an active intent for downstream compile checks
    let active_intent_body = json!({"directive": "Pool agreeing independent supplier sources"});
    let active_intent_res = mcp_tool(
        &app,
        &token,
        "acta_ingest_object",
        json!({
            "obj_type": "intent",
            "scope": scope,
            "priority": 95,
            "importance": 1.0,
            "tags": ["v172"],
            "body": active_intent_body,
        }),
    )
    .await;
    assert_eq!(active_intent_res["result"]["isError"], json!(false));

    // Forged signature on ingest_claim -> invalid_claim_client_signature
    let forged_clm = mcp_tool(
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
            "source_descriptor": "erp-feed-a",
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(forged_clm["result"]["isError"], json!(true));
    assert_eq!(
        forged_clm["result"]["structuredContent"]["reason_code"],
        json!("invalid_claim_client_signature")
    );
    assert_eq!(
        forged_clm["result"]["structuredContent"]["signing_domain"],
        json!("acta:claim_client_sig:v1")
    );
    let clm_a_digest_bytes: [u8; 32] = hex::decode(
        forged_clm["result"]["structuredContent"]["expected_intent_digest_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();

    // =========================================================================
    // MUST-FIX 2: Corroborating Claims in Bundle Proof (0.60 + 0.60 -> 0.72)
    // =========================================================================
    let valid_to_future = (Utc::now() + Duration::days(30)).trunc_subsecs(6);
    let clm_a = mcp_tool(
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
            "source_descriptor": "erp-feed-a",
            "client_signature_hex": hex::encode(author_sk.sign(&clm_a_digest_bytes).to_bytes()),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(clm_a["result"]["isError"], json!(false), "got: {clm_a}");
    let clm_a_id = clm_a["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let clm_b = mcp_tool(
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
            "source_descriptor": "carrier-bol-b",
            "valid_to": valid_to_future.to_rfc3339(),
        }),
    )
    .await;
    assert_eq!(clm_b["result"]["isError"], json!(false));
    let clm_b_id = clm_b["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let comp_b1 = mcp_tool(
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
    assert_eq!(comp_b1["result"]["isError"], json!(false));
    let b1_hash = comp_b1["result"]["structuredContent"]["bundle_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let b1_state_comm = comp_b1["result"]["structuredContent"]["bundle"]["state_commitment"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        comp_b1["result"]["structuredContent"]["bundle"]["resolution_records"][0]["winning_claim"]["effective_confidence"],
        json!(0.72)
    );

    // Verify B1 via acta_verify_bundle in BOTH merkle and full modes -> verified_claims == 2!
    for mode in ["merkle", "full"] {
        let ver_b1 = mcp_tool(
            &app,
            &token,
            "acta_verify_bundle",
            json!({ "bundle_hash": b1_hash, "proof_mode": mode }),
        )
        .await;
        assert_eq!(ver_b1["result"]["isError"], json!(false), "mode={mode}: {ver_b1}");
        let vsum = &ver_b1["result"]["structuredContent"]["summary"];
        assert_eq!(
            vsum["verified_claims"],
            json!(2),
            "Must-Fix 2: both corroborating claims must be proven in {mode} archive: {vsum}"
        );
        assert_eq!(vsum["verified_corroborated_resolutions"], json!(1));
    }

    // Export B1 merkle archive to /tmp for 3-way CLI/Python/TS parity check AND verify stripping claim 2 fails!
    let exp_b1_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/bundles/{b1_hash}/export?mode=merkle"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp_b1_resp.status(), StatusCode::OK);
    let exp_b1_bytes = exp_b1_resp.into_body().collect().await.unwrap().to_bytes();
    std::fs::write("/tmp/acta_v172_e2e_export.json", &exp_b1_bytes).unwrap();
    std::fs::write("/tmp/acta_v172_e2e_pubkey.txt", &host_pk_hex).unwrap();

    let mut parsed_exp: ExportArchive = serde_json::from_slice(&exp_b1_bytes).unwrap();
    let ok_exp_sum = verify_export_archive(&parsed_exp, &host_pk).unwrap();
    assert_eq!(ok_exp_sum.verified_claims, 2);
    assert_eq!(ok_exp_sum.verified_corroborated_resolutions, 1);
    parsed_exp.claims.retain(|c| c.id.to_string() == clm_a_id);
    assert!(
        verify_export_archive(&parsed_exp, &host_pk).is_err(),
        "stripping corroborating claim from archive.claims must fail verification"
    );

    // =========================================================================
    // PROBE 2, PROBE 3, PROBE 4, PROBE 7c & MUST-FIX 3 + SHOULD-FIX 3
    // =========================================================================
    // Probe 7c: cache_answer against bundle with mismatched task_id -> refused (`bundle_task_mismatch`)!
    let bad_task_cache = mcp_tool(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "task_id": "different-task-id",
            "query_text": "What is supplier:titan lead_days?",
            "answer_text": "14 days",
        }),
    )
    .await;
    assert_eq!(bad_task_cache["result"]["isError"], json!(true));
    assert_eq!(
        bad_task_cache["result"]["structuredContent"]["reason_code"],
        json!("bundle_task_mismatch")
    );

    // Forged signature on cache_answer -> invalid_answer_client_signature + expected_intent_digest_hex
    let forged_ans = mcp_tool(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": "What is supplier:titan lead_days?",
            "answer_text": "14 days (client-signed)",
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(forged_ans["result"]["isError"], json!(true));
    assert_eq!(
        forged_ans["result"]["structuredContent"]["reason_code"],
        json!("invalid_answer_client_signature")
    );

    // Cache Entry C_pin: narrowed `dependency_ids: [clm_a_id]` (Probe 3!) AND client-signed (`ed25519_client_sig`)!
    let q_pin = "Pinned to erp-feed-a only?";
    let a_pin = "14 days per erp-feed-a";
    let pin_intent = compute_answer_cache_client_intent_hash(
        &tenant_id,
        scope,
        "po-check",
        &compute_query_text_hash(q_pin),
        &hex::decode(&b1_hash).unwrap().try_into().unwrap(),
        &hex::decode(&b1_state_comm).unwrap().try_into().unwrap(),
        &compute_answer_text_hash(a_pin),
    );
    let cache_pin = mcp_tool(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": q_pin,
            "answer_text": a_pin,
            "validity_mode": "dependency_subset",
            "dependency_ids": [clm_a_id],
            "client_signature_hex": hex::encode(author_sk.sign(&pin_intent).to_bytes()),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(cache_pin["result"]["isError"], json!(false), "got: {cache_pin}");

    // Cache Entry C_scope_root: `validity_mode: "scope_root"` (Probe 2!)
    let q_sr = "Whole-scope sensitive query?";
    let cache_sr = mcp_tool(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": q_sr,
            "answer_text": "Whole-scope answer",
            "validity_mode": "scope_root",
        }),
    )
    .await;
    assert_eq!(cache_sr["result"]["isError"], json!(false));

    // Cache Entry C_ttl: `ttl_seconds: 1` (Probe 4!)
    let q_ttl = "Short TTL query?";
    let cache_ttl = mcp_tool(
        &app,
        &token,
        "acta_cache_answer",
        json!({
            "source_bundle_hash": b1_hash,
            "query_text": q_ttl,
            "answer_text": "Ephemeral 1s answer",
            "ttl_seconds": 1,
        }),
    )
    .await;
    assert_eq!(cache_ttl["result"]["isError"], json!(false));

    // PROBE 4: Sleep 1.2s -> C_ttl expires with `expired_ttl` chained ONCE ONLY!
    tokio::time::sleep(std::time::Duration::from_millis(1250)).await;
    let ttl_miss_1 = mcp_tool(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({ "scope": scope, "task_id": "po-check", "query_text": q_ttl }),
    )
    .await;
    let tm1 = &ttl_miss_1["result"]["structuredContent"];
    assert_eq!(tm1["cache_hit"], json!(false));
    assert_eq!(tm1["status"], json!("expired_ttl"));
    assert_eq!(tm1["invalidation_newly_recorded"], json!(true));
    assert_eq!(
        tm1["invalidation_evidence"]["answer_cache_summary"]["invalidation_reason"],
        json!("expired_ttl")
    );
    let ttl_inv_seq = tm1["invalidation_evidence_seq_num"].as_i64().unwrap();

    let ttl_miss_2 = mcp_tool(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({ "scope": scope, "task_id": "po-check", "query_text": q_ttl }),
    )
    .await;
    assert_eq!(
        ttl_miss_2["result"]["structuredContent"]["invalidation_newly_recorded"],
        json!(false)
    );
    assert_eq!(
        ttl_miss_2["result"]["structuredContent"]["invalidation_evidence_seq_num"],
        json!(ttl_inv_seq)
    );

    // PROBE 2: Unrelated write in same scope -> invalidates `scope_root` cache (`stale_state_commitment`)
    // while leaving `C_pin` (`dependency_subset` pinned to `clm_a_id`) a HIT!
    let unrel_write = mcp_tool(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "warehouse:mesa",
            "predicate": "bay_doors",
            "object_val": 12,
            "object_type": "int",
            "confidence": 0.90,
            "source_descriptor": "ops-sheet",
        }),
    )
    .await;
    assert_eq!(unrel_write["result"]["isError"], json!(false));

    let sr_lookup = mcp_tool(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({ "scope": scope, "task_id": "po-check", "query_text": q_sr }),
    )
    .await;
    assert_eq!(sr_lookup["result"]["structuredContent"]["cache_hit"], json!(false));
    assert_eq!(
        sr_lookup["result"]["structuredContent"]["status"],
        json!("stale_state_commitment")
    );
    assert_eq!(
        sr_lookup["result"]["structuredContent"]["invalidation_evidence"]["answer_cache_summary"]["invalidation_reason"],
        json!("stale_state_commitment")
    );

    // PROBE 3: Supersede `clm_b` (`carrier-bol-b`) in the SAME `supplier:titan / lead_days` group!
    // Because `C_pin` narrowed `dependency_ids` to `[clm_a_id]` ONLY, `C_pin` MUST STILL HIT!
    let clm_b_v2 = mcp_tool(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.85,
            "source_provenance_class": 2,
            "source_descriptor": "carrier-bol-b",
            "predecessor_id": clm_b_id,
            "valid_to": valid_to_future.to_rfc3339(),
        }),
    )
    .await;
    assert_eq!(clm_b_v2["result"]["isError"], json!(false));

    let pin_still_hit = mcp_tool(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({ "scope": scope, "task_id": "po-check", "query_text": q_pin }),
    )
    .await;
    assert_eq!(
        pin_still_hit["result"]["structuredContent"]["cache_hit"],
        json!(true),
        "Probe 3: changing non-listed claim in same group must leave narrowed dependency_ids cache a HIT: {pin_still_hit}"
    );

    // Now supersede `clm_a` (`erp-feed-a` -> 21 days) -> invalidates `C_pin`!
    // MUST-FIX 3 & SHOULD-FIX 3: Verify `ed25519_client_sig` + key + sig are preserved on invalidation receipt,
    // `invalidated_by` records the OAuth caller, `invalidation_evidence` is returned inline,
    // and `acta_trace_claim_impact` includes `invalidation_reason`!
    let clm_a_v2 = mcp_tool(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 21,
            "object_type": "int",
            "confidence": 0.91,
            "source_provenance_class": 3,
            "source_descriptor": "erp-feed-a",
            "predecessor_id": clm_a_id,
            "valid_to": valid_to_future.to_rfc3339(),
        }),
    )
    .await;
    assert_eq!(clm_a_v2["result"]["isError"], json!(false));
    let clm_a_v2_id = clm_a_v2["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let pin_inv = mcp_tool(
        &app,
        &token,
        "acta_lookup_cached_answer",
        json!({ "scope": scope, "task_id": "po-check", "query_text": q_pin }),
    )
    .await;
    let pi_sc = &pin_inv["result"]["structuredContent"];
    assert_eq!(pi_sc["cache_hit"], json!(false));
    assert_eq!(pi_sc["status"], json!("stale_dependency_commitment"));
    let inv_acs = &pi_sc["invalidation_evidence"]["answer_cache_summary"];
    assert_eq!(
        inv_acs["cacher_auth_kind"],
        json!("ed25519_client_sig"),
        "Must-Fix 3: invalidation receipt must preserve original cacher_auth_kind"
    );
    assert_eq!(inv_acs["client_public_key"], json!(author_pk_hex));
    assert!(inv_acs["client_signature"].as_str().unwrap().len() == 128);
    assert_eq!(
        inv_acs["invalidated_by"],
        json!(format!("{tenant_id}::oauth:kylewilson04"))
    );
    assert_eq!(
        inv_acs["invalidator_auth_kind"],
        json!("oauth_github_principal")
    );

    let trace_a = mcp_tool(
        &app,
        &token,
        "acta_trace_claim_impact",
        json!({ "item_id": clm_a_id }),
    )
    .await;
    assert_eq!(trace_a["result"]["isError"], json!(false));
    let impacted_answers = trace_a["result"]["structuredContent"]["impacted_cached_answers"]
        .as_array()
        .unwrap();
    let pin_row = impacted_answers
        .iter()
        .find(|r| r["cache_id"] == inv_acs["cache_id"])
        .expect("trace must find C_pin");
    assert_eq!(
        pin_row["invalidation_reason"],
        json!("stale_dependency_commitment"),
        "Should-Fix 3: trace must surface invalidation_reason"
    );

    // =========================================================================
    // SHOULD-FIX 7 & 8: Asymmetric Contradiction Edge + resolver_compat in Replay
    // =========================================================================
    // `dock_strike = true` (different group!) explicitly contradicts `clm_a_v2_id` (`lead_days = 21`).
    // `dock_strike` MUST resolve as [FACT], while `lead_days` halts with [DISPUTE: BLOCKING_CONTRADICTION]!
    let dock_clm = mcp_tool(
        &app,
        &token,
        "acta_ingest_claim",
        json!({
            "scope": scope,
            "subject": "port:long_beach",
            "predicate": "dock_strike",
            "object_val": true,
            "object_type": "bool",
            "confidence": 0.89,
            "source_provenance_class": 2,
            "source_descriptor": "port-bulletin-11",
            "contradiction_ids": [clm_a_v2_id],
        }),
    )
    .await;
    assert_eq!(dock_clm["result"]["isError"], json!(false));
    let dock_clm_id = dock_clm["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let comp_asym = mcp_tool(
        &app,
        &token,
        "acta_compile_context",
        json!({
            "scope": scope,
            "task_id": "po-check",
            "query_text": "Check supplier:titan lead_days and port:long_beach dock_strike",
        }),
    )
    .await;
    let asym_sc = &comp_asym["result"]["structuredContent"];
    let asym_hash = asym_sc["bundle_hash"].as_str().unwrap().to_string();
    let asym_res = asym_sc["bundle"]["resolution_records"].as_array().unwrap();
    let asym_disp = asym_sc["bundle"]["dispute_records"].as_array().unwrap();
    assert!(
        asym_res
            .iter()
            .any(|r| r["winning_claim"]["predicate"] == json!("dock_strike")),
        "Should-Fix 7: contradicting claim dock_strike must resolve as FACT, not block itself: {asym_res:?}"
    );
    assert_eq!(asym_disp.len(), 1);
    assert_eq!(asym_disp[0]["reason_code"], json!("BLOCKING_CONTRADICTION"));
    assert_eq!(
        asym_disp[0]["competing_claims"][0]["predicate"],
        json!("lead_days")
    );

    // Should-Fix 8: Replay exposes `resolver_compat == "v172_current"`
    let rep_asym = mcp_tool(
        &app,
        &token,
        "acta_replay_counterfactual",
        json!({ "source_bundle_hash": asym_hash }),
    )
    .await;
    assert_eq!(
        rep_asym["result"]["structuredContent"]["reproduced_source_bundle_bit_for_bit"],
        json!(true)
    );
    assert_eq!(
        rep_asym["result"]["structuredContent"]["reproducing_resolver"],
        json!("v173_current")
    );
    assert_eq!(
        rep_asym["result"]["structuredContent"]["recorded_resolver_version"],
        json!("v1.7.3")
    );

    // =========================================================================
    // PROBE 7a & 7b + Forged Retract & Override Refusal Codes
    // =========================================================================
    let forged_ret = mcp_tool(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "claim_id": dock_clm_id,
            "reason": "Port strike resolved",
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(forged_ret["result"]["isError"], json!(true));
    assert_eq!(
        forged_ret["result"]["structuredContent"]["reason_code"],
        json!("invalid_retract_client_signature")
    );

    let forged_ovr = mcp_tool(
        &app,
        &token,
        "acta_attest_override",
        json!({
            "scope": scope,
            "winning_claim_id": clm_a_v2_id,
            "adjudicator_id": "ops-committee",
            "justification": "Override test",
            "client_signature_hex": "00".repeat(64),
            "client_public_key_hex": author_pk_hex,
        }),
    )
    .await;
    assert_eq!(forged_ovr["result"]["isError"], json!(true));
    assert_eq!(
        forged_ovr["result"]["structuredContent"]["reason_code"],
        json!("invalid_adjudicator_client_signature")
    );

    // Probe 7b: Retract claim passing wrong scope -> refused (`claim_scope_mismatch`)!
    let wrong_scope_ret = mcp_tool(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "scope": "other/wrong-scope",
            "claim_id": dock_clm_id,
            "reason": "Wrong scope probe",
        }),
    )
    .await;
    assert_eq!(wrong_scope_ret["result"]["isError"], json!(true));
    assert_eq!(
        wrong_scope_ret["result"]["structuredContent"]["reason_code"],
        json!("claim_scope_mismatch")
    );

    // Valid retract on dock_clm_id -> succeeds!
    let ok_ret = mcp_tool(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "scope": scope,
            "claim_id": dock_clm_id,
            "reason": "Strike settled",
        }),
    )
    .await;
    assert_eq!(ok_ret["result"]["isError"], json!(false));

    // Probe 7a: Retract same claim a second time -> refused (`claim_already_retracted`)!
    let double_ret = mcp_tool(
        &app,
        &token,
        "acta_retract_claim",
        json!({
            "claim_id": dock_clm_id,
            "reason": "Second retract attempt",
        }),
    )
    .await;
    assert_eq!(double_ret["result"]["isError"], json!(true));
    assert_eq!(
        double_ret["result"]["structuredContent"]["reason_code"],
        json!("claim_already_retracted")
    );

    // =========================================================================
    // SHOULD-FIX 6: Witness Registration & Revocation Under 12-Part Event `v3`
    // =========================================================================
    let wit_sk = SigningKey::from_bytes(&[0xB2; 32]);
    let wit_pk_hex = hex::encode(wit_sk.verifying_key().to_bytes());
    let reg_w = mcp_tool(
        &app,
        &token,
        "acta_register_witness",
        json!({
            "witness_id": "witness-v172-main",
            "witness_public_key_hex": wit_pk_hex,
            "description": "v1.7.2 Event v3 Witness",
        }),
    )
    .await;
    assert_eq!(reg_w["result"]["isError"], json!(false));
    let reg_seq = reg_w["result"]["structuredContent"]["evidence_seq_num"]
        .as_i64()
        .unwrap();

    // Anchor at reg_seq
    let cp_m = mcp_tool(&app, &token, "acta_get_checkpoint", json!({})).await;
    let m_sz = cp_m["result"]["structuredContent"]["tree_size"]
        .as_i64()
        .unwrap();
    let m_cp_hex = cp_m["result"]["structuredContent"]["checkpoint"]["checkpoint_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let m_cp_arr: [u8; 32] = hex::decode(&m_cp_hex).unwrap().try_into().unwrap();
    let w_sig = sign_witness_anchor(&wit_sk, &tenant_id, m_sz, &m_cp_arr);
    let anch = mcp_tool(
        &app,
        &token,
        "acta_anchor_checkpoint",
        json!({
            "tree_size": m_sz,
            "checkpoint_hash": m_cp_hex,
            "witness_id": "witness-v172-main",
            "witness_public_key_hex": wit_pk_hex,
            "witness_signature_hex": hex::encode(w_sig),
        }),
    )
    .await;
    assert_eq!(anch["result"]["isError"], json!(false));

    // Also register + retire a second witness to verify revocation under event v3!
    let wit2_sk = SigningKey::from_bytes(&[0xB3; 32]);
    let wit2_pk_hex = hex::encode(wit2_sk.verifying_key().to_bytes());
    let _ = mcp_tool(
        &app,
        &token,
        "acta_register_witness",
        json!({
            "witness_id": "witness-v172-temp",
            "witness_public_key_hex": wit2_pk_hex,
            "description": "Temp witness",
        }),
    )
    .await;
    let rev_w2 = mcp_tool(
        &app,
        &token,
        "acta_revoke_witness",
        json!({
            "witness_id": "witness-v172-temp",
            "mode": "retire",
            "reason": "Scheduled rotation",
        }),
    )
    .await;
    assert_eq!(rev_w2["result"]["isError"], json!(false));
    let rev_seq = rev_w2["result"]["structuredContent"]["evidence_seq_num"]
        .as_i64()
        .unwrap();

    let ev_list = mcp_tool(
        &app,
        &token,
        "acta_list_evidence",
        json!({ "from_seq": reg_seq, "limit": 10 }),
    )
    .await;
    let entries = ev_list["result"]["structuredContent"]["entries"]
        .as_array()
        .unwrap();
    let reg_entry = entries.iter().find(|e| e["seq_num"] == json!(reg_seq)).unwrap();
    let rev_entry = entries.iter().find(|e| e["seq_num"] == json!(rev_seq)).unwrap();
    assert_eq!(
        reg_entry["event_domain"],
        json!("acta:evidence_event:v3"),
        "Should-Fix 6: v1.7.2 witness registration must hash under acta:evidence_event:v3"
    );
    assert_eq!(
        rev_entry["event_domain"],
        json!("acta:evidence_event:v3"),
        "Should-Fix 6: v1.7.2 witness revocation must hash under acta:evidence_event:v3"
    );

    // =========================================================================
    // SHOULD-FIX 4 & 5 + PROBE 1 & PROBE 5: Signed StateRebuildArchive Header,
    // Always Emit override_attestations: [], SPEC §2.5 Exact Match & Tamper Probes!
    // =========================================================================
    let rb_res = mcp_tool(
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

    let raw_archive_json = serde_json::to_vec_pretty(&rb_sc["rebuild_proof_archive"]).unwrap();
    let raw_archive_str = String::from_utf8(raw_archive_json.clone()).unwrap();
    assert!(
        raw_archive_str.contains("\"override_attestations\": []"),
        "Should-Fix 5: override_attestations must always be emitted even when empty"
    );
    std::fs::write("/tmp/acta_v172_e2e_rebuild.json", &raw_archive_json).unwrap();

    let archive: StateRebuildArchive =
        serde_json::from_slice(&raw_archive_json).unwrap();
    let offline = verify_and_rebuild_scope_state_offline(&archive, &host_pk, None).unwrap();
    assert!(offline.header_signature_verified);
    assert_eq!(
        offline.reconstructed_state_commitment_hex,
        rb_sc["live_store_state_commitment"].as_str().unwrap()
    );

    // Independent pure-SPEC.md §2.5 check on reconstructed sub-roots -> exact state_commitment!
    let spec_state_comm = spec_s25_state_commitment(
        SCHEMA_VERSION,
        &tenant_id,
        scope,
        &hex::decode(&offline.reconstructed_intent_root_hex).unwrap().try_into().unwrap(),
        &hex::decode(&offline.reconstructed_knowledge_root_hex).unwrap().try_into().unwrap(),
        &hex::decode(&offline.reconstructed_memory_root_hex).unwrap().try_into().unwrap(),
        &archive.permission_root,
    );
    assert_eq!(
        hex::encode(spec_state_comm),
        offline.reconstructed_state_commitment_hex
    );
    assert_eq!(
        spec_state_comm,
        compute_state_commitment(
            SCHEMA_VERSION,
            &tenant_id,
            scope,
            &hex::decode(&offline.reconstructed_intent_root_hex).unwrap().try_into().unwrap(),
            &hex::decode(&offline.reconstructed_knowledge_root_hex).unwrap().try_into().unwrap(),
            &hex::decode(&offline.reconstructed_memory_root_hex).unwrap().try_into().unwrap(),
            &archive.permission_root,
        )
    );

    // PROBE 5a: Flip 1 byte in record_snapshot -> MUST fail verification!
    let mut bad_snap = archive.clone();
    for ev in &mut bad_snap.evidence_chain {
        if let Some(ref mut ws) = ev.write_summary {
            ws.record_snapshot["priority"] = json!(999999);
            break;
        }
    }
    assert!(verify_and_rebuild_scope_state_offline(&bad_snap, &host_pk, None).is_err());

    // PROBE 5b: Strip 1 write entry -> MUST fail verification!
    let mut stripped_entry = archive.clone();
    stripped_entry.evidence_chain.pop();
    assert!(verify_and_rebuild_scope_state_offline(&stripped_entry, &host_pk, None).is_err());

    // PROBE 5c: Swap evaluated_at past valid_to -> MUST fail signed header verification!
    let mut swapped_clock = archive.clone();
    swapped_clock.evaluated_at = valid_to_future + Duration::days(5);
    let clock_err = verify_and_rebuild_scope_state_offline(&swapped_clock, &host_pk, None).unwrap_err();
    assert!(
        clock_err.contains("header"),
        "Probe 5c: swapping evaluated_at past valid_to must fail signed rebuild header: {clock_err}"
    );
}
