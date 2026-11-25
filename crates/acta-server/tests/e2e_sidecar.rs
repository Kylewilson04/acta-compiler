use std::collections::BTreeMap;
use std::sync::Arc;

use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{
    routes::{
        auth::MintTenantKeyResponse,
        build_router,
        replay::ReplayResponse,
        verify::{TenantEvidenceResponse, VerifyArchiveResponse},
    },
    state::AppState,
};
use acta_store::pool::{create_pool, run_migrations};
use acta_types::{
    CompileRequest, CompileResponse, ContextBudget, ExportArchive, IngestClaimRequest,
    IngestObjectRequest, LifecycleStatus, ObjectType,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

#[tokio::test]
async fn test_e2e_ingest_compile_dispute_replay_verify_and_mcp() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("Skipping E2E HTTP sidecar test: DATABASE_URL not set");
        return;
    };

    let pool = create_pool(&database_url, 16).await.expect("connect pool");
    run_migrations(&pool).await.expect("run migrations");

    let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new()).unwrap());
    let host_key = Arc::new(SigningKey::from_bytes(&[0x91u8; 32]));
    let state = AppState::new(pool, gate, host_key.clone(), PipelineConfig::default())
        .with_auth(Some("test-secret-key".to_string()), "sandbox".to_string());
    let app = build_router(state);

    // 0. Check GET / (Control Plane HTML) & GET /v1/health
    let ui_res = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ui_res.status(), StatusCode::OK);

    let health_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_res.status(), StatusCode::OK);

    // Verify protected tenant without API key returns 401, while `sandbox-*` works without API key!
    let unauth_compile = CompileRequest {
        tenant_id: "protected-corp".to_string(),
        actor_id: "agent-1".to_string(),
        task_id: "t1".to_string(),
        scope: "payments".to_string(),
        query_text: "test".to_string(),
        query_embedding: None,
        budget: ContextBudget::Tokens(512),
        evaluation_time: None,
    };
    let unauth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/compile")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&unauth_compile).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

    let tenant_id = format!("sandbox-e2e-{}", Uuid::new_v4());

    // 1. Ingest Intent via POST /v1/objects
    let intent_req = IngestObjectRequest {
        id: None,
        tenant_id: tenant_id.clone(),
        obj_type: ObjectType::Intent,
        scope: "payments".to_string(),
        lifecycle_status: LifecycleStatus::Active,
        priority: 100,
        importance: 1.0,
        tags: vec!["compliance".to_string()],
        body: json!({ "directive": "Always surface disputed vendor settlement rates" }),
        embedding: None,
        predecessor_id: None,
        client_signature_hex: None,
        client_public_key_hex: None,
    };
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/objects")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. Ingest Memory via POST /v1/objects
    let mem_req = IngestObjectRequest {
        id: None,
        tenant_id: tenant_id.clone(),
        obj_type: ObjectType::Memory,
        scope: "payments".to_string(),
        lifecycle_status: LifecycleStatus::Active,
        priority: 10,
        importance: 0.85,
        tags: vec!["audit".to_string()],
        body: json!({ "summary": "Vendor acme-pay migrated settlement rails on Tuesday" }),
        embedding: None,
        predecessor_id: None,
        client_signature_hex: None,
        client_public_key_hex: None,
    };
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/objects")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&mem_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 3. Ingest Two Contradictory Claims (0.81 vs 0.74 -> margin 0.07 < 0.15 -> [DISPUTE])
    for (val, conf, src) in [("2.9%", 0.81, "billing-db"), ("2.4%", 0.74, "sales-contract")] {
        let claim_req = IngestClaimRequest {
            id: None,
            tenant_id: tenant_id.clone(),
            scope: "payments".to_string(),
            subject: "vendor:acme-pay".to_string(),
            predicate: "take_rate".to_string(),
            object_val: json!(val),
            object_type: "string".to_string(),
            confidence: conf,
            source_provenance_class: 2,
            source_descriptor: src.to_string(),
            source_commitment_hex: None,
            source_content: None,
            status: LifecycleStatus::Active,
            contradiction_ids: vec![],
            valid_from: None,
            valid_to: None,
            predecessor_id: None,
            erasable: None,
            client_signature_hex: None,
            client_public_key_hex: None,
        };
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/claims")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&claim_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    // 4. Compile Deterministic Context via POST /v1/compile
    let compile_req = CompileRequest {
        tenant_id: tenant_id.clone(),
        actor_id: format!("{tenant_id}::auditor"),
        task_id: "e2e-task-1".to_string(),
        scope: "payments".to_string(),
        query_text: "What is vendor:acme-pay take_rate?".to_string(),
        query_embedding: None,
        budget: ContextBudget::Tokens(2048),
        evaluation_time: None,
    };
    let comp_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/compile")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&compile_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(comp_res.status(), StatusCode::OK);
    let comp_bytes = comp_res.into_body().collect().await.unwrap().to_bytes();
    let comp_out: CompileResponse = serde_json::from_slice(&comp_bytes).unwrap();
    let ctx_text = comp_out.context_text.as_deref().unwrap();
    assert!(ctx_text.contains("[DISPUTE: INSUFFICIENT_MARGIN]"));
    let bundle_hash_hex = comp_out.bundle_hash.unwrap();

    // 5. Counterfactual Replay via POST /v1/replay (override margin to 0.05 -> resolves dispute!)
    let replay_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/replay")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "request": compile_req,
                        "override_decisiveness_threshold": 0.05
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_res.status(), StatusCode::OK);
    let replay_out: ReplayResponse =
        serde_json::from_slice(&replay_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(replay_out.diff.dispute_delta, -1);
    assert_eq!(replay_out.diff.resolution_delta, 1);
    assert!(replay_out.diff.bundle_hash_changed);

    // 6. Export Archive & Verify via POST /v1/verify (authentic vs 1-field tampered)
    let exp_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/bundles/{bundle_hash_hex}/export"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp_res.status(), StatusCode::OK);
    let mut archive: ExportArchive =
        serde_json::from_slice(&exp_res.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let ver_ok_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&json!({ "archive": archive })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ver_ok_res.status(), StatusCode::OK);
    let ver_ok: VerifyArchiveResponse =
        serde_json::from_slice(&ver_ok_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(ver_ok.verified);

    archive.claims[0].object_val = json!("99.9%");
    let ver_bad_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&json!({ "archive": archive })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ver_bad_res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 7. Check Tenant Evidence Ledger, OAuth 2.1 401 Challenge & Sandbox MCP tools/call
    let ev_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/tenants/{tenant_id}/evidence"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ev_res.status(), StatusCode::OK);
    let ev_out: TenantEvidenceResponse =
        serde_json::from_slice(&ev_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(ev_out.entry_count, 6);

    // Unauthenticated MCP call without X-Acta-Tenant must return 401 + WWW-Authenticate for OAuth 2.1
    let mcp_unauth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_unauth_res.status(), StatusCode::UNAUTHORIZED);
    assert!(mcp_unauth_res
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("/.well-known/oauth-protected-resource"));

    let mcp_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("x-acta-tenant", &tenant_id)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "acta_verify_bundle",
                            "arguments": { "bundle_hash": bundle_hash_hex }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_res.status(), StatusCode::OK);
    let mcp_json: Value =
        serde_json::from_slice(&mcp_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(mcp_json["result"]["isError"], json!(false));

    // 8. Stateless Tenant-Bound Key (`acta_tk_v1`) + `/mcp` Auto-Locking & Cross-Tenant Block
    let locked_tenant = format!("client-acme-{}", Uuid::new_v4().simple());
    let mint_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mint-tenant-key")
                .header("content-type", "application/json")
                .header("x-acta-api-key", "test-secret-key")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "tenant_id": locked_tenant })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mint_res.status(), StatusCode::OK);
    let minted: MintTenantKeyResponse =
        serde_json::from_slice(&mint_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(minted.tenant_api_key.starts_with(&format!("acta_tk_v1:{locked_tenant}:")));

    // Tenant key CANNOT mint keys for another tenant!
    let illegal_mint = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mint-tenant-key")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", minted.tenant_api_key))
                .body(Body::from(
                    serde_json::to_vec(&json!({ "tenant_id": "ardyn-core" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(illegal_mint.status(), StatusCode::UNAUTHORIZED);

    // MCP `acta_compile_context` with `tenant_id` OMITTED -> auto-injects `locked_tenant`!
    let mcp_auto_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", minted.tenant_api_key))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "acta_compile_context",
                            "arguments": {
                                "actor_id": "claude",
                                "scope": "contracts",
                                "query_text": "Check active MSA"
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mcp_auto_json: Value =
        serde_json::from_slice(&mcp_auto_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(mcp_auto_json["result"]["isError"], json!(false));
    assert_eq!(
        mcp_auto_json["result"]["structuredContent"]["evidence"]["tenant_id"],
        json!(locked_tenant)
    );

    // MCP `acta_compile_context` attempting cross-tenant read to `ardyn-core` -> BLOCKED!
    let mcp_cross_res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", minted.tenant_api_key))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "acta_compile_context",
                            "arguments": {
                                "tenant_id": "ardyn-core",
                                "actor_id": "claude",
                                "scope": "contracts",
                                "query_text": "Attempt cross-tenant exfiltration"
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mcp_cross_json: Value =
        serde_json::from_slice(&mcp_cross_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(mcp_cross_json["result"]["isError"], json!(true));
}
