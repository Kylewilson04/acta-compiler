use std::collections::BTreeMap;
use std::sync::Arc;

use acta_crypto::compute_pkce_s256;
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{config::OAuthServerConfig, routes::build_router, state::AppState};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower::ServiceExt;

const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once('?')?;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn spawn_mock_github_server(orgs_json: Value) -> String {
    let orgs_clone = orgs_json.clone();
    let mock_gh = Router::new()
        .route(
            "/login/oauth/access_token",
            post(|Json(body): Json<Value>| async move {
                assert_eq!(body["client_id"], json!("gh_client_test_123"));
                assert_eq!(body["client_secret"], json!("gh_secret_test_456"));
                Json(json!({
                    "access_token": "gho_mock_token_abc123",
                    "token_type": "bearer",
                    "scope": "read:org,read:user"
                }))
            }),
        )
        .route(
            "/user",
            get(|| async {
                Json(json!({
                    "login": "ardyn-founder",
                    "name": "Ardyn Founder"
                }))
            }),
        )
        .route(
            "/user/orgs",
            get(move || {
                let payload = orgs_clone.clone();
                async move { Json(payload) }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_gh).await.unwrap();
    });
    format!("http://{addr}")
}

fn build_lazy_oauth_test_app(gh_base: &str) -> Router {
    let lazy_pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/acta_unused")
        .unwrap();
    let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new()).unwrap());
    let host_key = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
    let oauth_cfg = OAuthServerConfig {
        public_base_url: Some("https://acta.ardyn.example".to_string()),
        github_client_id: Some("gh_client_test_123".to_string()),
        github_client_secret: Some("gh_secret_test_456".to_string()),
        github_authorize_url: format!("{gh_base}/login/oauth/authorize"),
        github_token_url: format!("{gh_base}/login/oauth/access_token"),
        github_api_base_url: gh_base.to_string(),
        auto_select_single_org: true,
    };
    let state = AppState::new(lazy_pool, gate, host_key, PipelineConfig::default())
        .with_auth(Some("master_secret_test_999".to_string()), "sandbox".to_string())
        .with_oauth(oauth_cfg);
    build_router(state)
}

#[tokio::test]
async fn test_full_mcp_oauth21_pkce_dcr_and_single_github_org_autorouting() {
    let gh_base = spawn_mock_github_server(json!([
        {
            "login": "Ardyn-Intelligence",
            "description": "ARDYN INTELLIGENCE SYSTEMS INC."
        }
    ]))
    .await;
    let app = build_lazy_oauth_test_app(&gh_base);

    // 1. Unauthenticated Claude/Cursor `POST /mcp` (`initialize`) -> 401 + WWW-Authenticate RFC 9728
    let mcp_init_unauth = app
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
    assert_eq!(mcp_init_unauth.status(), StatusCode::UNAUTHORIZED);
    let www_auth = mcp_init_unauth
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www_auth.contains("https://acta.ardyn.example/.well-known/oauth-protected-resource"));

    // 2. Discover Protected Resource Metadata & Authorization Server Metadata
    let prm_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-protected-resource/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prm_res.status(), StatusCode::OK);
    let prm: Value =
        serde_json::from_slice(&prm_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(prm["resource"], json!("https://acta.ardyn.example/mcp"));
    assert_eq!(
        prm["authorization_servers"],
        json!(["https://acta.ardyn.example"])
    );

    let as_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(as_res.status(), StatusCode::OK);
    let as_meta: Value =
        serde_json::from_slice(&as_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(as_meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(as_meta["client_id_metadata_document_supported"], json!(true));

    // 3. Dynamic Client Registration (`POST /oauth/register`) for Claude + Cursor
    let dcr_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "client_name": "Claude Custom Connector",
                        "redirect_uris": [
                            "https://claude.ai/api/mcp/auth_callback",
                            "cursor://anysphere.cursor-mcp/oauth/callback"
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dcr_res.status(), StatusCode::CREATED);
    let dcr: Value =
        serde_json::from_slice(&dcr_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let client_id = dcr["client_id"].as_str().unwrap().to_string();
    assert!(client_id.starts_with("acta_cid_v1."));

    // Unsafe HTTP non-loopback DCR must fail!
    let bad_dcr = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "client_name": "Attacker",
                        "redirect_uris": ["http://evil.example.com/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_dcr.status(), StatusCode::BAD_REQUEST);

    // 4. Start Authorization (`GET /oauth/authorize?provider=github...`) with PKCE S256
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = compute_pkce_s256(verifier).unwrap();
    let redirect_uri = "https://claude.ai/api/mcp/auth_callback";

    let auth_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=claude_state_xyz&provider=github",
        percent_encode(&client_id),
        percent_encode(redirect_uri),
        percent_encode(&challenge),
    );
    let auth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(auth_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_res.status(), StatusCode::SEE_OTHER);
    let gh_loc = auth_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(gh_loc.contains("/login/oauth/authorize"));
    let gh_state = extract_query_param(gh_loc, "state").unwrap();

    // 5. GitHub OAuth Callback (`GET /oauth/github/callback`) -> 1 org (`Ardyn-Intelligence`)
    // auto-routes directly back to Claude's `redirect_uri` with signed `acta_ac_v1` code!
    let cb_uri = format!(
        "/oauth/github/callback?code=mock_gh_code_777&state={}",
        percent_encode(&gh_state)
    );
    let cb_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(cb_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_res.status(), StatusCode::SEE_OTHER);
    let claude_loc = cb_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(claude_loc.starts_with("https://claude.ai/api/mcp/auth_callback?"));
    assert_eq!(
        extract_query_param(claude_loc, "state").as_deref(),
        Some("claude_state_xyz")
    );
    let auth_code = extract_query_param(claude_loc, "code").unwrap();
    assert!(auth_code.starts_with("acta_ac_v1."));

    // 6a. Wrong PKCE `code_verifier` MUST be rejected without burning the code
    let bad_tok_body = format!(
        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier=wrong_verifier_that_is_at_least_43_characters_long_0000",
        percent_encode(&auth_code),
        percent_encode(&client_id),
        percent_encode(redirect_uri),
    );
    let bad_tok_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(bad_tok_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_tok_res.status(), StatusCode::BAD_REQUEST);

    // 6b. Valid PKCE `code_verifier` -> mints `acta_tk_v1:ardyn-intelligence:<mac>`!
    let ok_tok_body = format!(
        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
        percent_encode(&auth_code),
        percent_encode(&client_id),
        percent_encode(redirect_uri),
        percent_encode(verifier),
    );
    let ok_tok_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(ok_tok_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_tok_res.status(), StatusCode::OK);
    let tok_json: Value =
        serde_json::from_slice(&ok_tok_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let access_token = tok_json["access_token"].as_str().unwrap().to_string();
    let refresh_token = tok_json["refresh_token"].as_str().unwrap().to_string();
    assert!(access_token.starts_with("acta_tk_v1:ardyn-intelligence:"));
    assert_eq!(tok_json["acta_tenant_id"], json!("ardyn-intelligence"));
    assert_eq!(tok_json["github_login"], json!("ardyn-founder"));

    // 6c. Replaying the exact same authorization_code MUST fail (OAuth 2.1 single-use)!
    let replay_tok_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(ok_tok_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_tok_res.status(), StatusCode::BAD_REQUEST);

    // 6d. Refresh token rotation (`grant_type=refresh_token`)
    let refresh_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": client_id,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refreshed: Value =
        serde_json::from_slice(&refresh_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(refreshed["access_token"], json!(access_token));

    // 7. Call `POST /mcp` (`acta_whoami`) with the OAuth-minted Bearer token -> locked to `ardyn-intelligence`!
    let whoami_res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "tools/call",
                        "params": {
                            "name": "acta_whoami",
                            "arguments": {}
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(whoami_res.status(), StatusCode::OK);
    let whoami_json: Value =
        serde_json::from_slice(&whoami_res.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(whoami_json["result"]["isError"], json!(false));
    assert_eq!(
        whoami_json["result"]["structuredContent"]["locked_tenant"],
        json!("ardyn-intelligence")
    );
}

#[tokio::test]
async fn test_multi_github_org_picker_and_spoof_prevention() {
    let gh_base = spawn_mock_github_server(json!([
        { "login": "Ardyn-Intelligence", "description": "Internal Core" },
        { "login": "Client-Acme-Corp", "description": "Client Vault" }
    ]))
    .await;
    let app = build_lazy_oauth_test_app(&gh_base);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = compute_pkce_s256(verifier).unwrap();
    let redirect_uri = "cursor://anysphere.cursor-mcp/oauth/callback";

    // Unregistered Cursor client using custom cursor:// scheme + PKCE S256
    let auth_uri = format!(
        "/oauth/authorize?response_type=code&client_id=cursor-mcp&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=cur_1&provider=github",
        percent_encode(redirect_uri),
        percent_encode(&challenge),
    );
    let auth_res = app
        .clone()
        .oneshot(Request::builder().method("GET").uri(auth_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let gh_state = extract_query_param(
        auth_res.headers().get(header::LOCATION).unwrap().to_str().unwrap(),
        "state",
    )
    .unwrap();

    // Callback with 2 GitHub Orgs -> renders 200 OK HTML Org Picker containing signed `picker_token`
    let cb_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/oauth/github/callback?code=gh_multi_code&state={}",
                    percent_encode(&gh_state)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_res.status(), StatusCode::OK);
    let html = String::from_utf8(
        cb_res.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(html.contains("Ardyn-Intelligence"));
    assert!(html.contains("Client-Acme-Corp"));

    let marker = "name=\"picker_token\" value=\"";
    let start = html.find(marker).unwrap() + marker.len();
    let end = start + html[start..].find('"').unwrap();
    let picker_token = &html[start..end];

    // Attempting to spoof an unauthorized org (`unrelated-enterprise`) MUST return 403 Forbidden!
    let spoof_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/approve")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "picker_token={}&tenant_id=unrelated-enterprise",
                    percent_encode(picker_token)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spoof_res.status(), StatusCode::FORBIDDEN);

    // Selecting verified `client-acme-corp` succeeds and redirects to `cursor://...`!
    let approve_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/approve")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "picker_token={}&tenant_id=client-acme-corp",
                    percent_encode(picker_token)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approve_res.status(), StatusCode::SEE_OTHER);
    let cursor_loc = approve_res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cursor_loc.starts_with("cursor://anysphere.cursor-mcp/oauth/callback?code=acta_ac_v1."));
}

#[tokio::test]
async fn test_control_plane_ui_github_signin_returns_multi_vault_tokens_and_guards_vault_api() {
    let gh_base = spawn_mock_github_server(json!([
        { "login": "Ardyn-Intelligence", "description": "Internal Core" },
        { "login": "Client-Acme-Corp", "description": "Client Vault" }
    ]))
    .await;
    let app = build_lazy_oauth_test_app(&gh_base);

    // 1. Unauthenticated Vault Explorer request for protected tenant -> 401 Unauthorized
    let unauth_vault = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/tenants/kylewilson04/vault")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_vault.status(), StatusCode::UNAUTHORIZED);

    // 2. Control Plane UI initiates PKCE GitHub sign-in (`client_id = https://acta.ardyn.example/control-plane`)
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = compute_pkce_s256(verifier).unwrap();
    let ui_cid = "https://acta.ardyn.example/control-plane";
    let ui_ruri = "https://acta.ardyn.example/";

    let auth_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=ui_st_1&scope={}&provider=github",
        percent_encode(ui_cid),
        percent_encode(ui_ruri),
        percent_encode(&challenge),
        percent_encode("mcp:tools acta:ui"),
    );
    let auth_res = app
        .clone()
        .oneshot(Request::builder().method("GET").uri(auth_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let gh_state = extract_query_param(
        auth_res.headers().get(header::LOCATION).unwrap().to_str().unwrap(),
        "state",
    )
    .unwrap();

    // Even with 2 GitHub Orgs, Control Plane UI bounces straight back to `/` in 1 click!
    let cb_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/oauth/github/callback?code=gh_ui_code&state={}",
                    percent_encode(&gh_state)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_res.status(), StatusCode::SEE_OTHER);
    let ui_loc = cb_res.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(ui_loc.starts_with("https://acta.ardyn.example/?code=acta_ac_v1."));
    let code = extract_query_param(ui_loc, "code").unwrap();

    // Exchange code -> returns authorized_vaults for all 3 verified GitHub vaults!
    let tok_res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "grant_type": "authorization_code",
                        "code": code,
                        "code_verifier": verifier,
                        "client_id": ui_cid,
                        "redirect_uri": ui_ruri,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tok_res.status(), StatusCode::OK);
    let tok_json: Value =
        serde_json::from_slice(&tok_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let vaults = tok_json["authorized_vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 3);
    assert_eq!(vaults[0]["tenant_id"], json!("ardyn-intelligence"));
    assert_eq!(vaults[1]["tenant_id"], json!("client-acme-corp"));
    assert_eq!(vaults[2]["tenant_id"], json!("ardyn-founder"));
    assert!(vaults[2]["access_token"]
        .as_str()
        .unwrap()
        .starts_with("acta_tk_v1:ardyn-founder:"));
}
