use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use acta_crypto::compute_pkce_s256;
use acta_engine::PipelineConfig;
use acta_policy::PolicyGate;
use acta_server::{
    config::{EmailOtpConfig, OAuthServerConfig},
    routes::build_router,
    state::AppState,
};
use axum::{
    body::Body,
    extract::Path,
    http::{header, Request, StatusCode},
    routing::{patch, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower::ServiceExt;

const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

#[derive(Debug, Clone)]
struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub code: Option<String>,
    pub idempotency_key: Option<String>,
    pub list_unsubscribe: Option<String>,
}

#[derive(Debug, Clone)]
struct CapturedContactEvent {
    pub op: String,
    pub email: String,
    pub first_name: Option<String>,
    pub unsubscribed: bool,
    pub segment_id: Option<String>,
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

fn extract_hidden_input(html: &str, field_name: &str) -> String {
    let marker = format!("name=\"{field_name}\" value=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("missing hidden input {field_name} in HTML:\n{html}"))
        + marker.len();
    let end = html[start..].find('"').expect("closing quote") + start;
    html[start..end].to_string()
}

fn extract_six_digit_from_subject(subject: &str) -> String {
    subject
        .split_whitespace()
        .next()
        .expect("6-digit code prefix in subject")
        .to_string()
}

async fn spawn_mock_email_server() -> (
    String,
    Arc<Mutex<Vec<CapturedEmail>>>,
    Arc<Mutex<Vec<CapturedContactEvent>>>,
    Arc<Mutex<Vec<Value>>>,
) {
    let inbox: Arc<Mutex<Vec<CapturedEmail>>> = Arc::new(Mutex::new(Vec::new()));
    let contacts: Arc<Mutex<Vec<CapturedContactEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let crm_events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));

    let inbox_resend = inbox.clone();
    let inbox_webhook = inbox.clone();
    let contacts_create = contacts.clone();
    let contacts_patch = contacts.clone();
    let crm_hook = crm_events.clone();

    let app = Router::new()
        .route(
            "/emails",
            post(move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let inbox = inbox_resend.clone();
                async move {
                    let auth = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    assert_eq!(auth, "Bearer re_test_secret_123");
                    let idemp = headers
                        .get("idempotency-key")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let list_unsub = body
                        .get("headers")
                        .and_then(|h| h.get("List-Unsubscribe"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let to = body["to"][0].as_str().unwrap().to_string();
                    let subject = body["subject"].as_str().unwrap().to_string();
                    let text = body["text"].as_str().unwrap().to_string();
                    inbox.lock().unwrap().push(CapturedEmail {
                        to,
                        subject,
                        text,
                        code: None,
                        idempotency_key: idemp,
                        list_unsubscribe: list_unsub,
                    });
                    (StatusCode::OK, Json(json!({ "id": "re_msg_001" })))
                }
            }),
        )
        .route(
            "/contacts",
            post(move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let contacts = contacts_create.clone();
                async move {
                    let auth = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    assert_eq!(auth, "Bearer re_test_secret_123");
                    let email = body["email"].as_str().unwrap().to_string();
                    let first_name = body.get("first_name").and_then(Value::as_str).map(str::to_string);
                    let unsubscribed = body["unsubscribed"].as_bool().unwrap_or(false);
                    let segment_id = body
                        .get("segments")
                        .and_then(|s| s.get(0))
                        .and_then(|s| s.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    contacts.lock().unwrap().push(CapturedContactEvent {
                        op: "create".to_string(),
                        email: email.clone(),
                        first_name,
                        unsubscribed,
                        segment_id,
                    });
                    (
                        StatusCode::OK,
                        Json(json!({
                            "object": "contact",
                            "id": format!("re_cnt_{}", email.replace('@', "_"))
                        })),
                    )
                }
            }),
        )
        .route(
            "/contacts/:email_or_id",
            patch(
                move |Path(email_or_id): Path<String>,
                      headers: axum::http::HeaderMap,
                      Json(body): Json<Value>| {
                    let contacts = contacts_patch.clone();
                    async move {
                        let auth = headers
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        assert_eq!(auth, "Bearer re_test_secret_123");
                        contacts.lock().unwrap().push(CapturedContactEvent {
                            op: "patch".to_string(),
                            email: percent_decode(&email_or_id),
                            first_name: None,
                            unsubscribed: body["unsubscribed"].as_bool().unwrap_or(true),
                            segment_id: None,
                        });
                        (
                            StatusCode::OK,
                            Json(json!({ "object": "contact", "id": "re_cnt_patched" })),
                        )
                    }
                },
            ),
        )
        .route(
            "/crm-signup",
            post(move |Json(body): Json<Value>| {
                let crm_hook = crm_hook.clone();
                async move {
                    crm_hook.lock().unwrap().push(body);
                    (StatusCode::OK, Json(json!({ "ok": true })))
                }
            }),
        )
        .route(
            "/webhook",
            post(move |Json(body): Json<Value>| {
                let inbox = inbox_webhook.clone();
                async move {
                    let to = body["to"].as_str().unwrap().to_string();
                    let subject = body["subject"].as_str().unwrap().to_string();
                    let text = body["text"].as_str().unwrap().to_string();
                    let code = body.get("code").and_then(Value::as_str).map(str::to_string);
                    inbox.lock().unwrap().push(CapturedEmail {
                        to,
                        subject,
                        text,
                        code,
                        idempotency_key: None,
                        list_unsubscribe: None,
                    });
                    (StatusCode::OK, Json(json!({ "ok": true })))
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), inbox, contacts, crm_events)
}

fn build_email_oauth_app(email_cfg: EmailOtpConfig) -> Router {
    let lazy_pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/acta_unused")
        .unwrap();
    let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new()).unwrap());
    let host_key = Arc::new(SigningKey::from_bytes(&[0x55u8; 32]));
    let oauth_cfg = OAuthServerConfig {
        public_base_url: Some("https://acta.ardyn.example".to_string()),
        github_client_id: Some("gh_client_123".to_string()),
        github_client_secret: Some("gh_secret_456".to_string()),
        github_authorize_url: "https://github.com/login/oauth/authorize".to_string(),
        github_token_url: "https://github.com/login/oauth/access_token".to_string(),
        github_api_base_url: "https://api.github.com".to_string(),
        auto_select_single_org: true,
    };
    let state = AppState::new(lazy_pool, gate, host_key, PipelineConfig::default())
        .with_auth(Some("master_secret_email_999".to_string()), "sandbox".to_string())
        .with_oauth(oauth_cfg)
        .with_email_otp(email_cfg);
    build_router(state)
}

async fn start_pkce_authorize(app: &Router, verifier: &str) -> (String, String, String) {
    let reg_req = Request::builder()
        .method("POST")
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "client_name": "Claude Desktop",
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
            }))
            .unwrap(),
        ))
        .unwrap();
    let reg_resp = app.clone().oneshot(reg_req).await.unwrap();
    assert_eq!(reg_resp.status(), StatusCode::CREATED);
    let reg_json: Value =
        serde_json::from_slice(&reg_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();

    let challenge = compute_pkce_s256(verifier).unwrap();
    let auth_uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz987",
        percent_encode(&client_id),
        percent_encode("https://claude.ai/api/mcp/auth_callback"),
        percent_encode(&challenge),
    );
    let auth_resp = app
        .clone()
        .oneshot(Request::builder().method("GET").uri(auth_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::OK);
    let auth_html =
        String::from_utf8(auth_resp.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
    assert!(auth_html.contains("Sign in with GitHub"));
    assert!(auth_html.contains("Email Me a 6-Digit Sign-In Code"));
    let otx_token = extract_hidden_input(&auth_html, "otx_token");
    (client_id, "https://claude.ai/api/mcp/auth_callback".to_string(), otx_token)
}

#[tokio::test]
async fn e2e_email_otp_pkce_marketing_sync_welcome_and_unsubscribe() {
    let (mail_base, inbox, contacts, crm_events) = spawn_mock_email_server().await;
    let app = build_email_oauth_app(EmailOtpConfig {
        resend_api_key: Some("re_test_secret_123".to_string()),
        resend_api_url: format!("{mail_base}/emails"),
        resend_segment_id: Some("seg_acta_founders_01".to_string()),
        email_from: "Acta Compiler <noreply@acta.ardyn.ai>".to_string(),
        signup_webhook_url: Some(format!("{mail_base}/crm-signup")),
        allowed_org_domains: vec!["ardyn.ai".to_string()],
        ..EmailOtpConfig::default()
    });

    let verifier = "v173_email_otp_pkce_verifier_string_0123456789abcdef";
    let (client_id, redirect_uri, otx_token) = start_pkce_authorize(&app, verifier).await;

    // 1. User kylewilson04@gmail.com signs in (opted in to marketing updates)
    let send_body = format!(
        "otx_token={}&marketing_form=1&marketing_opt_in=1&email={}",
        percent_encode(&otx_token),
        percent_encode("KyleWilson04@gmail.com")
    );
    let send_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(send_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_resp.status(), StatusCode::OK);
    let verify_page =
        String::from_utf8(send_resp.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
    let otp_token = extract_hidden_input(&verify_page, "otp_token");

    let sent = inbox.lock().unwrap().last().cloned().expect("captured OTP email");
    assert_eq!(sent.to, "kylewilson04@gmail.com");
    let code_6 = extract_six_digit_from_subject(&sent.subject);
    assert_eq!(code_6.len(), 6);
    assert!(sent.text.contains(&code_6));

    // Confirm raw 6-digit code is NOT recoverable by base64-decoding the otp_token payload!
    let b64_part = otp_token.split('.').nth(1).unwrap();
    let decoded_env = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b64_part)
            .unwrap(),
    )
    .unwrap();
    assert!(
        !decoded_env.contains(&format!("\"{code_6}\"")),
        "plaintext OTP must never appear inside envelope JSON: {decoded_env}"
    );

    // 2. Submit formatted code ("123-456") -> verifies OTP, syncs Resend Contact, fires CRM webhook,
    //    dispatches Welcome Email, and redirects with PKCE authorization code!
    let formatted_code = format!("{}-{}", &code_6[..3], &code_6[3..]);
    let verify_body = format!(
        "otp_token={}&code={}",
        percent_encode(&otp_token),
        percent_encode(&formatted_code)
    );
    let verify_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(verify_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(verify_resp.status().is_redirection());
    let loc = verify_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.starts_with("https://claude.ai/api/mcp/auth_callback?code=acta_ac_v1."));
    let auth_code = extract_query_param(loc, "code").unwrap();

    // Assert Resend Contact was created with unsubscribed=false & segment_id!
    {
        let cnts = contacts.lock().unwrap();
        assert_eq!(cnts.len(), 1);
        assert_eq!(cnts[0].op, "create");
        assert_eq!(cnts[0].email, "kylewilson04@gmail.com");
        assert_eq!(cnts[0].first_name.as_deref(), Some("Kylewilson"));
        assert!(!cnts[0].unsubscribed);
        assert_eq!(cnts[0].segment_id.as_deref(), Some("seg_acta_founders_01"));
    }
    // Assert CRM signup webhook fired!
    {
        let crms = crm_events.lock().unwrap();
        assert_eq!(crms.len(), 1);
        assert_eq!(crms[0]["event"], json!("acta.user.signup"));
        assert_eq!(crms[0]["email"], json!("kylewilson04@gmail.com"));
        assert_eq!(crms[0]["marketing_opt_in"], json!(true));
    }
    // Assert Welcome Email was dispatched with Idempotency-Key and RFC 8058 List-Unsubscribe!
    let welcome_mail = inbox.lock().unwrap().last().cloned().expect("welcome email");
    assert_eq!(welcome_mail.to, "kylewilson04@gmail.com");
    assert!(welcome_mail.subject.contains("Welcome to Acta Compiler"));
    assert!(welcome_mail
        .idempotency_key
        .as_deref()
        .unwrap_or("")
        .starts_with("welcome-email.kylewilson04."));
    let list_unsub_hdr = welcome_mail
        .list_unsubscribe
        .clone()
        .expect("List-Unsubscribe header");
    let unsub_url = list_unsub_hdr.trim_matches(|c| c == '<' || c == '>').to_string();
    assert!(unsub_url.contains("/signup/unsubscribe?token=acta_unsub_v1."));

    // Replaying the exact same otp_token a second time MUST be rejected (single-use burn)!
    let replay_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(verify_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_resp.status(), StatusCode::BAD_REQUEST);

    // 3. Repeat sign-in by the SAME user MUST NOT send a second Welcome email or re-create Contact!
    let inbox_count_before_repeat = inbox.lock().unwrap().len();
    let (_, _, otx_repeat) = start_pkce_authorize(&app, verifier).await;
    let send_rep = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otx_token={}&email={}",
                    percent_encode(&otx_repeat),
                    percent_encode("kylewilson04@gmail.com")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let rep_html =
        String::from_utf8(send_rep.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
    let otp_rep = extract_hidden_input(&rep_html, "otp_token");
    let code_rep = extract_six_digit_from_subject(&inbox.lock().unwrap().last().unwrap().subject);
    let ver_rep = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={}",
                    percent_encode(&otp_rep),
                    percent_encode(&code_rep)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(ver_rep.status().is_redirection());
    // Only +1 email (the OTP code itself), NOT +2 (no duplicate Welcome email)!
    assert_eq!(inbox.lock().unwrap().len(), inbox_count_before_repeat + 1);
    assert_eq!(contacts.lock().unwrap().len(), 1);
    assert_eq!(crm_events.lock().unwrap().len(), 1);

    // 4. Exchange PKCE code at /oauth/token -> inspect minted acta_tk_v1 token
    let tok_body = format!(
        "grant_type=authorization_code&code={}&code_verifier={}&client_id={}&redirect_uri={}",
        percent_encode(&auth_code),
        percent_encode(verifier),
        percent_encode(&client_id),
        percent_encode(&redirect_uri),
    );
    let tok_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(tok_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tok_resp.status(), StatusCode::OK);
    let tok_json: Value =
        serde_json::from_slice(&tok_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let access_token = tok_json["access_token"].as_str().unwrap().to_string();
    let tenant_a = tok_json["acta_tenant_id"].as_str().unwrap().to_string();
    assert!(tenant_a.starts_with("email.kylewilson04."));

    // 5. Second user (bob@gmail.com) unchecks marketing_opt_in -> synced as unsubscribed=true!
    let (_, _, otx2) = start_pkce_authorize(&app, verifier).await;
    let send2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otx_token={}&marketing_form=1&email={}",
                    percent_encode(&otx2),
                    percent_encode("bob@gmail.com")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html2 =
        String::from_utf8(send2.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let otp2 = extract_hidden_input(&html2, "otp_token");
    let code2 = extract_six_digit_from_subject(&inbox.lock().unwrap().last().unwrap().subject);
    let ver2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={}",
                    percent_encode(&otp2),
                    percent_encode(&code2)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(ver2.status().is_redirection());
    {
        let cnts = contacts.lock().unwrap();
        assert_eq!(cnts.len(), 2);
        assert_eq!(cnts[1].email, "bob@gmail.com");
        assert!(cnts[1].unsubscribed, "unchecked opt-in must sync unsubscribed=true");
    }

    // 6. Test GET /v1/admin/signups authorization, JSON & CSV export, and 1-click unsubscribe!
    let unauth_admin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/admin/signups")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_admin.status(), StatusCode::UNAUTHORIZED);

    let admin_json_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/admin/signups")
                .header("x-acta-api-key", "master_secret_email_999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_json_resp.status(), StatusCode::OK);
    let admin_json: Value = serde_json::from_slice(
        &admin_json_resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(admin_json["total_returned"], json!(2));
    assert_eq!(admin_json["marketing_opted_in_count"], json!(1));

    let admin_csv_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/admin/signups?marketing_only=true&format=csv")
                .header("x-acta-api-key", "master_secret_email_999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_csv_resp.status(), StatusCode::OK);
    let csv_txt = String::from_utf8(
        admin_csv_resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(csv_txt.contains("kylewilson04@gmail.com"));
    assert!(!csv_txt.contains("bob@gmail.com"));

    // Click signed 1-click unsubscribe link -> marks unsubscribed in DB AND fires Resend PATCH!
    let unsub_path = unsub_url
        .strip_prefix("https://acta.ardyn.example")
        .expect("matching base URL");
    let unsub_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(unsub_path)
                .body(Body::from("List-Unsubscribe=One-Click"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsub_resp.status(), StatusCode::OK);
    {
        let cnts = contacts.lock().unwrap();
        assert_eq!(cnts.len(), 3);
        assert_eq!(cnts[2].op, "patch");
        assert_eq!(cnts[2].email, "kylewilson04@gmail.com");
        assert!(cnts[2].unsubscribed);
    }

    let after_unsub_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/admin/signups?marketing_only=true")
                .header("x-acta-api-key", "master_secret_email_999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let after_unsub: Value = serde_json::from_slice(
        &after_unsub_resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(after_unsub["total_returned"], json!(0));
}

#[tokio::test]
async fn redteam_otp_bruteforce_lockout_rate_limit_and_signup_portal() {
    let (mail_base, inbox, _, _) = spawn_mock_email_server().await;
    let app = build_email_oauth_app(EmailOtpConfig {
        resend_api_key: None,
        resend_api_url: "https://unused.invalid".to_string(),
        email_from: "Acta Auth <auth@ardyn.example>".to_string(),
        webhook_url: Some(format!("{mail_base}/webhook")),
        ..EmailOtpConfig::default()
    });

    // 1. Test 5-attempt brute-force lockout on /oauth/email/verify
    let verifier = "v173_bruteforce_test_verifier_0123456789abcdefghijk";
    let (_, _, otx) = start_pkce_authorize(&app, verifier).await;
    let send_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otx_token={}&email={}",
                    percent_encode(&otx),
                    percent_encode("target@enterprise.io")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let html =
        String::from_utf8(send_resp.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
    let otp_tok = extract_hidden_input(&html, "otp_token");
    let real_code = inbox.lock().unwrap().last().unwrap().code.clone().unwrap();
    let wrong_code = if real_code == "000000" {
        "999999"
    } else {
        "000000"
    };

    for expected_rem in (1..=4).rev() {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/email/verify")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "otp_token={}&code={wrong_code}",
                        percent_encode(&otp_tok)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body_txt =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body_txt.contains(&format!("{expected_rem} attempt")));
    }

    let r5 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={wrong_code}",
                    percent_encode(&otp_tok)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r5.status(), StatusCode::TOO_MANY_REQUESTS);

    let r6 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={real_code}",
                    percent_encode(&otp_tok)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r6.status(), StatusCode::TOO_MANY_REQUESTS);

    // 2. Test standalone /signup self-serve portal + cross-flow substitution defense + Welcome webhook
    let signup_get = app
        .clone()
        .oneshot(Request::builder().method("GET").uri("/signup").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(signup_get.status(), StatusCode::OK);

    let signup_send = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signup/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("email=pilot%40clientcorp.com"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signup_send.status(), StatusCode::OK);
    let signup_verify_html = String::from_utf8(
        signup_send.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    let signup_otp_tok = extract_hidden_input(&signup_verify_html, "otp_token");
    let signup_code = inbox.lock().unwrap().last().unwrap().code.clone().unwrap();

    // Cross-flow substitution: submitting a signup otp_token to /oauth/email/verify MUST fail!
    let cross_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/email/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={signup_code}",
                    percent_encode(&signup_otp_tok)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_resp.status(), StatusCode::BAD_REQUEST);

    // Legitimate /signup/verify mints isolated acta_tk_v1 key + sends Welcome email!
    let ok_signup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signup/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "otp_token={}&code={signup_code}",
                    percent_encode(&signup_otp_tok)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_signup.status(), StatusCode::OK);
    assert_eq!(
        ok_signup.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let key_html = String::from_utf8(
        ok_signup.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    let key_start =
        key_html.find("id=\"acta-access-key\">").unwrap() + "id=\"acta-access-key\">".len();
    let key_end = key_html[key_start..].find('<').unwrap() + key_start;
    let minted_key = &key_html[key_start..key_end];
    assert!(minted_key.starts_with("acta_tk_v1:email.pilot."));

    let last_mail = inbox.lock().unwrap().last().cloned().expect("welcome email via webhook");
    assert_eq!(last_mail.to, "pilot@clientcorp.com");
    assert!(last_mail.subject.contains("Welcome to Acta Compiler"));

    // Verify per-email send rate limit (4 allowed per 10 min; 5th returns 429)
    for _ in 0..4 {
        let rr = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup/send")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("email=spamcheck%40clientcorp.com"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rr.status(), StatusCode::OK);
    }
    let rr5 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signup/send")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("email=spamcheck%40clientcorp.com"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rr5.status(), StatusCode::TOO_MANY_REQUESTS);
}
