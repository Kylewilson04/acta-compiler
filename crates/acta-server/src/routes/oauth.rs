use std::collections::HashMap;

use acta_crypto::{
    encode_length_delimited, hash_length_delimited, mint_signed_envelope, mint_tenant_api_key,
    mint_user_tenant_api_key, normalize_github_slug, token::derive_oauth_envelope_key,
    verify_pkce_s256, verify_signed_envelope, verify_tenant_api_key_with_principal,
    TENANT_TOKEN_PREFIX,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{AppState, OtpVerifyOutcome};

const DCR_CLIENT_PREFIX: &str = "acta_cid_v1";
const DCR_CLIENT_DOMAIN: &[u8] = b"acta:oauth:dcr_client:v1";

const OAUTH_TX_PREFIX: &str = "acta_otx_v1";
const OAUTH_TX_DOMAIN: &[u8] = b"acta:oauth:tx_state:v1";

const ORG_PICKER_PREFIX: &str = "acta_ghp_v1";
const ORG_PICKER_DOMAIN: &[u8] = b"acta:oauth:org_picker:v1";

const AUTH_CODE_PREFIX: &str = "acta_ac_v1";
const AUTH_CODE_DOMAIN: &[u8] = b"acta:oauth:auth_code:v1";

const REFRESH_TOKEN_PREFIX: &str = "acta_rt_v1";
const REFRESH_TOKEN_DOMAIN: &[u8] = b"acta:oauth:refresh_token:v1";

const EMAIL_OTP_PREFIX: &str = "acta_otp_v1";
const EMAIL_OTP_DOMAIN: &[u8] = b"acta:oauth:email_otp:v1";
const EMAIL_OTP_CODE_MAC_DOMAIN: &[u8] = b"acta:oauth:email_otp_code_mac:v1";

const EMAIL_UNSUB_PREFIX: &str = "acta_unsub_v1";
const EMAIL_UNSUB_DOMAIN: &[u8] = b"acta:oauth:email_unsub:v1";

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailOtpEnvelope {
    pub flow: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otx: Option<OAuthTxEnvelope>,
    pub email: String,
    pub code_mac_hex: String,
    #[serde(default = "default_true")]
    pub marketing_opt_in: bool,
    pub nonce: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailUnsubscribeEnvelope {
    pub email: String,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisteredClientEnvelope {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthTxEnvelope {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub scope: String,
    pub resource: Option<String>,
    pub select_org: bool,
    pub nonce: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CandidateOrgOption {
    pub slug: String,
    pub label: String,
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrgPickerEnvelope {
    pub otx: OAuthTxEnvelope,
    pub github_login: String,
    pub options: Vec<CandidateOrgOption>,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthCodeEnvelope {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub tenant_id: String,
    pub github_login: Option<String>,
    pub scope: String,
    #[serde(default)]
    pub available_vaults: Vec<CandidateOrgOption>,
    pub nonce: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenEnvelope {
    pub client_id: String,
    pub tenant_id: String,
    pub github_login: Option<String>,
    pub scope: String,
    #[serde(default)]
    pub available_vaults: Vec<CandidateOrgOption>,
    pub nonce: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterClientRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubTokenResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubUserProfile {
    pub login: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubOrgSummary {
    pub login: String,
    pub description: Option<String>,
}

fn random_nonce_hex() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn apply_oauth_cors(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, X-Acta-Api-Key, X-Acta-Tenant",
        ),
    );
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("WWW-Authenticate, Mcp-Session-Id"),
    );
    resp
}

pub async fn handle_oauth_preflight() -> Response {
    apply_oauth_cors(StatusCode::NO_CONTENT.into_response())
}

fn oauth_json_error(status: StatusCode, error: &str, desc: impl Into<String>) -> Response {
    let mut resp = (
        status,
        Json(json!({
            "error": error,
            "error_description": desc.into(),
        })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    apply_oauth_cors(resp)
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
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
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    out.push(((hi << 4) | lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_form_urlencoded(raw: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(raw);
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn is_loopback_http_uri(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let host = if let Some(bracketed) = authority.strip_prefix("[::1]") {
        if bracketed.is_empty() || bracketed.starts_with(':') {
            "[::1]"
        } else {
            return None;
        }
    } else {
        let h = authority.split(':').next().unwrap_or("");
        if h == "127.0.0.1" || h.eq_ignore_ascii_case("localhost") {
            h
        } else {
            return None;
        }
    };
    let clean_path = path_part.split('?').next().unwrap_or("/");
    Some((host, clean_path))
}

fn is_ide_custom_scheme_uri(uri: &str) -> bool {
    const ALLOWED_SCHEMES: &[&str] = &[
        "cursor://",
        "vscode://",
        "vscode-insiders://",
        "claude://",
        "windsurf://",
        "jetbrains://",
        "zed://",
    ];
    ALLOWED_SCHEMES
        .iter()
        .any(|prefix| uri.to_ascii_lowercase().starts_with(prefix))
}

fn extract_https_host(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("https://")?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn is_valid_dcr_redirect_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.contains('#') {
        return false;
    }
    if extract_https_host(trimmed).is_some() {
        return true;
    }
    if is_loopback_http_uri(trimmed).is_some() {
        return true;
    }
    is_ide_custom_scheme_uri(trimmed)
}

fn redirect_uri_matches_registered(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    if let (Some((reg_host, reg_path)), Some((req_host, req_path))) = (
        is_loopback_http_uri(registered),
        is_loopback_http_uri(requested),
    ) {
        return reg_host.eq_ignore_ascii_case(req_host) && reg_path == req_path;
    }
    false
}

fn validate_client_and_redirect(
    secret: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let cid = client_id.trim();
    let ruri = redirect_uri.trim();
    if cid.is_empty() {
        return Err("missing client_id".to_string());
    }
    if !is_valid_dcr_redirect_uri(ruri) {
        return Err(format!("disallowed or malformed redirect_uri '{ruri}'"));
    }

    if cid.starts_with(&format!("{DCR_CLIENT_PREFIX}.")) {
        let reg: RegisteredClientEnvelope =
            verify_signed_envelope(secret, DCR_CLIENT_PREFIX, DCR_CLIENT_DOMAIN, cid)?;
        if !reg
            .redirect_uris
            .iter()
            .any(|u| redirect_uri_matches_registered(u, ruri))
        {
            return Err(
                "redirect_uri does not match any URI registered for this client_id".to_string(),
            );
        }
        return Ok(reg.client_name);
    }

    if let Some(cid_host) = extract_https_host(cid) {
        if is_loopback_http_uri(ruri).is_some() || is_ide_custom_scheme_uri(ruri) {
            return Ok(cid_host.to_string());
        }
        if let Some(r_host) = extract_https_host(ruri) {
            if r_host.eq_ignore_ascii_case(cid_host)
                || matches!(
                    ruri,
                    "https://claude.ai/api/mcp/auth_callback"
                        | "https://claude.com/api/mcp/auth_callback"
                )
            {
                return Ok(cid_host.to_string());
            }
        }
        return Err(format!(
            "CIMD client_id host '{cid_host}' is not permitted to redirect to '{ruri}'"
        ));
    }

    if is_loopback_http_uri(ruri).is_some()
        || is_ide_custom_scheme_uri(ruri)
        || matches!(
            ruri,
            "https://claude.ai/api/mcp/auth_callback" | "https://claude.com/api/mcp/auth_callback"
        )
    {
        return Ok(cid.to_string());
    }

    Err(
        "unregistered client_id must register via POST /oauth/register or use CIMD / loopback redirect_uri"
            .to_string(),
    )
}

fn build_client_callback_url(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut out = format!("{redirect_uri}{sep}code={}", percent_encode(code));
    if let Some(st) = state.filter(|s| !s.is_empty()) {
        out.push_str("&state=");
        out.push_str(&percent_encode(st));
    }
    out
}

/// `GET /.well-known/oauth-protected-resource` & `GET /.well-known/oauth-protected-resource/mcp`
pub async fn handle_protected_resource_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let base = state.resolve_public_base_url(&headers);
    let body = json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:tools"],
        "resource_name": "Acta Deterministic Context Compiler",
        "resource_documentation": format!("{}/", state.resolve_public_base_url(&headers)),
    });
    apply_oauth_cors((StatusCode::OK, Json(body)).into_response())
}

/// `GET /.well-known/oauth-authorization-server` & `GET /.well-known/openid-configuration`
pub async fn handle_authorization_server_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let base = state.resolve_public_base_url(&headers);
    let body = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "scopes_supported": ["mcp:tools"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": true,
    });
    apply_oauth_cors((StatusCode::OK, Json(body)).into_response())
}

/// `POST /oauth/register` -> RFC 7591 Dynamic Client Registration (stateless Keyed-BLAKE3 `client_id`).
pub async fn handle_register_client(
    State(state): State<AppState>,
    Json(req): Json<RegisterClientRequest>,
) -> Response {
    if req.redirect_uris.is_empty() || req.redirect_uris.len() > 16 {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must contain 1..=16 valid URIs",
        );
    }
    let mut cleaned_uris = Vec::with_capacity(req.redirect_uris.len());
    for u in &req.redirect_uris {
        let trimmed = u.trim();
        if !is_valid_dcr_redirect_uri(trimmed) {
            return oauth_json_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                format!("unsupported or unsafe redirect_uri: {trimmed}"),
            );
        }
        cleaned_uris.push(trimmed.to_string());
    }

    let client_name = req
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("MCP Client")
        .chars()
        .take(80)
        .collect::<String>();
    let issued_at = Utc::now().timestamp();

    let env = RegisteredClientEnvelope {
        client_name: client_name.clone(),
        redirect_uris: cleaned_uris.clone(),
        issued_at,
    };
    let Ok(client_id) = mint_signed_envelope(
        state.effective_token_secret(),
        DCR_CLIENT_PREFIX,
        DCR_CLIENT_DOMAIN,
        &env,
    ) else {
        return oauth_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to mint stateless client_id",
        );
    };

    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string(), "refresh_token".to_string()]);
    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    let auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());

    let resp = (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "client_name": client_name,
            "redirect_uris": cleaned_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "token_endpoint_auth_method": auth_method,
            "scope": req.scope.unwrap_or_else(|| "mcp:tools".to_string()),
        })),
    )
        .into_response();
    apply_oauth_cors(resp)
}

/// `GET /oauth/authorize` -> Validates OAuth 2.1 + PKCE S256 parameters and launches GitHub Sign-In.
pub async fn handle_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(otx_tok) = params.get("otx") {
        let select_org = params
            .get("select_org")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        return start_github_oauth_redirect(&state, &headers, otx_tok, select_org);
    }

    let response_type = params.get("response_type").map(String::as_str).unwrap_or("");
    if response_type != "code" {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Unsupported response_type",
            "OAuth 2.1 requires response_type=code.",
        );
    }

    let client_id = params.get("client_id").map(String::as_str).unwrap_or("");
    let redirect_uri = params.get("redirect_uri").map(String::as_str).unwrap_or("");
    let client_name =
        match validate_client_and_redirect(state.effective_token_secret(), client_id, redirect_uri)
        {
            Ok(name) => name,
            Err(e) => {
                return render_oauth_error_html(
                    StatusCode::BAD_REQUEST,
                    "Invalid Client or Redirect URI",
                    &e,
                );
            }
        };

    let code_challenge = params
        .get("code_challenge")
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or("");
    if !(43..=128).contains(&code_challenge.len())
        || !code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "PKCE S256 Required",
            "OAuth 2.1 requires a valid 43..=128 char PKCE code_challenge.",
        );
    }

    let method = params
        .get("code_challenge_method")
        .map(String::as_str)
        .unwrap_or("S256");
    if method != "S256" {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Unsupported PKCE Method",
            "Only code_challenge_method=S256 is permitted under OAuth 2.1.",
        );
    }

    let select_org = params
        .get("select_org")
        .or_else(|| params.get("prompt"))
        .map(|v| v == "1" || v == "true" || v.contains("select"))
        .unwrap_or(false);

    let otx = OAuthTxEnvelope {
        client_id: client_id.trim().to_string(),
        client_name: client_name.clone(),
        redirect_uri: redirect_uri.trim().to_string(),
        code_challenge: code_challenge.to_string(),
        state: params.get("state").cloned(),
        scope: params
            .get("scope")
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "mcp:tools".to_string()),
        resource: params.get("resource").cloned(),
        select_org,
        nonce: random_nonce_hex(),
        exp: Utc::now().timestamp() + 600,
    };

    let Ok(otx_token) = mint_signed_envelope(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        &otx,
    ) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to sign OAuth transaction ticket.",
        );
    };

    if params.get("provider").map(String::as_str) == Some("github") && state.oauth.github_enabled()
    {
        return start_github_oauth_redirect(&state, &headers, &otx_token, select_org);
    }

    let base_url = state.resolve_public_base_url(&headers);
    render_authorize_signin_html(&state, &base_url, &client_name, &otx_token)
}

fn start_github_oauth_redirect(
    state: &AppState,
    headers: &HeaderMap,
    otx_token: &str,
    select_org_override: bool,
) -> Response {
    let now = Utc::now().timestamp();
    let Ok(mut otx) = verify_signed_envelope::<OAuthTxEnvelope>(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        otx_token,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Expired or Invalid Session",
            "Please restart the MCP connection from Claude or Cursor.",
        );
    };
    if otx.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "OAuth Session Expired",
            "Authorization request timed out after 10 minutes. Please click Connect again.",
        );
    }
    if select_org_override {
        otx.select_org = true;
    }

    let Some(ref gh_client_id) = state.oauth.github_client_id else {
        return render_oauth_error_html(
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub OAuth Not Configured Yet",
            "Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET on acta-server or sign in with an Acta API key.",
        );
    };

    let Ok(fresh_otx_tok) = mint_signed_envelope(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        &otx,
    ) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to mint GitHub state envelope.",
        );
    };

    let base = state.resolve_public_base_url(headers);
    let callback_uri = format!("{base}/oauth/github/callback");
    let sep = if state.oauth.github_authorize_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let target = format!(
        "{}{sep}client_id={}&redirect_uri={}&scope={}&state={}",
        state.oauth.github_authorize_url,
        percent_encode(gh_client_id),
        percent_encode(&callback_uri),
        percent_encode("read:org read:user"),
        percent_encode(&fresh_otx_tok),
    );
    Redirect::to(&target).into_response()
}

/// `GET /oauth/github/callback` -> Exchanges GitHub OAuth code, fetches `/user` + `/user/orgs`,
/// auto-routes single-org users straight into their GitHub Org vault, or shows a 1-click Org Picker.
pub async fn handle_github_callback(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(err) = params.get("error") {
        let desc = params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or("GitHub authorization was cancelled or denied.");
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            &format!("GitHub Sign-In Error ({err})"),
            desc,
        );
    }

    let Some(gh_code) = params.get("code").filter(|s| !s.trim().is_empty()) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing GitHub Code",
            "GitHub callback did not include an authorization code.",
        );
    };
    let Some(state_tok) = params.get("state") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing OAuth State",
            "GitHub callback did not include the signed state parameter.",
        );
    };

    let now = Utc::now().timestamp();
    let Ok(otx) = verify_signed_envelope::<OAuthTxEnvelope>(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        state_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid OAuth State Signature",
            "State verification failed. Please reconnect from Claude or Cursor.",
        );
    };
    if otx.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "OAuth Session Expired",
            "Authorization session expired. Please reconnect from Claude or Cursor.",
        );
    }

    let (Some(ref gh_client_id), Some(ref gh_client_secret)) = (
        state.oauth.github_client_id.clone(),
        state.oauth.github_client_secret.clone(),
    ) else {
        return render_oauth_error_html(
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub OAuth Missing Credentials",
            "GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not configured on acta-server.",
        );
    };

    let token_res = state
        .http_client
        .post(&state.oauth.github_token_url)
        .header(header::ACCEPT, "application/json")
        .json(&json!({
            "client_id": gh_client_id,
            "client_secret": gh_client_secret,
            "code": gh_code,
        }))
        .send()
        .await;

    let gh_token_payload: GitHubTokenResponse = match token_res {
        Ok(r) => match r.json().await {
            Ok(p) => p,
            Err(e) => {
                return render_oauth_error_html(
                    StatusCode::BAD_GATEWAY,
                    "GitHub Token Parse Error",
                    &format!("Failed to decode GitHub OAuth token response: {e}"),
                );
            }
        },
        Err(e) => {
            return render_oauth_error_html(
                StatusCode::BAD_GATEWAY,
                "GitHub OAuth Unreachable",
                &format!("Failed to contact GitHub token endpoint: {e}"),
            );
        }
    };

    let Some(gh_access_token) = gh_token_payload
        .access_token
        .filter(|t| !t.trim().is_empty())
    else {
        let msg = gh_token_payload
            .error_description
            .or(gh_token_payload.error)
            .unwrap_or_else(|| "GitHub did not return an access_token".to_string());
        return render_oauth_error_html(StatusCode::BAD_GATEWAY, "GitHub Token Exchange Failed", &msg);
    };

    let user_url = format!("{}/user", state.oauth.github_api_base_url);
    let orgs_url = format!("{}/user/orgs?per_page=100", state.oauth.github_api_base_url);

    let user_fut = state
        .http_client
        .get(&user_url)
        .bearer_auth(&gh_access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send();

    let orgs_fut = state
        .http_client
        .get(&orgs_url)
        .bearer_auth(&gh_access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send();

    let (user_resp, orgs_resp) = match tokio::try_join!(user_fut, orgs_fut) {
        Ok(pair) => pair,
        Err(e) => {
            return render_oauth_error_html(
                StatusCode::BAD_GATEWAY,
                "GitHub API Request Failed",
                &format!("Could not fetch GitHub profile and organization memberships: {e}"),
            );
        }
    };

    if !user_resp.status().is_success() {
        return render_oauth_error_html(
            StatusCode::BAD_GATEWAY,
            "GitHub User Lookup Failed",
            &format!("GET /user returned HTTP {}", user_resp.status()),
        );
    }

    let gh_user: GitHubUserProfile = match user_resp.json().await {
        Ok(u) => u,
        Err(e) => {
            return render_oauth_error_html(
                StatusCode::BAD_GATEWAY,
                "GitHub User Parse Error",
                &format!("Invalid JSON from GitHub /user: {e}"),
            );
        }
    };

    let gh_orgs: Vec<GitHubOrgSummary> = if orgs_resp.status().is_success() {
        orgs_resp.json().await.unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut options: Vec<CandidateOrgOption> = Vec::new();
    for org in &gh_orgs {
        if let Ok(slug) = normalize_github_slug(&org.login) {
            if !options.iter().any(|o| o.slug == slug) {
                options.push(CandidateOrgOption {
                    slug,
                    label: org.login.clone(),
                    kind: "github_org".to_string(),
                    description: org
                        .description
                        .clone()
                        .filter(|d| !d.trim().is_empty())
                        .unwrap_or_else(|| "GitHub Organization Vault".to_string()),
                });
            }
        }
    }

    if let Ok(personal_slug) = normalize_github_slug(&gh_user.login) {
        if !options.iter().any(|o| o.slug == personal_slug) {
            options.push(CandidateOrgOption {
                slug: personal_slug,
                label: format!("@{}", gh_user.login),
                kind: "github_user".to_string(),
                description: gh_user
                    .name
                    .clone()
                    .filter(|n| !n.trim().is_empty())
                    .map(|n| format!("Personal GitHub Vault ({n})"))
                    .unwrap_or_else(|| "Personal GitHub Vault".to_string()),
            });
        }
    }

    if options.is_empty() {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "No Valid GitHub Identity",
            "Could not derive a valid tenant slug from your GitHub account.",
        );
    }

    let org_count = options.iter().filter(|o| o.kind == "github_org").count();
    let is_ui_session = otx.scope.split_whitespace().any(|s| s == "acta:ui");

    if is_ui_session || (!otx.select_org && state.oauth.auto_select_single_org && org_count <= 1) {
        let chosen = if org_count >= 1 {
            options
                .iter()
                .find(|o| o.kind == "github_org")
                .unwrap_or(&options[0])
        } else {
            &options[0]
        };
        let carried = if is_ui_session {
            options.clone()
        } else {
            Vec::new()
        };
        return issue_auth_code_redirect(
            &state,
            &otx,
            &chosen.slug,
            Some(gh_user.login),
            carried,
        );
    }

    let picker = OrgPickerEnvelope {
        otx: otx.clone(),
        github_login: gh_user.login.clone(),
        options: options.clone(),
        exp: Utc::now().timestamp() + 300,
    };
    let Ok(picker_token) = mint_signed_envelope(
        state.effective_token_secret(),
        ORG_PICKER_PREFIX,
        ORG_PICKER_DOMAIN,
        &picker,
    ) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to sign organization picker ticket.",
        );
    };

    render_org_picker_html(&otx.client_name, &gh_user.login, &options, &picker_token)
}

/// `POST /oauth/approve` -> Completes 1-click GitHub Organization vault selection.
pub async fn handle_approve_org(State(state): State<AppState>, body: Bytes) -> Response {
    let form = parse_form_urlencoded(&body);
    let Some(picker_tok) = form.get("picker_token") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Picker Ticket",
            "Form submission lacked picker_token.",
        );
    };
    let Some(selected_slug) = form.get("tenant_id").map(|s| s.trim()) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Organization Selection",
            "Please select a GitHub organization.",
        );
    };

    let now = Utc::now().timestamp();
    let Ok(picker) = verify_signed_envelope::<OrgPickerEnvelope>(
        state.effective_token_secret(),
        ORG_PICKER_PREFIX,
        ORG_PICKER_DOMAIN,
        picker_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Picker Ticket",
            "Organization picker signature failed verification.",
        );
    };
    if picker.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Selection Expired",
            "Organization picker expired. Please reconnect from Claude or Cursor.",
        );
    }

    if !picker.options.iter().any(|o| o.slug == selected_slug) {
        return render_oauth_error_html(
            StatusCode::FORBIDDEN,
            "Unauthorized Organization",
            "Selected tenant is not among your verified GitHub organization memberships.",
        );
    }

    let carried = if picker.otx.scope.split_whitespace().any(|s| s == "acta:ui") {
        picker.options
    } else {
        Vec::new()
    };
    issue_auth_code_redirect(
        &state,
        &picker.otx,
        selected_slug,
        Some(picker.github_login),
        carried,
    )
}

/// `POST /oauth/key-login` -> Direct `acta_tk_v1` or Master API Key fallback on `/oauth/authorize`.
pub async fn handle_key_login(State(state): State<AppState>, body: Bytes) -> Response {
    let form = parse_form_urlencoded(&body);
    let Some(otx_tok) = form.get("otx_token") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Session Ticket",
            "Form submission lacked otx_token.",
        );
    };
    let raw_key = form.get("api_key").map(|s| s.trim()).unwrap_or("");
    let requested_tenant = form.get("tenant_id").map(|s| s.trim()).unwrap_or("");

    let now = Utc::now().timestamp();
    let Ok(otx) = verify_signed_envelope::<OAuthTxEnvelope>(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        otx_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid OAuth Session",
            "Session signature verification failed.",
        );
    };
    if otx.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "OAuth Session Expired",
            "Please restart the connection from Claude or Cursor.",
        );
    }

    let (resolved_tenant, resolved_principal) = if raw_key.starts_with(TENANT_TOKEN_PREFIX) {
        match verify_tenant_api_key_with_principal(state.effective_token_secret(), raw_key) {
            Ok((locked, principal)) => {
                if !requested_tenant.is_empty() && requested_tenant != locked {
                    return render_oauth_error_html(
                        StatusCode::FORBIDDEN,
                        "Tenant Mismatch",
                        &format!(
                            "Provided acta_tk_v1 key is locked to '{locked}', not '{requested_tenant}'."
                        ),
                    );
                }
                (locked, principal)
            }
            Err(e) => {
                return render_oauth_error_html(StatusCode::UNAUTHORIZED, "Invalid Key", &e);
            }
        }
    } else {
        let mut h = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(raw_key) {
            h.insert("x-acta-api-key", hv);
        }
        if let Err(e) = state.check_master_admin_auth(&h) {
            return render_oauth_error_html(StatusCode::UNAUTHORIZED, "Invalid Master Key", &e);
        }
        let requested_principal = form.get("principal").map(|s| s.trim()).unwrap_or("");
        let opt_principal = if requested_principal.is_empty() {
            None
        } else {
            match normalize_github_slug(requested_principal) {
                Ok(p) => Some(p),
                Err(_) => {
                    return render_oauth_error_html(
                        StatusCode::BAD_REQUEST,
                        "Invalid Principal Slug",
                        "Optional principal slug must contain only lowercase letters, digits, or hyphens.",
                    );
                }
            }
        };
        match normalize_github_slug(requested_tenant) {
            Ok(slug) => (slug, opt_principal),
            Err(_) => {
                return render_oauth_error_html(
                    StatusCode::BAD_REQUEST,
                    "Missing Organization / Tenant Slug",
                    "When signing in with a master key, enter the target org slug (e.g. ardyn-intelligence).",
                );
            }
        }
    };

    issue_auth_code_redirect(&state, &otx, &resolved_tenant, resolved_principal, Vec::new())
}

fn issue_auth_code_redirect(
    state: &AppState,
    otx: &OAuthTxEnvelope,
    tenant_id: &str,
    github_login: Option<String>,
    available_vaults: Vec<CandidateOrgOption>,
) -> Response {
    let ac = AuthCodeEnvelope {
        client_id: otx.client_id.clone(),
        redirect_uri: otx.redirect_uri.clone(),
        code_challenge: otx.code_challenge.clone(),
        tenant_id: tenant_id.to_string(),
        github_login,
        scope: otx.scope.clone(),
        available_vaults,
        nonce: random_nonce_hex(),
        exp: Utc::now().timestamp() + 300,
    };

    let Ok(code_tok) = mint_signed_envelope(
        state.effective_token_secret(),
        AUTH_CODE_PREFIX,
        AUTH_CODE_DOMAIN,
        &ac,
    ) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to mint authorization code.",
        );
    };

    let target = build_client_callback_url(&otx.redirect_uri, &code_tok, otx.state.as_deref());
    Redirect::to(&target).into_response()
}

fn extract_basic_client_id(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?
        .trim();
    let decoded = BASE64_STD.decode(b64).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (cid, _) = text.split_once(':')?;
    let clean = percent_decode(cid.trim());
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

/// `POST /oauth/token` -> OAuth 2.1 Token Endpoint (`authorization_code` + PKCE `S256` & `refresh_token`).
/// Mints a principal-bound `acta_tk_v1:<github_org_slug>:<github_login>:<mac>` Bearer token (`v1.6+`)!
pub async fn handle_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let params: HashMap<String, String> = if content_type.contains("application/json") {
        match serde_json::from_slice::<HashMap<String, Value>>(&body) {
            Ok(raw_map) => raw_map
                .into_iter()
                .filter_map(|(k, v)| match v {
                    Value::String(s) => Some((k, s)),
                    Value::Number(n) => Some((k, n.to_string())),
                    _ => None,
                })
                .collect(),
            Err(_) => {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "malformed JSON token request body",
                );
            }
        }
    } else {
        parse_form_urlencoded(&body)
    };

    let caller_client_id = params
        .get("client_id")
        .cloned()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| extract_basic_client_id(&headers));

    let grant_type = params.get("grant_type").map(String::as_str).unwrap_or("");
    let now = Utc::now().timestamp();

    match grant_type {
        "authorization_code" => {
            let Some(code_tok) = params.get("code").filter(|s| !s.trim().is_empty()) else {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "missing authorization code",
                );
            };
            let Some(code_verifier) = params.get("code_verifier").filter(|s| !s.trim().is_empty())
            else {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "missing PKCE code_verifier (required by OAuth 2.1)",
                );
            };

            let Ok(ac) = verify_signed_envelope::<AuthCodeEnvelope>(
                state.effective_token_secret(),
                AUTH_CODE_PREFIX,
                AUTH_CODE_DOMAIN,
                code_tok,
            ) else {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "invalid or forged authorization code",
                );
            };

            if ac.exp < now {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "authorization code has expired",
                );
            }

            if let Some(ref cid) = caller_client_id {
                if cid.trim() != ac.client_id {
                    return oauth_json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client",
                        "client_id does not match authorization code",
                    );
                }
            }

            if let Some(ruri) = params.get("redirect_uri").filter(|s| !s.trim().is_empty()) {
                if ruri.trim() != ac.redirect_uri {
                    return oauth_json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "redirect_uri does not match authorization code",
                    );
                }
            }

            if !verify_pkce_s256(code_verifier, &ac.code_challenge) {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE S256 code_verifier verification failed",
                );
            }

            if !state.consume_auth_code_once(code_tok, ac.exp, now) {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "authorization code has already been redeemed",
                );
            }

            issue_oauth_token_response(
                &state,
                &headers,
                &ac.client_id,
                &ac.tenant_id,
                ac.github_login,
                &ac.scope,
                ac.available_vaults,
            )
        }
        "refresh_token" => {
            let Some(rt_tok) = params.get("refresh_token").filter(|s| !s.trim().is_empty()) else {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "missing refresh_token",
                );
            };
            let Ok(rt) = verify_signed_envelope::<RefreshTokenEnvelope>(
                state.effective_token_secret(),
                REFRESH_TOKEN_PREFIX,
                REFRESH_TOKEN_DOMAIN,
                rt_tok,
            ) else {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "invalid refresh_token",
                );
            };
            if rt.exp < now {
                return oauth_json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token has expired",
                );
            }
            if let Some(ref cid) = caller_client_id {
                if cid.trim() != rt.client_id {
                    return oauth_json_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client",
                        "client_id does not match refresh_token",
                    );
                }
            }
            issue_oauth_token_response(
                &state,
                &headers,
                &rt.client_id,
                &rt.tenant_id,
                rt.github_login,
                &rt.scope,
                rt.available_vaults,
            )
        }
        _ => oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported grant_types: authorization_code, refresh_token",
        ),
    }
}

fn issue_oauth_token_response(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    tenant_id: &str,
    github_login: Option<String>,
    scope: &str,
    available_vaults: Vec<CandidateOrgOption>,
) -> Response {
    let secret = state.effective_token_secret();
    let gh_clean = github_login
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let tok_res = match gh_clean {
        Some(gh) => mint_user_tenant_api_key(secret, tenant_id, gh),
        None => mint_tenant_api_key(secret, tenant_id),
    };
    let Ok(access_token) = tok_res else {
        return oauth_json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to mint tenant-bound access_token",
        );
    };

    let base_origin = state.resolve_public_base_url(headers);
    let expected_ui_cid = format!("{}/control-plane", base_origin.trim_end_matches('/'));
    let is_same_origin_ui = scope.split_whitespace().any(|s| s == "acta:ui")
        && (client_id.trim_end_matches('/') == expected_ui_cid
            || client_id.trim_end_matches('/') == base_origin.trim_end_matches('/'));

    let authorized_vaults: Vec<Value> = if is_same_origin_ui {
        available_vaults
            .iter()
            .filter_map(|opt| {
                let tok = match gh_clean {
                    Some(gh) => mint_user_tenant_api_key(secret, &opt.slug, gh).ok()?,
                    None => mint_tenant_api_key(secret, &opt.slug).ok()?,
                };
                Some(json!({
                    "tenant_id": opt.slug,
                    "label": opt.label,
                    "kind": opt.kind,
                    "description": opt.description,
                    "access_token": tok,
                }))
            })
            .collect()
    } else {
        Vec::new()
    };

    let rt = RefreshTokenEnvelope {
        client_id: client_id.to_string(),
        tenant_id: tenant_id.to_string(),
        github_login: github_login.clone(),
        scope: scope.to_string(),
        available_vaults,
        nonce: random_nonce_hex(),
        exp: Utc::now().timestamp() + 86_400 * 30,
    };
    let refresh_token =
        mint_signed_envelope(secret, REFRESH_TOKEN_PREFIX, REFRESH_TOKEN_DOMAIN, &rt)
            .unwrap_or_default();

    let mut payload = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 2_592_000,
        "refresh_token": refresh_token,
        "scope": scope,
        "acta_tenant_id": tenant_id,
        "github_login": github_login,
    });
    if is_same_origin_ui {
        payload["authorized_vaults"] = Value::Array(authorized_vaults);
    }

    let mut resp = (StatusCode::OK, Json(payload)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    apply_oauth_cors(resp)
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn generate_six_digit_otp() -> String {
    let mut rng = rand::rngs::OsRng;
    // Reject values >= 4_294_000_000 (largest multiple of 1_000_000 <= u32::MAX) for zero modulo bias.
    loop {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let val = u32::from_le_bytes(buf);
        if val < 4_294_000_000 {
            return format!("{:06}", val % 1_000_000);
        }
    }
}

fn compute_otp_code_mac(
    secret: &str,
    flow: &str,
    nonce: &str,
    canonical_email: &str,
    code_6: &str,
) -> [u8; 32] {
    let key_32 = derive_oauth_envelope_key(secret, EMAIL_OTP_CODE_MAC_DOMAIN);
    let preimage = encode_length_delimited(&[
        EMAIL_OTP_CODE_MAC_DOMAIN,
        flow.as_bytes(),
        nonce.as_bytes(),
        canonical_email.as_bytes(),
        code_6.as_bytes(),
    ]);
    *blake3::keyed_hash(&key_32, &preimage).as_bytes()
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|ip| !ip.is_empty() && ip.len() <= 64)
        .map(str::to_string)
}

fn normalize_and_validate_email(raw: &str) -> Result<(String, String, String), String> {
    let clean = raw.trim().to_ascii_lowercase();
    if clean.len() < 5 || clean.len() > 254 {
        return Err("Email address must be between 5 and 254 characters.".to_string());
    }
    if clean.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("Email address cannot contain whitespace or control characters.".to_string());
    }
    let Some((local, domain)) = clean.split_once('@') else {
        return Err("Email address must contain '@'.".to_string());
    };
    if local.is_empty()
        || local.len() > 64
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
    {
        return Err("Invalid email local address part.".to_string());
    }
    if !local.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'_' | b'-' | b'+' | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'/'
                    | b'=' | b'?' | b'^' | b'`' | b'{' | b'|' | b'}' | b'~'
            )
    }) {
        return Err("Email local part contains unsupported characters.".to_string());
    }
    if domain.len() < 3
        || domain.len() > 253
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return Err("Email domain must be a valid DNS hostname (e.g. company.com).".to_string());
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid email domain label.".to_string());
        }
    }
    Ok((clean.clone(), local.to_string(), domain.to_string()))
}

fn is_public_consumer_email_domain(domain: &str) -> bool {
    matches!(
        domain,
        "gmail.com"
            | "googlemail.com"
            | "outlook.com"
            | "hotmail.com"
            | "live.com"
            | "msn.com"
            | "yahoo.com"
            | "ymail.com"
            | "icloud.com"
            | "me.com"
            | "mac.com"
            | "aol.com"
            | "proton.me"
            | "protonmail.com"
            | "pm.me"
            | "hey.com"
            | "fastmail.com"
            | "zoho.com"
            | "gmx.com"
            | "mail.com"
            | "yandex.com"
            | "tutanota.com"
            | "tutamail.com"
    )
}

fn sanitize_slug_fragment(raw: &str, max_len: usize, allow_dot: bool) -> String {
    let mut out = String::with_capacity(raw.len().min(max_len));
    let mut prev_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || (allow_dot && ch == '.') {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep && !out.is_empty() {
            out.push('-');
            prev_sep = true;
        }
        if out.len() >= max_len {
            break;
        }
    }
    let trimmed = out.trim_matches(|c| c == '-' || c == '.').to_string();
    if trimmed.is_empty() {
        "user".to_string()
    } else {
        trimmed
    }
}

/// Derives a principal slug (`em.<local>.<10hex>`) and vault options (`email.<local>.<10hex>`,
/// plus optional `domain.<corp>` when `domain` is explicitly allowlisted and non-consumer).
/// Because GitHub usernames and organizations strictly forbid `.`, `email.*`, `domain.*`, and `em.*`
/// are mathematically guaranteed never to collide with any GitHub vault or principal.
fn derive_email_vault_options(
    canonical_email: &str,
    local: &str,
    domain: &str,
    allowed_org_domains: &[String],
) -> (String, Vec<CandidateOrgOption>) {
    let fp = hash_length_delimited(&[b"acta:email_identity:v1", canonical_email.as_bytes()]);
    let fp10 = &hex::encode(fp)[..10];
    let local_clean = sanitize_slug_fragment(local, 24, false);
    let domain_clean = sanitize_slug_fragment(domain, 48, true);

    let principal = format!("em.{local_clean}.{fp10}");
    let personal_slug = format!("email.{local_clean}.{fp10}");

    let mut options = Vec::new();
    let org_allowed = !is_public_consumer_email_domain(domain)
        && allowed_org_domains
            .iter()
            .any(|d| d == "*" || d.eq_ignore_ascii_case(domain));

    if org_allowed {
        options.push(CandidateOrgOption {
            slug: format!("domain.{domain_clean}"),
            label: domain.to_string(),
            kind: "email_org".to_string(),
            description: format!("Verified Domain Organization Vault (@{domain})"),
        });
    }

    options.push(CandidateOrgOption {
        slug: personal_slug,
        label: canonical_email.to_string(),
        kind: "email_user".to_string(),
        description: format!("Isolated Personal Vault ({canonical_email})"),
    });

    (principal, options)
}

fn no_store_html(status: StatusCode, html: String) -> Response {
    let mut resp = (status, Html(html)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

async fn dispatch_otp_email(
    state: &AppState,
    recipient_email: &str,
    code_6: &str,
    client_name: &str,
) -> Result<(), String> {
    let subject = format!("{code_6} is your Acta Compiler verification code");
    let text_body = format!(
        "Your Acta Compiler verification code for {client_name} is: {code_6}\n\n\
         This code expires in 10 minutes and can only be used once.\n\
         If you did not request this sign-in, you can safely ignore this email."
    );
    let client_esc = html_escape(client_name);
    let code_esc = html_escape(code_6);
    let html_body = format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:460px;margin:0 auto;padding:24px;background:#0b0f17;color:#f3f6fb;border:1px solid #243046;">
  <div style="font-family:ui-monospace,monospace;font-size:11px;color:#38e8ff;margin-bottom:10px;">ACTA DETERMINISTIC CONTEXT COMPILER</div>
  <h2 style="margin:0 0 10px;font-size:19px;color:#ffffff;">Verify your email for {client_esc}</h2>
  <p style="margin:0 0 18px;font-size:14px;color:#9fb0ca;line-height:1.5;">Enter this one-time 6-digit verification code to unlock your isolated cryptographic vault:</p>
  <div style="font-family:ui-monospace,monospace;font-size:30px;font-weight:700;letter-spacing:6px;text-align:center;padding:16px;background:#111827;border:1px solid #38e8ff;color:#38e8ff;margin-bottom:18px;">{code_esc}</div>
  <p style="margin:0;font-size:12px;color:#9fb0ca;">Expires in 10 minutes · Single-use Keyed-BLAKE3 ticket.</p>
</div>"#
    );

    if let Some(ref resend_key) = state.email_otp.resend_api_key {
        let resp = state
            .http_client
            .post(&state.email_otp.resend_api_url)
            .bearer_auth(resend_key)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&json!({
                "from": state.email_otp.email_from,
                "to": [recipient_email],
                "subject": subject,
                "text": text_body,
                "html": html_body,
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to reach email delivery service: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            return Err(format!("Email provider returned HTTP {status}: {err_txt}"));
        }
        return Ok(());
    }

    if let Some(ref webhook_url) = state.email_otp.webhook_url {
        let mut req = state
            .http_client
            .post(webhook_url)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(ref bearer) = state.email_otp.webhook_bearer {
            req = req.bearer_auth(bearer);
        }
        let resp = req
            .json(&json!({
                "to": recipient_email,
                "from": state.email_otp.email_from,
                "subject": subject,
                "code": code_6,
                "client_name": client_name,
                "text": text_body,
                "html": html_body,
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to reach email webhook: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            return Err(format!("Email webhook returned HTTP {status}: {err_txt}"));
        }
        return Ok(());
    }

    Err("Email verification is not configured on this server (set ACTA_RESEND_API_KEY or ACTA_EMAIL_WEBHOOK_URL).".to_string())
}

fn parse_marketing_opt_in_from_form(form: &HashMap<String, String>) -> bool {
    if form.get("marketing_form").map(String::as_str) == Some("1") {
        return form
            .get("marketing_opt_in")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
            .unwrap_or(false);
    }
    match form.get("marketing_opt_in") {
        Some(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"),
        None => true,
    }
}

fn infer_display_first_name(local: &str) -> String {
    let raw_tok = local
        .split(['.', '_', '-', '+'])
        .find(|s| !s.is_empty())
        .unwrap_or(local);
    let cleaned: String = raw_tok
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(40)
        .collect();
    if cleaned.is_empty() {
        return "Builder".to_string();
    }
    let mut chars = cleaned.chars();
    match chars.next() {
        Some(first) => {
            format!(
                "{}{}",
                first.to_ascii_uppercase(),
                chars.as_str().to_ascii_lowercase()
            )
        }
        None => "Builder".to_string(),
    }
}

fn mint_unsubscribe_url(state: &AppState, base_url: &str, canonical_email: &str) -> Option<String> {
    let env = EmailUnsubscribeEnvelope {
        email: canonical_email.to_string(),
        issued_at: Utc::now().timestamp(),
    };
    let tok = mint_signed_envelope(
        state.effective_token_secret(),
        EMAIL_UNSUB_PREFIX,
        EMAIL_UNSUB_DOMAIN,
        &env,
    )
    .ok()?;
    Some(format!(
        "{}/signup/unsubscribe?token={}",
        base_url.trim_end_matches('/'),
        percent_encode(&tok)
    ))
}

async fn sync_resend_contact_on_signup(
    state: &AppState,
    canonical_email: &str,
    local: &str,
    marketing_opt_in: bool,
) -> Option<String> {
    if !state.email_otp.sync_resend_contacts {
        return None;
    }
    let resend_key = state.email_otp.resend_api_key.as_ref()?;
    let contacts_url = state.email_otp.effective_resend_contacts_url();
    let first_name = infer_display_first_name(local);

    let mut payload = json!({
        "email": canonical_email,
        "first_name": first_name,
        "unsubscribed": !marketing_opt_in,
    });
    if let Some(ref seg_id) = state.email_otp.resend_segment_id {
        payload["segments"] = json!([{ "id": seg_id }]);
    }

    match state
        .http_client
        .post(&contacts_url)
        .bearer_auth(resend_key)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string)),
        Ok(resp) => {
            let status = resp.status();
            let err_txt = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                email = %canonical_email,
                "Resend Contacts sync returned non-success ({err_txt})"
            );
            None
        }
        Err(e) => {
            tracing::warn!(email = %canonical_email, error = %e, "Resend Contacts sync request failed");
            None
        }
    }
}

async fn sync_resend_contact_unsubscribe(state: &AppState, canonical_email: &str) {
    let Some(ref resend_key) = state.email_otp.resend_api_key else {
        return;
    };
    let contacts_url = state.email_otp.effective_resend_contacts_url();
    let patch_url = format!(
        "{}/{}",
        contacts_url.trim_end_matches('/'),
        percent_encode(canonical_email)
    );
    if let Err(e) = state
        .http_client
        .patch(&patch_url)
        .bearer_auth(resend_key)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({ "unsubscribed": true }))
        .send()
        .await
    {
        tracing::warn!(email = %canonical_email, error = %e, "Resend Contact unsubscribe PATCH failed");
    }
}

async fn dispatch_signup_crm_webhook(
    state: &AppState,
    canonical_email: &str,
    tenant_id: &str,
    principal: &str,
    flow: &str,
    client_name: &str,
    marketing_opt_in: bool,
    resend_contact_id: Option<&str>,
) {
    let Some(ref wh_url) = state.email_otp.signup_webhook_url else {
        return;
    };
    let mut req = state
        .http_client
        .post(wh_url)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(ref bearer) = state.email_otp.signup_webhook_bearer {
        req = req.bearer_auth(bearer);
    }
    if let Err(e) = req
        .json(&json!({
            "event": "acta.user.signup",
            "email": canonical_email,
            "tenant_id": tenant_id,
            "principal": principal,
            "signup_flow": flow,
            "client_name": client_name,
            "marketing_opt_in": marketing_opt_in,
            "resend_contact_id": resend_contact_id,
            "timestamp": Utc::now().to_rfc3339(),
        }))
        .send()
        .await
    {
        tracing::warn!(email = %canonical_email, error = %e, "Signup CRM webhook POST failed");
    }
}

async fn dispatch_welcome_email(
    state: &AppState,
    base_url: &str,
    recipient_email: &str,
    local: &str,
    tenant_id: &str,
    principal: &str,
    marketing_opt_in: bool,
) -> bool {
    if !state.email_otp.welcome_email_enabled {
        return false;
    }

    let first_name = infer_display_first_name(local);
    let subject = state.email_otp.welcome_email_subject.clone();
    let mcp_url = format!("{}/mcp", base_url.trim_end_matches('/'));
    let signup_url = format!("{}/signup", base_url.trim_end_matches('/'));
    let cp_url = format!("{}/", base_url.trim_end_matches('/'));
    let unsub_url = mint_unsubscribe_url(state, base_url, recipient_email);

    let unsub_text_footer = match (&unsub_url, marketing_opt_in) {
        (Some(u), true) => format!(
            "

---
You opted in to Acta quickstart & product updates during vault verification.
Unsubscribe in 1 click: {u}"
        ),
        (_, false) => "

---
Marketing updates are turned off for this address (one-time transactional welcome receipt only).".to_string(),
        _ => String::new(),
    };

    let text_body = format!(
        "Hi {first_name},

         Welcome to Acta Deterministic Context Compiler. Your isolated cryptographic vault is provisioned and ready:

         - Locked Tenant Vault: {tenant_id}
         - Verified Principal:  {principal}
         - MCP OAuth Gateway:   {mcp_url}
         - Self-Serve Key Page: {signup_url}
         - Control Plane UI:    {cp_url}

         Connect Claude, Cursor, Windsurf, or Gemini directly to {mcp_url}, or visit {signup_url} anytime to mint a stateless acta_tk_v1 Bearer key for Python/TypeScript SDKs.{unsub_text_footer}"
    );

    let name_esc = html_escape(&first_name);
    let tenant_esc = html_escape(tenant_id);
    let principal_esc = html_escape(principal);
    let mcp_esc = html_escape(&mcp_url);
    let signup_esc = html_escape(&signup_url);
    let cp_esc = html_escape(&cp_url);

    let unsub_html_footer = match (&unsub_url, marketing_opt_in) {
        (Some(u), true) => {
            let u_esc = html_escape(u);
            format!(
                r#"<p style="margin:18px 0 0;padding-top:14px;border-top:1px solid #243046;font-size:11.5px;color:#6e82a3;line-height:1.5;">You opted in to Acta quickstart guides and product release notes · <a href="{u_esc}" style="color:#9fb0ca;text-decoration:underline;">Unsubscribe in 1 click</a></p>"#
            )
        }
        _ => {
            r#"<p style="margin:18px 0 0;padding-top:14px;border-top:1px solid #243046;font-size:11.5px;color:#6e82a3;">One-time vault provisioning confirmation · Marketing broadcasts are opted out for this address.</p>"#.to_string()
        }
    };

    let html_body = format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:520px;margin:0 auto;padding:26px;background:#0b0f17;color:#f3f6fb;border:1px solid #243046;">
  <div style="font-family:ui-monospace,monospace;font-size:11px;color:#34d399;margin-bottom:10px;">ACTA COMPILER · VAULT PROVISIONED</div>
  <h2 style="margin:0 0 10px;font-size:20px;color:#ffffff;">Welcome, {name_esc} — your isolated vault is live</h2>
  <p style="margin:0 0 16px;font-size:14px;color:#9fb0ca;line-height:1.55;">Every context bundle, epistemic claim, and policy decision in your workspace is Ed25519-notarized and Merkle-checkpointed inside your locked tenant vault:</p>
  <div style="background:#111827;border:1px solid #243046;padding:14px;margin-bottom:16px;font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.7;">
    <div><span style="color:#9fb0ca;">Tenant Vault:</span> <strong style="color:#38e8ff;">{tenant_esc}</strong></div>
    <div><span style="color:#9fb0ca;">Principal:</span> <span style="color:#f3f6fb;">{principal_esc}</span></div>
    <div><span style="color:#9fb0ca;">MCP Gateway:</span> <span style="color:#38e8ff;">{mcp_esc}</span></div>
  </div>
  <p style="margin:0 0 16px;font-size:13.5px;color:#dbe7f8;line-height:1.55;"><strong>Next step:</strong> Connect Claude, Cursor, Windsurf, or Gemini to <code style="color:#38e8ff;">{mcp_esc}</code>, or mint a CLI/SDK <code style="color:#38e8ff;">acta_tk_v1</code> token anytime on your key portal:</p>
  <div style="margin:18px 0;">
    <a href="{signup_esc}" style="display:inline-block;padding:11px 18px;background:#38e8ff;color:#0b0f17;font-weight:700;font-size:13.5px;text-decoration:none;margin-right:10px;">Open Key Portal</a>
    <a href="{cp_esc}" style="display:inline-block;padding:11px 18px;background:#162238;color:#f3f6fb;border:1px solid #243046;font-weight:600;font-size:13.5px;text-decoration:none;">Control Plane</a>
  </div>
  {unsub_html_footer}
</div>"#
    );

    if let Some(ref resend_key) = state.email_otp.resend_api_key {
        let mut email_json = json!({
            "from": state.email_otp.email_from,
            "to": [recipient_email],
            "subject": subject,
            "text": text_body,
            "html": html_body,
            "tags": [{ "name": "category", "value": "welcome_onboarding" }],
        });
        if let Some(ref u) = unsub_url {
            email_json["headers"] = json!({
                "List-Unsubscribe": format!("<{u}>"),
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            });
        }
        match state
            .http_client
            .post(&state.email_otp.resend_api_url)
            .bearer_auth(resend_key)
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", format!("welcome-{tenant_id}"))
            .json(&email_json)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => return true,
            Ok(r) => {
                let st = r.status();
                let txt = r.text().await.unwrap_or_default();
                tracing::warn!(status = %st, email = %recipient_email, "Welcome email Resend API returned non-success ({txt})");
                return false;
            }
            Err(e) => {
                tracing::warn!(email = %recipient_email, error = %e, "Welcome email Resend request failed");
                return false;
            }
        }
    }

    if let Some(ref webhook_url) = state.email_otp.webhook_url {
        let mut req = state
            .http_client
            .post(webhook_url)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(ref bearer) = state.email_otp.webhook_bearer {
            req = req.bearer_auth(bearer);
        }
        if let Ok(r) = req
            .json(&json!({
                "kind": "welcome_onboarding",
                "to": recipient_email,
                "from": state.email_otp.email_from,
                "subject": subject,
                "client_name": "Acta Welcome Onboarding",
                "tenant_id": tenant_id,
                "principal": principal,
                "marketing_opt_in": marketing_opt_in,
                "unsubscribe_url": unsub_url,
                "text": text_body,
                "html": html_body,
            }))
            .send()
            .await
        {
            return r.status().is_success();
        }
    }

    false
}

#[allow(clippy::too_many_arguments)]
async fn process_verified_signup_onboarding(
    state: &AppState,
    headers: &HeaderMap,
    canonical_email: &str,
    local: &str,
    tenant_id: &str,
    principal: &str,
    flow: &str,
    client_name: &str,
    marketing_opt_in: bool,
) {
    let record = state
        .record_verified_signup(
            canonical_email,
            tenant_id,
            principal,
            flow,
            client_name,
            marketing_opt_in,
        )
        .await;

    // Trigger CRM / Resend Contact creation and Welcome email strictly on first-time signup!
    if record.verification_count != 1 {
        return;
    }

    let base_url = state.resolve_public_base_url(headers);
    let resend_contact_id =
        sync_resend_contact_on_signup(state, canonical_email, local, record.marketing_opt_in).await;

    dispatch_signup_crm_webhook(
        state,
        canonical_email,
        tenant_id,
        principal,
        flow,
        client_name,
        record.marketing_opt_in,
        resend_contact_id.as_deref(),
    )
    .await;

    let welcome_sent = if record.welcome_sent_at.is_none() {
        dispatch_welcome_email(
            state,
            &base_url,
            canonical_email,
            local,
            tenant_id,
            principal,
            record.marketing_opt_in,
        )
        .await
    } else {
        false
    };

    if resend_contact_id.is_some() || welcome_sent {
        state
            .record_signup_delivery_meta(
                canonical_email,
                resend_contact_id.as_deref(),
                welcome_sent,
            )
            .await;
    }
}

fn normalize_submitted_otp_code(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 6 {
        Some(digits)
    } else {
        None
    }
}

/// `POST /oauth/email/send` -> Validates `otx_token` & email, rate-limits, emails a 6-digit code,
/// and renders the stateless `acta_otp_v1` verification screen.
pub async fn handle_oauth_email_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.email_otp.enabled() {
        return render_oauth_error_html(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email Sign-In Not Configured",
            "Set ACTA_RESEND_API_KEY or ACTA_EMAIL_WEBHOOK_URL on acta-server, or sign in with GitHub / an Acta Key.",
        );
    }

    let form = parse_form_urlencoded(&body);
    let Some(otx_tok) = form.get("otx_token") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Session Ticket",
            "Form submission lacked otx_token.",
        );
    };

    let now = Utc::now().timestamp();
    let Ok(mut otx) = verify_signed_envelope::<OAuthTxEnvelope>(
        state.effective_token_secret(),
        OAUTH_TX_PREFIX,
        OAUTH_TX_DOMAIN,
        otx_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid OAuth Session",
            "Session signature verification failed. Please reconnect from your MCP client.",
        );
    };
    if otx.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "OAuth Session Expired",
            "Authorization request timed out after 10 minutes. Please click Connect again.",
        );
    }
    if form
        .get("select_org")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        otx.select_org = true;
    }

    let raw_email = form.get("email").map(String::as_str).unwrap_or("");
    let (canonical_email, _, _) = match normalize_and_validate_email(raw_email) {
        Ok(parts) => parts,
        Err(e) => {
            return render_oauth_error_html(StatusCode::BAD_REQUEST, "Invalid Email Address", &e);
        }
    };

    let client_ip = extract_client_ip(&headers);
    if let Err(msg) = state.check_otp_send_rate_limit(&canonical_email, client_ip.as_deref(), now) {
        return render_oauth_error_html(StatusCode::TOO_MANY_REQUESTS, "Rate Limit Exceeded", &msg);
    }

    let code_6 = generate_six_digit_otp();
    let nonce = random_nonce_hex();
    let exp = otx.exp.min(now + 600);
    let secret = state.effective_token_secret();
    let code_mac = compute_otp_code_mac(secret, "oauth", &nonce, &canonical_email, &code_6);

    let marketing_opt_in = parse_marketing_opt_in_from_form(&form);
    let otp_env = EmailOtpEnvelope {
        flow: "oauth".to_string(),
        otx: Some(otx.clone()),
        email: canonical_email.clone(),
        code_mac_hex: hex::encode(code_mac),
        marketing_opt_in,
        nonce,
        exp,
    };

    let Ok(otp_token) = mint_signed_envelope(secret, EMAIL_OTP_PREFIX, EMAIL_OTP_DOMAIN, &otp_env)
    else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to mint email verification ticket.",
        );
    };

    if let Err(e) = dispatch_otp_email(&state, &canonical_email, &code_6, &otx.client_name).await {
        return render_oauth_error_html(StatusCode::BAD_GATEWAY, "Email Delivery Failed", &e);
    }

    render_email_code_entry_html(
        "/oauth/email/verify",
        &otx.client_name,
        &canonical_email,
        &otp_token,
        Some(otx_tok),
        None,
    )
}

/// `POST /oauth/email/verify` -> Verifies the 6-digit code in constant time under a 5-attempt
/// atomic lockout + single-use burn, then issues the PKCE S256 authorization code redirect.
pub async fn handle_oauth_email_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = parse_form_urlencoded(&body);
    let Some(otp_tok) = form.get("otp_token") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Verification Ticket",
            "Form submission lacked otp_token.",
        );
    };

    let now = Utc::now().timestamp();
    let secret = state.effective_token_secret();
    let Ok(otp_env) = verify_signed_envelope::<EmailOtpEnvelope>(
        secret,
        EMAIL_OTP_PREFIX,
        EMAIL_OTP_DOMAIN,
        otp_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Verification Ticket",
            "Email verification signature failed check.",
        );
    };

    if otp_env.flow != "oauth" {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Ticket Flow",
            "Ticket was not issued for an OAuth authorization flow.",
        );
    }
    let Some(otx) = otp_env.otx.clone() else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Malformed Ticket",
            "Missing embedded OAuth transaction state.",
        );
    };

    if otp_env.exp < now || otx.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Verification Code Expired",
            "This 6-digit code expired after 10 minutes. Please start the connection again.",
        );
    }

    let raw_code = form.get("code").map(String::as_str).unwrap_or("");
    let Some(clean_code) = normalize_submitted_otp_code(raw_code) else {
        return render_email_code_entry_html(
            "/oauth/email/verify",
            &otx.client_name,
            &otp_env.email,
            otp_tok,
            None,
            Some("Please enter all 6 digits of your verification code."),
        );
    };

    let Ok(stored_mac_vec) = hex::decode(&otp_env.code_mac_hex) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Malformed Verification Ticket",
            "Invalid MAC encoding.",
        );
    };
    let Ok(stored_mac): Result<[u8; 32], _> = stored_mac_vec.try_into() else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Malformed Verification Ticket",
            "Invalid MAC length.",
        );
    };

    let candidate_mac =
        compute_otp_code_mac(secret, "oauth", &otp_env.nonce, &otp_env.email, &clean_code);
    let matched = constant_time_eq_32(&stored_mac, &candidate_mac);

    match state.verify_and_consume_otp_attempt(&otp_env.nonce, otp_env.exp, now, matched) {
        OtpVerifyOutcome::Verified => {}
        OtpVerifyOutcome::InvalidCode { remaining_attempts } => {
            let msg = format!(
                "Incorrect code — {remaining_attempts} {} remaining.",
                if remaining_attempts == 1 {
                    "attempt"
                } else {
                    "attempts"
                }
            );
            return render_email_code_entry_html(
                "/oauth/email/verify",
                &otx.client_name,
                &otp_env.email,
                otp_tok,
                None,
                Some(&msg),
            );
        }
        OtpVerifyOutcome::LockedOut => {
            return render_oauth_error_html(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Incorrect Attempts",
                "This verification code has been permanently invalidated after 5 failed attempts. Please restart sign-in to request a new code.",
            );
        }
        OtpVerifyOutcome::AlreadyRedeemed => {
            return render_oauth_error_html(
                StatusCode::BAD_REQUEST,
                "Code Already Used",
                "This one-time verification code has already been redeemed.",
            );
        }
    }

    let Ok((canonical_email, local, domain)) = normalize_and_validate_email(&otp_env.email) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Verified Email",
            "Could not parse verified email identity.",
        );
    };

    let (principal, options) = derive_email_vault_options(
        &canonical_email,
        &local,
        &domain,
        &state.email_otp.allowed_org_domains,
    );

    let org_count = options.iter().filter(|o| o.kind == "email_org").count();
    let is_ui_session = otx.scope.split_whitespace().any(|s| s == "acta:ui");
    let default_chosen = if org_count >= 1 {
        options
            .iter()
            .find(|o| o.kind == "email_org")
            .unwrap_or(&options[0])
    } else {
        &options[0]
    };

    process_verified_signup_onboarding(
        &state,
        &headers,
        &canonical_email,
        &local,
        &default_chosen.slug,
        &principal,
        "oauth",
        &otx.client_name,
        otp_env.marketing_opt_in,
    )
    .await;

    if is_ui_session || (!otx.select_org && state.oauth.auto_select_single_org && org_count <= 1) {
        let carried = if is_ui_session {
            options.clone()
        } else {
            Vec::new()
        };
        return issue_auth_code_redirect(
            &state,
            &otx,
            &default_chosen.slug,
            Some(principal),
            carried,
        );
    }

    let picker = OrgPickerEnvelope {
        otx: otx.clone(),
        github_login: principal,
        options: options.clone(),
        exp: Utc::now().timestamp() + 300,
    };
    let Ok(picker_token) = mint_signed_envelope(
        secret,
        ORG_PICKER_PREFIX,
        ORG_PICKER_DOMAIN,
        &picker,
    ) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to sign workspace picker ticket.",
        );
    };

    render_org_picker_html(&otx.client_name, &canonical_email, &options, &picker_token)
}

/// `GET /signup` -> Standalone self-serve portal to mint an isolated `acta_tk_v1` API key via Email 6-Digit Code.
pub async fn handle_signup_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let base_url = state.resolve_public_base_url(&headers);
    let base_esc = html_escape(&base_url);
    let email_ready = state.email_otp.enabled();

    let body_section = if email_ready {
        r#"<form method="POST" action="/signup/send">
      <input type="hidden" name="marketing_form" value="1" />
      <label class="fld">Work or Personal Email</label>
      <input type="email" name="email" required autofocus placeholder="you@company.com" />
      <label class="chk" style="display:flex;align-items:flex-start;gap:8px;margin-top:12px;font-size:12px;color:#9fb0ca;cursor:pointer;line-height:1.45;">
        <input type="checkbox" name="marketing_opt_in" value="1" checked style="margin-top:2px;" />
        <span>Send me Acta quickstart guides, product updates, and release notes (1-click unsubscribe anytime)</span>
      </label>
      <button type="submit" class="btn-primary">Email Me a 6-Digit Code</button>
    </form>"#.to_string()
    } else {
        r#"<div class="warn-box">Self-serve email verification is not enabled on this server yet (set <code>ACTA_RESEND_API_KEY</code> or <code>ACTA_EMAIL_WEBHOOK_URL</code>).</div>"#.to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Get an Acta Access Key</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ width:100%; max-width:460px; background:#111827; border:1px solid #243046; padding:28px; box-shadow:0 20px 50px rgba(0,0,0,0.5); }}
  .badge {{ display:inline-block; font-family:ui-monospace,monospace; font-size:11px; color:#38e8ff; border:1px solid rgba(56,232,255,0.4); background:rgba(56,232,255,0.08); padding:3px 8px; margin-bottom:12px; }}
  h1 {{ margin:0 0 8px; font-size:21px; letter-spacing:-0.02em; }}
  p.sub {{ margin:0 0 20px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  label.fld {{ display:block; font-size:11.5px; color:#9fb0ca; margin:0 0 6px; text-transform:uppercase; letter-spacing:0.04em; }}
  input[type=email] {{ width:100%; box-sizing:border-box; background:#090d14; border:1px solid #243046; color:#f3f6fb; padding:11px 12px; font-family:ui-monospace,monospace; font-size:14px; }}
  .btn-primary {{ width:100%; margin-top:14px; padding:12px 16px; background:#38e8ff; color:#0b0f17; border:none; font-weight:700; font-size:14px; cursor:pointer; }}
  .warn-box {{ background:#090d14; border:1px solid #ffb547; color:#ffb547; padding:12px; font-size:13px; line-height:1.5; }}
  code {{ font-family:ui-monospace,monospace; color:#38e8ff; }}
  .foot {{ margin-top:18px; padding-top:14px; border-top:1px solid #243046; font-size:12px; color:#9fb0ca; }}
  a {{ color:#38e8ff; text-decoration:none; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">SELF-SERVE VAULT ONBOARDING · v1.7.3</span>
    <h1>Get Your Acta Access Key</h1>
    <p class="sub">No GitHub account needed. Verify your email with a one-time 6-digit code to provision an isolated vault and receive a stateless <code>acta_tk_v1</code> key for CLI, SDK, or MCP clients.</p>
    {body_section}
    <div class="foot">Connecting from Claude or Gemini OAuth? Point your client directly to <code>{base_esc}/mcp</code> — or <a href="/">return to the Control Plane</a>.</div>
  </div>
</body>
</html>"#
    );

    no_store_html(StatusCode::OK, html)
}

/// `POST /signup/send` -> Sends a 6-digit verification code for standalone key provisioning (`flow = "signup"`).
pub async fn handle_signup_email_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.email_otp.enabled() {
        return render_oauth_error_html(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email Sign-Up Not Configured",
            "Set ACTA_RESEND_API_KEY or ACTA_EMAIL_WEBHOOK_URL on acta-server.",
        );
    }

    let form = parse_form_urlencoded(&body);
    let raw_email = form.get("email").map(String::as_str).unwrap_or("");
    let (canonical_email, _, _) = match normalize_and_validate_email(raw_email) {
        Ok(parts) => parts,
        Err(e) => {
            return render_oauth_error_html(StatusCode::BAD_REQUEST, "Invalid Email Address", &e);
        }
    };

    let now = Utc::now().timestamp();
    let client_ip = extract_client_ip(&headers);
    if let Err(msg) = state.check_otp_send_rate_limit(&canonical_email, client_ip.as_deref(), now) {
        return render_oauth_error_html(StatusCode::TOO_MANY_REQUESTS, "Rate Limit Exceeded", &msg);
    }

    let code_6 = generate_six_digit_otp();
    let nonce = random_nonce_hex();
    let exp = now + 600;
    let secret = state.effective_token_secret();
    let code_mac = compute_otp_code_mac(secret, "signup", &nonce, &canonical_email, &code_6);

    let marketing_opt_in = parse_marketing_opt_in_from_form(&form);
    let otp_env = EmailOtpEnvelope {
        flow: "signup".to_string(),
        otx: None,
        email: canonical_email.clone(),
        code_mac_hex: hex::encode(code_mac),
        marketing_opt_in,
        nonce,
        exp,
    };

    let Ok(otp_token) = mint_signed_envelope(secret, EMAIL_OTP_PREFIX, EMAIL_OTP_DOMAIN, &otp_env)
    else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server Error",
            "Failed to mint signup verification ticket.",
        );
    };

    if let Err(e) =
        dispatch_otp_email(&state, &canonical_email, &code_6, "Acta Self-Serve Key Portal").await
    {
        return render_oauth_error_html(StatusCode::BAD_GATEWAY, "Email Delivery Failed", &e);
    }

    render_email_code_entry_html(
        "/signup/verify",
        "Acta Self-Serve Key Portal",
        &canonical_email,
        &otp_token,
        None,
        None,
    )
}

/// `POST /signup/verify` -> Verifies the 6-digit code and renders the user's freshly minted `acta_tk_v1` key.
pub async fn handle_signup_email_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = parse_form_urlencoded(&body);
    let Some(otp_tok) = form.get("otp_token") else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Verification Ticket",
            "Form submission lacked otp_token.",
        );
    };

    let now = Utc::now().timestamp();
    let secret = state.effective_token_secret();
    let Ok(otp_env) = verify_signed_envelope::<EmailOtpEnvelope>(
        secret,
        EMAIL_OTP_PREFIX,
        EMAIL_OTP_DOMAIN,
        otp_tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Verification Ticket",
            "Verification ticket signature failed check.",
        );
    };

    if otp_env.flow != "signup" {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Ticket Flow",
            "Ticket was not issued for self-serve key provisioning.",
        );
    }
    if otp_env.exp < now {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Verification Code Expired",
            "This 6-digit code expired after 10 minutes. Visit /signup to request a new code.",
        );
    }

    let raw_code = form.get("code").map(String::as_str).unwrap_or("");
    let Some(clean_code) = normalize_submitted_otp_code(raw_code) else {
        return render_email_code_entry_html(
            "/signup/verify",
            "Acta Self-Serve Key Portal",
            &otp_env.email,
            otp_tok,
            None,
            Some("Please enter all 6 digits of your verification code."),
        );
    };

    let Ok(stored_mac_vec) = hex::decode(&otp_env.code_mac_hex) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Malformed Ticket",
            "Invalid MAC encoding.",
        );
    };
    let Ok(stored_mac): Result<[u8; 32], _> = stored_mac_vec.try_into() else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Malformed Ticket",
            "Invalid MAC length.",
        );
    };

    let candidate_mac =
        compute_otp_code_mac(secret, "signup", &otp_env.nonce, &otp_env.email, &clean_code);
    let matched = constant_time_eq_32(&stored_mac, &candidate_mac);

    match state.verify_and_consume_otp_attempt(&otp_env.nonce, otp_env.exp, now, matched) {
        OtpVerifyOutcome::Verified => {}
        OtpVerifyOutcome::InvalidCode { remaining_attempts } => {
            let msg = format!(
                "Incorrect code — {remaining_attempts} {} remaining.",
                if remaining_attempts == 1 {
                    "attempt"
                } else {
                    "attempts"
                }
            );
            return render_email_code_entry_html(
                "/signup/verify",
                "Acta Self-Serve Key Portal",
                &otp_env.email,
                otp_tok,
                None,
                Some(&msg),
            );
        }
        OtpVerifyOutcome::LockedOut => {
            return render_oauth_error_html(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Incorrect Attempts",
                "This verification code has been permanently invalidated after 5 failed attempts. Visit /signup to request a new code.",
            );
        }
        OtpVerifyOutcome::AlreadyRedeemed => {
            return render_oauth_error_html(
                StatusCode::BAD_REQUEST,
                "Code Already Used",
                "This one-time verification code has already been redeemed.",
            );
        }
    }

    let Ok((canonical_email, local, domain)) = normalize_and_validate_email(&otp_env.email) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Email Identity",
            "Failed to derive tenant slug from verified email.",
        );
    };

    let (principal, options) = derive_email_vault_options(
        &canonical_email,
        &local,
        &domain,
        &state.email_otp.allowed_org_domains,
    );
    let chosen = &options[0];

    process_verified_signup_onboarding(
        &state,
        &headers,
        &canonical_email,
        &local,
        &chosen.slug,
        &principal,
        "signup",
        "Acta Self-Serve Key Portal",
        otp_env.marketing_opt_in,
    )
    .await;

    let Ok(access_key) = mint_user_tenant_api_key(secret, &chosen.slug, &principal) else {
        return render_oauth_error_html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Key Minting Error",
            "Failed to mint principal-bound acta_tk_v1 key.",
        );
    };

    let base_esc = html_escape(&state.resolve_public_base_url(&headers));
    let email_esc = html_escape(&canonical_email);
    let tenant_esc = html_escape(&chosen.slug);
    let principal_esc = html_escape(&principal);
    let key_esc = html_escape(&access_key);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your Acta Access Key</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ width:100%; max-width:540px; background:#111827; border:1px solid #34d399; padding:28px; box-shadow:0 20px 50px rgba(0,0,0,0.5); }}
  .badge {{ display:inline-block; font-family:ui-monospace,monospace; font-size:11px; color:#34d399; border:1px solid rgba(52,211,153,0.4); background:rgba(52,211,153,0.1); padding:3px 8px; margin-bottom:12px; }}
  h1 {{ margin:0 0 8px; font-size:21px; }}
  p.sub {{ margin:0 0 18px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:0.05em; color:#9fb0ca; margin:14px 0 5px; }}
  .mono-box {{ background:#090d14; border:1px solid #243046; padding:11px 12px; font-family:ui-monospace,monospace; font-size:12.5px; color:#38e8ff; word-break:break-all; user-select:all; }}
  .foot {{ margin-top:20px; padding-top:14px; border-top:1px solid #243046; font-size:12.5px; color:#9fb0ca; }}
  a {{ color:#38e8ff; text-decoration:none; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">EMAIL VERIFIED · {email_esc}</span>
    <h1>Your Isolated Vault Is Ready</h1>
    <p class="sub">Copy and store your Keyed-BLAKE3 access key below. You can pass it as a Bearer token in MCP headers, SDKs, or paste it on <code>/oauth/authorize</code>.</p>
    <div class="lbl">Locked Tenant Vault</div>
    <div class="mono-box" id="vault-slug">{tenant_esc}</div>
    <div class="lbl">Verified Principal</div>
    <div class="mono-box">{principal_esc}</div>
    <div class="lbl">Acta Access Key (acta_tk_v1)</div>
    <div class="mono-box" id="acta-access-key">{key_esc}</div>
    <div class="lbl">MCP Endpoint &amp; Header</div>
    <div class="mono-box">{base_esc}/mcp
Authorization: Bearer {key_esc}</div>
    <div class="foot"><a href="/">Open Acta Control Plane</a></div>
  </div>
</body>
</html>"#
    );

    no_store_html(StatusCode::OK, html)
}

fn render_email_code_entry_html(
    verify_action: &str,
    client_name: &str,
    email: &str,
    otp_token: &str,
    back_otx_token: Option<&str>,
    error_banner: Option<&str>,
) -> Response {
    let action_esc = html_escape(verify_action);
    let client_esc = html_escape(client_name);
    let email_esc = html_escape(email);
    let otp_esc = html_escape(otp_token);

    let err_html = match error_banner {
        Some(msg) => format!(
            r#"<div class="err-banner">{}</div>"#,
            html_escape(msg)
        ),
        None => String::new(),
    };

    let back_html = match back_otx_token {
        Some(_otx) => {
            r#"<p style="margin:14px 0 0;font-size:12px;color:#9fb0ca;text-align:center;">Check your inbox and spam folder. Code expires in 10 minutes.</p>"#.to_string()
        }
        None => {
            r#"<p style="margin:14px 0 0;font-size:12px;color:#9fb0ca;text-align:center;">Code expires in 10 minutes · <a href="/signup" style="color:#38e8ff;">Use a different email</a></p>"#.to_string()
        }
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enter 6-Digit Verification Code — Acta Compiler</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ width:100%; max-width:440px; background:#111827; border:1px solid #243046; padding:28px; box-shadow:0 20px 50px rgba(0,0,0,0.5); }}
  .badge {{ display:inline-block; font-family:ui-monospace,monospace; font-size:11px; color:#38e8ff; border:1px solid rgba(56,232,255,0.4); background:rgba(56,232,255,0.08); padding:3px 8px; margin-bottom:12px; }}
  h1 {{ margin:0 0 8px; font-size:20px; }}
  p.sub {{ margin:0 0 18px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  .err-banner {{ background:rgba(248,113,113,0.12); border:1px solid #f87171; color:#fca5a5; padding:10px 12px; font-size:13px; margin-bottom:16px; }}
  input.otp-inp {{ width:100%; box-sizing:border-box; background:#090d14; border:1px solid #38e8ff; color:#f3f6fb; padding:14px; font-family:ui-monospace,monospace; font-size:24px; letter-spacing:8px; text-align:center; }}
  .btn-verify {{ width:100%; margin-top:14px; padding:13px 16px; background:#38e8ff; color:#0b0f17; border:none; font-size:14.5px; font-weight:700; cursor:pointer; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">ONE-TIME EMAIL VERIFICATION</span>
    <h1>Check your email</h1>
    <p class="sub">Enter the 6-digit code sent to <strong>{email_esc}</strong> to authorize <strong>{client_esc}</strong>:</p>
    {err_html}
    <form method="POST" action="{action_esc}">
      <input type="hidden" name="otp_token" value="{otp_esc}" />
      <input type="text" name="code" class="otp-inp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9\s\-]{{6,9}}" maxlength="9" required autofocus placeholder="000000" />
      <button type="submit" class="btn-verify">Verify &amp; Continue</button>
    </form>
    {back_html}
  </div>
</body>
</html>"#
    );

    no_store_html(StatusCode::OK, html)
}

fn render_authorize_signin_html(
    state: &AppState,
    base_url: &str,
    client_name: &str,
    otx_token: &str,
) -> Response {
    let client_esc = html_escape(client_name);
    let base_esc = html_escape(base_url);
    let otx_esc = html_escape(otx_token);
    let gh_enabled = state.oauth.github_enabled();
    let email_enabled = state.email_otp.enabled();

    let github_section = if gh_enabled {
        format!(
            r#"<form method="GET" action="/oauth/authorize" style="margin-bottom:16px;">
  <input type="hidden" name="otx" value="{otx_esc}" />
  <button type="submit" class="btn-gh">
    <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
    Sign in with GitHub
  </button>
  <label class="chk">
    <input type="checkbox" name="select_org" value="1" />
    Let me choose manually if I belong to a GitHub organization + personal account
  </label>
</form>"#
        )
    } else if !email_enabled {
        format!(
            r#"<div class="setup-box">
  <div class="setup-title">1-Time OAuth Provider Setup</div>
  <p style="margin:6px 0 10px;color:#9fb0ca;font-size:12.5px;">
    Enable GitHub (<code>GITHUB_CLIENT_ID</code> + <code>GITHUB_CLIENT_SECRET</code>, callback <code>{base_esc}/oauth/github/callback</code>) or Email 6-Digit Code (<code>ACTA_RESEND_API_KEY</code>), or authorize <strong>{client_esc}</strong> below with an Acta key:
  </p>
</div>"#
        )
    } else {
        String::new()
    };

    let divider_html = if gh_enabled && email_enabled {
        r#"<div class="or-div"><span>or continue without GitHub</span></div>"#
    } else {
        ""
    };

    let email_section = if email_enabled {
        format!(
            r#"<form method="POST" action="/oauth/email/send" style="margin-bottom:16px;">
  <input type="hidden" name="otx_token" value="{otx_esc}" />
  <input type="hidden" name="marketing_form" value="1" />
  <label class="fld" style="margin-top:0;">Work or Personal Email (6-Digit Code)</label>
  <input type="email" name="email" required placeholder="you@company.com" />
  <label class="chk">
    <input type="checkbox" name="marketing_opt_in" value="1" checked />
    Send me Acta quickstart guides &amp; product updates (1-click unsubscribe anytime)
  </label>
  <button type="submit" class="btn-email">Email Me a 6-Digit Sign-In Code</button>
</form>"#
        )
    } else {
        String::new()
    };

    let details_open = if gh_enabled || email_enabled { "" } else { "open" };
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to Acta Compiler</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ width:100%; max-width:460px; background:#111827; border:1px solid #243046; padding:28px; box-shadow:0 20px 50px rgba(0,0,0,0.5); }}
  .badge {{ display:inline-block; font-family:ui-monospace,monospace; font-size:11px; color:#38e8ff; border:1px solid rgba(56,232,255,0.4); background:rgba(56,232,255,0.08); padding:3px 8px; margin-bottom:12px; }}
  h1 {{ margin:0 0 8px; font-size:21px; letter-spacing:-0.02em; }}
  p.sub {{ margin:0 0 20px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  .btn-gh {{ width:100%; display:flex; align-items:center; justify-content:center; gap:10px; padding:13px 16px; background:#f3f6fb; color:#0b0f17; border:none; font-size:14.5px; font-weight:700; cursor:pointer; }}
  .btn-gh:hover {{ background:#ffffff; }}
  .btn-email {{ width:100%; margin-top:10px; padding:11px 16px; background:#0e2a38; color:#38e8ff; border:1px solid #38e8ff; font-size:13.5px; font-weight:700; cursor:pointer; }}
  .btn-email:hover {{ background:#14384a; }}
  .or-div {{ display:flex; align-items:center; gap:10px; margin:16px 0; color:#6e82a3; font-size:11.5px; text-transform:uppercase; letter-spacing:0.05em; }}
  .or-div::before, .or-div::after {{ content:""; flex:1; height:1px; background:#243046; }}
  .chk {{ display:flex; align-items:center; gap:8px; margin-top:10px; font-size:12px; color:#9fb0ca; cursor:pointer; }}
  .setup-box {{ background:#090d14; border:1px solid #243046; padding:14px; margin-bottom:18px; }}
  .setup-title {{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#ffb547; }}
  code {{ font-family:ui-monospace,monospace; color:#38e8ff; background:#0d1422; padding:2px 5px; word-break:break-all; }}
  details {{ border-top:1px solid #243046; padding-top:14px; margin-top:10px; }}
  summary {{ cursor:pointer; font-size:12.5px; color:#9fb0ca; font-weight:600; }}
  label.fld {{ display:block; font-size:11.5px; color:#9fb0ca; margin:12px 0 4px; text-transform:uppercase; letter-spacing:0.04em; }}
  input[type=text], input[type=password], input[type=email] {{ width:100%; box-sizing:border-box; background:#090d14; border:1px solid #243046; color:#f3f6fb; padding:9px 11px; font-family:ui-monospace,monospace; font-size:13px; }}
  .btn-sec {{ width:100%; margin-top:12px; padding:10px 14px; background:#162238; color:#f3f6fb; border:1px solid #243046; font-weight:600; font-size:13px; cursor:pointer; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">ACTA MCP OAUTH 2.1 · PKCE S256 · v1.7.3</span>
    <h1>Connect {client_esc}</h1>
    <p class="sub">Sign in with GitHub or a one-time Email 6-Digit Code to cryptographically bind <strong>{client_esc}</strong> to your isolated Acta vault.</p>
    {github_section}
    {divider_html}
    {email_section}
    <details {details_open}>
      <summary>Or authorize with an Acta Key (acta_tk_v1 / Master Key)</summary>
      <form method="POST" action="/oauth/key-login">
        <input type="hidden" name="otx_token" value="{otx_esc}" />
        <label class="fld">Acta Key (acta_tk_v1:... or Master Key)</label>
        <input type="password" name="api_key" required placeholder="acta_tk_v1:ardyn-intelligence:..." />
        <label class="fld">Organization / Tenant Slug (required only for Master Key)</label>
        <input type="text" name="tenant_id" placeholder="ardyn-intelligence" />
        <button type="submit" class="btn-sec">Authorize MCP Client</button>
      </form>
    </details>
  </div>
</body>
</html>"#
    );

    no_store_html(StatusCode::OK, html)
}

fn render_org_picker_html(
    client_name: &str,
    identity_display: &str,
    options: &[CandidateOrgOption],
    picker_token: &str,
) -> Response {
    let client_esc = html_escape(client_name);
    let id_esc = html_escape(identity_display);
    let picker_esc = html_escape(picker_token);
    let badge_label = if identity_display.contains('@') {
        format!("EMAIL VERIFIED · {id_esc}")
    } else {
        format!("GITHUB VERIFIED · @{id_esc}")
    };

    let mut buttons_html = String::new();
    for opt in options {
        let slug_esc = html_escape(&opt.slug);
        let label_esc = html_escape(&opt.label);
        let desc_esc = html_escape(&opt.description);
        let tag = if opt.kind.ends_with("_org") {
            "ORG VAULT"
        } else {
            "PERSONAL"
        };
        buttons_html.push_str(&format!(
            r#"<button type="submit" name="tenant_id" value="{slug_esc}" class="org-btn">
  <div>
    <div class="org-name">{label_esc} <span class="org-slug">({slug_esc})</span></div>
    <div class="org-desc">{desc_esc}</div>
  </div>
  <span class="org-tag">{tag}</span>
</button>"#
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Select Vault — Acta Compiler</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ width:100%; max-width:480px; background:#111827; border:1px solid #243046; padding:28px; }}
  .badge {{ display:inline-block; font-family:ui-monospace,monospace; font-size:11px; color:#34d399; border:1px solid rgba(52,211,153,0.4); background:rgba(52,211,153,0.1); padding:3px 8px; margin-bottom:12px; }}
  h1 {{ margin:0 0 8px; font-size:20px; }}
  p.sub {{ margin:0 0 20px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  .org-btn {{ width:100%; display:flex; align-items:center; justify-content:space-between; gap:12px; background:#0d1422; border:1px solid #243046; color:#f3f6fb; padding:14px 16px; margin-bottom:10px; text-align:left; cursor:pointer; }}
  .org-btn:hover {{ border-color:#38e8ff; background:#142038; }}
  .org-name {{ font-size:14.5px; font-weight:700; }}
  .org-slug {{ font-family:ui-monospace,monospace; font-size:12px; color:#38e8ff; font-weight:400; }}
  .org-desc {{ font-size:12px; color:#9fb0ca; margin-top:3px; }}
  .org-tag {{ font-family:ui-monospace,monospace; font-size:10.5px; color:#38e8ff; border:1px solid rgba(56,232,255,0.35); padding:2px 6px; white-space:nowrap; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">{badge_label}</span>
    <h1>Choose Organization or Personal Vault</h1>
    <p class="sub">Select which vault <strong>{client_esc}</strong> should lock its Keyed-BLAKE3 token to:</p>
    <form method="POST" action="/oauth/approve">
      <input type="hidden" name="picker_token" value="{picker_esc}" />
      {buttons_html}
    </form>
  </div>
</body>
</html>"#
    );

    no_store_html(StatusCode::OK, html)
}

fn render_oauth_error_html(status: StatusCode, title: &str, detail: &str) -> Response {
    let t = html_escape(title);
    let d = html_escape(detail);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{t}</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ max-width:460px; width:100%; background:#111827; border:1px solid #f87171; padding:26px; }}
  h1 {{ margin:0 0 10px; font-size:19px; color:#f87171; }}
  p {{ margin:0; color:#dbe7f8; font-size:13.5px; line-height:1.5; }}
</style></head>
<body><div class="card"><h1>{t}</h1><p>{d}</p></div></body></html>"#
    );
    no_store_html(status, html)
}


fn csv_escape_field(val: &str) -> String {
    if val.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

/// `GET` / `POST /signup/unsubscribe?token=...` -> Stateless Keyed-BLAKE3 1-click unsubscribe
/// honoring both browser clicks and RFC 8058 mail-client `List-Unsubscribe-Post: List-Unsubscribe=One-Click`.
pub async fn handle_signup_unsubscribe(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let form = parse_form_urlencoded(&body);
    let Some(tok) = query
        .get("token")
        .or_else(|| form.get("token"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Missing Unsubscribe Token",
            "Please use the full unsubscribe link from the bottom of your Acta email.",
        );
    };

    let Ok(unsub_env) = verify_signed_envelope::<EmailUnsubscribeEnvelope>(
        state.effective_token_secret(),
        EMAIL_UNSUB_PREFIX,
        EMAIL_UNSUB_DOMAIN,
        tok,
    ) else {
        return render_oauth_error_html(
            StatusCode::BAD_REQUEST,
            "Invalid Unsubscribe Link",
            "Unsubscribe token signature verification failed.",
        );
    };

    state.unsubscribe_signup_email(&unsub_env.email).await;
    sync_resend_contact_unsubscribe(&state, &unsub_env.email).await;

    let email_esc = html_escape(&unsub_env.email);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Unsubscribed — Acta Compiler</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0b0f17; color:#f3f6fb; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:20px; }}
  .card {{ max-width:460px; width:100%; background:#111827; border:1px solid #34d399; padding:26px; }}
  h1 {{ margin:0 0 10px; font-size:19px; color:#34d399; }}
  p {{ margin:0; color:#dbe7f8; font-size:13.5px; line-height:1.55; }}
</style></head>
<body><div class="card">
  <h1>Unsubscribed from Marketing Updates</h1>
  <p><strong>{email_esc}</strong> will no longer receive Acta product updates or marketing broadcasts. One-time 6-digit sign-in codes will still work whenever you request them.</p>
</div></body></html>"#
    );
    no_store_html(StatusCode::OK, html)
}

/// `GET /v1/admin/signups` -> Master-admin protected JSON or CSV export of verified email signups.
pub async fn handle_admin_list_signups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(msg) = state.check_master_admin_auth(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": msg })),
        )
            .into_response();
    }

    let marketing_only = params
        .get("marketing_only")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1_000)
        .clamp(1, 10_000);

    let records = state.list_verified_signups(marketing_only, limit).await;
    let opted_in_count = records
        .iter()
        .filter(|r| r.marketing_opt_in && r.unsubscribed_at.is_none())
        .count();

    if params.get("format").map(|s| s.eq_ignore_ascii_case("csv")).unwrap_or(false) {
        let mut csv = String::from(
            "email,tenant_id,principal,first_signup_flow,first_client_name,marketing_opt_in,resend_contact_id,welcome_sent_at,unsubscribed_at,verification_count,created_at,last_verified_at\n",
        );
        for r in &records {
            let line = [
                csv_escape_field(&r.email),
                csv_escape_field(&r.tenant_id),
                csv_escape_field(&r.principal),
                csv_escape_field(&r.first_signup_flow),
                csv_escape_field(&r.first_client_name),
                r.marketing_opt_in.to_string(),
                csv_escape_field(r.resend_contact_id.as_deref().unwrap_or("")),
                csv_escape_field(
                    &r.welcome_sent_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default(),
                ),
                csv_escape_field(
                    &r.unsubscribed_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default(),
                ),
                r.verification_count.to_string(),
                csv_escape_field(&r.created_at.to_rfc3339()),
                csv_escape_field(&r.last_verified_at.to_rfc3339()),
            ]
            .join(",");
            csv.push_str(&line);
            csv.push('\n');
        }

        let mut resp = (StatusCode::OK, csv).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        resp.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"acta_email_signups.csv\""),
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return resp;
    }

    let items: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "email": r.email,
                "tenant_id": r.tenant_id,
                "principal": r.principal,
                "first_signup_flow": r.first_signup_flow,
                "first_client_name": r.first_client_name,
                "marketing_opt_in": r.marketing_opt_in,
                "resend_contact_id": r.resend_contact_id,
                "welcome_sent_at": r.welcome_sent_at.map(|t| t.to_rfc3339()),
                "unsubscribed_at": r.unsubscribed_at.map(|t| t.to_rfc3339()),
                "verification_count": r.verification_count,
                "created_at": r.created_at.to_rfc3339(),
                "last_verified_at": r.last_verified_at.to_rfc3339(),
            })
        })
        .collect();

    let mut resp = (
        StatusCode::OK,
        Json(json!({
            "total_returned": items.len(),
            "marketing_opted_in_count": opted_in_count,
            "signups": items,
        })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
