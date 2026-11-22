use std::collections::HashMap;

use acta_crypto::{
    mint_signed_envelope, mint_tenant_api_key, normalize_github_slug, verify_pkce_s256,
    verify_signed_envelope, verify_tenant_api_key, TENANT_TOKEN_PREFIX,
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

use crate::state::AppState;

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
    // RFC 8252 §7.3: native loopback clients may bind an ephemeral port at authorize time.
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

    // CIMD (`client_id` is an `https://` metadata URL)
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

    // Public unregistered native MCP clients (Cursor, Claude Desktop/Code, Gemini CLI, MCP Inspector)
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
/// Implements RFC 9728 OAuth 2.0 Protected Resource Metadata for MCP discovery.
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
/// Implements RFC 8414 Authorization Server Metadata advertising OAuth 2.1 + PKCE S256 + DCR + CIMD.
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
    // Direct redirect when user clicks the "Sign in with GitHub" button on the consent screen
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

    // Control Plane UI sign-in (`scope=acta:ui`) routes straight back to `/` in 1 click
    // carrying all GitHub-verified vaults so the header Vault Switcher can toggle seamlessly.
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

    // Multiple GitHub organizations (e.g. consultant across multiple client orgs) -> 1-click picker!
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

    let resolved_tenant = if raw_key.starts_with(TENANT_TOKEN_PREFIX) {
        match verify_tenant_api_key(state.effective_token_secret(), raw_key) {
            Ok(locked) => {
                if !requested_tenant.is_empty() && requested_tenant != locked {
                    return render_oauth_error_html(
                        StatusCode::FORBIDDEN,
                        "Tenant Mismatch",
                        &format!(
                            "Provided acta_tk_v1 key is locked to '{locked}', not '{requested_tenant}'."
                        ),
                    );
                }
                locked
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
        match normalize_github_slug(requested_tenant) {
            Ok(slug) => slug,
            Err(_) => {
                return render_oauth_error_html(
                    StatusCode::BAD_REQUEST,
                    "Missing Organization / Tenant Slug",
                    "When signing in with a master key, enter the target org slug (e.g. ardyn-intelligence).",
                );
            }
        }
    };

    issue_auth_code_redirect(&state, &otx, &resolved_tenant, None, Vec::new())
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
/// Mints a stateless Keyed-BLAKE3 `acta_tk_v1:<github_org_slug>:<mac>` Bearer token!
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
    let Ok(access_token) = mint_tenant_api_key(secret, tenant_id) else {
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
                let tok = mint_tenant_api_key(secret, &opt.slug).ok()?;
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

    let github_section = if gh_enabled {
        format!(
            r#"<form method="GET" action="/oauth/authorize" style="margin-bottom:18px;">
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
    } else {
        format!(
            r#"<div class="setup-box">
  <div class="setup-title">1-Time GitHub OAuth App Setup (30 sec)</div>
  <p style="margin:6px 0 10px;color:#9fb0ca;font-size:12.5px;">
    Create a GitHub OAuth App at <code>github.com/settings/developers</code> with:
  </p>
  <div class="kv"><span>Homepage URL</span><code>{base_esc}</code></div>
  <div class="kv"><span>Callback URL</span><code>{base_esc}/oauth/github/callback</code></div>
  <p style="margin:10px 0 0;color:#9fb0ca;font-size:12px;">
    Until <code>GITHUB_CLIENT_ID</code> &amp; <code>GITHUB_CLIENT_SECRET</code> are set, you can authorize <strong>{client_esc}</strong> right below using your Acta key:
  </p>
</div>"#
        )
    };

    let details_open = if gh_enabled { "" } else { "open" };
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
  p.sub {{ margin:0 0 22px; color:#9fb0ca; font-size:13.5px; line-height:1.5; }}
  .btn-gh {{ width:100%; display:flex; align-items:center; justify-content:center; gap:10px; padding:13px 16px; background:#f3f6fb; color:#0b0f17; border:none; font-size:14.5px; font-weight:700; cursor:pointer; }}
  .btn-gh:hover {{ background:#ffffff; }}
  .chk {{ display:flex; align-items:center; gap:8px; margin-top:10px; font-size:12px; color:#9fb0ca; cursor:pointer; }}
  .setup-box {{ background:#090d14; border:1px solid #243046; padding:14px; margin-bottom:18px; }}
  .setup-title {{ font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:#ffb547; }}
  .kv {{ display:flex; flex-direction:column; gap:2px; margin-top:8px; font-size:11.5px; color:#9fb0ca; }}
  code {{ font-family:ui-monospace,monospace; color:#38e8ff; background:#0d1422; padding:4px 6px; word-break:break-all; }}
  details {{ border-top:1px solid #243046; padding-top:14px; margin-top:10px; }}
  summary {{ cursor:pointer; font-size:12.5px; color:#9fb0ca; font-weight:600; }}
  label.fld {{ display:block; font-size:11.5px; color:#9fb0ca; margin:12px 0 4px; text-transform:uppercase; letter-spacing:0.04em; }}
  input[type=text], input[type=password] {{ width:100%; box-sizing:border-box; background:#090d14; border:1px solid #243046; color:#f3f6fb; padding:9px 11px; font-family:ui-monospace,monospace; font-size:13px; }}
  .btn-sec {{ width:100%; margin-top:12px; padding:10px 14px; background:#162238; color:#f3f6fb; border:1px solid #38e8ff; font-weight:600; font-size:13px; cursor:pointer; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">ACTA MCP OAUTH 2.1 · PKCE S256</span>
    <h1>Connect {client_esc}</h1>
    <p class="sub">Sign in with GitHub to automatically bind <strong>{client_esc}</strong> to your GitHub Organization's cryptographic context vault.</p>
    {github_section}
    <details {details_open}>
      <summary>Or authorize with an Acta Key (acta_tk_v1 / Master Key)</summary>
      <form method="POST" action="/oauth/key-login">
        <input type="hidden" name="otx_token" value="{otx_esc}" />
        <label class="fld">Acta Key (acta_tk_v1:... or Master Key)</label>
        <input type="password" name="api_key" required placeholder="acta_tk_v1:ardyn-intelligence:..." />
        <label class="fld">GitHub Org / Tenant Slug (required only for Master Key)</label>
        <input type="text" name="tenant_id" placeholder="ardyn-intelligence" />
        <button type="submit" class="btn-sec">Authorize MCP Client</button>
      </form>
    </details>
  </div>
</body>
</html>"#
    );

    (StatusCode::OK, Html(html)).into_response()
}

fn render_org_picker_html(
    client_name: &str,
    github_login: &str,
    options: &[CandidateOrgOption],
    picker_token: &str,
) -> Response {
    let client_esc = html_escape(client_name);
    let login_esc = html_escape(github_login);
    let picker_esc = html_escape(picker_token);

    let mut buttons_html = String::new();
    for opt in options {
        let slug_esc = html_escape(&opt.slug);
        let label_esc = html_escape(&opt.label);
        let desc_esc = html_escape(&opt.description);
        let tag = if opt.kind == "github_org" {
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
<title>Select GitHub Organization — Acta Compiler</title>
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
    <span class="badge">GITHUB VERIFIED · @{login_esc}</span>
    <h1>Choose Organization Vault</h1>
    <p class="sub">Select which GitHub organization <strong>{client_esc}</strong> should lock its Keyed-BLAKE3 token to:</p>
    <form method="POST" action="/oauth/approve">
      <input type="hidden" name="picker_token" value="{picker_esc}" />
      {buttons_html}
    </form>
  </div>
</body>
</html>"#
    );

    (StatusCode::OK, Html(html)).into_response()
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
    (status, Html(html)).into_response()
}
