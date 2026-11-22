use acta_crypto::{mint_tenant_api_key, mint_user_tenant_api_key, normalize_github_slug};
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::ApiError;
use crate::state::{AppState, VerifiedKeyInfo};

#[derive(Debug, Clone, Deserialize)]
pub struct MintTenantKeyRequest {
    pub tenant_id: String,
    #[serde(default)]
    pub principal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintTenantKeyResponse {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_principal: Option<String>,
    pub tenant_api_key: String,
    pub token_scheme: String,
    pub mcp_headers: Value,
}

/// `POST /v1/auth/mint-tenant-key` -> mints a stateless Keyed-BLAKE3 `acta_tk_v1:<tenant_id>[:<principal>]:<mac>`
/// key strictly bound to `tenant_id` (and optionally a verified principal). Requires the master `ACTA_API_KEY`.
pub async fn handle_mint_tenant_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MintTenantKeyRequest>,
) -> Result<Json<MintTenantKeyResponse>, ApiError> {
    let master = state
        .check_master_admin_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    let clean_tenant = req.tenant_id.trim().to_string();
    let (token, verified_principal, scheme) = match req
        .principal
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(p) => {
            let norm = normalize_github_slug(p)?;
            let tok = mint_user_tenant_api_key(master, &clean_tenant, &norm)?;
            (tok, Some(norm), "blake3-keyed-user-mac-v2".to_string())
        }
        None => {
            let tok = mint_tenant_api_key(master, &clean_tenant)?;
            (tok, None, "blake3-keyed-mac-v1".to_string())
        }
    };

    Ok(Json(MintTenantKeyResponse {
        tenant_id: clean_tenant.clone(),
        verified_principal,
        tenant_api_key: token.clone(),
        token_scheme: scheme,
        mcp_headers: json!({
            "Authorization": format!("Bearer {token}"),
            "X-Acta-Tenant": clean_tenant,
        }),
    }))
}

/// `GET /v1/auth/inspect-key` -> verifies caller credentials and reports active tenant + principal lock.
pub async fn handle_inspect_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let info = state
        .inspect_caller_auth(&headers)
        .map_err(ApiError::unauthorized)?;

    let body = match info {
        VerifiedKeyInfo::TenantBound {
            locked_tenant,
            verified_principal,
        } => json!({
            "valid": true,
            "key_kind": if verified_principal.is_some() { "oauth_user_tenant_bound" } else { "tenant_bound" },
            "locked_tenant": locked_tenant,
            "verified_principal": verified_principal,
        }),
        VerifiedKeyInfo::Master {
            header_locked_tenant,
        } => json!({
            "valid": true,
            "key_kind": "master",
            "locked_tenant": header_locked_tenant,
        }),
        VerifiedKeyInfo::Anonymous {
            header_locked_tenant,
        } => json!({
            "valid": true,
            "key_kind": "anonymous_sandbox",
            "locked_tenant": header_locked_tenant,
            "public_sandbox_prefix": state.public_sandbox_prefix,
        }),
    };
    Ok(Json(body))
}
