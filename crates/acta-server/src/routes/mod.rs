pub mod auth;
pub mod compile;
pub mod export;
pub mod ingest;
pub mod mcp;
pub mod oauth;
pub mod overrides;
pub mod replay;
pub mod ui;
pub mod vault;
pub mod verify;

use acta_types::ActaError;
use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::state::AppState;

/// Hard 512 KiB HTTP request body limit protecting sidecar memory against oversized payloads.
pub const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
        }
    }
}

impl From<ActaError> for ApiError {
    fn from(err: ActaError) -> Self {
        let status = match err {
            ActaError::PolicyDenied(_) => StatusCode::FORBIDDEN,
            ActaError::PolicyEscalated(_) => StatusCode::ACCEPTED,
            ActaError::BudgetInsufficientForDisputes(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ActaError::Validation(_) => StatusCode::BAD_REQUEST,
            ActaError::NotFound(_) => StatusCode::NOT_FOUND,
            ActaError::PolicyEngine(_) | ActaError::Crypto(_) | ActaError::Storage(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ActaError::VerificationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        Self {
            status,
            message: err.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui::handle_index_ui))
        .route("/health", get(compile::handle_health))
        .route("/v1/health", get(compile::handle_health))
        .route("/healthz", get(compile::handle_health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::handle_protected_resource_metadata).options(oauth::handle_oauth_preflight),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::handle_protected_resource_metadata).options(oauth::handle_oauth_preflight),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::handle_authorization_server_metadata).options(oauth::handle_oauth_preflight),
        )
        .route(
            "/.well-known/openid-configuration",
            get(oauth::handle_authorization_server_metadata).options(oauth::handle_oauth_preflight),
        )
        .route(
            "/oauth/register",
            post(oauth::handle_register_client).options(oauth::handle_oauth_preflight),
        )
        .route("/oauth/authorize", get(oauth::handle_authorize))
        .route(
            "/oauth/github/callback",
            get(oauth::handle_github_callback),
        )
        .route("/oauth/approve", post(oauth::handle_approve_org))
        .route("/oauth/key-login", post(oauth::handle_key_login))
        .route(
            "/oauth/token",
            post(oauth::handle_token).options(oauth::handle_oauth_preflight),
        )
        .route(
            "/v1/auth/mint-tenant-key",
            post(auth::handle_mint_tenant_key),
        )
        .route("/v1/auth/inspect-key", get(auth::handle_inspect_key))
        .route("/v1/compile", post(compile::handle_compile))
        .route("/v1/replay", post(replay::handle_replay))
        .route("/v1/verify", post(verify::handle_verify_archive))
        .route("/v1/overrides", post(overrides::handle_attest_override))
        .route(
            "/v1/tenants/:tenant_id/overrides",
            get(overrides::handle_list_overrides),
        )
        .route(
            "/v1/tenants/:tenant_id/vault",
            get(vault::handle_tenant_vault),
        )
        .route(
            "/v1/tenants/:tenant_id/evidence",
            get(verify::handle_tenant_evidence),
        )
        .route("/v1/objects", post(ingest::handle_ingest_object))
        .route("/v1/claims", post(ingest::handle_ingest_claim))
        .route(
            "/v1/bundles/:bundle_hash/export",
            get(export::handle_export_bundle),
        )
        .route(
            "/mcp",
            get(mcp::handle_mcp_info)
                .post(mcp::handle_mcp_rpc)
                .delete(mcp::handle_mcp_delete)
                .options(oauth::handle_oauth_preflight),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}
