pub mod answers;
pub mod auth;
pub mod checkpoints;
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
use serde_json::{json, Value};

use crate::state::AppState;

/// Hard 512 KiB HTTP request body limit protecting sidecar memory against oversized payloads.
pub const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub reason_code: Option<String>,
    pub signing_domain: Option<String>,
    pub expected_intent_digest_hex: Option<String>,
    pub refusal_evidence_seq_num: Option<i64>,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
            reason_code: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num: None,
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
            reason_code: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num: None,
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
            reason_code: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num: None,
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
            reason_code: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num: None,
        }
    }

    pub fn refusal(
        status: StatusCode,
        base_msg: impl Into<String>,
        reason_code: &str,
        refusal_evidence_seq_num: Option<i64>,
    ) -> Self {
        let base = base_msg.into();
        let seq_suffix = refusal_evidence_seq_num
            .map(|n| format!(" seq_num={n}"))
            .unwrap_or_default();
        Self {
            status,
            message: format!("{base} [reason_code={reason_code}{seq_suffix}]"),
            reason_code: Some(reason_code.to_string()),
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num,
        }
    }

    pub fn signature_refusal(
        status: StatusCode,
        base_msg: impl Into<String>,
        reason_code: &str,
        signing_domain: &str,
        expected_intent_digest: [u8; 32],
        refusal_evidence_seq_num: Option<i64>,
    ) -> Self {
        let base = base_msg.into();
        let digest_hex = hex::encode(expected_intent_digest);
        let seq_suffix = refusal_evidence_seq_num
            .map(|n| format!(" seq_num={n}"))
            .unwrap_or_default();
        let formatted = format!(
            "{base} [reason_code={reason_code} signing_domain={signing_domain} expected_intent_digest_hex={digest_hex}{seq_suffix}]"
        );
        Self {
            status,
            message: formatted,
            reason_code: Some(reason_code.to_string()),
            signing_domain: Some(signing_domain.to_string()),
            expected_intent_digest_hex: Some(digest_hex),
            refusal_evidence_seq_num,
        }
    }

    pub fn to_json_body(&self) -> Value {
        let mut obj = json!({
            "error": self.message,
        });
        if let Some(ref rc) = self.reason_code {
            obj["reason_code"] = json!(rc);
        }
        if let Some(ref dom) = self.signing_domain {
            obj["signing_domain"] = json!(dom);
        }
        if let Some(ref dig) = self.expected_intent_digest_hex {
            obj["expected_intent_digest_hex"] = json!(dig);
        }
        if let Some(seq) = self.refusal_evidence_seq_num {
            obj["refusal_evidence_seq_num"] = json!(seq);
        }
        obj
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
            ActaError::BundleStaleAtCacheTime(_) => StatusCode::CONFLICT,
            ActaError::PolicyEngine(_) | ActaError::Crypto(_) | ActaError::Storage(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ActaError::VerificationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        Self {
            status,
            message: err.to_string(),
            reason_code: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
            refusal_evidence_seq_num: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = self.to_json_body();
        (self.status, Json(body)).into_response()
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui::handle_index_ui))
        .route("/signup", get(oauth::handle_signup_page))
        .route("/signup/send", post(oauth::handle_signup_email_send))
        .route("/signup/verify", post(oauth::handle_signup_email_verify))
        .route("/signup/unsubscribe", get(oauth::handle_signup_unsubscribe).post(oauth::handle_signup_unsubscribe))
        .route("/v1/admin/signups", get(oauth::handle_admin_list_signups))
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
        .route("/oauth/email/send", post(oauth::handle_oauth_email_send))
        .route("/oauth/email/verify", post(oauth::handle_oauth_email_verify))
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
        .route("/v1/witnesses", post(checkpoints::handle_register_witness))
        .route(
            "/v1/witnesses/revoke",
            post(checkpoints::handle_revoke_witness),
        )
        .route("/v1/anchors", post(checkpoints::handle_anchor_checkpoint))
        .route("/v1/answers/cache", post(answers::handle_cache_answer))
        .route(
            "/v1/answers/lookup",
            post(answers::handle_lookup_cached_answer),
        )
        .route(
            "/v1/tenants/:tenant_id/overrides",
            get(overrides::handle_list_overrides),
        )
        .route(
            "/v1/tenants/:tenant_id/checkpoint",
            get(checkpoints::handle_get_checkpoint),
        )
        .route(
            "/v1/tenants/:tenant_id/witnesses",
            get(checkpoints::handle_list_witnesses),
        )
        .route(
            "/v1/tenants/:tenant_id/anchors",
            get(checkpoints::handle_list_anchors),
        )
        .route(
            "/v1/tenants/:tenant_id/impact/:item_id",
            get(answers::handle_trace_item_impact),
        )
        .route(
            "/v1/tenants/:tenant_id/state-rebuild",
            get(answers::handle_rebuild_scope_state),
        )
        .route(
            "/v1/tenants/:tenant_id/backfill-legacy-scope",
            post(answers::handle_backfill_legacy_scope),
        )
        .route(
            "/v1/tenants/:tenant_id/claims/:claim_id/secret",
            get(ingest::handle_get_claim_secret),
        )
        .route(
            "/v1/admin/rotate-host-key",
            post(answers::handle_rotate_host_key),
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
        .route("/v1/claims/retract", post(ingest::handle_retract_claim))
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
