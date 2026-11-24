use acta_types::{
    validate_budget, validate_identifier, validate_query_text, validate_scope, CompileRequest,
    CompileResponse, PolicyDecision,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

use crate::routes::ApiError;
use crate::state::AppState;

/// `POST /v1/compile` -> authorizes tenant access, validates bounds, and invokes `CompilePipeline::compile`.
pub async fn handle_compile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CompileRequest>,
) -> Result<(StatusCode, Json<CompileResponse>), ApiError> {
    if req.tenant_id.trim().is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, &req.tenant_id, "compile")
        .await
        .map_err(ApiError::unauthorized)?;

    validate_identifier("tenant_id", &req.tenant_id)?;
    validate_identifier("actor_id", &req.actor_id)?;
    validate_identifier("task_id", &req.task_id)?;
    validate_scope(&req.scope)?;
    validate_query_text(&req.query_text)?;
    validate_budget(req.budget)?;

    if let Some(ref emb) = req.query_embedding {
        if emb.len() != 1536 {
            return Err(ApiError::bad_request(
                "query_embedding must have exactly 1536 dimensions",
            ));
        }
        if emb.iter().any(|x| !x.is_finite()) {
            return Err(ApiError::bad_request(
                "query_embedding values must be finite",
            ));
        }
    }

    let response = state.pipeline.compile(req).await?;
    let status = match response.policy_decision {
        PolicyDecision::Allow => StatusCode::OK,
        PolicyDecision::Block { .. } => StatusCode::FORBIDDEN,
        PolicyDecision::Escalate { .. } => StatusCode::ACCEPTED,
    };

    Ok((status, Json(response)))
}

/// `GET /health` & `GET /v1/health` (non-`z` paths so Google Cloud Run GFE forwards requests cleanly).
pub async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "service": "acta-compiler",
                "version": "1.7.2",
                "host_public_key": hex::encode(state.host_public_key),
                "permission_root": hex::encode(state.policy_gate.permission_root()),
                "auth_mode": if state.api_key.is_some() { "mcp_oauth21_github_and_blake3_mac" } else { "open" },
                "github_oauth_enabled": state.oauth.github_enabled(),
                "tenant_isolation": "acta_tk_v1_user_mac_and_x_acta_tenant",
                "merkle_checkpoint_scheme": "rfc6962-sha256-v1",
                "public_sandbox_prefix": state.public_sandbox_prefix,
            })),
        ),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "error": err.to_string(),
            })),
        ),
    }
}
