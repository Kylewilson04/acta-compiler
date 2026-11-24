use acta_crypto::{verify_export_archive, VerificationSummary};
use acta_store::evidence_repo;
use acta_types::{EvidenceEntry, ExportArchive, PolicyResultTag};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyArchiveRequest {
    pub archive: ExportArchive,
    #[serde(default)]
    pub expected_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyArchiveResponse {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<VerificationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_evidence_seq_num: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EvidenceQueryParams {
    pub from_seq: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantEvidenceResponse {
    pub tenant_id: String,
    pub host_public_key: String,
    pub total_count: usize,
    pub entry_count: usize,
    pub from_seq: i64,
    pub limit: i64,
    pub has_more: bool,
    pub next_seq: Option<i64>,
    pub entries: Vec<EvidenceEntry>,
}

/// `POST /v1/verify` -> verifies an `ExportArchive` cryptographically against `expected_pubkey_hex`
/// (logging a signed refusal entry with `RefusalMetadata` when verification fails).
pub async fn handle_verify_archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyArchiveRequest>,
) -> Result<(StatusCode, Json<VerifyArchiveResponse>), ApiError> {
    let expected_pk: [u8; 32] = match req.expected_pubkey_hex {
        Some(ref hex_str) if !hex_str.trim().is_empty() => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| ApiError::bad_request(format!("invalid expected_pubkey_hex: {e}")))?;
            bytes.try_into().map_err(|_| {
                ApiError::bad_request("expected_pubkey_hex must decode to 32 bytes (64 hex chars)")
            })?
        }
        _ => state.host_public_key,
    };

    match verify_export_archive(&req.archive, &expected_pk) {
        Ok(summary) => Ok((
            StatusCode::OK,
            Json(VerifyArchiveResponse {
                verified: true,
                summary: Some(summary),
                error: None,
                refusal_evidence_seq_num: None,
            }),
        )),
        Err(reason) => {
            let ev_seq = state
                .append_refusal_audit_with_scope(
                    &headers,
                    Some(&req.archive.bundle.tenant_id),
                    PolicyResultTag::Block,
                    "verify_archive",
                    "archive_verify_failed",
                    Some(&req.archive.bundle.scope),
                    &reason,
                )
                .await
                .map(|e| e.seq_num);
            Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(VerifyArchiveResponse {
                    verified: false,
                    summary: None,
                    error: Some(reason),
                    refusal_evidence_seq_num: ev_seq,
                }),
            ))
        }
    }
}

/// `GET /v1/tenants/:tenant_id/evidence?from_seq=1&limit=100` -> returns a paginated slice (`1..=500`,
/// default `limit = 100`) of the hash-chained `evidence_history` audit ledger for `tenant_id`.
pub async fn handle_tenant_evidence(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<EvidenceQueryParams>,
    headers: HeaderMap,
) -> Result<Json<TenantEvidenceResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "list_evidence")
        .await
        .map_err(ApiError::unauthorized)?;

    let from_seq = query.from_seq.unwrap_or(1);
    let limit = query.limit.unwrap_or(100);
    let (total_count, entries) = evidence_repo::fetch_tenant_evidence_page(
        &state.pool,
        clean_tenant,
        from_seq,
        limit,
        None,
    )
    .await?;

    let next_seq = match entries.last() {
        Some(last) if (last.seq_num as usize) < total_count => Some(last.seq_num + 1),
        None if total_count > 0 && (from_seq as usize) <= total_count => Some(from_seq),
        _ => None,
    };

    Ok(Json(TenantEvidenceResponse {
        tenant_id: clean_tenant.to_string(),
        host_public_key: hex::encode(state.host_public_key),
        total_count,
        entry_count: entries.len(),
        from_seq,
        limit,
        has_more: next_seq.is_some(),
        next_seq,
        entries,
    }))
}
