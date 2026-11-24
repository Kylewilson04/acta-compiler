use std::collections::BTreeSet;

use acta_store::{
    claims_repo,
    evidence_repo::{self, TenantLookupScope},
    objects_repo, overrides_repo,
};
use acta_types::ExportArchive;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, BundleTenantFilter};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExportQueryParams {
    pub mode: Option<String>,
    pub tenant_id: Option<String>,
    pub anchor_tree_size: Option<i64>,
    pub anchored_tree_size: Option<i64>,
}

impl ExportQueryParams {
    pub fn resolved_anchor_tree_size(&self) -> Result<Option<i64>, ApiError> {
        match (self.anchor_tree_size, self.anchored_tree_size) {
            (Some(a), Some(b)) if a != b => Err(ApiError::bad_request(format!(
                "conflicting anchor_tree_size ({a}) and anchored_tree_size ({b}); pass one or matching values"
            ))),
            (a, b) => Ok(a.or(b)),
        }
    }
}

/// Builds an `ExportArchive` enforcing zero-oracle tenant scoping (`v1.6.7+`) and never mutating
/// `evidence_history` on malformed hex, wrong-length hex, `not_found`, or selector validation errors.
pub async fn build_export_archive_scoped(
    state: &AppState,
    bundle_hash_hex: &str,
    headers: Option<&HeaderMap>,
    explicit_tenant: Option<&str>,
    is_mcp: bool,
    include_full_chain: bool,
    anchor_tree_size: Option<i64>,
) -> Result<ExportArchive, ApiError> {
    let filter = match headers {
        Some(hdrs) => state
            .resolve_bundle_lookup_scope(hdrs, explicit_tenant, "export_or_verify_bundle", is_mcp)
            .await
            .map_err(ApiError::unauthorized)?,
        None => BundleTenantFilter::UnrestrictedMaster,
    };

    let raw_hash = hex::decode(bundle_hash_hex.trim())
        .map_err(|e| ApiError::bad_request(format!("invalid bundle_hash hex: {e}")))?;
    let bundle_hash: [u8; 32] = raw_hash.try_into().map_err(|_| {
        ApiError::bad_request("bundle_hash path parameter must be 32 bytes (64 hex chars)")
    })?;

    let lookup_scope = match &filter {
        BundleTenantFilter::ExactTenant(tid) => TenantLookupScope::Exact(tid.as_str()),
        BundleTenantFilter::SandboxPrefix(pfx) => TenantLookupScope::SandboxPrefix(pfx.as_str()),
        BundleTenantFilter::UnrestrictedMaster => TenantLookupScope::Any,
    };

    let (bundle, evidence_chain, merkle_proof) =
        evidence_repo::fetch_bundle_with_merkle_options_scoped(
            &state.pool,
            &state.host_signing_key,
            lookup_scope,
            &bundle_hash,
            &[],
            include_full_chain,
            anchor_tree_size,
        )
        .await?;

    let object_ids: Vec<Uuid> = bundle
        .selected_objects
        .iter()
        .map(|o| o.id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut claim_id_set = BTreeSet::new();
    let mut override_id_set = BTreeSet::new();
    for res in &bundle.resolution_records {
        claim_id_set.insert(res.winning_claim.id);
        if let Some(ref ovr) = res.override_attestation {
            override_id_set.insert(ovr.attestation_id);
        }
    }
    for disp in &bundle.dispute_records {
        for cand in &disp.competing_claims {
            claim_id_set.insert(cand.id);
        }
        if let Some(ref lapsed) = disp.lapsed_override {
            override_id_set.insert(lapsed.attestation_id);
        }
    }
    let claim_ids: Vec<Uuid> = claim_id_set.into_iter().collect();
    let override_ids: Vec<Uuid> = override_id_set.into_iter().collect();

    let (objects, claims, override_attestations) = tokio::try_join!(
        objects_repo::fetch_objects_by_ids(&state.pool, &bundle.tenant_id, &object_ids),
        claims_repo::fetch_claims_by_ids(&state.pool, &bundle.tenant_id, &claim_ids),
        overrides_repo::fetch_overrides_by_ids(&state.pool, &bundle.tenant_id, &override_ids),
    )?;

    Ok(ExportArchive {
        bundle_hash,
        bundle,
        objects,
        claims,
        override_attestations,
        evidence_chain,
        merkle_proof: Some(merkle_proof),
        host_public_key: state.host_public_key,
    })
}

/// Builds an `ExportArchive` with configurable linear-chain mode AND optional forward
/// cross-checkpoint bridging (`anchor_tree_size`).
pub async fn build_export_archive_with_options(
    state: &AppState,
    bundle_hash_hex: &str,
    headers: Option<&HeaderMap>,
    include_full_chain: bool,
    anchor_tree_size: Option<i64>,
) -> Result<ExportArchive, ApiError> {
    build_export_archive_scoped(
        state,
        bundle_hash_hex,
        headers,
        None,
        false,
        include_full_chain,
        anchor_tree_size,
    )
    .await
}

/// Builds an `ExportArchive` with automatic latest-anchored checkpoint bridging when applicable.
pub async fn build_export_archive_with_mode(
    state: &AppState,
    bundle_hash_hex: &str,
    headers: Option<&HeaderMap>,
    include_full_chain: bool,
) -> Result<ExportArchive, ApiError> {
    build_export_archive_with_options(state, bundle_hash_hex, headers, include_full_chain, None)
        .await
}

/// Default export builder embedding both full `evidence_chain` and `merkle_proof`.
pub async fn build_export_archive(
    state: &AppState,
    bundle_hash_hex: &str,
    headers: Option<&HeaderMap>,
) -> Result<ExportArchive, ApiError> {
    build_export_archive_with_mode(state, bundle_hash_hex, headers, true).await
}

/// `GET /v1/bundles/:bundle_hash/export?mode=full|merkle&anchor_tree_size=N` -> packages a self-contained `ExportArchive`.
pub async fn handle_export_bundle(
    State(state): State<AppState>,
    Path(bundle_hash_hex): Path<String>,
    Query(query): Query<ExportQueryParams>,
    headers: HeaderMap,
) -> Result<Json<ExportArchive>, ApiError> {
    let include_full_chain = match query.mode.as_deref().map(str::trim) {
        None | Some("") | Some("full") => true,
        Some("merkle") => false,
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "unsupported export mode '{other}' (expected 'full' or 'merkle')"
            )))
        }
    };
    let resolved_anchor = query.resolved_anchor_tree_size()?;
    let archive = build_export_archive_scoped(
        &state,
        &bundle_hash_hex,
        Some(&headers),
        query.tenant_id.as_deref(),
        false,
        include_full_chain,
        resolved_anchor,
    )
    .await?;
    Ok(Json(archive))
}
