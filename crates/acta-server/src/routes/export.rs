use std::collections::BTreeSet;

use acta_store::{claims_repo, evidence_repo, objects_repo, overrides_repo};
use acta_types::{ExportArchive, PolicyResultTag};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::AppState;

/// Reusable export builder shared by `GET /v1/bundles/:bundle_hash/export` and `/mcp`.
pub async fn build_export_archive(
    state: &AppState,
    bundle_hash_hex: &str,
    headers: Option<&HeaderMap>,
) -> Result<ExportArchive, ApiError> {
    let raw_hash = match hex::decode(bundle_hash_hex.trim()) {
        Ok(h) => h,
        Err(e) => {
            let mut suffix = String::new();
            if let Some(hdrs) = headers {
                if let Some(ev) = state
                    .append_refusal_audit_with_scope(
                        hdrs,
                        None,
                        PolicyResultTag::Block,
                        "verify_bundle",
                        "verify_malformed_bundle_hash",
                        None,
                        &format!("invalid bundle_hash hex '{bundle_hash_hex}': {e}"),
                    )
                    .await
                {
                    suffix = format!(" [logged at evidence seq_num={}]", ev.seq_num);
                }
            }
            return Err(ApiError::bad_request(format!(
                "invalid bundle_hash hex: {e}{suffix}"
            )));
        }
    };
    let bundle_hash: [u8; 32] = match raw_hash.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let mut suffix = String::new();
            if let Some(hdrs) = headers {
                if let Some(ev) = state
                    .append_refusal_audit_with_scope(
                        hdrs,
                        None,
                        PolicyResultTag::Block,
                        "verify_bundle",
                        "verify_invalid_bundle_hash_len",
                        None,
                        &format!("bundle_hash '{bundle_hash_hex}' is not 32 bytes"),
                    )
                    .await
                {
                    suffix = format!(" [logged at evidence seq_num={}]", ev.seq_num);
                }
            }
            return Err(ApiError::bad_request(format!(
                "bundle_hash path parameter must be 32 bytes (64 hex chars){suffix}"
            )));
        }
    };

    let (bundle, evidence_chain) = match evidence_repo::fetch_bundle_with_evidence_slice(
        &state.pool,
        &bundle_hash,
    )
    .await
    {
        Ok(pair) => pair,
        Err(err) => {
            let mut api_err: ApiError = err.into();
            if let Some(hdrs) = headers {
                if let Some(ev) = state
                    .append_refusal_audit_with_scope(
                        hdrs,
                        None,
                        PolicyResultTag::Block,
                        "verify_bundle",
                        "verify_bundle_not_found",
                        None,
                        &api_err.message,
                    )
                    .await
                {
                    api_err.message =
                        format!("{} [logged at evidence seq_num={}]", api_err.message, ev.seq_num);
                }
            }
            return Err(api_err);
        }
    };

    if let Some(hdrs) = headers {
        state
            .check_tenant_auth_audited(hdrs, &bundle.tenant_id, "export_or_verify_bundle")
            .await
            .map_err(ApiError::unauthorized)?;
    }

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
        host_public_key: state.host_public_key,
    })
}

/// `GET /v1/bundles/:bundle_hash/export` -> packages a self-contained `ExportArchive`.
pub async fn handle_export_bundle(
    State(state): State<AppState>,
    Path(bundle_hash_hex): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ExportArchive>, ApiError> {
    let archive = build_export_archive(&state, &bundle_hash_hex, Some(&headers)).await?;
    Ok(Json(archive))
}
