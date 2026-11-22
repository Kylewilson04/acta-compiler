use std::collections::HashMap;

use acta_store::{evidence_repo, overrides_repo};
use acta_types::{
    ContextBundle, EvidenceEntry, ExternalWitnessAnchor, ResolverManifest, SignedTreeHead,
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::AppState;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VaultQueryParams {
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VaultScopeSummary {
    pub scope: String,
    pub claim_count: i64,
    pub intent_count: i64,
    pub memory_count: i64,
    pub bundle_count: i64,
    pub latest_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct VaultClaimRow {
    id: Uuid,
    scope: String,
    subject: String,
    predicate: String,
    object_val: Value,
    object_type: String,
    confidence: f64,
    source_provenance_class: i32,
    source_descriptor: String,
    claim_group_key: Vec<u8>,
    content_hash: Vec<u8>,
    status: String,
    version: i32,
    predecessor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    is_superseded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultClaimItem {
    pub id: Uuid,
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub object_val: Value,
    pub object_type: String,
    pub confidence: f64,
    pub source_provenance_class: i32,
    pub source_descriptor: String,
    pub claim_group_key: String,
    pub content_hash: String,
    pub status: String,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub has_competing_peer: bool,
    pub is_superseded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct VaultObjectRow {
    id: Uuid,
    obj_type: String,
    scope: String,
    lifecycle_status: String,
    priority: i32,
    importance: f32,
    tags: Vec<String>,
    body: Value,
    content_hash: Vec<u8>,
    version: i32,
    predecessor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    is_superseded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultObjectItem {
    pub id: Uuid,
    pub obj_type: String,
    pub scope: String,
    pub lifecycle_status: String,
    pub priority: i32,
    pub importance: f32,
    pub tags: Vec<String>,
    pub body: Value,
    pub content_hash: String,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub is_superseded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct VaultBundleRow {
    bundle_hash: Vec<u8>,
    state_commitment: Vec<u8>,
    dependency_commitment: Vec<u8>,
    bundle_canonical: Vec<u8>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBundleItem {
    pub bundle_hash: String,
    pub scope: String,
    pub task_id: String,
    pub policy_result: String,
    pub state_commitment: String,
    pub dependency_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_manifest: Option<ResolverManifest>,
    pub selected_object_count: usize,
    pub resolution_count: usize,
    pub dispute_count: usize,
    pub omitted_count: usize,
    pub has_unresolved_claims: bool,
    pub issued_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultOverrideItem {
    pub id: Uuid,
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub winning_claim_id: Uuid,
    pub overridden_count: usize,
    pub adjudicator_id: String,
    pub justification: String,
    pub version: i32,
    pub attestation_hash: String,
    pub evidence_seq_num: i64,
    pub has_client_signature: bool,
    pub is_superseded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantVaultResponse {
    pub tenant_id: String,
    pub active_scope_filter: Option<String>,
    pub host_public_key: String,
    pub permission_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_checkpoint: Option<SignedTreeHead>,
    #[serde(default)]
    pub witness_anchors: Vec<ExternalWitnessAnchor>,
    pub scopes: Vec<VaultScopeSummary>,
    pub claims: Vec<VaultClaimItem>,
    pub objects: Vec<VaultObjectItem>,
    pub overrides: Vec<VaultOverrideItem>,
    pub bundles: Vec<VaultBundleItem>,
    pub evidence: Vec<EvidenceEntry>,
}

/// `GET /v1/tenants/:tenant_id/vault` -> Read-only Control Plane Vault Explorer endpoint.
pub async fn handle_tenant_vault(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<VaultQueryParams>,
    headers: HeaderMap,
) -> Result<Json<TenantVaultResponse>, ApiError> {
    let clean_tenant = tenant_id.trim();
    if clean_tenant.is_empty() {
        return Err(ApiError::bad_request("tenant_id must be non-empty"));
    }
    state
        .check_tenant_auth_audited(&headers, clean_tenant, "vault_explorer")
        .await
        .map_err(ApiError::unauthorized)?;

    let scope_filter = query
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let scopes_fut = sqlx::query_as::<_, VaultScopeSummary>(
        r#"
        WITH all_items AS (
            SELECT scope,
                   1::bigint AS claims,
                   0::bigint AS intents,
                   0::bigint AS memories,
                   0::bigint AS bundles,
                   created_at
            FROM knowledge_claims
            WHERE tenant_id = $1
            UNION ALL
            SELECT scope,
                   0::bigint AS claims,
                   CASE WHEN obj_type = 'intent' THEN 1::bigint ELSE 0::bigint END AS intents,
                   CASE WHEN obj_type = 'memory' THEN 1::bigint ELSE 0::bigint END AS memories,
                   0::bigint AS bundles,
                   created_at
            FROM objects
            WHERE tenant_id = $1
            UNION ALL
            SELECT COALESCE((convert_from(bundle_canonical, 'UTF8')::jsonb ->> 'scope'), 'unknown') AS scope,
                   0::bigint AS claims,
                   0::bigint AS intents,
                   0::bigint AS memories,
                   1::bigint AS bundles,
                   created_at
            FROM context_bundles
            WHERE tenant_id = $1
        )
        SELECT scope,
               SUM(claims)::bigint AS claim_count,
               SUM(intents)::bigint AS intent_count,
               SUM(memories)::bigint AS memory_count,
               SUM(bundles)::bigint AS bundle_count,
               MAX(created_at) AS latest_at
        FROM all_items
        GROUP BY scope
        ORDER BY MAX(created_at) DESC NULLS LAST, scope ASC
        "#,
    )
    .bind(clean_tenant)
    .fetch_all(&state.pool);

    let claims_fut = sqlx::query_as::<_, VaultClaimRow>(
        r#"
        SELECT c.id,
               c.scope,
               c.subject,
               c.predicate,
               c.object_val,
               c.object_type,
               c.confidence,
               c.source_provenance_class,
               c.source_descriptor,
               c.claim_group_key,
               c.content_hash,
               c.status,
               c.version,
               c.predecessor_id,
               c.created_at,
               EXISTS (
                   SELECT 1 FROM knowledge_claims c2
                   WHERE c2.tenant_id = c.tenant_id AND c2.predecessor_id = c.id
               ) AS is_superseded
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND ($2::text IS NULL OR c.scope = $2)
        ORDER BY c.created_at DESC, c.id ASC
        LIMIT 200
        "#,
    )
    .bind(clean_tenant)
    .bind(scope_filter.as_deref())
    .fetch_all(&state.pool);

    let objects_fut = sqlx::query_as::<_, VaultObjectRow>(
        r#"
        SELECT o.id,
               o.obj_type,
               o.scope,
               o.lifecycle_status,
               o.priority,
               o.importance,
               o.tags,
               o.body,
               o.content_hash,
               o.version,
               o.predecessor_id,
               o.created_at,
               EXISTS (
                   SELECT 1 FROM objects o2
                   WHERE o2.tenant_id = o.tenant_id AND o2.predecessor_id = o.id
               ) AS is_superseded
        FROM objects o
        WHERE o.tenant_id = $1
          AND ($2::text IS NULL OR o.scope = $2)
        ORDER BY CASE WHEN o.obj_type = 'intent' THEN 0 ELSE 1 END ASC,
                 o.priority DESC,
                 o.created_at DESC
        LIMIT 200
        "#,
    )
    .bind(clean_tenant)
    .bind(scope_filter.as_deref())
    .fetch_all(&state.pool);

    let bundles_fut = sqlx::query_as::<_, VaultBundleRow>(
        r#"
        SELECT bundle_hash, state_commitment, dependency_commitment, bundle_canonical, created_at
        FROM context_bundles
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(clean_tenant)
    .fetch_all(&state.pool);

    let overrides_fut = overrides_repo::fetch_tenant_overrides(
        &state.pool,
        clean_tenant,
        scope_filter.as_deref(),
    );
    let evidence_fut = evidence_repo::fetch_tenant_evidence_chain(&state.pool, clean_tenant, None);
    let cp_fut = evidence_repo::build_signed_tree_head(
        &state.pool,
        &state.host_signing_key,
        clean_tenant,
        None,
    );
    let anchors_fut = evidence_repo::fetch_recent_witness_anchors(&state.pool, clean_tenant);

    let (
        scopes_res,
        claims_res,
        objects_res,
        overrides_res,
        bundles_res,
        evidence_res,
        cp_res,
        anchors_res,
    ) = tokio::join!(
        scopes_fut,
        claims_fut,
        objects_fut,
        overrides_fut,
        bundles_fut,
        evidence_fut,
        cp_fut,
        anchors_fut,
    );

    let scopes = scopes_res
        .map_err(|e| ApiError::bad_request(format!("vault scopes query failed: {e}")))?;
    let claim_rows = claims_res
        .map_err(|e| ApiError::bad_request(format!("vault claims query failed: {e}")))?;
    let object_rows = objects_res
        .map_err(|e| ApiError::bad_request(format!("vault objects query failed: {e}")))?;
    let override_pairs = overrides_res?;
    let bundle_rows = bundles_res
        .map_err(|e| ApiError::bad_request(format!("vault bundles query failed: {e}")))?;
    let evidence = evidence_res?;
    let latest_checkpoint = cp_res?.map(|(sth, _)| sth);
    let witness_anchors = anchors_res?;

    let mut distinct_vals_by_slot: HashMap<(String, String, String), Vec<String>> = HashMap::new();
    let mut seen_source_head: HashMap<(String, String, String, String), ()> = HashMap::new();
    for r in &claim_rows {
        if r.status == "active" && !r.is_superseded {
            let src_key = (
                r.scope.clone(),
                r.subject.clone(),
                r.predicate.clone(),
                r.source_descriptor.clone(),
            );
            if seen_source_head.contains_key(&src_key) {
                continue;
            }
            seen_source_head.insert(src_key, ());
            let val_s = r.object_val.to_string();
            let entry = distinct_vals_by_slot
                .entry((r.scope.clone(), r.subject.clone(), r.predicate.clone()))
                .or_default();
            if !entry.contains(&val_s) {
                entry.push(val_s);
            }
        }
    }

    let claims = claim_rows
        .into_iter()
        .map(|r| {
            let competing = distinct_vals_by_slot
                .get(&(r.scope.clone(), r.subject.clone(), r.predicate.clone()))
                .map(|v| v.len() > 1)
                .unwrap_or(false);
            VaultClaimItem {
                id: r.id,
                scope: r.scope,
                subject: r.subject,
                predicate: r.predicate,
                object_val: r.object_val,
                object_type: r.object_type,
                confidence: r.confidence,
                source_provenance_class: r.source_provenance_class,
                source_descriptor: r.source_descriptor,
                claim_group_key: hex::encode(&r.claim_group_key),
                content_hash: hex::encode(&r.content_hash),
                status: r.status,
                version: r.version,
                predecessor_id: r.predecessor_id,
                has_competing_peer: competing,
                is_superseded: r.is_superseded,
                created_at: r.created_at,
            }
        })
        .collect();

    let objects = object_rows
        .into_iter()
        .map(|r| VaultObjectItem {
            id: r.id,
            obj_type: r.obj_type,
            scope: r.scope,
            lifecycle_status: r.lifecycle_status,
            priority: r.priority,
            importance: r.importance,
            tags: r.tags,
            body: r.body,
            content_hash: hex::encode(&r.content_hash),
            version: r.version,
            predecessor_id: r.predecessor_id,
            is_superseded: r.is_superseded,
            created_at: r.created_at,
        })
        .collect();

    let overrides = override_pairs
        .into_iter()
        .map(|(a, is_sup)| VaultOverrideItem {
            id: a.id,
            scope: a.scope,
            subject: a.subject,
            predicate: a.predicate,
            winning_claim_id: a.winning_claim_id,
            overridden_count: a.overridden_claims.len(),
            adjudicator_id: a.adjudicator_id,
            justification: a.justification,
            version: a.version,
            attestation_hash: hex::encode(a.attestation_hash),
            evidence_seq_num: a.evidence_seq_num,
            has_client_signature: a.client_signature.is_some(),
            is_superseded: is_sup,
            created_at: a.created_at,
        })
        .collect();

    let mut bundles = Vec::new();
    for r in bundle_rows {
        if let Ok(b) = serde_json::from_slice::<ContextBundle>(&r.bundle_canonical) {
            if let Some(ref sf) = scope_filter {
                if &b.scope != sf {
                    continue;
                }
            }
            bundles.push(VaultBundleItem {
                bundle_hash: hex::encode(&r.bundle_hash),
                scope: b.scope,
                task_id: b.task_id,
                policy_result: b.policy_result.as_str().to_string(),
                state_commitment: hex::encode(&r.state_commitment),
                dependency_commitment: hex::encode(&r.dependency_commitment),
                resolver_manifest: b.resolver_manifest,
                selected_object_count: b.selected_objects.len(),
                resolution_count: b.resolution_records.len(),
                dispute_count: b.dispute_records.len(),
                omitted_count: b.omission_record.total_omitted_count,
                has_unresolved_claims: b.omission_record.has_unresolved_claims,
                issued_at: b.issued_at,
                created_at: r.created_at,
            });
            if bundles.len() >= 50 {
                break;
            }
        }
    }

    Ok(Json(TenantVaultResponse {
        tenant_id: clean_tenant.to_string(),
        active_scope_filter: scope_filter,
        host_public_key: hex::encode(state.host_public_key),
        permission_root: hex::encode(state.policy_gate.permission_root()),
        latest_checkpoint,
        witness_anchors,
        scopes,
        claims,
        objects,
        overrides,
        bundles,
        evidence,
    }))
}
