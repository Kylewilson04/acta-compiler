use std::collections::BTreeMap;

use acta_engine::{compute_resolution_changed, CompileSimulation, ResolverConfig};
use acta_policy::PolicyGate;
use acta_types::{
    validate_budget, validate_identifier, validate_query_text, validate_scope, CompileRequest,
    PolicyDecision, PolicyResultTag, ResolverManifest,
};
use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayRequest {
    pub request: CompileRequest,
    #[serde(default)]
    pub counterfactual_evaluation_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub override_min_confidence: Option<f64>,
    #[serde(default)]
    pub override_decisiveness_threshold: Option<f64>,
    #[serde(default)]
    pub override_policy_cedar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBranchSummary {
    pub policy_decision: PolicyDecision,
    pub permission_root: String,
    pub reproducing_resolver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_resolver_version: Option<String>,
    pub resolver_compat: String,
    pub bundle_hash: Option<String>,
    pub state_commitment: Option<String>,
    pub dependency_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_manifest: Option<ResolverManifest>,
    pub selected_object_count: usize,
    pub resolution_count: usize,
    pub dispute_count: usize,
    pub omitted_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_facts_omitted: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_token_count: Option<usize>,
    pub context_text: Option<String>,
}

impl From<CompileSimulation> for ReplayBranchSummary {
    fn from(sim: CompileSimulation) -> Self {
        let (
            state_commitment,
            dependency_commitment,
            resolver_manifest,
            selected_object_count,
            resolution_count,
            dispute_count,
            omitted_count,
            resolved_facts_omitted,
        ) = match &sim.bundle {
            Some(b) => (
                Some(hex::encode(b.state_commitment)),
                Some(hex::encode(b.dependency_commitment)),
                b.resolver_manifest.clone(),
                b.selected_objects.len(),
                b.resolution_records.len(),
                b.dispute_records.len(),
                b.omission_record.total_omitted_count,
                b.resolved_facts_omitted,
            ),
            None => (None, None, None, 0, 0, 0, 0, None),
        };

        let recorded_resolver_version = resolver_manifest
            .as_ref()
            .and_then(|m| m.resolver_version.clone());
        Self {
            policy_decision: sim.policy_decision,
            permission_root: hex::encode(sim.permission_root),
            reproducing_resolver: "v173_current".to_string(),
            recorded_resolver_version,
            resolver_compat: "v173_current".to_string(),
            bundle_hash: sim.bundle_hash.map(hex::encode),
            state_commitment,
            dependency_commitment,
            resolver_manifest,
            selected_object_count,
            resolution_count,
            dispute_count,
            omitted_count,
            resolved_facts_omitted,
            context_token_count: sim.context_token_count,
            context_text: sim.context_text,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiff {
    pub bundle_hash_changed: bool,
    pub state_commitment_changed: bool,
    pub resolution_changed: bool,
    pub policy_decision_changed: bool,
    pub dispute_delta: isize,
    pub resolution_delta: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    pub baseline: ReplayBranchSummary,
    pub counterfactual: ReplayBranchSummary,
    pub diff: ReplayDiff,
    #[serde(default)]
    pub evidence_ledger_mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_evidence_seq_num: Option<i64>,
}

/// `POST /v1/replay` -> executes read-only baseline vs counterfactual compilation without
/// appending entries to `evidence_history` on `Allow`, while logging signed refusal evidence
/// with auditor-readable `RefusalMetadata` when targeting a blocked or restricted scope.
pub async fn handle_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, ApiError> {
    if req.request.tenant_id.trim().is_empty()
        || req.request.actor_id.trim().is_empty()
        || req.request.scope.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "request.tenant_id, request.actor_id, and request.scope must be non-empty",
        ));
    }
    state
        .check_tenant_auth_audited(&headers, &req.request.tenant_id, "replay")
        .await
        .map_err(ApiError::unauthorized)?;

    validate_identifier("request.tenant_id", &req.request.tenant_id)?;
    validate_identifier("request.actor_id", &req.request.actor_id)?;
    validate_identifier("request.task_id", &req.request.task_id)?;
    validate_scope(&req.request.scope)?;
    validate_query_text(&req.request.query_text)?;
    validate_budget(req.request.budget)?;

    if let Some(c) = req.override_min_confidence {
        if !c.is_finite() || !(0.0..=1.0).contains(&c) {
            return Err(ApiError::bad_request(
                "override_min_confidence must be in [0.0, 1.0]",
            ));
        }
    }
    if let Some(d) = req.override_decisiveness_threshold {
        if !d.is_finite() || !(0.0..=1.0).contains(&d) {
            return Err(ApiError::bad_request(
                "override_decisiveness_threshold must be in [0.0, 1.0]",
            ));
        }
    }

    let tenant_for_audit = req.request.tenant_id.clone();
    let scope_for_audit = req.request.scope.clone();

    let mut base_req = req.request.clone();
    base_req.evaluation_time = req.request.evaluation_time.map(|t| t.trunc_subsecs(6));

    let mut cf_req = req.request;
    cf_req.evaluation_time = req
        .counterfactual_evaluation_time
        .or(base_req.evaluation_time)
        .map(|t| t.trunc_subsecs(6));

    let custom_gate = match req.override_policy_cedar {
        Some(ref cedar_src) if !cedar_src.trim().is_empty() => {
            Some(PolicyGate::from_policy_str(cedar_src, BTreeMap::new())?)
        }
        _ => None,
    };

    let base_resolver = state.pipeline.config().resolver.clone();
    let cf_resolver = ResolverConfig {
        min_confidence: req.override_min_confidence.unwrap_or(base_resolver.min_confidence),
        decisiveness_threshold: req
            .override_decisiveness_threshold
            .unwrap_or(base_resolver.decisiveness_threshold),
    };

    let (base_sim, cf_sim) = tokio::try_join!(
        state.pipeline.simulate_compile(base_req, None, None),
        state
            .pipeline
            .simulate_compile(cf_req, custom_gate.as_ref(), Some(cf_resolver)),
    )?;

    let resolution_changed = compute_resolution_changed(&base_sim, &cf_sim);
    let baseline = ReplayBranchSummary::from(base_sim);
    let counterfactual = ReplayBranchSummary::from(cf_sim);

    let mut evidence_ledger_mutated = false;
    let mut refusal_evidence_seq_num = None;
    if !baseline.policy_decision.is_allow() && !counterfactual.policy_decision.is_allow() {
        let tag = match (&baseline.policy_decision, &counterfactual.policy_decision) {
            (PolicyDecision::Block { .. }, _) | (_, PolicyDecision::Block { .. }) => {
                PolicyResultTag::Block
            }
            _ => PolicyResultTag::Escalate,
        };
        if let Some(ev) = state
            .append_refusal_audit_with_scope(
                &headers,
                Some(&tenant_for_audit),
                tag,
                "replay",
                "replay_policy_refusal",
                Some(&scope_for_audit),
                &format!("counterfactual replay refused on scope '{scope_for_audit}'"),
            )
            .await
        {
            evidence_ledger_mutated = true;
            refusal_evidence_seq_num = Some(ev.seq_num);
        }
    }

    let diff = ReplayDiff {
        bundle_hash_changed: baseline.bundle_hash != counterfactual.bundle_hash,
        state_commitment_changed: baseline.state_commitment != counterfactual.state_commitment,
        resolution_changed,
        policy_decision_changed: baseline.policy_decision != counterfactual.policy_decision,
        dispute_delta: counterfactual.dispute_count as isize - baseline.dispute_count as isize,
        resolution_delta: counterfactual.resolution_count as isize
            - baseline.resolution_count as isize,
    };

    Ok(Json(ReplayResponse {
        baseline,
        counterfactual,
        diff,
        evidence_ledger_mutated,
        refusal_evidence_seq_num,
    }))
}
