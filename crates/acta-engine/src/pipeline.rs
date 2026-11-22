use std::collections::BTreeSet;
use std::sync::Arc;

use acta_crypto::{
    compute_bundle_hash, compute_dependency_commitment, compute_state_commitment,
    compute_sub_commitment,
};
use acta_policy::{PolicyAction, PolicyGate};
use acta_store::evidence_repo::BundleWritePayload;
use acta_store::CompileStore;
use acta_types::{
    ActaError, ActaResult, ClaimStatus, CompileRequest, CompileResponse, ContextBudget,
    ContextBundle, KnowledgeClaim, OverrideAttestation, PolicyDecision, PolicyResultTag,
    RankedMemory, RefusalMetadata, ResolverManifest, StoredObject,
    DEFAULT_CORROBORATION_DAMPING, SCHEMA_VERSION,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use uuid::Uuid;

use crate::budget::apply_budget_and_omissions;
use crate::resolver::{resolve_claims_with_overrides, ResolverConfig};

/// Computes the deterministic state watermark timestamp across all evaluated objects, claims,
/// and signed dispute overrides in `(tenant_id, scope)` so repeated compiles over unchanged vault
/// state produce bit-for-bit identical `issued_at`, `hybrid_score`, `context_text`, and `bundle_hash`.
fn compute_state_watermark(
    intents: &[StoredObject],
    memories: &[RankedMemory],
    claims: &[KnowledgeClaim],
    overrides: &[OverrideAttestation],
    eval_wall_clock: DateTime<Utc>,
) -> DateTime<Utc> {
    let mut watermark = DateTime::<Utc>::UNIX_EPOCH;
    for i in intents {
        if i.created_at > watermark {
            watermark = i.created_at;
        }
    }
    for m in memories {
        if m.object.created_at > watermark {
            watermark = m.object.created_at;
        }
    }
    for c in claims {
        if c.created_at > watermark {
            watermark = c.created_at;
        }
        if let Some(vf) = c.valid_from {
            if vf <= eval_wall_clock && vf > watermark {
                watermark = vf;
            }
        }
        if let Some(vt) = c.valid_to {
            if vt <= eval_wall_clock && vt > watermark {
                watermark = vt;
            }
        }
    }
    for ovr in overrides {
        if ovr.created_at > watermark {
            watermark = ovr.created_at;
        }
    }
    watermark.trunc_subsecs(6)
}

/// Re-stabilizes scalar memory `hybrid_score` against the deterministic `bundle_time` when
/// no vector `query_embedding` was passed, eliminating wall-clock drift on `score=0.xxxx`.
fn restabilize_scalar_memory_scores(memories: &mut [RankedMemory], bundle_time: DateTime<Utc>) {
    for m in memories.iter_mut() {
        let elapsed_secs = ((bundle_time - m.object.created_at)
            .num_microseconds()
            .unwrap_or(0)
            .max(0) as f64)
            / 1_000_000.0;
        let recency = 1.0 / (1.0 + elapsed_secs / 86_400.0);
        m.hybrid_score = 0.70 * f64::from(m.object.importance) + 0.30 * recency;
    }
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub resolver: ResolverConfig,
    pub max_inline_omissions: usize,
    pub embedding_model_version: String,
    pub candidate_memory_fetch_limit: i64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            resolver: ResolverConfig::default(),
            max_inline_omissions: 25,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            candidate_memory_fetch_limit: 256,
        }
    }
}

/// Read-only counterfactual compile simulation result (never mutates `context_bundles` or `evidence_history` on Allow).
#[derive(Debug, Clone)]
pub struct CompileSimulation {
    pub policy_decision: PolicyDecision,
    pub permission_root: [u8; 32],
    pub bundle_hash: Option<[u8; 32]>,
    pub context_text: Option<String>,
    pub bundle: Option<ContextBundle>,
}

pub struct CompilePipeline<S: CompileStore> {
    policy_gate: Arc<PolicyGate>,
    store: S,
    host_signing_key: Arc<SigningKey>,
    config: PipelineConfig,
}

impl<S: CompileStore + Clone> Clone for CompilePipeline<S> {
    fn clone(&self) -> Self {
        Self {
            policy_gate: self.policy_gate.clone(),
            store: self.store.clone(),
            host_signing_key: self.host_signing_key.clone(),
            config: self.config.clone(),
        }
    }
}

impl<S: CompileStore> CompilePipeline<S> {
    pub fn new(
        policy_gate: Arc<PolicyGate>,
        store: S,
        host_signing_key: Arc<SigningKey>,
        config: PipelineConfig,
    ) -> Self {
        Self {
            policy_gate,
            store,
            host_signing_key,
            config,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn policy_gate(&self) -> &Arc<PolicyGate> {
        &self.policy_gate
    }

    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    pub fn host_signing_key(&self) -> &Arc<SigningKey> {
        &self.host_signing_key
    }

    pub fn host_verifying_key_bytes(&self) -> [u8; 32] {
        self.host_signing_key.verifying_key().to_bytes()
    }

    /// Executes a deterministic read-only counterfactual simulation under optional policy and
    /// resolver threshold overrides without writing to `context_bundles`.
    pub async fn simulate_compile(
        &self,
        req: CompileRequest,
        policy_override: Option<&PolicyGate>,
        resolver_override: Option<ResolverConfig>,
    ) -> ActaResult<CompileSimulation> {
        self.simulate_compile_with_manifest_mode(req, policy_override, resolver_override, true)
            .await
    }

    /// Same as `simulate_compile`, optionally omitting `resolver_manifest` when replaying a
    /// legacy `v1.0`–`v1.4` `source_bundle_hash` that lacked a `resolver_manifest`.
    pub async fn simulate_compile_with_manifest_mode(
        &self,
        req: CompileRequest,
        policy_override: Option<&PolicyGate>,
        resolver_override: Option<ResolverConfig>,
        include_resolver_manifest: bool,
    ) -> ActaResult<CompileSimulation> {
        let eval_wall_clock = req
            .evaluation_time
            .unwrap_or_else(Utc::now)
            .trunc_subsecs(6);

        let active_gate = policy_override.unwrap_or(&self.policy_gate);
        let (policy_decision, permission_root) = active_gate.evaluate_action(
            &req.tenant_id,
            &req.actor_id,
            &req.task_id,
            &req.scope,
            PolicyAction::Replay,
        );

        if !matches!(policy_decision, PolicyDecision::Allow) {
            return Ok(CompileSimulation {
                policy_decision,
                permission_root,
                bundle_hash: None,
                context_text: None,
                bundle: None,
            });
        }

        let mem_limit = match req.budget {
            ContextBudget::Records(r) => (r as i64).max(1),
            _ => self.config.candidate_memory_fetch_limit,
        };

        let (
            intents,
            mut ranked_memories,
            object_scan,
            (scoped_claims, superseded_claims),
            scoped_overrides,
        ) = tokio::try_join!(
            self.store.fetch_scoped_intents(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_memories_ranked(
                &req.tenant_id,
                &req.scope,
                req.query_embedding.as_deref(),
                eval_wall_clock,
                mem_limit,
            ),
            self.store
                .fetch_all_active_hashes_in_scope(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_claims(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_overrides(&req.tenant_id, &req.scope),
        )?;

        let active_overrides: Vec<OverrideAttestation> = scoped_overrides
            .into_iter()
            .filter(|o| o.created_at <= eval_wall_clock)
            .collect();

        let bundle_time = match req.evaluation_time {
            Some(explicit_t) => explicit_t.trunc_subsecs(6),
            None => compute_state_watermark(
                &intents,
                &ranked_memories,
                &scoped_claims,
                &active_overrides,
                eval_wall_clock,
            ),
        };

        if req.evaluation_time.is_none() && req.query_embedding.is_none() {
            restabilize_scalar_memory_scores(&mut ranked_memories, bundle_time);
        }

        let mut active_claim_hashes: Vec<[u8; 32]> = scoped_claims
            .iter()
            .filter(|c| {
                c.status == ClaimStatus::Active
                    && c.valid_from.map_or(true, |vf| vf <= eval_wall_clock)
                    && c.valid_to.map_or(true, |vt| vt >= eval_wall_clock)
            })
            .map(|c| c.content_hash)
            .collect();
        for ovr in &active_overrides {
            active_claim_hashes.push(ovr.attestation_hash);
        }

        let mut evaluated_hashes = Vec::with_capacity(
            intents.len() + ranked_memories.len() + scoped_claims.len() + active_overrides.len(),
        );
        for i in &intents {
            evaluated_hashes.push(i.content_hash);
        }
        for m in &ranked_memories {
            evaluated_hashes.push(m.object.content_hash);
        }
        for c in &scoped_claims {
            evaluated_hashes.push(c.content_hash);
        }
        for ovr in &active_overrides {
            evaluated_hashes.push(ovr.attestation_hash);
        }

        let fetched_mem_ids: BTreeSet<Uuid> =
            ranked_memories.iter().map(|m| m.object.id).collect();
        let unfetched_tail_memory_ids: Vec<Uuid> = object_scan
            .active_memory_ids
            .iter()
            .copied()
            .filter(|id| !fetched_mem_ids.contains(id))
            .collect();

        let resolver_cfg = resolver_override.unwrap_or_else(|| self.config.resolver.clone());
        let resolver_out = resolve_claims_with_overrides(
            scoped_claims,
            &active_overrides,
            eval_wall_clock,
            &resolver_cfg,
        );

        let mut pre_excluded = object_scan.excluded_objects;
        pre_excluded.extend(superseded_claims);
        pre_excluded.extend(resolver_out.excluded_claims);

        let budgeted = apply_budget_and_omissions(
            intents,
            resolver_out.resolutions,
            resolver_out.disputes,
            ranked_memories,
            pre_excluded,
            unfetched_tail_memory_ids,
            req.budget,
            self.config.max_inline_omissions,
        )?;

        let intent_root = compute_sub_commitment(&object_scan.active_intent_hashes);
        let memory_root = compute_sub_commitment(&object_scan.active_memory_hashes);
        let knowledge_root = compute_sub_commitment(&active_claim_hashes);

        let state_commitment = compute_state_commitment(
            SCHEMA_VERSION,
            &req.tenant_id,
            &req.scope,
            &intent_root,
            &knowledge_root,
            &memory_root,
            &permission_root,
        );
        let dependency_commitment = compute_dependency_commitment(&evaluated_hashes);

        let resolver_manifest = if include_resolver_manifest {
            Some(ResolverManifest::new(
                resolver_cfg.min_confidence,
                resolver_cfg.decisiveness_threshold,
                DEFAULT_CORROBORATION_DAMPING,
                req.budget,
                permission_root,
            ))
        } else {
            None
        };

        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: req.tenant_id.clone(),
            task_id: req.task_id.clone(),
            scope: req.scope.clone(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: self.config.embedding_model_version.clone(),
            resolver_manifest,
            selected_objects: budgeted.selected_object_refs,
            resolution_records: budgeted.selected_resolutions,
            dispute_records: budgeted.selected_disputes,
            omission_record: budgeted.omission_record,
            state_commitment,
            dependency_commitment,
            issued_at: bundle_time,
        };

        let (bundle_hash, _canonical) = compute_bundle_hash(&bundle)?;

        Ok(CompileSimulation {
            policy_decision: PolicyDecision::Allow,
            permission_root,
            bundle_hash: Some(bundle_hash),
            context_text: Some(budgeted.context_text),
            bundle: Some(bundle),
        })
    }

    /// Executes the 6-stage deterministic compile pipeline, strictly enforcing
    /// Invariant 1 (Policy-Before-Read), binding `resolver_manifest` into `ContextBundle`,
    /// and logging signed auditor-readable `RefusalMetadata` on ALL non-Allow outcomes.
    pub async fn compile(&self, req: CompileRequest) -> ActaResult<CompileResponse> {
        let audit_wall_time = Utc::now().trunc_subsecs(6);
        let eval_wall_clock = req
            .evaluation_time
            .unwrap_or(audit_wall_time)
            .trunc_subsecs(6);

        // =====================================================================
        // Stage 1: Embedded Cedar Policy Gate (Policy-Before-Read)
        // =====================================================================
        let (policy_decision, permission_root) = self.policy_gate.evaluate(&req);

        match &policy_decision {
            PolicyDecision::Block { reason } => {
                let meta = RefusalMetadata {
                    operation: "compile".to_string(),
                    reason_code: "compile_policy_block".to_string(),
                    target_scope: Some(req.scope.clone()),
                    summary: format!(
                        "policy denied compile for actor '{}' on scope '{}': {}",
                        req.actor_id, req.scope, reason
                    ),
                    scope_state_commitment: None,
                };
                let evidence = self
                    .store
                    .append_refusal_metadata(
                        &self.host_signing_key,
                        &req.tenant_id,
                        PolicyResultTag::Block,
                        meta,
                        audit_wall_time,
                    )
                    .await?;
                return Ok(CompileResponse {
                    policy_decision,
                    bundle_hash: None,
                    context_text: None,
                    bundle: None,
                    evidence,
                });
            }
            PolicyDecision::Escalate { reason } => {
                let meta = RefusalMetadata {
                    operation: "compile".to_string(),
                    reason_code: "compile_policy_escalate".to_string(),
                    target_scope: Some(req.scope.clone()),
                    summary: format!(
                        "policy escalation required for actor '{}' on restricted scope '{}': {}",
                        req.actor_id, req.scope, reason
                    ),
                    scope_state_commitment: None,
                };
                let evidence = self
                    .store
                    .append_refusal_metadata(
                        &self.host_signing_key,
                        &req.tenant_id,
                        PolicyResultTag::Escalate,
                        meta,
                        audit_wall_time,
                    )
                    .await?;
                return Ok(CompileResponse {
                    policy_decision,
                    bundle_hash: None,
                    context_text: None,
                    bundle: None,
                    evidence,
                });
            }
            PolicyDecision::Allow => {}
        }

        // =====================================================================
        // Stage 2: Scoped Retrieval (parallelized across independent read queries)
        // =====================================================================
        let mem_limit = match req.budget {
            ContextBudget::Records(r) => (r as i64).max(1),
            _ => self.config.candidate_memory_fetch_limit,
        };

        let (
            intents,
            mut ranked_memories,
            object_scan,
            (scoped_claims, superseded_claims),
            scoped_overrides,
        ) = tokio::try_join!(
            self.store.fetch_scoped_intents(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_memories_ranked(
                &req.tenant_id,
                &req.scope,
                req.query_embedding.as_deref(),
                eval_wall_clock,
                mem_limit,
            ),
            self.store
                .fetch_all_active_hashes_in_scope(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_claims(&req.tenant_id, &req.scope),
            self.store.fetch_scoped_overrides(&req.tenant_id, &req.scope),
        )?;

        let active_overrides: Vec<OverrideAttestation> = scoped_overrides
            .into_iter()
            .filter(|o| o.created_at <= eval_wall_clock)
            .collect();

        let bundle_time = match req.evaluation_time {
            Some(explicit_t) => explicit_t.trunc_subsecs(6),
            None => compute_state_watermark(
                &intents,
                &ranked_memories,
                &scoped_claims,
                &active_overrides,
                eval_wall_clock,
            ),
        };

        if req.evaluation_time.is_none() && req.query_embedding.is_none() {
            restabilize_scalar_memory_scores(&mut ranked_memories, bundle_time);
        }

        let mut active_claim_hashes: Vec<[u8; 32]> = scoped_claims
            .iter()
            .filter(|c| {
                c.status == ClaimStatus::Active
                    && c.valid_from.map_or(true, |vf| vf <= eval_wall_clock)
                    && c.valid_to.map_or(true, |vt| vt >= eval_wall_clock)
            })
            .map(|c| c.content_hash)
            .collect();
        for ovr in &active_overrides {
            active_claim_hashes.push(ovr.attestation_hash);
        }

        let mut evaluated_hashes = Vec::with_capacity(
            intents.len() + ranked_memories.len() + scoped_claims.len() + active_overrides.len(),
        );
        for i in &intents {
            evaluated_hashes.push(i.content_hash);
        }
        for m in &ranked_memories {
            evaluated_hashes.push(m.object.content_hash);
        }
        for c in &scoped_claims {
            evaluated_hashes.push(c.content_hash);
        }
        for ovr in &active_overrides {
            evaluated_hashes.push(ovr.attestation_hash);
        }

        let fetched_mem_ids: BTreeSet<Uuid> =
            ranked_memories.iter().map(|m| m.object.id).collect();
        let unfetched_tail_memory_ids: Vec<Uuid> = object_scan
            .active_memory_ids
            .iter()
            .copied()
            .filter(|id| !fetched_mem_ids.contains(id))
            .collect();

        // =====================================================================
        // Stage 3: Cryptographic State & Dependency Commitments
        // =====================================================================
        let intent_root = compute_sub_commitment(&object_scan.active_intent_hashes);
        let memory_root = compute_sub_commitment(&object_scan.active_memory_hashes);
        let knowledge_root = compute_sub_commitment(&active_claim_hashes);

        let state_commitment = compute_state_commitment(
            SCHEMA_VERSION,
            &req.tenant_id,
            &req.scope,
            &intent_root,
            &knowledge_root,
            &memory_root,
            &permission_root,
        );
        let dependency_commitment = compute_dependency_commitment(&evaluated_hashes);

        // =====================================================================
        // Stage 4: Deterministic Claim Resolution (+ Signed Overrides)
        // =====================================================================
        let resolver_out = resolve_claims_with_overrides(
            scoped_claims,
            &active_overrides,
            eval_wall_clock,
            &self.config.resolver,
        );

        // =====================================================================
        // Stage 5: Tiered Budgeting, Omission Engine & Context Formatting
        // =====================================================================
        let mut pre_excluded = object_scan.excluded_objects;
        pre_excluded.extend(superseded_claims);
        pre_excluded.extend(resolver_out.excluded_claims);

        let budgeted = match apply_budget_and_omissions(
            intents,
            resolver_out.resolutions,
            resolver_out.disputes,
            ranked_memories,
            pre_excluded,
            unfetched_tail_memory_ids,
            req.budget,
            self.config.max_inline_omissions,
        ) {
            Ok(b) => b,
            Err(ActaError::BudgetInsufficientForDisputes(msg)) => {
                let meta = RefusalMetadata {
                    operation: "compile".to_string(),
                    reason_code: "budget_insufficient_for_disputes".to_string(),
                    target_scope: Some(req.scope.clone()),
                    summary: msg.clone(),
                    scope_state_commitment: Some(state_commitment),
                };
                let ev = self
                    .store
                    .append_refusal_metadata(
                        &self.host_signing_key,
                        &req.tenant_id,
                        PolicyResultTag::Block,
                        meta,
                        audit_wall_time,
                    )
                    .await?;
                return Err(ActaError::BudgetInsufficientForDisputes(format!(
                    "{msg} [logged at evidence seq_num={}]",
                    ev.seq_num
                )));
            }
            Err(other) => return Err(other),
        };

        // =====================================================================
        // Stage 6: Bundle Assembly & Transactional Evidence Persistence
        // =====================================================================
        let resolver_manifest = ResolverManifest::new(
            self.config.resolver.min_confidence,
            self.config.resolver.decisiveness_threshold,
            DEFAULT_CORROBORATION_DAMPING,
            req.budget,
            permission_root,
        );

        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: req.tenant_id.clone(),
            task_id: req.task_id.clone(),
            scope: req.scope.clone(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: self.config.embedding_model_version.clone(),
            resolver_manifest: Some(resolver_manifest),
            selected_objects: budgeted.selected_object_refs,
            resolution_records: budgeted.selected_resolutions,
            dispute_records: budgeted.selected_disputes,
            omission_record: budgeted.omission_record,
            state_commitment,
            dependency_commitment,
            issued_at: bundle_time,
        };

        let (bundle_hash, bundle_canonical) = compute_bundle_hash(&bundle)?;

        let write_payload = BundleWritePayload {
            bundle_hash: &bundle_hash,
            state_commitment: &state_commitment,
            dependency_commitment: &dependency_commitment,
            bundle_canonical: &bundle_canonical,
        };

        let evidence = self
            .store
            .append_evidence(
                &self.host_signing_key,
                &req.tenant_id,
                PolicyResultTag::Allow,
                Some(write_payload),
                audit_wall_time,
            )
            .await?;

        Ok(CompileResponse {
            policy_decision: PolicyDecision::Allow,
            bundle_hash: Some(hex::encode(bundle_hash)),
            context_text: Some(budgeted.context_text),
            bundle: Some(bundle),
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    use acta_crypto::{
        compute_evidence_event_hash_with_meta, compute_refusal_metadata_commitment,
        sign_evidence_entry, verify_evidence_signature,
    };
    use acta_policy::ActorRoleRecord;
    use acta_store::objects_repo::ScopedObjectScan;
    use acta_store::{BoxFuture, QueryCountingStore};
    use acta_types::{EvidenceEntry, KnowledgeClaim, OmissionReason, RankedMemory, StoredObject};
    use chrono::DateTime;

    const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

    #[derive(Default, Clone)]
    struct InMemoryEvidenceLedger {
        entries: Arc<Mutex<Vec<EvidenceEntry>>>,
    }

    impl CompileStore for InMemoryEvidenceLedger {
        fn fetch_scoped_intents<'a>(
            &'a self,
            _tenant_id: &'a str,
            _scope: &'a str,
        ) -> BoxFuture<'a, ActaResult<Vec<StoredObject>>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn fetch_scoped_memories_ranked<'a>(
            &'a self,
            _tenant_id: &'a str,
            _scope: &'a str,
            _query_embedding: Option<&'a [f32]>,
            _now: DateTime<Utc>,
            _limit: i64,
        ) -> BoxFuture<'a, ActaResult<Vec<RankedMemory>>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn fetch_all_active_hashes_in_scope<'a>(
            &'a self,
            _tenant_id: &'a str,
            _scope: &'a str,
        ) -> BoxFuture<'a, ActaResult<ScopedObjectScan>> {
            Box::pin(async { Ok(ScopedObjectScan::default()) })
        }

        fn fetch_scoped_claims<'a>(
            &'a self,
            _tenant_id: &'a str,
            _scope: &'a str,
        ) -> BoxFuture<'a, ActaResult<(Vec<KnowledgeClaim>, Vec<(Uuid, OmissionReason)>)>> {
            Box::pin(async { Ok((vec![], vec![])) })
        }

        fn fetch_all_active_claim_hashes_in_scope<'a>(
            &'a self,
            _tenant_id: &'a str,
            _scope: &'a str,
            _now: DateTime<Utc>,
        ) -> BoxFuture<'a, ActaResult<Vec<[u8; 32]>>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn append_evidence<'a>(
            &'a self,
            host_key: &'a SigningKey,
            tenant_id: &'a str,
            policy_result: PolicyResultTag,
            bundle: Option<BundleWritePayload<'a>>,
            created_at: DateTime<Utc>,
        ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
            let entries = self.entries.clone();
            let bundle_hash_opt = bundle.as_ref().map(|b| *b.bundle_hash);
            let state_commitment_opt = bundle.as_ref().map(|b| *b.state_commitment);
            let tenant = tenant_id.to_string();

            Box::pin(async move {
                let mut guard = entries.lock().unwrap();
                let (seq_num, prev_hash) = match guard.iter().rev().find(|e| e.tenant_id == tenant) {
                    Some(last) => (last.seq_num + 1, last.event_hash),
                    None => (1, [0u8; 32]),
                };
                let event_hash = compute_evidence_event_hash_with_meta(
                    &tenant,
                    seq_num,
                    &prev_hash,
                    bundle_hash_opt.as_ref(),
                    state_commitment_opt.as_ref(),
                    policy_result,
                    created_at.timestamp_micros(),
                    None,
                    None,
                )?;
                let host_signature =
                    sign_evidence_entry(host_key, &tenant, seq_num, &prev_hash, &event_hash);
                let entry = EvidenceEntry {
                    tenant_id: tenant,
                    seq_num,
                    prev_hash,
                    event_hash,
                    bundle_hash: bundle_hash_opt,
                    state_commitment: state_commitment_opt,
                    policy_result,
                    refusal_metadata: None,
                    override_summary: None,
                    host_signature,
                    created_at,
                };
                guard.push(entry.clone());
                Ok(entry)
            })
        }

        fn append_refusal_metadata<'a>(
            &'a self,
            host_key: &'a SigningKey,
            tenant_id: &'a str,
            policy_result: PolicyResultTag,
            meta: RefusalMetadata,
            created_at: DateTime<Utc>,
        ) -> BoxFuture<'a, ActaResult<EvidenceEntry>> {
            let entries = self.entries.clone();
            let tenant = tenant_id.to_string();

            Box::pin(async move {
                let comm = compute_refusal_metadata_commitment(&meta)?;
                let mut guard = entries.lock().unwrap();
                let (seq_num, prev_hash) = match guard.iter().rev().find(|e| e.tenant_id == tenant) {
                    Some(last) => (last.seq_num + 1, last.event_hash),
                    None => (1, [0u8; 32]),
                };
                let event_hash = compute_evidence_event_hash_with_meta(
                    &tenant,
                    seq_num,
                    &prev_hash,
                    None,
                    Some(&comm),
                    policy_result,
                    created_at.timestamp_micros(),
                    Some(&meta),
                    None,
                )?;
                let host_signature =
                    sign_evidence_entry(host_key, &tenant, seq_num, &prev_hash, &event_hash);
                let entry = EvidenceEntry {
                    tenant_id: tenant,
                    seq_num,
                    prev_hash,
                    event_hash,
                    bundle_hash: None,
                    state_commitment: Some(comm),
                    policy_result,
                    refusal_metadata: Some(meta),
                    override_summary: None,
                    host_signature,
                    created_at,
                };
                guard.push(entry.clone());
                Ok(entry)
            })
        }
    }

    #[tokio::test]
    async fn test_policy_before_read_block_and_escalate_zero_data_queries() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "mallory-other-tenant".to_string(),
            ActorRoleRecord {
                tenant_id: "tenant-evil".to_string(),
                authorized: true,
                roles: BTreeSet::from(["reader".to_string()]),
            },
        );
        roles.insert(
            "alice".to_string(),
            ActorRoleRecord {
                tenant_id: "tenant-acme".to_string(),
                authorized: true,
                roles: BTreeSet::from(["reader".to_string()]),
            },
        );

        let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, roles).unwrap());
        let ledger = InMemoryEvidenceLedger::default();
        let spy_store = QueryCountingStore::new(ledger.clone());
        let host_key = Arc::new(SigningKey::from_bytes(&[0x77u8; 32]));
        let pipeline = CompilePipeline::new(
            gate,
            spy_store.clone(),
            host_key.clone(),
            PipelineConfig::default(),
        );

        let block_req = CompileRequest {
            tenant_id: "tenant-acme".to_string(),
            actor_id: "mallory-other-tenant".to_string(),
            task_id: "task-1".to_string(),
            scope: "general".to_string(),
            query_text: "Steal secrets".to_string(),
            query_embedding: None,
            budget: ContextBudget::Tokens(1024),
            evaluation_time: None,
        };
        let block_resp = pipeline.compile(block_req).await.unwrap();
        assert!(matches!(block_resp.policy_decision, PolicyDecision::Block { .. }));
        assert!(block_resp.bundle.is_none());
        assert!(block_resp.bundle_hash.is_none());
        assert_eq!(spy_store.objects_query_count(), 0);
        assert_eq!(spy_store.claims_query_count(), 0);
        assert_eq!(spy_store.evidence_write_count(), 1);
        assert_eq!(block_resp.evidence.policy_result, PolicyResultTag::Block);
        assert_eq!(block_resp.evidence.seq_num, 1);
        assert_eq!(
            block_resp
                .evidence
                .refusal_metadata
                .as_ref()
                .unwrap()
                .reason_code,
            "compile_policy_block"
        );
        assert_eq!(
            block_resp
                .evidence
                .refusal_metadata
                .as_ref()
                .unwrap()
                .target_scope
                .as_deref(),
            Some("general")
        );

        let escalate_req = CompileRequest {
            tenant_id: "tenant-acme".to_string(),
            actor_id: "alice".to_string(),
            task_id: "task-2".to_string(),
            scope: "restricted/hr".to_string(),
            query_text: "Check compensation".to_string(),
            query_embedding: None,
            budget: ContextBudget::Tokens(1024),
            evaluation_time: None,
        };
        let esc_resp = pipeline.compile(escalate_req).await.unwrap();
        assert!(matches!(esc_resp.policy_decision, PolicyDecision::Escalate { .. }));
        assert!(esc_resp.bundle.is_none());
        assert_eq!(spy_store.objects_query_count(), 0);
        assert_eq!(spy_store.claims_query_count(), 0);
        assert_eq!(spy_store.evidence_write_count(), 2);
        assert_eq!(esc_resp.evidence.policy_result, PolicyResultTag::Escalate);
        assert_eq!(esc_resp.evidence.seq_num, 2);
        assert_eq!(esc_resp.evidence.prev_hash, block_resp.evidence.event_hash);
        assert_eq!(
            esc_resp
                .evidence
                .refusal_metadata
                .as_ref()
                .unwrap()
                .target_scope
                .as_deref(),
            Some("restricted/hr")
        );

        assert!(verify_evidence_signature(
            &host_key.verifying_key(),
            &esc_resp.evidence.tenant_id,
            esc_resp.evidence.seq_num,
            &esc_resp.evidence.prev_hash,
            &esc_resp.evidence.event_hash,
            &esc_resp.evidence.host_signature
        ));
    }

    #[tokio::test]
    async fn test_identical_compiles_produce_reproducible_bundle_hash_and_bind_resolver_manifest() {
        let gate = Arc::new(PolicyGate::from_policy_str(DEFAULT_CEDAR, BTreeMap::new()).unwrap());
        let ledger = InMemoryEvidenceLedger::default();
        let host_key = Arc::new(SigningKey::from_bytes(&[0x55u8; 32]));
        let pipeline = CompilePipeline::new(gate, ledger, host_key, PipelineConfig::default());

        let req = CompileRequest {
            tenant_id: "tenant-det".to_string(),
            actor_id: "tenant-det::agent".to_string(),
            task_id: "mcp-task".to_string(),
            scope: "audit".to_string(),
            query_text: "check fee".to_string(),
            query_embedding: None,
            budget: ContextBudget::Tokens(512),
            evaluation_time: None,
        };

        let r1 = pipeline.compile(req.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let r2 = pipeline.compile(req.clone()).await.unwrap();
        let sim_default = pipeline.simulate_compile(req.clone(), None, None).await.unwrap();
        let sim_lowered = pipeline
            .simulate_compile(
                req,
                None,
                Some(ResolverConfig {
                    min_confidence: 0.70,
                    decisiveness_threshold: 0.05,
                }),
            )
            .await
            .unwrap();

        assert_eq!(r1.bundle_hash, r2.bundle_hash, "bundle_hash must be reproducible across compiles");
        assert_eq!(r1.bundle_hash.as_deref(), sim_default.bundle_hash.map(hex::encode).as_deref());
        assert_ne!(
            r1.bundle_hash.as_deref(),
            sim_lowered.bundle_hash.map(hex::encode).as_deref(),
            "lowering decisiveness_threshold must change bundle_hash via resolver_manifest even on empty claims!"
        );
        assert!(
            !r1.bundle
                .as_ref()
                .unwrap()
                .resolver_manifest
                .as_ref()
                .unwrap()
                .non_default_thresholds
        );
        assert!(
            sim_lowered
                .bundle
                .as_ref()
                .unwrap()
                .resolver_manifest
                .as_ref()
                .unwrap()
                .non_default_thresholds
        );
    }
}
