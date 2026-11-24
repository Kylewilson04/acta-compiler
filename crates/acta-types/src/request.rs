use std::collections::BTreeSet;
use crate::error::{ActaError, ActaResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bundle::{ContextBundle, EvidenceEntry, StateRebuildArchive};

fn default_cache_validity_mode() -> String {
    "scope_root".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "limit", rename_all = "snake_case")]
pub enum ContextBudget {
    Tokens(usize),
    Bytes(usize),
    Records(usize),
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self::Tokens(4096)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileRequest {
    pub tenant_id: String,
    pub actor_id: String,
    pub task_id: String,
    pub scope: String,
    pub query_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_embedding: Option<Vec<f32>>,
    pub budget: ContextBudget,
    /// Optional deterministic evaluation timestamp; defaults to truncated `Utc::now()` in pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Block { reason: String },
    Escalate { reason: String },
}

impl PolicyDecision {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Block { .. } => "block",
            PolicyDecision::Escalate { .. } => "escalate",
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileResponse {
    pub policy_decision: PolicyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_token_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_token_ids: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_token_bytes_hex: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_facts_omitted: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<ContextBundle>,
    pub evidence: EvidenceEntry,
}

/// Request to persist a state-root-conditioned cached answer bound to a compiled `ContextBundle`
/// (PPA 1 Independent Claim 19, Claims 19–27).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheAnswerRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub query_text: Option<String>,
    pub source_bundle_hash: String,
    pub answer_text: String,
    #[serde(default)]
    pub answer_metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub validity_mode: Option<String>,
    #[serde(default)]
    pub dependency_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub client_signature_hex: Option<String>,
    #[serde(default)]
    pub client_public_key_hex: Option<String>,
}

/// Cryptographic receipt binding a cached answer to its prior `ContextBundle`, `state_commitment`,
/// `answer_hash`, and signed `evidence_history` entry (PPA 1 Claim 27).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedAnswerReceipt {
    pub cache_id: Uuid,
    pub tenant_id: String,
    pub scope: String,
    pub task_id: String,
    pub query_hash: String,
    pub source_bundle_hash: String,
    pub state_commitment: String,
    #[serde(default = "default_cache_validity_mode")]
    pub validity_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_dependency_commitment: Option<String>,
    pub answer_hash: String,
    pub cache_domain: String,
    pub cache_commitment: String,
    pub evidence_seq_num: i64,
    pub host_signature: String,
    pub cached_by: String,
    pub cacher_auth_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_signature_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAnswerResponse {
    pub receipt: CachedAnswerReceipt,
    pub evidence: EvidenceEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupCachedAnswerRequest {
    pub tenant_id: String,
    #[serde(default)]
    pub actor_id: Option<String>,
    pub scope: String,
    pub task_id: String,
    #[serde(default)]
    pub query_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupCachedAnswerResponse {
    pub cache_hit: bool,
    pub status: String,
    pub policy_decision: PolicyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_state_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_state_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_commitment_matches: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_task_dependency_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_task_dependency_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_dependency_commitment_matches: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_hash_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<CachedAnswerReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_evidence_seq_num: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_newly_recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_evidence: Option<EvidenceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_evidence_seq_num: Option<i64>,
}

/// Indexed historical bundle dependency entry returned by `acta_trace_claim_impact` (`O(k)` lookup).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactBundleRecord {
    pub bundle_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_seq_num: Option<i64>,
    pub scope: String,
    pub task_id: String,
    pub dependency_role: String,
    pub bundle_state_commitment: String,
    pub current_scope_state_commitment: String,
    pub is_stale_now: bool,
    pub bundle_issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactedCachedAnswerRecord {
    pub cache_id: Uuid,
    pub scope: String,
    pub task_id: String,
    pub query_hash: String,
    pub source_bundle_hash: String,
    #[serde(default = "default_cache_validity_mode")]
    pub validity_mode: String,
    pub answer_hash: String,
    pub evidence_seq_num: i64,
    pub invalidated_by_state_change: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_evidence_seq_num: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceItemImpactResponse {
    pub tenant_id: String,
    pub item_id: Uuid,
    pub item_kind: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    pub version: i32,
    pub lifecycle_state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub successor_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retracted_by_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_evidence_seq_num: Option<i64>,
    pub impacted_bundle_count: usize,
    pub stale_bundle_count: usize,
    pub impacted_bundles: Vec<ImpactBundleRecord>,
    pub impacted_cached_answer_count: usize,
    pub impacted_cached_answers: Vec<ImpactedCachedAnswerRecord>,
}

/// Result of deterministic state reconstruction directly from `evidence_history` (`v1.7.0+`, PPA 1 Claim 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerStateRebuildResponse {
    pub tenant_id: String,
    pub scope: String,
    pub verified_up_to_seq: i64,
    pub chain_cryptographically_verified: bool,
    pub write_events_replayed: usize,
    pub reconstructed_active_intents: usize,
    pub reconstructed_active_memories: usize,
    pub reconstructed_active_claims: usize,
    pub reconstructed_superseded_or_retracted_items: usize,
    pub reconstructed_active_overrides: usize,
    pub legacy_pre_v17_unchained_objects: usize,
    pub legacy_pre_v17_unchained_claims: usize,
    pub reconstructed_intent_root: String,
    pub reconstructed_knowledge_root: String,
    pub reconstructed_memory_root: String,
    pub permission_root: String,
    pub reconstructed_state_commitment: String,
    pub live_store_state_commitment: String,
    pub matches_live_store_bit_for_bit: bool,
    pub evaluated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_header_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_anchored_tree_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_proof_archive: Option<StateRebuildArchive>,
}

/// Persisted PPA 1 Claim 25 dependency subset specification stored on `cached_answers.dependency_spec`.
/// In `v1.7.2+`, `pinned_claim_ids` records explicit claim UUIDs when `dependency_ids` narrows
/// tracking to specific claims within a group (leaving `pinned_claim_ids` empty when `dependency_ids`
/// was omitted so all `v1.7.1` group-level `dependency_spec` rows remain bit-for-bit identical).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheDependencySpec {
    #[serde(default)]
    pub claim_group_keys_hex: Vec<String>,
    #[serde(default)]
    pub memory_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_claim_ids: Vec<Uuid>,
    #[serde(default)]
    pub empty_knowledge_fallback: bool,
}

impl CacheDependencySpec {
    pub fn parsed_group_keys(&self) -> ActaResult<BTreeSet<[u8; 32]>> {
        let mut out = BTreeSet::new();
        for h in &self.claim_group_keys_hex {
            let raw = hex::decode(h.trim()).map_err(|e| {
                ActaError::Storage(format!("invalid group key hex in dependency_spec: {e}"))
            })?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| {
                ActaError::Storage("group key in dependency_spec not 32 bytes".to_string())
            })?;
            out.insert(arr);
        }
        Ok(out)
    }
}
