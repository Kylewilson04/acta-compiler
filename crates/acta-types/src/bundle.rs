use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::claims::{DisputeRecord, KnowledgeClaim, OverrideAttestation, ResolutionRecord};
use crate::objects::{SelectedObjectRef, StoredObject};
use crate::request::ContextBudget;
use crate::serde_hex::{hex_32, hex_64, opt_hex_32};

pub const SCHEMA_VERSION: &str = "acta-context-bundle/v1";
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.70;
pub const DEFAULT_DECISIVENESS_THRESHOLD: f64 = 0.15;
pub const DEFAULT_CORROBORATION_DAMPING: f64 = 0.50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    BudgetExceeded,
    OutOfScope,
    LifecycleExpired,
    PolicyDenied,
    Superseded,
    DisputedWithheld,
}

impl OmissionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            OmissionReason::BudgetExceeded => "budget_exceeded",
            OmissionReason::OutOfScope => "out_of_scope",
            OmissionReason::LifecycleExpired => "lifecycle_expired",
            OmissionReason::PolicyDenied => "policy_denied",
            OmissionReason::Superseded => "superseded",
            OmissionReason::DisputedWithheld => "disputed_withheld",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OmittedItem {
    pub id: Uuid,
    pub reason: OmissionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmissionRecord {
    pub inline_items: Vec<OmittedItem>,
    pub total_omitted_count: usize,
    #[serde(with = "hex_32")]
    pub full_excluded_hash: [u8; 32],
    pub has_unresolved_claims: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyResultTag {
    Allow,
    Block,
    Escalate,
}

impl PolicyResultTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyResultTag::Allow => "allow",
            PolicyResultTag::Block => "block",
            PolicyResultTag::Escalate => "escalate",
        }
    }

    pub fn from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "allow" => Ok(PolicyResultTag::Allow),
            "block" => Ok(PolicyResultTag::Block),
            "escalate" => Ok(PolicyResultTag::Escalate),
            other => Err(format!("invalid policy_result: {other}")),
        }
    }
}

/// Cryptographically bound manifest of the exact resolver thresholds, corroboration damping,
/// budget envelope, and Cedar `permission_root` active when a `ContextBundle` was compiled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolverManifest {
    pub min_confidence: f64,
    pub decisiveness_threshold: f64,
    pub corroboration_damping: f64,
    pub non_default_thresholds: bool,
    pub budget: ContextBudget,
    #[serde(with = "hex_32")]
    pub permission_root: [u8; 32],
}

impl ResolverManifest {
    pub fn new(
        min_confidence: f64,
        decisiveness_threshold: f64,
        corroboration_damping: f64,
        budget: ContextBudget,
        permission_root: [u8; 32],
    ) -> Self {
        let non_default_thresholds = (min_confidence - DEFAULT_MIN_CONFIDENCE).abs() > 1e-9
            || (decisiveness_threshold - DEFAULT_DECISIVENESS_THRESHOLD).abs() > 1e-9
            || (corroboration_damping - DEFAULT_CORROBORATION_DAMPING).abs() > 1e-9;
        Self {
            min_confidence,
            decisiveness_threshold,
            corroboration_damping,
            non_default_thresholds,
            budget,
            permission_root,
        }
    }

    pub fn expected_non_default_flag(&self) -> bool {
        (self.min_confidence - DEFAULT_MIN_CONFIDENCE).abs() > 1e-9
            || (self.decisiveness_threshold - DEFAULT_DECISIVENESS_THRESHOLD).abs() > 1e-9
            || (self.corroboration_damping - DEFAULT_CORROBORATION_DAMPING).abs() > 1e-9
    }
}

/// Auditor-readable refusal record bound into `EvidenceEntry.event_hash` (`acta:evidence_event:v2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalMetadata {
    pub operation: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_scope: Option<String>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub scope_state_commitment: Option<[u8; 32]>,
}

/// Auditor-readable summary bound into `EvidenceEntry.event_hash` when an entry notarizes
/// a signed dispute-override attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideLedgerSummary {
    pub attestation_id: Uuid,
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub winning_claim_id: Uuid,
    pub overridden_count: usize,
    pub adjudicator_id: String,
    pub version: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBundle {
    pub schema_version: String,
    pub tenant_id: String,
    pub task_id: String,
    pub scope: String,
    pub policy_result: PolicyResultTag,
    pub embedding_model_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_manifest: Option<ResolverManifest>,
    pub selected_objects: Vec<SelectedObjectRef>,
    pub resolution_records: Vec<ResolutionRecord>,
    pub dispute_records: Vec<DisputeRecord>,
    pub omission_record: OmissionRecord,
    #[serde(with = "hex_32")]
    pub state_commitment: [u8; 32],
    #[serde(with = "hex_32")]
    pub dependency_commitment: [u8; 32],
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub tenant_id: String,
    pub seq_num: i64,
    #[serde(with = "hex_32")]
    pub prev_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub event_hash: [u8; 32],
    #[serde(default, with = "opt_hex_32")]
    pub bundle_hash: Option<[u8; 32]>,
    #[serde(default, with = "opt_hex_32")]
    pub state_commitment: Option<[u8; 32]>,
    pub policy_result: PolicyResultTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_metadata: Option<RefusalMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_summary: Option<OverrideLedgerSummary>,
    #[serde(with = "hex_64")]
    pub host_signature: [u8; 64],
    pub created_at: DateTime<Utc>,
}

/// External witness cosignature or transparency-log anchor over a `SignedTreeHead` (`v1.6+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalWitnessAnchor {
    pub id: Uuid,
    pub tenant_id: String,
    pub tree_size: i64,
    #[serde(with = "hex_32")]
    pub checkpoint_hash: [u8; 32],
    pub witness_id: String,
    #[serde(with = "hex_32")]
    pub witness_public_key: [u8; 32],
    #[serde(with = "hex_64")]
    pub witness_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_uri: Option<String>,
    pub anchored_at: DateTime<Utc>,
}

/// Deterministic RFC 6962–style Merkle checkpoint over `evidence_history[1..=tree_size]` (`v1.6+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tenant_id: String,
    pub tree_size: i64,
    #[serde(with = "hex_32")]
    pub head_event_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub merkle_root: [u8; 32],
    pub issued_at: DateTime<Utc>,
    #[serde(with = "hex_32")]
    pub checkpoint_hash: [u8; 32],
    #[serde(with = "hex_64")]
    pub host_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_anchors: Vec<ExternalWitnessAnchor>,
}

/// `O(log N)` RFC 6962 inclusion proof binding a single `EvidenceEntry` into a `SignedTreeHead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInclusionProof {
    pub entry: EvidenceEntry,
    pub audit_path: Vec<String>,
}

/// Compact `O(log N)` Merkle proof replacing linear `evidence_chain` scans in `ExportArchive` (`v1.6+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleBundleProof {
    pub checkpoint: SignedTreeHead,
    pub bundle_entry_proof: EntryInclusionProof,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_entry_proofs: Vec<EntryInclusionProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCheckpointRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    pub tree_size: i64,
    pub checkpoint_hash_hex: String,
    pub witness_id: String,
    pub witness_public_key_hex: String,
    pub witness_signature_hex: String,
    #[serde(default)]
    pub external_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportArchive {
    #[serde(with = "hex_32")]
    pub bundle_hash: [u8; 32],
    pub bundle: ContextBundle,
    pub objects: Vec<StoredObject>,
    pub claims: Vec<KnowledgeClaim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_attestations: Vec<OverrideAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_chain: Vec<EvidenceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<MerkleBundleProof>,
    #[serde(with = "hex_32")]
    pub host_public_key: [u8; 32],
}
