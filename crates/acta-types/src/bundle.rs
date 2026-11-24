use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::claims::{DisputeRecord, KnowledgeClaim, OverrideAttestation, ResolutionRecord};
use crate::objects::{SelectedObjectRef, StoredObject};
use crate::request::ContextBudget;
use crate::serde_hex::{hex_32, hex_64, opt_hex_32, opt_hex_vec};

pub const SCHEMA_VERSION: &str = "acta-context-bundle/v1";
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.70;
pub const DEFAULT_DECISIVENESS_THRESHOLD: f64 = 0.15;
pub const DEFAULT_CORROBORATION_DAMPING: f64 = 0.50;

pub const WITNESS_REG_DOMAIN_V1: &str = "acta:witness_reg:v1";
pub const WITNESS_REG_DOMAIN_V2: &str = "acta:witness_reg:v2";
pub const WITNESS_REG_DOMAIN_V3: &str = "acta:witness_reg:v3";
pub const WITNESS_REVOKE_DOMAIN_V1: &str = "acta:witness_revoke:v1";
pub const WITNESS_REVOKE_DOMAIN_V2: &str = "acta:witness_revoke:v2";
pub const WRITE_EVENT_DOMAIN_V1: &str = "acta:write_event:v1";
pub const ANSWER_CACHE_DOMAIN_V1: &str = "acta:answer_cache:v1";
pub const CACHE_DEPENDENCY_DOMAIN_V1: &str = "acta:cache_dep_root:v1";
pub const STATE_REBUILD_ARCHIVE_SCHEMA_V1: &str = "acta-state-rebuild-archive/v1";
pub const REBUILD_HEADER_DOMAIN_V1: &str = "acta:rebuild_header:v1";
pub const REBUILD_SIG_DOMAIN_V1: &str = "acta:rebuild_sig:v1";

fn default_witness_reg_domain() -> String {
    WITNESS_REG_DOMAIN_V1.to_string()
}

fn default_revocation_mode() -> String {
    "compromise".to_string()
}

fn default_write_event_domain() -> String {
    WRITE_EVENT_DOMAIN_V1.to_string()
}

fn default_answer_cache_domain() -> String {
    ANSWER_CACHE_DOMAIN_V1.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    BudgetExceeded,
    OutOfScope,
    LifecycleExpired,
    PolicyDenied,
    Superseded,
    DisputedWithheld,
    Retracted,
    RetractionTombstone,
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
            OmissionReason::Retracted => "retracted",
            OmissionReason::RetractionTombstone => "retraction_tombstone",
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
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub attempted_checkpoint_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub expected_intent_digest_hex: Option<[u8; 32]>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteOperationKind {
    IngestObject,
    IngestClaim,
    RetractClaim,
}

impl WriteOperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            WriteOperationKind::IngestObject => "ingest_object",
            WriteOperationKind::IngestClaim => "ingest_claim",
            WriteOperationKind::RetractClaim => "retract_claim",
        }
    }
}

/// Strip-proof write-path ledger summary bound into `EvidenceEntry.event_hash` (`acta:evidence_event:v3`, `v1.7.0+`)
/// carrying the full canonical object/claim snapshot and optional client Ed25519 signature so vault state
/// can be verified and reconstructed from `evidence_history` alone (PPA 1 Claim 1 & Claim 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteLedgerSummary {
    #[serde(default = "default_write_event_domain")]
    pub write_domain: String,
    pub operation: WriteOperationKind,
    pub item_id: Uuid,
    pub scope: String,
    pub version: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_id: Option<Uuid>,
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
    pub written_by: String,
    pub writer_auth_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub client_public_key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_vec")]
    pub client_signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction_reason: Option<String>,
    pub record_snapshot: serde_json::Value,
}

/// Strip-proof state-conditioned answer-cache event summary bound into `EvidenceEntry.event_hash`
/// (`acta:evidence_event:v3`, `v1.7.0+`, PPA 1 Independent Claim 19 / Claim 21).
/// In `v1.7.2+`, invalidation receipts (`event_kind = "invalidated"`) preserve the original cacher's
/// `cached_by`, `cacher_auth_kind`, `client_public_key`, and `client_signature` unchanged while
/// recording the lookup caller separately in `invalidated_by` and `invalidator_auth_kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerCacheLedgerSummary {
    #[serde(default = "default_answer_cache_domain")]
    pub cache_domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    pub cache_id: Uuid,
    pub scope: String,
    pub task_id: String,
    #[serde(with = "hex_32")]
    pub query_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub source_bundle_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub state_commitment: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub task_dependency_commitment: Option<[u8; 32]>,
    #[serde(with = "hex_32")]
    pub answer_hash: [u8; 32],
    pub cached_by: String,
    pub cacher_auth_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub client_public_key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_vec")]
    pub client_signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidator_auth_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub observed_state_commitment: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub observed_dependency_commitment: Option<[u8; 32]>,
}

/// Auditor-readable summary + raw BLAKE3 preimage exposed on `EvidenceEntry` when an entry
/// notarizes a `trusted_witnesses` enrollment (`acta:witness_reg:v1`, `v2`, or description-bound `v3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRegistrationSummary {
    pub witness_id: String,
    #[serde(with = "hex_32")]
    pub public_key: [u8; 32],
    pub registered_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub registration_domain: String,
    pub registration_blake3_preimage_hex: String,
}

/// Auditor-readable summary + raw BLAKE3 preimage exposed on `EvidenceEntry` when an entry
/// notarizes an append-only witness revocation (`acta:witness_revoke:v1`, `v1.6.3+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRevocationSummary {
    pub witness_id: String,
    #[serde(with = "hex_32")]
    pub public_key: [u8; 32],
    pub revoked_by: String,
    #[serde(default = "default_revocation_mode")]
    pub revocation_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from_tree_size: Option<i64>,
    pub reason: String,
    pub revocation_domain: String,
    pub revocation_blake3_preimage_hex: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_facts_omitted: Option<usize>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_domain: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_summary: Option<WriteLedgerSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_cache_summary: Option<AnswerCacheLedgerSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_reg_summary: Option<WitnessRegistrationSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_revoke_summary: Option<WitnessRevocationSummary>,
    #[serde(with = "hex_64")]
    pub host_signature: [u8; 64],
    pub created_at: DateTime<Utc>,
}

impl EvidenceEntry {
    pub fn inferred_event_domain(
        has_refusal_metadata: bool,
        has_override_summary: bool,
    ) -> &'static str {
        Self::inferred_event_domain_v17(has_refusal_metadata, has_override_summary, false, false)
    }

    pub fn inferred_event_domain_v17(
        has_refusal_metadata: bool,
        has_override_summary: bool,
        has_write_summary: bool,
        has_answer_cache_summary: bool,
    ) -> &'static str {
        Self::inferred_event_domain_v172(
            has_refusal_metadata,
            has_override_summary,
            has_write_summary,
            has_answer_cache_summary,
            false,
        )
    }

    pub fn inferred_event_domain_v172(
        has_refusal_metadata: bool,
        has_override_summary: bool,
        has_write_summary: bool,
        has_answer_cache_summary: bool,
        witness_in_v3: bool,
    ) -> &'static str {
        if has_write_summary || has_answer_cache_summary || witness_in_v3 {
            "acta:evidence_event:v3"
        } else if has_refusal_metadata || has_override_summary {
            "acta:evidence_event:v2"
        } else {
            "acta:evidence_event:v1"
        }
    }

    /// Returns whether this entry's witness registration/revocation summary is bound directly
    /// into `acta:evidence_event:v3` (`v1.7.2+`) rather than legacy `v1` (`seq <= 184`).
    pub fn uses_witness_v3_event_domain(&self) -> bool {
        (self.witness_reg_summary.is_some() || self.witness_revoke_summary.is_some())
            && self.event_domain.as_deref() == Some("acta:evidence_event:v3")
    }

    pub fn expected_event_domain_str(&self) -> &'static str {
        Self::inferred_event_domain_v172(
            self.refusal_metadata.is_some(),
            self.override_summary.is_some(),
            self.write_summary.is_some(),
            self.answer_cache_summary.is_some(),
            self.uses_witness_v3_event_domain(),
        )
    }
}

/// Enrolled trusted external witness record pinned in `trusted_witnesses` (`v1.6.1+`),
/// with append-only revocation provenance joined from `witness_revocations` (`v1.6.3+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedWitness {
    pub tenant_id: String,
    pub witness_id: String,
    #[serde(with = "hex_32")]
    pub public_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub registered_by: String,
    #[serde(default = "default_witness_reg_domain")]
    pub reg_domain: String,
    pub evidence_seq_num: i64,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from_tree_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_evidence_seq_num: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWitnessRequest {
    pub tenant_id: String,
    pub witness_id: String,
    pub witness_public_key_hex: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWitnessResponse {
    pub tenant_id: String,
    pub witness_id: String,
    pub witness_public_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub registered_by: String,
    pub registration_domain: String,
    pub registration_blake3_preimage_hex: String,
    pub registration_commitment_hex: String,
    pub evidence_seq_num: i64,
    pub active: bool,
    pub was_idempotent_noop: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeWitnessRequest {
    pub tenant_id: String,
    pub witness_id: String,
    #[serde(default, alias = "revocation_mode")]
    pub mode: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeWitnessResponse {
    pub tenant_id: String,
    pub witness_id: String,
    pub witness_public_key_hex: String,
    pub revoked_by: String,
    pub revocation_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from_tree_size: Option<i64>,
    pub reason: String,
    pub revocation_domain: String,
    pub revocation_blake3_preimage_hex: String,
    pub revocation_commitment_hex: String,
    pub evidence_seq_num: i64,
    pub active: bool,
    pub was_idempotent_noop: bool,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedAnchorRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub tree_size: i64,
    #[serde(with = "hex_32")]
    pub head_event_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub merkle_root: [u8; 32],
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
    #[serde(default = "default_quarantine_merkle_scheme")]
    pub merkle_scheme: String,
    pub quarantine_reason: String,
}

fn default_quarantine_merkle_scheme() -> String {
    "rfc6962-sha256-v1".to_string()
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInclusionProof {
    pub entry: EvidenceEntry,
    pub audit_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleBundleProof {
    pub checkpoint: SignedTreeHead,
    pub bundle_entry_proof: EntryInclusionProof,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_entry_proofs: Vec<EntryInclusionProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_entry_proofs: Vec<EntryInclusionProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consistency_proof_to_anchor: Vec<String>,
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

fn default_state_rebuild_archive_schema() -> String {
    STATE_REBUILD_ARCHIVE_SCHEMA_V1.to_string()
}

/// Portable, host-header-signed cryptographic state-rebuild proof archive (`v1.7.2+`, PPA 1 Claim 1 & §11)
/// enabling an independent third party (`acta-verify`, Python `acta_sdk`, or TypeScript `@acta/sdk`)
/// to verify `(scope, up_to_seq, evaluated_at, permission_root)`, `evidence_chain[1..=up_to_seq]`,
/// `SignedTreeHead`, witness cosignatures, and strip-proof `override_attestations` (always serialized
/// even when empty) and reconstruct active scope state + `state_commitment` completely offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRebuildArchive {
    #[serde(default = "default_state_rebuild_archive_schema")]
    pub schema_version: String,
    pub tenant_id: String,
    pub scope: String,
    pub up_to_seq: i64,
    pub evaluated_at: DateTime<Utc>,
    #[serde(with = "hex_32")]
    pub host_public_key: [u8; 32],
    #[serde(with = "hex_32")]
    pub permission_root: [u8; 32],
    #[serde(with = "hex_32")]
    pub header_hash: [u8; 32],
    #[serde(with = "hex_64")]
    pub host_header_signature: [u8; 64],
    #[serde(default)]
    pub override_attestations: Vec<OverrideAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_chain: Vec<EvidenceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_anchored_checkpoint: Option<SignedTreeHead>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consistency_proof_from_latest_anchor: Vec<String>,
}
