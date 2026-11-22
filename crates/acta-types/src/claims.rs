use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::objects::LifecycleStatus;
use crate::serde_hex::{hex_32, hex_64, opt_hex_32, opt_hex_vec};

pub type ClaimStatus = LifecycleStatus;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeClaim {
    pub id: Uuid,
    pub tenant_id: String,
    #[serde(with = "hex_32")]
    pub claim_group_key: [u8; 32],
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub object_val: serde_json::Value,
    pub object_type: String,
    pub confidence: f64,
    pub source_provenance_class: i32,
    pub source_descriptor: String,
    #[serde(with = "hex_32")]
    pub source_commitment: [u8; 32],
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
    pub status: ClaimStatus,
    pub contradiction_ids: Vec<Uuid>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisputeReasonCode {
    InsufficientConfidence,
    InsufficientMargin,
    BlockingContradiction,
    TypeMismatch,
}

impl DisputeReasonCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisputeReasonCode::InsufficientConfidence => "INSUFFICIENT_CONFIDENCE",
            DisputeReasonCode::InsufficientMargin => "INSUFFICIENT_MARGIN",
            DisputeReasonCode::BlockingContradiction => "BLOCKING_CONTRADICTION",
            DisputeReasonCode::TypeMismatch => "TYPE_MISMATCH",
        }
    }
}

fn default_one_usize() -> usize {
    1
}

fn is_one_usize(n: &usize) -> bool {
    *n <= 1
}

fn is_none_f64(v: &Option<f64>) -> bool {
    v.is_none()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimCandidate {
    pub id: Uuid,
    pub subject: String,
    pub predicate: String,
    pub object_val: serde_json::Value,
    pub object_type: String,
    pub confidence: f64,
    pub source_provenance_class: i32,
    pub source_descriptor: String,
    #[serde(with = "hex_32")]
    pub source_commitment: [u8; 32],
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
    pub version: i32,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_one_usize", skip_serializing_if = "is_one_usize")]
    pub corroborating_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corroborating_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "is_none_f64")]
    pub effective_confidence: Option<f64>,
}

impl From<&KnowledgeClaim> for ClaimCandidate {
    fn from(c: &KnowledgeClaim) -> Self {
        Self {
            id: c.id,
            subject: c.subject.clone(),
            predicate: c.predicate.clone(),
            object_val: c.object_val.clone(),
            object_type: c.object_type.clone(),
            confidence: c.confidence,
            source_provenance_class: c.source_provenance_class,
            source_descriptor: c.source_descriptor.clone(),
            source_commitment: c.source_commitment,
            content_hash: c.content_hash,
            version: c.version,
            created_at: c.created_at,
            corroborating_count: 1,
            corroborating_sources: Vec::new(),
            effective_confidence: None,
        }
    }
}

/// Content-addressed reference to a competing claim superseded by a signed `OverrideAttestation`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OverriddenClaimRef {
    pub id: Uuid,
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
}

/// Embedded attestation proof inside a `ResolutionRecord` when a dispute was adjudicated via override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideResolutionRef {
    pub attestation_id: Uuid,
    #[serde(with = "hex_32")]
    pub attestation_hash: [u8; 32],
    pub adjudicator_id: String,
    pub justification: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub source_bundle_hash: Option<[u8; 32]>,
    pub evidence_seq_num: i64,
    pub version: i32,
    pub attested_at: DateTime<Utc>,
}

/// Immutable, Ed25519-notarized adjudication overriding a specific set of competing claims
/// in `(tenant_id, scope, claim_group_key)`. If a new unseen conflicting claim arrives later,
/// the resolver detects that its `(id, content_hash)` is absent from `overridden_claims` and
/// automatically re-escalates to `[DISPUTE]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideAttestation {
    pub id: Uuid,
    pub tenant_id: String,
    pub scope: String,
    #[serde(with = "hex_32")]
    pub claim_group_key: [u8; 32],
    pub subject: String,
    pub predicate: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub source_bundle_hash: Option<[u8; 32]>,
    pub winning_claim_id: Uuid,
    #[serde(with = "hex_32")]
    pub winning_claim_content_hash: [u8; 32],
    pub overridden_claims: Vec<OverriddenClaimRef>,
    pub adjudicator_id: String,
    pub justification: String,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    #[serde(with = "hex_32")]
    pub attestation_hash: [u8; 32],
    pub evidence_seq_num: i64,
    #[serde(with = "hex_64")]
    pub host_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_vec")]
    pub client_signature: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_32")]
    pub client_public_key: Option<[u8; 32]>,
}

impl From<&OverrideAttestation> for OverrideResolutionRef {
    fn from(att: &OverrideAttestation) -> Self {
        Self {
            attestation_id: att.id,
            attestation_hash: att.attestation_hash,
            adjudicator_id: att.adjudicator_id.clone(),
            justification: att.justification.clone(),
            source_bundle_hash: att.source_bundle_hash,
            evidence_seq_num: att.evidence_seq_num,
            version: att.version,
            attested_at: att.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolutionRecord {
    #[serde(with = "hex_32")]
    pub claim_group_key: [u8; 32],
    pub winning_claim: ClaimCandidate,
    pub margin: Option<f64>,
    pub suppressed_claim_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_attestation: Option<OverrideResolutionRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisputeRecord {
    #[serde(with = "hex_32")]
    pub claim_group_key: [u8; 32],
    pub competing_claims: Vec<ClaimCandidate>,
    pub reason_code: DisputeReasonCode,
    pub escalation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestClaimRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub object_val: serde_json::Value,
    pub object_type: String,
    pub confidence: f64,
    #[serde(default)]
    pub source_provenance_class: i32,
    pub source_descriptor: String,
    #[serde(default)]
    pub source_commitment_hex: Option<String>,
    #[serde(default = "default_active_status")]
    pub status: ClaimStatus,
    #[serde(default)]
    pub contradiction_ids: Vec<Uuid>,
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub valid_to: Option<DateTime<Utc>>,
    #[serde(default)]
    pub predecessor_id: Option<Uuid>,
    #[serde(default)]
    pub client_signature_hex: Option<String>,
    #[serde(default)]
    pub client_public_key_hex: Option<String>,
}

fn default_active_status() -> ClaimStatus {
    ClaimStatus::Active
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestClaimResponse {
    pub id: Uuid,
    pub version: i32,
    pub claim_group_key: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestOverrideRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    pub scope: String,
    pub winning_claim_id: Uuid,
    #[serde(default)]
    pub source_bundle_hash_hex: Option<String>,
    pub adjudicator_id: String,
    pub justification: String,
    #[serde(default)]
    pub client_signature_hex: Option<String>,
    #[serde(default)]
    pub client_public_key_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestOverrideResponse {
    pub id: Uuid,
    pub version: i32,
    pub claim_group_key: String,
    pub subject: String,
    pub predicate: String,
    pub winning_claim_id: Uuid,
    pub winning_claim_content_hash: String,
    pub overridden_claim_ids: Vec<Uuid>,
    pub adjudicator_id: String,
    pub justification: String,
    pub attestation_hash: String,
    pub evidence_seq_num: i64,
    pub host_signature: String,
    pub was_idempotent_noop: bool,
    pub created_at: DateTime<Utc>,
}
