use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::serde_hex::{hex_32, hex_64, opt_hex_32, opt_hex_vec};

pub use crate::objects::LifecycleStatus as ClaimStatus;

pub const OVERRIDE_DOMAIN_V1: &str = "acta:override:v1";
pub const OVERRIDE_DOMAIN_V2: &str = "acta:override:v2";

fn default_override_domain() -> String {
    OVERRIDE_DOMAIN_V1.to_string()
}

/// Infers `adjudicator_auth_kind` / `writer_auth_kind` deterministically when not explicitly stored.
pub fn infer_override_auth_kind(adjudicator_id: &str, has_client_signature: bool) -> &'static str {
    if has_client_signature {
        "ed25519_client_sig"
    } else if adjudicator_id.contains("::oauth:") {
        "oauth_github_principal"
    } else if adjudicator_id.ends_with("::master-admin") {
        "master_admin"
    } else {
        "tenant_session"
    }
}

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
    #[serde(default, with = "opt_hex_vec", skip_serializing_if = "Option::is_none")]
    pub client_signature: Option<Vec<u8>>,
    #[serde(default, with = "opt_hex_32", skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_seq_num: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DisputeReasonCode {
    #[serde(rename = "INSUFFICIENT_CONFIDENCE")]
    InsufficientConfidence,
    #[serde(rename = "INSUFFICIENT_MARGIN")]
    InsufficientMargin,
    #[serde(rename = "LAPSED_OVERRIDE_REOPENED")]
    LapsedOverrideReopened,
    #[serde(rename = "BLOCKING_CONTRADICTION")]
    BlockingContradiction,
    #[serde(rename = "TYPE_MISMATCH")]
    TypeMismatch,
}

impl DisputeReasonCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisputeReasonCode::InsufficientConfidence => "INSUFFICIENT_CONFIDENCE",
            DisputeReasonCode::InsufficientMargin => "INSUFFICIENT_MARGIN",
            DisputeReasonCode::LapsedOverrideReopened => "LAPSED_OVERRIDE_REOPENED",
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

/// Provenance attached to a `DisputeRecord` when an active signed `OverrideAttestation` was
/// reopened by newly ingested unseen conflicting claim(s) (`v1.6+`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LapsedOverrideRef {
    pub attestation_id: Uuid,
    #[serde(with = "hex_32")]
    pub attestation_hash: [u8; 32],
    pub prior_winning_claim_id: Uuid,
    pub adjudicator_id: String,
    pub justification: String,
    pub evidence_seq_num: i64,
    pub version: i32,
    pub attested_at: DateTime<Utc>,
    pub reopened_by_claim_ids: Vec<Uuid>,
}

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
    pub source_bundle_hash: Option<[u8; 32],>,
    pub winning_claim_id: Uuid,
    #[serde(with = "hex_32")]
    pub winning_claim_content_hash: [u8; 32],
    pub overridden_claims: Vec<OverriddenClaimRef>,
    pub adjudicator_id: String,
    #[serde(default)]
    pub adjudicator_auth_kind: String,
    pub justification: String,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_override_domain")]
    pub attestation_domain: String,
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

impl OverrideAttestation {
    pub fn effective_domain(&self) -> &str {
        let d = self.attestation_domain.trim();
        if d.is_empty() {
            OVERRIDE_DOMAIN_V1
        } else {
            d
        }
    }

    pub fn effective_auth_kind(&self) -> &str {
        let k = self.adjudicator_auth_kind.trim();
        if k.is_empty() {
            infer_override_auth_kind(&self.adjudicator_id, self.client_signature.is_some())
        } else {
            k
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin: Option<f64>,
    pub reason_code: DisputeReasonCode,
    pub escalation_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lapsed_override: Option<LapsedOverrideRef>,
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
    #[serde(default)]
    pub source_content: Option<String>,
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
    pub erasable: Option<bool>,
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
    pub status: ClaimStatus,
    pub claim_group_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_commitment: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradiction_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_seq_num: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_commitment_hex: Option<String>,
    #[serde(default)]
    pub was_idempotent_noop: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetractClaimRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub claim_id: Uuid,
    pub reason: String,
    #[serde(default)]
    pub erase_secret: Option<bool>,
    #[serde(default)]
    pub client_signature_hex: Option<String>,
    #[serde(default)]
    pub client_public_key_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetractClaimResponse {
    pub tombstone_id: Uuid,
    pub retracted_claim_id: Uuid,
    pub scope: String,
    pub subject: String,
    pub predicate: String,
    pub version: i32,
    pub status: ClaimStatus,
    pub reason: String,
    pub content_hash: String,
    pub evidence_seq_num: i64,
    pub evidence_event_hash: String,
    pub host_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    pub retracted_by: String,
    #[serde(default)]
    pub secret_erased: bool,
    pub was_idempotent_noop: bool,
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
    #[serde(default)]
    pub adjudicator_id: Option<String>,
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
    pub adjudicator_auth_kind: String,
    pub justification: String,
    pub attestation_domain: String,
    pub attestation_hash: String,
    pub evidence_seq_num: i64,
    pub host_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    pub was_idempotent_noop: bool,
    pub created_at: DateTime<Utc>,
}
