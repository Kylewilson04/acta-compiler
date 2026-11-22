use acta_types::{
    ActaResult, ContextBundle, KnowledgeClaim, OmittedItem, OverriddenClaimRef,
    OverrideLedgerSummary, PolicyResultTag, RefusalMetadata, StoredObject,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::canonical::to_canonical_bytes;

/// Computes a multi-field BLAKE3 hash where every input slice is prefixed by its
/// 8-byte little-endian byte length (Invariant 5: Length-Delimited Hashing).
pub fn hash_length_delimited(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        let len_le = (part.len() as u64).to_le_bytes();
        hasher.update(&len_le);
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Legacy v1.0–v1.3 `claim_group_key` over `(tenant, subject, predicate, object_type, scope)`.
/// Retained so `verify_export_archive` continues verifying historical bundles bit-for-bit.
pub fn compute_claim_group_key(
    tenant: &str,
    subject: &str,
    predicate: &str,
    object_type: &str,
    scope: &str,
) -> [u8; 32] {
    hash_length_delimited(&[
        tenant.as_bytes(),
        subject.as_bytes(),
        predicate.as_bytes(),
        object_type.as_bytes(),
        scope.as_bytes(),
    ])
}

/// Canonical v1.4+ type-agnostic `claim_group_key` over `(tenant, subject, predicate, scope)`
/// so conflicting JSON types (e.g. integer `290` vs string `"290"`) collide in the same group.
pub fn compute_logical_claim_group_key(
    tenant: &str,
    subject: &str,
    predicate: &str,
    scope: &str,
) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:claim_group:v2",
        tenant.as_bytes(),
        subject.as_bytes(),
        predicate.as_bytes(),
        scope.as_bytes(),
    ])
}

/// Computes a deterministic 32-byte commitment over a refusal event's reason code and detail
/// (v1.4 helper retained for compatibility).
pub fn compute_refusal_commitment(reason_code: &str, detail: &str) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:refusal_reason:v1",
        reason_code.as_bytes(),
        detail.as_bytes(),
    ])
}

/// Computes a deterministic 32-byte commitment over canonical `RefusalMetadata` (`v1.5+`).
pub fn compute_refusal_metadata_commitment(meta: &RefusalMetadata) -> ActaResult<[u8; 32]> {
    let canonical = to_canonical_bytes(meta)?;
    Ok(hash_length_delimited(&[
        b"acta:refusal_meta:v2",
        &canonical,
    ]))
}

fn encode_opt_uuid(u: Option<Uuid>) -> [u8; 17] {
    let mut buf = [0u8; 17];
    if let Some(id) = u {
        buf[0] = 1;
        buf[1..17].copy_from_slice(id.as_bytes());
    }
    buf
}

fn encode_opt_i64(v: Option<i64>) -> [u8; 9] {
    let mut buf = [0u8; 9];
    if let Some(n) = v {
        buf[0] = 1;
        buf[1..9].copy_from_slice(&n.to_le_bytes());
    }
    buf
}

fn encode_opt_hash32(h: Option<&[u8; 32]>) -> [u8; 33] {
    let mut buf = [0u8; 33];
    if let Some(bytes) = h {
        buf[0] = 1;
        buf[1..33].copy_from_slice(bytes);
    }
    buf
}

fn encode_opt_jcs<T: serde::Serialize>(opt: Option<&T>) -> ActaResult<Vec<u8>> {
    match opt {
        None => Ok(vec![0u8]),
        Some(v) => {
            let jcs = to_canonical_bytes(v)?;
            let mut out = Vec::with_capacity(1 + jcs.len());
            out.push(1u8);
            out.extend_from_slice(&jcs);
            Ok(out)
        }
    }
}

/// Computes the canonical `content_hash` for an immutable `StoredObject`.
pub fn compute_object_content_hash(obj: &StoredObject) -> ActaResult<[u8; 32]> {
    let canonical_tags = to_canonical_bytes(&obj.tags)?;
    let canonical_body = to_canonical_bytes(&obj.body)?;
    let priority_le = obj.priority.to_le_bytes();
    let importance_bits_le = obj.importance.to_bits().to_le_bytes();
    let version_le = obj.version.to_le_bytes();
    let pred_bytes = encode_opt_uuid(obj.predecessor_id);
    let created_micros_le = obj.created_at.timestamp_micros().to_le_bytes();

    Ok(hash_length_delimited(&[
        b"acta:object:v1",
        obj.id.as_bytes(),
        obj.tenant_id.as_bytes(),
        obj.obj_type.as_str().as_bytes(),
        obj.scope.as_bytes(),
        obj.lifecycle_status.as_str().as_bytes(),
        &priority_le,
        &importance_bits_le,
        &canonical_tags,
        &canonical_body,
        &version_le,
        &pred_bytes,
        &created_micros_le,
    ]))
}

/// Computes the canonical `content_hash` for an immutable `KnowledgeClaim`.
pub fn compute_claim_content_hash(claim: &KnowledgeClaim) -> ActaResult<[u8; 32]> {
    let canonical_val = to_canonical_bytes(&claim.object_val)?;
    let mut sorted_contradictions = claim.contradiction_ids.clone();
    sorted_contradictions.sort_unstable();
    let canonical_contradictions = to_canonical_bytes(&sorted_contradictions)?;

    let conf_bits_le = claim.confidence.to_bits().to_le_bytes();
    let prov_le = claim.source_provenance_class.to_le_bytes();
    let valid_from_bytes = encode_opt_i64(claim.valid_from.map(|t| t.timestamp_micros()));
    let valid_to_bytes = encode_opt_i64(claim.valid_to.map(|t| t.timestamp_micros()));
    let version_le = claim.version.to_le_bytes();
    let pred_bytes = encode_opt_uuid(claim.predecessor_id);
    let created_micros_le = claim.created_at.timestamp_micros().to_le_bytes();

    Ok(hash_length_delimited(&[
        b"acta:claim:v1",
        claim.id.as_bytes(),
        claim.tenant_id.as_bytes(),
        &claim.claim_group_key,
        claim.scope.as_bytes(),
        claim.subject.as_bytes(),
        claim.predicate.as_bytes(),
        &canonical_val,
        claim.object_type.as_bytes(),
        &conf_bits_le,
        &prov_le,
        claim.source_descriptor.as_bytes(),
        &claim.source_commitment,
        claim.status.as_str().as_bytes(),
        &canonical_contradictions,
        &valid_from_bytes,
        &valid_to_bytes,
        &version_le,
        &pred_bytes,
        &created_micros_le,
    ]))
}

/// Deterministic clock-free client signing digest (`b"acta:override_client_sig:v1"`) so external
/// human/committee Ed25519 keys can sign an override adjudication offline without knowing the
/// server's generated UUID or microsecond timestamp.
pub fn compute_override_client_intent_hash(
    tenant_id: &str,
    scope: &str,
    winning_claim_id: Uuid,
    adjudicator_id: &str,
    justification: &str,
) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:override_client_sig:v1",
        tenant_id.as_bytes(),
        scope.as_bytes(),
        winning_claim_id.as_bytes(),
        adjudicator_id.as_bytes(),
        justification.as_bytes(),
    ])
}

/// Computes the deterministic 32-byte `checkpoint_hash` for a `SignedTreeHead` (`v1.6+`).
pub fn compute_checkpoint_hash(
    tenant_id: &str,
    tree_size: i64,
    head_event_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    issued_at_micros: i64,
) -> [u8; 32] {
    let size_le = tree_size.to_le_bytes();
    let micros_le = issued_at_micros.to_le_bytes();
    hash_length_delimited(&[
        b"acta:checkpoint:v1",
        tenant_id.as_bytes(),
        &size_le,
        head_event_hash,
        merkle_root,
        &micros_le,
    ])
}

/// Input parameters hashed into `OverrideAttestation.attestation_hash` (`b"acta:override:v1"`).
pub struct OverrideHashInput<'a> {
    pub id: Uuid,
    pub tenant_id: &'a str,
    pub scope: &'a str,
    pub claim_group_key: &'a [u8; 32],
    pub subject: &'a str,
    pub predicate: &'a str,
    pub source_bundle_hash: Option<&'a [u8; 32]>,
    pub winning_claim_id: Uuid,
    pub winning_claim_content_hash: &'a [u8; 32],
    pub overridden_claims: &'a [OverriddenClaimRef],
    pub adjudicator_id: &'a str,
    pub justification: &'a str,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Computes the canonical 32-byte `attestation_hash` for an immutable `OverrideAttestation`.
pub fn compute_override_attestation_hash(inp: &OverrideHashInput<'_>) -> ActaResult<[u8; 32]> {
    let mut sorted_overridden = inp.overridden_claims.to_vec();
    sorted_overridden.sort_unstable();
    let canonical_overridden = to_canonical_bytes(&sorted_overridden)?;
    let src_bundle_bytes = encode_opt_hash32(inp.source_bundle_hash);
    let version_le = inp.version.to_le_bytes();
    let pred_bytes = encode_opt_uuid(inp.predecessor_id);
    let created_micros_le = inp.created_at.timestamp_micros().to_le_bytes();

    Ok(hash_length_delimited(&[
        b"acta:override:v1",
        inp.id.as_bytes(),
        inp.tenant_id.as_bytes(),
        inp.scope.as_bytes(),
        inp.claim_group_key,
        inp.subject.as_bytes(),
        inp.predicate.as_bytes(),
        &src_bundle_bytes,
        inp.winning_claim_id.as_bytes(),
        inp.winning_claim_content_hash,
        &canonical_overridden,
        inp.adjudicator_id.as_bytes(),
        inp.justification.as_bytes(),
        &version_le,
        &pred_bytes,
        &created_micros_le,
    ]))
}

/// Computes the length-delimited BLAKE3 hash of the full sorted omission list.
pub fn compute_omission_list_hash(sorted_items: &[OmittedItem]) -> ActaResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let domain = b"acta:omissions:v1";
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);

    let mut item_buf = [0u8; 96];
    item_buf[..7].copy_from_slice(b"{\"id\":\"");
    item_buf[43..55].copy_from_slice(b"\",\"reason\":\"");

    for item in sorted_items {
        item.id.hyphenated().encode_lower(&mut item_buf[7..43]);
        let reason_bytes = item.reason.as_str().as_bytes();
        let reason_end = 55 + reason_bytes.len();
        item_buf[55..reason_end].copy_from_slice(reason_bytes);
        item_buf[reason_end..reason_end + 2].copy_from_slice(b"\"}");
        let total_len = reason_end + 2;

        hasher.update(&(total_len as u64).to_le_bytes());
        hasher.update(&item_buf[..total_len]);
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Canonicalizes `ContextBundle` (RFC 8785) and computes `bundle_hash`.
pub fn compute_bundle_hash(bundle: &ContextBundle) -> ActaResult<([u8; 32], Vec<u8>)> {
    let canonical = to_canonical_bytes(bundle)?;
    let hash = hash_length_delimited(&[b"acta:bundle:v1", &canonical]);
    Ok((hash, canonical))
}

/// Computes the deterministic v1 `event_hash` for an `evidence_history` entry without extended metadata.
pub fn compute_evidence_event_hash(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
) -> [u8; 32] {
    let seq_le = seq_num.to_le_bytes();
    let bundle_bytes = encode_opt_hash32(bundle_hash);
    let state_bytes = encode_opt_hash32(state_commitment);
    let created_le = created_at_micros.to_le_bytes();

    hash_length_delimited(&[
        b"acta:evidence_event:v1",
        tenant_id.as_bytes(),
        &seq_le,
        prev_hash,
        &bundle_bytes,
        &state_bytes,
        policy_result.as_str().as_bytes(),
        &created_le,
    ])
}

/// Computes the deterministic `event_hash` for an `evidence_history` entry:
/// - Uses `b"acta:evidence_event:v1"` whenever `refusal_metadata.is_none() && override_summary.is_none()`
/// - Uses `b"acta:evidence_event:v2"` binding canonical `refusal_metadata` and `override_summary`
///   whenever either metadata struct is present.
pub fn compute_evidence_event_hash_with_meta(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
) -> ActaResult<[u8; 32]> {
    if refusal_metadata.is_none() && override_summary.is_none() {
        return Ok(compute_evidence_event_hash(
            tenant_id,
            seq_num,
            prev_hash,
            bundle_hash,
            state_commitment,
            policy_result,
            created_at_micros,
        ));
    }

    let seq_le = seq_num.to_le_bytes();
    let bundle_bytes = encode_opt_hash32(bundle_hash);
    let state_bytes = encode_opt_hash32(state_commitment);
    let created_le = created_at_micros.to_le_bytes();
    let refusal_tagged = encode_opt_jcs(refusal_metadata)?;
    let override_tagged = encode_opt_jcs(override_summary)?;

    Ok(hash_length_delimited(&[
        b"acta:evidence_event:v2",
        tenant_id.as_bytes(),
        &seq_le,
        prev_hash,
        &bundle_bytes,
        &state_bytes,
        policy_result.as_str().as_bytes(),
        &created_le,
        &refusal_tagged,
        &override_tagged,
    ]))
}
