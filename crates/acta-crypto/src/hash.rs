use std::collections::BTreeSet;

use acta_types::{ERASABLE_CLAIM_DOMAIN_V1, HOST_KEY_ROTATE_DOMAIN_V1, HostKeyRotationSummary,

    ActaError, ActaResult, AnswerCacheLedgerSummary, ClaimCandidate, ClaimStatus, ContextBundle,
    KnowledgeClaim, LifecycleStatus, ObjectType, OmittedItem, OverriddenClaimRef,
    OverrideLedgerSummary, PolicyResultTag, RefusalMetadata, StoredObject,
    WitnessRegistrationSummary, WitnessRevocationSummary, WriteLedgerSummary, OVERRIDE_DOMAIN_V1,
    OVERRIDE_DOMAIN_V2, WITNESS_REG_DOMAIN_V1, WITNESS_REG_DOMAIN_V2, WITNESS_REG_DOMAIN_V3,
    WITNESS_REVOKE_DOMAIN_V1, WITNESS_REVOKE_DOMAIN_V2,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::canonical::to_canonical_bytes;

/// Encodes `parts` using Acta's 8-byte little-endian length-delimited framing
/// (`concat_i(u64_le(len(part_i)) || part_i)`), returning the exact byte buffer hashed by BLAKE3.
pub fn encode_length_delimited(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| 8 + p.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

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

/// Computes the 7-part length-delimited preimage for `StateRebuildArchive.header_hash` (`b"acta:rebuild_header:v1"`),
/// binding `(schema_version, tenant_id, scope, up_to_seq, evaluated_at_micros, permission_root)` under host Ed25519 signing.
pub fn rebuild_archive_header_preimage_bytes(
    schema_version: &str,
    tenant_id: &str,
    scope: &str,
    up_to_seq: i64,
    evaluated_at_micros: i64,
    permission_root: &[u8; 32],
) -> Vec<u8> {
    let seq_le = up_to_seq.to_le_bytes();
    let eval_le = evaluated_at_micros.to_le_bytes();
    encode_length_delimited(&[
        b"acta:rebuild_header:v1",
        schema_version.as_bytes(),
        tenant_id.as_bytes(),
        scope.as_bytes(),
        &seq_le,
        &eval_le,
        permission_root,
    ])
}

/// Computes the 32-byte `header_hash` (`b"acta:rebuild_header:v1"`) for `StateRebuildArchive`.
pub fn compute_rebuild_archive_header_hash(
    schema_version: &str,
    tenant_id: &str,
    scope: &str,
    up_to_seq: i64,
    evaluated_at_micros: i64,
    permission_root: &[u8; 32],
) -> [u8; 32] {
    let pre = rebuild_archive_header_preimage_bytes(
        schema_version,
        tenant_id,
        scope,
        up_to_seq,
        evaluated_at_micros,
        permission_root,
    );
    *blake3::hash(&pre).as_bytes()
}

fn json_value_family_tag(val: &Value) -> u8 {
    match val {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Object(_) => 5,
    }
}

/// Returns `true` iff `candidate` belongs to the exact same `ValueBucket` (`(ValueTypeFamily, rfc8785_jcs(object_val))`)
/// as `winner` in the epistemic resolver (`v1.7.2+`).
pub fn claims_share_winning_value_bucket(
    winner: &ClaimCandidate,
    candidate: &KnowledgeClaim,
) -> bool {
    if json_value_family_tag(&winner.object_val) != json_value_family_tag(&candidate.object_val) {
        return false;
    }
    let w_jcs = to_canonical_bytes(&winner.object_val)
        .unwrap_or_else(|_| winner.object_val.to_string().into_bytes());
    let c_jcs = to_canonical_bytes(&candidate.object_val)
        .unwrap_or_else(|_| candidate.object_val.to_string().into_bytes());
    w_jcs == c_jcs
}

/// Sorts agreeing `KnowledgeClaim`s in a winning `ValueBucket` using the exact resolver tie-breaker order
/// and recomputes `(corroborating_count, corroborating_sources, effective_confidence)` via damped noisy-OR.
pub fn recompute_winning_bucket_corroboration(
    bucket_claims: &[&KnowledgeClaim],
    damping: f64,
) -> Result<(usize, Vec<String>, f64), String> {
    if bucket_claims.is_empty() {
        return Err("winning value bucket cannot be empty".to_string());
    }
    let mut sorted: Vec<&KnowledgeClaim> = bucket_claims.to_vec();
    sorted.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then_with(|| b.source_provenance_class.cmp(&a.source_provenance_class))
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| b.version.cmp(&a.version))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut seen_sources = BTreeSet::new();
    for c in &sorted {
        if !seen_sources.insert(c.source_descriptor.as_str()) {
            return Err(format!(
                "duplicate source_descriptor '{}' inside corroborating value bucket",
                c.source_descriptor
            ));
        }
    }

    let lead_conf = sorted[0].confidence;
    let round_9 = |v: f64| (v * 1_000_000_000.0).round() / 1_000_000_000.0;
    let effective_confidence = if sorted.len() == 1 {
        round_9(lead_conf)
    } else {
        let mut unconvinced = 1.0_f64;
        for c in &sorted[1..] {
            unconvinced *= (1.0 - damping * c.confidence).clamp(0.0, 1.0);
        }
        round_9((lead_conf + (1.0 - lead_conf) * (1.0 - unconvinced)).min(0.9999))
    };

    let sources: Vec<String> = sorted.iter().map(|c| c.source_descriptor.clone()).collect();
    Ok((sorted.len(), sources, effective_confidence))
}

/// Computes a content-bound `source_commitment` binding both `source_descriptor` and raw
/// `source_content` bytes (`b"acta:source_content:v1"`).
pub fn compute_source_content_commitment(
    source_descriptor: &str,
    source_content: &[u8],
) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:source_content:v1",
        source_descriptor.as_bytes(),
        source_content,
    ])
}

/// Computes a deterministic 32-byte query digest (`b"acta:query:v1"`) for Answer Cache keys.
pub fn compute_query_text_hash(query_text: &str) -> [u8; 32] {
    hash_length_delimited(&[b"acta:query:v1", query_text.as_bytes()])
}

/// Computes a deterministic 32-byte answer digest (`b"acta:answer:v1"`, PPA 1 Claim 19 & Claim 22).
pub fn compute_answer_text_hash(answer_text: &str) -> [u8; 32] {
    hash_length_delimited(&[b"acta:answer:v1", answer_text.as_bytes()])
}

/// Computes the PPA 1 Claim 25 task-scoped dependency commitment (`b"acta:cache_dep_root:v1"`):
/// `BLAKE3_LD("acta:cache_dep_root:v1", tenant_id, scope, permission_root, intent_root, selected_memory_root, relevant_knowledge_root)`.
pub fn compute_task_dependency_commitment(
    tenant_id: &str,
    scope: &str,
    permission_root: &[u8; 32],
    intent_root: &[u8; 32],
    selected_memory_root: &[u8; 32],
    relevant_knowledge_root: &[u8; 32],
) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:cache_dep_root:v1",
        tenant_id.as_bytes(),
        scope.as_bytes(),
        permission_root,
        intent_root,
        selected_memory_root,
        relevant_knowledge_root,
    ])
}

fn encode_opt_utf8(opt: Option<&str>) -> Vec<u8> {
    match opt {
        None => vec![0u8],
        Some(s) => {
            let b = s.as_bytes();
            let mut out = Vec::with_capacity(1 + b.len());
            out.push(1u8);
            out.extend_from_slice(b);
            out
        }
    }
}

/// Returns the raw length-delimited byte preimage hashed into `state_commitment` for a witness
/// registration entry (`"acta:witness_reg:v1"`, principal-bound `"acta:witness_reg:v2"`, or
/// principal+description-bound `"acta:witness_reg:v3"`).
pub fn witness_registration_preimage_bytes(
    reg_domain: &str,
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    registered_by: &str,
    description: Option<&str>,
) -> Result<Vec<u8>, String> {
    match reg_domain {
        WITNESS_REG_DOMAIN_V1 => Ok(encode_length_delimited(&[
            b"acta:witness_reg:v1",
            tenant_id.as_bytes(),
            witness_id.as_bytes(),
            public_key,
        ])),
        WITNESS_REG_DOMAIN_V2 => Ok(encode_length_delimited(&[
            b"acta:witness_reg:v2",
            tenant_id.as_bytes(),
            witness_id.as_bytes(),
            public_key,
            registered_by.as_bytes(),
        ])),
        WITNESS_REG_DOMAIN_V3 => {
            let opt_desc = encode_opt_utf8(description);
            Ok(encode_length_delimited(&[
                b"acta:witness_reg:v3",
                tenant_id.as_bytes(),
                witness_id.as_bytes(),
                public_key,
                registered_by.as_bytes(),
                &opt_desc,
            ]))
        }
        other => Err(format!("unsupported witness registration_domain: {other}")),
    }
}

/// Returns `(raw_preimage_bytes, state_commitment)` for `"acta:witness_reg:v1"`, `"v2"`, or `"v3"`.
pub fn compute_witness_registration_by_domain(
    reg_domain: &str,
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    registered_by: &str,
    description: Option<&str>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let preimage = witness_registration_preimage_bytes(
        reg_domain,
        tenant_id,
        witness_id,
        public_key,
        registered_by,
        description,
    )?;
    let comm = *blake3::hash(&preimage).as_bytes();
    Ok((preimage, comm))
}

/// Computes the legacy v1.6.1 `state_commitment` recorded in `evidence_history` when enrolling a
/// trusted witness Ed25519 key (`b"acta:witness_reg:v1"`).
pub fn compute_witness_registration_commitment(
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:witness_reg:v1",
        tenant_id.as_bytes(),
        witness_id.as_bytes(),
        public_key,
    ])
}

/// Computes the v1.6.2 `(raw_preimage_bytes, state_commitment)` (`b"acta:witness_reg:v2"`).
pub fn compute_witness_registration_v2_commitment(
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    registered_by: &str,
) -> (Vec<u8>, [u8; 32]) {
    let preimage = encode_length_delimited(&[
        b"acta:witness_reg:v2",
        tenant_id.as_bytes(),
        witness_id.as_bytes(),
        public_key,
        registered_by.as_bytes(),
    ]);
    let digest = *blake3::hash(&preimage).as_bytes();
    (preimage, digest)
}

/// Computes the v1.6.3+ principal- and description-bound `(raw_preimage_bytes, state_commitment)`
/// recorded in `evidence_history` when enrolling a trusted witness (`b"acta:witness_reg:v3"`).
pub fn compute_witness_registration_v3_commitment(
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    registered_by: &str,
    description: Option<&str>,
) -> (Vec<u8>, [u8; 32]) {
    let opt_desc = encode_opt_utf8(description);
    let preimage = encode_length_delimited(&[
        b"acta:witness_reg:v3",
        tenant_id.as_bytes(),
        witness_id.as_bytes(),
        public_key,
        registered_by.as_bytes(),
        &opt_desc,
    ]);
    let digest = *blake3::hash(&preimage).as_bytes();
    (preimage, digest)
}

/// Returns the raw length-delimited byte preimage hashed into `state_commitment` when revoking or
/// retiring an enrolled witness (`"acta:witness_revoke:v1"` or mode-bound `"acta:witness_revoke:v2"`).
pub fn witness_revocation_preimage_bytes(
    revoke_domain: &str,
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    revoked_by: &str,
    revocation_mode: &str,
    effective_from_tree_size: Option<i64>,
    reason: &str,
) -> Result<Vec<u8>, String> {
    match revoke_domain {
        WITNESS_REVOKE_DOMAIN_V1 => Ok(encode_length_delimited(&[
            b"acta:witness_revoke:v1",
            tenant_id.as_bytes(),
            witness_id.as_bytes(),
            public_key,
            revoked_by.as_bytes(),
            reason.as_bytes(),
        ])),
        WITNESS_REVOKE_DOMAIN_V2 => {
            match (revocation_mode, effective_from_tree_size) {
                ("compromise", None) => {}
                ("retire", Some(sz)) if sz >= 1 => {}
                ("retire", _) => {
                    return Err(
                        "acta:witness_revoke:v2 mode='retire' requires effective_from_tree_size >= 1"
                            .to_string(),
                    );
                }
                ("compromise", Some(_)) => {
                    return Err(
                        "acta:witness_revoke:v2 mode='compromise' must have effective_from_tree_size=None"
                            .to_string(),
                    );
                }
                (other, _) => {
                    return Err(format!(
                        "unsupported witness revocation_mode '{other}' (expected 'compromise' or 'retire')"
                    ));
                }
            }
            let eff_bytes = encode_opt_i64(effective_from_tree_size);
            Ok(encode_length_delimited(&[
                b"acta:witness_revoke:v2",
                tenant_id.as_bytes(),
                witness_id.as_bytes(),
                public_key,
                revoked_by.as_bytes(),
                revocation_mode.as_bytes(),
                &eff_bytes,
                reason.as_bytes(),
            ]))
        }
        other => Err(format!("unsupported witness revocation_domain: {other}")),
    }
}

pub fn compute_witness_revocation_by_domain(
    revoke_domain: &str,
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    revoked_by: &str,
    revocation_mode: &str,
    effective_from_tree_size: Option<i64>,
    reason: &str,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let preimage = witness_revocation_preimage_bytes(
        revoke_domain,
        tenant_id,
        witness_id,
        public_key,
        revoked_by,
        revocation_mode,
        effective_from_tree_size,
        reason,
    )?;
    let comm = *blake3::hash(&preimage).as_bytes();
    Ok((preimage, comm))
}

/// Legacy `v1.6.3` witness revocation commitment (`b"acta:witness_revoke:v1"`).
pub fn compute_witness_revocation_commitment(
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    revoked_by: &str,
    reason: &str,
) -> (Vec<u8>, [u8; 32]) {
    let preimage = encode_length_delimited(&[
        b"acta:witness_revoke:v1",
        tenant_id.as_bytes(),
        witness_id.as_bytes(),
        public_key,
        revoked_by.as_bytes(),
        reason.as_bytes(),
    ]);
    let digest = *blake3::hash(&preimage).as_bytes();
    (preimage, digest)
}

/// Mode-bound `v1.6.4+` witness revocation/retirement commitment (`b"acta:witness_revoke:v2"`).
pub fn compute_witness_revocation_v2_commitment(
    tenant_id: &str,
    witness_id: &str,
    public_key: &[u8; 32],
    revoked_by: &str,
    revocation_mode: &str,
    effective_from_tree_size: Option<i64>,
    reason: &str,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    compute_witness_revocation_by_domain(
        WITNESS_REVOKE_DOMAIN_V2,
        tenant_id,
        witness_id,
        public_key,
        revoked_by,
        revocation_mode,
        effective_from_tree_size,
        reason,
    )
}

/// Legacy v1.0–v1.3 `claim_group_key` over `(tenant, subject, predicate, object_type, scope)`.
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

/// Canonical v1.4+ type-agnostic `claim_group_key` over `(tenant, subject, predicate, scope)`.
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

/// Computes a deterministic 32-byte commitment over a refusal event's reason code and detail.
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

/// Computes a deterministic 32-byte commitment over canonical `WriteLedgerSummary` (`v1.7.0+`, `b"acta:write_event:v1"`).
pub fn compute_write_summary_commitment(summary: &WriteLedgerSummary) -> ActaResult<[u8; 32]> {
    let canonical = to_canonical_bytes(summary)?;
    Ok(hash_length_delimited(&[
        b"acta:write_event:v1",
        &canonical,
    ]))
}

/// Computes a deterministic 32-byte commitment over canonical `AnswerCacheLedgerSummary` (`v1.7.0+`, `b"acta:answer_cache:v1"`).
pub fn compute_answer_cache_summary_commitment(
    summary: &AnswerCacheLedgerSummary,
) -> ActaResult<[u8; 32]> {
    let canonical = to_canonical_bytes(summary)?;
    Ok(hash_length_delimited(&[
        b"acta:answer_cache:v1",
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

fn encode_opt_sig64(sig: Option<&[u8]>) -> ActaResult<Vec<u8>> {
    match sig {
        None => Ok(vec![0u8]),
        Some(bytes) => {
            if bytes.len() != 64 {
                return Err(ActaError::Validation(format!(
                    "client_signature must be 64 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut out = Vec::with_capacity(65);
            out.push(1u8);
            out.extend_from_slice(bytes);
            Ok(out)
        }
    }
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

/// Clock-free client signing preimage for `StoredObject` (`b"acta:object_client_sig:v1"`, PPA 1 Claim 8).
pub fn object_client_intent_preimage_bytes(
    tenant_id: &str,
    obj_type: ObjectType,
    scope: &str,
    lifecycle_status: LifecycleStatus,
    priority: i32,
    importance: f32,
    tags: &[String],
    body: &Value,
    predecessor_id: Option<Uuid>,
) -> ActaResult<Vec<u8>> {
    let canonical_tags = to_canonical_bytes(tags)?;
    let canonical_body = to_canonical_bytes(body)?;
    let priority_le = priority.to_le_bytes();
    let importance_bits_le = importance.to_bits().to_le_bytes();
    let pred_bytes = encode_opt_uuid(predecessor_id);

    Ok(encode_length_delimited(&[
        b"acta:object_client_sig:v1",
        tenant_id.as_bytes(),
        obj_type.as_str().as_bytes(),
        scope.as_bytes(),
        lifecycle_status.as_str().as_bytes(),
        &priority_le,
        &importance_bits_le,
        &canonical_tags,
        &canonical_body,
        &pred_bytes,
    ]))
}

pub fn compute_object_client_intent_hash(
    tenant_id: &str,
    obj_type: ObjectType,
    scope: &str,
    lifecycle_status: LifecycleStatus,
    priority: i32,
    importance: f32,
    tags: &[String],
    body: &Value,
    predecessor_id: Option<Uuid>,
) -> ActaResult<[u8; 32]> {
    let pre = object_client_intent_preimage_bytes(
        tenant_id,
        obj_type,
        scope,
        lifecycle_status,
        priority,
        importance,
        tags,
        body,
        predecessor_id,
    )?;
    Ok(*blake3::hash(&pre).as_bytes())
}

/// Clock-free client signing preimage for `KnowledgeClaim` (`b"acta:claim_client_sig:v1"`, PPA 1 Claim 8).
#[allow(clippy::too_many_arguments)]
pub fn claim_client_intent_preimage_bytes(
    tenant_id: &str,
    scope: &str,
    subject: &str,
    predicate: &str,
    object_val: &Value,
    object_type: &str,
    confidence: f64,
    source_provenance_class: i32,
    source_descriptor: &str,
    source_commitment: &[u8; 32],
    status: ClaimStatus,
    contradiction_ids: &[Uuid],
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    predecessor_id: Option<Uuid>,
) -> ActaResult<Vec<u8>> {
    let canonical_val = to_canonical_bytes(object_val)?;
    let mut sorted_contradictions = contradiction_ids.to_vec();
    sorted_contradictions.sort_unstable();
    let canonical_contradictions = to_canonical_bytes(&sorted_contradictions)?;

    let conf_bits_le = confidence.to_bits().to_le_bytes();
    let prov_le = source_provenance_class.to_le_bytes();
    let valid_from_bytes = encode_opt_i64(valid_from.map(|t| t.timestamp_micros()));
    let valid_to_bytes = encode_opt_i64(valid_to.map(|t| t.timestamp_micros()));
    let pred_bytes = encode_opt_uuid(predecessor_id);

    Ok(encode_length_delimited(&[
        b"acta:claim_client_sig:v1",
        tenant_id.as_bytes(),
        scope.as_bytes(),
        subject.as_bytes(),
        predicate.as_bytes(),
        &canonical_val,
        object_type.as_bytes(),
        &conf_bits_le,
        &prov_le,
        source_descriptor.as_bytes(),
        source_commitment,
        status.as_str().as_bytes(),
        &canonical_contradictions,
        &valid_from_bytes,
        &valid_to_bytes,
        &pred_bytes,
    ]))
}

#[allow(clippy::too_many_arguments)]
pub fn compute_claim_client_intent_hash(
    tenant_id: &str,
    scope: &str,
    subject: &str,
    predicate: &str,
    object_val: &Value,
    object_type: &str,
    confidence: f64,
    source_provenance_class: i32,
    source_descriptor: &str,
    source_commitment: &[u8; 32],
    status: ClaimStatus,
    contradiction_ids: &[Uuid],
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    predecessor_id: Option<Uuid>,
) -> ActaResult<[u8; 32]> {
    let pre = claim_client_intent_preimage_bytes(
        tenant_id,
        scope,
        subject,
        predicate,
        object_val,
        object_type,
        confidence,
        source_provenance_class,
        source_descriptor,
        source_commitment,
        status,
        contradiction_ids,
        valid_from,
        valid_to,
        predecessor_id,
    )?;
    Ok(*blake3::hash(&pre).as_bytes())
}

/// Clock-free client signing preimage for `acta_retract_claim` (`b"acta:retract_client_sig:v1"`).
pub fn retract_claim_client_intent_preimage_bytes(
    tenant_id: &str,
    claim_id: Uuid,
    reason: &str,
) -> Vec<u8> {
    encode_length_delimited(&[
        b"acta:retract_client_sig:v1",
        tenant_id.as_bytes(),
        claim_id.as_bytes(),
        reason.as_bytes(),
    ])
}

pub fn compute_retract_claim_client_intent_hash(
    tenant_id: &str,
    claim_id: Uuid,
    reason: &str,
) -> [u8; 32] {
    let pre = retract_claim_client_intent_preimage_bytes(tenant_id, claim_id, reason);
    *blake3::hash(&pre).as_bytes()
}

/// Clock-free client signing preimage for `acta_cache_answer` (`b"acta:answer_client_sig:v1"`).
pub fn answer_cache_client_intent_preimage_bytes(
    tenant_id: &str,
    scope: &str,
    task_id: &str,
    query_hash: &[u8; 32],
    source_bundle_hash: &[u8; 32],
    state_commitment: &[u8; 32],
    answer_hash: &[u8; 32],
) -> Vec<u8> {
    encode_length_delimited(&[
        b"acta:answer_client_sig:v1",
        tenant_id.as_bytes(),
        scope.as_bytes(),
        task_id.as_bytes(),
        query_hash,
        source_bundle_hash,
        state_commitment,
        answer_hash,
    ])
}

pub fn compute_answer_cache_client_intent_hash(
    tenant_id: &str,
    scope: &str,
    task_id: &str,
    query_hash: &[u8; 32],
    source_bundle_hash: &[u8; 32],
    state_commitment: &[u8; 32],
    answer_hash: &[u8; 32],
) -> [u8; 32] {
    let pre = answer_cache_client_intent_preimage_bytes(
        tenant_id,
        scope,
        task_id,
        query_hash,
        source_bundle_hash,
        state_commitment,
        answer_hash,
    );
    *blake3::hash(&pre).as_bytes()
}

/// Returns the exact raw length-delimited byte preimage hashed into `StoredObject.content_hash` (`b"acta:object:v1"`).
pub fn object_content_preimage_bytes(obj: &StoredObject) -> ActaResult<Vec<u8>> {
    let canonical_tags = to_canonical_bytes(&obj.tags)?;
    let canonical_body = to_canonical_bytes(&obj.body)?;
    let priority_le = obj.priority.to_le_bytes();
    let importance_bits_le = obj.importance.to_bits().to_le_bytes();
    let version_le = obj.version.to_le_bytes();
    let pred_bytes = encode_opt_uuid(obj.predecessor_id);
    let created_micros_le = obj.created_at.timestamp_micros().to_le_bytes();

    Ok(encode_length_delimited(&[
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

/// Computes the canonical `content_hash` for an immutable `StoredObject`.
pub fn compute_object_content_hash(obj: &StoredObject) -> ActaResult<[u8; 32]> {
    let pre = object_content_preimage_bytes(obj)?;
    Ok(*blake3::hash(&pre).as_bytes())
}

/// Returns `(group_domain_label, raw_preimage_bytes)` matching `claim.claim_group_key` (`"acta:claim_group:v2"` or `"legacy_v1_unprefixed"`).
pub fn claim_group_preimage_bytes(claim: &KnowledgeClaim) -> (&'static str, Vec<u8>) {
    let v2_pre = encode_length_delimited(&[
        b"acta:claim_group:v2",
        claim.tenant_id.as_bytes(),
        claim.subject.as_bytes(),
        claim.predicate.as_bytes(),
        claim.scope.as_bytes(),
    ]);
    if blake3::hash(&v2_pre).as_bytes() == &claim.claim_group_key {
        return ("acta:claim_group:v2", v2_pre);
    }
    let v1_pre = encode_length_delimited(&[
        claim.tenant_id.as_bytes(),
        claim.subject.as_bytes(),
        claim.predicate.as_bytes(),
        claim.object_type.as_bytes(),
        claim.scope.as_bytes(),
    ]);
    ("legacy_v1_unprefixed", v1_pre)
}

/// Returns the exact raw length-delimited byte preimage hashed into `KnowledgeClaim.content_hash` (`b"acta:claim:v1"`).
pub fn claim_content_preimage_bytes(claim: &KnowledgeClaim) -> ActaResult<Vec<u8>> {
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

    Ok(encode_length_delimited(&[
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

/// Computes the canonical `content_hash` for an immutable `KnowledgeClaim`.
pub fn compute_claim_content_hash(claim: &KnowledgeClaim) -> ActaResult<[u8; 32]> {
    let pre = claim_content_preimage_bytes(claim)?;
    Ok(*blake3::hash(&pre).as_bytes())
}

/// Returns the exact raw byte preimage hashed into `compute_override_client_intent_hash`.
pub fn override_client_intent_preimage_bytes(
    tenant_id: &str,
    scope: &str,
    winning_claim_id: Uuid,
    adjudicator_id: &str,
    justification: &str,
) -> Vec<u8> {
    encode_length_delimited(&[
        b"acta:override_client_sig:v1",
        tenant_id.as_bytes(),
        scope.as_bytes(),
        winning_claim_id.as_bytes(),
        adjudicator_id.as_bytes(),
        justification.as_bytes(),
    ])
}

/// Deterministic clock-free client signing digest (`b"acta:override_client_sig:v1"`).
pub fn compute_override_client_intent_hash(
    tenant_id: &str,
    scope: &str,
    winning_claim_id: Uuid,
    adjudicator_id: &str,
    justification: &str,
) -> [u8; 32] {
    let preimage = override_client_intent_preimage_bytes(
        tenant_id,
        scope,
        winning_claim_id,
        adjudicator_id,
        justification,
    );
    *blake3::hash(&preimage).as_bytes()
}

/// Returns the exact raw byte preimage hashed into `compute_checkpoint_hash`.
pub fn checkpoint_hash_preimage_bytes(
    tenant_id: &str,
    tree_size: i64,
    head_event_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    issued_at_micros: i64,
) -> Vec<u8> {
    let size_le = tree_size.to_le_bytes();
    let micros_le = issued_at_micros.to_le_bytes();
    encode_length_delimited(&[
        b"acta:checkpoint:v1",
        tenant_id.as_bytes(),
        &size_le,
        head_event_hash,
        merkle_root,
        &micros_le,
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
    let preimage = checkpoint_hash_preimage_bytes(
        tenant_id,
        tree_size,
        head_event_hash,
        merkle_root,
        issued_at_micros,
    );
    *blake3::hash(&preimage).as_bytes()
}

/// Input parameters hashed into `OverrideAttestation.attestation_hash`
/// (`b"acta:override:v1"` for legacy overrides, `b"acta:override:v2"` for `v1.6.3+` auth-bound overrides).
pub struct OverrideHashInput<'a> {
    pub attestation_domain: &'a str,
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
    pub adjudicator_auth_kind: &'a str,
    pub justification: &'a str,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub client_public_key: Option<&'a [u8; 32]>,
    pub client_signature: Option<&'a [u8]>,
}

/// Returns the exact raw byte preimage hashed into `OverrideAttestation.attestation_hash`.
pub fn override_attestation_preimage_bytes(inp: &OverrideHashInput<'_>) -> ActaResult<Vec<u8>> {
    let mut sorted_overridden = inp.overridden_claims.to_vec();
    sorted_overridden.sort_unstable();
    let canonical_overridden = to_canonical_bytes(&sorted_overridden)?;
    let src_bundle_bytes = encode_opt_hash32(inp.source_bundle_hash);
    let version_le = inp.version.to_le_bytes();
    let pred_bytes = encode_opt_uuid(inp.predecessor_id);
    let created_micros_le = inp.created_at.timestamp_micros().to_le_bytes();

    let domain = if inp.attestation_domain.trim().is_empty() {
        OVERRIDE_DOMAIN_V1
    } else {
        inp.attestation_domain.trim()
    };

    match domain {
        OVERRIDE_DOMAIN_V1 => Ok(encode_length_delimited(&[
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
        ])),
        OVERRIDE_DOMAIN_V2 => {
            let opt_pk = encode_opt_hash32(inp.client_public_key);
            let opt_sig = encode_opt_sig64(inp.client_signature)?;
            Ok(encode_length_delimited(&[
                b"acta:override:v2",
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
                inp.adjudicator_auth_kind.as_bytes(),
                inp.justification.as_bytes(),
                &version_le,
                &pred_bytes,
                &created_micros_le,
                &opt_pk,
                &opt_sig,
            ]))
        }
        other => Err(ActaError::Validation(format!(
            "unsupported override attestation_domain: {other}"
        ))),
    }
}

/// Computes the canonical 32-byte `attestation_hash` for an immutable `OverrideAttestation`.
pub fn compute_override_attestation_hash(inp: &OverrideHashInput<'_>) -> ActaResult<[u8; 32]> {
    let preimage = override_attestation_preimage_bytes(inp)?;
    Ok(*blake3::hash(&preimage).as_bytes())
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

/// Canonicalizes `ContextBundle` (RFC 8785) and returns `(canonical_jcs, blake3_preimage, bundle_hash)`.
pub fn bundle_hash_preimage_bytes(
    bundle: &ContextBundle,
) -> ActaResult<(Vec<u8>, Vec<u8>, [u8; 32])> {
    let canonical = to_canonical_bytes(bundle)?;
    let preimage = encode_length_delimited(&[b"acta:bundle:v1", &canonical]);
    let hash = *blake3::hash(&preimage).as_bytes();
    Ok((canonical, preimage, hash))
}

/// Canonicalizes `ContextBundle` (RFC 8785) and computes `bundle_hash`.
pub fn compute_bundle_hash(bundle: &ContextBundle) -> ActaResult<([u8; 32], Vec<u8>)> {
    let (canonical, _preimage, hash) = bundle_hash_preimage_bytes(bundle)?;
    Ok((hash, canonical))
}

/// Returns `(domain, blake3_preimage_bytes)` for `v1` and `v2` `evidence_history` entries.
#[allow(clippy::too_many_arguments)]
pub fn evidence_event_preimage_bytes(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
) -> ActaResult<(&'static str, Vec<u8>)> {
    evidence_event_preimage_bytes_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        None,
        None,
        None,
        None,
        false,
    )
}

/// Returns `(domain, blake3_preimage_bytes)` across `v1`, `v2`, and `v3` (`write_summary` / `answer_cache_summary`).
#[allow(clippy::too_many_arguments)]
pub fn evidence_event_preimage_bytes_full(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
) -> ActaResult<(&'static str, Vec<u8>)> {
    evidence_event_preimage_bytes_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        write_summary,
        answer_cache_summary,
        None,
        None,
        false,
    )
}

/// Returns `(domain, blake3_preimage_bytes)` across `v1`, `v2`, 10-part `v3` (`write_summary` /
/// `answer_cache_summary`), and 12-part `v3` (`v1.7.2+` `witness_reg_summary` / `witness_revoke_summary`
/// when `witness_in_v3 == true`, preserving 8-part `v1` on legacy `seq <= 184` witness events).
#[allow(clippy::too_many_arguments)]
pub fn evidence_event_preimage_bytes_v172(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
    witness_reg_summary: Option<&WitnessRegistrationSummary>,
    witness_revoke_summary: Option<&WitnessRevocationSummary>,
    witness_in_v3: bool,
) -> ActaResult<(&'static str, Vec<u8>)> {
    let seq_le = seq_num.to_le_bytes();
    let bundle_bytes = encode_opt_hash32(bundle_hash);
    let state_bytes = encode_opt_hash32(state_commitment);
    let created_le = created_at_micros.to_le_bytes();

    if write_summary.is_some() || answer_cache_summary.is_some() {
        let write_tagged = encode_opt_jcs(write_summary)?;
        let cache_tagged = encode_opt_jcs(answer_cache_summary)?;
        let preimage = encode_length_delimited(&[
            b"acta:evidence_event:v3",
            tenant_id.as_bytes(),
            &seq_le,
            prev_hash,
            &bundle_bytes,
            &state_bytes,
            policy_result.as_str().as_bytes(),
            &created_le,
            &write_tagged,
            &cache_tagged,
        ]);
        return Ok(("acta:evidence_event:v3", preimage));
    }

    if witness_in_v3 && (witness_reg_summary.is_some() || witness_revoke_summary.is_some()) {
        let wreg_tagged = encode_opt_jcs(witness_reg_summary)?;
        let wrev_tagged = encode_opt_jcs(witness_revoke_summary)?;
        let preimage = encode_length_delimited(&[
            b"acta:evidence_event:v3",
            tenant_id.as_bytes(),
            &seq_le,
            prev_hash,
            &bundle_bytes,
            &state_bytes,
            policy_result.as_str().as_bytes(),
            &created_le,
            &[0u8],
            &[0u8],
            &wreg_tagged,
            &wrev_tagged,
        ]);
        return Ok(("acta:evidence_event:v3", preimage));
    }

    if refusal_metadata.is_none() && override_summary.is_none() {
        let preimage = encode_length_delimited(&[
            b"acta:evidence_event:v1",
            tenant_id.as_bytes(),
            &seq_le,
            prev_hash,
            &bundle_bytes,
            &state_bytes,
            policy_result.as_str().as_bytes(),
            &created_le,
        ]);
        return Ok(("acta:evidence_event:v1", preimage));
    }

    let refusal_tagged = encode_opt_jcs(refusal_metadata)?;
    let override_tagged = encode_opt_jcs(override_summary)?;
    let preimage = encode_length_delimited(&[
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
    ]);
    Ok(("acta:evidence_event:v2", preimage))
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
    let (_domain, preimage) = evidence_event_preimage_bytes(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        None,
        None,
    )
    .expect("v1 evidence preimage cannot fail");
    *blake3::hash(&preimage).as_bytes()
}

/// Computes the deterministic `event_hash` for `v1` and `v2` `evidence_history` entries.
#[allow(clippy::too_many_arguments)]
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
    compute_evidence_event_hash_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        None,
        None,
        None,
        None,
        false,
    )
}

/// Computes the deterministic `event_hash` across `v1`, `v2`, and 10-part `v3`.
#[allow(clippy::too_many_arguments)]
pub fn compute_evidence_event_hash_full(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
) -> ActaResult<[u8; 32]> {
    compute_evidence_event_hash_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        write_summary,
        answer_cache_summary,
        None,
        None,
        false,
    )
}

/// Computes the deterministic `event_hash` across `v1`, `v2`, 10-part `v3`, and `v1.7.2+` 12-part witness `v3`.
#[allow(clippy::too_many_arguments)]
pub fn compute_evidence_event_hash_v172(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
    witness_reg_summary: Option<&WitnessRegistrationSummary>,
    witness_revoke_summary: Option<&WitnessRevocationSummary>,
    witness_in_v3: bool,
) -> ActaResult<[u8; 32]> {
    let (_domain, preimage) = evidence_event_preimage_bytes_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        write_summary,
        answer_cache_summary,
        witness_reg_summary,
        witness_revoke_summary,
        witness_in_v3,
    )?;
    Ok(*blake3::hash(&preimage).as_bytes())
}

/// Computes the 32-byte salted commitment for an `erasable: true` claim (`b"acta:erasable_claim:v1"`, `v1.7.3+`).
pub fn compute_erasable_claim_commitment(
    id: Uuid,
    salt_32: &[u8; 32],
    object_val: &serde_json::Value,
    source_commitment: &[u8; 32],
) -> ActaResult<[u8; 32]> {
    let val_jcs = to_canonical_bytes(object_val)?;
    Ok(hash_length_delimited(&[
        ERASABLE_CLAIM_DOMAIN_V1.as_bytes(),
        id.as_bytes(),
        salt_32,
        &val_jcs,
        source_commitment,
    ]))
}

/// Computes `state_commitment` for a `HostKeyRotationSummary` (`b"acta:host_key_rotate:v1"`, `v1.7.3+`).
pub fn compute_host_key_rotation_commitment(
    rot: &HostKeyRotationSummary,
) -> ActaResult<[u8; 32]> {
    let canonical = to_canonical_bytes(rot)?;
    Ok(hash_length_delimited(&[
        HOST_KEY_ROTATE_DOMAIN_V1.as_bytes(),
        &canonical,
    ]))
}

/// Returns `(event_domain, preimage_bytes)` across `v1`, `v2`, 10-part `v3`, 12-part witness `v3`,
/// and `v1.7.3+` 13-part `host_key_rotation_summary` `v3`.
#[allow(clippy::too_many_arguments)]
pub fn evidence_event_preimage_bytes_v173(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
    witness_reg_summary: Option<&WitnessRegistrationSummary>,
    witness_revoke_summary: Option<&WitnessRevocationSummary>,
    witness_in_v3: bool,
    host_key_rotation_summary: Option<&HostKeyRotationSummary>,
) -> ActaResult<(&'static str, Vec<u8>)> {
    if let Some(rot) = host_key_rotation_summary {
        let seq_le = seq_num.to_le_bytes();
        let created_le = created_at_micros.to_le_bytes();
        let bundle_bytes = encode_opt_hash32(bundle_hash);
        let state_bytes = encode_opt_hash32(state_commitment);
        let rot_tagged = encode_opt_jcs(Some(rot))?;
        let preimage = encode_length_delimited(&[
            b"acta:evidence_event:v3",
            tenant_id.as_bytes(),
            &seq_le,
            prev_hash,
            &bundle_bytes,
            &state_bytes,
            policy_result.as_str().as_bytes(),
            &created_le,
            &[0u8],
            &[0u8],
            &[0u8],
            &[0u8],
            &rot_tagged,
        ]);
        return Ok(("acta:evidence_event:v3", preimage));
    }
    evidence_event_preimage_bytes_v172(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        write_summary,
        answer_cache_summary,
        witness_reg_summary,
        witness_revoke_summary,
        witness_in_v3,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compute_evidence_event_hash_v173(
    tenant_id: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    bundle_hash: Option<&[u8; 32]>,
    state_commitment: Option<&[u8; 32]>,
    policy_result: PolicyResultTag,
    created_at_micros: i64,
    refusal_metadata: Option<&RefusalMetadata>,
    override_summary: Option<&OverrideLedgerSummary>,
    write_summary: Option<&WriteLedgerSummary>,
    answer_cache_summary: Option<&AnswerCacheLedgerSummary>,
    witness_reg_summary: Option<&WitnessRegistrationSummary>,
    witness_revoke_summary: Option<&WitnessRevocationSummary>,
    witness_in_v3: bool,
    host_key_rotation_summary: Option<&HostKeyRotationSummary>,
) -> ActaResult<[u8; 32]> {
    let (_dom, preimage) = evidence_event_preimage_bytes_v173(
        tenant_id,
        seq_num,
        prev_hash,
        bundle_hash,
        state_commitment,
        policy_result,
        created_at_micros,
        refusal_metadata,
        override_summary,
        write_summary,
        answer_cache_summary,
        witness_reg_summary,
        witness_revoke_summary,
        witness_in_v3,
        host_key_rotation_summary,
    )?;
    Ok(*blake3::hash(&preimage).as_bytes())
}

