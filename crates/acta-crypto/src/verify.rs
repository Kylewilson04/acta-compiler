use std::collections::{BTreeMap, BTreeSet, HashMap};

use acta_types::{
    ClaimStatus, EntryInclusionProof, EvidenceEntry, ExportArchive, KnowledgeClaim,
    LifecycleStatus, ObjectType, ResolverManifest, SignedTreeHead, StateRebuildArchive,
    StoredObject, WriteLedgerSummary, WriteOperationKind, ANSWER_CACHE_DOMAIN_V1,
    DEFAULT_CORROBORATION_DAMPING, SCHEMA_VERSION, STATE_REBUILD_ARCHIVE_SCHEMA_V1,
    WRITE_EVENT_DOMAIN_V1,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    bundle_hash_preimage_bytes, checkpoint_hash_preimage_bytes, checkpoint_signing_preimage,
    checkpoint_signing_preimage_bytes, claim_content_preimage_bytes, claim_group_preimage_bytes,
    claims_share_winning_value_bucket, compute_answer_cache_client_intent_hash,
    compute_answer_cache_summary_commitment, compute_bundle_hash, compute_checkpoint_hash,
    compute_claim_client_intent_hash, compute_claim_content_hash, compute_claim_group_key,
    compute_evidence_event_hash_v172, compute_logical_claim_group_key,
    compute_merkle_root_from_leaves, compute_object_client_intent_hash,
    compute_object_content_hash, compute_override_attestation_hash,
    compute_override_client_intent_hash, compute_rebuild_archive_header_hash,
    compute_refusal_metadata_commitment, compute_retract_claim_client_intent_hash,
    compute_state_commitment, compute_sub_commitment, compute_write_summary_commitment,
    evidence_event_preimage_bytes_v172, evidence_signing_preimage, evidence_signing_preimage_bytes,
    legacy_blake3_merkle_empty_root, merkle_empty_root, merkle_leaf_hash,
    merkle_leaf_preimage_bytes, object_content_preimage_bytes, override_attestation_preimage_bytes,
    override_client_intent_preimage_bytes, override_signing_preimage,
    override_signing_preimage_bytes, recompute_winning_bucket_corroboration, to_canonical_bytes,
    verify_checkpoint_signature, verify_client_content_signature, verify_evidence_signature,
    verify_merkle_consistency_proof, verify_merkle_inclusion_proof, verify_override_signature,
    verify_rebuild_archive_header_signature, verify_witness_anchor_signature,
    witness_anchor_signing_preimage, witness_anchor_signing_preimage_bytes,
    witness_registration_preimage_bytes, witness_revocation_preimage_bytes, OverrideHashInput,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub tenant_id: String,
    pub bundle_hash_hex: String,
    pub state_commitment_hex: String,
    pub verified_objects: usize,
    pub verified_claims: usize,
    #[serde(default)]
    pub verified_corroborated_resolutions: usize,
    #[serde(default)]
    pub verified_overrides: usize,
    #[serde(default)]
    pub verified_writes: usize,
    #[serde(default)]
    pub verified_answer_caches: usize,
    #[serde(default)]
    pub verified_refusals: usize,
    pub verified_evidence_entries: usize,
    #[serde(default)]
    pub verification_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_tree_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_tree_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_merkle_root_hex: Option<String>,
    #[serde(default)]
    pub verified_witness_anchors: usize,
    #[serde(default)]
    pub non_default_thresholds: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_manifest: Option<ResolverManifest>,
}

#[derive(Default, Clone, Copy)]
struct EntryClassCounts {
    is_refusal: bool,
    is_write: bool,
    is_answer_cache: bool,
}

fn claim_matches_record_group(record_group: &[u8; 32], stored: &KnowledgeClaim) -> bool {
    if record_group == &stored.claim_group_key {
        return true;
    }
    let logical_v2 = compute_logical_claim_group_key(
        &stored.tenant_id,
        &stored.subject,
        &stored.predicate,
        &stored.scope,
    );
    record_group == &logical_v2
}

fn verify_auth_kind_and_client_sig_presence(
    label: &str,
    auth_kind: &str,
    has_sig: bool,
    has_pk: bool,
) -> Result<(), String> {
    if has_sig != has_pk {
        return Err(format!(
            "{label} inconsistent client_signature / client_public_key presence"
        ));
    }
    match auth_kind {
        "ed25519_client_sig" => {
            if !has_sig {
                return Err(format!(
                    "{label} auth_kind='ed25519_client_sig' requires client_signature + client_public_key"
                ));
            }
        }
        "oauth_github_principal" | "tenant_session" | "master_admin" => {
            if has_sig {
                return Err(format!(
                    "{label} auth_kind='{auth_kind}' cannot coexist with client_signature"
                ));
            }
        }
        other => {
            return Err(format!("{label} unsupported auth_kind '{other}'"));
        }
    }
    Ok(())
}

fn verify_override_auth_kind_consistency(att: &acta_types::OverrideAttestation) -> Result<(), String> {
    verify_auth_kind_and_client_sig_presence(
        &format!("override_attestation[id={}]", att.id),
        att.effective_auth_kind(),
        att.client_signature.is_some(),
        att.client_public_key.is_some(),
    )
}

fn verify_object_author_signature(obj: &StoredObject, label: &str) -> Result<(), String> {
    match (&obj.client_signature, &obj.client_public_key) {
        (Some(csig), Some(cpk)) => {
            let sig_arr: [u8; 64] = csig
                .as_slice()
                .try_into()
                .map_err(|_| format!("{label} client_signature is not 64 bytes"))?;
            let intent_hash = compute_object_client_intent_hash(
                &obj.tenant_id,
                obj.obj_type,
                &obj.scope,
                obj.lifecycle_status,
                obj.priority,
                obj.importance,
                &obj.tags,
                &obj.body,
                obj.predecessor_id,
            )
            .map_err(|e| format!("{label} client intent hash failed: {e}"))?;
            let ok_intent = verify_client_content_signature(cpk, &intent_hash, &sig_arr);
            let ok_full = verify_client_content_signature(cpk, &obj.content_hash, &sig_arr);
            if !ok_intent && !ok_full {
                return Err(format!(
                    "client Ed25519 signature verification failed on {label}"
                ));
            }
            Ok(())
        }
        (None, Some(_)) => Err(format!(
            "{label} has client_public_key without client_signature"
        )),
        _ => Ok(()),
    }
}

fn verify_claim_author_signature(
    claim: &KnowledgeClaim,
    retraction_reason: Option<&str>,
    label: &str,
) -> Result<(), String> {
    match (&claim.client_signature, &claim.client_public_key) {
        (Some(csig), Some(cpk)) => {
            let sig_arr: [u8; 64] = csig
                .as_slice()
                .try_into()
                .map_err(|_| format!("{label} client_signature is not 64 bytes"))?;
            let intent_hash = compute_claim_client_intent_hash(
                &claim.tenant_id,
                &claim.scope,
                &claim.subject,
                &claim.predicate,
                &claim.object_val,
                &claim.object_type,
                claim.confidence,
                claim.source_provenance_class,
                &claim.source_descriptor,
                &claim.source_commitment,
                claim.status,
                &claim.contradiction_ids,
                claim.valid_from,
                claim.valid_to,
                claim.predecessor_id,
            )
            .map_err(|e| format!("{label} client intent hash failed: {e}"))?;
            let ok_intent = verify_client_content_signature(cpk, &intent_hash, &sig_arr);
            let ok_full = verify_client_content_signature(cpk, &claim.content_hash, &sig_arr);
            let ok_retract = match (
                retraction_reason.or(claim.retraction_reason.as_deref()),
                claim.predecessor_id,
            ) {
                (Some(reason), Some(retracted_id)) if claim.status == ClaimStatus::Revoked => {
                    let r_hash = compute_retract_claim_client_intent_hash(
                        &claim.tenant_id,
                        retracted_id,
                        reason,
                    );
                    verify_client_content_signature(cpk, &r_hash, &sig_arr)
                }
                _ => false,
            };
            if !ok_intent && !ok_full && !ok_retract {
                return Err(format!(
                    "client Ed25519 signature verification failed on {label}"
                ));
            }
            Ok(())
        }
        (Some(_), None) | (None, Some(_)) => Err(format!(
            "{label} inconsistent client_signature / client_public_key presence"
        )),
        (None, None) => Ok(()),
    }
}

fn verify_write_ledger_summary(
    entry: &EvidenceEntry,
    ws: &WriteLedgerSummary,
) -> Result<(), String> {
    if ws.write_domain != WRITE_EVENT_DOMAIN_V1 {
        return Err(format!(
            "unsupported write_summary.write_domain '{}' at seq_num={}",
            ws.write_domain, entry.seq_num
        ));
    }
    let label = format!(
        "write_summary[seq_num={}, item_id={}]",
        entry.seq_num, ws.item_id
    );
    verify_auth_kind_and_client_sig_presence(
        &label,
        ws.writer_auth_kind.trim(),
        ws.client_signature.is_some(),
        ws.client_public_key.is_some(),
    )?;

    match ws.operation {
        WriteOperationKind::IngestObject => {
            let mut snap_obj: StoredObject = serde_json::from_value(ws.record_snapshot.clone())
                .map_err(|e| format!("{label} invalid StoredObject record_snapshot: {e}"))?;
            if snap_obj.tenant_id != entry.tenant_id
                || snap_obj.id != ws.item_id
                || snap_obj.scope != ws.scope
                || snap_obj.version != ws.version
                || snap_obj.predecessor_id != ws.predecessor_id
            {
                return Err(format!("{label} metadata mismatch against record_snapshot"));
            }
            let recomputed = compute_object_content_hash(&snap_obj)
                .map_err(|e| format!("{label} object canonicalization failed: {e}"))?;
            if recomputed != snap_obj.content_hash || recomputed != ws.content_hash {
                return Err(format!(
                    "{label} tampered object record_snapshot: recomputed content_hash {} != {}",
                    hex::encode(recomputed),
                    hex::encode(ws.content_hash)
                ));
            }
            snap_obj.client_signature = ws.client_signature.clone();
            snap_obj.client_public_key = ws.client_public_key;
            verify_object_author_signature(&snap_obj, &label)?;
        }
        WriteOperationKind::IngestClaim | WriteOperationKind::RetractClaim => {
            let mut snap_claim: KnowledgeClaim =
                serde_json::from_value(ws.record_snapshot.clone())
                    .map_err(|e| format!("{label} invalid KnowledgeClaim record_snapshot: {e}"))?;
            if snap_claim.tenant_id != entry.tenant_id
                || snap_claim.id != ws.item_id
                || snap_claim.scope != ws.scope
                || snap_claim.version != ws.version
                || snap_claim.predecessor_id != ws.predecessor_id
            {
                return Err(format!("{label} metadata mismatch against record_snapshot"));
            }
            let expected_v2 = compute_logical_claim_group_key(
                &snap_claim.tenant_id,
                &snap_claim.subject,
                &snap_claim.predicate,
                &snap_claim.scope,
            );
            let expected_v1 = compute_claim_group_key(
                &snap_claim.tenant_id,
                &snap_claim.subject,
                &snap_claim.predicate,
                &snap_claim.object_type,
                &snap_claim.scope,
            );
            if snap_claim.claim_group_key != expected_v2 && snap_claim.claim_group_key != expected_v1
            {
                return Err(format!("{label} tampered claim_group_key in record_snapshot"));
            }
            let recomputed = compute_claim_content_hash(&snap_claim)
                .map_err(|e| format!("{label} claim canonicalization failed: {e}"))?;
            if recomputed != snap_claim.content_hash || recomputed != ws.content_hash {
                return Err(format!(
                    "{label} tampered claim record_snapshot: recomputed content_hash {} != {}",
                    hex::encode(recomputed),
                    hex::encode(ws.content_hash)
                ));
            }
            if ws.operation == WriteOperationKind::RetractClaim
                && (snap_claim.status != ClaimStatus::Revoked
                    || ws.predecessor_id.is_none()
                    || ws.retraction_reason.as_deref().unwrap_or("").trim().is_empty())
            {
                return Err(format!(
                    "{label} retract_claim requires status='revoked', predecessor_id, and retraction_reason"
                ));
            }
            snap_claim.client_signature = ws.client_signature.clone();
            snap_claim.client_public_key = ws.client_public_key;
            verify_claim_author_signature(&snap_claim, ws.retraction_reason.as_deref(), &label)?;
        }
    }

    let expected_comm = compute_write_summary_commitment(ws)
        .map_err(|e| format!("{label} write commitment failed: {e}"))?;
    if entry.state_commitment != Some(expected_comm) {
        return Err(format!(
            "tampered write_summary at seq_num={}: state_commitment mismatch",
            entry.seq_num
        ));
    }
    Ok(())
}

pub fn verify_single_evidence_entry_public(
    entry: &EvidenceEntry,
    expected_tenant: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    verify_single_evidence_entry(entry, expected_tenant, verifying_key).map(|_| ())
}

fn verify_single_evidence_entry(
    entry: &EvidenceEntry,
    expected_tenant: &str,
    verifying_key: &VerifyingKey,
) -> Result<EntryClassCounts, String> {
    if entry.tenant_id != expected_tenant {
        return Err(format!(
            "evidence entry seq_num={} tenant_id '{}' != bundle tenant_id '{}'",
            entry.seq_num, entry.tenant_id, expected_tenant
        ));
    }
    if entry.seq_num < 1 {
        return Err(format!("invalid evidence seq_num={}: must be >= 1", entry.seq_num));
    }

    let expected_event_domain = entry.expected_event_domain_str();
    if let Some(ref declared_domain) = entry.event_domain {
        if declared_domain != expected_event_domain {
            return Err(format!(
                "tampered event_domain at seq_num={}: declared '{}' != expected '{}'",
                entry.seq_num, declared_domain, expected_event_domain
            ));
        }
    }

    let mut counts = EntryClassCounts::default();

    if let Some(ref rmeta) = entry.refusal_metadata {
        if entry.bundle_hash.is_some()
            || entry.write_summary.is_some()
            || entry.answer_cache_summary.is_some()
            || entry.witness_reg_summary.is_some()
            || entry.witness_revoke_summary.is_some()
        {
            return Err(format!(
                "invalid evidence entry at seq_num={}: refusal_metadata cannot coexist with bundle_hash, write_summary, answer_cache_summary, or witness summaries",
                entry.seq_num
            ));
        }
        let expected_refusal_comm = compute_refusal_metadata_commitment(rmeta)
            .map_err(|e| format!("refusal_metadata canonicalization failed: {e}"))?;
        if entry.state_commitment != Some(expected_refusal_comm) {
            return Err(format!(
                "tampered refusal_metadata at seq_num={}: state_commitment mismatch",
                entry.seq_num
            ));
        }
        counts.is_refusal = true;
    }

    if let Some(ref ws) = entry.write_summary {
        if entry.bundle_hash.is_some()
            || entry.refusal_metadata.is_some()
            || entry.override_summary.is_some()
            || entry.answer_cache_summary.is_some()
            || entry.witness_reg_summary.is_some()
            || entry.witness_revoke_summary.is_some()
        {
            return Err(format!(
                "invalid evidence entry at seq_num={}: write_summary cannot coexist with other entry payloads",
                entry.seq_num
            ));
        }
        verify_write_ledger_summary(entry, ws)?;
        counts.is_write = true;
    }

    if let Some(ref acs) = entry.answer_cache_summary {
        if entry.bundle_hash.is_some()
            || entry.refusal_metadata.is_some()
            || entry.override_summary.is_some()
            || entry.write_summary.is_some()
            || entry.witness_reg_summary.is_some()
            || entry.witness_revoke_summary.is_some()
        {
            return Err(format!(
                "invalid evidence entry at seq_num={}: answer_cache_summary cannot coexist with other entry payloads",
                entry.seq_num
            ));
        }
        if acs.cache_domain != ANSWER_CACHE_DOMAIN_V1 {
            return Err(format!(
                "unsupported answer_cache_summary.cache_domain '{}' at seq_num={}",
                acs.cache_domain, entry.seq_num
            ));
        }
        let label = format!(
            "answer_cache_summary[seq_num={}, cache_id={}]",
            entry.seq_num, acs.cache_id
        );
        match acs.event_kind.as_deref() {
            None | Some("cached") => {
                if acs.invalidation_reason.is_some()
                    || acs.invalidated_by.is_some()
                    || acs.invalidator_auth_kind.is_some()
                    || acs.observed_state_commitment.is_some()
                    || acs.observed_dependency_commitment.is_some()
                {
                    return Err(format!(
                        "{label} cached event_kind cannot carry invalidation fields"
                    ));
                }
            }
            Some("invalidated") => {
                match acs.invalidation_reason.as_deref() {
                    Some("stale_dependency_commitment")
                    | Some("stale_state_commitment")
                    | Some("expired_ttl") => {}
                    other => {
                        return Err(format!(
                            "{label} invalidation event has unsupported invalidation_reason '{:?}'",
                            other
                        ));
                    }
                }
                if acs.observed_state_commitment.is_none() {
                    return Err(format!(
                        "{label} invalidation event requires observed_state_commitment"
                    ));
                }
                if let Some(ref inv_kind) = acs.invalidator_auth_kind {
                    match inv_kind.trim() {
                        "oauth_github_principal"
                        | "ed25519_client_sig"
                        | "tenant_session"
                        | "master_admin" => {}
                        other => {
                            return Err(format!(
                                "{label} unsupported invalidator_auth_kind '{other}'"
                            ));
                        }
                    }
                }
            }
            Some(other) => {
                return Err(format!("{label} unsupported answer_cache event_kind '{other}'"));
            }
        }
        verify_auth_kind_and_client_sig_presence(
            &label,
            acs.cacher_auth_kind.trim(),
            acs.client_signature.is_some(),
            acs.client_public_key.is_some(),
        )?;
        if let (Some(ref csig), Some(ref cpk)) = (&acs.client_signature, &acs.client_public_key) {
            let sig_arr: [u8; 64] = csig
                .as_slice()
                .try_into()
                .map_err(|_| format!("{label} client_signature is not 64 bytes"))?;
            let intent_hash = compute_answer_cache_client_intent_hash(
                &entry.tenant_id,
                &acs.scope,
                &acs.task_id,
                &acs.query_hash,
                &acs.source_bundle_hash,
                &acs.state_commitment,
                &acs.answer_hash,
            );
            if !verify_client_content_signature(cpk, &intent_hash, &sig_arr)
                && !verify_client_content_signature(cpk, &acs.answer_hash, &sig_arr)
            {
                return Err(format!(
                    "client Ed25519 signature verification failed on {label}"
                ));
            }
        }
        let expected_cache_comm = compute_answer_cache_summary_commitment(acs)
            .map_err(|e| format!("{label} commitment failed: {e}"))?;
        if entry.state_commitment != Some(expected_cache_comm) {
            return Err(format!(
                "tampered answer_cache_summary at seq_num={}: state_commitment mismatch",
                entry.seq_num
            ));
        }
        counts.is_answer_cache = true;
    }

    if let Some(ref wreg) = entry.witness_reg_summary {
        if entry.bundle_hash.is_some()
            || entry.refusal_metadata.is_some()
            || entry.override_summary.is_some()
            || entry.write_summary.is_some()
            || entry.answer_cache_summary.is_some()
            || entry.witness_revoke_summary.is_some()
        {
            return Err(format!(
                "invalid evidence entry at seq_num={}: witness_reg_summary cannot coexist with other entry payloads",
                entry.seq_num
            ));
        }
        let expected_preimage = witness_registration_preimage_bytes(
            &wreg.registration_domain,
            &entry.tenant_id,
            &wreg.witness_id,
            &wreg.public_key,
            &wreg.registered_by,
            wreg.description.as_deref(),
        )
        .map_err(|e| format!("invalid witness_reg_summary at seq_num={}: {e}", entry.seq_num))?;

        let expected_preimage_hex = hex::encode(&expected_preimage);
        if wreg
            .registration_blake3_preimage_hex
            .trim()
            .to_ascii_lowercase()
            != expected_preimage_hex
        {
            return Err(format!(
                "tampered witness_reg_summary.registration_blake3_preimage_hex at seq_num={}",
                entry.seq_num
            ));
        }
        let expected_reg_comm = *blake3::hash(&expected_preimage).as_bytes();
        if entry.state_commitment != Some(expected_reg_comm) {
            return Err(format!(
                "tampered witness_reg_summary at seq_num={}: state_commitment mismatch",
                entry.seq_num
            ));
        }
    }

    if let Some(ref wrev) = entry.witness_revoke_summary {
        if entry.bundle_hash.is_some()
            || entry.refusal_metadata.is_some()
            || entry.override_summary.is_some()
            || entry.write_summary.is_some()
            || entry.answer_cache_summary.is_some()
            || entry.witness_reg_summary.is_some()
        {
            return Err(format!(
                "invalid evidence entry at seq_num={}: witness_revoke_summary cannot coexist with other entry payloads",
                entry.seq_num
            ));
        }
        let eff_mode = if wrev.revocation_mode.trim().is_empty() {
            "compromise"
        } else {
            wrev.revocation_mode.trim()
        };
        let expected_preimage = witness_revocation_preimage_bytes(
            &wrev.revocation_domain,
            &entry.tenant_id,
            &wrev.witness_id,
            &wrev.public_key,
            &wrev.revoked_by,
            eff_mode,
            wrev.effective_from_tree_size,
            &wrev.reason,
        )
        .map_err(|e| format!("invalid witness_revoke_summary at seq_num={}: {e}", entry.seq_num))?;

        let expected_preimage_hex = hex::encode(&expected_preimage);
        if wrev
            .revocation_blake3_preimage_hex
            .trim()
            .to_ascii_lowercase()
            != expected_preimage_hex
        {
            return Err(format!(
                "tampered witness_revoke_summary.revocation_blake3_preimage_hex at seq_num={}",
                entry.seq_num
            ));
        }
        let expected_rev_comm = *blake3::hash(&expected_preimage).as_bytes();
        if entry.state_commitment != Some(expected_rev_comm) {
            return Err(format!(
                "tampered witness_revoke_summary at seq_num={}: state_commitment mismatch",
                entry.seq_num
            ));
        }
    }

    let witness_in_v3 = entry.uses_witness_v3_event_domain();
    let recomputed_event_hash = compute_evidence_event_hash_v172(
        &entry.tenant_id,
        entry.seq_num,
        &entry.prev_hash,
        entry.bundle_hash.as_ref(),
        entry.state_commitment.as_ref(),
        entry.policy_result,
        entry.created_at.timestamp_micros(),
        entry.refusal_metadata.as_ref(),
        entry.override_summary.as_ref(),
        entry.write_summary.as_ref(),
        entry.answer_cache_summary.as_ref(),
        entry.witness_reg_summary.as_ref(),
        entry.witness_revoke_summary.as_ref(),
        witness_in_v3,
    )
    .map_err(|e| format!("evidence event_hash computation failed at seq_num={}: {e}", entry.seq_num))?;

    if recomputed_event_hash != entry.event_hash {
        return Err(format!(
            "tampered evidence entry at seq_num={}: recomputed event_hash {} != stored {}",
            entry.seq_num,
            hex::encode(recomputed_event_hash),
            hex::encode(entry.event_hash)
        ));
    }

    if !verify_evidence_signature(
        verifying_key,
        &entry.tenant_id,
        entry.seq_num,
        &entry.prev_hash,
        &recomputed_event_hash,
        &entry.host_signature,
    ) {
        return Err(format!(
            "Ed25519 host_signature verification failed at evidence seq_num={}",
            entry.seq_num
        ));
    }

    Ok(counts)
}

fn decode_audit_path(hex_nodes: &[String]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(hex_nodes.len());
    for h in hex_nodes {
        let bytes =
            hex::decode(h.trim()).map_err(|e| format!("invalid hex in merkle audit_path: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "merkle audit_path node must be 32 bytes (64 hex chars)".to_string())?;
        out.push(arr);
    }
    Ok(out)
}

/// Verifies a `SignedTreeHead` checkpoint (including any attached external witness cosignatures).
pub fn verify_signed_tree_head(
    sth: &SignedTreeHead,
    expected_tenant: &str,
    verifying_key: &VerifyingKey,
) -> Result<usize, String> {
    if sth.tenant_id != expected_tenant {
        return Err(format!(
            "checkpoint tenant_id '{}' != expected '{}'",
            sth.tenant_id, expected_tenant
        ));
    }
    if sth.tree_size < 1 {
        return Err(format!("invalid checkpoint tree_size={}", sth.tree_size));
    }
    let recomputed_cp = compute_checkpoint_hash(
        &sth.tenant_id,
        sth.tree_size,
        &sth.head_event_hash,
        &sth.merkle_root,
        sth.issued_at.timestamp_micros(),
    );
    if recomputed_cp != sth.checkpoint_hash {
        return Err(format!(
            "tampered SignedTreeHead: recomputed checkpoint_hash {} != stored {}",
            hex::encode(recomputed_cp),
            hex::encode(sth.checkpoint_hash)
        ));
    }
    if !verify_checkpoint_signature(
        verifying_key,
        &sth.tenant_id,
        &recomputed_cp,
        &sth.host_signature,
    ) {
        return Err("Ed25519 host_signature verification failed on SignedTreeHead".to_string());
    }

    for anchor in &sth.witness_anchors {
        if anchor.tenant_id != sth.tenant_id
            || anchor.tree_size != sth.tree_size
            || anchor.checkpoint_hash != sth.checkpoint_hash
        {
            return Err(format!(
                "witness_anchor[id={}] metadata mismatch against SignedTreeHead",
                anchor.id
            ));
        }
        if !verify_witness_anchor_signature(
            &anchor.witness_public_key,
            &anchor.tenant_id,
            anchor.tree_size,
            &anchor.checkpoint_hash,
            &anchor.witness_signature,
        ) {
            return Err(format!(
                "Ed25519 witness_signature verification failed on witness_anchor[id={}, witness={}]",
                anchor.id, anchor.witness_id
            ));
        }
    }

    Ok(sth.witness_anchors.len())
}

fn verify_entry_inclusion(
    proof: &EntryInclusionProof,
    sth: &SignedTreeHead,
    verifying_key: &VerifyingKey,
) -> Result<EntryClassCounts, String> {
    let counts = verify_single_evidence_entry(&proof.entry, &sth.tenant_id, verifying_key)?;
    let path_arr = decode_audit_path(&proof.audit_path)?;
    if !verify_merkle_inclusion_proof(
        proof.entry.seq_num,
        &proof.entry.event_hash,
        sth.tree_size,
        &path_arr,
        &sth.merkle_root,
    ) {
        return Err(format!(
            "Merkle inclusion proof failed for seq_num={} against tree_size={} merkle_root={}",
            proof.entry.seq_num,
            sth.tree_size,
            hex::encode(sth.merkle_root)
        ));
    }
    if proof.entry.seq_num == sth.tree_size && proof.entry.event_hash != sth.head_event_hash {
        return Err(format!(
            "head entry event_hash mismatch at tree_size={}",
            sth.tree_size
        ));
    }
    Ok(counts)
}

/// Cryptographically verifies an `ExportArchive` against `expected_pubkey` without database access,
/// including full winning-bucket corroborating claim proofs and damped noisy-OR `effective_confidence` re-derivation (`v1.7.2+`).
pub fn verify_export_archive(
    archive: &ExportArchive,
    expected_pubkey: &[u8; 32],
) -> Result<VerificationSummary, String> {
    if &archive.host_public_key != expected_pubkey {
        return Err(format!(
            "host_public_key mismatch: archive contains {}, expected {}",
            hex::encode(archive.host_public_key),
            hex::encode(expected_pubkey)
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(expected_pubkey)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
    if verifying_key.is_weak() {
        return Err("rejected weak low-order Ed25519 public key".to_string());
    }

    let corroboration_damping = if let Some(ref rm) = archive.bundle.resolver_manifest {
        if !rm.min_confidence.is_finite()
            || !(0.0..=1.0).contains(&rm.min_confidence)
            || !rm.decisiveness_threshold.is_finite()
            || !(0.0..=1.0).contains(&rm.decisiveness_threshold)
            || !rm.corroboration_damping.is_finite()
            || !(0.0..=1.0).contains(&rm.corroboration_damping)
        {
            return Err("invalid resolver_manifest threshold bounds in ContextBundle".to_string());
        }
        if rm.non_default_thresholds != rm.expected_non_default_flag() {
            return Err(format!(
                "inconsistent resolver_manifest.non_default_thresholds={} for min_confidence={}, decisiveness_threshold={}",
                rm.non_default_thresholds, rm.min_confidence, rm.decisiveness_threshold
            ));
        }
        rm.corroboration_damping
    } else {
        DEFAULT_CORROBORATION_DAMPING
    };

    if let Some(omitted_facts) = archive.bundle.resolved_facts_omitted {
        if omitted_facts > archive.bundle.omission_record.total_omitted_count {
            return Err(format!(
                "tampered resolved_facts_omitted ({omitted_facts}) exceeds omission_record.total_omitted_count ({})",
                archive.bundle.omission_record.total_omitted_count
            ));
        }
    }

    let mut objects_by_id: HashMap<Uuid, &StoredObject> =
        HashMap::with_capacity(archive.objects.len());
    for obj in &archive.objects {
        let recomputed = compute_object_content_hash(obj)
            .map_err(|e| format!("object[id={}] canonicalization failed: {e}", obj.id))?;
        if recomputed != obj.content_hash {
            return Err(format!(
                "tampered object[id={}]: recomputed content_hash {} != stored {}",
                obj.id,
                hex::encode(recomputed),
                hex::encode(obj.content_hash)
            ));
        }
        if obj.client_public_key.is_some() {
            verify_object_author_signature(obj, &format!("object[id={}]", obj.id))?;
        }
        objects_by_id.insert(obj.id, obj);
    }

    let mut claims_by_id: HashMap<Uuid, &KnowledgeClaim> =
        HashMap::with_capacity(archive.claims.len());
    for claim in &archive.claims {
        let expected_v2 = compute_logical_claim_group_key(
            &claim.tenant_id,
            &claim.subject,
            &claim.predicate,
            &claim.scope,
        );
        let expected_v1 = compute_claim_group_key(
            &claim.tenant_id,
            &claim.subject,
            &claim.predicate,
            &claim.object_type,
            &claim.scope,
        );
        if claim.claim_group_key != expected_v2 && claim.claim_group_key != expected_v1 {
            return Err(format!(
                "tampered claim[id={}].claim_group_key: recomputed {} (v2) / {} (v1) != stored {}",
                claim.id,
                hex::encode(expected_v2),
                hex::encode(expected_v1),
                hex::encode(claim.claim_group_key)
            ));
        }

        let recomputed = compute_claim_content_hash(claim)
            .map_err(|e| format!("claim[id={}] canonicalization failed: {e}", claim.id))?;
        if recomputed != claim.content_hash {
            return Err(format!(
                "tampered claim[id={}] body/metadata: recomputed content_hash {} != stored {}",
                claim.id,
                hex::encode(recomputed),
                hex::encode(claim.content_hash)
            ));
        }
        verify_claim_author_signature(claim, None, &format!("claim[id={}]", claim.id))?;
        claims_by_id.insert(claim.id, claim);
    }

    let mut overrides_by_id: HashMap<Uuid, &acta_types::OverrideAttestation> =
        HashMap::with_capacity(archive.override_attestations.len());
    for att in &archive.override_attestations {
        if att.tenant_id != archive.bundle.tenant_id {
            return Err(format!(
                "override_attestation[id={}] tenant_id '{}' != bundle tenant_id '{}'",
                att.id, att.tenant_id, archive.bundle.tenant_id
            ));
        }
        verify_override_auth_kind_consistency(att)?;

        if let (Some(ref csig), Some(ref cpk)) = (&att.client_signature, &att.client_public_key) {
            let sig_arr: [u8; 64] = csig.as_slice().try_into().map_err(|_| {
                format!(
                    "override_attestation[id={}] client_signature is not 64 bytes",
                    att.id
                )
            })?;
            let intent_hash = compute_override_client_intent_hash(
                &att.tenant_id,
                &att.scope,
                att.winning_claim_id,
                &att.adjudicator_id,
                &att.justification,
            );
            let ok_intent = verify_client_content_signature(cpk, &intent_hash, &sig_arr);
            let ok_full = verify_client_content_signature(cpk, &att.attestation_hash, &sig_arr);
            if !ok_intent && !ok_full {
                return Err(format!(
                    "client Ed25519 signature verification failed on override_attestation[id={}]",
                    att.id
                ));
            }
        }

        let recomputed_att_hash = compute_override_attestation_hash(&OverrideHashInput {
            attestation_domain: att.effective_domain(),
            id: att.id,
            tenant_id: &att.tenant_id,
            scope: &att.scope,
            claim_group_key: &att.claim_group_key,
            subject: &att.subject,
            predicate: &att.predicate,
            source_bundle_hash: att.source_bundle_hash.as_ref(),
            winning_claim_id: att.winning_claim_id,
            winning_claim_content_hash: &att.winning_claim_content_hash,
            overridden_claims: &att.overridden_claims,
            adjudicator_id: &att.adjudicator_id,
            adjudicator_auth_kind: att.effective_auth_kind(),
            justification: &att.justification,
            version: att.version,
            predecessor_id: att.predecessor_id,
            created_at: att.created_at,
            client_public_key: att.client_public_key.as_ref(),
            client_signature: att.client_signature.as_deref(),
        })
        .map_err(|e| format!("override_attestation[id={}] canonicalization failed: {e}", att.id))?;
        if recomputed_att_hash != att.attestation_hash {
            return Err(format!(
                "tampered override_attestation[id={}]: recomputed attestation_hash {} != stored {}",
                att.id,
                hex::encode(recomputed_att_hash),
                hex::encode(att.attestation_hash)
            ));
        }
        if !verify_override_signature(
            &verifying_key,
            &att.tenant_id,
            att.evidence_seq_num,
            &recomputed_att_hash,
            &att.host_signature,
        ) {
            return Err(format!(
                "Ed25519 host_signature verification failed on override_attestation[id={}]",
                att.id
            ));
        }
        overrides_by_id.insert(att.id, att);
    }

    for sel in &archive.bundle.selected_objects {
        let obj = objects_by_id.get(&sel.id).ok_or_else(|| {
            format!(
                "bundle selected_objects references missing object[id={}]",
                sel.id
            )
        })?;
        if sel.content_hash != obj.content_hash || sel.version != obj.version {
            return Err(format!(
                "tampered bundle selected_objects[id={}]: reference (v{}, {}) != object (v{}, {})",
                sel.id,
                sel.version,
                hex::encode(sel.content_hash),
                obj.version,
                hex::encode(obj.content_hash)
            ));
        }
    }

    let mut verified_corroborated_resolutions = 0usize;
    for res in &archive.bundle.resolution_records {
        let c = &res.winning_claim;
        let stored = claims_by_id.get(&c.id).ok_or_else(|| {
            format!(
                "bundle resolution_records references missing claim[id={}]",
                c.id
            )
        })?;
        if c.content_hash != stored.content_hash
            || !claim_matches_record_group(&res.claim_group_key, stored)
        {
            return Err(format!(
                "tampered resolution_record for claim[id={}]: content_hash {} != verified claim {}",
                c.id,
                hex::encode(c.content_hash),
                hex::encode(stored.content_hash)
            ));
        }
        if let Some(ref ovr_ref) = res.override_attestation {
            let verified_att = overrides_by_id.get(&ovr_ref.attestation_id).ok_or_else(|| {
                format!(
                    "resolution_record references missing override_attestation[id={}]",
                    ovr_ref.attestation_id
                )
            })?;
            if verified_att.attestation_hash != ovr_ref.attestation_hash
                || verified_att.winning_claim_id != c.id
                || verified_att.winning_claim_content_hash != c.content_hash
                || verified_att.adjudicator_id != ovr_ref.adjudicator_id
                || verified_att.justification != ovr_ref.justification
                || verified_att.evidence_seq_num != ovr_ref.evidence_seq_num
            {
                return Err(format!(
                    "tampered override_attestation reference on resolution_record for claim[id={}]",
                    c.id
                ));
            }
        } else if c.corroborating_count > 1 || c.effective_confidence.is_some() {
            let expected_count = c.corroborating_count.max(2);
            let mut bucket_claims: Vec<&KnowledgeClaim> = vec![stored];
            for sid in &res.suppressed_claim_ids {
                if *sid == c.id {
                    continue;
                }
                if let Some(sup_stored) = claims_by_id.get(sid) {
                    if !claim_matches_record_group(&res.claim_group_key, sup_stored) {
                        return Err(format!(
                            "corroborating claim[id={sid}] does not match resolution claim_group_key"
                        ));
                    }
                    if claims_share_winning_value_bucket(c, sup_stored) {
                        bucket_claims.push(sup_stored);
                    }
                }
            }
            if bucket_claims.len() != expected_count {
                return Err(format!(
                    "resolution_record for claim[id={}] declares corroborating_count={expected_count}, but archive.claims contains {} winning-bucket claim(s); all corroborating claims must be proven in archive.claims",
                    c.id,
                    bucket_claims.len()
                ));
            }
            let (recomputed_cnt, recomputed_sources, recomputed_eff) =
                recompute_winning_bucket_corroboration(&bucket_claims, corroboration_damping)?;
            if recomputed_cnt != expected_count {
                return Err(format!(
                    "corroborating_count mismatch on claim[id={}]: recomputed {recomputed_cnt} != {expected_count}",
                    c.id
                ));
            }
            if !c.corroborating_sources.is_empty() && recomputed_sources != c.corroborating_sources {
                return Err(format!(
                    "corroborating_sources mismatch on claim[id={}]: recomputed {:?} != {:?}",
                    c.id, recomputed_sources, c.corroborating_sources
                ));
            }
            if let Some(claimed_eff) = c.effective_confidence {
                if (claimed_eff - recomputed_eff).abs() > 1e-9 {
                    return Err(format!(
                        "tampered effective_confidence on claim[id={}]: recomputed {recomputed_eff:.9} != bundle {claimed_eff:.9}",
                        c.id
                    ));
                }
            }
            verified_corroborated_resolutions += 1;
        }
    }

    for disp in &archive.bundle.dispute_records {
        if disp.competing_claims.is_empty() {
            return Err("invalid dispute_record with empty competing_claims".to_string());
        }
        for c in &disp.competing_claims {
            let stored = claims_by_id.get(&c.id).ok_or_else(|| {
                format!(
                    "bundle dispute_records references missing claim[id={}]",
                    c.id
                )
            })?;
            if c.content_hash != stored.content_hash
                || !claim_matches_record_group(&disp.claim_group_key, stored)
            {
                return Err(format!(
                    "tampered dispute_record candidate claim[id={}]: content_hash {} != verified claim {}",
                    c.id,
                    hex::encode(c.content_hash),
                    hex::encode(stored.content_hash)
                ));
            }
        }
        if let Some(ref lapsed) = disp.lapsed_override {
            let verified_att = overrides_by_id.get(&lapsed.attestation_id).ok_or_else(|| {
                format!(
                    "dispute_record.lapsed_override references missing override_attestation[id={}]",
                    lapsed.attestation_id
                )
            })?;
            if verified_att.attestation_hash != lapsed.attestation_hash
                || verified_att.winning_claim_id != lapsed.prior_winning_claim_id
                || verified_att.adjudicator_id != lapsed.adjudicator_id
                || verified_att.justification != lapsed.justification
                || verified_att.evidence_seq_num != lapsed.evidence_seq_num
            {
                return Err(format!(
                    "tampered lapsed_override reference on dispute_record[id={}]",
                    lapsed.attestation_id
                ));
            }
        }
    }

    let (recomputed_bundle_hash, _canonical_bytes) = compute_bundle_hash(&archive.bundle)
        .map_err(|e| format!("ContextBundle canonicalization failed: {e}"))?;
    if recomputed_bundle_hash != archive.bundle_hash {
        return Err(format!(
            "tampered ContextBundle (e.g., resolver_manifest / omission_record / records / commitments): recomputed bundle_hash {} != archive bundle_hash {}",
            hex::encode(recomputed_bundle_hash),
            hex::encode(archive.bundle_hash)
        ));
    }

    if archive.evidence_chain.is_empty() && archive.merkle_proof.is_none() {
        return Err(
            "ExportArchive must contain either evidence_chain or merkle_proof".to_string(),
        );
    }

    let mut verified_refusals = 0usize;
    let mut verified_writes = 0usize;
    let mut verified_answer_caches = 0usize;
    let mut verified_evidence_entries = 0usize;
    let mut evidence_by_seq: HashMap<i64, &EvidenceEntry> = HashMap::new();
    let mut found_matching_bundle_entry = false;

    if !archive.evidence_chain.is_empty() {
        for (idx, entry) in archive.evidence_chain.iter().enumerate() {
            if idx == 0 {
                if entry.seq_num == 1 && entry.prev_hash != [0u8; 32] {
                    return Err(format!(
                        "tampered genesis evidence_chain[0]: seq_num=1 must have zero prev_hash, got {}",
                        hex::encode(entry.prev_hash)
                    ));
                }
            } else {
                let prev_entry = &archive.evidence_chain[idx - 1];
                if entry.seq_num != prev_entry.seq_num + 1 {
                    return Err(format!(
                        "tampered evidence seq_num at index {idx}: expected {}, got {}",
                        prev_entry.seq_num + 1,
                        entry.seq_num
                    ));
                }
                if entry.prev_hash != prev_entry.event_hash {
                    return Err(format!(
                        "broken evidence prev_hash link at seq_num={}: prev_hash {} != prior event_hash {}",
                        entry.seq_num,
                        hex::encode(entry.prev_hash),
                        hex::encode(prev_entry.event_hash)
                    ));
                }
            }

            let counts =
                verify_single_evidence_entry(entry, &archive.bundle.tenant_id, &verifying_key)?;
            if counts.is_refusal {
                verified_refusals += 1;
            }
            if counts.is_write {
                verified_writes += 1;
            }
            if counts.is_answer_cache {
                verified_answer_caches += 1;
            }
            verified_evidence_entries += 1;

            if entry.bundle_hash == Some(recomputed_bundle_hash) {
                if entry.state_commitment != Some(archive.bundle.state_commitment) {
                    return Err(format!(
                        "evidence seq_num={} state_commitment mismatch against ContextBundle",
                        entry.seq_num
                    ));
                }
                found_matching_bundle_entry = true;
            }
            evidence_by_seq.insert(entry.seq_num, entry);
        }
    }

    let mut merkle_tree_size = None;
    let mut merkle_root_hex = None;
    let mut anchored_tree_size = None;
    let mut anchored_merkle_root_hex = None;
    let mut verified_witness_anchors = 0usize;

    if let Some(ref mp) = archive.merkle_proof {
        verified_witness_anchors =
            verify_signed_tree_head(&mp.checkpoint, &archive.bundle.tenant_id, &verifying_key)?;
        verify_entry_inclusion(&mp.bundle_entry_proof, &mp.checkpoint, &verifying_key)?;

        if mp.bundle_entry_proof.entry.bundle_hash != Some(recomputed_bundle_hash)
            || mp.bundle_entry_proof.entry.state_commitment != Some(archive.bundle.state_commitment)
        {
            return Err(
                "merkle_proof.bundle_entry_proof does not bind archive bundle_hash and state_commitment"
                    .to_string(),
            );
        }
        found_matching_bundle_entry = true;

        if archive.evidence_chain.is_empty() {
            verified_evidence_entries += 1;
        }
        evidence_by_seq.insert(mp.bundle_entry_proof.entry.seq_num, &mp.bundle_entry_proof.entry);

        for ovr_proof in &mp.override_entry_proofs {
            verify_entry_inclusion(ovr_proof, &mp.checkpoint, &verifying_key)?;
            if archive.evidence_chain.is_empty()
                && !evidence_by_seq.contains_key(&ovr_proof.entry.seq_num)
            {
                verified_evidence_entries += 1;
            }
            evidence_by_seq.insert(ovr_proof.entry.seq_num, &ovr_proof.entry);
        }

        for wr_proof in &mp.write_entry_proofs {
            let counts = verify_entry_inclusion(wr_proof, &mp.checkpoint, &verifying_key)?;
            if archive.evidence_chain.is_empty()
                && !evidence_by_seq.contains_key(&wr_proof.entry.seq_num)
            {
                verified_evidence_entries += 1;
                if counts.is_write {
                    verified_writes += 1;
                }
            }
            evidence_by_seq.insert(wr_proof.entry.seq_num, &wr_proof.entry);
        }

        if !archive.evidence_chain.is_empty()
            && archive.evidence_chain[0].seq_num == 1
            && archive.evidence_chain.len() as i64 == mp.checkpoint.tree_size
        {
            let leaves: Vec<[u8; 32]> = archive
                .evidence_chain
                .iter()
                .map(|e| merkle_leaf_hash(e.seq_num, &e.event_hash))
                .collect();
            let chain_root = compute_merkle_root_from_leaves(&leaves);
            if chain_root != mp.checkpoint.merkle_root {
                return Err(format!(
                    "merkle_proof.checkpoint.merkle_root {} != root {} computed from evidence_chain",
                    hex::encode(mp.checkpoint.merkle_root),
                    hex::encode(chain_root)
                ));
            }
        }

        if !mp.consistency_proof_to_anchor.is_empty() && mp.anchored_checkpoint.is_none() {
            return Err(
                "merkle_proof.consistency_proof_to_anchor present without anchored_checkpoint"
                    .to_string(),
            );
        }

        if let Some(ref anchor_sth) = mp.anchored_checkpoint {
            if anchor_sth.tree_size < mp.checkpoint.tree_size {
                return Err(format!(
                    "anchored_checkpoint.tree_size ({}) < checkpoint.tree_size ({})",
                    anchor_sth.tree_size, mp.checkpoint.tree_size
                ));
            }
            let bridged_anchors =
                verify_signed_tree_head(anchor_sth, &archive.bundle.tenant_id, &verifying_key)?;
            let cons_nodes = decode_audit_path(&mp.consistency_proof_to_anchor)?;
            if !verify_merkle_consistency_proof(
                mp.checkpoint.tree_size,
                &mp.checkpoint.merkle_root,
                anchor_sth.tree_size,
                &anchor_sth.merkle_root,
                &cons_nodes,
            ) {
                return Err(format!(
                    "RFC 6962 consistency_proof_to_anchor verification failed from tree_size={} to anchored tree_size={}",
                    mp.checkpoint.tree_size, anchor_sth.tree_size
                ));
            }
            if anchor_sth.tree_size > mp.checkpoint.tree_size {
                verified_witness_anchors += bridged_anchors;
            }
            anchored_tree_size = Some(anchor_sth.tree_size);
            anchored_merkle_root_hex = Some(hex::encode(anchor_sth.merkle_root));
        } else if !mp.checkpoint.witness_anchors.is_empty() {
            anchored_tree_size = Some(mp.checkpoint.tree_size);
            anchored_merkle_root_hex = Some(hex::encode(mp.checkpoint.merkle_root));
        }

        merkle_tree_size = Some(mp.checkpoint.tree_size);
        merkle_root_hex = Some(hex::encode(mp.checkpoint.merkle_root));
    }

    for att in &archive.override_attestations {
        let ev = evidence_by_seq.get(&att.evidence_seq_num).ok_or_else(|| {
            format!(
                "override_attestation[id={}] references missing verified evidence seq_num={}",
                att.id, att.evidence_seq_num
            )
        })?;
        if ev.state_commitment != Some(att.attestation_hash) {
            return Err(format!(
                "override_attestation[id={}] attestation_hash not bound in evidence seq_num={}",
                att.id, att.evidence_seq_num
            ));
        }
    }

    for obj in &archive.objects {
        if let Some(seq) = obj.evidence_seq_num {
            if let Some(ev) = evidence_by_seq.get(&seq) {
                let Some(ref ws) = ev.write_summary else {
                    return Err(format!(
                        "object[id={}] references evidence seq_num={seq} without write_summary",
                        obj.id
                    ));
                };
                if ws.item_id != obj.id || ws.content_hash != obj.content_hash {
                    return Err(format!(
                        "object[id={}] content_hash mismatch against write_summary at seq_num={seq}",
                        obj.id
                    ));
                }
            } else if archive.merkle_proof.is_some() || !archive.evidence_chain.is_empty() {
                return Err(format!(
                    "object[id={}] references missing verified write evidence seq_num={seq}",
                    obj.id
                ));
            }
        }
    }

    for clm in &archive.claims {
        if let Some(seq) = clm.evidence_seq_num {
            if let Some(ev) = evidence_by_seq.get(&seq) {
                let Some(ref ws) = ev.write_summary else {
                    return Err(format!(
                        "claim[id={}] references evidence seq_num={seq} without write_summary",
                        clm.id
                    ));
                };
                if ws.item_id != clm.id || ws.content_hash != clm.content_hash {
                    return Err(format!(
                        "claim[id={}] content_hash mismatch against write_summary at seq_num={seq}",
                        clm.id
                    ));
                }
            } else if archive.merkle_proof.is_some() || !archive.evidence_chain.is_empty() {
                return Err(format!(
                    "claim[id={}] references missing verified write evidence seq_num={seq}",
                    clm.id
                ));
            }
        }
    }

    if !found_matching_bundle_entry {
        return Err(format!(
            "no verified evidence_history entry binds bundle_hash {}",
            hex::encode(recomputed_bundle_hash)
        ));
    }

    let verification_mode = match (!archive.evidence_chain.is_empty(), archive.merkle_proof.is_some())
    {
        (true, true) => "full_chain_and_merkle",
        (true, false) => "full_chain",
        (false, true) => "merkle_inclusion",
        (false, false) => unreachable!(),
    }
    .to_string();

    let non_default_thresholds = archive
        .bundle
        .resolver_manifest
        .as_ref()
        .is_some_and(|rm| rm.non_default_thresholds);

    Ok(VerificationSummary {
        tenant_id: archive.bundle.tenant_id.clone(),
        bundle_hash_hex: hex::encode(recomputed_bundle_hash),
        state_commitment_hex: hex::encode(archive.bundle.state_commitment),
        verified_objects: objects_by_id.len(),
        verified_claims: claims_by_id.len(),
        verified_corroborated_resolutions,
        verified_overrides: overrides_by_id.len(),
        verified_writes,
        verified_answer_caches,
        verified_refusals,
        verified_evidence_entries,
        verification_mode,
        merkle_tree_size,
        merkle_root_hex,
        anchored_tree_size,
        anchored_merkle_root_hex,
        verified_witness_anchors,
        non_default_thresholds,
        resolver_manifest: archive.bundle.resolver_manifest.clone(),
    })
}

fn dump_checkpoint_preimages(sth: &SignedTreeHead, bundle_audit_path_len: Option<usize>) -> Value {
    let cp_preimage = checkpoint_hash_preimage_bytes(
        &sth.tenant_id,
        sth.tree_size,
        &sth.head_event_hash,
        &sth.merkle_root,
        sth.issued_at.timestamp_micros(),
    );
    let cp_sig_preimage = checkpoint_signing_preimage_bytes(&sth.tenant_id, &sth.checkpoint_hash);
    let cp_sig_digest = checkpoint_signing_preimage(&sth.tenant_id, &sth.checkpoint_hash);
    let witness_dump: Vec<Value> = sth
        .witness_anchors
        .iter()
        .map(|a| {
            let w_preimage = witness_anchor_signing_preimage_bytes(
                &a.tenant_id,
                a.tree_size,
                &a.checkpoint_hash,
            );
            let w_digest = witness_anchor_signing_preimage(
                &a.tenant_id,
                a.tree_size,
                &a.checkpoint_hash,
            );
            json!({
                "id": a.id,
                "witness_id": a.witness_id,
                "witness_public_key_hex": hex::encode(a.witness_public_key),
                "witness_sig_domain": "acta:witness_sig:v1",
                "witness_sig_blake3_preimage_hex": hex::encode(w_preimage),
                "witness_sig_digest_hex": hex::encode(w_digest),
                "witness_signature_hex": hex::encode(a.witness_signature),
            })
        })
        .collect();

    let mut val = json!({
        "tree_size": sth.tree_size,
        "head_event_hash": hex::encode(sth.head_event_hash),
        "merkle_root": hex::encode(sth.merkle_root),
        "issued_at_micros": sth.issued_at.timestamp_micros(),
        "checkpoint_domain": "acta:checkpoint:v1",
        "checkpoint_blake3_preimage_hex": hex::encode(cp_preimage),
        "checkpoint_hash": hex::encode(sth.checkpoint_hash),
        "host_sig_preimage_domain": "acta:checkpoint_sig:v1",
        "host_sig_blake3_preimage_hex": hex::encode(cp_sig_preimage),
        "host_sig_digest_hex": hex::encode(cp_sig_digest),
        "host_signature_hex": hex::encode(sth.host_signature),
        "witness_anchors": witness_dump,
    });
    if let Some(len) = bundle_audit_path_len {
        val["bundle_audit_path_len"] = json!(len);
    }
    val
}

/// Renders explicit domain-separated raw byte preimages and canonical JCS strings inside `archive`.
pub fn dump_archive_preimages(archive: &ExportArchive) -> Result<Value, String> {
    let (bundle_jcs, bundle_preimage, _bundle_hash) =
        bundle_hash_preimage_bytes(&archive.bundle).map_err(|e| format!("bundle JCS error: {e}"))?;
    let bundle_jcs_utf8 =
        String::from_utf8(bundle_jcs.clone()).map_err(|e| format!("bundle UTF-8 error: {e}"))?;

    let mut objects_dump = Vec::with_capacity(archive.objects.len());
    for obj in &archive.objects {
        let obj_pre = object_content_preimage_bytes(obj)
            .map_err(|e| format!("object[{}] preimage error: {e}", obj.id))?;
        objects_dump.push(json!({
            "id": obj.id,
            "obj_type": obj.obj_type.as_str(),
            "version": obj.version,
            "evidence_seq_num": obj.evidence_seq_num,
            "object_domain": "acta:object:v1",
            "object_blake3_preimage_hex": hex::encode(obj_pre),
            "content_hash": hex::encode(obj.content_hash),
            "client_public_key_hex": obj.client_public_key.map(hex::encode),
            "client_signature_hex": obj.client_signature.as_ref().map(hex::encode),
        }));
    }

    let mut claims_dump = Vec::with_capacity(archive.claims.len());
    for claim in &archive.claims {
        let (grp_domain, grp_pre) = claim_group_preimage_bytes(claim);
        let clm_pre = claim_content_preimage_bytes(claim)
            .map_err(|e| format!("claim[{}] preimage error: {e}", claim.id))?;
        claims_dump.push(json!({
            "id": claim.id,
            "subject": claim.subject,
            "predicate": claim.predicate,
            "version": claim.version,
            "evidence_seq_num": claim.evidence_seq_num,
            "claim_group_domain": grp_domain,
            "claim_group_blake3_preimage_hex": hex::encode(grp_pre),
            "claim_group_key": hex::encode(claim.claim_group_key),
            "claim_domain": "acta:claim:v1",
            "claim_blake3_preimage_hex": hex::encode(clm_pre),
            "content_hash": hex::encode(claim.content_hash),
            "source_commitment_hex": hex::encode(claim.source_commitment),
            "client_public_key_hex": claim.client_public_key.map(hex::encode),
            "client_signature_hex": claim.client_signature.as_ref().map(hex::encode),
        }));
    }

    let mut overrides_dump = Vec::with_capacity(archive.override_attestations.len());
    for att in &archive.override_attestations {
        let att_domain = att.effective_domain();
        let auth_kind = att.effective_auth_kind();
        let att_preimage = override_attestation_preimage_bytes(&OverrideHashInput {
            attestation_domain: att_domain,
            id: att.id,
            tenant_id: &att.tenant_id,
            scope: &att.scope,
            claim_group_key: &att.claim_group_key,
            subject: &att.subject,
            predicate: &att.predicate,
            source_bundle_hash: att.source_bundle_hash.as_ref(),
            winning_claim_id: att.winning_claim_id,
            winning_claim_content_hash: &att.winning_claim_content_hash,
            overridden_claims: &att.overridden_claims,
            adjudicator_id: &att.adjudicator_id,
            adjudicator_auth_kind: auth_kind,
            justification: &att.justification,
            version: att.version,
            predecessor_id: att.predecessor_id,
            created_at: att.created_at,
            client_public_key: att.client_public_key.as_ref(),
            client_signature: att.client_signature.as_deref(),
        })
        .map_err(|e| format!("override preimage error: {e}"))?;
        let host_sig_preimage = override_signing_preimage_bytes(
            &att.tenant_id,
            att.evidence_seq_num,
            &att.attestation_hash,
        );
        let host_sig_digest = override_signing_preimage(
            &att.tenant_id,
            att.evidence_seq_num,
            &att.attestation_hash,
        );

        let (client_sig_domain, client_sig_preimage_hex, client_sig_digest_hex) =
            if att.client_signature.is_some() {
                let c_pre = override_client_intent_preimage_bytes(
                    &att.tenant_id,
                    &att.scope,
                    att.winning_claim_id,
                    &att.adjudicator_id,
                    &att.justification,
                );
                let c_dig = compute_override_client_intent_hash(
                    &att.tenant_id,
                    &att.scope,
                    att.winning_claim_id,
                    &att.adjudicator_id,
                    &att.justification,
                );
                (
                    json!("acta:override_client_sig:v1"),
                    json!(hex::encode(c_pre)),
                    json!(hex::encode(c_dig)),
                )
            } else {
                (Value::Null, Value::Null, Value::Null)
            };

        overrides_dump.push(json!({
            "id": att.id,
            "evidence_seq_num": att.evidence_seq_num,
            "adjudicator_auth_kind": auth_kind,
            "attestation_domain": att_domain,
            "attestation_blake3_preimage_hex": hex::encode(att_preimage),
            "attestation_hash": hex::encode(att.attestation_hash),
            "host_sig_preimage_domain": "acta:override_sig:v1",
            "host_sig_blake3_preimage_hex": hex::encode(host_sig_preimage),
            "host_sig_digest_hex": hex::encode(host_sig_digest),
            "host_signature_hex": hex::encode(att.host_signature),
            "client_sig_domain": client_sig_domain,
            "client_sig_blake3_preimage_hex": client_sig_preimage_hex,
            "client_sig_digest_hex": client_sig_digest_hex,
            "client_public_key_hex": att.client_public_key.map(hex::encode),
            "client_signature_hex": att.client_signature.as_ref().map(hex::encode),
        }));
    }

    let entries_source: Vec<&EvidenceEntry> = if !archive.evidence_chain.is_empty() {
        archive.evidence_chain.iter().collect()
    } else if let Some(ref mp) = archive.merkle_proof {
        let mut v = vec![&mp.bundle_entry_proof.entry];
        for op in &mp.override_entry_proofs {
            if !v.iter().any(|e| e.seq_num == op.entry.seq_num) {
                v.push(&op.entry);
            }
        }
        for wp in &mp.write_entry_proofs {
            if !v.iter().any(|e| e.seq_num == wp.entry.seq_num) {
                v.push(&wp.entry);
            }
        }
        v.sort_by_key(|e| e.seq_num);
        v
    } else {
        Vec::new()
    };

    let mut evidence_dump = Vec::with_capacity(entries_source.len());
    for entry in entries_source {
        let (event_domain, ev_preimage) = evidence_event_preimage_bytes_v172(
            &entry.tenant_id,
            entry.seq_num,
            &entry.prev_hash,
            entry.bundle_hash.as_ref(),
            entry.state_commitment.as_ref(),
            entry.policy_result,
            entry.created_at.timestamp_micros(),
            entry.refusal_metadata.as_ref(),
            entry.override_summary.as_ref(),
            entry.write_summary.as_ref(),
            entry.answer_cache_summary.as_ref(),
            entry.witness_reg_summary.as_ref(),
            entry.witness_revoke_summary.as_ref(),
            entry.uses_witness_v3_event_domain(),
        )
        .map_err(|e| format!("evidence preimage error at seq {}: {e}", entry.seq_num))?;

        let sig_preimage = evidence_signing_preimage_bytes(
            &entry.tenant_id,
            entry.seq_num,
            &entry.prev_hash,
            &entry.event_hash,
        );
        let sig_digest = evidence_signing_preimage(
            &entry.tenant_id,
            entry.seq_num,
            &entry.prev_hash,
            &entry.event_hash,
        );
        let leaf_preimage = merkle_leaf_preimage_bytes(&entry.event_hash);
        let leaf_hash = merkle_leaf_hash(entry.seq_num, &entry.event_hash);
        let refusal_jcs = entry
            .refusal_metadata
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let override_jcs = entry
            .override_summary
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let write_jcs = entry
            .write_summary
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let answer_cache_jcs = entry
            .answer_cache_summary
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let witness_reg_jcs = entry
            .witness_reg_summary
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let witness_revoke_jcs = entry
            .witness_revoke_summary
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        evidence_dump.push(json!({
            "seq_num": entry.seq_num,
            "event_domain": event_domain,
            "event_blake3_preimage_hex": hex::encode(ev_preimage),
            "event_hash": hex::encode(entry.event_hash),
            "merkle_leaf_sha256_preimage_hex": hex::encode(leaf_preimage),
            "merkle_leaf_hash": hex::encode(leaf_hash),
            "host_sig_preimage_domain": "acta:evidence_sig:v1",
            "host_sig_blake3_preimage_hex": hex::encode(sig_preimage),
            "host_sig_digest_hex": hex::encode(sig_digest),
            "host_signature_hex": hex::encode(entry.host_signature),
            "refusal_metadata_canonical_jcs": refusal_jcs,
            "override_summary_canonical_jcs": override_jcs,
            "write_summary_canonical_jcs": write_jcs,
            "answer_cache_summary_canonical_jcs": answer_cache_jcs,
            "witness_reg_summary_canonical_jcs": witness_reg_jcs,
            "witness_revoke_summary_canonical_jcs": witness_revoke_jcs,
            "witness_registration": entry.witness_reg_summary,
            "witness_revocation": entry.witness_revoke_summary,
        }));
    }

    let checkpoint_dump = archive.merkle_proof.as_ref().map(|mp| {
        dump_checkpoint_preimages(&mp.checkpoint, Some(mp.bundle_entry_proof.audit_path.len()))
    });

    let anchored_checkpoint_dump = archive
        .merkle_proof
        .as_ref()
        .and_then(|mp| {
            mp.anchored_checkpoint.as_ref().map(|asth| {
                let mut v = dump_checkpoint_preimages(asth, None);
                v["from_tree_size"] = json!(mp.checkpoint.tree_size);
                v["consistency_proof_to_anchor"] = json!(mp.consistency_proof_to_anchor);
                v
            })
        });

    let mut out = json!({
        "framing_spec": "BLAKE3 digests hash concat_i(u64_le(len(part_i)) || part_i); Ed25519 signatures sign raw 32-byte digest bytes; Merkle trees follow RFC 6962 §2.1 SHA-256.",
        "merkle_spec": {
            "scheme": "rfc6962-sha256-v1",
            "empty_root_sha256_hex": hex::encode(merkle_empty_root()),
            "leaf_formula": "SHA-256(0x00 || event_hash_32)",
            "node_formula": "SHA-256(0x01 || left_32 || right_32)",
            "legacy_v160_blake3_merkle_spec": {
                "scheme": "acta-blake3-merkle-v1",
                "empty_root_blake3_hex": hex::encode(legacy_blake3_merkle_empty_root()),
                "leaf_formula": "BLAKE3(encode_length_delimited([b\"acta:merkle_leaf:v1\", i64_le(seq_num), event_hash_32]))",
                "node_formula": "BLAKE3(encode_length_delimited([b\"acta:merkle_node:v1\", left_32, right_32]))",
            },
        },
        "bundle_domain": "acta:bundle:v1",
        "bundle_canonical_jcs_len": bundle_jcs.len(),
        "bundle_canonical_jcs_utf8": bundle_jcs_utf8,
        "bundle_blake3_preimage_hex": hex::encode(bundle_preimage),
        "bundle_hash": hex::encode(archive.bundle_hash),
        "objects": objects_dump,
        "claims": claims_dump,
        "checkpoint": checkpoint_dump,
        "override_attestations": overrides_dump,
        "evidence_entries": evidence_dump,
    });
    if let Some(acp) = anchored_checkpoint_dump {
        out["anchored_checkpoint"] = acp;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineStateRebuildSummary {
    pub tenant_id: String,
    pub scope: String,
    pub verified_up_to_seq: i64,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub header_hash_hex: String,
    pub header_signature_verified: bool,
    pub verified_evidence_entries: usize,
    pub write_events_replayed: usize,
    pub reconstructed_active_intents: usize,
    pub reconstructed_active_memories: usize,
    pub reconstructed_active_claims: usize,
    pub reconstructed_superseded_or_retracted_items: usize,
    pub reconstructed_active_overrides: usize,
    pub reconstructed_intent_root_hex: String,
    pub reconstructed_knowledge_root_hex: String,
    pub reconstructed_memory_root_hex: String,
    pub permission_root_hex: String,
    pub reconstructed_state_commitment_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_tree_size: Option<i64>,
    #[serde(default)]
    pub verified_witness_anchors: usize,
}

/// Standalone offline verifier & state reconstructor (`v1.7.2+`, PPA 1 Claim 1 & §11):
/// Verifies `StateRebuildArchive` against `expected_pubkey` with zero database or server trust,
/// checking the host-signed archive header (`b"acta:rebuild_header:v1"` -> `b"acta:rebuild_sig:v1"`
/// binding `scope`, `up_to_seq`, `evaluated_at`, and `permission_root`), every `prev_hash` link,
/// `v1`/`v2`/`v3` `event_hash`, host & client Ed25519 signature, RFC 6962 `SignedTreeHead` Merkle root,
/// witness cosignature consistency proof, and strip-proof `override_attestations`, then reconstructs
/// active `(intents, memories, claims, overrides)` and `state_commitment` at `archive.evaluated_at`.
pub fn verify_and_rebuild_scope_state_offline(
    archive: &StateRebuildArchive,
    expected_pubkey: &[u8; 32],
    scope_override: Option<&str>,
) -> Result<OfflineStateRebuildSummary, String> {
    if archive.schema_version != STATE_REBUILD_ARCHIVE_SCHEMA_V1 {
        return Err(format!(
            "unsupported StateRebuildArchive schema_version '{}' (expected '{}')",
            archive.schema_version, STATE_REBUILD_ARCHIVE_SCHEMA_V1
        ));
    }
    if &archive.host_public_key != expected_pubkey {
        return Err(format!(
            "host_public_key mismatch: archive contains {}, expected {}",
            hex::encode(archive.host_public_key),
            hex::encode(expected_pubkey)
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(expected_pubkey)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
    if verifying_key.is_weak() {
        return Err("rejected weak low-order Ed25519 public key".to_string());
    }

    if archive.up_to_seq < 0 {
        return Err(format!("invalid up_to_seq={}: must be >= 0", archive.up_to_seq));
    }

    let recomputed_header_hash = compute_rebuild_archive_header_hash(
        &archive.schema_version,
        &archive.tenant_id,
        &archive.scope,
        archive.up_to_seq,
        archive.evaluated_at.timestamp_micros(),
        &archive.permission_root,
    );
    if recomputed_header_hash != archive.header_hash {
        return Err(format!(
            "tampered StateRebuildArchive header (scope / up_to_seq / evaluated_at / permission_root): recomputed header_hash {} != stored {}",
            hex::encode(recomputed_header_hash),
            hex::encode(archive.header_hash)
        ));
    }
    if !verify_rebuild_archive_header_signature(
        &verifying_key,
        &archive.tenant_id,
        &recomputed_header_hash,
        &archive.host_header_signature,
    ) {
        return Err(
            "Ed25519 host_header_signature verification failed on StateRebuildArchive header"
                .to_string(),
        );
    }

    let target_scope = scope_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(archive.scope.as_str());

    if (archive.evidence_chain.len() as i64) != archive.up_to_seq {
        return Err(format!(
            "evidence_chain length ({}) != archive.up_to_seq ({})",
            archive.evidence_chain.len(),
            archive.up_to_seq
        ));
    }

    let mut objects_map: BTreeMap<Uuid, StoredObject> = BTreeMap::new();
    let mut claims_map: BTreeMap<Uuid, KnowledgeClaim> = BTreeMap::new();
    let mut write_events_replayed = 0usize;
    let mut expected_override_seqs: BTreeMap<i64, (Uuid, [u8; 32])> = BTreeMap::new();
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(archive.evidence_chain.len());

    for (idx, entry) in archive.evidence_chain.iter().enumerate() {
        let expected_seq = (idx + 1) as i64;
        if entry.seq_num != expected_seq {
            return Err(format!(
                "gap in evidence_chain at index {idx}: expected seq_num={expected_seq}, got {}",
                entry.seq_num
            ));
        }
        if idx == 0 {
            if entry.prev_hash != [0u8; 32] {
                return Err(format!(
                    "tampered genesis seq_num=1: expected zero prev_hash, got {}",
                    hex::encode(entry.prev_hash)
                ));
            }
        } else if entry.prev_hash != archive.evidence_chain[idx - 1].event_hash {
            return Err(format!(
                "broken prev_hash link at seq_num={}",
                entry.seq_num
            ));
        }

        verify_single_evidence_entry(entry, &archive.tenant_id, &verifying_key)?;
        leaves.push(merkle_leaf_hash(entry.seq_num, &entry.event_hash));

        if let Some(ref ws) = entry.write_summary {
            if ws.scope == target_scope {
                write_events_replayed += 1;
                match ws.operation {
                    WriteOperationKind::IngestObject => {
                        let obj: StoredObject = serde_json::from_value(ws.record_snapshot.clone())
                            .map_err(|e| {
                                format!(
                                    "malformed StoredObject snapshot at seq_num={}: {e}",
                                    entry.seq_num
                                )
                            })?;
                        objects_map.insert(obj.id, obj);
                    }
                    WriteOperationKind::IngestClaim | WriteOperationKind::RetractClaim => {
                        let clm: KnowledgeClaim =
                            serde_json::from_value(ws.record_snapshot.clone()).map_err(|e| {
                                format!(
                                    "malformed KnowledgeClaim snapshot at seq_num={}: {e}",
                                    entry.seq_num
                                )
                            })?;
                        claims_map.insert(clm.id, clm);
                    }
                }
            }
        }

        if let Some(ref ovs) = entry.override_summary {
            if ovs.scope == target_scope {
                let att_comm = entry.state_commitment.ok_or_else(|| {
                    format!(
                        "override evidence entry at seq_num={} missing state_commitment",
                        entry.seq_num
                    )
                })?;
                expected_override_seqs.insert(entry.seq_num, (ovs.attestation_id, att_comm));
            }
        }
    }

    // Verify every provided OverrideAttestation in target_scope AND ensure none in evidence_chain were stripped!
    let mut verified_overrides_by_seq: BTreeMap<i64, &acta_types::OverrideAttestation> =
        BTreeMap::new();
    for att in &archive.override_attestations {
        if att.tenant_id != archive.tenant_id {
            return Err(format!(
                "override_attestation[id={}] tenant_id '{}' != archive tenant_id '{}'",
                att.id, att.tenant_id, archive.tenant_id
            ));
        }
        if att.scope != target_scope {
            continue;
        }
        verify_override_auth_kind_consistency(att)?;
        if let (Some(ref csig), Some(ref cpk)) = (&att.client_signature, &att.client_public_key) {
            let sig_arr: [u8; 64] = csig.as_slice().try_into().map_err(|_| {
                format!(
                    "override_attestation[id={}] client_signature is not 64 bytes",
                    att.id
                )
            })?;
            let intent_hash = compute_override_client_intent_hash(
                &att.tenant_id,
                &att.scope,
                att.winning_claim_id,
                &att.adjudicator_id,
                &att.justification,
            );
            if !verify_client_content_signature(cpk, &intent_hash, &sig_arr)
                && !verify_client_content_signature(cpk, &att.attestation_hash, &sig_arr)
            {
                return Err(format!(
                    "client Ed25519 signature verification failed on override_attestation[id={}]",
                    att.id
                ));
            }
        }
        let recomputed_att_hash = compute_override_attestation_hash(&OverrideHashInput {
            attestation_domain: att.effective_domain(),
            id: att.id,
            tenant_id: &att.tenant_id,
            scope: &att.scope,
            claim_group_key: &att.claim_group_key,
            subject: &att.subject,
            predicate: &att.predicate,
            source_bundle_hash: att.source_bundle_hash.as_ref(),
            winning_claim_id: att.winning_claim_id,
            winning_claim_content_hash: &att.winning_claim_content_hash,
            overridden_claims: &att.overridden_claims,
            adjudicator_id: &att.adjudicator_id,
            adjudicator_auth_kind: att.effective_auth_kind(),
            justification: &att.justification,
            version: att.version,
            predecessor_id: att.predecessor_id,
            created_at: att.created_at,
            client_public_key: att.client_public_key.as_ref(),
            client_signature: att.client_signature.as_deref(),
        })
        .map_err(|e| format!("override_attestation[id={}] canonicalization failed: {e}", att.id))?;
        if recomputed_att_hash != att.attestation_hash {
            return Err(format!(
                "tampered override_attestation[id={}]: recomputed {} != stored {}",
                att.id,
                hex::encode(recomputed_att_hash),
                hex::encode(att.attestation_hash)
            ));
        }
        if !verify_override_signature(
            &verifying_key,
            &att.tenant_id,
            att.evidence_seq_num,
            &recomputed_att_hash,
            &att.host_signature,
        ) {
            return Err(format!(
                "Ed25519 host_signature verification failed on override_attestation[id={}]",
                att.id
            ));
        }
        let Some(&(exp_id, exp_comm)) = expected_override_seqs.get(&att.evidence_seq_num) else {
            return Err(format!(
                "unlinked override_attestation[id={}] at evidence_seq_num={} not present in evidence_chain",
                att.id, att.evidence_seq_num
            ));
        };
        if exp_id != att.id || exp_comm != att.attestation_hash {
            return Err(format!(
                "override_attestation[id={}] mismatch against evidence_chain seq_num={}",
                att.id, att.evidence_seq_num
            ));
        }
        verified_overrides_by_seq.insert(att.evidence_seq_num, att);
    }

    for (&seq, &(att_id, _)) in &expected_override_seqs {
        if !verified_overrides_by_seq.contains_key(&seq) {
            return Err(format!(
                "stripped override_attestation[id={att_id}] notarized at evidence_chain seq_num={seq} is missing from archive.override_attestations"
            ));
        }
    }

    let mut merkle_root_hex = None;
    let mut anchored_tree_size = None;
    let mut verified_witness_anchors = 0usize;

    if archive.up_to_seq > 0 {
        let computed_root = compute_merkle_root_from_leaves(&leaves);
        if let Some(ref sth) = archive.checkpoint {
            if sth.tree_size != archive.up_to_seq {
                return Err(format!(
                    "checkpoint.tree_size ({}) != archive.up_to_seq ({})",
                    sth.tree_size, archive.up_to_seq
                ));
            }
            verified_witness_anchors =
                verify_signed_tree_head(sth, &archive.tenant_id, &verifying_key)?;
            if sth.merkle_root != computed_root {
                return Err(format!(
                    "checkpoint.merkle_root {} != root {} computed from evidence_chain",
                    hex::encode(sth.merkle_root),
                    hex::encode(computed_root)
                ));
            }
            if sth.head_event_hash != archive.evidence_chain.last().unwrap().event_hash {
                return Err("checkpoint.head_event_hash mismatch against chain tail".to_string());
            }
            if !sth.witness_anchors.is_empty() {
                anchored_tree_size = Some(sth.tree_size);
            }
        }
        merkle_root_hex = Some(hex::encode(computed_root));

        if let Some(ref anchor_sth) = archive.latest_anchored_checkpoint {
            let anchor_cnt =
                verify_signed_tree_head(anchor_sth, &archive.tenant_id, &verifying_key)?;
            if anchor_cnt == 0 {
                return Err(
                    "latest_anchored_checkpoint contains zero verified witness_anchors".to_string(),
                );
            }
            let cons_nodes = decode_audit_path(&archive.consistency_proof_from_latest_anchor)?;
            if anchor_sth.tree_size <= archive.up_to_seq {
                let prefix_root =
                    compute_merkle_root_from_leaves(&leaves[..anchor_sth.tree_size as usize]);
                if prefix_root != anchor_sth.merkle_root {
                    return Err(format!(
                        "latest_anchored_checkpoint merkle_root {} != prefix root {} at tree_size={}",
                        hex::encode(anchor_sth.merkle_root),
                        hex::encode(prefix_root),
                        anchor_sth.tree_size
                    ));
                }
                if !verify_merkle_consistency_proof(
                    anchor_sth.tree_size,
                    &anchor_sth.merkle_root,
                    archive.up_to_seq,
                    &computed_root,
                    &cons_nodes,
                ) {
                    return Err(format!(
                        "RFC 6962 consistency proof failed from latest_anchored_checkpoint ({}) to head ({})",
                        anchor_sth.tree_size, archive.up_to_seq
                    ));
                }
            } else if !verify_merkle_consistency_proof(
                archive.up_to_seq,
                &computed_root,
                anchor_sth.tree_size,
                &anchor_sth.merkle_root,
                &cons_nodes,
            ) {
                return Err(format!(
                    "RFC 6962 consistency proof failed from up_to_seq ({}) to latest_anchored_checkpoint ({})",
                    archive.up_to_seq, anchor_sth.tree_size
                ));
            }
            if anchored_tree_size != Some(anchor_sth.tree_size) {
                verified_witness_anchors += anchor_cnt;
                anchored_tree_size = Some(anchor_sth.tree_size);
            }
        }
    }

    let eval_ts = archive.evaluated_at;
    let obj_pred_ids: BTreeSet<Uuid> = objects_map
        .values()
        .filter_map(|o| o.predecessor_id)
        .collect();
    let clm_pred_ids: BTreeSet<Uuid> = claims_map
        .values()
        .filter_map(|c| c.predecessor_id)
        .collect();
    let ovr_pred_ids: BTreeSet<Uuid> = verified_overrides_by_seq
        .values()
        .filter_map(|o| o.predecessor_id)
        .collect();

    let mut intent_hashes = Vec::new();
    let mut memory_hashes = Vec::new();
    let mut superseded_or_retracted = 0usize;

    for obj in objects_map.values() {
        if obj_pred_ids.contains(&obj.id) || obj.lifecycle_status != LifecycleStatus::Active {
            superseded_or_retracted += 1;
        } else {
            match obj.obj_type {
                ObjectType::Intent => intent_hashes.push(obj.content_hash),
                ObjectType::Memory => memory_hashes.push(obj.content_hash),
            }
        }
    }

    let mut claim_hashes = Vec::new();
    for clm in claims_map.values() {
        let within_from = clm.valid_from.map_or(true, |vf| vf <= eval_ts);
        let within_to = clm.valid_to.map_or(true, |vt| vt >= eval_ts);
        if clm_pred_ids.contains(&clm.id)
            || clm.status != ClaimStatus::Active
            || !within_from
            || !within_to
        {
            superseded_or_retracted += 1;
        } else {
            claim_hashes.push(clm.content_hash);
        }
    }

    let reconstructed_active_claims = claim_hashes.len();
    let mut active_overrides_count = 0usize;
    for ovr in verified_overrides_by_seq.values() {
        if !ovr_pred_ids.contains(&ovr.id) {
            claim_hashes.push(ovr.attestation_hash);
            active_overrides_count += 1;
        }
    }

    let intent_root = compute_sub_commitment(&intent_hashes);
    let memory_root = compute_sub_commitment(&memory_hashes);
    let knowledge_root = compute_sub_commitment(&claim_hashes);
    let state_commitment = compute_state_commitment(
        SCHEMA_VERSION,
        &archive.tenant_id,
        target_scope,
        &intent_root,
        &knowledge_root,
        &memory_root,
        &archive.permission_root,
    );

    Ok(OfflineStateRebuildSummary {
        tenant_id: archive.tenant_id.clone(),
        scope: target_scope.to_string(),
        verified_up_to_seq: archive.up_to_seq,
        evaluated_at: eval_ts,
        header_hash_hex: hex::encode(recomputed_header_hash),
        header_signature_verified: true,
        verified_evidence_entries: archive.evidence_chain.len(),
        write_events_replayed,
        reconstructed_active_intents: intent_hashes.len(),
        reconstructed_active_memories: memory_hashes.len(),
        reconstructed_active_claims,
        reconstructed_superseded_or_retracted_items: superseded_or_retracted,
        reconstructed_active_overrides: active_overrides_count,
        reconstructed_intent_root_hex: hex::encode(intent_root),
        reconstructed_knowledge_root_hex: hex::encode(knowledge_root),
        reconstructed_memory_root_hex: hex::encode(memory_root),
        permission_root_hex: hex::encode(archive.permission_root),
        reconstructed_state_commitment_hex: hex::encode(state_commitment),
        merkle_root_hex,
        anchored_tree_size,
        verified_witness_anchors,
    })
}
