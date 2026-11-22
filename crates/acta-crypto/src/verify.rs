use std::collections::HashMap;

use acta_types::{
    EntryInclusionProof, EvidenceEntry, ExportArchive, ResolverManifest, SignedTreeHead,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    checkpoint_signing_preimage, compute_bundle_hash, compute_checkpoint_hash,
    compute_claim_content_hash, compute_claim_group_key, compute_evidence_event_hash_with_meta,
    compute_logical_claim_group_key, compute_merkle_root_from_leaves, compute_object_content_hash,
    compute_override_attestation_hash, compute_override_client_intent_hash,
    compute_refusal_metadata_commitment, evidence_signing_preimage, merkle_leaf_hash,
    override_signing_preimage, to_canonical_bytes, verify_checkpoint_signature,
    verify_client_content_signature, verify_evidence_signature, verify_merkle_inclusion_proof,
    verify_override_signature, verify_witness_anchor_signature, OverrideHashInput,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub tenant_id: String,
    pub bundle_hash_hex: String,
    pub state_commitment_hex: String,
    pub verified_objects: usize,
    pub verified_claims: usize,
    #[serde(default)]
    pub verified_overrides: usize,
    #[serde(default)]
    pub verified_refusals: usize,
    pub verified_evidence_entries: usize,
    #[serde(default)]
    pub verification_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_tree_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root_hex: Option<String>,
    #[serde(default)]
    pub verified_witness_anchors: usize,
    #[serde(default)]
    pub non_default_thresholds: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_manifest: Option<ResolverManifest>,
}

fn claim_matches_record_group(record_group: &[u8; 32], stored: &acta_types::KnowledgeClaim) -> bool {
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

fn verify_single_evidence_entry(
    entry: &EvidenceEntry,
    expected_tenant: &str,
    verifying_key: &VerifyingKey,
) -> Result<bool, String> {
    if entry.tenant_id != expected_tenant {
        return Err(format!(
            "evidence entry seq_num={} tenant_id '{}' != bundle tenant_id '{}'",
            entry.seq_num, entry.tenant_id, expected_tenant
        ));
    }
    if entry.seq_num < 1 {
        return Err(format!("invalid evidence seq_num={}: must be >= 1", entry.seq_num));
    }

    let mut is_refusal = false;
    if let Some(ref rmeta) = entry.refusal_metadata {
        if entry.bundle_hash.is_some() {
            return Err(format!(
                "invalid evidence entry at seq_num={}: refusal_metadata cannot coexist with bundle_hash",
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
        is_refusal = true;
    }

    let recomputed_event_hash = compute_evidence_event_hash_with_meta(
        &entry.tenant_id,
        entry.seq_num,
        &entry.prev_hash,
        entry.bundle_hash.as_ref(),
        entry.state_commitment.as_ref(),
        entry.policy_result,
        entry.created_at.timestamp_micros(),
        entry.refusal_metadata.as_ref(),
        entry.override_summary.as_ref(),
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

    Ok(is_refusal)
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
) -> Result<(), String> {
    verify_single_evidence_entry(&proof.entry, &sth.tenant_id, verifying_key)?;
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
    Ok(())
}

/// Cryptographically verifies an `ExportArchive` against `expected_pubkey` without database access.
/// Supports both linear `evidence_chain` verification AND `O(log N)` `merkle_proof` verification!
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

    if let Some(ref rm) = archive.bundle.resolver_manifest {
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
    }

    let mut objects_by_id: HashMap<Uuid, &acta_types::StoredObject> =
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
        objects_by_id.insert(obj.id, obj);
    }

    let mut claims_by_id: HashMap<Uuid, &acta_types::KnowledgeClaim> =
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
        let recomputed_att_hash = compute_override_attestation_hash(&OverrideHashInput {
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
            justification: &att.justification,
            version: att.version,
            predecessor_id: att.predecessor_id,
            created_at: att.created_at,
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
            let ok_full = verify_client_content_signature(cpk, &recomputed_att_hash, &sig_arr);
            if !ok_intent && !ok_full {
                return Err(format!(
                    "client Ed25519 signature verification failed on override_attestation[id={}]",
                    att.id
                ));
            }
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

            if verify_single_evidence_entry(entry, &archive.bundle.tenant_id, &verifying_key)? {
                verified_refusals += 1;
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
                && ovr_proof.entry.seq_num != mp.bundle_entry_proof.entry.seq_num
            {
                verified_evidence_entries += 1;
            }
            evidence_by_seq.insert(ovr_proof.entry.seq_num, &ovr_proof.entry);
        }

        // If full `evidence_chain` from genesis `seq 1..=tree_size` is also present, cross-verify root!
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
        verified_overrides: overrides_by_id.len(),
        verified_refusals,
        verified_evidence_entries,
        verification_mode,
        merkle_tree_size,
        merkle_root_hex,
        verified_witness_anchors,
        non_default_thresholds,
        resolver_manifest: archive.bundle.resolver_manifest.clone(),
    })
}

/// Renders explicit domain-separated cryptographic preimages inside `archive` for external auditors
/// (`acta-verify --dump-preimages`).
pub fn dump_archive_preimages(archive: &ExportArchive) -> Result<Value, String> {
    let bundle_jcs =
        to_canonical_bytes(&archive.bundle).map_err(|e| format!("bundle JCS error: {e}"))?;
    let overrides_dump: Vec<Value> = archive
        .override_attestations
        .iter()
        .map(|att| {
            let host_sig_digest = override_signing_preimage(
                &att.tenant_id,
                att.evidence_seq_num,
                &att.attestation_hash,
            );
            let client_intent = compute_override_client_intent_hash(
                &att.tenant_id,
                &att.scope,
                att.winning_claim_id,
                &att.adjudicator_id,
                &att.justification,
            );
            json!({
                "id": att.id,
                "evidence_seq_num": att.evidence_seq_num,
                "attestation_hash": hex::encode(att.attestation_hash),
                "host_sig_preimage_domain": "acta:override_sig:v1",
                "host_sig_digest_hex": hex::encode(host_sig_digest),
                "client_sig_domain": "acta:override_client_sig:v1",
                "client_sig_digest_hex": hex::encode(client_intent),
            })
        })
        .collect();

    let entries_source: Vec<&EvidenceEntry> = if !archive.evidence_chain.is_empty() {
        archive.evidence_chain.iter().collect()
    } else if let Some(ref mp) = archive.merkle_proof {
        let mut v = vec![&mp.bundle_entry_proof.entry];
        for op in &mp.override_entry_proofs {
            v.push(&op.entry);
        }
        v
    } else {
        Vec::new()
    };

    let mut evidence_dump = Vec::with_capacity(entries_source.len());
    for entry in entries_source {
        let event_domain = if entry.refusal_metadata.is_none() && entry.override_summary.is_none() {
            "acta:evidence_event:v1"
        } else {
            "acta:evidence_event:v2"
        };
        let sig_digest = evidence_signing_preimage(
            &entry.tenant_id,
            entry.seq_num,
            &entry.prev_hash,
            &entry.event_hash,
        );
        let refusal_jcs = entry
            .refusal_metadata
            .as_ref()
            .and_then(|m| to_canonical_bytes(m).ok())
            .and_then(|b| String::from_utf8(b).ok());
        evidence_dump.push(json!({
            "seq_num": entry.seq_num,
            "event_domain": event_domain,
            "event_hash": hex::encode(entry.event_hash),
            "merkle_leaf_hash": hex::encode(merkle_leaf_hash(entry.seq_num, &entry.event_hash)),
            "host_sig_preimage_domain": "acta:evidence_sig:v1",
            "host_sig_digest_hex": hex::encode(sig_digest),
            "refusal_metadata_canonical_jcs": refusal_jcs,
        }));
    }

    let checkpoint_dump = archive.merkle_proof.as_ref().map(|mp| {
        let cp_sig_digest =
            checkpoint_signing_preimage(&mp.checkpoint.tenant_id, &mp.checkpoint.checkpoint_hash);
        json!({
            "tree_size": mp.checkpoint.tree_size,
            "merkle_root": hex::encode(mp.checkpoint.merkle_root),
            "checkpoint_hash": hex::encode(mp.checkpoint.checkpoint_hash),
            "host_sig_preimage_domain": "acta:checkpoint_sig:v1",
            "host_sig_digest_hex": hex::encode(cp_sig_digest),
            "bundle_audit_path_len": mp.bundle_entry_proof.audit_path.len(),
        })
    });

    Ok(json!({
        "bundle_domain": "acta:bundle:v1",
        "bundle_canonical_jcs_len": bundle_jcs.len(),
        "bundle_hash": hex::encode(archive.bundle_hash),
        "checkpoint": checkpoint_dump,
        "override_attestations": overrides_dump,
        "evidence_entries": evidence_dump,
    }))
}
