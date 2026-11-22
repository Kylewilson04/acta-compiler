use std::collections::HashMap;

use acta_types::{ExportArchive, ResolverManifest};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    compute_bundle_hash, compute_claim_content_hash, compute_claim_group_key,
    compute_evidence_event_hash_with_meta, compute_logical_claim_group_key,
    compute_object_content_hash, compute_override_attestation_hash,
    compute_refusal_metadata_commitment, verify_client_content_signature,
    verify_evidence_signature, verify_override_signature, OverrideHashInput,
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

/// Cryptographically verifies an `ExportArchive` against `expected_pubkey` without database access:
/// 1. Rejects mismatched or weak low-order Ed25519 public keys.
/// 2. Recomputes RFC 8785 + length-delimited BLAKE3 `content_hash` for every object and claim.
/// 3. Validates `resolver_manifest` bounds & truthful `non_default_thresholds` flag when present.
/// 4. Verifies every `OverrideAttestation` (`attestation_hash`, host Ed25519 signature, optional
///    client Ed25519 signature) and ensures every override-resolved `ResolutionRecord` matches a
///    verified attestation AND its corresponding ledger entry in `evidence_chain`.
/// 5. Re-canonicalizes `ContextBundle` and verifies `bundle_hash`.
/// 6. Verifies monotonic `seq_num`, unbroken `prev_hash` chain, `event_hash` (`v1` or `v2` with
///    tamper/strip-proof `refusal_metadata` and `override_summary`), and Ed25519 `verify_strict`.
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
            if !verify_client_content_signature(cpk, &recomputed_att_hash, &sig_arr) {
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

    if archive.evidence_chain.is_empty() {
        return Err("evidence_chain cannot be empty".to_string());
    }

    let mut found_matching_bundle_entry = false;
    let mut verified_refusals = 0usize;
    let mut evidence_by_seq: HashMap<i64, &acta_types::EvidenceEntry> =
        HashMap::with_capacity(archive.evidence_chain.len());

    for (idx, entry) in archive.evidence_chain.iter().enumerate() {
        if entry.tenant_id != archive.bundle.tenant_id {
            return Err(format!(
                "evidence_chain[{idx}] tenant_id '{}' != bundle tenant_id '{}'",
                entry.tenant_id, archive.bundle.tenant_id
            ));
        }

        if idx == 0 {
            if entry.seq_num == 1 && entry.prev_hash != [0u8; 32] {
                return Err(format!(
                    "tampered genesis evidence_chain[0]: seq_num=1 must have zero prev_hash, got {}",
                    hex::encode(entry.prev_hash)
                ));
            }
            if entry.seq_num < 1 {
                return Err(format!(
                    "tampered evidence_chain[0].seq_num={}: must be >= 1",
                    entry.seq_num
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
            verified_refusals += 1;
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
            &verifying_key,
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

    for att in &archive.override_attestations {
        let ev = evidence_by_seq.get(&att.evidence_seq_num).ok_or_else(|| {
            format!(
                "override_attestation[id={}] references missing evidence_chain seq_num={}",
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
        verified_evidence_entries: archive.evidence_chain.len(),
        non_default_thresholds,
        resolver_manifest: archive.bundle.resolver_manifest.clone(),
    })
}
