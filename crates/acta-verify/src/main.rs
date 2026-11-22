use std::process::ExitCode;

pub use acta_crypto::{verify_export_archive, VerificationSummary};
use acta_types::ExportArchive;

fn parse_cli_args(args: &[String]) -> Result<(String, [u8; 32]), String> {
    let mut archive_path: Option<String> = None;
    let mut pubkey_hex: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--pubkey" {
            i += 1;
            if i >= args.len() {
                return Err("missing hex value after --pubkey".to_string());
            }
            pubkey_hex = Some(args[i].clone());
        } else if let Some(val) = arg.strip_prefix("--pubkey=") {
            pubkey_hex = Some(val.to_string());
        } else if arg == "--help" || arg == "-h" {
            return Err("Usage: acta-verify <export.json> --pubkey <hex>".to_string());
        } else if arg.starts_with('-') {
            return Err(format!("unknown flag: {arg}"));
        } else if archive_path.is_none() {
            archive_path = Some(arg.clone());
        } else {
            return Err(format!("unexpected positional argument: {arg}"));
        }
        i += 1;
    }

    let path = archive_path
        .ok_or_else(|| "Usage: acta-verify <export.json> --pubkey <hex>".to_string())?;
    let pk_str = pubkey_hex.ok_or_else(|| "missing required --pubkey <hex> flag".to_string())?;
    let pk_raw =
        hex::decode(pk_str.trim()).map_err(|e| format!("invalid --pubkey hex encoding: {e}"))?;
    let pk_arr: [u8; 32] = pk_raw
        .try_into()
        .map_err(|_| "--pubkey must decode to exactly 32 bytes (64 hex chars)".to_string())?;

    Ok((path, pk_arr))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (archive_path, expected_pubkey) = match parse_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("VERIFICATION FAILED: {msg}");
            return ExitCode::from(2);
        }
    };

    let raw_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("VERIFICATION FAILED: unable to read '{archive_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let archive: ExportArchive = match serde_json::from_slice(&raw_bytes) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("VERIFICATION FAILED: malformed ExportArchive JSON: {e}");
            return ExitCode::from(1);
        }
    };

    match verify_export_archive(&archive, &expected_pubkey) {
        Ok(summary) => {
            println!(
                "VERIFIED tenant={} bundle_hash={} state_commitment={} objects={} claims={} overrides={} refusals={} evidence_entries={} non_default_thresholds={}",
                summary.tenant_id,
                summary.bundle_hash_hex,
                summary.state_commitment_hex,
                summary.verified_objects,
                summary.verified_claims,
                summary.verified_overrides,
                summary.verified_refusals,
                summary.verified_evidence_entries,
                summary.non_default_thresholds
            );
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("VERIFICATION FAILED: {reason}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acta_crypto::{
        compute_bundle_hash, compute_claim_content_hash, compute_claim_group_key,
        compute_evidence_event_hash_with_meta, compute_object_content_hash,
        compute_omission_list_hash, compute_refusal_metadata_commitment, sign_evidence_entry,
    };
    use acta_types::{
        ClaimCandidate, ClaimStatus, ContextBudget, ContextBundle, DisputeReasonCode,
        DisputeRecord, EvidenceEntry, KnowledgeClaim, LifecycleStatus, ObjectType, OmissionReason,
        OmissionRecord, OmittedItem, PolicyResultTag, RefusalMetadata, ResolverManifest,
        SelectedObjectRef, StoredObject, SCHEMA_VERSION,
    };
    use chrono::{SubsecRound, Utc};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use uuid::Uuid;

    fn build_signed_fixture() -> (ExportArchive, [u8; 32]) {
        let host_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let host_pubkey = host_key.verifying_key().to_bytes();
        let now = Utc::now().trunc_subsecs(6);

        let mut intent = StoredObject {
            id: Uuid::new_v4(),
            tenant_id: "tenant-verify".to_string(),
            obj_type: ObjectType::Intent,
            scope: "prod".to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority: 10,
            importance: 1.0,
            tags: vec!["audit".to_string()],
            body: json!({"rule": "enforce strict verification"}),
            content_hash: [0u8; 32],
            embedding: None,
            version: 1,
            predecessor_id: None,
            client_signature: None,
            created_at: now,
        };
        intent.content_hash = compute_object_content_hash(&intent).unwrap();

        let group_key =
            compute_claim_group_key("tenant-verify", "api:gateway", "timeout_ms", "int", "prod");
        let mut claim_a = KnowledgeClaim {
            id: Uuid::new_v4(),
            tenant_id: "tenant-verify".to_string(),
            claim_group_key: group_key,
            scope: "prod".to_string(),
            subject: "api:gateway".to_string(),
            predicate: "timeout_ms".to_string(),
            object_val: json!(500),
            object_type: "int".to_string(),
            confidence: 0.81,
            source_provenance_class: 2,
            source_descriptor: "envoy-cfg".to_string(),
            source_commitment: [0x11; 32],
            content_hash: [0u8; 32],
            status: ClaimStatus::Active,
            contradiction_ids: vec![],
            valid_from: None,
            valid_to: None,
            version: 1,
            predecessor_id: None,
            created_at: now,
        };
        claim_a.content_hash = compute_claim_content_hash(&claim_a).unwrap();

        let mut claim_b = claim_a.clone();
        claim_b.id = Uuid::new_v4();
        claim_b.object_val = json!(1500);
        claim_b.confidence = 0.74;
        claim_b.source_descriptor = "terraform-vars".to_string();
        claim_b.content_hash = compute_claim_content_hash(&claim_b).unwrap();

        let omitted_items = vec![OmittedItem {
            id: Uuid::new_v4(),
            reason: OmissionReason::BudgetExceeded,
        }];
        let full_excluded_hash = compute_omission_list_hash(&omitted_items).unwrap();

        let manifest = ResolverManifest::new(
            0.70,
            0.15,
            0.50,
            ContextBudget::Tokens(2048),
            [0xCC; 32],
        );

        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: "tenant-verify".to_string(),
            task_id: "task-verify-1".to_string(),
            scope: "prod".to_string(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            resolver_manifest: Some(manifest),
            selected_objects: vec![SelectedObjectRef::from(&intent)],
            resolution_records: vec![],
            dispute_records: vec![DisputeRecord {
                claim_group_key: group_key,
                competing_claims: vec![
                    ClaimCandidate::from(&claim_a),
                    ClaimCandidate::from(&claim_b),
                ],
                reason_code: DisputeReasonCode::InsufficientMargin,
                escalation_required: true,
            }],
            omission_record: OmissionRecord {
                inline_items: omitted_items,
                total_omitted_count: 1,
                full_excluded_hash,
                has_unresolved_claims: true,
            },
            state_commitment: [0xAA; 32],
            dependency_commitment: [0xBB; 32],
            issued_at: now,
        };

        let (bundle_hash, _) = compute_bundle_hash(&bundle).unwrap();

        let prev_0 = [0u8; 32];
        let rmeta = RefusalMetadata {
            operation: "ingest_claim".to_string(),
            reason_code: "ingest_policy_escalate".to_string(),
            target_scope: Some("restricted/keys".to_string()),
            summary: "policy escalation required on ingest to restricted scope".to_string(),
            scope_state_commitment: None,
        };
        let rcomm = compute_refusal_metadata_commitment(&rmeta).unwrap();
        let event_1 = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            1,
            &prev_0,
            None,
            Some(&rcomm),
            PolicyResultTag::Escalate,
            now.timestamp_micros(),
            Some(&rmeta),
            None,
        )
        .unwrap();
        let sig_1 = sign_evidence_entry(&host_key, "tenant-verify", 1, &prev_0, &event_1);
        let entry_1 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 1,
            prev_hash: prev_0,
            event_hash: event_1,
            bundle_hash: None,
            state_commitment: Some(rcomm),
            policy_result: PolicyResultTag::Escalate,
            refusal_metadata: Some(rmeta),
            override_summary: None,
            host_signature: sig_1,
            created_at: now,
        };

        let event_2 = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            2,
            &event_1,
            Some(&bundle_hash),
            Some(&bundle.state_commitment),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let sig_2 = sign_evidence_entry(&host_key, "tenant-verify", 2, &event_1, &event_2);
        let entry_2 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 2,
            prev_hash: event_1,
            event_hash: event_2,
            bundle_hash: Some(bundle_hash),
            state_commitment: Some(bundle.state_commitment),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            host_signature: sig_2,
            created_at: now,
        };

        let archive = ExportArchive {
            bundle_hash,
            bundle,
            objects: vec![intent],
            claims: vec![claim_a, claim_b],
            override_attestations: vec![],
            evidence_chain: vec![entry_1, entry_2],
            host_public_key: host_pubkey,
        };

        (archive, host_pubkey)
    }

    #[test]
    fn test_valid_export_verifies_cleanly() {
        let (archive, pubkey) = build_signed_fixture();
        let summary = verify_export_archive(&archive, &pubkey).expect("valid archive must pass");
        assert_eq!(summary.verified_objects, 1);
        assert_eq!(summary.verified_claims, 2);
        assert_eq!(summary.verified_refusals, 1);
        assert_eq!(summary.verified_evidence_entries, 2);
        assert!(!summary.non_default_thresholds);
    }

    #[test]
    fn test_tampered_claim_body_fails_and_flags_claim() {
        let (mut archive, pubkey) = build_signed_fixture();
        archive.claims[0].object_val = json!(501);
        let err = verify_export_archive(&archive, &pubkey).unwrap_err();
        assert!(
            err.contains("tampered claim"),
            "expected tampered claim error, got: {err}"
        );
    }

    #[test]
    fn test_tampered_resolver_manifest_threshold_or_stripped_refusal_metadata_fails() {
        let (mut archive, pubkey) = build_signed_fixture();
        archive
            .bundle
            .resolver_manifest
            .as_mut()
            .unwrap()
            .decisiveness_threshold = 0.05;
        archive
            .bundle
            .resolver_manifest
            .as_mut()
            .unwrap()
            .non_default_thresholds = true;
        let err_manifest = verify_export_archive(&archive, &pubkey).unwrap_err();
        assert!(
            err_manifest.contains("tampered ContextBundle"),
            "got: {err_manifest}"
        );

        let (mut archive_2, pubkey_2) = build_signed_fixture();
        archive_2.evidence_chain[0].refusal_metadata = None;
        let err_strip = verify_export_archive(&archive_2, &pubkey_2).unwrap_err();
        assert!(
            err_strip.contains("tampered evidence entry"),
            "stripping refusal_metadata must fail event_hash verification, got: {err_strip}"
        );
    }

    #[test]
    fn test_forged_evidence_signature_or_broken_chain_fails() {
        let (mut archive, pubkey) = build_signed_fixture();
        archive.evidence_chain[1].host_signature[0] ^= 0xFF;
        let err = verify_export_archive(&archive, &pubkey).unwrap_err();
        assert!(err.contains("host_signature verification failed"));
    }
}
