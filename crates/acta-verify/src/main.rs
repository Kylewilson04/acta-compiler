use std::process::ExitCode;

pub use acta_crypto::{
    dump_archive_preimages, verify_and_rebuild_scope_state_offline, verify_export_archive,
    OfflineStateRebuildSummary, VerificationSummary,
};
use acta_types::{
    ExportArchive, StateRebuildArchive, STATE_REBUILD_ARCHIVE_SCHEMA_V1,
    STATE_REBUILD_ARCHIVE_SCHEMA_V2,
};

struct CliArgs {
    archive_path: String,
    expected_pubkey: [u8; 32],
    dump_preimages: bool,
    rebuild_scope: Option<String>,
}

fn parse_cli_args(args: &[String]) -> Result<CliArgs, String> {
    let mut archive_path: Option<String> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut dump_preimages = false;
    let mut rebuild_scope: Option<String> = None;

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
        } else if arg == "--rebuild-scope" {
            i += 1;
            if i >= args.len() {
                return Err("missing scope value after --rebuild-scope".to_string());
            }
            rebuild_scope = Some(args[i].clone());
        } else if let Some(val) = arg.strip_prefix("--rebuild-scope=") {
            rebuild_scope = Some(val.to_string());
        } else if arg == "--dump-preimages" {
            dump_preimages = true;
        } else if arg == "--help" || arg == "-h" {
            return Err(
                "Usage: acta-verify <export_or_rebuild.json> --pubkey <hex> [--rebuild-scope <scope>] [--dump-preimages]".to_string(),
            );
        } else if arg.starts_with('-') {
            return Err(format!("unknown flag: {arg}"));
        } else if archive_path.is_none() {
            archive_path = Some(arg.clone());
        } else {
            return Err(format!("unexpected positional argument: {arg}"));
        }
        i += 1;
    }

    let path = archive_path.ok_or_else(|| {
        "Usage: acta-verify <export_or_rebuild.json> --pubkey <hex> [--rebuild-scope <scope>] [--dump-preimages]".to_string()
    })?;
    let pk_str = pubkey_hex.ok_or_else(|| "missing required --pubkey <hex> flag".to_string())?;
    let pk_raw =
        hex::decode(pk_str.trim()).map_err(|e| format!("invalid --pubkey hex encoding: {e}"))?;
    let pk_arr: [u8; 32] = pk_raw
        .try_into()
        .map_err(|_| "--pubkey must decode to exactly 32 bytes (64 hex chars)".to_string())?;

    Ok(CliArgs {
        archive_path: path,
        expected_pubkey: pk_arr,
        dump_preimages,
        rebuild_scope,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cli = match parse_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("VERIFICATION FAILED: {msg}");
            return ExitCode::from(2);
        }
    };
    let archive_path = cli.archive_path;
    let expected_pubkey = cli.expected_pubkey;
    let dump_preimages = cli.dump_preimages;

    let raw_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("VERIFICATION FAILED: unable to read '{archive_path}': {e}");
            return ExitCode::from(2);
        }
    };

    let peek_val: serde_json::Value = match serde_json::from_slice(&raw_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("VERIFICATION FAILED: malformed JSON: {e}");
            return ExitCode::from(1);
        }
    };

    // Unwrap if user saved the full LedgerStateRebuildResponse JSON (`{"rebuild_proof_archive": {...}}`)
    let inner_rebuild_opt = if matches!(
        peek_val.get("schema_version").and_then(|s| s.as_str()),
        Some(STATE_REBUILD_ARCHIVE_SCHEMA_V1) | Some(STATE_REBUILD_ARCHIVE_SCHEMA_V2)
    ) {
        Some(peek_val.clone())
    } else {
        peek_val.get("rebuild_proof_archive").cloned()
    };

    if cli.rebuild_scope.is_some() || inner_rebuild_opt.is_some() {
        let target_json = inner_rebuild_opt.unwrap_or(peek_val);
        let rebuild_archive: StateRebuildArchive = match serde_json::from_value(target_json) {
            Ok(ra) => ra,
            Err(e) => {
                eprintln!("VERIFICATION FAILED: malformed StateRebuildArchive JSON: {e}");
                return ExitCode::from(1);
            }
        };
        return match verify_and_rebuild_scope_state_offline(
            &rebuild_archive,
            &expected_pubkey,
            cli.rebuild_scope.as_deref(),
        ) {
            Ok(summary) => {
                println!(
                    "REBUILT_VERIFIED tenant={} scope={} up_to_seq={} header_hash={} state_commitment={} intents={} memories={} claims={} superseded_or_retracted={} overrides={} writes={} evidence_entries={} merkle_root={} anchored_tree_size={} witness_anchors={}",
                    summary.tenant_id,
                    summary.scope,
                    summary.verified_up_to_seq,
                    summary.header_hash_hex,
                    summary.reconstructed_state_commitment_hex,
                    summary.reconstructed_active_intents,
                    summary.reconstructed_active_memories,
                    summary.reconstructed_active_claims,
                    summary.reconstructed_superseded_or_retracted_items,
                    summary.reconstructed_active_overrides,
                    summary.write_events_replayed,
                    summary.verified_evidence_entries,
                    summary.merkle_root_hex.as_deref().unwrap_or("none"),
                    summary.anchored_tree_size.unwrap_or(0),
                    summary.verified_witness_anchors,
                );
                if dump_preimages {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&summary).unwrap_or_default()
                    );
                }
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("VERIFICATION FAILED: {reason}");
                ExitCode::from(1)
            }
        };
    }

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
                "VERIFIED tenant={} mode={} bundle_hash={} state_commitment={} objects={} claims={} corroborated_resolutions={} overrides={} writes={} answer_caches={} refusals={} evidence_entries={} merkle_tree_size={} anchored_tree_size={} witness_anchors={} non_default_thresholds={}",
                summary.tenant_id,
                summary.verification_mode,
                summary.bundle_hash_hex,
                summary.state_commitment_hex,
                summary.verified_objects,
                summary.verified_claims,
                summary.verified_corroborated_resolutions,
                summary.verified_overrides,
                summary.verified_writes,
                summary.verified_answer_caches,
                summary.verified_refusals,
                summary.verified_evidence_entries,
                summary.merkle_tree_size.unwrap_or(0),
                summary.anchored_tree_size.unwrap_or(0),
                summary.verified_witness_anchors,
                summary.non_default_thresholds
            );
            if dump_preimages {
                match dump_archive_preimages(&archive) {
                    Ok(preimages) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&preimages).unwrap_or_default()
                        );
                    }
                    Err(e) => {
                        eprintln!("VERIFICATION FAILED: preimage dump error: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
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
        compute_bundle_hash, compute_checkpoint_hash, compute_claim_content_hash,
        compute_claim_group_key, compute_evidence_event_hash_with_meta,
        compute_merkle_consistency_proof, compute_merkle_inclusion_proof,
        compute_merkle_root_from_leaves, compute_object_content_hash, compute_omission_list_hash,
        compute_refusal_metadata_commitment, compute_witness_registration_v2_commitment,
        merkle_leaf_hash, sign_checkpoint_head, sign_evidence_entry, sign_witness_anchor,
    };
    use acta_types::{
        ClaimCandidate, ClaimStatus, ContextBudget, ContextBundle, DisputeReasonCode,
        DisputeRecord, EntryInclusionProof, EvidenceEntry, ExternalWitnessAnchor, KnowledgeClaim,
        LifecycleStatus, MerkleBundleProof, ObjectType, OmissionReason, OmissionRecord,
        OmittedItem, PolicyResultTag, RefusalMetadata, ResolverManifest, SelectedObjectRef,
        SignedTreeHead, StoredObject, WitnessRegistrationSummary, SCHEMA_VERSION,
        WITNESS_REG_DOMAIN_V2,
    };
    use chrono::{SubsecRound, Utc};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use uuid::Uuid;

    fn build_signed_fixture() -> (ExportArchive, [u8; 32]) {
        let host_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let host_pubkey = host_key.verifying_key().to_bytes();
        let witness_key = SigningKey::from_bytes(&[0x77u8; 32]);
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
            client_public_key: None,
            written_by: None,
            evidence_seq_num: None,
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
            client_signature: None,
            client_public_key: None,
            retraction_reason: None,
            written_by: None,
            evidence_seq_num: None,
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
                margin: Some(0.07),
                reason_code: DisputeReasonCode::InsufficientMargin,
                escalation_required: true,
                lapsed_override: None,
            }],
            omission_record: OmissionRecord {
                inline_items: omitted_items,
                total_omitted_count: 1,
                full_excluded_hash,
                has_unresolved_claims: true,
            },
            resolved_facts_omitted: None,
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
            attempted_checkpoint_hash: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
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
            event_domain: Some("acta:evidence_event:v2".to_string()),
            prev_hash: prev_0,
            event_hash: event_1,
            bundle_hash: None,
            state_commitment: Some(rcomm),
            policy_result: PolicyResultTag::Escalate,
            refusal_metadata: Some(rmeta),
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
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
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: event_1,
            event_hash: event_2,
            bundle_hash: Some(bundle_hash),
            state_commitment: Some(bundle.state_commitment),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sig_2,
            created_at: now,
        };

        // Entry 3: witness enrollment (`acta:witness_reg:v2`) + anchor at tree_size=3 bridging bundle at seq 2!
        let wit_pk = witness_key.verifying_key().to_bytes();
        let (wreg_preimage, wreg_comm) = compute_witness_registration_v2_commitment(
            "tenant-verify",
            "rekor-mirror-1",
            &wit_pk,
            "tenant-verify::oauth:alice",
        );
        let event_3 = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            3,
            &event_2,
            None,
            Some(&wreg_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let sig_3 = sign_evidence_entry(&host_key, "tenant-verify", 3, &event_2, &event_3);
        let entry_3 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 3,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: event_2,
            event_hash: event_3,
            bundle_hash: None,
            state_commitment: Some(wreg_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: Some(WitnessRegistrationSummary {
                witness_id: "rekor-mirror-1".to_string(),
                public_key: wit_pk,
                registered_by: "tenant-verify::oauth:alice".to_string(),
                description: Some("Rekor witness".to_string()),
                registration_domain: WITNESS_REG_DOMAIN_V2.to_string(),
                registration_blake3_preimage_hex: hex::encode(&wreg_preimage),
            }),
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sig_3,
            created_at: now,
        };

        let leaves_2 = vec![merkle_leaf_hash(1, &event_1), merkle_leaf_hash(2, &event_2)];
        let merkle_root_2 = compute_merkle_root_from_leaves(&leaves_2);
        let cp_hash_2 = compute_checkpoint_hash(
            "tenant-verify",
            2,
            &event_2,
            &merkle_root_2,
            now.timestamp_micros(),
        );
        let cp_sig_2 = sign_checkpoint_head(&host_key, "tenant-verify", &cp_hash_2);

        let leaves_3 = vec![
            merkle_leaf_hash(1, &event_1),
            merkle_leaf_hash(2, &event_2),
            merkle_leaf_hash(3, &event_3),
        ];
        let merkle_root_3 = compute_merkle_root_from_leaves(&leaves_3);
        let cp_hash_3 = compute_checkpoint_hash(
            "tenant-verify",
            3,
            &event_3,
            &merkle_root_3,
            now.timestamp_micros(),
        );
        let cp_sig_3 = sign_checkpoint_head(&host_key, "tenant-verify", &cp_hash_3);
        let w_sig_3 = sign_witness_anchor(&witness_key, "tenant-verify", 3, &cp_hash_3);
        let anchor_3 = ExternalWitnessAnchor {
            id: Uuid::new_v4(),
            tenant_id: "tenant-verify".to_string(),
            tree_size: 3,
            checkpoint_hash: cp_hash_3,
            witness_id: "rekor-mirror-1".to_string(),
            witness_public_key: wit_pk,
            witness_signature: w_sig_3,
            external_uri: Some("https://witness.ardyn.example/entry/3".to_string()),
            anchored_at: now,
        };

        let path_2: Vec<String> = compute_merkle_inclusion_proof(&leaves_2, 1)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect();
        let cons_2_to_3: Vec<String> = compute_merkle_consistency_proof(&leaves_3, 2, 3)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect();

        let merkle_proof = MerkleBundleProof {
            checkpoint: SignedTreeHead {
                tenant_id: "tenant-verify".to_string(),
                tree_size: 2,
                head_event_hash: event_2,
                merkle_root: merkle_root_2,
                issued_at: now,
                checkpoint_hash: cp_hash_2,
                host_signature: cp_sig_2,
                witness_anchors: vec![],
            },
            bundle_entry_proof: EntryInclusionProof {
                entry: entry_2.clone(),
                audit_path: path_2,
            },
            override_entry_proofs: vec![],
            rotation_entry_proofs: vec![],
            write_entry_proofs: vec![],
            anchored_checkpoint: Some(SignedTreeHead {
                tenant_id: "tenant-verify".to_string(),
                tree_size: 3,
                head_event_hash: event_3,
                merkle_root: merkle_root_3,
                issued_at: now,
                checkpoint_hash: cp_hash_3,
                host_signature: cp_sig_3,
                witness_anchors: vec![anchor_3],
            }),
            consistency_proof_to_anchor: cons_2_to_3,
        };

        let archive = ExportArchive {
            bundle_hash,
            bundle,
            objects: vec![intent],
            claims: vec![claim_a, claim_b],
            override_attestations: vec![],
            evidence_chain: vec![entry_1, entry_2, entry_3],
            merkle_proof: Some(merkle_proof),
            host_public_key: host_pubkey,
        };

        (archive, host_pubkey)
    }

    #[test]
    fn test_valid_export_verifies_full_merkle_and_cross_checkpoint_bridge() {
        let (archive, pubkey) = build_signed_fixture();
        let summary = verify_export_archive(&archive, &pubkey).expect("valid archive must pass");
        assert_eq!(summary.verified_objects, 1);
        assert_eq!(summary.verified_claims, 2);
        assert_eq!(summary.verified_refusals, 1);
        assert_eq!(summary.verified_evidence_entries, 3);
        assert_eq!(summary.verification_mode, "full_chain_and_merkle");
        assert_eq!(summary.merkle_tree_size, Some(2));
        assert_eq!(summary.anchored_tree_size, Some(3));
        assert_eq!(summary.verified_witness_anchors, 1);
        assert!(!summary.non_default_thresholds);

        // Tampered `registered_by` on v2 `witness_reg_summary` must fail offline verification!
        let mut bad_reg = archive.clone();
        bad_reg.evidence_chain[2]
            .witness_reg_summary
            .as_mut()
            .unwrap()
            .registered_by = "tenant-verify::session".to_string();
        let reg_err = verify_export_archive(&bad_reg, &pubkey).unwrap_err();
        assert!(reg_err.contains("witness_reg_summary"), "got: {reg_err}");

        // Verify compact `merkle_proof`-only ExportArchive (`evidence_chain = []`) with `2 -> 3` bridge!
        let mut compact = archive.clone();
        compact.evidence_chain.clear();
        let c_sum = verify_export_archive(&compact, &pubkey).expect("merkle-only archive must pass");
        assert_eq!(c_sum.verification_mode, "merkle_inclusion");
        assert_eq!(c_sum.verified_evidence_entries, 1);
        assert_eq!(c_sum.merkle_tree_size, Some(2));
        assert_eq!(c_sum.anchored_tree_size, Some(3));
        assert_eq!(c_sum.verified_witness_anchors, 1);

        let dumped = dump_archive_preimages(&compact).unwrap();
        assert_eq!(dumped["checkpoint"]["tree_size"], json!(2));
        assert_eq!(dumped["anchored_checkpoint"]["tree_size"], json!(3));

        // Tampered consistency_proof_to_anchor must fail!
        let mut bad_cons = compact.clone();
        bad_cons
            .merkle_proof
            .as_mut()
            .unwrap()
            .consistency_proof_to_anchor[0] = "00".repeat(32);
        let cons_err = verify_export_archive(&bad_cons, &pubkey).unwrap_err();
        assert!(cons_err.contains("consistency_proof_to_anchor"), "got: {cons_err}");

        // Tampered witness signature on anchored_checkpoint must fail!
        let mut bad_witness = compact;
        bad_witness
            .merkle_proof
            .as_mut()
            .unwrap()
            .anchored_checkpoint
            .as_mut()
            .unwrap()
            .witness_anchors[0]
            .witness_signature[0] ^= 0xFF;
        let w_err = verify_export_archive(&bad_witness, &pubkey).unwrap_err();
        assert!(w_err.contains("witness_signature"));
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
            err_strip.contains("tampered"),
            "stripping refusal_metadata must fail verification, got: {err_strip}"
        );
    }

    #[test]
    fn test_forged_evidence_signature_or_broken_chain_fails() {
        let (mut archive, pubkey) = build_signed_fixture();
        archive.evidence_chain[1].host_signature[0] ^= 0xFF;
        let err = verify_export_archive(&archive, &pubkey).unwrap_err();
        assert!(err.contains("host_signature verification failed"));
    }

    #[test]
    fn test_v163_override_v2_auth_kind_null_client_sig_reg_v3_and_revocation() {
        use acta_crypto::{
            compute_logical_claim_group_key, compute_override_attestation_hash,
            compute_witness_registration_v3_commitment, compute_witness_revocation_commitment,
            sign_override_attestation, OverrideHashInput,
        };
        use acta_types::{
            OverriddenClaimRef, OverrideAttestation, OverrideLedgerSummary, OverrideResolutionRef,
            ResolutionRecord, WitnessRevocationSummary, OVERRIDE_DOMAIN_V2, WITNESS_REG_DOMAIN_V3,
            WITNESS_REVOKE_DOMAIN_V1,
        };

        let host_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let pubkey = host_key.verifying_key().to_bytes();
        let wit_key = SigningKey::from_bytes(&[0x88u8; 32]);
        let wit_pk = wit_key.verifying_key().to_bytes();
        let now = Utc::now().trunc_subsecs(6);

        let lkey = compute_logical_claim_group_key("tenant-verify", "api:gateway", "timeout_ms", "prod");
        let mut claim_a = KnowledgeClaim {
            id: Uuid::new_v4(),
            tenant_id: "tenant-verify".to_string(),
            claim_group_key: lkey,
            scope: "prod".to_string(),
            subject: "api:gateway".to_string(),
            predicate: "timeout_ms".to_string(),
            object_val: json!(500),
            object_type: "int".to_string(),
            confidence: 0.82,
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
            client_signature: None,
            client_public_key: None,
            retraction_reason: None,
            written_by: None,
            evidence_seq_num: None,
            created_at: now,
        };
        claim_a.content_hash = compute_claim_content_hash(&claim_a).unwrap();

        let mut claim_b = claim_a.clone();
        claim_b.id = Uuid::new_v4();
        claim_b.object_val = json!(1500);
        claim_b.confidence = 0.75;
        claim_b.source_descriptor = "msa-cfg".to_string();
        claim_b.content_hash = compute_claim_content_hash(&claim_b).unwrap();

        let att_id = Uuid::new_v4();
        let overridden = vec![OverriddenClaimRef {
            id: claim_a.id,
            content_hash: claim_a.content_hash,
        }];
        let att_hash = compute_override_attestation_hash(&OverrideHashInput {
            attestation_domain: OVERRIDE_DOMAIN_V2,
            id: att_id,
            tenant_id: "tenant-verify",
            scope: "prod",
            claim_group_key: &lkey,
            subject: "api:gateway",
            predicate: "timeout_ms",
            source_bundle_hash: None,
            winning_claim_id: claim_b.id,
            winning_claim_content_hash: &claim_b.content_hash,
            overridden_claims: &overridden,
            adjudicator_id: "tenant-verify::oauth:kylewilson04",
            adjudicator_auth_kind: "oauth_github_principal",
            justification: "Executed MSA governs",
            version: 1,
            predecessor_id: None,
            created_at: now,
            client_public_key: None,
            client_signature: None,
        })
        .unwrap();
        let att_sig = sign_override_attestation(&host_key, "tenant-verify", 1, &att_hash);
        let att = OverrideAttestation {
            id: att_id,
            tenant_id: "tenant-verify".to_string(),
            scope: "prod".to_string(),
            claim_group_key: lkey,
            subject: "api:gateway".to_string(),
            predicate: "timeout_ms".to_string(),
            source_bundle_hash: None,
            winning_claim_id: claim_b.id,
            winning_claim_content_hash: claim_b.content_hash,
            overridden_claims: overridden,
            adjudicator_id: "tenant-verify::oauth:kylewilson04".to_string(),
            adjudicator_auth_kind: "oauth_github_principal".to_string(),
            justification: "Executed MSA governs".to_string(),
            version: 1,
            predecessor_id: None,
            created_at: now,
            attestation_domain: OVERRIDE_DOMAIN_V2.to_string(),
            attestation_hash: att_hash,
            evidence_seq_num: 1,
            host_signature: att_sig,
            client_signature: None,
            client_public_key: None,
        };

        let ov_sum = OverrideLedgerSummary {
            attestation_id: att_id,
            scope: "prod".to_string(),
            subject: "api:gateway".to_string(),
            predicate: "timeout_ms".to_string(),
            winning_claim_id: claim_b.id,
            overridden_count: 1,
            adjudicator_id: att.adjudicator_id.clone(),
            version: 1,
        };
        let ev1_hash = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            1,
            &[0u8; 32],
            None,
            Some(&att_hash),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            Some(&ov_sum),
        )
        .unwrap();
        let ev1 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 1,
            event_domain: Some("acta:evidence_event:v2".to_string()),
            prev_hash: [0u8; 32],
            event_hash: ev1_hash,
            bundle_hash: None,
            state_commitment: Some(att_hash),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: Some(ov_sum),
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-verify", 1, &[0u8; 32], &ev1_hash),
            created_at: now,
        };

        // Seq 2: witness_reg:v3 (description-bound)
        let (reg3_pre, reg3_comm) = compute_witness_registration_v3_commitment(
            "tenant-verify",
            "wit-v3",
            &wit_pk,
            "tenant-verify::oauth:kylewilson04",
            Some("Bound Description v3"),
        );
        let ev2_hash = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            2,
            &ev1_hash,
            None,
            Some(&reg3_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let ev2 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 2,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: ev1_hash,
            event_hash: ev2_hash,
            bundle_hash: None,
            state_commitment: Some(reg3_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: Some(WitnessRegistrationSummary {
                witness_id: "wit-v3".to_string(),
                public_key: wit_pk,
                registered_by: "tenant-verify::oauth:kylewilson04".to_string(),
                description: Some("Bound Description v3".to_string()),
                registration_domain: WITNESS_REG_DOMAIN_V3.to_string(),
                registration_blake3_preimage_hex: hex::encode(&reg3_pre),
            }),
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-verify", 2, &ev1_hash, &ev2_hash),
            created_at: now,
        };

        // Seq 3: witness_revoke:v1
        let (rev_pre, rev_comm) = compute_witness_revocation_commitment(
            "tenant-verify",
            "wit-v3",
            &wit_pk,
            "tenant-verify::oauth:kylewilson04",
            "Rotated key",
        );
        let ev3_hash = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            3,
            &ev2_hash,
            None,
            Some(&rev_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let ev3 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 3,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: ev2_hash,
            event_hash: ev3_hash,
            bundle_hash: None,
            state_commitment: Some(rev_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: Some(WitnessRevocationSummary {
                witness_id: "wit-v3".to_string(),
                public_key: wit_pk,
                revoked_by: "tenant-verify::oauth:kylewilson04".to_string(),
                revocation_mode: "compromise".to_string(),
                effective_from_tree_size: None,
                reason: "Rotated key".to_string(),
                revocation_domain: WITNESS_REVOKE_DOMAIN_V1.to_string(),
                revocation_blake3_preimage_hex: hex::encode(&rev_pre),
            }),
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-verify", 3, &ev2_hash, &ev3_hash),
            created_at: now,
        };

        // Seq 4: resolved bundle
        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: "tenant-verify".to_string(),
            task_id: "task-v163".to_string(),
            scope: "prod".to_string(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            resolver_manifest: None,
            selected_objects: vec![],
            resolution_records: vec![ResolutionRecord {
                claim_group_key: lkey,
                winning_claim: ClaimCandidate::from(&claim_b),
                margin: Some(-0.07),
                suppressed_claim_ids: vec![claim_a.id],
                override_attestation: Some(OverrideResolutionRef::from(&att)),
            }],
            dispute_records: vec![],
            omission_record: OmissionRecord {
                inline_items: vec![],
                total_omitted_count: 0,
                full_excluded_hash: compute_omission_list_hash(&[]).unwrap(),
                has_unresolved_claims: false,
            },
            resolved_facts_omitted: None,
            state_commitment: [0x99; 32],
            dependency_commitment: [0x88; 32],
            issued_at: now,
        };
        let (bundle_hash, _) = compute_bundle_hash(&bundle).unwrap();
        let ev4_hash = compute_evidence_event_hash_with_meta(
            "tenant-verify",
            4,
            &ev3_hash,
            Some(&bundle_hash),
            Some(&bundle.state_commitment),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let ev4 = EvidenceEntry {
            tenant_id: "tenant-verify".to_string(),
            seq_num: 4,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: ev3_hash,
            event_hash: ev4_hash,
            bundle_hash: Some(bundle_hash),
            state_commitment: Some(bundle.state_commitment),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-verify", 4, &ev3_hash, &ev4_hash),
            created_at: now,
        };

        let archive = ExportArchive {
            bundle_hash,
            bundle,
            objects: vec![],
            claims: vec![claim_a, claim_b],
            override_attestations: vec![att],
            evidence_chain: vec![ev1, ev2, ev3, ev4],
            merkle_proof: None,
            host_public_key: pubkey,
        };

        let sum = verify_export_archive(&archive, &pubkey).expect("v1.6.3 archive must verify");
        assert_eq!(sum.verified_overrides, 1);
        assert_eq!(sum.verified_evidence_entries, 4);

        // Dump preimages must NOT emit stray client_sig_* digests on unsigned override!
        let dumped = dump_archive_preimages(&archive).unwrap();
        let ov_dump = &dumped["override_attestations"][0];
        assert_eq!(ov_dump["attestation_domain"], json!("acta:override:v2"));
        assert_eq!(ov_dump["adjudicator_auth_kind"], json!("oauth_github_principal"));
        assert!(ov_dump["client_sig_domain"].is_null());
        assert!(ov_dump["client_sig_blake3_preimage_hex"].is_null());
        assert!(ov_dump["client_sig_digest_hex"].is_null());
        assert_eq!(
            dumped["evidence_entries"][2]["witness_revocation"]["revocation_domain"],
            json!("acta:witness_revoke:v1")
        );

        // Tampering adjudicator_auth_kind on v2 override MUST fail verification!
        let mut bad_auth = archive.clone();
        bad_auth.override_attestations[0].adjudicator_auth_kind = "tenant_session".to_string();
        assert!(verify_export_archive(&bad_auth, &pubkey).is_err());

        // Tampering description on v3 witness registration MUST fail verification!
        let mut bad_desc = archive.clone();
        bad_desc.evidence_chain[1]
            .witness_reg_summary
            .as_mut()
            .unwrap()
            .description = Some("Tampered Description".to_string());
        assert!(verify_export_archive(&bad_desc, &pubkey).is_err());

        // Tampering reason on witness revocation MUST fail verification!
        let mut bad_rev = archive;
        bad_rev.evidence_chain[2]
            .witness_revoke_summary
            .as_mut()
            .unwrap()
            .reason = "Forged reason".to_string();
        assert!(verify_export_archive(&bad_rev, &pubkey).is_err());
    }

    #[test]
    fn test_v164_witness_retirement_v2_and_direct_anchor_summary() {
        use acta_crypto::compute_witness_revocation_v2_commitment;
        use acta_types::{WitnessRevocationSummary, WITNESS_REVOKE_DOMAIN_V2};

        let host_key = SigningKey::from_bytes(&[0x51; 32]);
        let pubkey = host_key.verifying_key().to_bytes();
        let wit_key = SigningKey::from_bytes(&[0x52; 32]);
        let wit_pk = wit_key.verifying_key().to_bytes();
        let now = Utc::now().trunc_subsecs(6);

        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: "tenant-v164".to_string(),
            task_id: "task-v164".to_string(),
            scope: "acta-test/v164".to_string(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            resolver_manifest: None,
            selected_objects: vec![],
            resolution_records: vec![],
            dispute_records: vec![],
            omission_record: OmissionRecord {
                inline_items: vec![],
                total_omitted_count: 0,
                full_excluded_hash: compute_omission_list_hash(&[]).unwrap(),
                has_unresolved_claims: false,
            },
            resolved_facts_omitted: None,
            state_commitment: [0x11; 32],
            dependency_commitment: [0x22; 32],
            issued_at: now,
        };
        let (bundle_hash, _) = compute_bundle_hash(&bundle).unwrap();

        let ev1_hash = compute_evidence_event_hash_with_meta(
            "tenant-v164",
            1,
            &[0u8; 32],
            Some(&bundle_hash),
            Some(&bundle.state_commitment),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let ev1 = EvidenceEntry {
            tenant_id: "tenant-v164".to_string(),
            seq_num: 1,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: [0u8; 32],
            event_hash: ev1_hash,
            bundle_hash: Some(bundle_hash),
            state_commitment: Some(bundle.state_commitment),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-v164", 1, &[0u8; 32], &ev1_hash),
            created_at: now,
        };

        let (ret_pre, ret_comm) = compute_witness_revocation_v2_commitment(
            "tenant-v164",
            "wit-retire-v164",
            &wit_pk,
            "tenant-v164::oauth:kylewilson04",
            "retire",
            Some(2),
            "Planned key rotation after anchoring seq 1",
        )
        .unwrap();
        let ev2_hash = compute_evidence_event_hash_with_meta(
            "tenant-v164",
            2,
            &ev1_hash,
            None,
            Some(&ret_comm),
            PolicyResultTag::Allow,
            now.timestamp_micros(),
            None,
            None,
        )
        .unwrap();
        let ev2 = EvidenceEntry {
            tenant_id: "tenant-v164".to_string(),
            seq_num: 2,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: ev1_hash,
            event_hash: ev2_hash,
            bundle_hash: None,
            state_commitment: Some(ret_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: Some(WitnessRevocationSummary {
                witness_id: "wit-retire-v164".to_string(),
                public_key: wit_pk,
                revoked_by: "tenant-v164::oauth:kylewilson04".to_string(),
                revocation_mode: "retire".to_string(),
                effective_from_tree_size: Some(2),
                reason: "Planned key rotation after anchoring seq 1".to_string(),
                revocation_domain: WITNESS_REVOKE_DOMAIN_V2.to_string(),
                revocation_blake3_preimage_hex: hex::encode(&ret_pre),
            }),
            host_key_rotation_summary: None,
            host_signature: sign_evidence_entry(&host_key, "tenant-v164", 2, &ev1_hash, &ev2_hash),
            created_at: now,
        };

        let leaf1 = merkle_leaf_hash(1, &ev1_hash);
        let root1 = compute_merkle_root_from_leaves(&[leaf1]);
        let cp1_hash = compute_checkpoint_hash(
            "tenant-v164",
            1,
            &ev1_hash,
            &root1,
            now.timestamp_micros(),
        );
        let cp1 = SignedTreeHead {
            tenant_id: "tenant-v164".to_string(),
            tree_size: 1,
            head_event_hash: ev1_hash,
            merkle_root: root1,
            issued_at: now,
            checkpoint_hash: cp1_hash,
            host_signature: sign_checkpoint_head(&host_key, "tenant-v164", &cp1_hash),
            witness_anchors: vec![ExternalWitnessAnchor {
                id: Uuid::new_v4(),
                tenant_id: "tenant-v164".to_string(),
                tree_size: 1,
                checkpoint_hash: cp1_hash,
                witness_id: "wit-retire-v164".to_string(),
                witness_public_key: wit_pk,
                witness_signature: sign_witness_anchor(&wit_key, "tenant-v164", 1, &cp1_hash),
                external_uri: None,
                anchored_at: now,
            }],
        };

        let archive = ExportArchive {
            bundle_hash,
            bundle,
            objects: vec![],
            claims: vec![],
            override_attestations: vec![],
            evidence_chain: vec![ev1.clone(), ev2],
            merkle_proof: Some(MerkleBundleProof {
                checkpoint: cp1,
                bundle_entry_proof: EntryInclusionProof {
                    entry: ev1,
                    audit_path: vec![],
                },
                override_entry_proofs: vec![],
            rotation_entry_proofs: vec![],
            write_entry_proofs: vec![],
                anchored_checkpoint: None,
                consistency_proof_to_anchor: vec![],
            }),
            host_public_key: pubkey,
        };

        let summary = verify_export_archive(&archive, &pubkey).expect("v1.6.4 archive must verify");
        assert_eq!(summary.merkle_tree_size, Some(1));
        assert_eq!(summary.anchored_tree_size, Some(1));
        assert_eq!(summary.verified_witness_anchors, 1);

        let dumped = dump_archive_preimages(&archive).unwrap();
        assert_eq!(
            dumped["evidence_entries"][1]["witness_revocation"]["revocation_domain"],
            json!("acta:witness_revoke:v2")
        );
        assert_eq!(
            dumped["evidence_entries"][1]["witness_revocation"]["revocation_mode"],
            json!("retire")
        );
        assert_eq!(
            dumped["evidence_entries"][1]["witness_revocation"]["effective_from_tree_size"],
            json!(2)
        );

        let mut tampered_mode = archive.clone();
        tampered_mode.evidence_chain[1]
            .witness_revoke_summary
            .as_mut()
            .unwrap()
            .revocation_mode = "compromise".to_string();
        assert!(verify_export_archive(&tampered_mode, &pubkey).is_err());

        let mut tampered_eff = archive;
        tampered_eff.evidence_chain[1]
            .witness_revoke_summary
            .as_mut()
            .unwrap()
            .effective_from_tree_size = Some(99);
        assert!(verify_export_archive(&tampered_eff, &pubkey).is_err());
    }
}
