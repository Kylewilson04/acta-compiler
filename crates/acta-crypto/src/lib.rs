pub mod canonical;
pub mod commitment;
pub mod hash;
pub mod merkle;
pub mod signing;
pub mod token;
pub mod verify;

pub use canonical::to_canonical_bytes;
pub use commitment::{
    compute_dependency_commitment, compute_state_commitment, compute_sub_commitment,
};
pub use hash::{
    answer_cache_client_intent_preimage_bytes, bundle_hash_preimage_bytes,
    checkpoint_hash_preimage_bytes, claim_client_intent_preimage_bytes,
    claim_content_preimage_bytes, claim_group_preimage_bytes, claims_share_winning_value_bucket,
    compute_answer_cache_client_intent_hash, compute_answer_cache_summary_commitment,
    compute_answer_text_hash, compute_bundle_hash, compute_checkpoint_hash,
    compute_claim_client_intent_hash, compute_claim_content_hash, compute_claim_group_key,
    compute_evidence_event_hash, compute_evidence_event_hash_full,
    compute_evidence_event_hash_v172, compute_evidence_event_hash_with_meta,
    compute_logical_claim_group_key, compute_object_client_intent_hash,
    compute_object_content_hash, compute_omission_list_hash, compute_override_attestation_hash,
    compute_override_client_intent_hash, compute_query_text_hash,
    compute_rebuild_archive_header_hash, compute_refusal_commitment,
    compute_refusal_metadata_commitment, compute_retract_claim_client_intent_hash,
    compute_source_content_commitment, compute_task_dependency_commitment,
    compute_witness_registration_by_domain, compute_witness_registration_commitment,
    compute_witness_registration_v2_commitment, compute_witness_registration_v3_commitment,
    compute_witness_revocation_by_domain, compute_witness_revocation_commitment,
    compute_witness_revocation_v2_commitment, compute_write_summary_commitment,
    encode_length_delimited, evidence_event_preimage_bytes, evidence_event_preimage_bytes_full,
    evidence_event_preimage_bytes_v172, hash_length_delimited, object_client_intent_preimage_bytes,
    object_content_preimage_bytes, override_attestation_preimage_bytes,
    override_client_intent_preimage_bytes, rebuild_archive_header_preimage_bytes,
    recompute_winning_bucket_corroboration, retract_claim_client_intent_preimage_bytes,
    witness_registration_preimage_bytes, witness_revocation_preimage_bytes, OverrideHashInput,
};
pub use merkle::{
    compute_legacy_blake3_merkle_root_from_events, compute_legacy_blake3_merkle_root_from_leaves,
    compute_merkle_consistency_proof, compute_merkle_inclusion_proof,
    compute_merkle_root_from_leaves, legacy_blake3_merkle_empty_root,
    legacy_blake3_merkle_leaf_hash, legacy_blake3_merkle_node_hash, merkle_empty_root,
    merkle_leaf_hash, merkle_leaf_preimage_bytes, merkle_node_hash,
    verify_merkle_consistency_proof, verify_merkle_inclusion_proof,
};
pub use signing::{
    answer_cache_signing_preimage, answer_cache_signing_preimage_bytes,
    checkpoint_signing_preimage, checkpoint_signing_preimage_bytes, evidence_signing_preimage,
    evidence_signing_preimage_bytes, override_signing_preimage, override_signing_preimage_bytes,
    rebuild_header_signing_preimage, rebuild_header_signing_preimage_bytes,
    sign_answer_cache_receipt, sign_checkpoint_head, sign_evidence_entry,
    sign_override_attestation, sign_rebuild_archive_header, sign_witness_anchor,
    verify_answer_cache_signature, verify_checkpoint_signature, verify_client_content_signature,
    verify_evidence_signature, verify_override_signature, verify_rebuild_archive_header_signature,
    verify_witness_anchor_signature, witness_anchor_signing_preimage,
    witness_anchor_signing_preimage_bytes,
};
pub use token::{
    compute_pkce_s256, derive_oauth_envelope_key, derive_tenant_mac_key, mint_signed_envelope,
    mint_tenant_api_key, mint_user_tenant_api_key, normalize_github_slug, verify_pkce_s256,
    verify_signed_envelope, verify_tenant_api_key, verify_tenant_api_key_with_principal,
    TENANT_TOKEN_PREFIX,
};
pub use verify::{
    dump_archive_preimages, verify_and_rebuild_scope_state_offline, verify_export_archive,
    verify_signed_tree_head, verify_single_evidence_entry_public, OfflineStateRebuildSummary,
    VerificationSummary,
};

#[cfg(test)]
mod tests {
    use super::*;
    use acta_types::{
        AnswerCacheLedgerSummary, ClaimCandidate, ClaimStatus, ContextBudget, ContextBundle,
        EvidenceEntry, ExportArchive, KnowledgeClaim, LifecycleStatus, ObjectType, OmissionReason,
        OmissionRecord, OmittedItem, PolicyResultTag, RefusalMetadata, ResolutionRecord,
        ResolverManifest, StateRebuildArchive, StoredObject, WitnessRegistrationSummary,
        WriteLedgerSummary, WriteOperationKind, ANSWER_CACHE_DOMAIN_V1, OVERRIDE_DOMAIN_V2,
        SCHEMA_VERSION, STATE_REBUILD_ARCHIVE_SCHEMA_V1, WITNESS_REG_DOMAIN_V3,
        WRITE_EVENT_DOMAIN_V1,
    };
    use chrono::{Duration, TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use uuid::Uuid;

    #[test]
    fn test_canonical_json_key_order_invariance() {
        let json_a: Value = serde_json::from_str(
            r#"{"zeta": 100, "alpha": {"b": true, "a": [3, 2, 1]}, "meta": "ok"}"#,
        )
        .unwrap();
        let json_b: Value = serde_json::from_str(
            r#"{"alpha": {"a": [3, 2, 1], "b": true}, "meta": "ok", "zeta": 100}"#,
        )
        .unwrap();

        let bytes_a = to_canonical_bytes(&json_a).unwrap();
        let bytes_b = to_canonical_bytes(&json_b).unwrap();
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(
            std::str::from_utf8(&bytes_a).unwrap(),
            r#"{"alpha":{"a":[3,2,1],"b":true},"meta":"ok","zeta":100}"#
        );

        let hash_a = hash_length_delimited(&[&bytes_a]);
        let hash_b = hash_length_delimited(&[&bytes_b]);
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_spec_2_5_empty_sub_commitment_and_state_layout() {
        // SPEC.md §2.5: empty sub-commitment has 0 slices -> BLAKE3(b"")
        let empty = compute_sub_commitment(&[]);
        assert_eq!(
            hex::encode(empty),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        let h1 = [0x11; 32];
        let h2 = [0x22; 32];
        assert_eq!(
            compute_sub_commitment(&[h2, h1]),
            hash_length_delimited(&[&h1, &h2])
        );
        let perm = [0x33; 32];
        assert_eq!(
            compute_state_commitment(SCHEMA_VERSION, "t", "s", &h1, &h2, &empty, &perm),
            hash_length_delimited(&[
                SCHEMA_VERSION.as_bytes(),
                b"t",
                b"s",
                &h1,
                &h2,
                &empty,
                &perm
            ])
        );
    }

    #[test]
    fn test_omission_list_hash_matches_jcs_reference() {
        let items = vec![
            OmittedItem {
                id: Uuid::from_bytes([0x01; 16]),
                reason: OmissionReason::BudgetExceeded,
            },
            OmittedItem {
                id: Uuid::from_bytes([0xAB; 16]),
                reason: OmissionReason::OutOfScope,
            },
            OmittedItem {
                id: Uuid::from_bytes([0xCD; 16]),
                reason: OmissionReason::LifecycleExpired,
            },
            OmittedItem {
                id: Uuid::from_bytes([0xEF; 16]),
                reason: OmissionReason::PolicyDenied,
            },
            OmittedItem {
                id: Uuid::from_bytes([0x77; 16]),
                reason: OmissionReason::Superseded,
            },
            OmittedItem {
                id: Uuid::from_bytes([0x99; 16]),
                reason: OmissionReason::DisputedWithheld,
            },
            OmittedItem {
                id: Uuid::from_bytes([0xA1; 16]),
                reason: OmissionReason::Retracted,
            },
            OmittedItem {
                id: Uuid::from_bytes([0xA2; 16]),
                reason: OmissionReason::RetractionTombstone,
            },
        ];

        let fast_hash = compute_omission_list_hash(&items).unwrap();

        let mut encoded_ref: Vec<Vec<u8>> = vec![b"acta:omissions:v1".to_vec()];
        for item in &items {
            encoded_ref.push(to_canonical_bytes(item).unwrap());
        }
        let ref_slices: Vec<&[u8]> = encoded_ref.iter().map(|v| v.as_slice()).collect();
        let expected_hash = hash_length_delimited(&ref_slices);

        assert_eq!(fast_hash, expected_hash);
    }

    #[test]
    fn test_length_delimited_prevents_concatenation_collision() {
        let h1 = hash_length_delimited(&[b"tenant_a", b"b_scope"]);
        let h2 = hash_length_delimited(&[b"tenant_", b"ab_scope"]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sub_commitment_order_independence() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        assert_eq!(
            compute_sub_commitment(&[c, a, b]),
            compute_sub_commitment(&[a, b, c])
        );
    }

    #[test]
    fn test_changing_permission_root_changes_state_commitment() {
        let intent_root = [0x11; 32];
        let knowledge_root = [0x22; 32];
        let memory_root = [0x33; 32];
        let perm_root_v1 = [0x44; 32];
        let mut perm_root_v2 = perm_root_v1;
        perm_root_v2[31] ^= 0x01;

        let sc1 = compute_state_commitment(
            "acta-context-bundle/v1",
            "tenant-1",
            "prod",
            &intent_root,
            &knowledge_root,
            &memory_root,
            &perm_root_v1,
        );
        let sc2 = compute_state_commitment(
            "acta-context-bundle/v1",
            "tenant-1",
            "prod",
            &intent_root,
            &knowledge_root,
            &memory_root,
            &perm_root_v2,
        );
        assert_ne!(sc1, sc2);
    }

    #[test]
    fn test_single_bit_mutation_fails_ed25519_verification() {
        let seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let tenant = "tenant-alpha";
        let seq_num = 7_i64;
        let prev_hash = [0xAAu8; 32];
        let event_hash = [0xBBu8; 32];

        let sig = sign_evidence_entry(&signing_key, tenant, seq_num, &prev_hash, &event_hash);
        assert!(verify_evidence_signature(
            &verifying_key,
            tenant,
            seq_num,
            &prev_hash,
            &event_hash,
            &sig
        ));

        let mut tampered_event_hash = event_hash;
        tampered_event_hash[15] ^= 0x01;
        assert!(!verify_evidence_signature(
            &verifying_key,
            tenant,
            seq_num,
            &prev_hash,
            &tampered_event_hash,
            &sig
        ));
    }

    #[test]
    fn test_live_witness_reg_v1_v2_v3_and_revocation_vectors() {
        let pk_58: [u8; 32] = hex::decode(
            "e5b050185444bd8e1b0892678934c70ff65f896602e9bf0faa87a4702a7ad9e4",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let pre_v1 = witness_registration_preimage_bytes(
            "acta:witness_reg:v1",
            "kylewilson04",
            "claude-witness-v161",
            &pk_58,
            "kylewilson04::session",
            None,
        )
        .unwrap();
        let comm_v1 = *blake3::hash(&pre_v1).as_bytes();
        assert_eq!(
            hex::encode(comm_v1),
            "e28df78841329df7b66aef44558586b81d952d1434a48f6605d0a6431e080fec"
        );
        assert_eq!(
            comm_v1,
            compute_witness_registration_commitment("kylewilson04", "claude-witness-v161", &pk_58)
        );

        let (pre_v2_a, comm_v2_a) = compute_witness_registration_v2_commitment(
            "kylewilson04",
            "claude-witness-v162",
            &pk_58,
            "kylewilson04::oauth:kylewilson04",
        );
        let (_pre_v2_b, comm_v2_b) = compute_witness_registration_v2_commitment(
            "kylewilson04",
            "claude-witness-v162",
            &pk_58,
            "kylewilson04::session",
        );
        assert_ne!(comm_v2_a, comm_v2_b);
        assert_eq!(
            pre_v2_a,
            witness_registration_preimage_bytes(
                "acta:witness_reg:v2",
                "kylewilson04",
                "claude-witness-v162",
                &pk_58,
                "kylewilson04::oauth:kylewilson04",
                Some("ignored in v2"),
            )
            .unwrap()
        );

        let (_pre_v3_a, comm_v3_a) = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            &pk_58,
            "kylewilson04::oauth:kylewilson04",
            Some("Claude v1.6.3 Witness"),
        );
        let (_pre_v3_b, comm_v3_b) = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            &pk_58,
            "kylewilson04::oauth:kylewilson04",
            Some("Tampered Description"),
        );
        let (_pre_v3_none, comm_v3_none) = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            &pk_58,
            "kylewilson04::oauth:kylewilson04",
            None,
        );
        assert_ne!(comm_v3_a, comm_v3_b);
        assert_ne!(comm_v3_a, comm_v3_none);

        let (rev_pre_1, rev_comm_1) = compute_witness_revocation_commitment(
            "kylewilson04",
            "claude-revoke-probe-v163",
            &pk_58,
            "kylewilson04::session",
            "Key rotation",
        );
        let (_rev_pre_2, rev_comm_2) = compute_witness_revocation_commitment(
            "kylewilson04",
            "claude-revoke-probe-v163",
            &pk_58,
            "kylewilson04::session",
            "Different reason",
        );
        assert_ne!(rev_comm_1, rev_comm_2);
        assert_eq!(
            rev_pre_1,
            witness_revocation_preimage_bytes(
                "acta:witness_revoke:v1",
                "kylewilson04",
                "claude-revoke-probe-v163",
                &pk_58,
                "kylewilson04::session",
                "compromise",
                None,
                "Key rotation",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_override_v2_binds_auth_kind_and_client_signature() {
        let now = Utc.with_ymd_and_hms(2026, 11, 22, 23, 30, 0).unwrap();
        let id = Uuid::from_bytes([0x55; 16]);
        let group = [0xAA; 32];
        let win_id = Uuid::from_bytes([0x66; 16]);
        let win_hash = [0xBB; 32];

        let h_session = compute_override_attestation_hash(&OverrideHashInput {
            attestation_domain: OVERRIDE_DOMAIN_V2,
            id,
            tenant_id: "kylewilson04",
            scope: "acta-test/v163-override",
            claim_group_key: &group,
            subject: "contract:epsilon",
            predicate: "fee_bps",
            source_bundle_hash: None,
            winning_claim_id: win_id,
            winning_claim_content_hash: &win_hash,
            overridden_claims: &[],
            adjudicator_id: "kylewilson04::session",
            adjudicator_auth_kind: "tenant_session",
            justification: "Executed MSA governs",
            version: 1,
            predecessor_id: None,
            created_at: now,
            client_public_key: None,
            client_signature: None,
        })
        .unwrap();

        let h_oauth = compute_override_attestation_hash(&OverrideHashInput {
            attestation_domain: OVERRIDE_DOMAIN_V2,
            id,
            tenant_id: "kylewilson04",
            scope: "acta-test/v163-override",
            claim_group_key: &group,
            subject: "contract:epsilon",
            predicate: "fee_bps",
            source_bundle_hash: None,
            winning_claim_id: win_id,
            winning_claim_content_hash: &win_hash,
            overridden_claims: &[],
            adjudicator_id: "kylewilson04::session",
            adjudicator_auth_kind: "oauth_github_principal",
            justification: "Executed MSA governs",
            version: 1,
            predecessor_id: None,
            created_at: now,
            client_public_key: None,
            client_signature: None,
        })
        .unwrap();

        assert_ne!(
            h_session, h_oauth,
            "swapping adjudicator_auth_kind must alter acta:override:v2 attestation_hash"
        );
    }

    #[test]
    fn test_evidence_event_v2_cannot_strip_refusal_metadata() {
        let meta = RefusalMetadata {
            operation: "ingest_claim".to_string(),
            reason_code: "ingest_policy_escalate".to_string(),
            target_scope: Some("Restricted/signing-keys".to_string()),
            summary: "policy escalation required on ingest to restricted scope".to_string(),
            scope_state_commitment: None,
            attempted_checkpoint_hash: None,
            signing_domain: None,
            expected_intent_digest_hex: None,
        };
        let comm = compute_refusal_metadata_commitment(&meta).unwrap();
        let h_v2 = compute_evidence_event_hash_with_meta(
            "tenant-1",
            18,
            &[0xAA; 32],
            None,
            Some(&comm),
            PolicyResultTag::Escalate,
            1_700_000_000_000_000,
            Some(&meta),
            None,
        )
        .unwrap();
        let h_stripped = compute_evidence_event_hash_with_meta(
            "tenant-1",
            18,
            &[0xAA; 32],
            None,
            Some(&comm),
            PolicyResultTag::Escalate,
            1_700_000_000_000_000,
            None,
            None,
        )
        .unwrap();
        assert_ne!(h_v2, h_stripped);
    }

    #[test]
    fn test_v165_legacy_blake3_merkle_and_object_claim_preimages() {
        let t = Utc.with_ymd_and_hms(2026, 11, 23, 12, 0, 0).unwrap();
        let mut obj = StoredObject {
            id: Uuid::from_bytes([0x11; 16]),
            tenant_id: "kylewilson04".to_string(),
            obj_type: ObjectType::Intent,
            scope: "acta-test/v165".to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority: 100,
            importance: 1.0,
            tags: vec!["audit".to_string()],
            body: serde_json::json!({"rule": "strict"}),
            embedding: None,
            content_hash: [0u8; 32],
            version: 1,
            predecessor_id: None,
            client_signature: None,
            client_public_key: None,
            written_by: None,
            evidence_seq_num: None,
            created_at: t,
        };
        let obj_pre = object_content_preimage_bytes(&obj).unwrap();
        obj.content_hash = compute_object_content_hash(&obj).unwrap();
        assert_eq!(blake3::hash(&obj_pre).as_bytes(), &obj.content_hash);

        let gkey = compute_logical_claim_group_key(
            "kylewilson04",
            "contract:eta",
            "fee_bps",
            "acta-test/v165",
        );
        let mut clm = KnowledgeClaim {
            id: Uuid::from_bytes([0x22; 16]),
            tenant_id: "kylewilson04".to_string(),
            claim_group_key: gkey,
            scope: "acta-test/v165".to_string(),
            subject: "contract:eta".to_string(),
            predicate: "fee_bps".to_string(),
            object_val: serde_json::json!(245),
            object_type: "int".to_string(),
            confidence: 0.85,
            source_provenance_class: 2,
            source_descriptor: "msa".to_string(),
            source_commitment: [0x33; 32],
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
            created_at: t,
        };
        let (gdom, gpre) = claim_group_preimage_bytes(&clm);
        assert_eq!(gdom, "acta:claim_group:v2");
        assert_eq!(blake3::hash(&gpre).as_bytes(), &clm.claim_group_key);
        let cpre = claim_content_preimage_bytes(&clm).unwrap();
        clm.content_hash = compute_claim_content_hash(&clm).unwrap();
        assert_eq!(blake3::hash(&cpre).as_bytes(), &clm.content_hash);

        let events = vec![(1, [0xAA; 32]), (2, [0xBB; 32]), (3, [0xCC; 32])];
        let leg_root = compute_legacy_blake3_merkle_root_from_events(&events);
        let rfc_leaves: Vec<[u8; 32]> = events
            .iter()
            .map(|(s, e)| merkle_leaf_hash(*s, e))
            .collect();
        let rfc_root = compute_merkle_root_from_leaves(&rfc_leaves);
        assert_ne!(leg_root, rfc_root);
    }

    #[test]
    fn test_v170_evidence_v3_write_and_answer_cache_strip_proof_and_author_sig() {
        let host_sk = SigningKey::from_bytes(&[0x51; 32]);
        let host_vk = host_sk.verifying_key();
        let author_sk = SigningKey::from_bytes(&[0x61; 32]);
        let author_pk = author_sk.verifying_key().to_bytes();
        let t = Utc.with_ymd_and_hms(2026, 11, 24, 7, 0, 0).unwrap();

        let gkey = compute_logical_claim_group_key(
            "kylewilson04",
            "vendor:acme",
            "lead_days",
            "acta-test/v170",
        );
        let mut clm = KnowledgeClaim {
            id: Uuid::from_bytes([0x33; 16]),
            tenant_id: "kylewilson04".to_string(),
            claim_group_key: gkey,
            scope: "acta-test/v170".to_string(),
            subject: "vendor:acme".to_string(),
            predicate: "lead_days".to_string(),
            object_val: serde_json::json!(14),
            object_type: "int".to_string(),
            confidence: 0.88,
            source_provenance_class: 3,
            source_descriptor: "signed-po".to_string(),
            source_commitment: [0x44; 32],
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
            created_at: t,
        };
        clm.content_hash = compute_claim_content_hash(&clm).unwrap();

        let intent_hash = compute_claim_client_intent_hash(
            &clm.tenant_id,
            &clm.scope,
            &clm.subject,
            &clm.predicate,
            &clm.object_val,
            &clm.object_type,
            clm.confidence,
            clm.source_provenance_class,
            &clm.source_descriptor,
            &clm.source_commitment,
            clm.status,
            &clm.contradiction_ids,
            clm.valid_from,
            clm.valid_to,
            clm.predecessor_id,
        )
        .unwrap();
        let author_sig = author_sk.sign(&intent_hash).to_bytes().to_vec();

        let ws = WriteLedgerSummary {
            write_domain: WRITE_EVENT_DOMAIN_V1.to_string(),
            operation: WriteOperationKind::IngestClaim,
            item_id: clm.id,
            scope: clm.scope.clone(),
            version: 1,
            predecessor_id: None,
            content_hash: clm.content_hash,
            written_by: "kylewilson04::oauth:kylewilson04".to_string(),
            writer_auth_kind: "ed25519_client_sig".to_string(),
            client_public_key: Some(author_pk),
            client_signature: Some(author_sig.clone()),
            retraction_reason: None,
            record_snapshot: serde_json::to_value(&clm).unwrap(),
        };
        let ws_comm = compute_write_summary_commitment(&ws).unwrap();
        let ev_hash = compute_evidence_event_hash_full(
            "kylewilson04",
            154,
            &[0x99; 32],
            None,
            Some(&ws_comm),
            PolicyResultTag::Allow,
            t.timestamp_micros(),
            None,
            None,
            Some(&ws),
            None,
        )
        .unwrap();
        let ev_stripped = compute_evidence_event_hash_full(
            "kylewilson04",
            154,
            &[0x99; 32],
            None,
            Some(&ws_comm),
            PolicyResultTag::Allow,
            t.timestamp_micros(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_ne!(ev_hash, ev_stripped, "stripping write_summary must mutate event_hash");

        let entry = EvidenceEntry {
            tenant_id: "kylewilson04".to_string(),
            seq_num: 154,
            event_domain: Some("acta:evidence_event:v3".to_string()),
            prev_hash: [0x99; 32],
            event_hash: ev_hash,
            bundle_hash: None,
            state_commitment: Some(ws_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: Some(ws),
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_signature: sign_evidence_entry(&host_sk, "kylewilson04", 154, &[0x99; 32], &ev_hash),
            created_at: t,
        };
        verify_single_evidence_entry_public(&entry, "kylewilson04", &host_vk)
            .expect("valid v3 write entry must verify");

        let qh = compute_query_text_hash("What is vendor:acme lead_days?");
        let ah = compute_answer_text_hash("14 days per signed-po.");
        let ans_intent = compute_answer_cache_client_intent_hash(
            "kylewilson04",
            "acta-test/v170",
            "task-1",
            &qh,
            &[0xAB; 32],
            &[0xCD; 32],
            &ah,
        );
        let ans_sig = author_sk.sign(&ans_intent).to_bytes().to_vec();

        // v1.7.2 invalidation receipt preserving original ed25519_client_sig + invalidated_by:
        let inv_acs = AnswerCacheLedgerSummary {
            cache_domain: ANSWER_CACHE_DOMAIN_V1.to_string(),
            event_kind: Some("invalidated".to_string()),
            cache_id: Uuid::from_bytes([0x77; 16]),
            scope: "acta-test/v170".to_string(),
            task_id: "task-1".to_string(),
            query_hash: qh,
            source_bundle_hash: [0xAB; 32],
            state_commitment: [0xCD; 32],
            validity_mode: Some("dependency_subset".to_string()),
            task_dependency_commitment: Some([0xDD; 32]),
            answer_hash: ah,
            cached_by: "kylewilson04::oauth:kylewilson04".to_string(),
            cacher_auth_kind: "ed25519_client_sig".to_string(),
            client_public_key: Some(author_pk),
            client_signature: Some(ans_sig),
            expires_at: None,
            invalidation_reason: Some("stale_dependency_commitment".to_string()),
            invalidated_by: Some("kylewilson04::oauth:kylewilson04".to_string()),
            invalidator_auth_kind: Some("oauth_github_principal".to_string()),
            observed_state_commitment: Some([0xEE; 32]),
            observed_dependency_commitment: Some([0xFF; 32]),
        };
        let ac_comm = compute_answer_cache_summary_commitment(&inv_acs).unwrap();
        let ac_ev_hash = compute_evidence_event_hash_full(
            "kylewilson04",
            155,
            &ev_hash,
            None,
            Some(&ac_comm),
            PolicyResultTag::Allow,
            t.timestamp_micros(),
            None,
            None,
            None,
            Some(&inv_acs),
        )
        .unwrap();
        let ac_entry = EvidenceEntry {
            tenant_id: "kylewilson04".to_string(),
            seq_num: 155,
            event_domain: Some("acta:evidence_event:v3".to_string()),
            prev_hash: ev_hash,
            event_hash: ac_ev_hash,
            bundle_hash: None,
            state_commitment: Some(ac_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: Some(inv_acs),
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_signature: sign_evidence_entry(&host_sk, "kylewilson04", 155, &ev_hash, &ac_ev_hash),
            created_at: t,
        };
        verify_single_evidence_entry_public(&ac_entry, "kylewilson04", &host_vk)
            .expect("valid v1.7.2 invalidation entry preserving ed25519_client_sig must verify");
    }

    #[test]
    fn test_v172_witness_v3_and_signed_rebuild_header_and_corroboration_proof() {
        let host_sk = SigningKey::from_bytes(&[0x71; 32]);
        let host_pk = host_sk.verifying_key().to_bytes();
        let host_vk = host_sk.verifying_key();
        let wit_pk = [0x82; 32];
        let t = Utc.with_ymd_and_hms(2026, 11, 24, 18, 0, 0).unwrap();

        // 1. Legacy v1 witness entry (like seq 183) vs v1.7.2 v3 witness entry:
        let (reg_pre, reg_comm) = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v172",
            &wit_pk,
            "kylewilson04::oauth:kylewilson04",
            Some("v1.7.2 witness"),
        );
        let wreg = WitnessRegistrationSummary {
            witness_id: "claude-witness-v172".to_string(),
            public_key: wit_pk,
            registered_by: "kylewilson04::oauth:kylewilson04".to_string(),
            description: Some("v1.7.2 witness".to_string()),
            registration_domain: WITNESS_REG_DOMAIN_V3.to_string(),
            registration_blake3_preimage_hex: hex::encode(&reg_pre),
        };
        let v1_hash = compute_evidence_event_hash_v172(
            "kylewilson04",
            1,
            &[0u8; 32],
            None,
            Some(&reg_comm),
            PolicyResultTag::Allow,
            t.timestamp_micros(),
            None,
            None,
            None,
            None,
            Some(&wreg),
            None,
            false,
        )
        .unwrap();
        let v3_hash = compute_evidence_event_hash_v172(
            "kylewilson04",
            1,
            &[0u8; 32],
            None,
            Some(&reg_comm),
            PolicyResultTag::Allow,
            t.timestamp_micros(),
            None,
            None,
            None,
            None,
            Some(&wreg),
            None,
            true,
        )
        .unwrap();
        assert_ne!(v1_hash, v3_hash, "v3 witness preimage must differ from legacy v1");

        let entry_v3_wit = EvidenceEntry {
            tenant_id: "kylewilson04".to_string(),
            seq_num: 1,
            event_domain: Some("acta:evidence_event:v3".to_string()),
            prev_hash: [0u8; 32],
            event_hash: v3_hash,
            bundle_hash: None,
            state_commitment: Some(reg_comm),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: Some(wreg),
            witness_revoke_summary: None,
            host_signature: sign_evidence_entry(&host_sk, "kylewilson04", 1, &[0u8; 32], &v3_hash),
            created_at: t,
        };
        verify_single_evidence_entry_public(&entry_v3_wit, "kylewilson04", &host_vk)
            .expect("v1.7.2 v3 witness entry must verify");

        // 2. Signed StateRebuildArchive header rejects swapped evaluated_at!
        let perm_root = [0x3F; 32];
        let hdr_hash = compute_rebuild_archive_header_hash(
            STATE_REBUILD_ARCHIVE_SCHEMA_V1,
            "kylewilson04",
            "acta-test/v172",
            1,
            t.timestamp_micros(),
            &perm_root,
        );
        let hdr_sig = sign_rebuild_archive_header(&host_sk, "kylewilson04", &hdr_hash);
        let mut reb_archive = StateRebuildArchive {
            schema_version: STATE_REBUILD_ARCHIVE_SCHEMA_V1.to_string(),
            tenant_id: "kylewilson04".to_string(),
            scope: "acta-test/v172".to_string(),
            up_to_seq: 1,
            evaluated_at: t,
            host_public_key: host_pk,
            permission_root: perm_root,
            header_hash: hdr_hash,
            host_header_signature: hdr_sig,
            override_attestations: vec![],
            evidence_chain: vec![entry_v3_wit.clone()],
            checkpoint: None,
            latest_anchored_checkpoint: None,
            consistency_proof_from_latest_anchor: vec![],
        };
        let reb_ok =
            verify_and_rebuild_scope_state_offline(&reb_archive, &host_pk, None).expect("signed header passes");
        assert!(reb_ok.header_signature_verified);

        // Swap evaluated_at forward by 1 year -> MUST fail header check!
        reb_archive.evaluated_at = t + Duration::days(365);
        assert!(
            verify_and_rebuild_scope_state_offline(&reb_archive, &host_pk, None).is_err(),
            "swapping evaluated_at without host signature MUST fail verification"
        );

        // 3. Corroborating claims in ExportArchive: missing A1 fails, both A1 + A2 pass with verified_claims == 2 and 0.72!
        let gkey = compute_logical_claim_group_key(
            "kylewilson04",
            "supplier:titan",
            "lead_days",
            "acta-test/v172",
        );
        let mut c1 = KnowledgeClaim {
            id: Uuid::from_bytes([0x11; 16]),
            tenant_id: "kylewilson04".to_string(),
            claim_group_key: gkey,
            scope: "acta-test/v172".to_string(),
            subject: "supplier:titan".to_string(),
            predicate: "lead_days".to_string(),
            object_val: json!(14),
            object_type: "int".to_string(),
            confidence: 0.60,
            source_provenance_class: 2,
            source_descriptor: "erp-feed-a".to_string(),
            source_commitment: [0xA1; 32],
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
            created_at: t,
        };
        c1.content_hash = compute_claim_content_hash(&c1).unwrap();

        let mut c2 = c1.clone();
        c2.id = Uuid::from_bytes([0x22; 16]);
        c2.source_descriptor = "carrier-bol-b".to_string();
        c2.source_commitment = [0xA2; 32];
        c2.created_at = t + Duration::seconds(1);
        c2.content_hash = compute_claim_content_hash(&c2).unwrap();

        let mut winner_cand = ClaimCandidate::from(&c2);
        winner_cand.corroborating_count = 2;
        winner_cand.corroborating_sources =
            vec!["carrier-bol-b".to_string(), "erp-feed-a".to_string()];
        winner_cand.effective_confidence = Some(0.72);

        let empty_root = compute_sub_commitment(&[]);
        let know_root = compute_sub_commitment(&[c1.content_hash, c2.content_hash]);
        let sc = compute_state_commitment(
            SCHEMA_VERSION,
            "kylewilson04",
            "acta-test/v172",
            &empty_root,
            &know_root,
            &empty_root,
            &perm_root,
        );
        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: "kylewilson04".to_string(),
            task_id: "po-lead".to_string(),
            scope: "acta-test/v172".to_string(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            resolver_manifest: Some(ResolverManifest::new(
                0.70,
                0.15,
                0.50,
                ContextBudget::Tokens(2048),
                perm_root,
            )),
            selected_objects: vec![],
            resolution_records: vec![ResolutionRecord {
                claim_group_key: gkey,
                winning_claim: winner_cand,
                margin: None,
                suppressed_claim_ids: vec![c1.id],
                override_attestation: None,
            }],
            dispute_records: vec![],
            omission_record: OmissionRecord {
                inline_items: vec![],
                total_omitted_count: 0,
                full_excluded_hash: compute_omission_list_hash(&[]).unwrap(),
                has_unresolved_claims: false,
            },
            resolved_facts_omitted: Some(0),
            state_commitment: sc,
            dependency_commitment: know_root,
            issued_at: c2.created_at,
        };
        let (bh, _) = compute_bundle_hash(&bundle).unwrap();
        let b_ev_hash = compute_evidence_event_hash(
            "kylewilson04",
            2,
            &v3_hash,
            Some(&bh),
            Some(&sc),
            PolicyResultTag::Allow,
            c2.created_at.timestamp_micros(),
        );
        let b_entry = EvidenceEntry {
            tenant_id: "kylewilson04".to_string(),
            seq_num: 2,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: v3_hash,
            event_hash: b_ev_hash,
            bundle_hash: Some(bh),
            state_commitment: Some(sc),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_signature: sign_evidence_entry(&host_sk, "kylewilson04", 2, &v3_hash, &b_ev_hash),
            created_at: c2.created_at,
        };

        let incomplete_archive = ExportArchive {
            bundle_hash: bh,
            bundle: bundle.clone(),
            objects: vec![],
            claims: vec![c2.clone()],
            override_attestations: vec![],
            evidence_chain: vec![entry_v3_wit.clone(), b_entry.clone()],
            merkle_proof: None,
            host_public_key: host_pk,
        };
        assert!(
            verify_export_archive(&incomplete_archive, &host_pk).is_err(),
            "missing corroborating claim c1 in archive.claims must fail verification"
        );

        let full_archive = ExportArchive {
            bundle_hash: bh,
            bundle,
            objects: vec![],
            claims: vec![c1, c2],
            override_attestations: vec![],
            evidence_chain: vec![entry_v3_wit, b_entry],
            merkle_proof: None,
            host_public_key: host_pk,
        };
        let sum = verify_export_archive(&full_archive, &host_pk)
            .expect("archive with both corroborating claims must verify");
        assert_eq!(sum.verified_claims, 2);
        assert_eq!(sum.verified_corroborated_resolutions, 1);
    }
}
