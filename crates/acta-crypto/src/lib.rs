pub mod canonical;
pub mod commitment;
pub mod hash;
pub mod signing;
pub mod token;
pub mod verify;

pub use canonical::to_canonical_bytes;
pub use commitment::{
    compute_dependency_commitment, compute_state_commitment, compute_sub_commitment,
};
pub use hash::{
    compute_bundle_hash, compute_claim_content_hash, compute_claim_group_key,
    compute_evidence_event_hash, compute_evidence_event_hash_with_meta,
    compute_logical_claim_group_key, compute_object_content_hash, compute_omission_list_hash,
    compute_override_attestation_hash, compute_refusal_commitment,
    compute_refusal_metadata_commitment, hash_length_delimited, OverrideHashInput,
};
pub use signing::{
    sign_evidence_entry, sign_override_attestation, verify_client_content_signature,
    verify_evidence_signature, verify_override_signature,
};
pub use token::{
    compute_pkce_s256, derive_oauth_envelope_key, derive_tenant_mac_key, mint_signed_envelope,
    mint_tenant_api_key, normalize_github_slug, verify_pkce_s256, verify_signed_envelope,
    verify_tenant_api_key, TENANT_TOKEN_PREFIX,
};
pub use verify::{verify_export_archive, VerificationSummary};

#[cfg(test)]
mod tests {
    use super::*;
    use acta_types::{OmissionReason, OmittedItem, PolicyResultTag, RefusalMetadata};
    use ed25519_dalek::SigningKey;
    use serde_json::Value;
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
    fn test_evidence_event_v2_cannot_strip_refusal_metadata() {
        let meta = RefusalMetadata {
            operation: "ingest_claim".to_string(),
            reason_code: "ingest_policy_escalate".to_string(),
            target_scope: Some("Restricted/signing-keys".to_string()),
            summary: "policy escalation required on ingest to restricted scope".to_string(),
            scope_state_commitment: None,
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
}
