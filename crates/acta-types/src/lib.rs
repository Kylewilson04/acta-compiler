pub mod bundle;
pub mod claims;
pub mod error;
pub mod objects;
pub mod request;
pub mod validation;

pub mod serde_hex {
    pub mod hex_32 {
        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&hex::encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
            let s = String::deserialize(deserializer)?;
            let raw = hex::decode(&s).map_err(D::Error::custom)?;
            raw.try_into()
                .map_err(|_| D::Error::custom("expected 32-byte hex string (64 hex chars)"))
        }
    }

    pub mod hex_64 {
        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&hex::encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
            let s = String::deserialize(deserializer)?;
            let raw = hex::decode(&s).map_err(D::Error::custom)?;
            raw.try_into()
                .map_err(|_| D::Error::custom("expected 64-byte hex string (128 hex chars)"))
        }
    }

    pub mod opt_hex_32 {
        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(
            opt: &Option<[u8; 32]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match opt {
                Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<[u8; 32]>, D::Error> {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) => {
                    let raw = hex::decode(&s).map_err(D::Error::custom)?;
                    let arr: [u8; 32] = raw.try_into().map_err(|_| {
                        D::Error::custom("expected 32-byte hex string (64 hex chars)")
                    })?;
                    Ok(Some(arr))
                }
                None => Ok(None),
            }
        }
    }

    pub mod opt_hex_vec {
        use serde::{de::Error, Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(
            opt: &Option<Vec<u8>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match opt {
                Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Vec<u8>>, D::Error> {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) => Ok(Some(hex::decode(&s).map_err(D::Error::custom)?)),
                None => Ok(None),
            }
        }
    }
}

pub use bundle::{
    AnchorCheckpointRequest, AnswerCacheLedgerSummary, ContextBundle, EntryInclusionProof,
    EvidenceEntry, ExportArchive, ExternalWitnessAnchor, MerkleBundleProof, OmissionReason,
    OmissionRecord, OmittedItem, OverrideLedgerSummary, PolicyResultTag, QuarantinedAnchorRecord,
    RefusalMetadata, RegisterWitnessRequest, RegisterWitnessResponse, ResolverManifest,
    RevokeWitnessRequest, RevokeWitnessResponse, SignedTreeHead, StateRebuildArchive,
    TrustedWitness, WitnessRegistrationSummary, WitnessRevocationSummary, WriteLedgerSummary,
    WriteOperationKind, ANSWER_CACHE_DOMAIN_V1, CACHE_DEPENDENCY_DOMAIN_V1,
    DEFAULT_CORROBORATION_DAMPING, DEFAULT_DECISIVENESS_THRESHOLD, DEFAULT_MIN_CONFIDENCE,
    SCHEMA_VERSION, STATE_REBUILD_ARCHIVE_SCHEMA_V1, WITNESS_REG_DOMAIN_V1, WITNESS_REG_DOMAIN_V2,
    WITNESS_REG_DOMAIN_V3, WITNESS_REVOKE_DOMAIN_V1, WITNESS_REVOKE_DOMAIN_V2,
    WRITE_EVENT_DOMAIN_V1,
};
pub use claims::{
    infer_override_auth_kind, AttestOverrideRequest, AttestOverrideResponse, ClaimCandidate,
    ClaimStatus, DisputeReasonCode, DisputeRecord, IngestClaimRequest, IngestClaimResponse,
    KnowledgeClaim, LapsedOverrideRef, OverriddenClaimRef, OverrideAttestation,
    OverrideResolutionRef, ResolutionRecord, RetractClaimRequest, RetractClaimResponse,
    OVERRIDE_DOMAIN_V1, OVERRIDE_DOMAIN_V2,
};
pub use error::{ActaError, ActaResult};
pub use objects::{
    IngestObjectRequest, IngestObjectResponse, LifecycleStatus, ObjectType, RankedMemory,
    SelectedObjectRef, StoredObject,
};
pub use request::{
    CacheAnswerRequest, CacheAnswerResponse, CacheDependencySpec, CachedAnswerReceipt,
    CompileRequest, CompileResponse,
    ContextBudget, ImpactBundleRecord, ImpactedCachedAnswerRecord, LedgerStateRebuildResponse,
    LookupCachedAnswerRequest, LookupCachedAnswerResponse, PolicyDecision, TraceItemImpactResponse,
};
pub use validation::{
    validate_budget, validate_claim_value_type, validate_confidence, validate_identifier,
    validate_importance, validate_json_payload_size, validate_justification, validate_priority,
    validate_provenance_class, validate_query_text, validate_scope, validate_tags,
};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{SubsecRound, Utc};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn test_compile_request_and_budget_round_trip() {
        for budget in [
            ContextBudget::Tokens(2048),
            ContextBudget::Bytes(8192),
            ContextBudget::Records(15),
        ] {
            let req = CompileRequest {
                tenant_id: "tenant-acme".to_string(),
                actor_id: "agent-planner-1".to_string(),
                task_id: "task-42".to_string(),
                scope: "billing/enterprise".to_string(),
                query_text: "What is the active discount tier?".to_string(),
                query_embedding: Some(vec![0.125, -0.5, 0.75]),
                budget,
                evaluation_time: Some(Utc::now().trunc_subsecs(6)),
            };
            let encoded = serde_json::to_string(&req).expect("serialize request");
            let decoded: CompileRequest = serde_json::from_str(&encoded).expect("deserialize");
            assert_eq!(req, decoded);
        }
    }

    #[test]
    fn test_policy_decision_and_omission_reasons_round_trip() {
        let decisions = vec![
            PolicyDecision::Allow,
            PolicyDecision::Block {
                reason: "cross-tenant".to_string(),
            },
            PolicyDecision::Escalate {
                reason: "restricted scope".to_string(),
            },
        ];
        let encoded = serde_json::to_string(&decisions).unwrap();
        let decoded: Vec<PolicyDecision> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decisions, decoded);

        let reasons = vec![
            OmissionReason::BudgetExceeded,
            OmissionReason::OutOfScope,
            OmissionReason::LifecycleExpired,
            OmissionReason::PolicyDenied,
            OmissionReason::Superseded,
            OmissionReason::DisputedWithheld,
            OmissionReason::Retracted,
            OmissionReason::RetractionTombstone,
        ];
        let encoded_reasons = serde_json::to_string(&reasons).unwrap();
        let decoded_reasons: Vec<OmissionReason> = serde_json::from_str(&encoded_reasons).unwrap();
        assert_eq!(reasons, decoded_reasons);
    }

    #[test]
    fn test_context_bundle_and_export_archive_round_trip() {
        let now = Utc::now().trunc_subsecs(6);
        let obj_id = Uuid::new_v4();
        let claim_a_id = Uuid::new_v4();
        let claim_b_id = Uuid::new_v4();

        let stored_obj = StoredObject {
            id: obj_id,
            tenant_id: "tenant-1".to_string(),
            obj_type: ObjectType::Intent,
            scope: "ops".to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority: 10,
            importance: 0.9,
            tags: vec!["critical".to_string()],
            body: json!({"instruction": "Never drop audit records"}),
            content_hash: [0x11; 32],
            embedding: None,
            version: 1,
            predecessor_id: None,
            client_signature: Some(vec![0xAA; 64]),
            client_public_key: None,
            written_by: None,
            evidence_seq_num: None,
            created_at: now,
        };

        let claim_a = KnowledgeClaim {
            id: claim_a_id,
            tenant_id: "tenant-1".to_string(),
            claim_group_key: [0x22; 32],
            scope: "ops".to_string(),
            subject: "service:payments".to_string(),
            predicate: "region_primary".to_string(),
            object_val: json!("us-east-1"),
            object_type: "string".to_string(),
            confidence: 0.81,
            source_provenance_class: 2,
            source_descriptor: "cmdb-sync".to_string(),
            source_commitment: [0x33; 32],
            content_hash: [0x44; 32],
            status: ClaimStatus::Active,
            contradiction_ids: vec![],
            valid_from: Some(now),
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

        let mut claim_b = claim_a.clone();
        claim_b.id = claim_b_id;
        claim_b.object_val = json!("us-west-2");
        claim_b.confidence = 0.74;
        claim_b.content_hash = [0x45; 32];

        let manifest = ResolverManifest::new(
            0.70,
            0.05,
            0.50,
            ContextBudget::Tokens(2048),
            [0xAE; 32],
        );
        assert!(manifest.non_default_thresholds);

        let bundle = ContextBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: "tenant-1".to_string(),
            task_id: "task-99".to_string(),
            scope: "ops".to_string(),
            policy_result: PolicyResultTag::Allow,
            embedding_model_version: "text-embedding-3-small-1536".to_string(),
            resolver_manifest: Some(manifest),
            selected_objects: vec![SelectedObjectRef::from(&stored_obj)],
            resolution_records: vec![],
            dispute_records: vec![DisputeRecord {
                claim_group_key: [0x22; 32],
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
                inline_items: vec![OmittedItem {
                    id: Uuid::new_v4(),
                    reason: OmissionReason::BudgetExceeded,
                }],
                total_omitted_count: 1,
                full_excluded_hash: [0x55; 32],
                has_unresolved_claims: true,
            },
            resolved_facts_omitted: Some(0),
            state_commitment: [0x66; 32],
            dependency_commitment: [0x77; 32],
            issued_at: now,
        };

        let evidence = EvidenceEntry {
            tenant_id: "tenant-1".to_string(),
            seq_num: 1,
            event_domain: Some("acta:evidence_event:v1".to_string()),
            prev_hash: [0u8; 32],
            event_hash: [0x88; 32],
            bundle_hash: Some([0x99; 32]),
            state_commitment: Some([0x66; 32]),
            policy_result: PolicyResultTag::Allow,
            refusal_metadata: None,
            override_summary: None,
            write_summary: None,
            answer_cache_summary: None,
            witness_reg_summary: None,
            witness_revoke_summary: None,
            host_signature: [0xAB; 64],
            created_at: now,
        };

        let archive = ExportArchive {
            bundle_hash: [0x99; 32],
            bundle,
            objects: vec![stored_obj],
            claims: vec![claim_a, claim_b],
            override_attestations: vec![],
            evidence_chain: vec![evidence],
            merkle_proof: None,
            host_public_key: [0xCD; 32],
        };

        let json_bytes = serde_json::to_vec_pretty(&archive).expect("serialize archive");
        let round_trip: ExportArchive =
            serde_json::from_slice(&json_bytes).expect("deserialize archive");
        assert_eq!(archive, round_trip);
    }
}
