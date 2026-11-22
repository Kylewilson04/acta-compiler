use std::collections::{BTreeMap, BTreeSet};

use acta_crypto::{compute_logical_claim_group_key, to_canonical_bytes};
use acta_types::{
    ClaimCandidate, ClaimStatus, DisputeReasonCode, DisputeRecord, KnowledgeClaim,
    LapsedOverrideRef, OmissionReason, OverrideAttestation, OverrideResolutionRef,
    ResolutionRecord,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

const FLOAT_EPS: f64 = 1e-9;

fn round_9(v: f64) -> f64 {
    (v * 1_000_000_000.0).round() / 1_000_000_000.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ValueTypeFamily {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

fn value_type_family(val: &Value, declared_object_type: &str) -> ValueTypeFamily {
    match val {
        Value::Null => ValueTypeFamily::Null,
        Value::Bool(_) => ValueTypeFamily::Bool,
        Value::Number(_) => ValueTypeFamily::Number,
        Value::String(_) => {
            let _ = declared_object_type;
            ValueTypeFamily::String
        }
        Value::Array(_) => ValueTypeFamily::Array,
        Value::Object(_) => ValueTypeFamily::Object,
    }
}

fn typed_value_signature(c: &KnowledgeClaim) -> (ValueTypeFamily, Vec<u8>) {
    let tf = value_type_family(&c.object_val, &c.object_type);
    let jcs = to_canonical_bytes(&c.object_val)
        .unwrap_or_else(|_| c.object_val.to_string().into_bytes());
    (tf, jcs)
}

#[derive(Debug, Clone)]
struct ValueBucket {
    type_family: ValueTypeFamily,
    claims: Vec<KnowledgeClaim>,
    effective_confidence: f64,
    max_provenance: i32,
}

impl ValueBucket {
    fn from_sorted_claims(type_family: ValueTypeFamily, claims: Vec<KnowledgeClaim>) -> Self {
        let lead_conf = claims[0].confidence;
        let effective_confidence = if claims.len() == 1 {
            round_9(lead_conf)
        } else {
            let mut unconvinced = 1.0_f64;
            for c in &claims[1..] {
                unconvinced *= (1.0 - 0.5 * c.confidence).clamp(0.0, 1.0);
            }
            round_9((lead_conf + (1.0 - lead_conf) * (1.0 - unconvinced)).min(0.9999))
        };
        let max_provenance = claims
            .iter()
            .map(|c| c.source_provenance_class)
            .max()
            .unwrap_or(0);
        Self {
            type_family,
            claims,
            effective_confidence,
            max_provenance,
        }
    }

    fn representative_candidate(&self) -> ClaimCandidate {
        let mut cand = ClaimCandidate::from(&self.claims[0]);
        if self.claims.len() > 1 {
            cand.corroborating_count = self.claims.len();
            cand.corroborating_sources = self
                .claims
                .iter()
                .map(|c| c.source_descriptor.clone())
                .collect();
            cand.effective_confidence = Some(self.effective_confidence);
        }
        cand
    }

    fn all_annotated_candidates(&self) -> Vec<ClaimCandidate> {
        let count = self.claims.len();
        let sources: Vec<String> = if count > 1 {
            self.claims
                .iter()
                .map(|c| c.source_descriptor.clone())
                .collect()
        } else {
            Vec::new()
        };
        let eff_opt = if count > 1 {
            Some(self.effective_confidence)
        } else {
            None
        };

        self.claims
            .iter()
            .map(|c| {
                let mut cand = ClaimCandidate::from(c);
                if count > 1 {
                    cand.corroborating_count = count;
                    cand.corroborating_sources = sources.clone();
                    cand.effective_confidence = eff_opt;
                }
                cand
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolverConfig {
    pub min_confidence: f64,
    pub decisiveness_threshold: f64,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.70,
            decisiveness_threshold: 0.15,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolverOutput {
    pub resolutions: Vec<ResolutionRecord>,
    pub disputes: Vec<DisputeRecord>,
    pub excluded_claims: Vec<(Uuid, OmissionReason)>,
}

fn compare_claims_desc(a: &KnowledgeClaim, b: &KnowledgeClaim) -> std::cmp::Ordering {
    b.confidence
        .total_cmp(&a.confidence)
        .then_with(|| b.source_provenance_class.cmp(&a.source_provenance_class))
        .then_with(|| b.created_at.cmp(&a.created_at))
        .then_with(|| b.version.cmp(&a.version))
        .then_with(|| a.id.cmp(&b.id))
}

enum OverrideEvalOutcome {
    Applied(ResolutionRecord),
    Lapsed(LapsedOverrideRef),
}

/// Evaluates an active signed `OverrideAttestation` against `group`:
/// - Returns `Applied(ResolutionRecord)` when `winner` matches `(id, content_hash)` AND every
///   non-agreeing active claim in `group` is covered in `att.overridden_claims`.
/// - Returns `Lapsed(LapsedOverrideRef)` listing `reopened_by_claim_ids` whenever unseen conflicting
///   evidence arrived (or the adjudicated winner was superseded/revoked), so the reopened
///   `DisputeRecord` carries full audit provenance of the superseded override!
fn evaluate_signed_override(
    record_group_key: [u8; 32],
    group: &[KnowledgeClaim],
    att: &OverrideAttestation,
) -> OverrideEvalOutcome {
    let Some(winner) = group
        .iter()
        .find(|c| c.id == att.winning_claim_id && c.content_hash == att.winning_claim_content_hash)
    else {
        let mut reopened_by: Vec<Uuid> = group
            .iter()
            .filter(|c| {
                !att.overridden_claims
                    .iter()
                    .any(|oc| oc.id == c.id && oc.content_hash == c.content_hash)
            })
            .map(|c| c.id)
            .collect();
        reopened_by.sort_unstable();
        return OverrideEvalOutcome::Lapsed(LapsedOverrideRef {
            attestation_id: att.id,
            attestation_hash: att.attestation_hash,
            prior_winning_claim_id: att.winning_claim_id,
            adjudicator_id: att.adjudicator_id.clone(),
            justification: att.justification.clone(),
            evidence_seq_num: att.evidence_seq_num,
            version: att.version,
            attested_at: att.created_at,
            reopened_by_claim_ids: reopened_by,
        });
    };

    let winner_sig = typed_value_signature(winner);
    let mut agreeing_peers = Vec::new();
    let mut non_agreeing = Vec::new();
    let mut unseen_ids = Vec::new();

    for c in group {
        if c.id == winner.id {
            continue;
        }
        if typed_value_signature(c) == winner_sig {
            agreeing_peers.push(c.clone());
        } else {
            let covered = att
                .overridden_claims
                .iter()
                .any(|oc| oc.id == c.id && oc.content_hash == c.content_hash);
            if !covered {
                unseen_ids.push(c.id);
            }
            non_agreeing.push(c.clone());
        }
    }

    if !unseen_ids.is_empty() {
        unseen_ids.sort_unstable();
        return OverrideEvalOutcome::Lapsed(LapsedOverrideRef {
            attestation_id: att.id,
            attestation_hash: att.attestation_hash,
            prior_winning_claim_id: att.winning_claim_id,
            adjudicator_id: att.adjudicator_id.clone(),
            justification: att.justification.clone(),
            evidence_seq_num: att.evidence_seq_num,
            version: att.version,
            attested_at: att.created_at,
            reopened_by_claim_ids: unseen_ids,
        });
    }

    let mut winner_claims = Vec::with_capacity(1 + agreeing_peers.len());
    winner_claims.push(winner.clone());
    agreeing_peers.sort_by(compare_claims_desc);
    winner_claims.extend(agreeing_peers);

    let winner_bucket = ValueBucket::from_sorted_claims(winner_sig.0, winner_claims);
    let winning_claim = winner_bucket.representative_candidate();

    non_agreeing.sort_by(compare_claims_desc);
    let margin = non_agreeing
        .first()
        .map(|top_other| round_9(winner_bucket.effective_confidence - top_other.confidence));

    let mut suppressed_claim_ids: Vec<Uuid> =
        winner_bucket.claims[1..].iter().map(|c| c.id).collect();
    suppressed_claim_ids.extend(non_agreeing.iter().map(|c| c.id));

    OverrideEvalOutcome::Applied(ResolutionRecord {
        claim_group_key: record_group_key,
        winning_claim,
        margin,
        suppressed_claim_ids,
        override_attestation: Some(OverrideResolutionRef::from(att)),
    })
}

/// Deterministically resolves grouped `KnowledgeClaim`s without external override attestations.
pub fn resolve_claims(
    claims: Vec<KnowledgeClaim>,
    now: DateTime<Utc>,
    config: &ResolverConfig,
) -> ResolverOutput {
    resolve_claims_with_overrides(claims, &[], now, config)
}

/// Deterministically resolves grouped `KnowledgeClaim`s with optional signed `OverrideAttestation`s
/// (attaching `LapsedOverrideRef` provenance onto reopened `DisputeRecord`s when unseen conflicting
/// evidence arrives after an override).
pub fn resolve_claims_with_overrides(
    claims: Vec<KnowledgeClaim>,
    overrides: &[OverrideAttestation],
    now: DateTime<Utc>,
    config: &ResolverConfig,
) -> ResolverOutput {
    let mut active_claims = Vec::with_capacity(claims.len());
    let mut excluded_claims = Vec::new();
    let mut inactive_ids = BTreeSet::new();

    let mut overrides_by_group: BTreeMap<[u8; 32], &OverrideAttestation> = BTreeMap::new();
    for ovr in overrides {
        let lkey = compute_logical_claim_group_key(
            &ovr.tenant_id,
            &ovr.subject,
            &ovr.predicate,
            &ovr.scope,
        );
        match overrides_by_group.get(&lkey) {
            Some(prev)
                if (prev.version, prev.created_at, prev.id)
                    >= (ovr.version, ovr.created_at, ovr.id) => {}
            _ => {
                overrides_by_group.insert(lkey, ovr);
            }
        }
    }

    for claim in claims {
        let within_from = claim.valid_from.map_or(true, |vf| now >= vf);
        let within_to = claim.valid_to.map_or(true, |vt| now <= vt);

        if claim.status != ClaimStatus::Active || !within_from || !within_to {
            inactive_ids.insert(claim.id);
            excluded_claims.push((claim.id, OmissionReason::LifecycleExpired));
        } else {
            active_claims.push(claim);
        }
    }

    let mut contradicted_active_ids = BTreeSet::new();
    for c in &active_claims {
        for target_id in &c.contradiction_ids {
            if !inactive_ids.contains(target_id) {
                contradicted_active_ids.insert(c.id);
                contradicted_active_ids.insert(*target_id);
            }
        }
    }

    let mut logical_groups: BTreeMap<[u8; 32], Vec<KnowledgeClaim>> = BTreeMap::new();
    for claim in active_claims {
        let lkey = compute_logical_claim_group_key(
            &claim.tenant_id,
            &claim.subject,
            &claim.predicate,
            &claim.scope,
        );
        logical_groups.entry(lkey).or_default().push(claim);
    }

    let mut resolutions = Vec::new();
    let mut disputes = Vec::new();

    for (logical_key, mut raw_group) in logical_groups {
        raw_group.sort_by(|a, b| {
            a.id.cmp(&b.id)
                .then_with(|| a.content_hash.cmp(&b.content_hash))
        });
        raw_group.dedup_by_key(|c| c.id);

        let first_stored_key = raw_group[0].claim_group_key;
        let record_group_key = if raw_group
            .iter()
            .all(|c| c.claim_group_key == first_stored_key)
        {
            first_stored_key
        } else {
            logical_key
        };

        let mut by_source: BTreeMap<String, Vec<KnowledgeClaim>> = BTreeMap::new();
        for c in raw_group {
            by_source
                .entry(c.source_descriptor.clone())
                .or_default()
                .push(c);
        }

        let mut group = Vec::with_capacity(by_source.len());
        for (_src, mut src_claims) in by_source {
            if src_claims.len() == 1 {
                group.push(src_claims.pop().unwrap());
                continue;
            }
            src_claims.sort_by(|a, b| {
                let a_contra = contradicted_active_ids.contains(&a.id);
                let b_contra = contradicted_active_ids.contains(&b.id);
                b_contra
                    .cmp(&a_contra)
                    .then_with(|| b.version.cmp(&a.version))
                    .then_with(|| b.created_at.cmp(&a.created_at))
                    .then_with(|| b.id.cmp(&a.id))
            });
            let mut iter = src_claims.into_iter();
            if let Some(head) = iter.next() {
                group.push(head);
            }
            for older in iter {
                if contradicted_active_ids.contains(&older.id) {
                    group.push(older);
                } else {
                    excluded_claims.push((older.id, OmissionReason::Superseded));
                }
            }
        }

        group.sort_by(compare_claims_desc);

        // Evaluate signed `OverrideAttestation`: either resolves OR records `lapsed_override`!
        let mut lapsed_override: Option<LapsedOverrideRef> = None;
        if let Some(att) = overrides_by_group.get(&logical_key) {
            match evaluate_signed_override(record_group_key, &group, att) {
                OverrideEvalOutcome::Applied(overridden_resolution) => {
                    resolutions.push(overridden_resolution);
                    continue;
                }
                OverrideEvalOutcome::Lapsed(lapsed) => {
                    lapsed_override = Some(lapsed);
                }
            }
        }

        // Note: If a prior override lapsed because an unseen higher-confidence claim arrived,
        // NEVER let the unseen claim auto-resolve silently over a previously human-adjudicated group!
        // Any group with a `lapsed_override` MUST surface as an explicit `[DISPUTE]` for human review.
        if group.iter().any(|c| contradicted_active_ids.contains(&c.id)) {
            let competing_claims = group.iter().map(ClaimCandidate::from).collect();
            disputes.push(DisputeRecord {
                claim_group_key: record_group_key,
                competing_claims,
                reason_code: DisputeReasonCode::BlockingContradiction,
                escalation_required: true,
                lapsed_override,
            });
            continue;
        }

        let mut qualifying = Vec::new();
        let mut sub_threshold = Vec::new();
        for c in group {
            if c.confidence + FLOAT_EPS >= config.min_confidence {
                qualifying.push(c);
            } else {
                sub_threshold.push(c);
            }
        }

        if qualifying.is_empty() {
            let competing_claims = sub_threshold.iter().map(ClaimCandidate::from).collect();
            disputes.push(DisputeRecord {
                claim_group_key: record_group_key,
                competing_claims,
                reason_code: DisputeReasonCode::InsufficientConfidence,
                escalation_required: true,
                lapsed_override,
            });
            continue;
        }

        let mut bucket_map: BTreeMap<(ValueTypeFamily, Vec<u8>), Vec<KnowledgeClaim>> =
            BTreeMap::new();
        for c in qualifying {
            let (tf, jcs) = typed_value_signature(&c);
            bucket_map.entry((tf, jcs)).or_default().push(c);
        }

        let mut buckets: Vec<ValueBucket> = bucket_map
            .into_iter()
            .map(|((tf, _), mut b_claims)| {
                b_claims.sort_by(compare_claims_desc);
                ValueBucket::from_sorted_claims(tf, b_claims)
            })
            .collect();

        buckets.sort_by(|a, b| {
            b.effective_confidence
                .total_cmp(&a.effective_confidence)
                .then_with(|| b.max_provenance.cmp(&a.max_provenance))
                .then_with(|| b.claims.len().cmp(&a.claims.len()))
                .then_with(|| compare_claims_desc(&a.claims[0], &b.claims[0]))
        });

        if buckets.len() == 1 && lapsed_override.is_none() {
            let winner_bucket = &buckets[0];
            let winning_claim = winner_bucket.representative_candidate();
            let margin = sub_threshold
                .first()
                .map(|sub| round_9(winner_bucket.effective_confidence - sub.confidence));

            let mut suppressed_claim_ids: Vec<Uuid> =
                winner_bucket.claims[1..].iter().map(|c| c.id).collect();
            suppressed_claim_ids.extend(sub_threshold.iter().map(|c| c.id));

            resolutions.push(ResolutionRecord {
                claim_group_key: record_group_key,
                winning_claim,
                margin,
                suppressed_claim_ids,
                override_attestation: None,
            });
            continue;
        }

        let lead_family = buckets[0].type_family;
        let has_type_mismatch = buckets.iter().any(|b| b.type_family != lead_family);
        let margin = if buckets.len() >= 2 {
            round_9(buckets[0].effective_confidence - buckets[1].effective_confidence)
        } else {
            0.0
        };

        if lapsed_override.is_none()
            && !has_type_mismatch
            && buckets.len() >= 2
            && margin + FLOAT_EPS >= config.decisiveness_threshold
        {
            let winning_claim = buckets[0].representative_candidate();
            let mut suppressed_claim_ids: Vec<Uuid> =
                buckets[0].claims[1..].iter().map(|c| c.id).collect();
            for other_b in &buckets[1..] {
                suppressed_claim_ids.extend(other_b.claims.iter().map(|c| c.id));
            }
            suppressed_claim_ids.extend(sub_threshold.iter().map(|c| c.id));

            resolutions.push(ResolutionRecord {
                claim_group_key: record_group_key,
                winning_claim,
                margin: Some(margin),
                suppressed_claim_ids,
                override_attestation: None,
            });
        } else {
            let reason_code = if has_type_mismatch {
                DisputeReasonCode::TypeMismatch
            } else {
                DisputeReasonCode::InsufficientMargin
            };

            let mut competing_claims = Vec::new();
            for b in &buckets {
                competing_claims.extend(b.all_annotated_candidates());
            }
            for sub in &sub_threshold {
                excluded_claims.push((sub.id, OmissionReason::DisputedWithheld));
            }

            disputes.push(DisputeRecord {
                claim_group_key: record_group_key,
                competing_claims,
                reason_code,
                escalation_required: true,
                lapsed_override,
            });
        }
    }

    resolutions.sort_by(|a, b| a.claim_group_key.cmp(&b.claim_group_key));
    disputes.sort_by(|a, b| a.claim_group_key.cmp(&b.claim_group_key));
    excluded_claims.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    ResolverOutput {
        resolutions,
        disputes,
        excluded_claims,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acta_crypto::{
        compute_claim_content_hash, compute_claim_group_key, compute_override_attestation_hash,
        OverrideHashInput,
    };
    use acta_types::OverriddenClaimRef;
    use chrono::TimeZone;
    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    use serde_json::json;

    fn make_claim(
        id_byte: u8,
        subject: &str,
        val: serde_json::Value,
        confidence: f64,
        prov: i32,
        status: ClaimStatus,
        contradictions: Vec<Uuid>,
    ) -> KnowledgeClaim {
        let ts = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 0).unwrap();
        let obj_type = if val.is_number() { "integer" } else { "string" };
        let group_key = compute_logical_claim_group_key("tenant-1", subject, "status", "ops");
        let mut id_bytes = [0u8; 16];
        id_bytes[15] = id_byte;
        let mut claim = KnowledgeClaim {
            id: Uuid::from_bytes(id_bytes),
            tenant_id: "tenant-1".to_string(),
            claim_group_key: group_key,
            scope: "ops".to_string(),
            subject: subject.to_string(),
            predicate: "status".to_string(),
            object_val: val,
            object_type: obj_type.to_string(),
            confidence,
            source_provenance_class: prov,
            source_descriptor: format!("src-{id_byte}"),
            source_commitment: [id_byte; 32],
            content_hash: [0u8; 32],
            status,
            contradiction_ids: contradictions,
            valid_from: None,
            valid_to: None,
            version: 1,
            predecessor_id: None,
            created_at: ts,
        };
        claim.content_hash = compute_claim_content_hash(&claim).unwrap();
        claim
    }

    #[test]
    fn test_numerical_examples_092_vs_060_resolves_and_081_vs_074_disputes() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig {
            min_confidence: 0.70,
            decisiveness_threshold: 0.15,
        };

        let c1 = make_claim(1, "db-primary", json!("healthy"), 0.92, 1, ClaimStatus::Active, vec![]);
        let c2 = make_claim(2, "db-primary", json!("degraded"), 0.60, 1, ClaimStatus::Active, vec![]);
        let out_1 = resolve_claims(vec![c2.clone(), c1.clone()], now, &cfg);
        assert_eq!(out_1.resolutions.len(), 1);
        assert!(out_1.disputes.is_empty());
        assert_eq!(out_1.resolutions[0].winning_claim.id, c1.id);
        assert_eq!(out_1.resolutions[0].suppressed_claim_ids, vec![c2.id]);

        let d1 = make_claim(3, "cache-tier", json!("redis-7"), 0.81, 1, ClaimStatus::Active, vec![]);
        let d2 = make_claim(4, "cache-tier", json!("valkey-8"), 0.74, 1, ClaimStatus::Active, vec![]);
        let out_2 = resolve_claims(vec![d2.clone(), d1.clone()], now, &cfg);
        assert!(out_2.resolutions.is_empty());
        assert_eq!(out_2.disputes.len(), 1);
        assert_eq!(out_2.disputes[0].reason_code, DisputeReasonCode::InsufficientMargin);
        assert!(out_2.disputes[0].escalation_required);
        assert_eq!(out_2.disputes[0].competing_claims.len(), 2);
    }

    #[test]
    fn test_signed_override_adjudicates_lower_confidence_winner_and_records_lapsed_override_on_unseen_claim() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig::default();

        let ledger_claim = make_claim(1, "fee_bps", json!(290), 0.82, 2, ClaimStatus::Active, vec![]);
        let msa_claim = make_claim(2, "fee_bps", json!(240), 0.75, 1, ClaimStatus::Active, vec![]);
        let lkey = compute_logical_claim_group_key("tenant-1", "fee_bps", "status", "ops");

        let overridden = vec![OverriddenClaimRef {
            id: ledger_claim.id,
            content_hash: ledger_claim.content_hash,
        }];
        let att_id = Uuid::from_bytes([0xEE; 16]);
        let att_hash = compute_override_attestation_hash(&OverrideHashInput {
            id: att_id,
            tenant_id: "tenant-1",
            scope: "ops",
            claim_group_key: &lkey,
            subject: "fee_bps",
            predicate: "status",
            source_bundle_hash: None,
            winning_claim_id: msa_claim.id,
            winning_claim_content_hash: &msa_claim.content_hash,
            overridden_claims: &overridden,
            adjudicator_id: "tenant-1::cfo",
            justification: "Executed MSA section 4.2 controls over unmigrated ledger",
            version: 1,
            predecessor_id: None,
            created_at: now,
        })
        .unwrap();

        let att = OverrideAttestation {
            id: att_id,
            tenant_id: "tenant-1".to_string(),
            scope: "ops".to_string(),
            claim_group_key: lkey,
            subject: "fee_bps".to_string(),
            predicate: "status".to_string(),
            source_bundle_hash: None,
            winning_claim_id: msa_claim.id,
            winning_claim_content_hash: msa_claim.content_hash,
            overridden_claims: overridden,
            adjudicator_id: "tenant-1::cfo".to_string(),
            justification: "Executed MSA section 4.2 controls over unmigrated ledger".to_string(),
            version: 1,
            predecessor_id: None,
            created_at: now,
            attestation_hash: att_hash,
            evidence_seq_num: 12,
            host_signature: [0xAB; 64],
            client_signature: None,
            client_public_key: None,
        };

        let out_overridden = resolve_claims_with_overrides(
            vec![ledger_claim.clone(), msa_claim.clone()],
            std::slice::from_ref(&att),
            now,
            &cfg,
        );
        assert!(out_overridden.disputes.is_empty());
        assert_eq!(out_overridden.resolutions.len(), 1);
        assert_eq!(out_overridden.resolutions[0].winning_claim.id, msa_claim.id);

        // Even if unseen_claim has 0.99 confidence (>= 0.15 margin), a previously adjudicated group
        // MUST NOT silently overwrite the human override without re-escalating AND recording `lapsed_override`!
        let unseen_claim = make_claim(3, "fee_bps", json!(310), 0.99, 3, ClaimStatus::Active, vec![]);
        let out_reescalated = resolve_claims_with_overrides(
            vec![ledger_claim, msa_claim.clone(), unseen_claim.clone()],
            std::slice::from_ref(&att),
            now,
            &cfg,
        );
        assert!(out_reescalated.resolutions.is_empty());
        assert_eq!(out_reescalated.disputes.len(), 1);
        assert_eq!(out_reescalated.disputes[0].competing_claims.len(), 3);
        let lapsed = out_reescalated.disputes[0]
            .lapsed_override
            .as_ref()
            .expect("must record lapsed_override provenance");
        assert_eq!(lapsed.attestation_id, att_id);
        assert_eq!(lapsed.prior_winning_claim_id, msa_claim.id);
        assert_eq!(lapsed.reopened_by_claim_ids, vec![unseen_claim.id]);
    }

    #[test]
    fn test_exact_float_boundary_082_minus_075_equals_007_resolves() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig {
            min_confidence: 0.70,
            decisiveness_threshold: 0.07,
        };
        let c1 = make_claim(1, "fee", json!(290), 0.82, 2, ClaimStatus::Active, vec![]);
        let c2 = make_claim(2, "fee", json!(240), 0.75, 2, ClaimStatus::Active, vec![]);
        let out = resolve_claims(vec![c1.clone(), c2], now, &cfg);
        assert_eq!(out.resolutions.len(), 1);
        assert_eq!(out.resolutions[0].winning_claim.id, c1.id);
    }

    #[test]
    fn test_same_source_legacy_duplicates_dedup_and_three_way_dispute_keeps_all_candidates() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig::default();

        let mut s1 = make_claim(1, "rate", json!(10), 0.85, 2, ClaimStatus::Active, vec![]);
        s1.source_descriptor = "feed-a".to_string();
        s1.created_at = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 1).unwrap();

        let mut s2 = make_claim(2, "rate", json!(20), 0.85, 2, ClaimStatus::Active, vec![]);
        s2.source_descriptor = "feed-a".to_string();
        s2.created_at = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 2).unwrap();

        let mut s3 = make_claim(3, "rate", json!(20), 0.85, 2, ClaimStatus::Active, vec![]);
        s3.source_descriptor = "feed-a".to_string();
        s3.created_at = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 3).unwrap();

        let out_same_src = resolve_claims(vec![s1, s2, s3.clone()], now, &cfg);
        assert!(out_same_src.disputes.is_empty());
        assert_eq!(out_same_src.resolutions.len(), 1);
        assert_eq!(out_same_src.resolutions[0].winning_claim.id, s3.id);

        let a = make_claim(11, "tier", json!("gold"), 0.84, 2, ClaimStatus::Active, vec![]);
        let b = make_claim(12, "tier", json!("silver"), 0.80, 2, ClaimStatus::Active, vec![]);
        let c = make_claim(13, "tier", json!("bronze"), 0.77, 2, ClaimStatus::Active, vec![]);
        let out_3way = resolve_claims(vec![c, a, b], now, &cfg);
        assert_eq!(out_3way.disputes.len(), 1);
        assert_eq!(out_3way.disputes[0].competing_claims.len(), 3);
    }

    #[test]
    fn test_multi_source_consensus_and_cross_type_conflict() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig::default();

        let a1 = make_claim(21, "bps", json!(290), 0.82, 2, ClaimStatus::Active, vec![]);
        let a2 = make_claim(22, "bps", json!(290), 0.80, 2, ClaimStatus::Active, vec![]);
        let b1 = make_claim(23, "bps", json!(240), 0.72, 2, ClaimStatus::Active, vec![]);
        let out_consensus = resolve_claims(vec![b1, a1, a2], now, &cfg);
        assert_eq!(out_consensus.resolutions.len(), 1);
        assert_eq!(out_consensus.resolutions[0].winning_claim.corroborating_count, 2);

        let mut int_claim = make_claim(31, "fee_bps", json!(290), 0.90, 2, ClaimStatus::Active, vec![]);
        int_claim.claim_group_key = compute_claim_group_key("tenant-1", "fee_bps", "status", "integer", "ops");
        let mut str_claim = make_claim(32, "fee_bps", json!("290"), 0.85, 2, ClaimStatus::Active, vec![]);
        str_claim.claim_group_key = compute_claim_group_key("tenant-1", "fee_bps", "status", "string", "ops");

        let out_type = resolve_claims(vec![int_claim, str_claim], now, &cfg);
        assert!(out_type.resolutions.is_empty());
        assert_eq!(out_type.disputes[0].reason_code, DisputeReasonCode::TypeMismatch);
    }

    #[test]
    fn test_blocking_contradiction_and_expired_filtering() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig::default();

        let c_high = make_claim(10, "region", json!("us-east-1"), 0.95, 2, ClaimStatus::Active, vec![]);
        let c_contra = make_claim(
            11,
            "region",
            json!("eu-west-1"),
            0.72,
            2,
            ClaimStatus::Active,
            vec![c_high.id],
        );
        let mut c_expired = make_claim(12, "region", json!("ap-south-1"), 0.99, 3, ClaimStatus::Expired, vec![]);
        c_expired.valid_to = Some(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap());

        let out = resolve_claims(vec![c_high, c_contra, c_expired.clone()], now, &cfg);
        assert!(out.resolutions.is_empty());
        assert_eq!(out.disputes[0].reason_code, DisputeReasonCode::BlockingContradiction);
        assert_eq!(
            out.excluded_claims,
            vec![(c_expired.id, OmissionReason::LifecycleExpired)]
        );
    }

    #[test]
    fn test_1000_shuffles_bit_for_bit_identical() {
        let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
        let cfg = ResolverConfig::default();

        let base_claims = vec![
            make_claim(1, "subj-a", json!("v1"), 0.92, 2, ClaimStatus::Active, vec![]),
            make_claim(2, "subj-a", json!("v2"), 0.60, 1, ClaimStatus::Active, vec![]),
            make_claim(3, "subj-b", json!("x1"), 0.81, 1, ClaimStatus::Active, vec![]),
            make_claim(4, "subj-b", json!("x2"), 0.74, 1, ClaimStatus::Active, vec![]),
            make_claim(5, "subj-b", json!("x3"), 0.55, 1, ClaimStatus::Active, vec![]),
            make_claim(6, "subj-c", json!("low"), 0.45, 1, ClaimStatus::Active, vec![]),
            make_claim(7, "subj-d", json!("exp"), 0.99, 3, ClaimStatus::Revoked, vec![]),
        ];

        let baseline = resolve_claims(base_claims.clone(), now, &cfg);
        let baseline_res_bytes = to_canonical_bytes(&baseline.resolutions).unwrap();
        let baseline_disp_bytes = to_canonical_bytes(&baseline.disputes).unwrap();
        let baseline_excl_bytes = to_canonical_bytes(&baseline.excluded_claims).unwrap();

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xAC7A_2026);
        for _ in 0..1_000 {
            let mut permuted = base_claims.clone();
            permuted.shuffle(&mut rng);
            let run = resolve_claims(permuted, now, &cfg);
            assert_eq!(to_canonical_bytes(&run.resolutions).unwrap(), baseline_res_bytes);
            assert_eq!(to_canonical_bytes(&run.disputes).unwrap(), baseline_disp_bytes);
            assert_eq!(to_canonical_bytes(&run.excluded_claims).unwrap(), baseline_excl_bytes);
        }
    }

    proptest! {
        #[test]
        fn prop_resolver_permutation_invariance(
            specs in prop::collection::vec((1u8..25u8, 0u8..3u8, 40u16..100u16, 0i32..4i32), 1..15)
        ) {
            let now = Utc.with_ymd_and_hms(2026, 11, 19, 18, 0, 0).unwrap();
            let cfg = ResolverConfig::default();
            let mut claims = Vec::new();
            for (idx, (val_b, subj_idx, conf_pct, prov)) in specs.into_iter().enumerate() {
                let unique_id = (idx as u8) + 1;
                let subj = format!("s-{subj_idx}");
                let val = json!(format!("v-{}", val_b % 3));
                let conf = (conf_pct as f64) / 100.0;
                claims.push(make_claim(unique_id, &subj, val, conf, prov, ClaimStatus::Active, vec![]));
            }
            let mut reversed = claims.clone();
            reversed.reverse();
            let a = resolve_claims(claims, now, &cfg);
            let b = resolve_claims(reversed, now, &cfg);
            prop_assert_eq!(a, b);
        }
    }
}
