use std::sync::OnceLock;

use acta_crypto::compute_omission_list_hash;
use acta_types::{
    ActaError, ActaResult, ContextBudget, DisputeRecord, OmissionReason, OmissionRecord,
    OmittedItem, RankedMemory, ResolutionRecord, SelectedObjectRef, StoredObject,
};
use tiktoken_rs::{cl100k_base, CoreBPE};
use uuid::Uuid;

use crate::formatter::{
    format_dispute_entry, format_dispute_stub, format_intent_compact, format_intent_entry,
    format_intent_stub, format_memory_entry, format_resolution_compact,
    format_resolution_compact_with_why, format_resolution_entry,
    render_context_text_with_rendered_tiers,
};

static CL100K_BPE: OnceLock<Result<CoreBPE, String>> = OnceLock::new();

fn bpe() -> ActaResult<&'static CoreBPE> {
    let res = CL100K_BPE.get_or_init(|| cl100k_base().map_err(|e| e.to_string()));
    res.as_ref()
        .map_err(|e| ActaError::Crypto(format!("tiktoken cl100k_base init error: {e}")))
}

/// Counts tokens using `tiktoken-rs` (`cl100k_base`).
pub fn count_tokens(text: &str) -> ActaResult<usize> {
    if text.is_empty() {
        return Ok(0);
    }
    Ok(bpe()?.encode_with_special_tokens(text).len())
}

/// Encodes `text` using `cl100k_base` and returns `(token_ids, token_bytes_hex)` whose raw byte
/// concatenation equals `text.as_bytes()` byte-for-byte.
pub fn encode_token_spans(text: &str) -> ActaResult<(Vec<u32>, Vec<String>)> {
    if text.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let enc = bpe()?;
    let ranks = enc.encode_with_special_tokens(text);
    let ids: Vec<u32> = ranks.iter().map(|&r| r as u32).collect();
    let pieces: Vec<String> = enc
        ._decode_native_and_split(ranks)
        .map(hex::encode)
        .collect();
    Ok((ids, pieces))
}

#[derive(Debug, Clone)]
pub struct BudgetedSelection {
    pub selected_intents: Vec<StoredObject>,
    pub selected_resolutions: Vec<ResolutionRecord>,
    pub selected_disputes: Vec<DisputeRecord>,
    pub selected_memories: Vec<RankedMemory>,
    pub selected_object_refs: Vec<SelectedObjectRef>,
    pub omission_record: OmissionRecord,
    pub resolved_facts_omitted: usize,
    pub context_text: String,
}

fn joined_fits_budget(
    intent_blocks: &[String],
    dispute_blocks: &[String],
    dispute_weights: &[usize],
    extra_blocks: &[String],
    extra_records: usize,
    budget: ContextBudget,
) -> ActaResult<bool> {
    match budget {
        ContextBudget::Records(limit) => {
            let total_records =
                intent_blocks.len() + dispute_weights.iter().sum::<usize>() + extra_records;
            Ok(total_records <= limit)
        }
        ContextBudget::Bytes(limit) => {
            let count = intent_blocks.len() + dispute_blocks.len() + extra_blocks.len();
            let content_bytes = intent_blocks.iter().map(String::len).sum::<usize>()
                + dispute_blocks.iter().map(String::len).sum::<usize>()
                + extra_blocks.iter().map(String::len).sum::<usize>();
            let total_bytes = content_bytes + count.saturating_sub(1);
            Ok(total_bytes <= limit)
        }
        ContextBudget::Tokens(limit) => {
            let mut joined = String::new();
            for b in intent_blocks
                .iter()
                .chain(dispute_blocks.iter())
                .chain(extra_blocks.iter())
            {
                if !joined.is_empty() {
                    joined.push('\n');
                }
                joined.push_str(b);
            }
            Ok(count_tokens(&joined)? <= limit)
        }
    }
}

pub fn apply_budget_and_omissions(
    intents: Vec<StoredObject>,
    resolutions: Vec<ResolutionRecord>,
    disputes: Vec<DisputeRecord>,
    memories: Vec<RankedMemory>,
    pre_excluded: Vec<(Uuid, OmissionReason)>,
    unfetched_tail_memory_ids: Vec<Uuid>,
    budget: ContextBudget,
    max_inline_omissions: usize,
) -> ActaResult<BudgetedSelection> {
    apply_budget_and_omissions_with_mode(
        intents,
        resolutions,
        disputes,
        memories,
        pre_excluded,
        unfetched_tail_memory_ids,
        budget,
        max_inline_omissions,
        true,
    )
}

/// Applies deterministic tiered budgeting (`v1.6.7+`):
/// - Tier 1a: Non-suppressible Dispute Stubs (`BudgetInsufficientForDisputes` if stubs cannot fit)
/// - Tier 1b (`prioritize_override_resolutions == true`): Signed human/committee override-adjudicated
///   facts reserved ahead of background intents so explicit human adjudications outrank intents under
///   tight budgets (`35..60` tokens), then upgraded (`full -> why(64) -> why(32) -> why(18) -> compact`)
/// - Tier 1c: Scoped Intents (`full -> compact -> stub`)
/// - Tier 2: Standard Resolved Claims (tracking exact `resolved_facts_omitted` whenever any Tier 1b/2
///   resolved fact is omitted under extreme budgets such as `token_budget: 1`)
/// - Tier 3: Ranked Memories
#[allow(clippy::too_many_arguments)]
pub fn apply_budget_and_omissions_with_mode(
    mut intents: Vec<StoredObject>,
    mut resolutions: Vec<ResolutionRecord>,
    mut disputes: Vec<DisputeRecord>,
    mut memories: Vec<RankedMemory>,
    pre_excluded: Vec<(Uuid, OmissionReason)>,
    unfetched_tail_memory_ids: Vec<Uuid>,
    budget: ContextBudget,
    max_inline_omissions: usize,
    prioritize_override_resolutions: bool,
) -> ActaResult<BudgetedSelection> {
    intents.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| b.version.cmp(&a.version))
            .then_with(|| a.id.cmp(&b.id))
    });
    disputes.sort_by(|a, b| a.claim_group_key.cmp(&b.claim_group_key));
    // Prioritize human-adjudicated override facts first within Tier 2, then canonical claim_group_key!
    resolutions.sort_by(|a, b| {
        b.override_attestation
            .is_some()
            .cmp(&a.override_attestation.is_some())
            .then_with(|| a.claim_group_key.cmp(&b.claim_group_key))
    });
    memories.sort_by(|a, b| {
        b.hybrid_score
            .total_cmp(&a.hybrid_score)
            .then_with(|| b.object.importance.total_cmp(&a.object.importance))
            .then_with(|| b.object.created_at.cmp(&a.object.created_at))
            .then_with(|| b.object.version.cmp(&a.object.version))
            .then_with(|| a.object.id.cmp(&b.object.id))
    });

    let had_any_disputes = !disputes.is_empty()
        || pre_excluded
            .iter()
            .any(|(_, r)| *r == OmissionReason::DisputedWithheld);

    let mut all_excluded: Vec<OmittedItem> = pre_excluded
        .into_iter()
        .map(|(id, reason)| OmittedItem { id, reason })
        .collect();

    // 1. Reserve mandatory Tier-1a Dispute Stubs first; hard-error if even stubs cannot fit!
    let mut dispute_blocks: Vec<String> = disputes.iter().map(format_dispute_stub).collect();
    let mut dispute_weights: Vec<usize> = vec![1; disputes.len()];

    if !disputes.is_empty()
        && !joined_fits_budget(&[], &dispute_blocks, &dispute_weights, &[], 0, budget)?
    {
        let joined_stubs = dispute_blocks.join("\n");
        let min_tokens = count_tokens(&joined_stubs)?;
        let min_bytes = joined_stubs.len();
        let min_records = disputes.len();
        return Err(ActaError::BudgetInsufficientForDisputes(format!(
            "requested budget {:?} cannot fit {} mandatory [DISPUTE] stub(s) (minimum required: {} cl100k_base tokens, {} bytes, {} records); refusing to suppress active conflict",
            budget,
            disputes.len(),
            min_tokens,
            min_bytes,
            min_records
        )));
    }

    let mut resolved_facts_omitted: usize = 0;
    let mut reserved_override_resolutions: Vec<ResolutionRecord> = Vec::new();
    let mut reserved_override_blocks: Vec<String> = Vec::new();
    let remaining_resolutions: Vec<ResolutionRecord> = if prioritize_override_resolutions {
        let mut standard = Vec::new();
        for res in resolutions {
            if res.override_attestation.is_some() {
                let min_form = format_resolution_compact(&res)
                    .unwrap_or_else(|| format_resolution_entry(&res));
                reserved_override_blocks.push(min_form);
                if joined_fits_budget(
                    &[],
                    &dispute_blocks,
                    &dispute_weights,
                    &reserved_override_blocks,
                    reserved_override_blocks.len(),
                    budget,
                )? {
                    reserved_override_resolutions.push(res);
                } else {
                    reserved_override_blocks.pop();
                    resolved_facts_omitted += 1;
                    all_excluded.push(OmittedItem {
                        id: res.winning_claim.id,
                        reason: OmissionReason::BudgetExceeded,
                    });
                }
            } else {
                standard.push(res);
            }
        }
        standard
    } else {
        resolutions
    };

    // 2. Pack Intents alongside reserved Dispute Stubs (+ reserved compact Override Facts in v1.6.7+).
    let mut selected_intents = Vec::new();
    let mut selected_intent_blocks = Vec::new();
    for intent in intents {
        let candidates = [
            format_intent_entry(&intent),
            format_intent_compact(&intent),
            format_intent_stub(&intent),
        ];
        let mut fitted = false;
        for candidate_block in candidates {
            selected_intent_blocks.push(candidate_block);
            if joined_fits_budget(
                &selected_intent_blocks,
                &dispute_blocks,
                &dispute_weights,
                &reserved_override_blocks,
                reserved_override_blocks.len(),
                budget,
            )? {
                fitted = true;
                break;
            }
            selected_intent_blocks.pop();
        }
        if fitted {
            selected_intents.push(intent);
        } else {
            all_excluded.push(OmittedItem {
                id: intent.id,
                reason: OmissionReason::BudgetExceeded,
            });
        }
    }

    // 3. Upgrade each Dispute Stub -> Full `[DISPUTE] ... [/DISPUTE]` block whenever budget permits.
    for (idx, dispute) in disputes.iter().enumerate() {
        let full_block = format_dispute_entry(dispute);
        let full_weight = dispute.competing_claims.len().max(1);
        let prev_block = std::mem::replace(&mut dispute_blocks[idx], full_block);
        let prev_weight = std::mem::replace(&mut dispute_weights[idx], full_weight);
        if !joined_fits_budget(
            &selected_intent_blocks,
            &dispute_blocks,
            &dispute_weights,
            &reserved_override_blocks,
            reserved_override_blocks.len(),
            budget,
        )? {
            dispute_blocks[idx] = prev_block;
            dispute_weights[idx] = prev_weight;
        }
    }

    // 3b. Upgrade each reserved compact Override Fact -> richest form (full -> why(64) -> why(32) -> why(18) -> compact).
    for (idx, res) in reserved_override_resolutions.iter().enumerate() {
        let mut richer_forms = vec![format_resolution_entry(res)];
        if let Some(c64) = format_resolution_compact_with_why(res, 64) {
            richer_forms.push(c64);
        }
        if let Some(c32) = format_resolution_compact_with_why(res, 32) {
            richer_forms.push(c32);
        }
        if let Some(c18) = format_resolution_compact_with_why(res, 18) {
            richer_forms.push(c18);
        }
        for candidate_form in richer_forms {
            let prev = std::mem::replace(&mut reserved_override_blocks[idx], candidate_form);
            if joined_fits_budget(
                &selected_intent_blocks,
                &dispute_blocks,
                &dispute_weights,
                &reserved_override_blocks,
                reserved_override_blocks.len(),
                budget,
            )? {
                break;
            }
            reserved_override_blocks[idx] = prev;
        }
    }

    let selected_disputes = disputes;

    let prefix_joined = selected_intent_blocks
        .iter()
        .chain(dispute_blocks.iter())
        .chain(reserved_override_blocks.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let mut has_any_block = !prefix_joined.is_empty();
    let mut used_tokens = if has_any_block {
        count_tokens(&prefix_joined)?
    } else {
        0
    };
    let mut used_bytes = prefix_joined.len();
    let mut used_records = selected_intent_blocks.len()
        + dispute_weights.iter().sum::<usize>()
        + reserved_override_blocks.len();

    let mut try_consume_lower_tier = |rendered: &str, weight: usize| -> ActaResult<bool> {
        let sep = usize::from(has_any_block);
        match budget {
            ContextBudget::Tokens(limit) => {
                if used_tokens + sep + 12 > limit {
                    return Ok(false);
                }
                let t = count_tokens(rendered)?;
                if used_tokens + sep + t > limit {
                    return Ok(false);
                }
                used_tokens += sep + t;
            }
            ContextBudget::Bytes(limit) => {
                if used_bytes + sep + rendered.len() > limit {
                    return Ok(false);
                }
                used_bytes += sep + rendered.len();
            }
            ContextBudget::Records(limit) => {
                if used_records + weight > limit {
                    return Ok(false);
                }
                used_records += weight;
            }
        }
        has_any_block = true;
        Ok(true)
    };

    // 4. Tier 2: Remaining Resolved Claims
    let mut selected_resolutions = reserved_override_resolutions;
    let mut selected_resolution_blocks = reserved_override_blocks;
    for res in remaining_resolutions {
        let mut candidate_forms = vec![format_resolution_entry(&res)];
        if let Some(c64) = format_resolution_compact_with_why(&res, 64) {
            candidate_forms.push(c64);
        }
        if let Some(c32) = format_resolution_compact_with_why(&res, 32) {
            candidate_forms.push(c32);
        }
        if let Some(c18) = format_resolution_compact_with_why(&res, 18) {
            candidate_forms.push(c18);
        }
        if let Some(c_min) = format_resolution_compact(&res) {
            candidate_forms.push(c_min);
        }

        let mut fitted_block = None;
        for block in candidate_forms {
            if try_consume_lower_tier(&block, 1)? {
                fitted_block = Some(block);
                break;
            }
        }

        if let Some(chosen) = fitted_block {
            selected_resolution_blocks.push(chosen);
            selected_resolutions.push(res);
        } else {
            resolved_facts_omitted += 1;
            all_excluded.push(OmittedItem {
                id: res.winning_claim.id,
                reason: OmissionReason::BudgetExceeded,
            });
        }
    }

    // Re-sort selected_resolutions (+ matching blocks) by canonical claim_group_key for deterministic bundle ordering!
    let mut paired: Vec<(ResolutionRecord, String)> = selected_resolutions
        .into_iter()
        .zip(selected_resolution_blocks)
        .collect();
    paired.sort_by(|a, b| a.0.claim_group_key.cmp(&b.0.claim_group_key));
    let (selected_resolutions, selected_resolution_blocks): (Vec<_>, Vec<_>) =
        paired.into_iter().unzip();

    // 5. Tier 3: Ranked Memories
    let mut selected_memories = Vec::new();
    for mem in memories {
        let block = format_memory_entry(&mem);
        if try_consume_lower_tier(&block, 1)? {
            selected_memories.push(mem);
        } else {
            all_excluded.push(OmittedItem {
                id: mem.object.id,
                reason: OmissionReason::BudgetExceeded,
            });
        }
    }

    for tail_id in unfetched_tail_memory_ids {
        all_excluded.push(OmittedItem {
            id: tail_id,
            reason: OmissionReason::BudgetExceeded,
        });
    }

    all_excluded.sort_unstable();
    all_excluded.dedup();

    let total_omitted_count = all_excluded.len();
    let full_excluded_hash = compute_omission_list_hash(&all_excluded)?;
    let inline_items = all_excluded
        .into_iter()
        .take(max_inline_omissions)
        .collect::<Vec<_>>();

    let mut selected_object_refs: Vec<SelectedObjectRef> = selected_intents
        .iter()
        .map(SelectedObjectRef::from)
        .chain(
            selected_memories
                .iter()
                .map(|m| SelectedObjectRef::from(&m.object)),
        )
        .collect();
    selected_object_refs.sort_unstable();

    let context_text = render_context_text_with_rendered_tiers(
        &selected_intent_blocks,
        &dispute_blocks,
        &selected_resolution_blocks,
        &selected_memories,
    );

    let omission_record = OmissionRecord {
        inline_items,
        total_omitted_count,
        full_excluded_hash,
        has_unresolved_claims: had_any_disputes,
    };

    Ok(BudgetedSelection {
        selected_intents,
        selected_resolutions,
        selected_disputes,
        selected_memories,
        selected_object_refs,
        omission_record,
        resolved_facts_omitted,
        context_text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use acta_crypto::compute_object_content_hash;
    use acta_types::{
        ClaimCandidate, DisputeReasonCode, LifecycleStatus, ObjectType, OverrideResolutionRef,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn sample_obj(
        id_b: u8,
        obj_type: ObjectType,
        priority: i32,
        importance: f32,
        text: &str,
    ) -> StoredObject {
        let ts = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 0).unwrap();
        let mut id_bytes = [0u8; 16];
        id_bytes[15] = id_b;
        let mut obj = StoredObject {
            id: Uuid::from_bytes(id_bytes),
            tenant_id: "tenant-1".to_string(),
            obj_type,
            scope: "ops".to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority,
            importance,
            tags: vec![],
            body: json!({ "text": text }),
            content_hash: [0u8; 32],
            embedding: None,
            version: 1,
            predecessor_id: None,
            client_signature: None,
            client_public_key: None,
            written_by: None,
            evidence_seq_num: None,
            created_at: ts,
        };
        obj.content_hash = compute_object_content_hash(&obj).unwrap();
        obj
    }

    fn sample_fee_dispute() -> DisputeRecord {
        let ts = Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 0).unwrap();
        DisputeRecord {
            claim_group_key: [0xAB; 32],
            competing_claims: vec![
                ClaimCandidate {
                    id: Uuid::from_bytes([1; 16]),
                    subject: "merchant:ardyn-pay".to_string(),
                    predicate: "fee_bps".to_string(),
                    object_val: json!(290),
                    object_type: "int".to_string(),
                    confidence: 0.82,
                    source_provenance_class: 2,
                    source_descriptor: "ledger-v1".to_string(),
                    source_commitment: [0x11; 32],
                    content_hash: [0x21; 32],
                    version: 1,
                    created_at: ts,
                    corroborating_count: 1,
                    corroborating_sources: vec![],
                    effective_confidence: None,
                },
                ClaimCandidate {
                    id: Uuid::from_bytes([2; 16]),
                    subject: "merchant:ardyn-pay".to_string(),
                    predicate: "fee_bps".to_string(),
                    object_val: json!(240),
                    object_type: "int".to_string(),
                    confidence: 0.75,
                    source_provenance_class: 2,
                    source_descriptor: "msa-contract".to_string(),
                    source_commitment: [0x12; 32],
                    content_hash: [0x22; 32],
                    version: 1,
                    created_at: ts,
                    corroborating_count: 1,
                    corroborating_sources: vec![],
                    effective_confidence: None,
                },
            ],
            margin: Some(0.07),
            reason_code: DisputeReasonCode::InsufficientMargin,
            escalation_required: true,
            lapsed_override: None,
        }
    }

    #[test]
    fn test_override_justification_snippet_survives_at_80_token_budget() {
        let ts = Utc.with_ymd_and_hms(2026, 11, 22, 6, 0, 0).unwrap();
        let res = ResolutionRecord {
            claim_group_key: [0x11; 32],
            winning_claim: ClaimCandidate {
                id: Uuid::parse_str("e54031bc-4f05-400a-b747-944c92a8d8ba").unwrap(),
                subject: "contract:acme".to_string(),
                predicate: "fee_bps".to_string(),
                object_val: json!(240),
                object_type: "int".to_string(),
                confidence: 0.75,
                source_provenance_class: 2,
                source_descriptor: "signed-msa-2026".to_string(),
                source_commitment: [0x22; 32],
                content_hash: [0x33; 32],
                version: 1,
                created_at: ts,
                corroborating_count: 1,
                corroborating_sources: vec![],
                effective_confidence: None,
            },
            margin: Some(-0.07),
            suppressed_claim_ids: vec![Uuid::from_bytes([9; 16])],
            override_attestation: Some(OverrideResolutionRef {
                attestation_id: Uuid::parse_str("0f07f3e7-4f05-400a-b747-944c92a8d8ba").unwrap(),
                attestation_hash: [0x44; 32],
                adjudicator_id: "kylewilson04::oauth:kylewilson04".to_string(),
                justification: "Signed MSA Schedule A section 4.2 governs over legacy ledger"
                    .to_string(),
                source_bundle_hash: None,
                evidence_seq_num: 41,
                version: 1,
                attested_at: ts,
            }),
        };

        let packed = apply_budget_and_omissions(
            vec![],
            vec![res],
            vec![],
            vec![],
            vec![],
            vec![],
            ContextBudget::Tokens(80),
            25,
        )
        .unwrap();
        let tok = count_tokens(&packed.context_text).unwrap();
        assert!(tok <= 80, "expected <= 80 tokens, got {tok}");
        assert!(
            packed.context_text.contains("why=")
                && packed.context_text.contains("Signed MSA Schedule A"),
            "compact override at budget 80 must preserve why snippet, got: {}",
            packed.context_text
        );
    }

    #[test]
    fn test_budget_drops_tier3_memories_before_tier1_intents_and_injects_disputes() {
        let intent_high = sample_obj(1, ObjectType::Intent, 100, 1.0, "Enforce zero silent drops");
        let intent_low = sample_obj(2, ObjectType::Intent, 50, 0.8, "Prefer concise citations");

        let mem_1 = RankedMemory {
            object: sample_obj(10, ObjectType::Memory, 0, 0.9, "Historical deploy note alpha"),
            hybrid_score: 0.91,
        };
        let mem_2 = RankedMemory {
            object: sample_obj(11, ObjectType::Memory, 0, 0.4, "Historical deploy note beta"),
            hybrid_score: 0.42,
        };

        let dispute = sample_fee_dispute();

        let packed = apply_budget_and_omissions(
            vec![intent_low.clone(), intent_high.clone()],
            vec![],
            vec![dispute],
            vec![mem_1, mem_2],
            vec![],
            vec![],
            ContextBudget::Records(4),
            25,
        )
        .unwrap();

        assert_eq!(packed.selected_intents.len(), 2);
        assert_eq!(packed.selected_intents[0].id, intent_high.id);
        assert_eq!(packed.selected_disputes.len(), 1);
        assert!(packed.selected_memories.is_empty());
        assert_eq!(packed.omission_record.total_omitted_count, 2);
    }

    #[test]
    fn test_acceptance_2_real_v4_uuid_intent_and_dispute_stub_both_survive_at_55_tokens() {
        let ts = Utc.with_ymd_and_hms(2026, 11, 21, 18, 0, 0).unwrap();
        let real_v4_id = Uuid::parse_str("7810c941-a4b2-4c9d-8e1f-998877665544").unwrap();
        let mut intent = StoredObject {
            id: real_v4_id,
            tenant_id: "kylewilson04".to_string(),
            obj_type: ObjectType::Intent,
            scope: "ardyn-launch-audit".to_string(),
            lifecycle_status: LifecycleStatus::Active,
            priority: 100,
            importance: 1.0,
            tags: vec![],
            body: json!({ "instruction": "audit the merchant fee" }),
            content_hash: [0u8; 32],
            embedding: None,
            version: 1,
            predecessor_id: None,
            client_signature: None,
            client_public_key: None,
            written_by: None,
            evidence_seq_num: None,
            created_at: ts,
        };
        intent.content_hash = compute_object_content_hash(&intent).unwrap();

        let mem_1 = RankedMemory {
            object: sample_obj(
                10,
                ObjectType::Memory,
                10,
                0.8,
                "Long historical settlement audit memory alpha that exceeds a 55 token budget",
            ),
            hybrid_score: 0.9,
        };
        let mem_2 = RankedMemory {
            object: sample_obj(
                11,
                ObjectType::Memory,
                10,
                0.7,
                "Second long historical memory beta that also must be evicted under budget pressure",
            ),
            hybrid_score: 0.8,
        };
        let dispute = sample_fee_dispute();

        let packed = apply_budget_and_omissions(
            vec![intent],
            vec![],
            vec![dispute],
            vec![mem_1, mem_2],
            vec![],
            vec![],
            ContextBudget::Tokens(55),
            25,
        )
        .unwrap();

        let tok = count_tokens(&packed.context_text).unwrap();
        assert!(tok <= 55);
        assert_eq!(packed.selected_intents.len(), 1);
        assert_eq!(packed.selected_disputes.len(), 1);
    }

    #[test]
    fn test_acceptance_3_starvation_budget_returns_hard_error_when_stub_cannot_fit() {
        let dispute = sample_fee_dispute();
        for starvation_budget in [
            ContextBudget::Tokens(10),
            ContextBudget::Bytes(20),
            ContextBudget::Records(0),
        ] {
            let err = apply_budget_and_omissions(
                vec![],
                vec![],
                vec![dispute.clone()],
                vec![],
                vec![],
                vec![],
                starvation_budget,
                25,
            )
            .unwrap_err();
            assert!(matches!(err, ActaError::BudgetInsufficientForDisputes(_)));
        }
    }

    #[test]
    fn test_acceptance_4_small_budget_without_disputes_succeeds_cleanly() {
        let intent = sample_obj(1, ObjectType::Intent, 100, 1.0, "Keep strict audit trail");
        let packed = apply_budget_and_omissions(
            vec![intent.clone()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            ContextBudget::Tokens(5),
            25,
        )
        .unwrap();
        assert!(packed.selected_intents.is_empty());
        assert_eq!(packed.omission_record.total_omitted_count, 1);
    }

    #[test]
    fn test_token_budget_enforcement_and_bounded_inline_omissions() {
        let intent = sample_obj(1, ObjectType::Intent, 10, 1.0, "Keep strict audit trail");
        let mut memories = Vec::new();
        for i in 0..30u8 {
            memories.push(RankedMemory {
                object: sample_obj(
                    i + 10,
                    ObjectType::Memory,
                    0,
                    0.5,
                    "Memory payload with multiple tokens to trigger cl100k_base cutoff quickly",
                ),
                hybrid_score: 1.0 - (i as f64) * 0.01,
            });
        }

        let packed = apply_budget_and_omissions(
            vec![intent],
            vec![],
            vec![],
            memories,
            vec![],
            vec![],
            ContextBudget::Tokens(60),
            25,
        )
        .unwrap();

        assert_eq!(packed.selected_intents.len(), 1);
        assert!(count_tokens(&packed.context_text).unwrap() <= 60);
        assert_eq!(packed.omission_record.inline_items.len(), 25);
    }

    #[test]
    fn test_encode_token_spans_exact_utf8_partition() {
        let sample = "[FACT] contract:epsilon.fee_bps = 240 (conf=0.7500, override_by=kylewilson04::oauth:kylewilson04, why=\"Signed Master Services Agreement v2026 Schedule A section 4.2 g\u{2026}\")";
        let cnt = count_tokens(sample).unwrap();
        let (ids, hex_pieces) = encode_token_spans(sample).unwrap();
        assert_eq!(ids.len(), cnt);
        assert_eq!(hex_pieces.len(), cnt);
        let mut rebuilt = Vec::new();
        for piece in &hex_pieces {
            let raw = hex::decode(piece).unwrap();
            assert!(!raw.is_empty());
            rebuilt.extend_from_slice(&raw);
        }
        assert_eq!(rebuilt, sample.as_bytes());
    }
}
