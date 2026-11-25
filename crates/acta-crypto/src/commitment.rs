use acta_types::{
    SCHEMA_VERSION_V1, SCHEMA_VERSION_V2, STATE_COMMITMENT_DOMAIN_V2, SUB_COMMITMENT_DOMAIN_V2,
};

use crate::hash::hash_length_delimited;

/// Returns `true` when `schema_ver` selects the `v1.7.3+` domain-tagged `v2` commitment scheme
/// (`b"acta:sub_commitment:v2"` and `b"acta:state:v2"`), keeping `v1` verifiable for `seq 1..219`.
pub fn is_v2_state_schema(schema_ver: &str) -> bool {
    matches!(
        schema_ver,
        "acta-context-bundle/v2" | "acta-state-rebuild-archive/v2" | "v2"
    )
}

/// Canonical `ContextBundle.schema_version` corresponding to a `StateRebuildArchive` or bundle schema string.
pub fn canonical_bundle_schema_for_state(schema_ver: &str) -> &'static str {
    if is_v2_state_schema(schema_ver) {
        SCHEMA_VERSION_V2
    } else {
        SCHEMA_VERSION_V1
    }
}

/// Legacy `v1` sub-commitment (`seq 1..219`): sorts 32-byte hashes ascending and hashes `LD[h_0, ...]`
/// with no domain prefix (`empty = BLAKE3(b"") = af1349b9...`).
pub fn compute_sub_commitment(sorted_or_unsorted_hashes: &[[u8; 32]]) -> [u8; 32] {
    let len_le = 32u64.to_le_bytes();

    if sorted_or_unsorted_hashes.windows(2).all(|w| w[0] <= w[1]) {
        let mut hasher = blake3::Hasher::new();
        for h in sorted_or_unsorted_hashes {
            hasher.update(&len_le);
            hasher.update(h);
        }
        return *hasher.finalize().as_bytes();
    }

    let mut sorted = sorted_or_unsorted_hashes.to_vec();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for h in &sorted {
        hasher.update(&len_le);
        hasher.update(h);
    }
    *hasher.finalize().as_bytes()
}

/// Domain-tagged `v2` sub-commitment (`v1.7.3+`, `b"acta:sub_commitment:v2"`):
/// sorts 32-byte hashes ascending and hashes `LD[b"acta:sub_commitment:v2", h_0, ...]`.
pub fn compute_sub_commitment_v2(sorted_or_unsorted_hashes: &[[u8; 32]]) -> [u8; 32] {
    let dom = SUB_COMMITMENT_DOMAIN_V2.as_bytes();
    let dom_len_le = (dom.len() as u64).to_le_bytes();
    let len_le = 32u64.to_le_bytes();

    if sorted_or_unsorted_hashes.windows(2).all(|w| w[0] <= w[1]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&dom_len_le);
        hasher.update(dom);
        for h in sorted_or_unsorted_hashes {
            hasher.update(&len_le);
            hasher.update(h);
        }
        return *hasher.finalize().as_bytes();
    }

    let mut sorted = sorted_or_unsorted_hashes.to_vec();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&dom_len_le);
    hasher.update(dom);
    for h in &sorted {
        hasher.update(&len_le);
        hasher.update(h);
    }
    *hasher.finalize().as_bytes()
}

/// Selects `compute_sub_commitment_v2` (`"acta-context-bundle/v2"`) or legacy `v1` (`"acta-context-bundle/v1"`).
pub fn compute_sub_commitment_for_schema(
    schema_ver: &str,
    sorted_or_unsorted_hashes: &[[u8; 32]],
) -> [u8; 32] {
    if is_v2_state_schema(schema_ver) {
        compute_sub_commitment_v2(sorted_or_unsorted_hashes)
    } else {
        compute_sub_commitment(sorted_or_unsorted_hashes)
    }
}

/// Computes `state_commitment` selected by `schema_ver`:
/// - `v2` (`"acta-context-bundle/v2"` / `"acta-state-rebuild-archive/v2"`): 8-part domain-tagged `b"acta:state:v2"`.
/// - `v1` (`"acta-context-bundle/v1"` / `"acta-state-rebuild-archive/v1"`): 7-part legacy layout for `seq 1..219`.
pub fn compute_state_commitment(
    schema_ver: &str,
    tenant: &str,
    scope: &str,
    intent_root: &[u8; 32],
    knowledge_root: &[u8; 32],
    memory_root: &[u8; 32],
    permission_root: &[u8; 32],
) -> [u8; 32] {
    if is_v2_state_schema(schema_ver) {
        let bundle_schema = if schema_ver == "acta-state-rebuild-archive/v2" || schema_ver == "v2" {
            SCHEMA_VERSION_V2
        } else {
            schema_ver
        };
        hash_length_delimited(&[
            STATE_COMMITMENT_DOMAIN_V2.as_bytes(),
            bundle_schema.as_bytes(),
            tenant.as_bytes(),
            scope.as_bytes(),
            intent_root.as_slice(),
            knowledge_root.as_slice(),
            memory_root.as_slice(),
            permission_root.as_slice(),
        ])
    } else {
        let bundle_schema = if schema_ver == "acta-state-rebuild-archive/v1" || schema_ver == "v1" {
            SCHEMA_VERSION_V1
        } else {
            schema_ver
        };
        hash_length_delimited(&[
            bundle_schema.as_bytes(),
            tenant.as_bytes(),
            scope.as_bytes(),
            intent_root.as_slice(),
            knowledge_root.as_slice(),
            memory_root.as_slice(),
            permission_root.as_slice(),
        ])
    }
}

/// Legacy `v1` `dependency_commitment` over evaluated object and claim hashes.
pub fn compute_dependency_commitment(evaluated_object_hashes: &[[u8; 32]]) -> [u8; 32] {
    compute_sub_commitment(evaluated_object_hashes)
}

/// Schema-aware `dependency_commitment` (`v2` domain-tagged `b"acta:sub_commitment:v2"` vs `v1`).
pub fn compute_dependency_commitment_for_schema(
    schema_ver: &str,
    evaluated_object_hashes: &[[u8; 32]],
) -> [u8; 32] {
    compute_sub_commitment_for_schema(schema_ver, evaluated_object_hashes)
}
