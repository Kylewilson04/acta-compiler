use crate::hash::hash_length_delimited;

/// Sorts 32-byte hashes lexicographically and hashes them with 8-byte LE length delimiters.
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

/// Computes the global `state_commitment` binding schema version, tenant, scope,
/// intent root, knowledge root, memory root, and permission root.
pub fn compute_state_commitment(
    schema_ver: &str,
    tenant: &str,
    scope: &str,
    intent_root: &[u8; 32],
    knowledge_root: &[u8; 32],
    memory_root: &[u8; 32],
    permission_root: &[u8; 32],
) -> [u8; 32] {
    hash_length_delimited(&[
        schema_ver.as_bytes(),
        tenant.as_bytes(),
        scope.as_bytes(),
        intent_root.as_slice(),
        knowledge_root.as_slice(),
        memory_root.as_slice(),
        permission_root.as_slice(),
    ])
}

/// Computes `dependency_commitment` over all evaluated object and claim hashes.
pub fn compute_dependency_commitment(evaluated_object_hashes: &[[u8; 32]]) -> [u8; 32] {
    compute_sub_commitment(evaluated_object_hashes)
}
