use acta_types::{ActaError, ActaResult};

use crate::hash::hash_length_delimited;

/// Domain-separated RFC 6962 empty-tree hash (`tree_size == 0`).
pub fn merkle_empty_root() -> [u8; 32] {
    hash_length_delimited(&[b"acta:merkle_empty:v1"])
}

/// Domain-separated leaf hash binding `(seq_num, event_hash)` at 0-based index `seq_num - 1`.
pub fn merkle_leaf_hash(seq_num: i64, event_hash: &[u8; 32]) -> [u8; 32] {
    let seq_le = seq_num.to_le_bytes();
    hash_length_delimited(&[b"acta:merkle_leaf:v1", &seq_le, event_hash])
}

/// Domain-separated interior node hash over `(left_child, right_child)`.
pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_length_delimited(&[b"acta:merkle_node:v1", left, right])
}

#[inline]
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Computes the RFC 6962 Merkle Tree Hash `MTH(D[0..n])` over pre-hashed leaves.
pub fn compute_merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => merkle_empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = compute_merkle_root_from_leaves(&leaves[..k]);
            let right = compute_merkle_root_from_leaves(&leaves[k..]);
            merkle_node_hash(&left, &right)
        }
    }
}

fn inclusion_path_slice(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if index < k {
        inclusion_path_slice(&leaves[..k], index, out);
        out.push(compute_merkle_root_from_leaves(&leaves[k..]));
    } else {
        inclusion_path_slice(&leaves[k..], index - k, out);
        out.push(compute_merkle_root_from_leaves(&leaves[..k]));
    }
}

/// Computes the `O(log N)` RFC 6962 audit path `PATH(leaf_index, D[0..n])` (`0 <= leaf_index < n`).
pub fn compute_merkle_inclusion_proof(
    leaves: &[[u8; 32]],
    leaf_index: usize,
) -> ActaResult<Vec<[u8; 32]>> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return Err(ActaError::Validation(format!(
            "leaf_index {leaf_index} out of bounds for tree_size {}",
            leaves.len()
        )));
    }
    let mut path = Vec::with_capacity(24);
    inclusion_path_slice(leaves, leaf_index, &mut path);
    Ok(path)
}

/// Verifies an `O(log N)` RFC 6962 / RFC 9162 §2.1.3.2 inclusion proof for `(seq_num, event_hash)`
/// against `(tree_size, expected_root)`.
pub fn verify_merkle_inclusion_proof(
    seq_num: i64,
    event_hash: &[u8; 32],
    tree_size: i64,
    audit_path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    if seq_num < 1 || tree_size < 1 || seq_num > tree_size {
        return false;
    }
    let mut r = merkle_leaf_hash(seq_num, event_hash);
    if tree_size == 1 {
        return audit_path.is_empty() && &r == expected_root;
    }

    let mut fn_idx = (seq_num - 1) as u64;
    let mut sn = (tree_size - 1) as u64;

    for sibling in audit_path {
        if sn == 0 {
            return false;
        }
        if (fn_idx & 1) == 1 || fn_idx == sn {
            r = merkle_node_hash(sibling, &r);
            while (fn_idx & 1) == 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            r = merkle_node_hash(&r, sibling);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    sn == 0 && &r == expected_root
}

fn subproof_slice(
    m: usize,
    leaves: &[[u8; 32]],
    is_complete_subtree: bool,
    out: &mut Vec<[u8; 32]>,
) {
    let n = leaves.len();
    if m == n {
        if !is_complete_subtree {
            out.push(compute_merkle_root_from_leaves(leaves));
        }
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if m <= k {
        subproof_slice(m, &leaves[..k], is_complete_subtree, out);
        out.push(compute_merkle_root_from_leaves(&leaves[k..]));
    } else {
        subproof_slice(m - k, &leaves[k..], false, out);
        out.push(compute_merkle_root_from_leaves(&leaves[..k]));
    }
}

/// Computes the `O(log N)` RFC 6962 consistency proof `PROOF(first_size, D[0..second_size])`
/// proving that `D[0..second_size]` is an append-only extension of `D[0..first_size]`.
pub fn compute_merkle_consistency_proof(
    leaves: &[[u8; 32]],
    first_size: usize,
    second_size: usize,
) -> ActaResult<Vec<[u8; 32]>> {
    if first_size == 0 || first_size > second_size || second_size > leaves.len() {
        return Err(ActaError::Validation(format!(
            "invalid consistency proof bounds: first={first_size}, second={second_size}, available={}",
            leaves.len()
        )));
    }
    if first_size == second_size {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(24);
    subproof_slice(first_size, &leaves[..second_size], true, &mut out);
    Ok(out)
}

/// Verifies an `O(log N)` RFC 6962 / RFC 9162 §2.1.4.2 consistency proof between two checkpoints
/// `(first_size, first_root)` and `(second_size, second_root)`.
pub fn verify_merkle_consistency_proof(
    first_size: i64,
    first_root: &[u8; 32],
    second_size: i64,
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first_size < 1 || second_size < first_size {
        return false;
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }
    if proof.is_empty() {
        return false;
    }

    let first_u = first_size as u64;
    let is_pow2 = (first_u & (first_u - 1)) == 0;

    let mut chain: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if is_pow2 {
        chain.push(*first_root);
    }
    chain.extend_from_slice(proof);

    let mut fn_idx = first_u - 1;
    let mut sn = (second_size as u64) - 1;
    while (fn_idx & 1) == 1 {
        fn_idx >>= 1;
        sn >>= 1;
    }

    let mut fr = chain[0];
    let mut sr = chain[0];

    for node in &chain[1..] {
        if sn == 0 {
            return false;
        }
        if (fn_idx & 1) == 1 || fn_idx == sn {
            fr = merkle_node_hash(node, &fr);
            sr = merkle_node_hash(node, &sr);
            while (fn_idx & 1) == 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            sr = merkle_node_hash(&sr, node);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    sn == 0 && &fr == first_root && &sr == second_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_events(n: usize) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut events = Vec::with_capacity(n);
        let mut leaves = Vec::with_capacity(n);
        for i in 0..n {
            let seq = (i + 1) as i64;
            let ev = hash_length_delimited(&[b"test:ev", &seq.to_le_bytes()]);
            events.push(ev);
            leaves.push(merkle_leaf_hash(seq, &ev));
        }
        (events, leaves)
    }

    #[test]
    fn test_rfc6962_inclusion_proofs_across_all_tree_sizes_1_to_65() {
        let (events, leaves) = sample_events(65);
        for size in 1..=65usize {
            let root = compute_merkle_root_from_leaves(&leaves[..size]);
            for idx in 0..size {
                let seq = (idx + 1) as i64;
                let path = compute_merkle_inclusion_proof(&leaves[..size], idx).unwrap();
                assert!(
                    path.len() <= 7,
                    "audit_path for size={size} must be O(log2 N), got {}",
                    path.len()
                );
                assert!(
                    verify_merkle_inclusion_proof(seq, &events[idx], size as i64, &path, &root),
                    "inclusion proof failed for seq={seq} in tree_size={size}"
                );

                // Wrong seq_num with same event_hash must fail!
                if size > 1 {
                    let wrong_seq = if seq < size as i64 { seq + 1 } else { seq - 1 };
                    assert!(!verify_merkle_inclusion_proof(
                        wrong_seq,
                        &events[idx],
                        size as i64,
                        &path,
                        &root
                    ));
                }

                // Single-bit mutation in event_hash or path must fail!
                let mut bad_ev = events[idx];
                bad_ev[0] ^= 0x01;
                assert!(!verify_merkle_inclusion_proof(
                    seq,
                    &bad_ev,
                    size as i64,
                    &path,
                    &root
                ));
                if !path.is_empty() {
                    let mut bad_path = path.clone();
                    bad_path[0][31] ^= 0x80;
                    assert!(!verify_merkle_inclusion_proof(
                        seq,
                        &events[idx],
                        size as i64,
                        &bad_path,
                        &root
                    ));
                }
            }
        }
    }

    #[test]
    fn test_rfc6962_consistency_proofs_across_all_pairs_1_to_40() {
        let (_events, leaves) = sample_events(40);
        for second in 1..=40usize {
            let second_root = compute_merkle_root_from_leaves(&leaves[..second]);
            for first in 1..=second {
                let first_root = compute_merkle_root_from_leaves(&leaves[..first]);
                let proof = compute_merkle_consistency_proof(&leaves, first, second).unwrap();
                assert!(
                    verify_merkle_consistency_proof(
                        first as i64,
                        &first_root,
                        second as i64,
                        &second_root,
                        &proof
                    ),
                    "consistency proof failed for first={first} -> second={second}"
                );

                // Rewritten history at `first` MUST fail consistency verification against `second_root`!
                if first < second {
                    let mut rewritten_first = first_root;
                    rewritten_first[7] ^= 0x01;
                    assert!(!verify_merkle_consistency_proof(
                        first as i64,
                        &rewritten_first,
                        second as i64,
                        &second_root,
                        &proof
                    ));
                }
            }
        }
    }
}
