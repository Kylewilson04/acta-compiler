use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::hash::encode_length_delimited;

pub fn evidence_signing_preimage_bytes(
    tenant: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    event_hash: &[u8; 32],
) -> Vec<u8> {
    let seq_le = seq_num.to_le_bytes();
    encode_length_delimited(&[
        b"acta:evidence_sig:v1",
        tenant.as_bytes(),
        &seq_le,
        prev_hash.as_slice(),
        event_hash.as_slice(),
    ])
}

pub fn evidence_signing_preimage(
    tenant: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    event_hash: &[u8; 32],
) -> [u8; 32] {
    let preimage = evidence_signing_preimage_bytes(tenant, seq_num, prev_hash, event_hash);
    *blake3::hash(&preimage).as_bytes()
}

pub fn override_signing_preimage_bytes(
    tenant: &str,
    evidence_seq_num: i64,
    attestation_hash: &[u8; 32],
) -> Vec<u8> {
    let seq_le = evidence_seq_num.to_le_bytes();
    encode_length_delimited(&[
        b"acta:override_sig:v1",
        tenant.as_bytes(),
        &seq_le,
        attestation_hash.as_slice(),
    ])
}

pub fn override_signing_preimage(
    tenant: &str,
    evidence_seq_num: i64,
    attestation_hash: &[u8; 32],
) -> [u8; 32] {
    let preimage = override_signing_preimage_bytes(tenant, evidence_seq_num, attestation_hash);
    *blake3::hash(&preimage).as_bytes()
}

pub fn answer_cache_signing_preimage_bytes(
    tenant: &str,
    evidence_seq_num: i64,
    cache_commitment: &[u8; 32],
) -> Vec<u8> {
    let seq_le = evidence_seq_num.to_le_bytes();
    encode_length_delimited(&[
        b"acta:answer_cache_sig:v1",
        tenant.as_bytes(),
        &seq_le,
        cache_commitment.as_slice(),
    ])
}

pub fn answer_cache_signing_preimage(
    tenant: &str,
    evidence_seq_num: i64,
    cache_commitment: &[u8; 32],
) -> [u8; 32] {
    let preimage = answer_cache_signing_preimage_bytes(tenant, evidence_seq_num, cache_commitment);
    *blake3::hash(&preimage).as_bytes()
}

pub fn checkpoint_signing_preimage_bytes(tenant: &str, checkpoint_hash: &[u8; 32]) -> Vec<u8> {
    encode_length_delimited(&[
        b"acta:checkpoint_sig:v1",
        tenant.as_bytes(),
        checkpoint_hash.as_slice(),
    ])
}

pub fn checkpoint_signing_preimage(tenant: &str, checkpoint_hash: &[u8; 32]) -> [u8; 32] {
    let preimage = checkpoint_signing_preimage_bytes(tenant, checkpoint_hash);
    *blake3::hash(&preimage).as_bytes()
}

pub fn witness_anchor_signing_preimage_bytes(
    tenant: &str,
    tree_size: i64,
    checkpoint_hash: &[u8; 32],
) -> Vec<u8> {
    let size_le = tree_size.to_le_bytes();
    encode_length_delimited(&[
        b"acta:witness_sig:v1",
        tenant.as_bytes(),
        &size_le,
        checkpoint_hash.as_slice(),
    ])
}

pub fn witness_anchor_signing_preimage(
    tenant: &str,
    tree_size: i64,
    checkpoint_hash: &[u8; 32],
) -> [u8; 32] {
    let preimage = witness_anchor_signing_preimage_bytes(tenant, tree_size, checkpoint_hash);
    *blake3::hash(&preimage).as_bytes()
}

/// Signs `(tenant, seq_num, prev_hash, event_hash)` with the host's Ed25519 `SigningKey`.
pub fn sign_evidence_entry(
    host_key: &SigningKey,
    tenant: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    event_hash: &[u8; 32],
) -> [u8; 64] {
    let digest = evidence_signing_preimage(tenant, seq_num, prev_hash, event_hash);
    host_key.sign(&digest).to_bytes()
}

/// Strictly verifies an Ed25519 `host_signature` over `(tenant, seq_num, prev_hash, event_hash)`.
pub fn verify_evidence_signature(
    verifying_key: &VerifyingKey,
    tenant: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    event_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    if verifying_key.is_weak() {
        return false;
    }
    let digest = evidence_signing_preimage(tenant, seq_num, prev_hash, event_hash);
    let sig = Signature::from_bytes(signature_bytes);
    verifying_key.verify_strict(&digest, &sig).is_ok()
}

/// Signs `(tenant, evidence_seq_num, attestation_hash)` for a dispute-override attestation.
pub fn sign_override_attestation(
    host_key: &SigningKey,
    tenant: &str,
    evidence_seq_num: i64,
    attestation_hash: &[u8; 32],
) -> [u8; 64] {
    let digest = override_signing_preimage(tenant, evidence_seq_num, attestation_hash);
    host_key.sign(&digest).to_bytes()
}

/// Strictly verifies a host Ed25519 signature over `(tenant, evidence_seq_num, attestation_hash)`.
pub fn verify_override_signature(
    verifying_key: &VerifyingKey,
    tenant: &str,
    evidence_seq_num: i64,
    attestation_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    if verifying_key.is_weak() {
        return false;
    }
    let digest = override_signing_preimage(tenant, evidence_seq_num, attestation_hash);
    let sig = Signature::from_bytes(signature_bytes);
    verifying_key.verify_strict(&digest, &sig).is_ok()
}

/// Signs `(tenant, evidence_seq_num, cache_commitment)` for an Answer Cache receipt (`b"acta:answer_cache_sig:v1"`).
pub fn sign_answer_cache_receipt(
    host_key: &SigningKey,
    tenant: &str,
    evidence_seq_num: i64,
    cache_commitment: &[u8; 32],
) -> [u8; 64] {
    let digest = answer_cache_signing_preimage(tenant, evidence_seq_num, cache_commitment);
    host_key.sign(&digest).to_bytes()
}

/// Strictly verifies a host Ed25519 signature over `(tenant, evidence_seq_num, cache_commitment)`.
pub fn verify_answer_cache_signature(
    verifying_key: &VerifyingKey,
    tenant: &str,
    evidence_seq_num: i64,
    cache_commitment: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    if verifying_key.is_weak() {
        return false;
    }
    let digest = answer_cache_signing_preimage(tenant, evidence_seq_num, cache_commitment);
    let sig = Signature::from_bytes(signature_bytes);
    verifying_key.verify_strict(&digest, &sig).is_ok()
}

/// Signs a `SignedTreeHead` checkpoint (`b"acta:checkpoint_sig:v1"`).
pub fn sign_checkpoint_head(
    host_key: &SigningKey,
    tenant: &str,
    checkpoint_hash: &[u8; 32],
) -> [u8; 64] {
    let digest = checkpoint_signing_preimage(tenant, checkpoint_hash);
    host_key.sign(&digest).to_bytes()
}

/// Strictly verifies a host Ed25519 signature over `(tenant, checkpoint_hash)`.
pub fn verify_checkpoint_signature(
    verifying_key: &VerifyingKey,
    tenant: &str,
    checkpoint_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    if verifying_key.is_weak() {
        return false;
    }
    let digest = checkpoint_signing_preimage(tenant, checkpoint_hash);
    let sig = Signature::from_bytes(signature_bytes);
    verifying_key.verify_strict(&digest, &sig).is_ok()
}

/// Signs `(tenant, tree_size, checkpoint_hash)` with an external witness Ed25519 key (`b"acta:witness_sig:v1"`).
pub fn sign_witness_anchor(
    witness_key: &SigningKey,
    tenant: &str,
    tree_size: i64,
    checkpoint_hash: &[u8; 32],
) -> [u8; 64] {
    let digest = witness_anchor_signing_preimage(tenant, tree_size, checkpoint_hash);
    witness_key.sign(&digest).to_bytes()
}

/// Strictly verifies an external witness Ed25519 cosignature over `(tenant, tree_size, checkpoint_hash)`.
pub fn verify_witness_anchor_signature(
    witness_public_key_bytes: &[u8; 32],
    tenant: &str,
    tree_size: i64,
    checkpoint_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(witness_public_key_bytes) else {
        return false;
    };
    if vk.is_weak() {
        return false;
    }
    let digest = witness_anchor_signing_preimage(tenant, tree_size, checkpoint_hash);
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify_strict(&digest, &sig).is_ok()
}

/// Verifies an optional client Ed25519 signature over a 32-byte digest (`content_hash` or intent hash).
pub fn verify_client_content_signature(
    public_key_bytes: &[u8; 32],
    content_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key_bytes) else {
        return false;
    };
    if vk.is_weak() {
        return false;
    }
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify_strict(content_hash, &sig).is_ok()
}
