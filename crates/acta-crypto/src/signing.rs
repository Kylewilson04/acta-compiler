use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::hash::hash_length_delimited;

fn evidence_signing_preimage(
    tenant: &str,
    seq_num: i64,
    prev_hash: &[u8; 32],
    event_hash: &[u8; 32],
) -> [u8; 32] {
    let seq_le = seq_num.to_le_bytes();
    hash_length_delimited(&[
        b"acta:evidence_sig:v1",
        tenant.as_bytes(),
        &seq_le,
        prev_hash.as_slice(),
        event_hash.as_slice(),
    ])
}

fn override_signing_preimage(
    tenant: &str,
    evidence_seq_num: i64,
    attestation_hash: &[u8; 32],
) -> [u8; 32] {
    let seq_le = evidence_seq_num.to_le_bytes();
    hash_length_delimited(&[
        b"acta:override_sig:v1",
        tenant.as_bytes(),
        &seq_le,
        attestation_hash.as_slice(),
    ])
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

/// Verifies an optional client Ed25519 signature over an ingested object/claim/override `content_hash`.
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
