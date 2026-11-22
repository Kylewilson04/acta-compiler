use acta_types::{ActaError, ActaResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::to_canonical_bytes;
use crate::hash::hash_length_delimited;

pub const TENANT_TOKEN_PREFIX: &str = "acta_tk_v1:";

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derives a domain-separated 32-byte MAC key from the master `ACTA_API_KEY`.
pub fn derive_tenant_mac_key(master_api_key: &str) -> [u8; 32] {
    hash_length_delimited(&[
        b"acta:tenant_mac_key:v1",
        master_api_key.trim().as_bytes(),
    ])
}

/// Derives a domain-separated 32-byte MAC key for stateless OAuth 2.1 envelopes.
pub fn derive_oauth_envelope_key(secret: &str, domain: &[u8]) -> [u8; 32] {
    hash_length_delimited(&[b"acta:oauth_envelope_key:v1", domain, secret.trim().as_bytes()])
}

fn build_length_delimited_preimage(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| 8 + p.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for p in parts {
        buf.extend_from_slice(&(p.len() as u64).to_le_bytes());
        buf.extend_from_slice(p);
    }
    buf
}

fn build_tenant_token_preimage(tenant_id: &str) -> Vec<u8> {
    build_length_delimited_preimage(&[b"acta:tenant_token:v1", tenant_id.as_bytes()])
}

fn build_user_tenant_token_preimage(tenant_id: &str, github_login: &str) -> Vec<u8> {
    build_length_delimited_preimage(&[
        b"acta:tenant_user_token:v2",
        tenant_id.as_bytes(),
        github_login.as_bytes(),
    ])
}

/// Normalizes a GitHub organization login or username into a clean Acta `tenant_id` slug (`[a-z0-9._-]`).
pub fn normalize_github_slug(raw: &str) -> ActaResult<String> {
    let trimmed = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_dash = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let clean = out.trim_matches('-').to_string();
    if clean.is_empty() || clean.len() > 100 {
        return Err(ActaError::Validation(
            "GitHub organization/user slug must be 1..=100 valid characters".to_string(),
        ));
    }
    Ok(clean)
}

/// Computes RFC 7636 OAuth 2.1 PKCE `S256` challenge: `BASE64URL_NO_PAD(SHA256(ASCII(code_verifier)))`.
pub fn compute_pkce_s256(code_verifier: &str) -> ActaResult<String> {
    let v = code_verifier.trim();
    if !(43..=128).contains(&v.len()) {
        return Err(ActaError::Validation(
            "PKCE code_verifier must be 43..=128 characters per RFC 7636".to_string(),
        ));
    }
    if !v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(ActaError::Validation(
            "PKCE code_verifier contains characters outside RFC 7636 unreserved set".to_string(),
        ));
    }
    let digest = Sha256::digest(v.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Constant-time verification of RFC 7636 PKCE `S256` `code_verifier` against `expected_challenge`.
pub fn verify_pkce_s256(code_verifier: &str, expected_challenge: &str) -> bool {
    let Ok(computed) = compute_pkce_s256(code_verifier) else {
        return false;
    };
    constant_time_eq_slice(computed.as_bytes(), expected_challenge.trim().as_bytes())
}

/// Mints a stateless Keyed-BLAKE3 signed envelope (`<prefix>.<base64url_jcs>.<64_hex_mac>`).
pub fn mint_signed_envelope<T: Serialize>(
    secret: &str,
    prefix: &str,
    domain: &[u8],
    payload: &T,
) -> ActaResult<String> {
    if secret.trim().is_empty() {
        return Err(ActaError::Validation(
            "OAuth envelope secret must be non-empty".to_string(),
        ));
    }
    let jcs_bytes = to_canonical_bytes(payload)?;
    let b64 = URL_SAFE_NO_PAD.encode(&jcs_bytes);
    let key_32 = derive_oauth_envelope_key(secret, domain);
    let preimage = build_length_delimited_preimage(&[domain, prefix.as_bytes(), &jcs_bytes]);
    let mac = blake3::keyed_hash(&key_32, &preimage);
    Ok(format!("{prefix}.{b64}.{}", hex::encode(mac.as_bytes())))
}

/// Verifies a stateless Keyed-BLAKE3 signed envelope in constant time and deserializes its payload.
pub fn verify_signed_envelope<T: DeserializeOwned>(
    secret: &str,
    prefix: &str,
    domain: &[u8],
    token: &str,
) -> Result<T, String> {
    if secret.trim().is_empty() {
        return Err("OAuth envelope secret is empty".to_string());
    }
    let expected_head = format!("{prefix}.");
    let rest = token
        .trim()
        .strip_prefix(&expected_head)
        .ok_or_else(|| format!("token does not start with {expected_head}"))?;
    let (b64_part, mac_hex) = rest
        .rsplit_once('.')
        .ok_or_else(|| "malformed signed envelope structure".to_string())?;
    let raw_bytes = URL_SAFE_NO_PAD
        .decode(b64_part)
        .map_err(|_| "invalid base64url payload in signed envelope".to_string())?;
    let mac_vec =
        hex::decode(mac_hex).map_err(|_| "invalid hex MAC in signed envelope".to_string())?;
    let provided_mac: [u8; 32] = mac_vec
        .try_into()
        .map_err(|_| "signed envelope MAC must be 32 bytes".to_string())?;

    let key_32 = derive_oauth_envelope_key(secret, domain);
    let preimage = build_length_delimited_preimage(&[domain, prefix.as_bytes(), &raw_bytes]);
    let expected_mac = *blake3::keyed_hash(&key_32, &preimage).as_bytes();
    if !constant_time_eq_32(&expected_mac, &provided_mac) {
        return Err("invalid or tampered signed envelope MAC".to_string());
    }
    serde_json::from_slice(&raw_bytes)
        .map_err(|e| format!("failed to decode verified envelope JSON: {e}"))
}

fn validate_token_segment(label: &str, val: &str) -> ActaResult<()> {
    if val.is_empty() || val.len() > 128 {
        return Err(ActaError::Validation(format!(
            "{label} must be 1..=128 bytes"
        )));
    }
    if val
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == ':')
    {
        return Err(ActaError::Validation(format!(
            "{label} in token cannot contain whitespace, control characters, or ':'"
        )));
    }
    Ok(())
}

/// Mints a stateless, cryptographically tenant-bound API key (`acta_tk_v1:<tenant_id>:<64_hex_mac>`).
pub fn mint_tenant_api_key(master_api_key: &str, tenant_id: &str) -> ActaResult<String> {
    let master_clean = master_api_key.trim();
    if master_clean.is_empty() {
        return Err(ActaError::Validation(
            "master_api_key must be non-empty".to_string(),
        ));
    }
    let tenant_clean = tenant_id.trim();
    validate_token_segment("tenant_id", tenant_clean)?;

    let key_32 = derive_tenant_mac_key(master_clean);
    let preimage = build_tenant_token_preimage(tenant_clean);
    let mac = blake3::keyed_hash(&key_32, &preimage);
    Ok(format!(
        "{TENANT_TOKEN_PREFIX}{tenant_clean}:{}",
        hex::encode(mac.as_bytes())
    ))
}

/// Mints a stateless OAuth principal-bound token (`acta_tk_v1:<tenant_id>:<github_login>:<64_hex_mac>`)
/// binding BOTH the locked organization vault AND the verified GitHub OAuth login (`v1.6+`).
pub fn mint_user_tenant_api_key(
    master_api_key: &str,
    tenant_id: &str,
    github_login: &str,
) -> ActaResult<String> {
    let master_clean = master_api_key.trim();
    if master_clean.is_empty() {
        return Err(ActaError::Validation(
            "master_api_key must be non-empty".to_string(),
        ));
    }
    let tenant_clean = tenant_id.trim();
    let user_clean = normalize_github_slug(github_login)?;
    validate_token_segment("tenant_id", tenant_clean)?;
    validate_token_segment("github_login", &user_clean)?;

    let key_32 = derive_tenant_mac_key(master_clean);
    let preimage = build_user_tenant_token_preimage(tenant_clean, &user_clean);
    let mac = blake3::keyed_hash(&key_32, &preimage);
    Ok(format!(
        "{TENANT_TOKEN_PREFIX}{tenant_clean}:{user_clean}:{}",
        hex::encode(mac.as_bytes())
    ))
}

/// Verifies either a 2-segment `acta_tk_v1:<tenant>:<mac>` token or a 3-segment OAuth user-bound
/// `acta_tk_v1:<tenant>:<github_login>:<mac>` token in constant time, returning `(tenant_id, Option<github_login>)`.
pub fn verify_tenant_api_key_with_principal(
    master_api_key: &str,
    token: &str,
) -> Result<(String, Option<String>), String> {
    let master_clean = master_api_key.trim();
    if master_clean.is_empty() {
        return Err("server master ACTA_API_KEY is not configured".to_string());
    }
    let rest = token
        .trim()
        .strip_prefix(TENANT_TOKEN_PREFIX)
        .ok_or_else(|| "token does not start with acta_tk_v1:".to_string())?;

    let parts: Vec<&str> = rest.split(':').collect();
    match parts.as_slice() {
        [tenant_part, mac_hex] => {
            validate_token_segment("tenant_id", tenant_part).map_err(|e| e.to_string())?;
            let mac_vec = hex::decode(mac_hex)
                .map_err(|_| "invalid hex MAC in acta_tk_v1 token".to_string())?;
            let provided_mac: [u8; 32] = mac_vec
                .try_into()
                .map_err(|_| "acta_tk_v1 MAC must be 32 bytes (64 hex chars)".to_string())?;

            let key_32 = derive_tenant_mac_key(master_clean);
            let preimage = build_tenant_token_preimage(tenant_part);
            let expected_mac = *blake3::keyed_hash(&key_32, &preimage).as_bytes();
            if !constant_time_eq_32(&expected_mac, &provided_mac) {
                return Err("invalid or forged tenant-bound API key MAC".to_string());
            }
            Ok(((*tenant_part).to_string(), None))
        }
        [tenant_part, user_part, mac_hex] => {
            validate_token_segment("tenant_id", tenant_part).map_err(|e| e.to_string())?;
            validate_token_segment("github_login", user_part).map_err(|e| e.to_string())?;
            let mac_vec = hex::decode(mac_hex)
                .map_err(|_| "invalid hex MAC in acta_tk_v1 user token".to_string())?;
            let provided_mac: [u8; 32] = mac_vec
                .try_into()
                .map_err(|_| "acta_tk_v1 MAC must be 32 bytes (64 hex chars)".to_string())?;

            let key_32 = derive_tenant_mac_key(master_clean);
            let preimage = build_user_tenant_token_preimage(tenant_part, user_part);
            let expected_mac = *blake3::keyed_hash(&key_32, &preimage).as_bytes();
            if !constant_time_eq_32(&expected_mac, &provided_mac) {
                return Err("invalid or forged user-bound API key MAC".to_string());
            }
            Ok(((*tenant_part).to_string(), Some((*user_part).to_string())))
        }
        _ => Err("malformed acta_tk_v1 token structure".to_string()),
    }
}

/// Verifies a stateless `acta_tk_v1` token in constant time and returns the bound `tenant_id`.
pub fn verify_tenant_api_key(master_api_key: &str, token: &str) -> Result<String, String> {
    verify_tenant_api_key_with_principal(master_api_key, token).map(|(t, _)| t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleEnvelope {
        tenant: String,
        exp: i64,
    }

    #[test]
    fn test_mint_and_verify_tenant_and_user_bound_api_keys() {
        let master = "acta_live_master_secret_998877";
        let key_a = mint_tenant_api_key(master, "ardyn-core").unwrap();
        let key_b = mint_tenant_api_key(master, "client-acme").unwrap();
        assert_ne!(key_a, key_b);
        assert!(key_a.starts_with("acta_tk_v1:ardyn-core:"));
        assert_eq!(
            verify_tenant_api_key_with_principal(master, &key_a).unwrap(),
            ("ardyn-core".to_string(), None)
        );

        let user_key = mint_user_tenant_api_key(master, "ardyn-core", "KyleWilson04").unwrap();
        assert!(user_key.starts_with("acta_tk_v1:ardyn-core:kylewilson04:"));
        assert_eq!(
            verify_tenant_api_key_with_principal(master, &user_key).unwrap(),
            ("ardyn-core".to_string(), Some("kylewilson04".to_string()))
        );

        // Swapping github_login inside user_key must fail MAC!
        let mac_u = user_key.rsplit_once(':').unwrap().1;
        let forged_user = format!("acta_tk_v1:ardyn-core:cfo-committee:{mac_u}");
        assert!(verify_tenant_api_key_with_principal(master, &forged_user).is_err());

        // Swapping tenant_id inside token while keeping MAC must fail
        let mac_a = key_a.rsplit_once(':').unwrap().1;
        let forged = format!("acta_tk_v1:client-acme:{mac_a}");
        assert!(verify_tenant_api_key(master, &forged).is_err());
        assert!(verify_tenant_api_key("wrong-master", &key_a).is_err());
    }

    #[test]
    fn test_rfc7636_pkce_s256_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(compute_pkce_s256(verifier).unwrap(), challenge);
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            challenge
        ));
        assert!(compute_pkce_s256("too_short").is_err());
    }

    #[test]
    fn test_signed_envelope_domain_separation_and_tamper_rejection() {
        let secret = "acta_live_secret_xyz";
        let env = SampleEnvelope {
            tenant: "ardyn-intelligence".to_string(),
            exp: 1_900_000_000,
        };
        let tok = mint_signed_envelope(secret, "acta_ac_v1", b"acta:oauth:code:v1", &env).unwrap();
        let decoded: SampleEnvelope =
            verify_signed_envelope(secret, "acta_ac_v1", b"acta:oauth:code:v1", &tok).unwrap();
        assert_eq!(decoded, env);
        assert!(verify_signed_envelope::<SampleEnvelope>(
            secret,
            "acta_ac_v1",
            b"acta:oauth:refresh:v1",
            &tok
        )
        .is_err());
    }

    #[test]
    fn test_normalize_github_slug() {
        assert_eq!(
            normalize_github_slug("Ardyn-Intelligence").unwrap(),
            "ardyn-intelligence"
        );
        assert_eq!(
            normalize_github_slug("@Client Acme Inc").unwrap(),
            "client-acme-inc"
        );
    }
}
