use acta_types::{ActaError, ActaResult};
use serde::Serialize;

/// Serializes any `Serialize` value into deterministic RFC 8785 (JCS) UTF-8 bytes.
pub fn to_canonical_bytes<T: Serialize + ?Sized>(value: &T) -> ActaResult<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|e| ActaError::Crypto(format!("RFC 8785 JCS canonicalization failed: {e}")))
}
