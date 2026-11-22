use crate::error::{ActaError, ActaResult};
use crate::request::ContextBudget;

pub const MAX_IDENTIFIER_CHARS: usize = 256;
pub const MAX_TAG_CHARS: usize = 128;
pub const MAX_TAGS_COUNT: usize = 64;
pub const MAX_QUERY_CHARS: usize = 16_384;
pub const MAX_JUSTIFICATION_CHARS: usize = 2_048;
pub const MAX_JSON_PAYLOAD_BYTES: usize = 262_144; // 256 KiB
pub const MIN_PRIORITY: i32 = -1_000;
pub const MAX_PRIORITY: i32 = 1_000;
pub const MIN_PROVENANCE_CLASS: i32 = 0;
pub const MAX_PROVENANCE_CLASS: i32 = 10;
pub const MAX_TOKEN_BUDGET: usize = 128_000;
pub const MAX_BYTE_BUDGET: usize = 1_048_576;
pub const MAX_RECORD_BUDGET: usize = 4_096;

fn contains_forbidden_marker_or_control(s: &str) -> Option<String> {
    for ch in s.chars() {
        if ch.is_control() {
            return Some(format!(
                "contains forbidden control character U+{:04X}",
                ch as u32
            ));
        }
        if ch == '[' || ch == ']' {
            return Some(format!(
                "contains reserved ACTA structural delimiter '{ch}'"
            ));
        }
    }
    None
}

/// Validates `scope`: non-empty, <= 256 chars, no whitespace, no control chars,
/// no `[` / `]` marker delimiters, no `\` backslashes, and no `..` path traversal segments.
pub fn validate_scope(raw: &str) -> ActaResult<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ActaError::Validation("scope must be non-empty".to_string()));
    }
    if raw != trimmed {
        return Err(ActaError::Validation(
            "scope must not have leading or trailing whitespace".to_string(),
        ));
    }
    if raw.len() > MAX_IDENTIFIER_CHARS {
        return Err(ActaError::Validation(format!(
            "scope exceeds maximum length of {MAX_IDENTIFIER_CHARS} bytes"
        )));
    }
    if let Some(reason) = contains_forbidden_marker_or_control(raw) {
        return Err(ActaError::Validation(format!("invalid scope: {reason}")));
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(ActaError::Validation(
            "scope must not contain whitespace".to_string(),
        ));
    }
    if raw.contains('\\') {
        return Err(ActaError::Validation(
            "scope must not contain backslashes".to_string(),
        ));
    }
    for seg in raw.split('/') {
        if seg == ".." || seg == "." {
            return Err(ActaError::Validation(
                "scope must not contain '.' or '..' path traversal segments".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validates identifier fields (`tenant_id`, `subject`, `predicate`, `source_descriptor`,
/// `object_type`, `actor_id`, `task_id`, `adjudicator_id`) to block newline/marker injection.
pub fn validate_identifier(field_name: &str, raw: &str) -> ActaResult<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ActaError::Validation(format!(
            "{field_name} must be non-empty"
        )));
    }
    if raw != trimmed {
        return Err(ActaError::Validation(format!(
            "{field_name} must not have leading or trailing whitespace or control characters"
        )));
    }
    if raw.chars().count() > MAX_IDENTIFIER_CHARS {
        return Err(ActaError::Validation(format!(
            "{field_name} exceeds maximum length of {MAX_IDENTIFIER_CHARS} characters"
        )));
    }
    if let Some(reason) = contains_forbidden_marker_or_control(raw) {
        return Err(ActaError::Validation(format!(
            "invalid {field_name}: {reason}"
        )));
    }
    Ok(())
}

/// Validates human/committee `justification` text on signed dispute overrides:
/// non-empty, <= 2048 chars, single-line without control characters or `[` / `]` marker injection.
pub fn validate_justification(raw: &str) -> ActaResult<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ActaError::Validation(
            "justification must be non-empty".to_string(),
        ));
    }
    if raw != trimmed {
        return Err(ActaError::Validation(
            "justification must not have leading or trailing whitespace or control characters"
                .to_string(),
        ));
    }
    if raw.chars().count() > MAX_JUSTIFICATION_CHARS {
        return Err(ActaError::Validation(format!(
            "justification exceeds maximum length of {MAX_JUSTIFICATION_CHARS} characters"
        )));
    }
    if let Some(reason) = contains_forbidden_marker_or_control(raw) {
        return Err(ActaError::Validation(format!(
            "invalid justification: {reason}"
        )));
    }
    Ok(())
}

/// Validates `tags` count and individual tag contents.
pub fn validate_tags(tags: &[String]) -> ActaResult<()> {
    if tags.len() > MAX_TAGS_COUNT {
        return Err(ActaError::Validation(format!(
            "tags count {} exceeds maximum of {MAX_TAGS_COUNT}",
            tags.len()
        )));
    }
    for (idx, tag) in tags.iter().enumerate() {
        let trimmed = tag.trim();
        if trimmed.is_empty() || tag != trimmed {
            return Err(ActaError::Validation(format!(
                "tags[{idx}] must be non-empty without surrounding whitespace"
            )));
        }
        if tag.chars().count() > MAX_TAG_CHARS {
            return Err(ActaError::Validation(format!(
                "tags[{idx}] exceeds maximum length of {MAX_TAG_CHARS} characters"
            )));
        }
        if let Some(reason) = contains_forbidden_marker_or_control(tag) {
            return Err(ActaError::Validation(format!(
                "invalid tags[{idx}]: {reason}"
            )));
        }
    }
    Ok(())
}

/// Validates `query_text` length and null-byte safety.
pub fn validate_query_text(query_text: &str) -> ActaResult<()> {
    if query_text.len() > MAX_QUERY_CHARS {
        return Err(ActaError::Validation(format!(
            "query_text exceeds maximum length of {MAX_QUERY_CHARS} bytes"
        )));
    }
    if query_text.contains('\0') {
        return Err(ActaError::Validation(
            "query_text must not contain NUL bytes".to_string(),
        ));
    }
    Ok(())
}

/// Enforces serialized JSON byte cap (`256 KiB`) on `body` and `object_val`.
pub fn validate_json_payload_size(field_name: &str, val: &serde_json::Value) -> ActaResult<()> {
    let encoded_len = serde_json::to_vec(val)
        .map_err(|e| ActaError::Validation(format!("invalid JSON in {field_name}: {e}")))?
        .len();
    if encoded_len > MAX_JSON_PAYLOAD_BYTES {
        return Err(ActaError::Validation(format!(
            "{field_name} serialized size ({encoded_len} bytes) exceeds maximum of {MAX_JSON_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Enforces priority bounds `[-1000, 1000]`.
pub fn validate_priority(priority: i64) -> ActaResult<i32> {
    if !(i64::from(MIN_PRIORITY)..=i64::from(MAX_PRIORITY)).contains(&priority) {
        return Err(ActaError::Validation(format!(
            "priority {priority} out of allowed range [{MIN_PRIORITY}, {MAX_PRIORITY}]"
        )));
    }
    Ok(priority as i32)
}

/// Enforces `importance` bounds `[0.0, 1.0]`.
pub fn validate_importance(importance: f32) -> ActaResult<()> {
    if !importance.is_finite() || !(0.0..=1.0).contains(&importance) {
        return Err(ActaError::Validation(
            "importance must be a finite number in [0.0, 1.0]".to_string(),
        ));
    }
    Ok(())
}

/// Enforces `confidence` bounds `[0.0, 1.0]`.
pub fn validate_confidence(confidence: f64) -> ActaResult<()> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(ActaError::Validation(
            "confidence must be a finite number in [0.0, 1.0]".to_string(),
        ));
    }
    Ok(())
}

/// Enforces `source_provenance_class` bounds `[0, 10]`.
pub fn validate_provenance_class(prov: i64) -> ActaResult<i32> {
    if !(i64::from(MIN_PROVENANCE_CLASS)..=i64::from(MAX_PROVENANCE_CLASS)).contains(&prov) {
        return Err(ActaError::Validation(format!(
            "source_provenance_class {prov} out of allowed range [{MIN_PROVENANCE_CLASS}, {MAX_PROVENANCE_CLASS}]"
        )));
    }
    Ok(prov as i32)
}

/// Enforces positive bounded `ContextBudget` (`> 0` and within hard ceiling).
pub fn validate_budget(budget: ContextBudget) -> ActaResult<()> {
    match budget {
        ContextBudget::Tokens(n) => {
            if n == 0 || n > MAX_TOKEN_BUDGET {
                return Err(ActaError::Validation(format!(
                    "token_budget must be between 1 and {MAX_TOKEN_BUDGET} (got {n})"
                )));
            }
        }
        ContextBudget::Bytes(n) => {
            if n == 0 || n > MAX_BYTE_BUDGET {
                return Err(ActaError::Validation(format!(
                    "byte budget must be between 1 and {MAX_BYTE_BUDGET} (got {n})"
                )));
            }
        }
        ContextBudget::Records(n) => {
            if n == 0 || n > MAX_RECORD_BUDGET {
                return Err(ActaError::Validation(format!(
                    "record budget must be between 1 and {MAX_RECORD_BUDGET} (got {n})"
                )));
            }
        }
    }
    Ok(())
}
