use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bundle::{ContextBundle, EvidenceEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "limit", rename_all = "snake_case")]
pub enum ContextBudget {
    Tokens(usize),
    Bytes(usize),
    Records(usize),
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self::Tokens(4096)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileRequest {
    pub tenant_id: String,
    pub actor_id: String,
    pub task_id: String,
    pub scope: String,
    pub query_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_embedding: Option<Vec<f32>>,
    pub budget: ContextBudget,
    /// Optional deterministic evaluation timestamp; defaults to truncated `Utc::now()` in pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Block { reason: String },
    Escalate { reason: String },
}

impl PolicyDecision {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Block { .. } => "block",
            PolicyDecision::Escalate { .. } => "escalate",
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileResponse {
    pub policy_decision: PolicyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<ContextBundle>,
    pub evidence: EvidenceEntry,
}
