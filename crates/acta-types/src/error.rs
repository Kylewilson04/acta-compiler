use thiserror::Error;

#[derive(Debug, Error)]
pub enum ActaError {
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("policy escalation required: {0}")]
    PolicyEscalated(String),

    #[error("policy engine error: {0}")]
    PolicyEngine(String),

    #[error("budget insufficient for active disputes: {0}")]
    BudgetInsufficientForDisputes(String),

    #[error("canonicalization / crypto error: {0}")]
    Crypto(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bundle stale at cache time: {0}")]
    BundleStaleAtCacheTime(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

pub type ActaResult<T> = Result<T, ActaError>;
