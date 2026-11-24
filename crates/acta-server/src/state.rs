use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acta_crypto::{
    hash_length_delimited, verify_tenant_api_key, verify_tenant_api_key_with_principal,
    TENANT_TOKEN_PREFIX,
};
use acta_engine::{CompilePipeline, PipelineConfig};
use acta_policy::PolicyGate;
use acta_store::{evidence_repo, PgActaStore};
use acta_types::{EvidenceEntry, PolicyResultTag, RefusalMetadata};
use axum::http::HeaderMap;
use chrono::{SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use sqlx::PgPool;

use crate::config::OAuthServerConfig;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sanitize_refusal_summary(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(512)
        .collect();
    cleaned.trim().to_string()
}

pub fn extract_credential(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-acta-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
}

pub fn extract_tenant_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-acta-tenant")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleTenantFilter {
    ExactTenant(String),
    SandboxPrefix(String),
    UnrestrictedMaster,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedKeyInfo {
    Master { header_locked_tenant: Option<String> },
    TenantBound {
        locked_tenant: String,
        verified_principal: Option<String>,
    },
    Anonymous { header_locked_tenant: Option<String> },
}

impl VerifiedKeyInfo {
    pub fn verified_principal(&self) -> Option<&str> {
        match self {
            VerifiedKeyInfo::TenantBound {
                verified_principal, ..
            } => verified_principal.as_deref(),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub pipeline: CompilePipeline<PgActaStore>,
    pub policy_gate: Arc<PolicyGate>,
    pub host_signing_key: Arc<SigningKey>,
    pub host_public_key: [u8; 32],
    pub api_key: Option<String>,
    pub fallback_token_secret: String,
    pub public_sandbox_prefix: String,
    pub oauth: OAuthServerConfig,
    pub http_client: reqwest::Client,
    pub used_auth_codes: Arc<Mutex<HashMap<[u8; 32], i64>>>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        policy_gate: Arc<PolicyGate>,
        host_signing_key: Arc<SigningKey>,
        pipeline_config: PipelineConfig,
    ) -> Self {
        let host_public_key = host_signing_key.verifying_key().to_bytes();
        let fallback_bytes = hash_length_delimited(&[
            b"acta:fallback_oauth_secret:v1",
            &host_signing_key.to_bytes(),
        ]);
        let fallback_token_secret = format!("acta_derived_{}", hex::encode(fallback_bytes));

        let store = PgActaStore::new(pool.clone());
        let pipeline = CompilePipeline::new(
            policy_gate.clone(),
            store,
            host_signing_key.clone(),
            pipeline_config,
        );

        let user_agent = std::env::var("ACTA_HTTP_USER_AGENT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Acta-Compiler-OAuth/1.7".to_string());

        let http_client = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            pool,
            pipeline,
            policy_gate,
            host_signing_key,
            host_public_key,
            api_key: None,
            fallback_token_secret,
            public_sandbox_prefix: "sandbox".to_string(),
            oauth: OAuthServerConfig::default(),
            http_client,
            used_auth_codes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_auth(mut self, api_key: Option<String>, public_sandbox_prefix: String) -> Self {
        self.api_key = api_key;
        self.public_sandbox_prefix = public_sandbox_prefix;
        self
    }

    pub fn with_oauth(mut self, oauth: OAuthServerConfig) -> Self {
        self.oauth = oauth;
        self
    }

    pub fn effective_token_secret(&self) -> &str {
        self.api_key
            .as_deref()
            .unwrap_or(self.fallback_token_secret.as_str())
    }

    pub fn resolve_public_base_url(&self, headers: &HeaderMap) -> String {
        if let Some(ref explicit) = self.oauth.public_base_url {
            return explicit.trim_end_matches('/').to_string();
        }
        let raw_host = headers
            .get("x-forwarded-host")
            .or_else(|| headers.get("host"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|h| {
                !h.is_empty()
                    && h.len() <= 253
                    && h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
            })
            .unwrap_or("localhost:8080");

        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|p| *p == "https" || *p == "http")
            .unwrap_or_else(|| {
                if raw_host.ends_with(".run.app") {
                    "https"
                } else {
                    "http"
                }
            });

        format!("{proto}://{raw_host}")
    }

    pub fn consume_auth_code_once(&self, code: &str, expires_at: i64, now_ts: i64) -> bool {
        let digest = *blake3::hash(code.as_bytes()).as_bytes();
        let Ok(mut guard) = self.used_auth_codes.lock() else {
            return false;
        };
        guard.retain(|_, &mut exp| exp >= now_ts);
        if guard.contains_key(&digest) {
            return false;
        }
        guard.insert(digest, expires_at);
        true
    }

    pub fn inspect_caller_auth(&self, headers: &HeaderMap) -> Result<VerifiedKeyInfo, String> {
        let hdr_tenant = extract_tenant_header(headers).map(str::to_string);
        let provided = extract_credential(headers);

        match (&self.api_key, provided) {
            (_, Some(tok)) if tok.starts_with(TENANT_TOKEN_PREFIX) => {
                let (locked, verified_principal) =
                    verify_tenant_api_key_with_principal(self.effective_token_secret(), tok)?;
                if let Some(ref ht) = hdr_tenant {
                    if ht != &locked {
                        return Err(format!(
                            "X-Acta-Tenant header '{ht}' conflicts with tenant-bound API key lock '{locked}'"
                        ));
                    }
                }
                Ok(VerifiedKeyInfo::TenantBound {
                    locked_tenant: locked,
                    verified_principal,
                })
            }
            (Some(master), Some(tok)) => {
                if !constant_time_eq(tok.as_bytes(), master.as_bytes()) {
                    return Err("invalid API key".to_string());
                }
                Ok(VerifiedKeyInfo::Master {
                    header_locked_tenant: hdr_tenant,
                })
            }
            (Some(_), None) => Ok(VerifiedKeyInfo::Anonymous {
                header_locked_tenant: hdr_tenant,
            }),
            (None, _) => Ok(VerifiedKeyInfo::Master {
                header_locked_tenant: hdr_tenant,
            }),
        }
    }

    /// Resolves the caller's verified tenant identity for refusal evidence logging without ever
    /// allowing an attacker to inject entries into an unowned victim tenant's ledger.
    pub fn authenticated_audit_tenant(
        &self,
        headers: &HeaderMap,
        fallback_tenant: Option<&str>,
    ) -> Option<String> {
        if let Some(tok) = extract_credential(headers) {
            if tok.starts_with(TENANT_TOKEN_PREFIX) {
                if let Ok(locked) = verify_tenant_api_key(self.effective_token_secret(), tok) {
                    return Some(locked);
                }
            }
        }

        match self.inspect_caller_auth(headers).ok()? {
            VerifiedKeyInfo::TenantBound { locked_tenant, .. } => Some(locked_tenant),
            VerifiedKeyInfo::Master {
                header_locked_tenant,
            } => header_locked_tenant.or_else(|| {
                fallback_tenant
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && s.len() <= 256)
                    .map(str::to_string)
            }),
            VerifiedKeyInfo::Anonymous {
                header_locked_tenant,
            } => {
                let candidate = header_locked_tenant.or_else(|| {
                    fallback_tenant
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && s.len() <= 256)
                        .map(str::to_string)
                })?;
                if !self.public_sandbox_prefix.is_empty()
                    && candidate.starts_with(&self.public_sandbox_prefix)
                {
                    Some(candidate)
                } else {
                    None
                }
            }
        }
    }

    /// Appends a signed `EvidenceEntry` with auditor-readable `RefusalMetadata` (`v1.5+`) to the
    /// authenticated caller's ledger when a refusal occurs.
    pub async fn append_refusal_audit_with_scope(
        &self,
        headers: &HeaderMap,
        fallback_tenant: Option<&str>,
        tag: PolicyResultTag,
        operation: &str,
        reason_code: &str,
        target_scope: Option<&str>,
        detail: &str,
    ) -> Option<EvidenceEntry> {
        self.append_anchor_refusal_audit(
            headers,
            fallback_tenant,
            tag,
            operation,
            reason_code,
            target_scope,
            detail,
            None,
        )
        .await
    }

    /// Appends a signed `EvidenceEntry` with `RefusalMetadata` (optionally binding structured
    /// `attempted_checkpoint_hash` for `anchor_checkpoint` refusals, `v1.6.6+`).
    #[allow(clippy::too_many_arguments)]
    pub async fn append_anchor_refusal_audit(
        &self,
        headers: &HeaderMap,
        fallback_tenant: Option<&str>,
        tag: PolicyResultTag,
        operation: &str,
        reason_code: &str,
        target_scope: Option<&str>,
        detail: &str,
        attempted_checkpoint_hash: Option<[u8; 32]>,
    ) -> Option<EvidenceEntry> {
        let audit_tenant = self.authenticated_audit_tenant(headers, fallback_tenant)?;
        let meta = RefusalMetadata {
            operation: sanitize_refusal_summary(operation),
            reason_code: sanitize_refusal_summary(reason_code),
            target_scope: target_scope
                .map(sanitize_refusal_summary)
                .filter(|s| !s.is_empty()),
            summary: sanitize_refusal_summary(detail),
            scope_state_commitment: None,
            attempted_checkpoint_hash,
            signing_domain: None,
            expected_intent_digest_hex: None,
        };
        evidence_repo::append_refusal_metadata_tx(
            &self.pool,
            &self.host_signing_key,
            &audit_tenant,
            tag,
            meta,
            Utc::now().trunc_subsecs(6),
        )
        .await
        .ok()
    }

    /// Appends a signed `EvidenceEntry` with `RefusalMetadata` binding `signing_domain` and
    /// `expected_intent_digest_hex` on client Ed25519 signature refusals (`v1.7.2+`, Should-Fix 1 & 2).
    #[allow(clippy::too_many_arguments)]
    pub async fn append_signature_refusal_audit(
        &self,
        headers: &HeaderMap,
        fallback_tenant: Option<&str>,
        tag: PolicyResultTag,
        operation: &str,
        reason_code: &str,
        target_scope: Option<&str>,
        detail: &str,
        signing_domain: &str,
        expected_intent_digest: [u8; 32],
    ) -> Option<EvidenceEntry> {
        let audit_tenant = self.authenticated_audit_tenant(headers, fallback_tenant)?;
        let meta = RefusalMetadata {
            operation: sanitize_refusal_summary(operation),
            reason_code: sanitize_refusal_summary(reason_code),
            target_scope: target_scope
                .map(sanitize_refusal_summary)
                .filter(|s| !s.is_empty()),
            summary: sanitize_refusal_summary(detail),
            scope_state_commitment: None,
            attempted_checkpoint_hash: None,
            signing_domain: Some(sanitize_refusal_summary(signing_domain)),
            expected_intent_digest_hex: Some(expected_intent_digest),
        };
        evidence_repo::append_refusal_metadata_tx(
            &self.pool,
            &self.host_signing_key,
            &audit_tenant,
            tag,
            meta,
            Utc::now().trunc_subsecs(6),
        )
        .await
        .ok()
    }

    /// Convenience wrapper around `append_refusal_audit_with_scope` when no scope applies.
    pub async fn append_refusal_audit(
        &self,
        headers: &HeaderMap,
        fallback_tenant: Option<&str>,
        tag: PolicyResultTag,
        reason_code: &str,
        detail: &str,
    ) -> Option<EvidenceEntry> {
        self.append_refusal_audit_with_scope(
            headers,
            fallback_tenant,
            tag,
            reason_code,
            reason_code,
            None,
            detail,
        )
        .await
    }

    pub fn check_master_admin_auth(&self, headers: &HeaderMap) -> Result<&str, String> {
        let Some(ref master) = self.api_key else {
            return Err("ACTA_API_KEY master secret is not configured on this server".to_string());
        };
        let Some(tok) = extract_credential(headers) else {
            return Err(
                "missing master ACTA_API_KEY (pass X-Acta-Api-Key or Authorization: Bearer)"
                    .to_string(),
            );
        };
        if tok.starts_with(TENANT_TOKEN_PREFIX) {
            return Err(
                "tenant-bound acta_tk_v1 keys cannot mint keys for other tenants; master ACTA_API_KEY required"
                    .to_string(),
            );
        }
        if !constant_time_eq(tok.as_bytes(), master.as_bytes()) {
            return Err("invalid master ACTA_API_KEY".to_string());
        }
        Ok(master.as_str())
    }

    pub fn check_tenant_auth(&self, headers: &HeaderMap, tenant_id: &str) -> Result<(), String> {
        match self.inspect_caller_auth(headers)? {
            VerifiedKeyInfo::TenantBound { locked_tenant, .. } => {
                if locked_tenant != tenant_id {
                    return Err(format!(
                        "tenant lock violation: API key is cryptographically bound to tenant '{locked_tenant}', cannot access '{tenant_id}'"
                    ));
                }
                Ok(())
            }
            VerifiedKeyInfo::Master {
                header_locked_tenant,
            } => {
                if let Some(locked) = header_locked_tenant {
                    if locked != tenant_id {
                        return Err(format!(
                            "X-Acta-Tenant lock violation: session is locked to '{locked}', cannot access '{tenant_id}'"
                        ));
                    }
                }
                Ok(())
            }
            VerifiedKeyInfo::Anonymous {
                header_locked_tenant,
            } => {
                if let Some(locked) = header_locked_tenant {
                    if locked != tenant_id {
                        return Err(format!(
                            "X-Acta-Tenant lock violation: session is locked to '{locked}', cannot access '{tenant_id}'"
                        ));
                    }
                }
                if !self.public_sandbox_prefix.is_empty()
                    && tenant_id.starts_with(&self.public_sandbox_prefix)
                {
                    return Ok(());
                }
                Err(format!(
                    "missing or invalid API key for protected tenant '{tenant_id}' (sign in with GitHub OAuth 2.1, pass a tenant-bound acta_tk_v1 key, or use '{}-*' sandbox tenant)",
                    self.public_sandbox_prefix
                ))
            }
        }
    }

    /// Audited wrapper around `check_tenant_auth` that logs a signed `Block` `EvidenceEntry`
    /// carrying `RefusalMetadata` into the caller's locked tenant ledger on tenant-lock violations.
    pub async fn check_tenant_auth_audited(
        &self,
        headers: &HeaderMap,
        tenant_id: &str,
        operation: &str,
    ) -> Result<(), String> {
        match self.check_tenant_auth(headers, tenant_id) {
            Ok(()) => Ok(()),
            Err(msg) => {
                if let Some(ev) = self
                    .append_refusal_audit_with_scope(
                        headers,
                        None,
                        PolicyResultTag::Block,
                        operation,
                        "tenant_lock_violation",
                        None,
                        &format!("{operation}: {msg}"),
                    )
                    .await
                {
                    Err(format!("{msg} [logged at evidence seq_num={}]", ev.seq_num))
                } else {
                    Err(msg)
                }
            }
        }
    }

    pub fn mcp_requires_oauth_challenge(&self, headers: &HeaderMap) -> Result<bool, String> {
        let info = self.inspect_caller_auth(headers)?;
        match info {
            VerifiedKeyInfo::TenantBound { .. } | VerifiedKeyInfo::Master { .. } => Ok(false),
            VerifiedKeyInfo::Anonymous {
                header_locked_tenant,
            } => {
                if let Some(ref t) = header_locked_tenant {
                    if !self.public_sandbox_prefix.is_empty()
                        && t.starts_with(&self.public_sandbox_prefix)
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    pub fn resolve_mcp_tenant(
        &self,
        headers: &HeaderMap,
        arg_tenant: Option<&str>,
    ) -> Result<String, String> {
        let info = self.inspect_caller_auth(headers)?;
        let locked_opt = match &info {
            VerifiedKeyInfo::TenantBound { locked_tenant, .. } => Some(locked_tenant.clone()),
            VerifiedKeyInfo::Master {
                header_locked_tenant,
            }
            | VerifiedKeyInfo::Anonymous {
                header_locked_tenant,
            } => header_locked_tenant.clone(),
        };

        let explicit_opt = arg_tenant.map(str::trim).filter(|s| !s.is_empty());

        let effective = match (explicit_opt, locked_opt) {
            (Some(explicit), Some(locked)) => {
                if explicit != locked {
                    return Err(format!(
                        "MCP tenant lock violation: tool requested tenant_id '{explicit}', but connection is locked to '{locked}'"
                    ));
                }
                locked
            }
            (None, Some(locked)) => locked,
            (Some(explicit), None) => explicit.to_string(),
            (None, None) => {
                return Err(
                    "missing tenant_id (sign in via GitHub OAuth 2.1, authenticate with a tenant-bound acta_tk_v1 key, or set X-Acta-Tenant)"
                        .to_string(),
                )
            }
        };

        self.check_tenant_auth(headers, &effective)?;
        Ok(effective)
    }

    /// Audited wrapper around `resolve_mcp_tenant` that appends a signed `Block` `EvidenceEntry`
    /// with structured `RefusalMetadata` on any cross-tenant access attempt.
    pub async fn resolve_mcp_tenant_audited(
        &self,
        headers: &HeaderMap,
        arg_tenant: Option<&str>,
        operation: &str,
    ) -> Result<String, String> {
        match self.resolve_mcp_tenant(headers, arg_tenant) {
            Ok(t) => Ok(t),
            Err(msg) => {
                if let Some(ev) = self
                    .append_refusal_audit_with_scope(
                        headers,
                        None,
                        PolicyResultTag::Block,
                        operation,
                        "mcp_tenant_lock_violation",
                        None,
                        &format!("{operation}: {msg}"),
                    )
                    .await
                {
                    Err(format!("{msg} [logged at evidence seq_num={}]", ev.seq_num))
                } else {
                    Err(msg)
                }
            }
        }
    }

    /// Resolves the caller's tenant scope BEFORE touching `context_bundles` (`v1.6.7+`).
    pub async fn resolve_bundle_lookup_scope(
        &self,
        headers: &HeaderMap,
        explicit_tenant: Option<&str>,
        operation: &str,
        is_mcp: bool,
    ) -> Result<BundleTenantFilter, String> {
        if let Some(exp) = explicit_tenant.map(str::trim).filter(|s| !s.is_empty()) {
            if is_mcp {
                let resolved = self
                    .resolve_mcp_tenant_audited(headers, Some(exp), operation)
                    .await?;
                return Ok(BundleTenantFilter::ExactTenant(resolved));
            }
            self.check_tenant_auth_audited(headers, exp, operation)
                .await?;
            return Ok(BundleTenantFilter::ExactTenant(exp.to_string()));
        }

        let info = self.inspect_caller_auth(headers)?;
        match info {
            VerifiedKeyInfo::TenantBound { locked_tenant, .. } => {
                Ok(BundleTenantFilter::ExactTenant(locked_tenant))
            }
            VerifiedKeyInfo::Master {
                header_locked_tenant: Some(t),
            } => Ok(BundleTenantFilter::ExactTenant(t)),
            VerifiedKeyInfo::Master {
                header_locked_tenant: None,
            } => Ok(BundleTenantFilter::UnrestrictedMaster),
            VerifiedKeyInfo::Anonymous {
                header_locked_tenant: Some(t),
            } => {
                self.check_tenant_auth_audited(headers, &t, operation)
                    .await?;
                Ok(BundleTenantFilter::ExactTenant(t))
            }
            VerifiedKeyInfo::Anonymous {
                header_locked_tenant: None,
            } => {
                if self.public_sandbox_prefix.is_empty() {
                    Err("missing authentication credentials".to_string())
                } else {
                    Ok(BundleTenantFilter::SandboxPrefix(
                        self.public_sandbox_prefix.clone(),
                    ))
                }
            }
        }
    }
}
