use std::net::SocketAddr;
use std::path::PathBuf;

use acta_engine::{PipelineConfig, ResolverConfig};
use acta_types::{ActaError, ActaResult};
use ed25519_dalek::SigningKey;

#[derive(Debug, Clone)]
pub struct OAuthServerConfig {
    pub public_base_url: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub github_authorize_url: String,
    pub github_token_url: String,
    pub github_api_base_url: String,
    pub auto_select_single_org: bool,
}

impl Default for OAuthServerConfig {
    fn default() -> Self {
        Self {
            public_base_url: None,
            github_client_id: None,
            github_client_secret: None,
            github_authorize_url: "https://github.com/login/oauth/authorize".to_string(),
            github_token_url: "https://github.com/login/oauth/access_token".to_string(),
            github_api_base_url: "https://api.github.com".to_string(),
            auto_select_single_org: true,
        }
    }
}

impl OAuthServerConfig {
    pub fn github_enabled(&self) -> bool {
        self.github_client_id.is_some() && self.github_client_secret.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct EmailOtpConfig {
    pub resend_api_key: Option<String>,
    pub resend_api_url: String,
    pub resend_contacts_api_url: Option<String>,
    pub resend_segment_id: Option<String>,
    pub sync_resend_contacts: bool,
    pub email_from: String,
    pub welcome_email_enabled: bool,
    pub welcome_email_subject: String,
    pub signup_webhook_url: Option<String>,
    pub signup_webhook_bearer: Option<String>,
    pub webhook_url: Option<String>,
    pub webhook_bearer: Option<String>,
    pub allowed_org_domains: Vec<String>,
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            resend_api_key: None,
            resend_api_url: "https://api.resend.com/emails".to_string(),
            resend_contacts_api_url: None,
            resend_segment_id: None,
            sync_resend_contacts: true,
            email_from: "Acta Compiler <onboarding@resend.dev>".to_string(),
            welcome_email_enabled: true,
            welcome_email_subject:
                "Welcome to Acta Compiler — Your Isolated Cryptographic Vault Is Ready".to_string(),
            signup_webhook_url: None,
            signup_webhook_bearer: None,
            webhook_url: None,
            webhook_bearer: None,
            allowed_org_domains: Vec::new(),
        }
    }
}

impl EmailOtpConfig {
    pub fn enabled(&self) -> bool {
        self.resend_api_key.is_some() || self.webhook_url.is_some()
    }

    pub fn effective_resend_contacts_url(&self) -> String {
        if let Some(ref explicit) = self.resend_contacts_api_url {
            let trimmed = explicit.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let emails_trimmed = self.resend_api_url.trim().trim_end_matches('/');
        if let Some(base) = emails_trimmed.strip_suffix("/emails") {
            return format!("{base}/contacts");
        }
        "https://api.resend.com/contacts".to_string()
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub host_signing_key: SigningKey,
    pub policy_path: PathBuf,
    pub bind_addr: SocketAddr,
    pub pipeline: PipelineConfig,
    pub db_max_connections: u32,
    pub api_key: Option<String>,
    pub public_sandbox_prefix: String,
    pub oauth: OAuthServerConfig,
    pub email_otp: EmailOtpConfig,
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn bool_env_default(name: &str, default_val: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| match v.trim().to_ascii_lowercase().as_str() {
            "0" | "false" | "no" | "off" => false,
            "1" | "true" | "yes" | "on" => true,
            _ => default_val,
        })
        .unwrap_or(default_val)
}

impl ServerConfig {
    pub fn from_env() -> ActaResult<Self> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ActaError::Validation("missing DATABASE_URL env var".to_string()))?;

        let key_hex = std::env::var("ACTA_HOST_PRIVATE_KEY_HEX").map_err(|_| {
            ActaError::Validation("missing ACTA_HOST_PRIVATE_KEY_HEX env var".to_string())
        })?;
        let key_bytes_vec = hex::decode(key_hex.trim()).map_err(|e| {
            ActaError::Validation(format!("ACTA_HOST_PRIVATE_KEY_HEX invalid hex: {e}"))
        })?;
        let key_seed: [u8; 32] = key_bytes_vec.try_into().map_err(|_| {
            ActaError::Validation(
                "ACTA_HOST_PRIVATE_KEY_HEX must decode to exactly 32 bytes".to_string(),
            )
        })?;
        let host_signing_key = SigningKey::from_bytes(&key_seed);

        let policy_path = PathBuf::from(
            std::env::var("ACTA_POLICY_PATH")
                .unwrap_or_else(|_| "./policies/default.cedar".to_string()),
        );

        let bind_str = match std::env::var("ACTA_BIND_ADDR") {
            Ok(val) if !val.trim().is_empty() => val,
            _ => {
                let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
                format!("0.0.0.0:{port}")
            }
        };
        let bind_addr: SocketAddr = bind_str
            .parse()
            .map_err(|e| ActaError::Validation(format!("invalid bind address '{bind_str}': {e}")))?;

        let min_confidence: f64 = std::env::var("MIN_CONFIDENCE")
            .unwrap_or_else(|_| "0.70".to_string())
            .parse()
            .map_err(|e| ActaError::Validation(format!("invalid MIN_CONFIDENCE: {e}")))?;

        let decisiveness_threshold: f64 = std::env::var("DECISIVENESS_THRESHOLD")
            .unwrap_or_else(|_| "0.15".to_string())
            .parse()
            .map_err(|e| ActaError::Validation(format!("invalid DECISIVENESS_THRESHOLD: {e}")))?;

        let max_inline_omissions: usize = std::env::var("MAX_INLINE_OMISSIONS")
            .unwrap_or_else(|_| "25".to_string())
            .parse()
            .map_err(|e| ActaError::Validation(format!("invalid MAX_INLINE_OMISSIONS: {e}")))?;

        let embedding_model_version = std::env::var("ACTA_EMBEDDING_MODEL_VERSION")
            .unwrap_or_else(|_| "text-embedding-3-small-1536".to_string());

        let db_max_connections: u32 = std::env::var("ACTA_DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "32".to_string())
            .parse()
            .unwrap_or(32);

        let api_key = non_empty_env("ACTA_API_KEY");

        let public_sandbox_prefix = std::env::var("ACTA_PUBLIC_SANDBOX_PREFIX")
            .unwrap_or_else(|_| "sandbox".to_string());

        let auto_select_single_org = bool_env_default("ACTA_OAUTH_AUTO_SELECT_SINGLE_ORG", true);

        let oauth = OAuthServerConfig {
            public_base_url: non_empty_env("ACTA_PUBLIC_BASE_URL")
                .map(|u| u.trim_end_matches('/').to_string()),
            github_client_id: non_empty_env("GITHUB_CLIENT_ID"),
            github_client_secret: non_empty_env("GITHUB_CLIENT_SECRET"),
            github_authorize_url: non_empty_env("ACTA_GITHUB_AUTHORIZE_URL")
                .unwrap_or_else(|| "https://github.com/login/oauth/authorize".to_string()),
            github_token_url: non_empty_env("ACTA_GITHUB_TOKEN_URL")
                .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string()),
            github_api_base_url: non_empty_env("ACTA_GITHUB_API_BASE_URL")
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_else(|| "https://api.github.com".to_string()),
            auto_select_single_org,
        };

        let allowed_org_domains = non_empty_env("ACTA_EMAIL_ORG_DOMAINS")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let email_otp = EmailOtpConfig {
            resend_api_key: non_empty_env("ACTA_RESEND_API_KEY")
                .or_else(|| non_empty_env("RESEND_API_KEY")),
            resend_api_url: non_empty_env("ACTA_RESEND_API_URL")
                .unwrap_or_else(|| "https://api.resend.com/emails".to_string()),
            resend_contacts_api_url: non_empty_env("ACTA_RESEND_CONTACTS_API_URL"),
            resend_segment_id: non_empty_env("ACTA_RESEND_SEGMENT_ID"),
            sync_resend_contacts: bool_env_default("ACTA_RESEND_SYNC_CONTACTS", true),
            email_from: non_empty_env("ACTA_EMAIL_FROM")
                .unwrap_or_else(|| "Acta Compiler <onboarding@resend.dev>".to_string()),
            welcome_email_enabled: bool_env_default("ACTA_WELCOME_EMAIL_ENABLED", true),
            welcome_email_subject: non_empty_env("ACTA_WELCOME_EMAIL_SUBJECT").unwrap_or_else(
                || "Welcome to Acta Compiler — Your Isolated Cryptographic Vault Is Ready"
                    .to_string(),
            ),
            signup_webhook_url: non_empty_env("ACTA_SIGNUP_WEBHOOK_URL"),
            signup_webhook_bearer: non_empty_env("ACTA_SIGNUP_WEBHOOK_BEARER"),
            webhook_url: non_empty_env("ACTA_EMAIL_WEBHOOK_URL"),
            webhook_bearer: non_empty_env("ACTA_EMAIL_WEBHOOK_BEARER"),
            allowed_org_domains,
        };

        Ok(Self {
            database_url,
            host_signing_key,
            policy_path,
            bind_addr,
            pipeline: PipelineConfig {
                resolver: ResolverConfig {
                    min_confidence,
                    decisiveness_threshold,
                },
                max_inline_omissions,
                embedding_model_version,
                candidate_memory_fetch_limit: 256,
            },
            db_max_connections,
            api_key,
            public_sandbox_prefix,
            oauth,
            email_otp,
        })
    }
}
