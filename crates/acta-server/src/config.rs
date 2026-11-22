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
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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

        let auto_select_single_org = std::env::var("ACTA_OAUTH_AUTO_SELECT_SINGLE_ORG")
            .ok()
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

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
        })
    }
}
