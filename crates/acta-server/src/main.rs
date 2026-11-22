use std::collections::BTreeMap;
use std::sync::Arc;

use acta_policy::PolicyGate;
use acta_server::{config::ServerConfig, routes::build_router, state::AppState};
use acta_store::pool::{create_pool, run_migrations};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,acta_server=info".into()),
        )
        .init();

    let cfg = ServerConfig::from_env()?;
    let pool = create_pool(&cfg.database_url, cfg.db_max_connections).await?;
    run_migrations(&pool).await?;

    let policy_gate = Arc::new(PolicyGate::from_file(&cfg.policy_path, BTreeMap::new())?);
    info!(
        permission_root = %hex::encode(policy_gate.permission_root()),
        policy_path = %cfg.policy_path.display(),
        "loaded embedded Cedar policy gate"
    );

    let github_oauth_enabled = cfg.oauth.github_enabled();
    let host_signing_key = Arc::new(cfg.host_signing_key);
    let state = AppState::new(pool, policy_gate, host_signing_key, cfg.pipeline)
        .with_auth(cfg.api_key, cfg.public_sandbox_prefix)
        .with_oauth(cfg.oauth);
    let pubkey_hex = hex::encode(state.host_public_key);

    let app = build_router(state);
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    info!(
        bind_addr = %cfg.bind_addr,
        host_public_key = %pubkey_hex,
        github_oauth_enabled = github_oauth_enabled,
        "acta-server v1.6.0 Epistemic Notary & RFC 6962 Merkle Checkpoint gateway listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received; draining acta-server");
}
