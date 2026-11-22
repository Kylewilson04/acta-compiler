use std::str::FromStr;
use std::time::Duration;

use acta_types::{ActaError, ActaResult};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

/// Initializes a tuned PostgreSQL connection pool supporting both standard TCP `DATABASE_URL`s
/// and Google Cloud Run / Cloud SQL Unix domain sockets (`postgres:///?host=/cloudsql/...`).
pub async fn create_pool(database_url: &str, max_connections: u32) -> ActaResult<PgPool> {
    let connect_opts = PgConnectOptions::from_str(database_url)
        .map_err(|e| ActaError::Storage(format!("invalid DATABASE_URL options: {e}")))?;

    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2.min(max_connections))
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(connect_opts)
        .await
        .map_err(|e| ActaError::Storage(format!("failed to connect to PostgreSQL: {e}")))
}

/// Runs embedded SQL migrations from `migrations/` idempotently.
pub async fn run_migrations(pool: &PgPool) -> ActaResult<()> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("database migration failed: {e}")))
}
