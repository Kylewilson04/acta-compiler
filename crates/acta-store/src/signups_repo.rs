use acta_types::{ActaError, ActaResult};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct EmailSignupRecord {
    pub email: String,
    pub tenant_id: String,
    pub principal: String,
    pub first_signup_flow: String,
    pub first_client_name: String,
    pub marketing_opt_in: bool,
    pub resend_contact_id: Option<String>,
    pub welcome_sent_at: Option<DateTime<Utc>>,
    pub unsubscribed_at: Option<DateTime<Utc>>,
    pub verification_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_verified_at: DateTime<Utc>,
}

/// Idempotently records a verified email login/signup in `email_signups`.
/// On first verification (`verification_count == 1`), stores initial signup metadata and consent.
/// On repeat verifications, increments `verification_count` and preserves prior unsubscribes.
pub async fn upsert_verified_signup(
    pool: &PgPool,
    email: &str,
    tenant_id: &str,
    principal: &str,
    signup_flow: &str,
    client_name: &str,
    marketing_opt_in: bool,
) -> ActaResult<EmailSignupRecord> {
    sqlx::query_as::<_, EmailSignupRecord>(
        r#"
        INSERT INTO email_signups (
            email,
            tenant_id,
            principal,
            first_signup_flow,
            first_client_name,
            marketing_opt_in,
            verification_count,
            created_at,
            last_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 1, NOW(), NOW())
        ON CONFLICT (email) DO UPDATE SET
            verification_count = email_signups.verification_count + 1,
            last_verified_at = NOW(),
            marketing_opt_in = CASE
                WHEN email_signups.unsubscribed_at IS NOT NULL THEN FALSE
                ELSE (email_signups.marketing_opt_in AND EXCLUDED.marketing_opt_in)
            END
        RETURNING
            email,
            tenant_id,
            principal,
            first_signup_flow,
            first_client_name,
            marketing_opt_in,
            resend_contact_id,
            welcome_sent_at,
            unsubscribed_at,
            verification_count,
            created_at,
            last_verified_at
        "#,
    )
    .bind(email)
    .bind(tenant_id)
    .bind(principal)
    .bind(signup_flow)
    .bind(client_name)
    .bind(marketing_opt_in)
    .fetch_one(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("upsert_verified_signup failed: {e}")))
}

/// Updates `resend_contact_id` and/or `welcome_sent_at` after post-signup onboarding sync.
pub async fn record_signup_delivery_meta(
    pool: &PgPool,
    email: &str,
    resend_contact_id: Option<&str>,
    mark_welcome_sent: bool,
) -> ActaResult<()> {
    sqlx::query(
        r#"
        UPDATE email_signups
        SET
            resend_contact_id = COALESCE($2, resend_contact_id),
            welcome_sent_at = CASE
                WHEN $3 AND welcome_sent_at IS NULL THEN NOW()
                ELSE welcome_sent_at
            END
        WHERE email = $1
        "#,
    )
    .bind(email)
    .bind(resend_contact_id)
    .bind(mark_welcome_sent)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("record_signup_delivery_meta failed: {e}")))?;
    Ok(())
}

/// Marks a verified email address as opted out from marketing emails (`marketing_opt_in = FALSE`).
pub async fn mark_email_unsubscribed(pool: &PgPool, email: &str) -> ActaResult<bool> {
    let res = sqlx::query(
        r#"
        UPDATE email_signups
        SET
            marketing_opt_in = FALSE,
            unsubscribed_at = COALESCE(unsubscribed_at, NOW())
        WHERE email = $1
        "#,
    )
    .bind(email)
    .execute(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("mark_email_unsubscribed failed: {e}")))?;
    Ok(res.rows_affected() > 0)
}

/// Lists verified email signups ordered newest-first for founder/admin marketing export.
pub async fn list_email_signups(
    pool: &PgPool,
    marketing_only: bool,
    limit: i64,
) -> ActaResult<Vec<EmailSignupRecord>> {
    let bounded_limit = limit.clamp(1, 10_000);
    if marketing_only {
        sqlx::query_as::<_, EmailSignupRecord>(
            r#"
            SELECT
                email,
                tenant_id,
                principal,
                first_signup_flow,
                first_client_name,
                marketing_opt_in,
                resend_contact_id,
                welcome_sent_at,
                unsubscribed_at,
                verification_count,
                created_at,
                last_verified_at
            FROM email_signups
            WHERE marketing_opt_in = TRUE AND unsubscribed_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(bounded_limit)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("list_email_signups failed: {e}")))
    } else {
        sqlx::query_as::<_, EmailSignupRecord>(
            r#"
            SELECT
                email,
                tenant_id,
                principal,
                first_signup_flow,
                first_client_name,
                marketing_opt_in,
                resend_contact_id,
                welcome_sent_at,
                unsubscribed_at,
                verification_count,
                created_at,
                last_verified_at
            FROM email_signups
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(bounded_limit)
        .fetch_all(pool)
        .await
        .map_err(|e| ActaError::Storage(format!("list_email_signups failed: {e}")))
    }
}
