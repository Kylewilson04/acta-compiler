-- Acta v1.7.3: Verified Email Signups, Marketing Consent & Resend Contact Sync
-- Strictly additive: zero updates or deletes on cryptographic ledger tables (`seq 1..234` untouched).

CREATE TABLE IF NOT EXISTS email_signups (
    email TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    first_signup_flow TEXT NOT NULL CHECK (first_signup_flow IN ('oauth', 'signup')),
    first_client_name TEXT NOT NULL,
    marketing_opt_in BOOLEAN NOT NULL DEFAULT TRUE,
    resend_contact_id TEXT,
    welcome_sent_at TIMESTAMPTZ,
    unsubscribed_at TIMESTAMPTZ,
    verification_count BIGINT NOT NULL DEFAULT 1 CHECK (verification_count >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_signups_created_at
    ON email_signups (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_email_signups_marketing_opt_in
    ON email_signups (marketing_opt_in, created_at DESC);
