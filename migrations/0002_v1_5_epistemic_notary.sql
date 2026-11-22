-- Acta Compiler v1.5 Epistemic Notary Migration (Strictly Additive & Append-Only)
-- 1. Adds human/auditor-readable refusal & override metadata columns to `evidence_history`
--    (cryptographically bound via `acta:evidence_event:v2` on new v1.5 entries while leaving
--    historical v1.0–v1.4 rows NULL and 100% bit-exact under `acta:evidence_event:v1`).
-- 2. Creates the append-only `override_attestations` table for signed dispute adjudications.

ALTER TABLE evidence_history
    ADD COLUMN IF NOT EXISTS refusal_meta JSONB NULL,
    ADD COLUMN IF NOT EXISTS override_meta JSONB NULL;

CREATE TABLE IF NOT EXISTS override_attestations (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    claim_group_key BYTEA NOT NULL CHECK (octet_length(claim_group_key) = 32),
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    source_bundle_hash BYTEA NULL CHECK (source_bundle_hash IS NULL OR octet_length(source_bundle_hash) = 32),
    winning_claim_id UUID NOT NULL REFERENCES knowledge_claims(id),
    winning_claim_content_hash BYTEA NOT NULL CHECK (octet_length(winning_claim_content_hash) = 32),
    overridden_claims JSONB NOT NULL,
    adjudicator_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    version INT NOT NULL DEFAULT 1 CHECK (version >= 1),
    predecessor_id UUID NULL REFERENCES override_attestations(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attestation_hash BYTEA NOT NULL CHECK (octet_length(attestation_hash) = 32),
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    host_signature BYTEA NOT NULL CHECK (octet_length(host_signature) = 64),
    client_signature BYTEA NULL,
    client_public_key BYTEA NULL CHECK (client_public_key IS NULL OR octet_length(client_public_key) = 32)
);

CREATE INDEX IF NOT EXISTS idx_override_attestations_tenant_scope_group
    ON override_attestations (tenant_id, scope, claim_group_key);

CREATE INDEX IF NOT EXISTS idx_override_attestations_tenant_predecessor
    ON override_attestations (tenant_id, predecessor_id)
    WHERE predecessor_id IS NOT NULL;

DROP TRIGGER IF EXISTS trg_override_attestations_immutable ON override_attestations;
CREATE TRIGGER trg_override_attestations_immutable
    BEFORE UPDATE OR DELETE ON override_attestations
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
