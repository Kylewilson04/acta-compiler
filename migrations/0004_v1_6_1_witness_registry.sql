-- Acta Compiler v1.6.1 Trusted Witness Registry Migration (Strictly Additive)
-- Pins enrolled external witness Ed25519 public keys per (tenant_id, witness_id) and binds
-- each registration to an append-only `evidence_history` sequence number (`acta:witness_reg:v1`).

CREATE TABLE IF NOT EXISTS trusted_witnesses (
    tenant_id TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    description TEXT NULL,
    registered_by TEXT NOT NULL,
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, witness_id),
    UNIQUE (tenant_id, public_key)
);

CREATE INDEX IF NOT EXISTS idx_trusted_witnesses_tenant_active
    ON trusted_witnesses (tenant_id, active, created_at DESC);

DROP TRIGGER IF EXISTS trg_trusted_witnesses_immutable ON trusted_witnesses;
CREATE TRIGGER trg_trusted_witnesses_immutable
    BEFORE UPDATE OR DELETE ON trusted_witnesses
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
