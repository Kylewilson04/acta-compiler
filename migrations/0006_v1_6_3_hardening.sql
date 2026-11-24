-- Acta Compiler v1.6.3 Auth-Bound Overrides & Append-Only Witness Revocation Migration (Strictly Additive)
-- 1. Preserves `'acta:override:v1'` on historical `override_attestations` rows without firing
--    `BEFORE UPDATE OR DELETE` triggers, while binding `adjudicator_auth_kind`, `client_public_key`,
--    and `client_signature` into `'acta:override:v2'` on newly notarized overrides (`v1.6.3+`).
-- 2. Adds append-only `witness_revocations` protected by `acta_prevent_mutation()` so enrolled
--    witnesses in immutable `trusted_witnesses` can be cryptographically revoked (`acta:witness_revoke:v1`)
--    and quarantined without mutating or deleting historical rows.

ALTER TABLE override_attestations
    ADD COLUMN IF NOT EXISTS att_domain TEXT NOT NULL DEFAULT 'acta:override:v1',
    ADD COLUMN IF NOT EXISTS adjudicator_auth_kind TEXT NULL;

CREATE TABLE IF NOT EXISTS witness_revocations (
    tenant_id TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoke_domain TEXT NOT NULL DEFAULT 'acta:witness_revoke:v1',
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, witness_id),
    FOREIGN KEY (tenant_id, witness_id) REFERENCES trusted_witnesses (tenant_id, witness_id)
);

CREATE INDEX IF NOT EXISTS idx_witness_revocations_tenant_seq
    ON witness_revocations (tenant_id, evidence_seq_num DESC);

DROP TRIGGER IF EXISTS trg_witness_revocations_immutable ON witness_revocations;
CREATE TRIGGER trg_witness_revocations_immutable
    BEFORE UPDATE OR DELETE ON witness_revocations
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
