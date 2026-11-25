-- Acta v1.7.3: Host Key Rotation Ledger, Salted-Commitment Cryptographic Erasure & Pilot Readiness
-- Strictly additive: zero updates or deletes on existing rows (`seq 1..219` remain bit-for-bit intact).

ALTER TABLE evidence_history
    ADD COLUMN IF NOT EXISTS host_key_rotation_meta JSONB;

CREATE TABLE IF NOT EXISTS host_key_rotations (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    old_public_key BYTEA NOT NULL CHECK (octet_length(old_public_key) = 32),
    new_public_key BYTEA NOT NULL CHECK (octet_length(new_public_key) = 32),
    effective_from_seq BIGINT NOT NULL CHECK (effective_from_seq >= 1),
    rotation_mode TEXT NOT NULL DEFAULT 'scheduled'
        CHECK (rotation_mode IN ('scheduled', 'compromise_recovery')),
    compromised_from_seq BIGINT,
    reason TEXT NOT NULL,
    old_key_signature BYTEA CHECK (old_key_signature IS NULL OR octet_length(old_key_signature) = 64),
    new_key_signature BYTEA NOT NULL CHECK (octet_length(new_key_signature) = 64),
    rotated_by TEXT NOT NULL,
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, effective_from_seq)
);

CREATE INDEX IF NOT EXISTS idx_host_key_rotations_tenant_seq
    ON host_key_rotations (tenant_id, effective_from_seq ASC);

DROP TRIGGER IF EXISTS trg_host_key_rotations_immutable ON host_key_rotations;
CREATE TRIGGER trg_host_key_rotations_immutable
    BEFORE UPDATE OR DELETE ON host_key_rotations
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();

-- Mutable ONLY for GDPR / PII cryptographic secret destruction (`DELETE` on `erase_secret = true`).
CREATE TABLE IF NOT EXISTS erasable_item_secrets (
    tenant_id TEXT NOT NULL,
    item_id UUID NOT NULL,
    item_kind TEXT NOT NULL CHECK (item_kind IN ('claim', 'object')),
    salt_32 BYTEA NOT NULL CHECK (octet_length(salt_32) = 32),
    sensitive_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, item_id)
);

ALTER TABLE knowledge_claims
    ADD COLUMN IF NOT EXISTS erasure_commitment BYTEA CHECK (erasure_commitment IS NULL OR octet_length(erasure_commitment) = 32),
    ADD COLUMN IF NOT EXISTS erased_at TIMESTAMPTZ;

-- Append-only ledger index tracking opt-in `legacy_import` backfill of pre-v1.7.0 unchained items
-- without issuing UPDATEs against immutable `objects` or `knowledge_claims`.
CREATE TABLE IF NOT EXISTS legacy_backfilled_items (
    tenant_id TEXT NOT NULL,
    item_id UUID NOT NULL,
    item_kind TEXT NOT NULL CHECK (item_kind IN ('object', 'claim')),
    scope TEXT NOT NULL,
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, item_id)
);

CREATE INDEX IF NOT EXISTS idx_legacy_backfilled_items_tenant_scope
    ON legacy_backfilled_items (tenant_id, scope, evidence_seq_num ASC);

DROP TRIGGER IF EXISTS trg_legacy_backfilled_items_immutable ON legacy_backfilled_items;
CREATE TRIGGER trg_legacy_backfilled_items_immutable
    BEFORE UPDATE OR DELETE ON legacy_backfilled_items
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
