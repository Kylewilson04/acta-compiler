-- Acta Compiler v1.6 Merkle Checkpoints & External Witness Anchoring Migration (Strictly Additive)
-- Creates append-only `checkpoint_anchors` storing external witness cosignatures and transparency
-- URIs over deterministic `SignedTreeHead` checkpoints (`acta:witness_sig:v1`).

CREATE TABLE IF NOT EXISTS checkpoint_anchors (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 1),
    head_event_hash BYTEA NOT NULL CHECK (octet_length(head_event_hash) = 32),
    merkle_root BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
    checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
    witness_id TEXT NOT NULL,
    witness_public_key BYTEA NOT NULL CHECK (octet_length(witness_public_key) = 32),
    witness_signature BYTEA NOT NULL CHECK (octet_length(witness_signature) = 64),
    external_uri TEXT NULL,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, tree_size, witness_public_key)
);

CREATE INDEX IF NOT EXISTS idx_checkpoint_anchors_tenant_size
    ON checkpoint_anchors (tenant_id, tree_size DESC);

DROP TRIGGER IF EXISTS trg_checkpoint_anchors_immutable ON checkpoint_anchors;
CREATE TRIGGER trg_checkpoint_anchors_immutable
    BEFORE UPDATE OR DELETE ON checkpoint_anchors
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
