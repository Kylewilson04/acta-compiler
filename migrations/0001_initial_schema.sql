-- Acta Compiler Initial Schema (Append-Only / Strictly Immutable)
-- Enforces Non-Negotiable Invariant 2: Strict Immutability across all 4 core tables.

CREATE EXTENSION IF NOT EXISTS vector;

-- 1. Objects table: stores versioned, append-only intents and memories.
CREATE TABLE IF NOT EXISTS objects (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    obj_type TEXT NOT NULL CHECK (obj_type IN ('intent', 'memory')),
    scope TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN ('active', 'revoked', 'expired', 'superseded')),
    priority INT NOT NULL DEFAULT 0,
    importance REAL NOT NULL DEFAULT 0.0,
    tags TEXT[] NOT NULL DEFAULT '{}',
    body JSONB NOT NULL,
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    embedding vector(1536),
    version INT NOT NULL DEFAULT 1 CHECK (version >= 1),
    predecessor_id UUID REFERENCES objects(id),
    client_signature BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Knowledge claims table: stores versioned, append-only structured claims.
CREATE TABLE IF NOT EXISTS knowledge_claims (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    claim_group_key BYTEA NOT NULL CHECK (octet_length(claim_group_key) = 32),
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_val JSONB NOT NULL,
    object_type TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_provenance_class INT NOT NULL DEFAULT 0,
    source_descriptor TEXT NOT NULL,
    source_commitment BYTEA NOT NULL CHECK (octet_length(source_commitment) = 32),
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired', 'superseded')),
    contradiction_ids UUID[] NOT NULL DEFAULT '{}',
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    version INT NOT NULL DEFAULT 1 CHECK (version >= 1),
    predecessor_id UUID REFERENCES knowledge_claims(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Context bundles table: content-addressed canonical bundles.
CREATE TABLE IF NOT EXISTS context_bundles (
    bundle_hash BYTEA PRIMARY KEY CHECK (octet_length(bundle_hash) = 32),
    tenant_id TEXT NOT NULL,
    state_commitment BYTEA NOT NULL CHECK (octet_length(state_commitment) = 32),
    dependency_commitment BYTEA NOT NULL CHECK (octet_length(dependency_commitment) = 32),
    bundle_canonical BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Evidence history table: per-tenant monotonic hash-chained audit ledger.
CREATE TABLE IF NOT EXISTS evidence_history (
    tenant_id TEXT NOT NULL,
    seq_num BIGINT NOT NULL CHECK (seq_num >= 1),
    prev_hash BYTEA NOT NULL CHECK (octet_length(prev_hash) = 32),
    event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32),
    bundle_hash BYTEA NULL REFERENCES context_bundles(bundle_hash),
    state_commitment BYTEA NULL CHECK (state_commitment IS NULL OR octet_length(state_commitment) = 32),
    policy_result TEXT NOT NULL CHECK (policy_result IN ('allow', 'block', 'escalate')),
    host_signature BYTEA NOT NULL CHECK (octet_length(host_signature) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, seq_num)
);

-- 5. Composite, predecessor, and HNSW vector indexes.
CREATE INDEX IF NOT EXISTS idx_objects_tenant_scope_lifecycle
    ON objects (tenant_id, scope, lifecycle_status);

CREATE INDEX IF NOT EXISTS idx_objects_scope_covering
    ON objects (tenant_id, scope, obj_type, lifecycle_status)
    INCLUDE (id, content_hash, priority, importance, version, created_at);

CREATE INDEX IF NOT EXISTS idx_objects_tenant_predecessor
    ON objects (tenant_id, predecessor_id)
    WHERE predecessor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_claims_tenant_scope_group_status
    ON knowledge_claims (tenant_id, scope, claim_group_key, status);

CREATE INDEX IF NOT EXISTS idx_claims_scope_covering
    ON knowledge_claims (tenant_id, scope, status)
    INCLUDE (id, content_hash, valid_from, valid_to);

CREATE INDEX IF NOT EXISTS idx_claims_tenant_predecessor
    ON knowledge_claims (tenant_id, predecessor_id)
    WHERE predecessor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_objects_embedding_hnsw
    ON objects USING hnsw (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS idx_evidence_history_bundle_hash
    ON evidence_history (bundle_hash)
    WHERE bundle_hash IS NOT NULL;

-- 6. Database-level immutability guard enforcing Invariant 2 (Append-Only).
CREATE OR REPLACE FUNCTION acta_prevent_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Invariant violation: table "%" is strictly append-only; % is forbidden', TG_TABLE_NAME, TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS trg_objects_immutable ON objects;
CREATE TRIGGER trg_objects_immutable
    BEFORE UPDATE OR DELETE ON objects
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();

DROP TRIGGER IF EXISTS trg_knowledge_claims_immutable ON knowledge_claims;
CREATE TRIGGER trg_knowledge_claims_immutable
    BEFORE UPDATE OR DELETE ON knowledge_claims
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();

DROP TRIGGER IF EXISTS trg_context_bundles_immutable ON context_bundles;
CREATE TRIGGER trg_context_bundles_immutable
    BEFORE UPDATE OR DELETE ON context_bundles
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();

DROP TRIGGER IF EXISTS trg_evidence_history_immutable ON evidence_history;
CREATE TRIGGER trg_evidence_history_immutable
    BEFORE UPDATE OR DELETE ON evidence_history
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
