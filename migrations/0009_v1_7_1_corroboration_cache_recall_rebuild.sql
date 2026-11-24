-- Acta Compiler v1.7.1 Migration:
--   1. PPA 1 Claim 25 Dependency-Scoped Answer Cache Validity (`validity_mode`, `task_dependency_commitment`, `dependency_spec`)
--   2. Append-Only Chained Cache Invalidation Receipts (`cached_answer_invalidations`)
-- Strictly additive & zero-mutation: never fires `BEFORE UPDATE OR DELETE` (`acta_prevent_mutation()`)
-- on historical `cached_answers`, `evidence_history`, `objects`, or `knowledge_claims` rows.

ALTER TABLE cached_answers
    ADD COLUMN IF NOT EXISTS validity_mode TEXT NOT NULL DEFAULT 'scope_root'
        CHECK (validity_mode IN ('scope_root', 'dependency_subset')),
    ADD COLUMN IF NOT EXISTS task_dependency_commitment BYTEA NULL
        CHECK (task_dependency_commitment IS NULL OR octet_length(task_dependency_commitment) = 32),
    ADD COLUMN IF NOT EXISTS dependency_spec JSONB NULL;

CREATE TABLE IF NOT EXISTS cached_answer_invalidations (
    cache_id UUID PRIMARY KEY REFERENCES cached_answers(id),
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    task_id TEXT NOT NULL,
    invalidation_reason TEXT NOT NULL CHECK (
        invalidation_reason IN (
            'stale_dependency_commitment',
            'stale_state_commitment',
            'expired_ttl'
        )
    ),
    observed_state_commitment BYTEA NOT NULL CHECK (octet_length(observed_state_commitment) = 32),
    observed_dependency_commitment BYTEA NULL CHECK (
        observed_dependency_commitment IS NULL OR octet_length(observed_dependency_commitment) = 32
    ),
    invalidated_by TEXT NOT NULL,
    invalidator_auth_kind TEXT NOT NULL,
    cache_commitment BYTEA NOT NULL CHECK (octet_length(cache_commitment) = 32),
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cached_answer_invalidations_tenant_seq
    ON cached_answer_invalidations (tenant_id, evidence_seq_num);

CREATE INDEX IF NOT EXISTS idx_cached_answer_invalidations_tenant_scope
    ON cached_answer_invalidations (tenant_id, scope, created_at DESC);

DROP TRIGGER IF EXISTS trg_cached_answer_invalidations_immutable ON cached_answer_invalidations;
CREATE TRIGGER trg_cached_answer_invalidations_immutable
    BEFORE UPDATE OR DELETE ON cached_answer_invalidations
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
