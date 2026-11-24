-- Acta Compiler v1.7.0 Full PPA 1 (64/112,919) Parity & Reverse Decision Recall Migration
-- Strictly additive & append-only: preserves every historical row, hash, and signature in `seq 1..153`
-- without firing `BEFORE UPDATE OR DELETE` immutability triggers (`acta_prevent_mutation()`).

-- 1. Extend `objects` and `knowledge_claims` with optional author key/signature & ledger provenance.
ALTER TABLE objects
    ADD COLUMN IF NOT EXISTS client_public_key BYTEA NULL CHECK (client_public_key IS NULL OR octet_length(client_public_key) = 32),
    ADD COLUMN IF NOT EXISTS written_by TEXT NULL,
    ADD COLUMN IF NOT EXISTS write_domain TEXT NULL,
    ADD COLUMN IF NOT EXISTS evidence_seq_num BIGINT NULL CHECK (evidence_seq_num IS NULL OR evidence_seq_num >= 1);

ALTER TABLE knowledge_claims
    ADD COLUMN IF NOT EXISTS client_signature BYTEA NULL CHECK (client_signature IS NULL OR octet_length(client_signature) = 64),
    ADD COLUMN IF NOT EXISTS client_public_key BYTEA NULL CHECK (client_public_key IS NULL OR octet_length(client_public_key) = 32),
    ADD COLUMN IF NOT EXISTS retraction_reason TEXT NULL,
    ADD COLUMN IF NOT EXISTS written_by TEXT NULL,
    ADD COLUMN IF NOT EXISTS write_domain TEXT NULL,
    ADD COLUMN IF NOT EXISTS evidence_seq_num BIGINT NULL CHECK (evidence_seq_num IS NULL OR evidence_seq_num >= 1);

CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_tenant_evidence_seq
    ON objects (tenant_id, evidence_seq_num)
    WHERE evidence_seq_num IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_claims_tenant_evidence_seq
    ON knowledge_claims (tenant_id, evidence_seq_num)
    WHERE evidence_seq_num IS NOT NULL;

-- 2. Extend `evidence_history` with strip-proof `write_meta` and `answer_cache_meta` (`acta:evidence_event:v3`).
-- Historical `v1.0`..`v1.6.7` rows keep NULL and remain 100% bit-exact under `v1` and `v2`.
ALTER TABLE evidence_history
    ADD COLUMN IF NOT EXISTS write_meta JSONB NULL,
    ADD COLUMN IF NOT EXISTS answer_cache_meta JSONB NULL;

-- 3. PPA 1 Independent Claim 19 (Claims 19–27): State-Conditioned Answer Cache (`cached_answers`).
CREATE TABLE IF NOT EXISTS cached_answers (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    task_id TEXT NOT NULL,
    query_hash BYTEA NOT NULL CHECK (octet_length(query_hash) = 32),
    query_text TEXT NOT NULL DEFAULT '',
    source_bundle_hash BYTEA NOT NULL REFERENCES context_bundles(bundle_hash),
    state_commitment BYTEA NOT NULL CHECK (octet_length(state_commitment) = 32),
    answer_hash BYTEA NOT NULL CHECK (octet_length(answer_hash) = 32),
    answer_text TEXT NOT NULL,
    answer_metadata JSONB NULL,
    cached_by TEXT NOT NULL,
    cacher_auth_kind TEXT NOT NULL,
    client_public_key BYTEA NULL CHECK (client_public_key IS NULL OR octet_length(client_public_key) = 32),
    client_signature BYTEA NULL CHECK (client_signature IS NULL OR octet_length(client_signature) = 64),
    cache_domain TEXT NOT NULL DEFAULT 'acta:answer_cache:v1',
    cache_commitment BYTEA NOT NULL CHECK (octet_length(cache_commitment) = 32),
    evidence_seq_num BIGINT NOT NULL CHECK (evidence_seq_num >= 1),
    host_signature BYTEA NOT NULL CHECK (octet_length(host_signature) = 64),
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cached_answers_lookup
    ON cached_answers (tenant_id, scope, task_id, query_hash, created_at DESC, evidence_seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_cached_answers_bundle
    ON cached_answers (tenant_id, source_bundle_hash);

DROP TRIGGER IF EXISTS trg_cached_answers_immutable ON cached_answers;
CREATE TRIGGER trg_cached_answers_immutable
    BEFORE UPDATE OR DELETE ON cached_answers
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();

-- 4. Reverse Decision-Recall / Blast-Radius Index (`bundle_dependencies`).
CREATE TABLE IF NOT EXISTS bundle_dependencies (
    tenant_id TEXT NOT NULL,
    item_id UUID NOT NULL,
    item_kind TEXT NOT NULL CHECK (item_kind IN ('claim', 'object', 'override')),
    dependency_role TEXT NOT NULL CHECK (
        dependency_role IN (
            'resolved_winner',
            'suppressed_candidate',
            'disputed_candidate',
            'selected_intent',
            'selected_memory',
            'applied_override',
            'lapsed_override'
        )
    ),
    bundle_hash BYTEA NOT NULL REFERENCES context_bundles(bundle_hash),
    scope TEXT NOT NULL,
    task_id TEXT NOT NULL,
    state_commitment BYTEA NOT NULL CHECK (octet_length(state_commitment) = 32),
    bundle_issued_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, item_id, dependency_role, bundle_hash)
);

CREATE INDEX IF NOT EXISTS idx_bundle_dependencies_item_lookup
    ON bundle_dependencies (tenant_id, item_id, bundle_issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_bundle_dependencies_bundle
    ON bundle_dependencies (tenant_id, bundle_hash);

-- Backfill `bundle_dependencies` for all historical `context_bundles` (`seq 1..153`) idempotently.
WITH parsed_bundles AS (
    SELECT
        cb.tenant_id,
        cb.bundle_hash,
        cb.state_commitment,
        cb.created_at,
        convert_from(cb.bundle_canonical, 'UTF8')::jsonb AS bjson
    FROM context_bundles cb
)
INSERT INTO bundle_dependencies (
    tenant_id, item_id, item_kind, dependency_role,
    bundle_hash, scope, task_id, state_commitment, bundle_issued_at, created_at
)
SELECT
    pb.tenant_id,
    (sel->>'id')::uuid AS item_id,
    'object' AS item_kind,
    CASE WHEN sel->>'obj_type' = 'intent' THEN 'selected_intent' ELSE 'selected_memory' END AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'selected_objects', '[]'::jsonb)) AS sel
UNION ALL
SELECT
    pb.tenant_id,
    (res->'winning_claim'->>'id')::uuid AS item_id,
    'claim' AS item_kind,
    'resolved_winner' AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'resolution_records', '[]'::jsonb)) AS res
UNION ALL
SELECT
    pb.tenant_id,
    (sup_id #>> '{}')::uuid AS item_id,
    'claim' AS item_kind,
    'suppressed_candidate' AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'resolution_records', '[]'::jsonb)) AS res
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(res->'suppressed_claim_ids', '[]'::jsonb)) AS sup_id
UNION ALL
SELECT
    pb.tenant_id,
    (res->'override_attestation'->>'attestation_id')::uuid AS item_id,
    'override' AS item_kind,
    'applied_override' AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'resolution_records', '[]'::jsonb)) AS res
WHERE res->'override_attestation' IS NOT NULL AND jsonb_typeof(res->'override_attestation') = 'object'
UNION ALL
SELECT
    pb.tenant_id,
    (cand->>'id')::uuid AS item_id,
    'claim' AS item_kind,
    'disputed_candidate' AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'dispute_records', '[]'::jsonb)) AS disp
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(disp->'competing_claims', '[]'::jsonb)) AS cand
UNION ALL
SELECT
    pb.tenant_id,
    (disp->'lapsed_override'->>'attestation_id')::uuid AS item_id,
    'override' AS item_kind,
    'lapsed_override' AS dependency_role,
    pb.bundle_hash,
    pb.bjson->>'scope' AS scope,
    pb.bjson->>'task_id' AS task_id,
    pb.state_commitment,
    (pb.bjson->>'issued_at')::timestamptz AS bundle_issued_at,
    pb.created_at
FROM parsed_bundles pb
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(pb.bjson->'dispute_records', '[]'::jsonb)) AS disp
WHERE disp->'lapsed_override' IS NOT NULL AND jsonb_typeof(disp->'lapsed_override') = 'object'
ON CONFLICT (tenant_id, item_id, dependency_role, bundle_hash) DO NOTHING;

DROP TRIGGER IF EXISTS trg_bundle_dependencies_immutable ON bundle_dependencies;
CREATE TRIGGER trg_bundle_dependencies_immutable
    BEFORE UPDATE OR DELETE ON bundle_dependencies
    FOR EACH ROW EXECUTE FUNCTION acta_prevent_mutation();
