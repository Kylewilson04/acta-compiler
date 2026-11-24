-- Acta Compiler v1.6.4 Non-Retroactive Witness Retirement Mode Migration (Strictly Additive)
-- Preserves `'compromise'` (`effective_from_tree_size = NULL`, retroactive quarantine across all
-- tree sizes) on historical `v1.6.3` revocations (e.g. `seq 78`) without firing `BEFORE UPDATE OR DELETE`
-- triggers, while enabling `revocation_mode = 'retire'` (`effective_from_tree_size = revocation_seq_num`)
-- so scheduled witness key rotations preserve historical cosignatures at `tree_size < effective_from_tree_size`
-- while blocking all post-retirement anchors (`acta:witness_revoke:v2`).

ALTER TABLE witness_revocations
    ADD COLUMN IF NOT EXISTS revocation_mode TEXT NOT NULL DEFAULT 'compromise',
    ADD COLUMN IF NOT EXISTS effective_from_tree_size BIGINT NULL;
