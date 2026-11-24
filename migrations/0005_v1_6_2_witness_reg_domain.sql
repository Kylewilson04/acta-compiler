-- Acta Compiler v1.6.2 Trusted Witness Registration Domain Migration (Strictly Additive)
-- Preserves `'acta:witness_reg:v1'` on existing v1.6.1 witness rows (e.g. `seq 58` `claude-witness-v161`)
-- without firing `BEFORE UPDATE OR DELETE` row triggers, while binding `registered_by` into
-- `'acta:witness_reg:v2'` on newly enrolled witnesses (`v1.6.2+`).

ALTER TABLE trusted_witnesses
    ADD COLUMN IF NOT EXISTS reg_domain TEXT NOT NULL DEFAULT 'acta:witness_reg:v1';
