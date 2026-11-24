-- Acta Compiler v1.7.2 Migration:
--   1. Event v3 Witness Registration & Revocation Preimage Columns (`witness_reg_meta`, `witness_revoke_meta`)
-- Strictly additive & zero-mutation: never fires `BEFORE UPDATE OR DELETE` (`acta_prevent_mutation()`).
-- Historical `evidence_history` rows (`seq 1..184`, including `seq 109` and `seq 183`) keep NULL in both
-- columns and remain 100% bit-for-bit verifiable under `acta:evidence_event:v1`.

ALTER TABLE evidence_history
    ADD COLUMN IF NOT EXISTS witness_reg_meta JSONB NULL,
    ADD COLUMN IF NOT EXISTS witness_revoke_meta JSONB NULL;
