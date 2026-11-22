# Acta Compiler

Deterministic, policy-gated, cryptographically verifiable context compiler with append-only PostgreSQL + `pgvector` storage, embedded Cedar authorization, and standalone offline verification.

## Non-Negotiable Invariants Enforced

1. **Policy-Before-Read**: `CompilePipeline::compile` evaluates `acta-policy::PolicyGate` (`cedar-policy` v4) in Stage 1 before any query touches `objects` or `knowledge_claims`. `Block` and `Escalate` outcomes append signed entries to `evidence_history` (`bundle_hash = NULL`) and return immediately (`crates/acta-engine/src/pipeline.rs`).
2. **Strict Immutability**: `objects`, `knowledge_claims`, `context_bundles`, and `evidence_history` are strictly append-only (enforced both in `acta-store` and via `BEFORE UPDATE OR DELETE` PostgreSQL triggers in `migrations/0001_initial_schema.sql`). Version updates insert new rows referencing `predecessor_id`.
3. **Bit-for-Bit Determinism**: RFC 8785 (`serde_jcs`) canonical JSON encoding, `BTreeMap` grouping, IEEE-754 `total_cmp` total ordering, microsecond-normalized timestamps, and lexicographically sorted Merkle/list sub-commitments guarantee byte-identical `ContextBundle`, `state_commitment`, and `bundle_hash` outputs.
4. **No Silent Conflict Resolution**: Claim groups failing `min_confidence`, `decisiveness_threshold`, or active `contradiction_ids` emit `DisputeRecord`s (`INSUFFICIENT_CONFIDENCE`, `INSUFFICIENT_MARGIN`, `BLOCKING_CONTRADICTION`) with `escalation_required: true` and render `[DISPUTE: <reason_code>] ... [/DISPUTE]` blocks in `context_text`.
5. **Length-Delimited Hashing**: Every multi-field BLAKE3 hash in `acta-crypto::hash_length_delimited` prefixes each input slice with its 8-byte little-endian byte length (`u64::to_le_bytes`).

## Quickstart & Verification Gates

```bash
cp .env.example .env
docker compose up -d

# 1. Workspace check & unit + 1,000-shuffle proptest + offline tamper tests
cargo check --workspace
cargo test --workspace

# 2. 10,000-row p99 < 15ms compile benchmark
cargo run --release -p acta-server --example bench_10k

# 3. Start HTTP sidecar
cargo run --release --bin acta-server

# 4. Offline verification of an exported bundle archive
cargo run --release --bin acta-verify -- export.json --pubkey <HOST_PUBKEY_HEX>

# 5. Build minimal distroless container image
docker build -t acta-server:latest .
```
