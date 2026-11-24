# Acta Compiler (`v1.7.0`)

Deterministic, policy-gated, cryptographically verifiable context compiler, PPA 1 (`64/112,919`) evidence-chained cognitive system of record, state-conditioned answer cache, and reverse decision recall engine with append-only PostgreSQL + `pgvector` storage, embedded Cedar authorization, 17-tool MCP OAuth 2.1 gateway, and standalone offline verification across Rust, Python, and TypeScript.

## Non-Negotiable Invariants Enforced

1. **Policy-Before-Read**: `CompilePipeline::compile`, write endpoints, state-rebuild, impact tracing, and `cached_answers` endpoints evaluate `acta-policy::PolicyGate` (`cedar-policy` v4) before reading tenant state. Security-relevant `Block` and `Escalate` outcomes append signed entries to `evidence_history`.
2. **Strict Immutability & Write-Path Evidence Chaining**: `objects`, `knowledge_claims`, `override_attestations`, `cached_answers`, `context_bundles`, and `evidence_history` are strictly append-only (enforced via `BEFORE UPDATE OR DELETE` PostgreSQL triggers). In `v1.7.0+`, every accepted non-noop `ingest_object`, `ingest_claim`, and `retract_claim` atomically appends a signed `WriteLedgerSummary` (`acta:write_event:v1` inside `acta:evidence_event:v3`) under `pg_advisory_xact_lock`, enabling ledger-alone state reconstruction (`acta_verify_state_rebuild`).
3. **Bit-for-Bit Determinism & Historical Ledger Preservation**: RFC 8785 (`serde_jcs`) canonical JSON encoding, `BTreeMap` grouping, IEEE-754 `total_cmp` total ordering, microsecond-normalized timestamps, and strict `v1`/`v2`/`v3` domain separation preserve pre-`v1.7.0` entries (`seq 1..153`) 100% bit-for-bit verifiable.
4. **No Silent Conflict Resolution & Lifecycle Retraction**: Claim groups failing `min_confidence`, `decisiveness_threshold`, lapsed overrides (`LAPSED_OVERRIDE_REOPENED`), or active `contradiction_ids` (`BLOCKING_CONTRADICTION`) emit `DisputeRecord`s with `escalation_required: true`. Explicit supersession or `acta_retract_claim` (`status = "revoked"`) clears stale `contradiction_ids` edges deterministically.
5. **State-Conditioned Answer Cache & `O(k)` Reverse Decision Recall**: `acta_cache_answer` / `acta_lookup_cached_answer` implement PPA 1 Claims 19–27 (`O(1)` `state_commitment` invalidation without scanning bundles + host Ed25519 receipt re-verification), and `bundle_dependencies` + `acta_trace_claim_impact` trace every downstream `ContextBundle` and cached answer impacted by a superseded or retracted claim.

## Quickstart & Verification Gates

```bash
cp .env.example .env
docker compose up -d

# 1. Workspace check & 59-test Rust workspace suite (unit, proptest, redteam, live Postgres E2E)
cargo check --workspace
cargo test --workspace --locked

# 2. Python & TypeScript SDK suites
PYTHONPATH=sdks/python python3 -m unittest discover -s sdks/python/tests -v
node sdks/typescript/tests/test_sdk.mjs

# 3. Start HTTP + MCP OAuth 2.1 sidecar
cargo run --release --bin acta-server

# 4. Offline verification of an exported v1.0..v1.7.0 bundle archive
cargo run --release --bin acta-verify -- export.json --pubkey <HOST_PUBKEY_HEX> --dump-preimages
```
