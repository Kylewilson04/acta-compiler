# CLAUDE.md — `acta-compiler`

## Project Overview
`acta-compiler` (`v1.5.0`) is a 7-crate Rust (`2021` edition) deterministic cryptographic context compiler, Epistemic Notary, Cedar policy gate, MCP OAuth 2.1 gateway, and Control Plane deployed on Google Cloud Run (`https://acta-server-998422936041.us-west1.run.app`, project `compounder-core-prod-487014`, region `us-west1`) backed by Cloud SQL PostgreSQL 17 (`acta-pg17`).

## Mandatory ACTA Context Protocol (`scope = "acta-compiler"`)
1. **Compile First**: At the start of every session and before answering architectural/state questions or modifying code, call `acta_compile_context` with `scope: "acta-compiler"`, `actor_id: "claude"`, and `token_budget: 2048`. Every compiled `ContextBundle` binds a `resolver_manifest` (`min_confidence`, `decisiveness_threshold`, `corroboration_damping`, `non_default_thresholds`, `budget`, `permission_root`) directly into `bundle_hash`.
2. **Never Guess Through Disputes (`acta_attest_override`)**: If `context_text` contains `[DISPUTE: ...]` or `policy_decision` is `"escalate"`, halt silent resolution and surface all candidate claims and margins to the user. Only call `acta_attest_override` after explicit human authorization naming the winning claim and justification; if any unseen conflicting claim arrives later, the resolver automatically re-escalates to `[DISPUTE]`.
3. **Write-Through Persistence**: Persist newly confirmed architectural invariants, version pins, endpoints, or security rules to `scope: "acta-compiler"` via `acta_ingest_claim` (native JSON `object_val`, clean `source_descriptor` without newlines/`[`/`]`/`..`) or `acta_ingest_object` (`"intent"` priority `100` for standing constraints, `"memory"` priority `50` for notes).
4. **Provenance Receipt**: End ACTA-backed replies with `ACTA: scope=acta-compiler | bundle=<12-hex> | seq=<seq_num>`.

## Build & Verification Commands
- Run full workspace tests: `cargo test --workspace`
- Build locked release binaries: `cargo build --release --locked --bin acta-server --bin acta-verify`
- Run Python SDK tests: `PYTHONPATH=sdks/python python3 -m unittest discover -s sdks/python/tests -v`
- Run TypeScript SDK tests: `node sdks/typescript/tests/test_sdk.mjs`
