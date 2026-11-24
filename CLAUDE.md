# CLAUDE.md — `acta-compiler`

## Project Overview
`acta-compiler` (`v1.7.0`) is a 7-crate Rust (`2021` edition) deterministic cryptographic context compiler, Epistemic Notary, PPA 1 Ledger-Chained Cognitive System of Record, State-Conditioned Answer Cache (Claims 19–27), Reverse Decision Recall Engine, RFC 6962 §2.1 SHA-256 Merkle transparency ledger, Cedar policy gate, MCP OAuth 2.1 gateway, and Control Plane deployed on Google Cloud Run (`https://acta-server-998422936041.us-west1.run.app`, project `compounder-core-prod-487014`, region `us-west1`) backed by Cloud SQL PostgreSQL 17 (`acta-pg17`).

## Mandatory ACTA Context Protocol (`scope = "acta-compiler"`)
1. **Compile First & Reuse State-Conditioned Answers**: At the start of every session and before answering architectural/state questions or modifying code, check `acta_lookup_cached_answer` or call `acta_compile_context` with `scope: "acta-compiler"`, `actor_id: "claude"`, and `token_budget: 2048`. Every compiled `ContextBundle` binds a `resolver_manifest` (`min_confidence`, `decisiveness_threshold`, `corroboration_damping`, `non_default_thresholds`, `budget`, `permission_root`) directly into `bundle_hash` and indexes every included object/claim/override into `bundle_dependencies`.
2. **Never Guess Through Disputes (`acta_attest_override`)**: If `context_text` contains `[DISPUTE: ...]` (including `BLOCKING_CONTRADICTION` or `LAPSED_OVERRIDE_REOPENED`) or `policy_decision` is `"escalate"`, halt silent resolution and surface all candidate claims and margins to the user. Only call `acta_attest_override` after explicit human authorization: omit `adjudicator_id` to bind your verified OAuth principal (`<tenant>::oauth:<github_login>`), or supply an offline Ed25519 `client_signature_hex` + `client_public_key_hex` (`b"acta:override_client_sig:v1"`) when asserting a third-party/committee `adjudicator_id` or overriding on `compliance/*`, `governance/*`, or `regulated/*` scopes.
3. **Chained Write-Through Persistence, Author Signatures, Retractions & Decision Recall**:
   - Every accepted non-noop `acta_ingest_object`, `acta_ingest_claim`, and `acta_retract_claim` atomically appends a signed `WriteLedgerSummary` (`acta:write_event:v1` inside `acta:evidence_event:v3`) onto `evidence_history` so active scope state and `state_commitment` can be reconstructed from the evidence chain alone via `acta_verify_state_rebuild`.
   - Optional offline Ed25519 author signatures (`client_signature_hex` + `client_public_key_hex`) are supported on `acta_ingest_object` (`acta:object_client_sig:v1`), `acta_ingest_claim` (`acta:claim_client_sig:v1`), `acta_retract_claim` (`acta:retract_client_sig:v1`), and `acta_cache_answer` (`acta:answer_client_sig:v1`).
   - Explicit graph & temporal lifecycle controls (`predecessor_id`, `contradiction_ids`, `valid_from`, `valid_to`, and immutable `status="revoked"` tombstones via `acta_retract_claim`) automatically clear `BLOCKING_CONTRADICTION` edges once the contradicted target claim is superseded or retracted, and `acta_trace_claim_impact` identifies all historical `ContextBundle`s and `cached_answers` that depended on any claim or object in `O(k)` indexed time.
4. **Provenance Receipt**: End ACTA-backed replies with `ACTA: scope=acta-compiler | bundle=<12-hex> | seq=<seq_num>`.

## Build & Verification Commands
- Run full workspace tests: `cargo test --workspace`
- Build locked release binaries: `cargo build --release --locked --bin acta-server --bin acta-verify`
- Verify archive with raw byte preimages: `./target/release/acta-verify <archive.json> --pubkey <hex> --dump-preimages`
- Run Python SDK tests: `PYTHONPATH=sdks/python python3 -m unittest discover -s sdks/python/tests -v`
- Run TypeScript SDK tests: `node sdks/typescript/tests/test_sdk.mjs`
- Run 50-way barrier concurrency & state-rebuild harness: `python3 scripts/acta_concurrency_harness.py --url http://127.0.0.1:8080`
- Canonical Wire-Format & Domain Specification: see `SPEC.md`.
