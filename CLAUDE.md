# CLAUDE.md — `acta-compiler`

## Project Overview
`acta-compiler` (`v1.6.0`) is a 7-crate Rust (`2021` edition) deterministic cryptographic context compiler, Epistemic Notary, RFC 6962 Merkle transparency ledger, Cedar policy gate, MCP OAuth 2.1 gateway, and Control Plane deployed on Google Cloud Run (`https://acta-server-998422936041.us-west1.run.app`, project `compounder-core-prod-487014`, region `us-west1`) backed by Cloud SQL PostgreSQL 17 (`acta-pg17`).

## Mandatory ACTA Context Protocol (`scope = "acta-compiler"`)
1. **Compile First**: At the start of every session and before answering architectural/state questions or modifying code, call `acta_compile_context` with `scope: "acta-compiler"`, `actor_id: "claude"`, and `token_budget: 2048`. Every compiled `ContextBundle` binds a `resolver_manifest` (`min_confidence`, `decisiveness_threshold`, `corroboration_damping`, `non_default_thresholds`, `budget`, `permission_root`) directly into `bundle_hash`.
2. **Never Guess Through Disputes (`acta_attest_override`)**: If `context_text` contains `[DISPUTE: ...]` or `policy_decision` is `"escalate"`, halt silent resolution and surface all candidate claims and margins (plus any `lapsed_override` provenance) to the user. Only call `acta_attest_override` after explicit human authorization: omit `adjudicator_id` to bind your verified OAuth principal (`<tenant>::oauth:<github_login>`), or supply an offline Ed25519 `client_signature_hex` + `client_public_key_hex` (`b"acta:override_client_sig:v1"`) when asserting a third-party/committee `adjudicator_id` or overriding on `compliance/*`, `governance/*`, or `regulated/*` scopes.
3. **Write-Through Persistence & Merkle Proofs**: Persist newly confirmed architectural invariants, version pins, endpoints, or security rules to `scope: "acta-compiler"` via `acta_ingest_claim` (native JSON `object_val`, clean `source_descriptor` without newlines/`[`/`]`/`..`) or `acta_ingest_object` (`"intent"` priority `100`, `"memory"` priority `50`). Use `acta_get_checkpoint` for RFC 6962 `SignedTreeHead` checkpoints + `O(log N)` consistency proofs, and `acta_verify_bundle` (`proof_mode: "merkle"` or `"full"`, `dump_preimages: true`) for independent audit verification.
4. **Provenance Receipt**: End ACTA-backed replies with `ACTA: scope=acta-compiler | bundle=<12-hex> | seq=<seq_num>`.

## Build & Verification Commands
- Run full workspace tests: `cargo test --workspace`
- Build locked release binaries: `cargo build --release --locked --bin acta-server --bin acta-verify`
- Verify archive with preimages: `./target/release/acta-verify <archive.json> --pubkey <hex> --dump-preimages`
- Run Python SDK tests: `PYTHONPATH=sdks/python python3 -m unittest discover -s sdks/python/tests -v`
- Run TypeScript SDK tests: `node sdks/typescript/tests/test_sdk.mjs`
