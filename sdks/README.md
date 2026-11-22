# Acta Compiler v1.1 Official SDKs (`acta-sdk` & `@acta/sdk`)

Zero-trust client SDKs, stateless per-client Keyed-BLAKE3 token minters (`acta_tk_v1`), offline cryptographic bundle verifiers, and pre-inference Gemini guardrails for the live [Acta Control Plane](https://acta-server-998422936041.us-west1.run.app/).

## v1.1 Multi-Business & Multi-Agent Isolation

Claude, Gemini, and your terminal agent (`pi` / CLI) all share your single [Acta Cloud Run service](https://acta-server-998422936041.us-west1.run.app/) while keeping businesses and external clients cryptographically isolated via stateless **Keyed-BLAKE3 Tenant Tokens (`acta_tk_v1:<tenant_id>:<mac>`)** and **`X-Acta-Tenant`** locking:

1. **Mint a locked key per business or client repo** (requires master `ACTA_API_KEY`):
   ```bash
   ACTA_API_KEY="$(gcloud secrets versions access latest --secret=acta-api-key --project=compounder-core-prod-487014)" \
     python3 -m acta_sdk.cli mint-key client-acme
   ```
2. **Drop the printed config into that project's `.gemini/settings.json` ([Gemini CLI docs](https://geminicli.com/docs/reference/configuration/)) or `.cursor/mcp.json` ([Cursor MCP guide](https://datamcp.app/blog/cursor-mcp-setup-guide))**:
   - Every `/mcp` tool call in that folder automatically defaults to `client-acme`—no need to specify `tenant_id` in prompts.
   - Any prompt-injected or accidental attempt to read, write, replay, or export another business (`ardyn-core`, `client-b`) is rejected in constant time at the HTTP edge before [`cedar-policy`](https://docs.rs/cedar-policy/latest/cedar_policy/struct.PolicySet.html) or PostgreSQL executes a single instruction.
3. **Automatic Tenant Inference in Python & TypeScript SDKs**:
   - Initializing `ActaClient(api_key="acta_tk_v1:client-acme:...")` or `new ActaClient({ apiKey: "acta_tk_v1:client-acme:..." })` automatically binds `locked_tenant = "client-acme"`, attaches `X-Acta-Tenant: client-acme`, makes `tenant_id` optional on [`google-genai`](https://github.com/googleapis/python-genai) and [`@google/genai`](https://www.npmjs.com/package/@google/genai) `ActaGeminiGuard` calls, and verifies every receipt via RFC 8785 JCS ([`serde_jcs`](https://docs.rs/serde_jcs/latest/src/serde_jcs/lib.rs.html)) and strict Ed25519 ([`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html)).
