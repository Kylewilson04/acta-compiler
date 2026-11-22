#!/usr/bin/env node
/**
 * Live end-to-end verification of `@acta/sdk` v1.1 (TypeScript/ESM) against Cloud Run.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  DEFAULT_CLOUDRUN_URL,
  ActaClient,
  ActaDisputeEscalationError,
  ActaGeminiGuard,
  ActaPolicyEscalatedError,
  ActaTenantLockError,
  extractTokenTenant,
} from "../typescript/dist/index.mjs";

const baseUrl = process.env.ACTA_BASE_URL || DEFAULT_CLOUDRUN_URL;
const apiKey = process.env.ACTA_API_KEY;
const tokTenant = apiKey ? extractTokenTenant(apiKey) : null;
const defaultTenantId = tokTenant ? undefined : apiKey ? "prod-ts-sdk" : "sandbox-ts-sdk";
const scope = `settlement-${crypto.randomBytes(3).toString("hex")}`;

const client = new ActaClient({ baseUrl, apiKey, defaultTenantId });
console.log(`[ts-sdk v1.1] Connected to ${baseUrl} (lockedTenant=${client.lockedTenant}, scope=${scope})`);
const health = await client.health();
console.log(`[ts-sdk v1.1] Health v${health.version} OK -> host Ed25519 key: ${health.host_public_key}`);

await assert.rejects(
  () =>
    client.compile({
      tenantId: "other-unrelated-business",
      actorId: "claude",
      scope,
      queryText: "cross-tenant probe",
    }),
  ActaTenantLockError
);
console.log(`[ts-sdk v1.1] Local tenant lock verified: blocked cross-tenant call from '${client.lockedTenant}'`);

// Notice: tenantId is OMITTED below—inherited directly from acta_tk_v1 / defaultTenantId!
await client.ingestObject({
  objType: "intent",
  scope,
  priority: 100,
  importance: 1.0,
  tags: ["sdk-v1.1"],
  body: { directive: "Halt automated payout when fee_bps is disputed" },
});
await client.ingestClaim({
  scope,
  subject: "merchant:global",
  predicate: "fee_bps",
  objectVal: 290,
  objectType: "int",
  confidence: 0.82,
  sourceProvenanceClass: 2,
  sourceDescriptor: "ledger-v1",
});
await client.ingestClaim({
  scope,
  subject: "merchant:global",
  predicate: "fee_bps",
  objectVal: 240,
  objectType: "int",
  confidence: 0.76,
  sourceProvenanceClass: 2,
  sourceDescriptor: "crm-contract",
});

const guard = new ActaGeminiGuard(client, null, { strictDisputes: true });
let llmInvoked = false;
let disputedHash = "";

try {
  await guard.generateContent({
    actorId: "ts-sdk-auditor",
    scope,
    prompt: "Approve merchant:global payout.",
    llmCallable: () => {
      llmInvoked = true;
      return "bad";
    },
  });
  assert.fail("Expected ActaDisputeEscalationError");
} catch (err) {
  assert.ok(err instanceof ActaDisputeEscalationError);
  assert.equal(llmInvoked, false);
  disputedHash = err.bundleHash;
  console.log(
    `[ts-sdk v1.1] Dispute circuit-breaker TRIPPED before LLM! bundleHash=${disputedHash} (seq=#${err.evidence.seq_num} Ed25519 verified locally)`
  );
}

try {
  await guard.generateContent({
    actorId: "ts-sdk-auditor",
    scope: "restricted/signing-vault",
    prompt: "Read vault keys",
    llmCallable: () => {
      llmInvoked = true;
      return "bad";
    },
  });
  assert.fail("Expected ActaPolicyEscalatedError");
} catch (err) {
  assert.ok(err instanceof ActaPolicyEscalatedError);
  assert.equal(llmInvoked, false);
  console.log(`[ts-sdk v1.1] Policy-Before-Read Escalate TRIPPED with 0 SQL reads! seq=#${err.evidence.seq_num}`);
}

const summary = await client.verifyBundleOffline(disputedHash);
console.log(
  `[ts-sdk v1.1] Offline zero-trust ExportArchive audit PASSED: tenant=${summary.tenant_id}, claims=${summary.verified_claims}`
);
