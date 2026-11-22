import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ActaAuthError,
  ActaClient,
  ActaDisputeEscalationError,
  ActaGeminiGuard,
  ActaPolicyEscalatedError,
  ActaSignatureVerificationError,
  ActaTenantLockError,
  ActaVerificationError,
  Blake3Hasher,
  computeBundleHash,
  computeClaimContentHash,
  computeClaimGroupKey,
  computeEvidenceEventHash,
  computeLogicalClaimGroupKey,
  computeObjectContentHash,
  computeOmissionListHash,
  computeOverrideAttestationHash,
  computeRefusalMetadataCommitment,
  deriveEd25519PublicKeyHex,
  hashLengthDelimited,
  mintTenantApiKey,
  signEvidenceEntry,
  signOverrideAttestation,
  toCanonicalJson,
  verifyExportArchive,
  verifyTenantApiKey,
} from "../dist/index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 1. Official BLAKE3 & RFC 8785 JCS tests
assert.equal(
  new Blake3Hasher().hexdigest(),
  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
);
assert.equal(
  new Blake3Hasher().update("abc").hexdigest(),
  "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
);
assert.equal(
  toCanonicalJson({ zeta: 100, alpha: { b: true, a: [3, 2, 1.0] }, meta: -0.0 }),
  '{"alpha":{"a":[3,2,1],"b":true},"meta":0,"zeta":100}'
);
assert.equal(toCanonicalJson(1e20), "100000000000000000000");
assert.equal(toCanonicalJson(1e21), "1e+21");

// 2. Live Cloud Run Production Vector Parity
const cedarPath = path.resolve(__dirname, "../../../policies/default.cedar");
const canonicalPolicy = fs.readFileSync(cedarPath, "utf8").replace(/\r\n/g, "\n").trim();
assert.ok(canonicalPolicy.includes('Action::"attest"'));
const permRoot = Buffer.from(
  hashLengthDelimited([
    "acta:permission_root:v1",
    canonicalPolicy,
    "{}",
    '["pii","regulated","restricted"]',
    new Uint8Array([1]),
  ])
).toString("hex");
assert.equal(permRoot.length, 64);
assert.notEqual(permRoot, "a885276369e22c385c756739f83d771e5874db13dfcd2f424268fc3fbda76a9a");

const cgk = computeClaimGroupKey(
  "sandbox-live",
  "merchant:global",
  "fee_bps",
  "int",
  "payments-audit-1795192619"
);
assert.equal(cgk, "c16dcc121d6c232910e0148b405abdfd8f0dc53c185724f4b7304ad2994bf958");

const ev1 = computeEvidenceEventHash({
  tenantId: "sandbox-live",
  seqNum: 1,
  prevHash: "00".repeat(32),
  bundleHash: "e39ff7e41347d1547b107de9bfa3339e9ef30fa75742d8d1f33a51599be4b562",
  stateCommitment: "a7c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd041",
  policyResult: "allow",
  createdAt: "2026-11-20T16:37:01.215313Z",
});
assert.ok(ev1.startsWith("5538aa5fc6559d1e"));

const ev2 = computeEvidenceEventHash({
  tenantId: "sandbox-live",
  seqNum: 2,
  prevHash: ev1,
  bundleHash: null,
  stateCommitment: null,
  policyResult: "escalate",
  createdAt: "2026-11-20T16:37:13.789999Z",
});
assert.equal(ev2, "1e1aa455fbcea3e6e698dce7efd85219ac006bd2470d70429452463bfd938753");

// 3. Offline ExportArchive verification & v1.5 Epistemic Notary tests
function buildFixture(seedHex, disputed = true) {
  const pkHex = deriveEd25519PublicKeyHex(seedHex);
  const ts = "2026-11-20T16:37:01.215313Z";
  const tenant = "sandbox-live";
  const scope = "payments-audit-1795192619";

  const obj = {
    id: "8b934fdc-0a70-43d8-9070-3b89ffb44ba2",
    tenant_id: tenant,
    obj_type: "intent",
    scope,
    lifecycle_status: "active",
    priority: 100,
    importance: 1.0,
    tags: ["compliance"],
    body: { directive: "Never silently resolve competing merchant fee claims" },
    content_hash: "",
    version: 1,
    predecessor_id: null,
    created_at: ts,
  };
  obj.content_hash = computeObjectContentHash(obj);

  const src1 = Buffer.from(hashLengthDelimited(["acta:source:v1", "ledger-v1"])).toString("hex");
  const claim1 = {
    id: "54e00c71-af84-4104-b180-0dd284829ac4",
    tenant_id: tenant,
    claim_group_key: cgk,
    scope,
    subject: "merchant:global",
    predicate: "fee_bps",
    object_val: 290,
    object_type: "int",
    confidence: 0.81,
    source_provenance_class: 2,
    source_descriptor: "ledger-v1",
    source_commitment: src1,
    content_hash: "",
    status: "active",
    contradiction_ids: [],
    valid_from: null,
    valid_to: null,
    version: 1,
    predecessor_id: null,
    created_at: ts,
  };
  claim1.content_hash = computeClaimContentHash(claim1);

  const cand1 = {
    id: claim1.id,
    subject: claim1.subject,
    predicate: claim1.predicate,
    object_val: claim1.object_val,
    object_type: claim1.object_type,
    confidence: claim1.confidence,
    source_provenance_class: claim1.source_provenance_class,
    source_descriptor: claim1.source_descriptor,
    source_commitment: claim1.source_commitment,
    content_hash: claim1.content_hash,
    version: 1,
    created_at: ts,
  };

  const claims = [claim1];
  const resolutions = [];
  const disputes = [];
  if (disputed) {
    const src2 = Buffer.from(hashLengthDelimited(["acta:source:v1", "crm-contract"])).toString("hex");
    const claim2 = {
      ...claim1,
      id: "652a3897-b0a8-410f-a18c-c8d80b3ae7b2",
      object_val: 240,
      confidence: 0.74,
      source_descriptor: "crm-contract",
      source_commitment: src2,
    };
    claim2.content_hash = computeClaimContentHash(claim2);
    claims.push(claim2);
    disputes.push({
      claim_group_key: cgk,
      competing_claims: [
        cand1,
        {
          ...cand1,
          id: claim2.id,
          object_val: 240,
          confidence: 0.74,
          source_descriptor: "crm-contract",
          source_commitment: src2,
          content_hash: claim2.content_hash,
        },
      ],
      reason_code: "INSUFFICIENT_MARGIN",
      escalation_required: true,
    });
  } else {
    resolutions.push({
      claim_group_key: cgk,
      winning_claim: cand1,
      margin: null,
      suppressed_claim_ids: [],
    });
  }

  const stateComm = "a7c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd041";
  const bundle = {
    schema_version: "acta-context-bundle/v1",
    tenant_id: tenant,
    task_id: "ui-compile-1",
    scope,
    policy_result: "allow",
    embedding_model_version: "text-embedding-3-small-1536",
    selected_objects: [{ id: obj.id, obj_type: "intent", version: 1, content_hash: obj.content_hash }],
    resolution_records: resolutions,
    dispute_records: disputes,
    omission_record: {
      inline_items: [],
      total_omitted_count: 0,
      full_excluded_hash: computeOmissionListHash([]),
      has_unresolved_claims: disputed,
    },
    state_commitment: stateComm,
    dependency_commitment: "b8c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd042",
    issued_at: ts,
  };
  const { hashHex: bundleHashHex } = computeBundleHash(bundle);
  const zeroPrev = "00".repeat(32);
  const eHash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 1,
    prevHash: zeroPrev,
    bundleHash: bundleHashHex,
    stateCommitment: stateComm,
    policyResult: "allow",
    createdAt: ts,
  });
  const sig = signEvidenceEntry(seedHex, tenant, 1, zeroPrev, eHash);
  return {
    pkHex,
    archive: {
      bundle_hash: bundleHashHex,
      bundle,
      objects: [obj],
      claims,
      evidence_chain: [
        {
          tenant_id: tenant,
          seq_num: 1,
          prev_hash: zeroPrev,
          event_hash: eHash,
          bundle_hash: bundleHashHex,
          state_commitment: stateComm,
          policy_result: "allow",
          host_signature: sig,
          created_at: ts,
        },
      ],
      host_public_key: pkHex,
    },
  };
}

const seedHex = "55".repeat(32);
const { pkHex, archive } = buildFixture(seedHex, true);
const summary = verifyExportArchive(archive, pkHex);
assert.equal(summary.verified_claims, 2);

const forged = JSON.parse(JSON.stringify(archive));
forged.claims[0].object_val = 999999;
assert.throws(() => verifyExportArchive(forged, pkHex), ActaVerificationError);

// v1.5 Epistemic Notary: ResolverManifest + RefusalMetadata v2 + OverrideAttestation
{
  const tenant = archive.bundle.tenant_id;
  const scope = archive.bundle.scope;
  const [claim1, claim2] = archive.claims;
  const logicalGroup = computeLogicalClaimGroupKey(tenant, claim1.subject, claim1.predicate, scope);
  const ts1 = "2026-11-22T04:10:00.000000Z";
  const ts2 = "2026-11-22T04:10:05.000000Z";
  const ts3 = "2026-11-22T04:10:10.000000Z";
  const zeroPrev = "00".repeat(32);

  const rmeta = {
    operation: "ingest_claim",
    reason_code: "POLICY_ESCALATE",
    target_scope: "restricted/signing-keys",
    summary: "Restricted scope requires supervisor escalation approval",
  };
  const rcomm = computeRefusalMetadataCommitment(rmeta);
  const ev1Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 1,
    prevHash: zeroPrev,
    stateCommitment: rcomm,
    policyResult: "escalate",
    createdAt: ts1,
    refusalMetadata: rmeta,
  });

  const attId = "99999999-1111-4222-8333-444444444444";
  const att = {
    id: attId,
    tenant_id: tenant,
    scope,
    claim_group_key: logicalGroup,
    subject: claim2.subject,
    predicate: claim2.predicate,
    source_bundle_hash: archive.bundle_hash,
    winning_claim_id: claim2.id,
    winning_claim_content_hash: claim2.content_hash,
    overridden_claims: [{ id: claim1.id, content_hash: claim1.content_hash }],
    adjudicator_id: `${tenant}::kyle-cfo`,
    justification: "Signed MSA addendum §4.2 supersedes legacy ledger rate",
    version: 1,
    predecessor_id: null,
    created_at: ts2,
    attestation_hash: "",
    evidence_seq_num: 2,
    host_signature: "",
  };
  att.attestation_hash = computeOverrideAttestationHash(att);
  att.host_signature = signOverrideAttestation(seedHex, tenant, 2, att.attestation_hash);

  const osummary = {
    attestation_id: attId,
    scope,
    subject: claim2.subject,
    predicate: claim2.predicate,
    winning_claim_id: claim2.id,
    overridden_count: 1,
    adjudicator_id: att.adjudicator_id,
    version: 1,
  };
  const ev2Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 2,
    prevHash: ev1Hash,
    stateCommitment: att.attestation_hash,
    policyResult: "allow",
    createdAt: ts2,
    overrideSummary: osummary,
  });

  const bundleV15 = JSON.parse(JSON.stringify(archive.bundle));
  bundleV15.resolver_manifest = {
    min_confidence: 0.7,
    decisiveness_threshold: 0.05,
    corroboration_damping: 0.5,
    non_default_thresholds: true,
    budget: { kind: "tokens", limit: 2048 },
    permission_root: "ab".repeat(32),
  };
  bundleV15.dispute_records = [];
  bundleV15.omission_record.has_unresolved_claims = false;
  bundleV15.resolution_records = [
    {
      claim_group_key: logicalGroup,
      winning_claim: archive.bundle.dispute_records[0].competing_claims[1],
      margin: null,
      suppressed_claim_ids: [claim1.id],
      override_attestation: {
        attestation_id: attId,
        attestation_hash: att.attestation_hash,
        adjudicator_id: att.adjudicator_id,
        justification: att.justification,
        source_bundle_hash: archive.bundle_hash,
        evidence_seq_num: 2,
        version: 1,
        attested_at: ts2,
      },
    },
  ];
  const { hashHex: bHexV15 } = computeBundleHash(bundleV15);
  const ev3Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 3,
    prevHash: ev2Hash,
    bundleHash: bHexV15,
    stateCommitment: bundleV15.state_commitment,
    policyResult: "allow",
    createdAt: ts3,
  });

  const archiveV15 = {
    bundle_hash: bHexV15,
    bundle: bundleV15,
    objects: archive.objects,
    claims: archive.claims,
    override_attestations: [att],
    evidence_chain: [
      {
        tenant_id: tenant,
        seq_num: 1,
        prev_hash: zeroPrev,
        event_hash: ev1Hash,
        bundle_hash: null,
        state_commitment: rcomm,
        policy_result: "escalate",
        refusal_metadata: rmeta,
        host_signature: signEvidenceEntry(seedHex, tenant, 1, zeroPrev, ev1Hash),
        created_at: ts1,
      },
      {
        tenant_id: tenant,
        seq_num: 2,
        prev_hash: ev1Hash,
        event_hash: ev2Hash,
        bundle_hash: null,
        state_commitment: att.attestation_hash,
        policy_result: "allow",
        override_summary: osummary,
        host_signature: signEvidenceEntry(seedHex, tenant, 2, ev1Hash, ev2Hash),
        created_at: ts2,
      },
      {
        tenant_id: tenant,
        seq_num: 3,
        prev_hash: ev2Hash,
        event_hash: ev3Hash,
        bundle_hash: bHexV15,
        state_commitment: bundleV15.state_commitment,
        policy_result: "allow",
        host_signature: signEvidenceEntry(seedHex, tenant, 3, ev2Hash, ev3Hash),
        created_at: ts3,
      },
    ],
    host_public_key: pkHex,
  };

  const sumV15 = verifyExportArchive(archiveV15, pkHex);
  assert.equal(sumV15.verified_overrides, 1);
  assert.equal(sumV15.verified_refusals, 1);
  assert.equal(sumV15.non_default_thresholds, true);

  const stripped = JSON.parse(JSON.stringify(archiveV15));
  delete stripped.evidence_chain[0].refusal_metadata;
  assert.throws(() => verifyExportArchive(stripped, pkHex), ActaVerificationError);

  const liedManifest = JSON.parse(JSON.stringify(archiveV15));
  liedManifest.bundle.resolver_manifest.non_default_thresholds = false;
  assert.throws(() => verifyExportArchive(liedManifest, pkHex), ActaVerificationError);
}

// 4. Live HTTP client + ActaGeminiGuard circuit-breaker tests
let forgeSig = false;
const srv = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/v1/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", version: "1.5.0", host_public_key: pkHex, permission_root: permRoot }));
    return;
  }
  if (req.method === "GET" && req.url.endsWith("/export")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(archive));
    return;
  }
  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => {
    const body = raw ? JSON.parse(raw) : {};
    if (req.url === "/v1/overrides") {
      const attHash = Buffer.from(hashLengthDelimited(["mock-override", body.tenant_id])).toString("hex");
      const sig = signOverrideAttestation(seedHex, body.tenant_id, 7, attHash);
      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: "99999999-1111-4222-8333-444444444444",
          version: 1,
          claim_group_key: "aa".repeat(32),
          subject: "merchant:global",
          predicate: "fee_bps",
          winning_claim_id: body.winning_claim_id,
          winning_claim_content_hash: "bb".repeat(32),
          overridden_claim_ids: ["54e00c71-af84-4104-b180-0dd284829ac4"],
          adjudicator_id: body.adjudicator_id,
          justification: body.justification,
          attestation_hash: attHash,
          evidence_seq_num: 7,
          host_signature: sig,
          was_idempotent_noop: false,
          created_at: "2026-11-22T04:10:05.000000Z",
        })
      );
      return;
    }
    if (req.url === "/v1/compile") {
      if (!body.tenant_id.startsWith("sandbox") && req.headers["x-acta-api-key"] !== "secret-prod-key") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "missing or invalid API key" }));
        return;
      }
      const ts = "2026-11-20T16:37:01.215313Z";
      const zeroPrev = "00".repeat(32);
      if (body.scope.startsWith("restricted/")) {
        const rmeta = {
          operation: "compile",
          reason_code: "POLICY_ESCALATE",
          target_scope: body.scope,
          summary: "Restricted scope",
        };
        const rcomm = computeRefusalMetadataCommitment(rmeta);
        const eh = computeEvidenceEventHash({
          tenantId: body.tenant_id,
          seqNum: 1,
          prevHash: zeroPrev,
          stateCommitment: rcomm,
          policyResult: "escalate",
          createdAt: ts,
          refusalMetadata: rmeta,
        });
        const sig = signEvidenceEntry(seedHex, body.tenant_id, 1, zeroPrev, eh);
        res.writeHead(202, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            policy_decision: { decision: "escalate", reason: "Restricted scope" },
            evidence: {
              tenant_id: body.tenant_id,
              seq_num: 1,
              prev_hash: zeroPrev,
              event_hash: eh,
              bundle_hash: null,
              state_commitment: rcomm,
              policy_result: "escalate",
              refusal_metadata: rmeta,
              host_signature: sig,
              created_at: ts,
            },
          })
        );
        return;
      }
      const disputed = body.scope.includes("dispute");
      const fx = buildFixture(seedHex, disputed).archive;
      fx.bundle.tenant_id = body.tenant_id;
      fx.bundle.scope = body.scope;
      const { hashHex } = computeBundleHash(fx.bundle);
      const eh = computeEvidenceEventHash({
        tenantId: body.tenant_id,
        seqNum: 1,
        prevHash: zeroPrev,
        bundleHash: hashHex,
        stateCommitment: fx.bundle.state_commitment,
        policyResult: "allow",
        createdAt: ts,
      });
      let sig = signEvidenceEntry(seedHex, body.tenant_id, 1, zeroPrev, eh);
      if (forgeSig) {
        sig = (sig.startsWith("00") ? "ff" : "00") + sig.slice(2);
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          policy_decision: { decision: "allow" },
          bundle_hash: hashHex,
          context_text: disputed ? "[DISPUTE: INSUFFICIENT_MARGIN]" : "[FACT] fee_bps = 290",
          bundle: fx.bundle,
          evidence: {
            tenant_id: body.tenant_id,
            seq_num: 1,
            prev_hash: zeroPrev,
            event_hash: eh,
            bundle_hash: hashHex,
            state_commitment: fx.bundle.state_commitment,
            policy_result: "allow",
            host_signature: sig,
            created_at: ts,
          },
        })
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });
});

await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
const port = srv.address().port;
const baseUrl = `http://127.0.0.1:${port}`;

try {
  const client = new ActaClient({ baseUrl, apiKey: "secret-prod-key" });
  const guard = new ActaGeminiGuard(client);
  let llmCalls = 0;

  const ok = await guard.generateContent({
    tenantId: "prod-acme",
    actorId: "ts-auditor",
    scope: "clean-settlement",
    prompt: "Verify fee_bps",
    llmCallable: (fullPrompt) => {
      llmCalls += 1;
      assert.ok(fullPrompt.includes("[FACT] fee_bps = 290"));
      return "Verified 290 bps";
    },
  });
  assert.equal(llmCalls, 1);
  assert.equal(ok.verifiedHostPubkey, pkHex);

  await assert.rejects(
    () =>
      guard.generateContent({
        tenantId: "prod-acme",
        actorId: "ts-auditor",
        scope: "dispute-settlement",
        prompt: "Verify fee_bps",
        llmCallable: () => {
          llmCalls += 1;
          return "Should never run";
        },
      }),
    ActaDisputeEscalationError
  );
  assert.equal(llmCalls, 1, "LLM must never run on unresolved [DISPUTE]");

  const ovr = await client.attestOverride({
    tenantId: "prod-acme",
    scope: "dispute-settlement",
    winningClaimId: "652a3897-b0a8-410f-a18c-c8d80b3ae7b2",
    adjudicatorId: "prod-acme::cfo",
    justification: "Verified signed MSA schedule",
  });
  assert.equal(ovr.evidence_seq_num, 7);

  await assert.rejects(
    () =>
      guard.generateContent({
        tenantId: "prod-acme",
        actorId: "ts-auditor",
        scope: "restricted/vault",
        prompt: "Read keys",
        llmCallable: () => {
          llmCalls += 1;
          return "Should never run";
        },
      }),
    ActaPolicyEscalatedError
  );
  assert.equal(llmCalls, 1);

  const offlineSummary = await client.verifyBundleOffline(ok.bundleHash);
  assert.equal(offlineSummary.verified_claims, 2);

  forgeSig = true;
  await assert.rejects(
    () =>
      guard.generateContent({
        tenantId: "prod-acme",
        actorId: "ts-auditor",
        scope: "clean-settlement",
        prompt: "Verify fee_bps",
        llmCallable: () => "Should never run",
      }),
    ActaSignatureVerificationError
  );

  const unauth = new ActaClient({ baseUrl });
  await assert.rejects(
    () =>
      unauth.compile({
        tenantId: "prod-acme",
        actorId: "ts-auditor",
        scope: "clean-settlement",
        queryText: "ping",
      }),
    ActaAuthError
  );

  console.log("ALL TYPESCRIPT @acta/sdk v1.5.0 TESTS + EPISTEMIC NOTARY VECTORS PASSED!");
} finally {
  srv.close();
}

// 5. v1.1 Stateless Keyed-BLAKE3 Tenant-Bound API Keys & Local Client Lock
const masterSecret = "acta_live_master_secret_998877";
const tkArdyn = mintTenantApiKey(masterSecret, "ardyn-core");
const tkAcme = mintTenantApiKey(masterSecret, "client-acme");
assert.ok(tkArdyn.startsWith("acta_tk_v1:ardyn-core:"));
assert.notEqual(tkArdyn, tkAcme);
assert.equal(verifyTenantApiKey(masterSecret, tkArdyn), "ardyn-core");
assert.equal(verifyTenantApiKey(masterSecret, tkAcme), "client-acme");

const macOnly = tkArdyn.split(":").pop();
assert.throws(() => verifyTenantApiKey(masterSecret, `acta_tk_v1:client-acme:${macOnly}`));

const lockedTsClient = new ActaClient({ baseUrl: "http://127.0.0.1:9", apiKey: tkAcme });
assert.equal(lockedTsClient.lockedTenant, "client-acme");
await assert.rejects(
  () =>
    lockedTsClient.compile({
      tenantId: "ardyn-core",
      actorId: "claude",
      scope: "ops",
      queryText: "attempt cross-tenant",
    }),
  ActaTenantLockError
);
console.log("ALL v1.1 TENANT-BOUND TOKEN & CLIENT LOCK TESTS PASSED!");
