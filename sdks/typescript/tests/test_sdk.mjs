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
  computeCheckpointHash,
  computeClaimContentHash,
  computeClaimGroupKey,
  computeEvidenceEventHash,
  computeLogicalClaimGroupKey,
  computeMerkleConsistencyProof,
  computeMerkleInclusionProof,
  computeMerkleRootFromLeaves,
  computeObjectContentHash,
  computeOmissionListHash,
  computeOverrideAttestationHash,
  computeRefusalMetadataCommitment,
  computeWitnessRevocationV2Commitment,
  witnessRevocationPreimageBytes,
  deriveEd25519PublicKeyHex,
  dumpArchivePreimages,
  extractTokenPrincipal,
  extractTokenTenant,
  hashLengthDelimited,
  merkleLeafHash,
  mintTenantApiKey,
  mintUserTenantApiKey,
  signCheckpointHead,
  signEvidenceEntry,
  signOverrideAttestation,
  signOverrideClientIntent,
  signWitnessAnchor,
  toCanonicalJson,
  verifyExportArchive,
  verifyMerkleConsistencyProof,
  verifyMerkleInclusionProof,
  verifyTenantApiKey,
  verifyTenantApiKeyWithPrincipal,
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

// 3. RFC 6962 Merkle Inclusion & Consistency Proofs across tree sizes 1..25
{
  const events = [];
  const leaves = [];
  for (let i = 1; i <= 25; i++) {
    const ev = Buffer.from(hashLengthDelimited(["ev", `seq-${i}`])).toString("hex");
    events.push(ev);
    leaves.push(merkleLeafHash(i, ev));
  }
  for (let size = 1; size <= 25; size++) {
    const root = computeMerkleRootFromLeaves(leaves.slice(0, size));
    for (let idx = 0; idx < size; idx++) {
      const pathNodes = computeMerkleInclusionProof(leaves.slice(0, size), idx);
      assert.ok(verifyMerkleInclusionProof(idx + 1, events[idx], size, pathNodes, root));
    }
    for (let first = 1; first <= size; first++) {
      const firstRoot = computeMerkleRootFromLeaves(leaves.slice(0, first));
      const cproof = computeMerkleConsistencyProof(leaves, first, size);
      assert.ok(verifyMerkleConsistencyProof(first, firstRoot, size, root, cproof));
      if (first < size) {
        const badFirst = (firstRoot.startsWith("00") ? "ff" : "00") + firstRoot.slice(2);
        assert.ok(!verifyMerkleConsistencyProof(first, badFirst, size, root, cproof));
      }
    }
  }
}

// 4. Offline ExportArchive verification & v1.6.5 Epistemic Notary + Merkle-only proof tests
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
assert.equal(summary.verification_mode, "full_chain");

const forged = JSON.parse(JSON.stringify(archive));
forged.claims[0].object_val = 999999;
assert.throws(() => verifyExportArchive(forged, pkHex), ActaVerificationError);

// v1.6.5 Merkle-only ExportArchive with client-signed LapsedOverrideRef & ExternalWitnessAnchor
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
    operation: "attest_override",
    reason_code: "adjudicator_signature_required",
    target_scope: scope,
    summary: "Custom adjudicator requires offline Ed25519 signature",
  };
  const rcomm = computeRefusalMetadataCommitment(rmeta);
  const ev1Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 1,
    prevHash: zeroPrev,
    stateCommitment: rcomm,
    policyResult: "block",
    createdAt: ts1,
    refusalMetadata: rmeta,
  });

  const committeeSeed = "99".repeat(32);
  const justification = "Signed MSA addendum §4.2 supersedes legacy ledger rate";
  const { clientSignatureHex, clientPublicKeyHex } = signOverrideClientIntent(committeeSeed, {
    tenantId: tenant,
    scope,
    winningClaimId: claim2.id,
    adjudicatorId: "cfo-committee",
    justification,
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
    adjudicator_id: `${tenant}::cfo-committee`,
    justification,
    version: 1,
    predecessor_id: null,
    created_at: ts2,
    attestation_hash: "",
    evidence_seq_num: 2,
    host_signature: "",
    client_signature: clientSignatureHex,
    client_public_key: clientPublicKeyHex,
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
  const ev2Entry = {
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
  };

  const claim3 = {
    ...claim1,
    id: "20b6b7a6-8c52-4590-9987-a6487f7cf185",
    object_val: 310,
    confidence: 0.79,
    source_descriptor: "erp-v3",
  };
  claim3.content_hash = computeClaimContentHash(claim3);

  const bundleV16 = JSON.parse(JSON.stringify(archive.bundle));
  bundleV16.dispute_records[0].claim_group_key = logicalGroup;
  bundleV16.dispute_records[0].competing_claims.push({
    ...archive.bundle.dispute_records[0].competing_claims[0],
    id: claim3.id,
    object_val: 310,
    confidence: 0.79,
    source_descriptor: "erp-v3",
    content_hash: claim3.content_hash,
  });
  bundleV16.dispute_records[0].lapsed_override = {
    attestation_id: attId,
    attestation_hash: att.attestation_hash,
    prior_winning_claim_id: claim2.id,
    adjudicator_id: att.adjudicator_id,
    justification,
    evidence_seq_num: 2,
    version: 1,
    attested_at: ts2,
    reopened_by_claim_ids: [claim3.id],
  };

  const { hashHex: bHexV16 } = computeBundleHash(bundleV16);
  const ev3Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 3,
    prevHash: ev2Hash,
    bundleHash: bHexV16,
    stateCommitment: bundleV16.state_commitment,
    policyResult: "allow",
    createdAt: ts3,
  });
  const ev3Entry = {
    tenant_id: tenant,
    seq_num: 3,
    prev_hash: ev2Hash,
    event_hash: ev3Hash,
    bundle_hash: bHexV16,
    state_commitment: bundleV16.state_commitment,
    policy_result: "allow",
    host_signature: signEvidenceEntry(seedHex, tenant, 3, ev2Hash, ev3Hash),
    created_at: ts3,
  };

  const chainLeaves = [
    merkleLeafHash(1, ev1Hash),
    merkleLeafHash(2, ev2Hash),
    merkleLeafHash(3, ev3Hash),
  ];
  const merkleRoot = computeMerkleRootFromLeaves(chainLeaves);
  const cpHash = computeCheckpointHash({
    tenantId: tenant,
    treeSize: 3,
    headEventHash: ev3Hash,
    merkleRoot,
    issuedAt: ts3,
  });
  const cpSig = signCheckpointHead(seedHex, tenant, cpHash);
  const { witnessSignatureHex, witnessPublicKeyHex } = signWitnessAnchor("77".repeat(32), tenant, 3, cpHash);

  const merkleOnlyArchive = {
    bundle_hash: bHexV16,
    bundle: bundleV16,
    objects: archive.objects,
    claims: [claim1, claim2, claim3],
    override_attestations: [att],
    evidence_chain: [],
    merkle_proof: {
      checkpoint: {
        tenant_id: tenant,
        tree_size: 3,
        head_event_hash: ev3Hash,
        merkle_root: merkleRoot,
        issued_at: ts3,
        checkpoint_hash: cpHash,
        host_signature: cpSig,
        witness_anchors: [
          {
            id: "11111111-2222-4333-8444-555555555555",
            tenant_id: tenant,
            tree_size: 3,
            checkpoint_hash: cpHash,
            witness_id: "rekor-transparency-mirror",
            witness_public_key: witnessPublicKeyHex,
            witness_signature: witnessSignatureHex,
            anchored_at: ts3,
          },
        ],
      },
      bundle_entry_proof: {
        entry: ev3Entry,
        audit_path: computeMerkleInclusionProof(chainLeaves, 2),
      },
      override_entry_proofs: [
        {
          entry: ev2Entry,
          audit_path: computeMerkleInclusionProof(chainLeaves, 1),
        },
      ],
    },
    host_public_key: pkHex,
  };

  const sumV16 = verifyExportArchive(merkleOnlyArchive, pkHex);
  assert.equal(sumV16.verification_mode, "merkle_inclusion");
  assert.equal(sumV16.verified_overrides, 1);
  assert.equal(sumV16.verified_evidence_entries, 2);
  assert.equal(sumV16.merkle_tree_size, 3);
  assert.equal(sumV16.verified_witness_anchors, 1);

  const preimages = dumpArchivePreimages(merkleOnlyArchive);
  assert.equal(preimages.checkpoint.tree_size, 3);
  assert.equal(preimages.override_attestations.length, 1);

  const badClientSig = JSON.parse(JSON.stringify(merkleOnlyArchive));
  badClientSig.override_attestations[0].client_signature = "00".repeat(64);
  assert.throws(() => verifyExportArchive(badClientSig, pkHex), ActaVerificationError);

  const badLapsed = JSON.parse(JSON.stringify(merkleOnlyArchive));
  badLapsed.bundle.dispute_records[0].lapsed_override.evidence_seq_num = 99;
  assert.throws(() => verifyExportArchive(badLapsed, pkHex), ActaVerificationError);
}

// 5. Live HTTP client + ActaGeminiGuard circuit-breaker tests
let forgeSig = false;
const srv = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/v1/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", version: "1.7.3", host_public_key: pkHex, permission_root: permRoot }));
    return;
  }
  if (req.method === "GET" && req.url.includes("/export")) {
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
          adjudicator_id: body.adjudicator_id || `${body.tenant_id}::session`,
          adjudicator_auth_kind: "master_api_key",
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
  assert.equal(llmCalls, 1);

  const ovr = await client.attestOverride({
    tenantId: "prod-acme",
    scope: "dispute-settlement",
    winningClaimId: "652a3897-b0a8-410f-a18c-c8d80b3ae7b2",
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
        llmCallable: () => "Should never run",
      }),
    ActaPolicyEscalatedError
  );

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

  console.log("ALL TYPESCRIPT @acta/sdk v1.7.2 TESTS + MERKLE & EPISTEMIC NOTARY VECTORS PASSED!");
} finally {
  srv.close();
}

// 6. v1.1 2-Segment & v1.6 3-Segment Principal Tokens & Local Client Lock
const masterSecret = "acta_live_master_secret_998877";
const tkArdyn = mintTenantApiKey(masterSecret, "ardyn-core");
const tkAcme = mintTenantApiKey(masterSecret, "client-acme");
assert.ok(tkArdyn.startsWith("acta_tk_v1:ardyn-core:"));
assert.equal(verifyTenantApiKey(masterSecret, tkArdyn), "ardyn-core");
assert.equal(extractTokenPrincipal(tkArdyn), null);

const tkUser = mintUserTenantApiKey(masterSecret, "ardyn-core", "KyleWilson04");
assert.ok(tkUser.startsWith("acta_tk_v1:ardyn-core:kylewilson04:"));
assert.equal(extractTokenTenant(tkUser), "ardyn-core");
assert.equal(extractTokenPrincipal(tkUser), "kylewilson04");
assert.deepEqual(verifyTenantApiKeyWithPrincipal(masterSecret, tkUser), {
  tenantId: "ardyn-core",
  principal: "kylewilson04",
});

const userMac = tkUser.split(":").pop();
assert.throws(() =>
  verifyTenantApiKeyWithPrincipal(masterSecret, `acta_tk_v1:ardyn-core:cfo-committee:${userMac}`)
);

const lockedTsClient = new ActaClient({ baseUrl: "http://127.0.0.1:9", apiKey: tkUser });
assert.equal(lockedTsClient.lockedTenant, "ardyn-core");
assert.equal(lockedTsClient.verifiedPrincipal, "kylewilson04");
await assert.rejects(
  () =>
    lockedTsClient.compile({
      tenantId: "client-acme",
      actorId: "claude",
      scope: "ops",
      queryText: "attempt cross-tenant",
    }),
  ActaTenantLockError
);
console.log("ALL v1.6.5 2-PART & 3-PART PRINCIPAL TOKEN & CLIENT LOCK TESTS PASSED!");

// v1.6.5 live seq 58 witness_reg:v1 & principal-bound witness_reg:v2 vectors
import {
  witnessRegistrationPreimageBytes,
  computeWitnessRegistrationCommitment,
  computeWitnessRegistrationV2Commitment,
} from "../dist/index.mjs";

const pk58 = "e5b050185444bd8e1b0892678934c70ff65f896602e9bf0faa87a4702a7ad9e4";
assert.equal(
  computeWitnessRegistrationCommitment("kylewilson04", "claude-witness-v161", pk58),
  "e28df78841329df7b66aef44558586b81d952d1434a48f6605d0a6431e080fec"
);
const v2Oauth = computeWitnessRegistrationV2Commitment(
  "kylewilson04",
  "claude-witness-v162",
  pk58,
  "kylewilson04::oauth:kylewilson04"
);
const v2Session = computeWitnessRegistrationV2Commitment(
  "kylewilson04",
  "claude-witness-v162",
  pk58,
  "kylewilson04::session"
);
assert.notEqual(v2Oauth.commitmentHex, v2Session.commitmentHex);
assert.equal(
  Buffer.from(
    witnessRegistrationPreimageBytes(
      "acta:witness_reg:v2",
      "kylewilson04",
      "claude-witness-v162",
      pk58,
      "kylewilson04::oauth:kylewilson04"
    )
  ).toString("hex"),
  v2Oauth.preimageHex
);
import {
  computeWitnessRegistrationV3Commitment,
  computeWitnessRevocationCommitment,
} from "../dist/index.mjs";

const wv3a = computeWitnessRegistrationV3Commitment(
  "kylewilson04",
  "claude-witness-v163",
  pk58,
  "kylewilson04::oauth:kylewilson04",
  "Claude v1.6.5 Witness"
);
const wv3b = computeWitnessRegistrationV3Commitment(
  "kylewilson04",
  "claude-witness-v163",
  pk58,
  "kylewilson04::oauth:kylewilson04",
  "Tampered"
);
assert.notStrictEqual(wv3a.commitmentHex, wv3b.commitmentHex);
const wrev = computeWitnessRevocationCommitment(
  "kylewilson04",
  "claude-revoke-probe-v163",
  pk58,
  "kylewilson04::session",
  "Key rotation"
);
assert.strictEqual(wrev.commitmentHex.length, 64);
console.log("ALL v1.6.5 WITNESS_REG V1/V2/V3 & REVOCATION VECTORS PASSED!");


// Acta v1.6.5 witness_revoke:v2 retire vs compromise domain separation
{
  const pk = "aa".repeat(32);
  const ret = computeWitnessRevocationV2Commitment(
    "kylewilson04",
    "claude-retire-probe-v164",
    pk,
    "kylewilson04::oauth:kylewilson04",
    "retire",
    86,
    "Graceful key rotation after anchoring head 85"
  );
  const comp = computeWitnessRevocationV2Commitment(
    "kylewilson04",
    "claude-retire-probe-v164",
    pk,
    "kylewilson04::oauth:kylewilson04",
    "compromise",
    null,
    "Graceful key rotation after anchoring head 85"
  );
  assert.notEqual(ret.commitmentHex, comp.commitmentHex);
  assert.notEqual(ret.preimageHex, comp.preimageHex);
  assert.throws(() =>
    witnessRevocationPreimageBytes(
      "acta:witness_revoke:v2",
      "kylewilson04",
      "claude-retire-probe-v164",
      pk,
      "kylewilson04::oauth:kylewilson04",
      "Bad combination",
      "retire",
      null
    )
  );
}


// 7. v1.7.2 Claim 25 Dependency Commitment, Cache Invalidation & Offline State Rebuild
{
  const {
    SCHEMA_VERSION,
    SCHEMA_VERSION_V1,
    STATE_REBUILD_ARCHIVE_SCHEMA_V1,
    computeSubCommitment,
    computeStateCommitment,
    computeTaskDependencyCommitment,
    computeObjectContentHash,
    computeClaimContentHash,
    computeLogicalClaimGroupKey,
    computeWriteSummaryCommitment,
    computeAnswerCacheSummaryCommitment,
    computeQueryTextHash,
    computeAnswerTextHash,
    verifyAndRebuildScopeStateOffline,
  } = await import("../dist/index.mjs");

  const tenant = "kylewilson04";
  const scope = "acta-test/v171-ts";
  const ts = "2026-11-24T17:10:00.000000Z";
  const dep1 = computeTaskDependencyCommitment({
    tenantId: tenant,
    scope,
    permissionRoot: permRoot,
    intentRoot: computeSubCommitment([]),
    selectedMemoryRoot: computeSubCommitment([]),
    relevantKnowledgeRoot: computeSubCommitment(["aa".repeat(32)]),
  });
  const dep2 = computeTaskDependencyCommitment({
    tenantId: tenant,
    scope,
    permissionRoot: permRoot,
    intentRoot: computeSubCommitment([]),
    selectedMemoryRoot: computeSubCommitment([]),
    relevantKnowledgeRoot: computeSubCommitment(["bb".repeat(32)]),
  });
  assert.equal(dep1.length, 64);
  assert.notEqual(dep1, dep2);

  const obj = {
    id: "11111111-1111-4111-8111-111111111111",
    tenant_id: tenant,
    obj_type: "intent",
    scope,
    lifecycle_status: "active",
    priority: 90,
    importance: 1.0,
    tags: ["v171"],
    body: { directive: "Pool corroborating sources" },
    version: 1,
    predecessor_id: null,
    created_at: ts,
  };
  obj.content_hash = computeObjectContentHash(obj);
  const ws1 = {
    write_domain: "acta:write_event:v1",
    operation: "ingest_object",
    item_id: obj.id,
    scope,
    version: 1,
    content_hash: obj.content_hash,
    written_by: `${tenant}::oauth:${tenant}`,
    writer_auth_kind: "oauth_github_principal",
    record_snapshot: obj,
  };
  const ws1Comm = computeWriteSummaryCommitment(ws1);
  const ev1Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 1,
    prevHash: "00".repeat(32),
    stateCommitment: ws1Comm,
    policyResult: "allow",
    createdAt: ts,
    writeSummary: ws1,
  });
  const entry1 = {
    tenant_id: tenant,
    seq_num: 1,
    event_domain: "acta:evidence_event:v3",
    prev_hash: "00".repeat(32),
    event_hash: ev1Hash,
    bundle_hash: null,
    state_commitment: ws1Comm,
    policy_result: "allow",
    write_summary: ws1,
    host_signature: signEvidenceEntry(seedHex, tenant, 1, "00".repeat(32), ev1Hash),
    created_at: ts,
  };

  const clm = {
    id: "22222222-2222-4222-8222-222222222222",
    tenant_id: tenant,
    claim_group_key: computeLogicalClaimGroupKey(tenant, "supplier:titan", "lead_days", scope),
    scope,
    subject: "supplier:titan",
    predicate: "lead_days",
    object_val: 14,
    object_type: "int",
    confidence: 0.6,
    source_provenance_class: 2,
    source_descriptor: "msa-a",
    source_commitment: "cc".repeat(32),
    status: "active",
    contradiction_ids: [],
    valid_from: null,
    valid_to: null,
    version: 1,
    predecessor_id: null,
    created_at: ts,
  };
  clm.content_hash = computeClaimContentHash(clm);
  const ws2 = {
    write_domain: "acta:write_event:v1",
    operation: "ingest_claim",
    item_id: clm.id,
    scope,
    version: 1,
    content_hash: clm.content_hash,
    written_by: `${tenant}::oauth:${tenant}`,
    writer_auth_kind: "oauth_github_principal",
    record_snapshot: clm,
  };
  const ws2Comm = computeWriteSummaryCommitment(ws2);
  const ev2Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 2,
    prevHash: ev1Hash,
    stateCommitment: ws2Comm,
    policyResult: "allow",
    createdAt: ts,
    writeSummary: ws2,
  });
  const entry2 = {
    tenant_id: tenant,
    seq_num: 2,
    event_domain: "acta:evidence_event:v3",
    prev_hash: ev1Hash,
    event_hash: ev2Hash,
    bundle_hash: null,
    state_commitment: ws2Comm,
    policy_result: "allow",
    write_summary: ws2,
    host_signature: signEvidenceEntry(seedHex, tenant, 2, ev1Hash, ev2Hash),
    created_at: ts,
  };

  const acsInv = {
    cache_domain: "acta:answer_cache:v1",
    event_kind: "invalidated",
    cache_id: "33333333-3333-4333-8333-333333333333",
    scope,
    task_id: "po-check",
    query_hash: computeQueryTextHash("lead_days?"),
    source_bundle_hash: "dd".repeat(32),
    state_commitment: "ee".repeat(32),
    validity_mode: "dependency_subset",
    task_dependency_commitment: dep1,
    answer_hash: computeAnswerTextHash("14 days"),
    cached_by: `${tenant}::oauth:${tenant}`,
    cacher_auth_kind: "oauth_github_principal",
    invalidation_reason: "stale_dependency_commitment",
    observed_state_commitment: "ff".repeat(32),
    observed_dependency_commitment: dep2,
  };
  const acsComm = computeAnswerCacheSummaryCommitment(acsInv);
  const ev3Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 3,
    prevHash: ev2Hash,
    stateCommitment: acsComm,
    policyResult: "allow",
    createdAt: ts,
    answerCacheSummary: acsInv,
  });
  const entry3 = {
    tenant_id: tenant,
    seq_num: 3,
    event_domain: "acta:evidence_event:v3",
    prev_hash: ev2Hash,
    event_hash: ev3Hash,
    bundle_hash: null,
    state_commitment: acsComm,
    policy_result: "allow",
    answer_cache_summary: acsInv,
    host_signature: signEvidenceEntry(seedHex, tenant, 3, ev2Hash, ev3Hash),
    created_at: ts,
  };

  const {
    computeRebuildArchiveHeaderHash,
    signRebuildArchiveHeader,
    recomputeWinningBucketCorroboration,
  } = await import("../dist/index.mjs");
  assert.equal(
    computeSubCommitment([]),
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  );
  const hdrHash = computeRebuildArchiveHeaderHash({
    schemaVersion: STATE_REBUILD_ARCHIVE_SCHEMA_V1,
    tenantId: tenant,
    scope,
    upToSeq: 3,
    evaluatedAt: ts,
    permissionRoot: permRoot,
  });
  const hdrSig = signRebuildArchiveHeader(seedHex, tenant, hdrHash);
  const rebuildArchive = {
    schema_version: STATE_REBUILD_ARCHIVE_SCHEMA_V1,
    tenant_id: tenant,
    scope,
    up_to_seq: 3,
    evaluated_at: ts,
    host_public_key: pkHex,
    permission_root: permRoot,
    header_hash: hdrHash,
    host_header_signature: hdrSig,
    override_attestations: [],
    evidence_chain: [entry1, entry2, entry3],
  };
  const rebuilt = verifyAndRebuildScopeStateOffline(rebuildArchive, pkHex);
  const expectedSc = computeStateCommitment({
    schemaVersion: SCHEMA_VERSION_V1,
    SCHEMA_VERSION_V1,
    tenantId: tenant,
    scope,
    intentRoot: computeSubCommitment([obj.content_hash]),
    knowledgeRoot: computeSubCommitment([clm.content_hash]),
    memoryRoot: computeSubCommitment([]),
    permissionRoot: permRoot,
  });
  assert.equal(rebuilt.reconstructed_state_commitment_hex, expectedSc);
  assert.equal(rebuilt.reconstructed_active_intents, 1);
  assert.equal(rebuilt.reconstructed_active_claims, 1);

  const tampered = JSON.parse(JSON.stringify(rebuildArchive));
  tampered.evidence_chain[1].write_summary.record_snapshot.object_val = 999;
  assert.throws(() => verifyAndRebuildScopeStateOffline(tampered, pkHex), ActaVerificationError);

  const swappedClock = JSON.parse(JSON.stringify(rebuildArchive));
  swappedClock.evaluated_at = "2027-06-01T00:00:00.000000Z";
  assert.throws(() => verifyAndRebuildScopeStateOffline(swappedClock, pkHex), ActaVerificationError);

  const clmB = { ...clm, id: "c87ad711-2222-4222-8222-222222222222", source_descriptor: "bol-b" };
  clmB.content_hash = computeClaimContentHash(clmB);
  const corrob = recomputeWinningBucketCorroboration([clm, clmB], 0.5);
  assert.equal(corrob.corroboratingCount, 2);
  assert.ok(Math.abs(corrob.effectiveConfidence - 0.72) < 1e-9);
  console.log("TYPESCRIPT @acta/sdk v1.7.2 OFFLINE STATE REBUILD & CLAIM 25 VECTORS PASSED!");
}


// v1.7.3 domain-tagged state:v2, sub_commitment:v2, host-key rotation, erasure & dependency_ids parity
{
  const {
    SCHEMA_VERSION_V2,
    STATE_REBUILD_ARCHIVE_SCHEMA_V2,
    computeSubCommitmentV2,
    computeStateCommitment,
    computeErasableClaimCommitment,
    computeHostKeyRotationCommitment,
    signHostKeyRotationOld,
    signHostKeyRotationNew,
    computeRebuildArchiveHeaderHash,
    signRebuildArchiveHeader,
    verifyAndRebuildScopeStateOffline,
    verifyEvidenceEntry,
  } = await import("../dist/index.mjs");

  const k0Seed = "21".repeat(32);
  const k1Seed = "22".repeat(32);
  const k0Pk = deriveEd25519PublicKeyHex(k0Seed);
  const k1Pk = deriveEd25519PublicKeyHex(k1Seed);
  const tenant = "tenant-v173-ts";
  const scope = "acta-test/v173-ts";
  const ts = "2026-11-24T22:00:00.000000Z";

  const claimId = "11111111-2222-4333-8444-555555555555";
  const srcComm = Buffer.from(hashLengthDelimited(["acta:source:v1", "pii-vault"])).toString("hex");
  const erasureComm = computeErasableClaimCommitment({
    claimId,
    salt32: "aa".repeat(32),
    objectVal: { ssn_last4: "9876" },
    sourceCommitment: srcComm,
  });
  const clm = {
    id: claimId,
    tenant_id: tenant,
    claim_group_key: computeLogicalClaimGroupKey(tenant, "cust:1", "pii", scope),
    scope,
    subject: "cust:1",
    predicate: "pii",
    object_val: { $acta_erasable_commitment: erasureComm },
    object_type: "object",
    confidence: 0.95,
    source_provenance_class: 2,
    source_descriptor: "pii-vault",
    source_commitment: srcComm,
    status: "active",
    contradiction_ids: [],
    valid_from: null,
    valid_to: null,
    version: 1,
    predecessor_id: null,
    created_at: ts,
  };
  clm.content_hash = computeClaimContentHash(clm);
  const ws1 = {
    write_domain: "acta:write_event:v1",
    operation: "legacy_import_claim",
    item_id: claimId,
    scope,
    version: 1,
    content_hash: clm.content_hash,
    written_by: `${tenant}::admin`,
    writer_auth_kind: "tenant_session",
    record_snapshot: clm,
  };
  const ws1Comm = Buffer.from(
    hashLengthDelimited(["acta:write_event:v1", Buffer.from(toCanonicalJson(ws1), "utf8")])
  ).toString("hex");
  const ev1Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 1,
    prevHash: "00".repeat(32),
    stateCommitment: ws1Comm,
    policyResult: "allow",
    createdAt: ts,
    writeSummary: ws1,
  });
  const ev1 = {
    tenant_id: tenant,
    seq_num: 1,
    event_domain: "acta:evidence_event:v3",
    prev_hash: "00".repeat(32),
    event_hash: ev1Hash,
    bundle_hash: null,
    state_commitment: ws1Comm,
    policy_result: "allow",
    write_summary: ws1,
    host_signature: signEvidenceEntry(k0Seed, tenant, 1, "00".repeat(32), ev1Hash),
    created_at: ts,
  };
  verifyEvidenceEntry(ev1, k0Pk);

  const rot2 = {
    rotation_domain: "acta:host_key_rotate:v1",
    old_public_key: k0Pk,
    new_public_key: k1Pk,
    effective_from_seq: 2,
    rotation_mode: "scheduled",
    reason: "Scheduled rotation",
    rotated_by: `${tenant}::master-admin`,
    old_key_signature: signHostKeyRotationOld(k0Seed, {
      tenantId: tenant,
      effectiveFromSeq: 2,
      oldPublicKey: k0Pk,
      newPublicKey: k1Pk,
      rotationMode: "scheduled",
      reason: "Scheduled rotation",
    }),
    new_key_signature: signHostKeyRotationNew(k1Seed, {
      tenantId: tenant,
      effectiveFromSeq: 2,
      oldPublicKey: k0Pk,
      newPublicKey: k1Pk,
      rotationMode: "scheduled",
      reason: "Scheduled rotation",
    }),
  };
  const rot2Comm = computeHostKeyRotationCommitment(rot2);
  const ev2Hash = computeEvidenceEventHash({
    tenantId: tenant,
    seqNum: 2,
    prevHash: ev1Hash,
    stateCommitment: rot2Comm,
    policyResult: "allow",
    createdAt: ts,
    hostKeyRotationSummary: rot2,
  });
  const ev2 = {
    tenant_id: tenant,
    seq_num: 2,
    event_domain: "acta:evidence_event:v3",
    prev_hash: ev1Hash,
    event_hash: ev2Hash,
    bundle_hash: null,
    state_commitment: rot2Comm,
    policy_result: "allow",
    host_key_rotation_summary: rot2,
    host_signature: signEvidenceEntry(k0Seed, tenant, 2, ev1Hash, ev2Hash),
    created_at: ts,
  };
  verifyEvidenceEntry(ev2, k0Pk);

  const hdr2 = computeRebuildArchiveHeaderHash({
    schemaVersion: STATE_REBUILD_ARCHIVE_SCHEMA_V2,
    tenantId: tenant,
    scope,
    upToSeq: 2,
    evaluatedAt: ts,
    permissionRoot: permRoot,
  });
  const rebV2 = {
    schema_version: STATE_REBUILD_ARCHIVE_SCHEMA_V2,
    tenant_id: tenant,
    scope,
    up_to_seq: 2,
    evaluated_at: ts,
    genesis_host_public_key: k0Pk,
    host_public_key: k1Pk,
    permission_root: permRoot,
    header_hash: hdr2,
    host_header_signature: signRebuildArchiveHeader(k1Seed, tenant, hdr2),
    override_attestations: [],
    evidence_chain: [ev1, ev2],
  };
  const rebuiltV2 = verifyAndRebuildScopeStateOffline(rebV2, k1Pk);
  const expV2 = computeStateCommitment({
    schemaVersion: SCHEMA_VERSION_V2,
    tenantId: tenant,
    scope,
    intentRoot: computeSubCommitmentV2([]),
    knowledgeRoot: computeSubCommitmentV2([clm.content_hash]),
    memoryRoot: computeSubCommitmentV2([]),
    permissionRoot: permRoot,
  });
  assert.equal(rebuiltV2.reconstructed_state_commitment_hex, expV2);
  console.log("TYPESCRIPT @acta/sdk v1.7.3 STATE:V2 + KEY ROTATION + ERASURE PARITY PASSED!");
}
