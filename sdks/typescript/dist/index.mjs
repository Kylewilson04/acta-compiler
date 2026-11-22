/**
 * @acta/sdk v1.5.0 — Zero-Dependency ESM Runtime for Acta Compiler v1.5
 *
 * Bit-for-bit compatible with Rust `acta-crypto`:
 * - Spec-exact pure-JS BLAKE3 (256-bit unkeyed + Keyed BLAKE3 MAC)
 * - Stateless `acta_tk_v1:<tenant_id>:<64_hex_mac>` tenant-bound API keys & `X-Acta-Tenant` locking
 * - RFC 8785 JSON Canonicalization Scheme (JCS) + 8-byte LE length-delimited hashing
 * - `ResolverManifest` verification, strip/tamper-proof `RefusalMetadata` (`b"acta:refusal_meta:v2"`
 *   + `b"acta:evidence_event:v2"`), and signed `OverrideAttestation` (`b"acta:override:v1"`) verification
 * - Strict Ed25519 verification via `node:crypto` rejecting all 8 torsion weak keys & `S >= L`
 * - `ActaClient` + `ActaGeminiGuard` pre-prompt circuit-breakers for `@google/genai`
 */

import * as nodeCrypto from "node:crypto";

export const DEFAULT_CLOUDRUN_URL = "https://acta-server-998422936041.us-west1.run.app";
export const TENANT_TOKEN_PREFIX = "acta_tk_v1:";
export const DEFAULT_MIN_CONFIDENCE = 0.7;
export const DEFAULT_DECISIVENESS_THRESHOLD = 0.15;
export const DEFAULT_CORROBORATION_DAMPING = 0.5;

const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;
const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;
const KEYED_HASH = 16;

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const WEAK_ED25519_PUBKEYS = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);

function rotr32(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function g(s, a, b, c, d, mx, my) {
  s[a] = (s[a] + s[b] + mx) >>> 0;
  s[d] = rotr32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + my) >>> 0;
  s[d] = rotr32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr32(s[b] ^ s[c], 7);
}

function roundFn(s, m) {
  g(s, 0, 4, 8, 12, m[0], m[1]);
  g(s, 1, 5, 9, 13, m[2], m[3]);
  g(s, 2, 6, 10, 14, m[4], m[5]);
  g(s, 3, 7, 11, 15, m[6], m[7]);
  g(s, 0, 5, 10, 15, m[8], m[9]);
  g(s, 1, 6, 11, 12, m[10], m[11]);
  g(s, 2, 7, 8, 13, m[12], m[13]);
  g(s, 3, 4, 9, 14, m[14], m[15]);
}

function compress(cv, blockWords, counterBig, blockLen, flags) {
  const s = new Uint32Array(16);
  s.set(cv, 0);
  s[8] = IV[0];
  s[9] = IV[1];
  s[10] = IV[2];
  s[11] = IV[3];
  s[12] = Number(counterBig & 0xffffffffn) >>> 0;
  s[13] = Number((counterBig >> 32n) & 0xffffffffn) >>> 0;
  s[14] = blockLen >>> 0;
  s[15] = flags >>> 0;

  let m = Uint32Array.from(blockWords);
  for (let r = 0; r < 7; r++) {
    roundFn(s, m);
    if (r < 6) {
      const next = new Uint32Array(16);
      for (let i = 0; i < 16; i++) next[i] = m[MSG_PERMUTATION[i]];
      m = next;
    }
  }
  for (let i = 0; i < 8; i++) {
    s[i] = (s[i] ^ s[i + 8]) >>> 0;
    s[i + 8] = (s[i + 8] ^ cv[i]) >>> 0;
  }
  return s;
}

function wordsFromBlock(buf, len) {
  const padded = new Uint8Array(BLOCK_LEN);
  padded.set(buf.subarray(0, len));
  const dv = new DataView(padded.buffer);
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) out[i] = dv.getUint32(i * 4, true);
  return out;
}

function wordsFromKey32(keyBytes) {
  if (keyBytes.length !== 32) throw new Error("BLAKE3 key must be 32 bytes");
  const copy = Uint8Array.from(keyBytes);
  const dv = new DataView(copy.buffer);
  const out = new Uint32Array(8);
  for (let i = 0; i < 8; i++) out[i] = dv.getUint32(i * 4, true);
  return out;
}

class Blake3Output {
  constructor(inputCv, blockWords, counterBig, blockLen, flags) {
    this.inputCv = inputCv;
    this.blockWords = blockWords;
    this.counterBig = counterBig;
    this.blockLen = blockLen;
    this.flags = flags;
  }
  chainingValue() {
    return compress(this.inputCv, this.blockWords, this.counterBig, this.blockLen, this.flags).subarray(0, 8);
  }
  rootBytes() {
    const words = compress(this.inputCv, this.blockWords, 0n, this.blockLen, this.flags | ROOT);
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(i * 4, words[i], true);
    return out;
  }
}

class ChunkState {
  constructor(keyWords, chunkCounterBig, flags) {
    this.cv = Uint32Array.from(keyWords);
    this.chunkCounterBig = chunkCounterBig;
    this.block = new Uint8Array(BLOCK_LEN);
    this.blockLen = 0;
    this.blocksCompressed = 0;
    this.flags = flags;
  }
  length() {
    return BLOCK_LEN * this.blocksCompressed + this.blockLen;
  }
  startFlag() {
    return this.blocksCompressed === 0 ? CHUNK_START : 0;
  }
  update(bytes) {
    let offset = 0;
    while (offset < bytes.length) {
      if (this.blockLen === BLOCK_LEN) {
        const words = wordsFromBlock(this.block, BLOCK_LEN);
        this.cv = compress(this.cv, words, this.chunkCounterBig, BLOCK_LEN, this.flags | this.startFlag()).subarray(0, 8);
        this.blocksCompressed += 1;
        this.block.fill(0);
        this.blockLen = 0;
      }
      const take = Math.min(BLOCK_LEN - this.blockLen, bytes.length - offset);
      this.block.set(bytes.subarray(offset, offset + take), this.blockLen);
      this.blockLen += take;
      offset += take;
    }
  }
  output() {
    const words = wordsFromBlock(this.block, this.blockLen);
    return new Blake3Output(
      this.cv,
      words,
      this.chunkCounterBig,
      this.blockLen,
      this.flags | this.startFlag() | CHUNK_END
    );
  }
}

function parentOutput(leftCv, rightCv, keyWords, flags) {
  const words = new Uint32Array(16);
  words.set(leftCv, 0);
  words.set(rightCv, 8);
  return new Blake3Output(keyWords, words, 0n, BLOCK_LEN, PARENT | flags);
}

export class Blake3Hasher {
  constructor(key32 = null) {
    if (key32 != null) {
      const kb = key32 instanceof Uint8Array ? key32 : Buffer.from(key32);
      this.keyWords = wordsFromKey32(kb);
      this.flags = KEYED_HASH;
    } else {
      this.keyWords = IV;
      this.flags = 0;
    }
    this.chunkState = new ChunkState(this.keyWords, 0n, this.flags);
    this.cvStack = [];
  }
  _addChunkCv(newCv, totalChunksBig) {
    let tc = totalChunksBig;
    let cv = newCv;
    while ((tc & 1n) === 0n) {
      const left = this.cvStack.pop();
      cv = parentOutput(left, cv, this.keyWords, this.flags).chainingValue();
      tc >>= 1n;
    }
    this.cvStack.push(cv);
  }
  update(input) {
    const bytes = input instanceof Uint8Array ? input : Buffer.from(input);
    let offset = 0;
    while (offset < bytes.length) {
      if (this.chunkState.length() === CHUNK_LEN) {
        const chunkCv = this.chunkState.output().chainingValue();
        const totalChunks = this.chunkState.chunkCounterBig + 1n;
        this._addChunkCv(chunkCv, totalChunks);
        this.chunkState = new ChunkState(this.keyWords, totalChunks, this.flags);
      }
      const take = Math.min(CHUNK_LEN - this.chunkState.length(), bytes.length - offset);
      this.chunkState.update(bytes.subarray(offset, offset + take));
      offset += take;
    }
    return this;
  }
  digest() {
    let out = this.chunkState.output();
    for (let i = this.cvStack.length - 1; i >= 0; i--) {
      out = parentOutput(this.cvStack[i], out.chainingValue(), this.keyWords, this.flags);
    }
    return out.rootBytes();
  }
  hexdigest() {
    return Buffer.from(this.digest()).toString("hex");
  }
}

const utf8Encoder = new TextEncoder();

function u64LeBytes(nBig) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(nBig), true);
  return b;
}

function i64LeBytes(nBig) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt(nBig), true);
  return b;
}

function i32LeBytes(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, n | 0, true);
  return b;
}

function f32LeBytes(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setFloat32(0, Number(n), true);
  return b;
}

function f64LeBytes(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setFloat64(0, Number(n), true);
  return b;
}

function hexToBytes(hexStr) {
  if (hexStr instanceof Uint8Array) return hexStr;
  return Uint8Array.from(Buffer.from(String(hexStr).trim(), "hex"));
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function uuidToBytes(uuidStr) {
  const clean = String(uuidStr).replace(/-/g, "").trim();
  if (clean.length !== 32) throw new Error(`Invalid UUID: ${uuidStr}`);
  return hexToBytes(clean);
}

function normalizeUuidString(uuidStr) {
  const raw = String(uuidStr).replace(/-/g, "").trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(raw)) throw new Error(`Invalid UUID: ${uuidStr}`);
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}

export function toCanonicalJson(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("RFC 8785 JCS forbids NaN and Infinity");
    if (Object.is(value, -0) || value === 0) return "0";
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((el) => toCanonicalJson(el)).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined);
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => `${JSON.stringify(k)}:${toCanonicalJson(value[k])}`).join(",") + "}";
  }
  throw new Error(`Unsupported JCS type: ${t}`);
}

export function toCanonicalBytes(value) {
  return utf8Encoder.encode(toCanonicalJson(value));
}

export function hashLengthDelimited(parts) {
  const hasher = new Blake3Hasher();
  for (const raw of parts) {
    const p = typeof raw === "string" ? utf8Encoder.encode(raw) : raw;
    hasher.update(u64LeBytes(BigInt(p.byteLength)));
    hasher.update(p);
  }
  return hasher.digest();
}

export function blake3KeyedHash(key32, parts) {
  const hasher = new Blake3Hasher(key32);
  for (const raw of parts) {
    const p = typeof raw === "string" ? utf8Encoder.encode(raw) : raw;
    hasher.update(p);
  }
  return hasher.digest();
}

export function deriveTenantMacKey(masterApiKey) {
  return hashLengthDelimited(["acta:tenant_mac_key:v1", String(masterApiKey).trim()]);
}

export function mintTenantApiKey(masterApiKey, tenantId) {
  const masterClean = String(masterApiKey || "").trim();
  if (!masterClean) throw new Error("masterApiKey must be non-empty");
  const tenantClean = String(tenantId || "").trim();
  const tBytes = utf8Encoder.encode(tenantClean);
  if (!tenantClean || tBytes.length > 128) throw new Error("tenantId must be 1..128 bytes");
  if (/[\s:\x00-\x1f\x7f]/.test(tenantClean)) {
    throw new Error("tenantId cannot contain whitespace, control characters, or ':'");
  }
  const key32 = deriveTenantMacKey(masterClean);
  const domain = utf8Encoder.encode("acta:tenant_token:v1");
  const mac = blake3KeyedHash(key32, [
    u64LeBytes(BigInt(domain.length)),
    domain,
    u64LeBytes(BigInt(tBytes.length)),
    tBytes,
  ]);
  return `${TENANT_TOKEN_PREFIX}${tenantClean}:${bytesToHex(mac)}`;
}

export function extractTokenTenant(token) {
  if (!token) return null;
  const clean = String(token).trim();
  if (!clean.startsWith(TENANT_TOKEN_PREFIX)) return null;
  const rest = clean.slice(TENANT_TOKEN_PREFIX.length);
  const sep = rest.lastIndexOf(":");
  if (sep <= 0) throw new Error("malformed acta_tk_v1 token");
  const tenantPart = rest.slice(0, sep);
  const macHex = rest.slice(sep + 1);
  if (!/^[0-9a-fA-F]{64}$/.test(macHex)) throw new Error("malformed acta_tk_v1 MAC");
  return tenantPart;
}

export function verifyTenantApiKey(masterApiKey, token) {
  const tenantPart = extractTokenTenant(token);
  if (!tenantPart) throw new Error("token does not start with acta_tk_v1:");
  const expected = Buffer.from(mintTenantApiKey(masterApiKey, tenantPart), "utf8");
  const provided = Buffer.from(String(token).trim(), "utf8");
  if (expected.length !== provided.length || !nodeCrypto.timingSafeEqual(expected, provided)) {
    throw new Error("invalid or forged tenant-bound API key MAC");
  }
  return tenantPart;
}

export function parseRfc3339Micros(ts) {
  const s = String(ts).trim();
  const match = s.match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/i
  );
  if (!match) {
    const ms = Date.parse(s);
    if (Number.isNaN(ms)) throw new Error(`Invalid RFC 3339 timestamp: ${ts}`);
    return BigInt(ms) * 1000n;
  }
  const [, yr, mo, da, hr, mi, se, fracRaw, tz] = match;
  const frac6 = ((fracRaw || "") + "000000").slice(0, 6);
  const utcMs = Date.UTC(
    Number(yr),
    Number(mo) - 1,
    Number(da),
    Number(hr),
    Number(mi),
    Number(se)
  );
  let offsetMin = 0;
  if (tz.toUpperCase() !== "Z") {
    const sign = tz[0] === "-" ? -1 : 1;
    const [oh, om] = tz.slice(1).split(":").map(Number);
    offsetMin = sign * (oh * 60 + om);
  }
  const adjustedMs = BigInt(utcMs) - BigInt(offsetMin) * 60_000n;
  return adjustedMs * 1000n + BigInt(frac6);
}

function encodeOptUuid(u) {
  const out = new Uint8Array(17);
  if (u != null) {
    out[0] = 1;
    out.set(uuidToBytes(u), 1);
  }
  return out;
}

function encodeOptI64(vBig) {
  const out = new Uint8Array(9);
  if (vBig != null) {
    out[0] = 1;
    out.set(i64LeBytes(vBig), 1);
  }
  return out;
}

function encodeOptHash32(h) {
  const out = new Uint8Array(33);
  if (h != null) {
    const b = hexToBytes(h);
    if (b.length !== 32) throw new Error("expected 32-byte hash");
    out[0] = 1;
    out.set(b, 1);
  }
  return out;
}

function encodeOptJcs(val) {
  if (val == null) return new Uint8Array([0]);
  const jcs = toCanonicalBytes(val);
  const out = new Uint8Array(1 + jcs.length);
  out[0] = 1;
  out.set(jcs, 1);
  return out;
}

function normalizeRefusalMetadata(meta) {
  const out = {
    operation: String(meta.operation),
    reason_code: String(meta.reason_code),
    summary: String(meta.summary),
  };
  if (meta.target_scope != null) {
    out.target_scope = String(meta.target_scope);
  }
  if (meta.scope_state_commitment != null) {
    const b = hexToBytes(meta.scope_state_commitment);
    if (b.length !== 32) throw new Error("expected 32-byte scope_state_commitment");
    out.scope_state_commitment = bytesToHex(b).toLowerCase();
  }
  return out;
}

function normalizeOverrideSummary(summary) {
  return {
    attestation_id: normalizeUuidString(summary.attestation_id),
    scope: String(summary.scope),
    subject: String(summary.subject),
    predicate: String(summary.predicate),
    winning_claim_id: normalizeUuidString(summary.winning_claim_id),
    overridden_count: Number(summary.overridden_count),
    adjudicator_id: String(summary.adjudicator_id),
    version: Number(summary.version),
  };
}

export function computeClaimGroupKey(tenant, subject, predicate, objectType, scope) {
  return bytesToHex(hashLengthDelimited([tenant, subject, predicate, objectType, scope]));
}

export function computeLogicalClaimGroupKey(tenant, subject, predicate, scope) {
  return bytesToHex(hashLengthDelimited(["acta:claim_group:v2", tenant, subject, predicate, scope]));
}

export function computeRefusalMetadataCommitment(meta) {
  return bytesToHex(
    hashLengthDelimited(["acta:refusal_meta:v2", toCanonicalBytes(normalizeRefusalMetadata(meta))])
  );
}

export function computeObjectContentHash(obj) {
  return bytesToHex(
    hashLengthDelimited([
      "acta:object:v1",
      uuidToBytes(obj.id),
      String(obj.tenant_id),
      String(obj.obj_type),
      String(obj.scope),
      String(obj.lifecycle_status),
      i32LeBytes(obj.priority),
      f32LeBytes(obj.importance),
      toCanonicalBytes(obj.tags || []),
      toCanonicalBytes(obj.body),
      i32LeBytes(obj.version),
      encodeOptUuid(obj.predecessor_id ?? null),
      i64LeBytes(parseRfc3339Micros(obj.created_at)),
    ])
  );
}

export function computeClaimContentHash(claim) {
  const sortedContradictions = [...(claim.contradiction_ids || [])]
    .map((u) => normalizeUuidString(u))
    .sort();
  return bytesToHex(
    hashLengthDelimited([
      "acta:claim:v1",
      uuidToBytes(claim.id),
      String(claim.tenant_id),
      hexToBytes(claim.claim_group_key),
      String(claim.scope),
      String(claim.subject),
      String(claim.predicate),
      toCanonicalBytes(claim.object_val),
      String(claim.object_type),
      f64LeBytes(claim.confidence),
      i32LeBytes(claim.source_provenance_class),
      String(claim.source_descriptor),
      hexToBytes(claim.source_commitment),
      String(claim.status),
      toCanonicalBytes(sortedContradictions),
      encodeOptI64(claim.valid_from != null ? parseRfc3339Micros(claim.valid_from) : null),
      encodeOptI64(claim.valid_to != null ? parseRfc3339Micros(claim.valid_to) : null),
      i32LeBytes(claim.version),
      encodeOptUuid(claim.predecessor_id ?? null),
      i64LeBytes(parseRfc3339Micros(claim.created_at)),
    ])
  );
}

export function computeOverrideAttestationHash(att) {
  const sortedOverridden = [...(att.overridden_claims || [])]
    .map((x) => {
      const id = normalizeUuidString(x.id);
      const chBytes = hexToBytes(x.content_hash);
      if (chBytes.length !== 32) throw new Error("expected 32-byte content_hash in overridden_claims");
      return { id, content_hash: bytesToHex(chBytes).toLowerCase() };
    })
    .sort((a, b) =>
      a.id < b.id ? -1 : a.id > b.id ? 1 : a.content_hash < b.content_hash ? -1 : a.content_hash > b.content_hash ? 1 : 0
    );

  return bytesToHex(
    hashLengthDelimited([
      "acta:override:v1",
      uuidToBytes(att.id),
      String(att.tenant_id),
      String(att.scope),
      hexToBytes(att.claim_group_key),
      String(att.subject),
      String(att.predicate),
      encodeOptHash32(att.source_bundle_hash ?? null),
      uuidToBytes(att.winning_claim_id),
      hexToBytes(att.winning_claim_content_hash),
      toCanonicalBytes(sortedOverridden),
      String(att.adjudicator_id),
      String(att.justification),
      i32LeBytes(att.version),
      encodeOptUuid(att.predecessor_id ?? null),
      i64LeBytes(parseRfc3339Micros(att.created_at)),
    ])
  );
}

export function computeOmissionListHash(sortedItems) {
  const parts = ["acta:omissions:v1"];
  for (const item of sortedItems) {
    parts.push(`{"id":"${normalizeUuidString(item.id)}","reason":"${item.reason}"}`);
  }
  return bytesToHex(hashLengthDelimited(parts));
}

export function computeBundleHash(bundle) {
  const canonicalBytes = toCanonicalBytes(bundle);
  const hashHex = bytesToHex(hashLengthDelimited(["acta:bundle:v1", canonicalBytes]));
  return { hashHex, canonicalBytes };
}

export function computeEvidenceEventHash({
  tenantId,
  seqNum,
  prevHash,
  bundleHash = null,
  stateCommitment = null,
  policyResult,
  createdAt,
  refusalMetadata = null,
  overrideSummary = null,
}) {
  const micros = typeof createdAt === "bigint" ? createdAt : parseRfc3339Micros(createdAt);
  if (refusalMetadata == null && overrideSummary == null) {
    return bytesToHex(
      hashLengthDelimited([
        "acta:evidence_event:v1",
        String(tenantId),
        i64LeBytes(BigInt(seqNum)),
        hexToBytes(prevHash),
        encodeOptHash32(bundleHash),
        encodeOptHash32(stateCommitment),
        String(policyResult),
        i64LeBytes(micros),
      ])
    );
  }
  const refusalTagged = encodeOptJcs(
    refusalMetadata != null ? normalizeRefusalMetadata(refusalMetadata) : null
  );
  const overrideTagged = encodeOptJcs(
    overrideSummary != null ? normalizeOverrideSummary(overrideSummary) : null
  );
  return bytesToHex(
    hashLengthDelimited([
      "acta:evidence_event:v2",
      String(tenantId),
      i64LeBytes(BigInt(seqNum)),
      hexToBytes(prevHash),
      encodeOptHash32(bundleHash),
      encodeOptHash32(stateCommitment),
      String(policyResult),
      i64LeBytes(micros),
      refusalTagged,
      overrideTagged,
    ])
  );
}

export function evidenceSigningPreimage(tenantId, seqNum, prevHash, eventHash) {
  return hashLengthDelimited([
    "acta:evidence_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(seqNum)),
    hexToBytes(prevHash),
    hexToBytes(eventHash),
  ]);
}

export function overrideSigningPreimage(tenantId, evidenceSeqNum, attestationHash) {
  return hashLengthDelimited([
    "acta:override_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(evidenceSeqNum)),
    hexToBytes(attestationHash),
  ]);
}

export function verifyEd25519Strict(pubkeyHexOrBytes, messageBytes, sigHexOrBytes) {
  const pk = hexToBytes(pubkeyHexOrBytes);
  const sig = hexToBytes(sigHexOrBytes);
  if (pk.length !== 32 || sig.length !== 64) return false;
  if (WEAK_ED25519_PUBKEYS.has(bytesToHex(pk).toLowerCase())) return false;

  let sScalar = 0n;
  for (let i = 63; i >= 32; i--) {
    sScalar = (sScalar << 8n) | BigInt(sig[i]);
  }
  if (sScalar >= ED25519_L) return false;

  try {
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pk)]);
    const keyObj = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    return nodeCrypto.verify(null, Buffer.from(messageBytes), keyObj, Buffer.from(sig));
  } catch {
    return false;
  }
}

export function signEvidenceEntry(seedHexOrBytes, tenantId, seqNum, prevHash, eventHash) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digest = evidenceSigningPreimage(tenantId, seqNum, prevHash, eventHash);
  return bytesToHex(nodeCrypto.sign(null, Buffer.from(digest), privKey));
}

export function signOverrideAttestation(seedHexOrBytes, tenantId, evidenceSeqNum, attestationHash) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digest = overrideSigningPreimage(tenantId, evidenceSeqNum, attestationHash);
  return bytesToHex(nodeCrypto.sign(null, Buffer.from(digest), privKey));
}

export function verifyOverrideSignature(pubkeyHexOrBytes, tenantId, evidenceSeqNum, attestationHash, sigHexOrBytes) {
  const digest = overrideSigningPreimage(tenantId, evidenceSeqNum, attestationHash);
  return verifyEd25519Strict(pubkeyHexOrBytes, digest, sigHexOrBytes);
}

export function deriveEd25519PublicKeyHex(seedHexOrBytes) {
  const seed = hexToBytes(seedHexOrBytes);
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = nodeCrypto.createPublicKey(privKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(12, 44).toString("hex");
}

export function verifyEvidenceEntry(entry, expectedPubkeyHex) {
  if (entry.refusal_metadata != null) {
    if (entry.bundle_hash != null) {
      throw new ActaSignatureVerificationError(
        `invalid evidence entry at seq_num=${entry.seq_num}: refusal_metadata cannot coexist with bundle_hash`
      );
    }
    const expectedRefusalComm = computeRefusalMetadataCommitment(entry.refusal_metadata);
    if (!entry.state_commitment || String(entry.state_commitment).toLowerCase() !== expectedRefusalComm) {
      throw new ActaSignatureVerificationError(
        `tampered refusal_metadata at seq_num=${entry.seq_num}: state_commitment mismatch`
      );
    }
  }

  const recomputed = computeEvidenceEventHash({
    tenantId: entry.tenant_id,
    seqNum: entry.seq_num,
    prevHash: entry.prev_hash,
    bundleHash: entry.bundle_hash ?? null,
    stateCommitment: entry.state_commitment ?? null,
    policyResult: entry.policy_result,
    createdAt: entry.created_at,
    refusalMetadata: entry.refusal_metadata ?? null,
    overrideSummary: entry.override_summary ?? null,
  });
  const storedHex = String(entry.event_hash).toLowerCase();
  if (recomputed !== storedHex) {
    throw new ActaSignatureVerificationError(
      `tampered evidence entry at seq_num=${entry.seq_num}: recomputed event_hash ${recomputed} != stored ${storedHex}`
    );
  }
  const digest = evidenceSigningPreimage(entry.tenant_id, entry.seq_num, entry.prev_hash, recomputed);
  if (!verifyEd25519Strict(expectedPubkeyHex, digest, entry.host_signature)) {
    throw new ActaSignatureVerificationError(
      `Ed25519 host_signature verification failed at evidence seq_num=${entry.seq_num}`
    );
  }
}

function expectedNonDefaultFlag(rm) {
  const minC = Number(rm.min_confidence);
  const decT = Number(rm.decisiveness_threshold);
  const damp = Number(rm.corroboration_damping);
  return (
    Math.abs(minC - DEFAULT_MIN_CONFIDENCE) > 1e-9 ||
    Math.abs(decT - DEFAULT_DECISIVENESS_THRESHOLD) > 1e-9 ||
    Math.abs(damp - DEFAULT_CORROBORATION_DAMPING) > 1e-9
  );
}

export function verifyExportArchive(archive, expectedPubkeyHex) {
  const expectedClean = String(expectedPubkeyHex).trim().toLowerCase();
  const archivePk = String(archive.host_public_key).trim().toLowerCase();
  if (archivePk !== expectedClean) {
    throw new ActaVerificationError(
      `host_public_key mismatch: archive contains ${archivePk}, expected ${expectedClean}`
    );
  }
  if (WEAK_ED25519_PUBKEYS.has(expectedClean)) {
    throw new ActaVerificationError("rejected weak low-order Ed25519 public key");
  }

  const bundle = archive.bundle;
  const rm = bundle.resolver_manifest ?? null;
  if (rm != null) {
    const minC = Number(rm.min_confidence);
    const decT = Number(rm.decisiveness_threshold);
    const damp = Number(rm.corroboration_damping);
    if (
      !Number.isFinite(minC) ||
      minC < 0 ||
      minC > 1 ||
      !Number.isFinite(decT) ||
      decT < 0 ||
      decT > 1 ||
      !Number.isFinite(damp) ||
      damp < 0 ||
      damp > 1
    ) {
      throw new ActaVerificationError("invalid resolver_manifest threshold bounds in ContextBundle");
    }
    if (Boolean(rm.non_default_thresholds) !== expectedNonDefaultFlag(rm)) {
      throw new ActaVerificationError(
        `inconsistent resolver_manifest.non_default_thresholds=${rm.non_default_thresholds}`
      );
    }
  }

  const objectsById = new Map();
  for (const obj of archive.objects || []) {
    const id = normalizeUuidString(obj.id);
    const recomputed = computeObjectContentHash(obj);
    if (recomputed !== String(obj.content_hash).toLowerCase()) {
      throw new ActaVerificationError(
        `tampered object[id=${id}]: recomputed content_hash ${recomputed} != stored ${obj.content_hash}`
      );
    }
    objectsById.set(id, obj);
  }

  const claimsById = new Map();
  for (const claim of archive.claims || []) {
    const id = normalizeUuidString(claim.id);
    const expectedV2 = computeLogicalClaimGroupKey(
      claim.tenant_id,
      claim.subject,
      claim.predicate,
      claim.scope
    );
    const expectedV1 = computeClaimGroupKey(
      claim.tenant_id,
      claim.subject,
      claim.predicate,
      claim.object_type,
      claim.scope
    );
    const storedGroup = String(claim.claim_group_key).toLowerCase();
    if (storedGroup !== expectedV2 && storedGroup !== expectedV1) {
      throw new ActaVerificationError(`tampered claim[id=${id}].claim_group_key`);
    }
    const recomputed = computeClaimContentHash(claim);
    if (recomputed !== String(claim.content_hash).toLowerCase()) {
      throw new ActaVerificationError(
        `tampered claim[id=${id}] body/metadata: recomputed content_hash ${recomputed} != stored ${claim.content_hash}`
      );
    }
    claimsById.set(id, claim);
  }

  const overridesById = new Map();
  for (const att of archive.override_attestations || []) {
    const aid = normalizeUuidString(att.id);
    if (String(att.tenant_id) !== String(bundle.tenant_id)) {
      throw new ActaVerificationError(`override_attestation[id=${aid}] tenant_id mismatch`);
    }
    const recomputedAtt = computeOverrideAttestationHash(att);
    if (recomputedAtt !== String(att.attestation_hash).toLowerCase()) {
      throw new ActaVerificationError(`tampered override_attestation[id=${aid}]`);
    }
    if (
      !verifyOverrideSignature(
        expectedClean,
        att.tenant_id,
        att.evidence_seq_num,
        recomputedAtt,
        att.host_signature
      )
    ) {
      throw new ActaVerificationError(
        `Ed25519 host_signature verification failed on override_attestation[id=${aid}]`
      );
    }
    if (att.client_signature != null && att.client_public_key != null) {
      if (!verifyEd25519Strict(att.client_public_key, hexToBytes(recomputedAtt), att.client_signature)) {
        throw new ActaVerificationError(
          `client Ed25519 signature verification failed on override_attestation[id=${aid}]`
        );
      }
    }
    overridesById.set(aid, att);
  }

  for (const sel of bundle.selected_objects || []) {
    const obj = objectsById.get(normalizeUuidString(sel.id));
    if (
      !obj ||
      String(sel.content_hash).toLowerCase() !== String(obj.content_hash).toLowerCase() ||
      sel.version !== obj.version
    ) {
      throw new ActaVerificationError(`tampered or missing selected_object[id=${sel.id}]`);
    }
  }

  for (const res of bundle.resolution_records || []) {
    const c = res.winning_claim;
    const cid = normalizeUuidString(c.id);
    const stored = claimsById.get(cid);
    if (!stored || String(c.content_hash).toLowerCase() !== String(stored.content_hash).toLowerCase()) {
      throw new ActaVerificationError(`tampered resolution_record claim[id=${c.id}]`);
    }
    if (res.override_attestation != null) {
      const ovrRef = res.override_attestation;
      const aid = normalizeUuidString(ovrRef.attestation_id);
      const verifiedAtt = overridesById.get(aid);
      if (!verifiedAtt) {
        throw new ActaVerificationError(`resolution_record references missing override_attestation[id=${aid}]`);
      }
      if (
        String(verifiedAtt.attestation_hash).toLowerCase() !== String(ovrRef.attestation_hash).toLowerCase() ||
        normalizeUuidString(verifiedAtt.winning_claim_id) !== cid ||
        String(verifiedAtt.winning_claim_content_hash).toLowerCase() !== String(c.content_hash).toLowerCase() ||
        String(verifiedAtt.adjudicator_id) !== String(ovrRef.adjudicator_id) ||
        String(verifiedAtt.justification) !== String(ovrRef.justification) ||
        Number(verifiedAtt.evidence_seq_num) !== Number(ovrRef.evidence_seq_num)
      ) {
        throw new ActaVerificationError(
          `tampered override_attestation reference on resolution_record for claim[id=${cid}]`
        );
      }
    }
  }

  for (const disp of bundle.dispute_records || []) {
    if (!disp.competing_claims || disp.competing_claims.length === 0) {
      throw new ActaVerificationError("invalid dispute_record with empty competing_claims");
    }
    for (const c of disp.competing_claims) {
      const stored = claimsById.get(normalizeUuidString(c.id));
      if (!stored || String(c.content_hash).toLowerCase() !== String(stored.content_hash).toLowerCase()) {
        throw new ActaVerificationError(`tampered dispute_record claim[id=${c.id}]`);
      }
    }
  }

  const { hashHex: recomputedBundleHash } = computeBundleHash(bundle);
  if (recomputedBundleHash !== String(archive.bundle_hash).toLowerCase()) {
    throw new ActaVerificationError(
      `tampered ContextBundle: recomputed bundle_hash ${recomputedBundleHash} != archive ${archive.bundle_hash}`
    );
  }

  const chain = archive.evidence_chain || [];
  if (chain.length === 0) throw new ActaVerificationError("evidence_chain cannot be empty");

  let foundBinding = false;
  let verifiedRefusals = 0;
  const evidenceBySeq = new Map();
  const zeroHex = "00".repeat(32);

  for (let idx = 0; idx < chain.length; idx++) {
    const entry = chain[idx];
    if (entry.tenant_id !== bundle.tenant_id) {
      throw new ActaVerificationError("evidence_chain tenant_id mismatch");
    }
    if (idx === 0) {
      if (entry.seq_num === 1 && String(entry.prev_hash).toLowerCase() !== zeroHex) {
        throw new ActaVerificationError("genesis seq_num=1 must have zero prev_hash");
      }
    } else {
      const prev = chain[idx - 1];
      if (
        entry.seq_num !== prev.seq_num + 1 ||
        String(entry.prev_hash).toLowerCase() !== String(prev.event_hash).toLowerCase()
      ) {
        throw new ActaVerificationError(`broken evidence chain at seq_num=${entry.seq_num}`);
      }
    }
    if (entry.refusal_metadata != null) verifiedRefusals += 1;
    try {
      verifyEvidenceEntry(entry, expectedClean);
    } catch (err) {
      throw new ActaVerificationError(err.message);
    }

    if (entry.bundle_hash && String(entry.bundle_hash).toLowerCase() === recomputedBundleHash) {
      if (String(entry.state_commitment).toLowerCase() !== String(bundle.state_commitment).toLowerCase()) {
        throw new ActaVerificationError("evidence state_commitment mismatch against ContextBundle");
      }
      foundBinding = true;
    }
    evidenceBySeq.set(Number(entry.seq_num), entry);
  }

  for (const [aid, att] of overridesById.entries()) {
    const ev = evidenceBySeq.get(Number(att.evidence_seq_num));
    if (!ev) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] references missing evidence_chain seq_num=${att.evidence_seq_num}`
      );
    }
    if (!ev.state_commitment || String(ev.state_commitment).toLowerCase() !== String(att.attestation_hash).toLowerCase()) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] attestation_hash not bound in evidence seq_num=${att.evidence_seq_num}`
      );
    }
  }

  if (!foundBinding) {
    throw new ActaVerificationError(`no verified evidence_history entry binds bundle_hash ${recomputedBundleHash}`);
  }

  return {
    tenant_id: bundle.tenant_id,
    bundle_hash_hex: recomputedBundleHash,
    state_commitment_hex: String(bundle.state_commitment).toLowerCase(),
    verified_objects: objectsById.size,
    verified_claims: claimsById.size,
    verified_overrides: overridesById.size,
    verified_refusals: verifiedRefusals,
    verified_evidence_entries: chain.length,
    non_default_thresholds: rm != null ? Boolean(rm.non_default_thresholds) : false,
    resolver_manifest: rm,
  };
}

export class ActaError extends Error {}
export class ActaHttpError extends ActaError {
  constructor(statusCode, message, payload = null) {
    super(`HTTP ${statusCode}: ${message}`);
    this.statusCode = statusCode;
    this.payload = payload;
  }
}
export class ActaAuthError extends ActaHttpError {}
export class ActaSignatureVerificationError extends ActaError {}
export class ActaVerificationError extends ActaError {}
export class ActaTenantLockError extends ActaError {}

export class ActaPolicyBlockedError extends ActaError {
  constructor(reason, evidence, policyDecision) {
    super(`Acta Cedar Policy BLOCKED request before read: ${reason}`);
    this.reason = reason;
    this.evidence = evidence;
    this.policyDecision = policyDecision;
  }
}

export class ActaPolicyEscalatedError extends ActaError {
  constructor(reason, evidence, policyDecision) {
    super(`Acta Cedar Policy ESCALATED request before read: ${reason}`);
    this.reason = reason;
    this.evidence = evidence;
    this.policyDecision = policyDecision;
  }
}

export class ActaDisputeEscalationError extends ActaError {
  constructor(bundleHash, disputes, evidence, contextText) {
    super(`Acta halted LLM execution: ${disputes.length} unresolved claim dispute(s) in bundle ${bundleHash}`);
    this.bundleHash = bundleHash;
    this.disputes = disputes;
    this.evidence = evidence;
    this.contextText = contextText;
  }
}

export class ActaClient {
  constructor(options = {}) {
    const baseUrl =
      options.baseUrl ||
      (typeof process !== "undefined" && process.env?.ACTA_BASE_URL) ||
      DEFAULT_CLOUDRUN_URL;
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.apiKey =
      options.apiKey ??
      (typeof process !== "undefined" ? process.env?.ACTA_API_KEY : undefined);

    const tokTenant = this.apiKey ? extractTokenTenant(this.apiKey) : null;
    const explicitTenant =
      (
        options.defaultTenantId ||
        (typeof process !== "undefined" ? process.env?.ACTA_TENANT_ID : "") ||
        ""
      ).trim() || null;
    if (tokTenant && explicitTenant && tokTenant !== explicitTenant) {
      throw new ActaTenantLockError(
        `defaultTenantId '${explicitTenant}' conflicts with acta_tk_v1 key bound to '${tokTenant}'`
      );
    }
    this.lockedTenant = tokTenant || explicitTenant;

    this.pinnedPubkey =
      (
        options.pinnedHostPublicKey ||
        (typeof process !== "undefined" ? process.env?.ACTA_HOST_PUBLIC_KEY : undefined) ||
        ""
      )
        .trim()
        .toLowerCase() || null;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  _enforceTenant(requestedTenant) {
    const clean = (requestedTenant || "").trim() || null;
    if (this.lockedTenant && clean && clean !== this.lockedTenant) {
      throw new ActaTenantLockError(
        `client is locked to tenant '${this.lockedTenant}', cannot issue request for '${clean}'`
      );
    }
    const resolved = clean || this.lockedTenant;
    if (!resolved) {
      throw new Error(
        "tenantId is required when client is not initialized with an acta_tk_v1 key or defaultTenantId"
      );
    }
    return resolved;
  }

  _headers(includeTenantLock = true) {
    const h = {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)",
    };
    if (this.apiKey) h["X-Acta-Api-Key"] = this.apiKey;
    if (includeTenantLock && this.lockedTenant) h["X-Acta-Tenant"] = this.lockedTenant;
    return h;
  }

  async _requestJson(method, path, body = undefined, allowedStatuses = [200, 201], includeTenantLock = true) {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: this._headers(includeTenantLock),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    if (!allowedStatuses.includes(res.status)) {
      const msg = parsed?.error || text || `status ${res.status}`;
      if (res.status === 401) throw new ActaAuthError(res.status, msg, parsed);
      throw new ActaHttpError(res.status, msg, parsed);
    }
    return { status: res.status, data: parsed };
  }

  async ensureHostPublicKey() {
    if (this.pinnedPubkey) return this.pinnedPubkey;
    const h = await this.health();
    const pk = String(h.host_public_key || "").trim().toLowerCase();
    if (pk.length !== 64) {
      throw new ActaSignatureVerificationError("server /v1/health returned invalid host_public_key");
    }
    this.pinnedPubkey = pk;
    return pk;
  }

  async health() {
    const { data } = await this._requestJson("GET", "/v1/health", undefined, [200], false);
    if (this.pinnedPubkey && String(data.host_public_key || "").toLowerCase() !== this.pinnedPubkey) {
      throw new ActaSignatureVerificationError("host_public_key mismatch against pinned key");
    }
    return data;
  }

  async mintTenantKey(tenantId) {
    const { data } = await this._requestJson(
      "POST",
      "/v1/auth/mint-tenant-key",
      { tenant_id: tenantId },
      [200],
      false
    );
    return data;
  }

  async inspectKey() {
    const { data } = await this._requestJson("GET", "/v1/auth/inspect-key", undefined, [200]);
    return data;
  }

  async ingestObject(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      obj_type: req.objType,
      scope: req.scope,
      lifecycle_status: req.lifecycleStatus || "active",
      priority: req.priority ?? 0,
      importance: req.importance ?? 0.5,
      tags: req.tags || [],
      body: req.body,
    };
    if (req.id) body.id = req.id;
    if (req.embedding) body.embedding = req.embedding;
    if (req.predecessorId) body.predecessor_id = req.predecessorId;
    const { data } = await this._requestJson("POST", "/v1/objects", body, [201]);
    return data;
  }

  async ingestClaim(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      scope: req.scope,
      subject: req.subject,
      predicate: req.predicate,
      object_val: req.objectVal,
      object_type: req.objectType,
      confidence: req.confidence,
      source_provenance_class: req.sourceProvenanceClass ?? 1,
      source_descriptor: req.sourceDescriptor,
      status: req.status || "active",
      contradiction_ids: req.contradictionIds || [],
    };
    if (req.id) body.id = req.id;
    if (req.sourceCommitmentHex) body.source_commitment_hex = req.sourceCommitmentHex;
    if (req.validFrom) body.valid_from = req.validFrom;
    if (req.validTo) body.valid_to = req.validTo;
    if (req.predecessorId) body.predecessor_id = req.predecessorId;
    const { data } = await this._requestJson("POST", "/v1/claims", body, [201]);
    return data;
  }

  async attestOverride(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const body = {
      tenant_id: effTenant,
      scope: req.scope,
      winning_claim_id: req.winningClaimId,
      adjudicator_id: req.adjudicatorId,
      justification: req.justification,
    };
    if (req.sourceBundleHashHex) body.source_bundle_hash_hex = req.sourceBundleHashHex;
    if (req.id) body.id = req.id;
    if (req.clientSignatureHex) body.client_signature_hex = req.clientSignatureHex;
    if (req.clientPublicKeyHex) body.client_public_key_hex = req.clientPublicKeyHex;

    const { data } = await this._requestJson("POST", "/v1/overrides", body, [200, 201]);
    if (
      !verifyOverrideSignature(
        hostPk,
        effTenant,
        data.evidence_seq_num,
        data.attestation_hash,
        data.host_signature
      )
    ) {
      throw new ActaSignatureVerificationError(
        "Ed25519 host_signature verification failed on attestOverride response"
      );
    }
    return data;
  }

  async listOverrides(params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const qs = params.scope ? `?scope=${encodeURIComponent(params.scope)}` : "";
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/overrides${qs}`,
      undefined,
      [200]
    );
    return data;
  }

  async listTenantEvidence(tenantId = undefined) {
    const effTenant = this._enforceTenant(tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/evidence`,
      undefined,
      [200]
    );
    for (const entry of data.entries || []) {
      verifyEvidenceEntry(entry, hostPk);
    }
    return data;
  }

  async compile(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const payload = {
      tenant_id: effTenant,
      actor_id: req.actorId,
      task_id: req.taskId || `task-${nodeCrypto.randomUUID().slice(0, 12)}`,
      scope: req.scope,
      query_text: req.queryText,
      budget: req.budget || { kind: "tokens", limit: 4096 },
    };
    if (req.queryEmbedding) payload.query_embedding = req.queryEmbedding;
    if (req.evaluationTime) payload.evaluation_time = req.evaluationTime;

    const { status, data } = await this._requestJson(
      "POST",
      "/v1/compile",
      payload,
      [200, 202, 403]
    );
    if (!data?.evidence) {
      throw new ActaSignatureVerificationError("compile response missing signed evidence entry");
    }
    verifyEvidenceEntry(data.evidence, hostPk);
    return {
      httpStatus: status,
      policyDecision: data.policy_decision,
      bundleHash: data.bundle_hash ?? null,
      contextText: data.context_text ?? null,
      bundle: data.bundle ?? null,
      evidence: data.evidence,
      verifiedHostPubkey: hostPk,
    };
  }

  async compileGuarded(req) {
    const res = await this.compile(req);
    const dec = res.policyDecision?.decision;
    const reason = res.policyDecision?.reason || "policy denied";
    if (dec === "block") throw new ActaPolicyBlockedError(reason, res.evidence, res.policyDecision);
    if (dec === "escalate") throw new ActaPolicyEscalatedError(reason, res.evidence, res.policyDecision);

    const strictDisputes = req.strictDisputes ?? true;
    const disputes = res.bundle?.dispute_records || [];
    if (strictDisputes && disputes.length > 0) {
      const triggers = req.haltOnAnyDispute
        ? disputes
        : disputes.filter((d) => d.escalation_required !== false);
      if (triggers.length > 0) {
        throw new ActaDisputeEscalationError(
          res.bundleHash || "",
          triggers,
          res.evidence,
          res.contextText || ""
        );
      }
    }
    return res;
  }

  async replay(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      request: {
        tenant_id: effTenant,
        actor_id: req.actorId,
        task_id: req.taskId || "sdk-replay",
        scope: req.scope,
        query_text: req.queryText,
        budget: req.budget || { kind: "tokens", limit: 4096 },
      },
    };
    if (req.evaluationTime) body.request.evaluation_time = req.evaluationTime;
    if (req.counterfactualEvaluationTime) body.counterfactual_evaluation_time = req.counterfactualEvaluationTime;
    if (req.overrideMinConfidence !== undefined) body.override_min_confidence = req.overrideMinConfidence;
    if (req.overrideDecisivenessThreshold !== undefined) body.override_decisiveness_threshold = req.overrideDecisivenessThreshold;
    if (req.overridePolicyCedar) body.override_policy_cedar = req.overridePolicyCedar;

    const { data } = await this._requestJson("POST", "/v1/replay", body, [200]);
    return data;
  }

  async exportBundle(bundleHash) {
    const clean = encodeURIComponent(String(bundleHash).trim().toLowerCase());
    const { data } = await this._requestJson("GET", `/v1/bundles/${clean}/export`, undefined, [200]);
    return data;
  }

  async verifyBundleOffline(bundleHash, expectedPubkeyHex = undefined) {
    const pk = (expectedPubkeyHex || (await this.ensureHostPublicKey())).trim().toLowerCase();
    const archive = await this.exportBundle(bundleHash);
    return verifyExportArchive(archive, pk);
  }
}

export const SYSTEM_GUARDRAIL_HEADER =
  "You are operating under a cryptographically verified Acta Context Bundle.\n" +
  "Treat [INTENT] directives as binding constraints, [FACT] entries as resolved state, " +
  "and NEVER silently guess or pick sides on any [DISPUTE] block.";

export function buildGuardedPrompt(compiledContext, userPrompt, bundleHash) {
  return (
    `=== VERIFIED ACTA CONTEXT BUNDLE (blake3=${bundleHash}) ===\n` +
    `${compiledContext}\n` +
    `=== END VERIFIED ACTA CONTEXT BUNDLE ===\n\n` +
    `User Task:\n${userPrompt}`
  );
}

export class ActaGeminiGuard {
  constructor(actaClient, genaiClient = null, options = {}) {
    this.acta = actaClient;
    this.genai = genaiClient;
    this.defaultModel = options.defaultModel || "gemini-2.5-flash";
    this.strictDisputes = options.strictDisputes ?? true;
    this.haltOnAnyDispute = options.haltOnAnyDispute ?? false;
  }

  async generateContent(params) {
    const compiled = await this.acta.compileGuarded({
      tenantId: params.tenantId,
      actorId: params.actorId,
      scope: params.scope,
      queryText: params.prompt,
      taskId: params.taskId,
      budget: params.budget,
      strictDisputes: this.strictDisputes,
      haltOnAnyDispute: this.haltOnAnyDispute,
    });

    const fullPrompt = buildGuardedPrompt(
      compiled.contextText || "",
      params.prompt,
      compiled.bundleHash
    );

    let rawResponse;
    let text;
    if (params.llmCallable) {
      rawResponse = await params.llmCallable(fullPrompt, compiled);
      text = typeof rawResponse === "string" ? rawResponse : String(rawResponse?.text ?? "");
    } else {
      if (!this.genai) {
        throw new Error("Provide a `@google/genai` GoogleGenAI instance or `llmCallable`");
      }
      const cfg = { ...(params.config || {}) };
      cfg.systemInstruction = cfg.systemInstruction
        ? `${SYSTEM_GUARDRAIL_HEADER}\n\n${cfg.systemInstruction}`
        : SYSTEM_GUARDRAIL_HEADER;
      rawResponse = await this.genai.models.generateContent({
        model: params.model || this.defaultModel,
        contents: fullPrompt,
        config: cfg,
      });
      text = String(rawResponse?.text ?? "");
    }

    return {
      text,
      bundleHash: compiled.bundleHash,
      stateCommitment: compiled.bundle.state_commitment,
      dependencyCommitment: compiled.bundle.dependency_commitment,
      contextText: compiled.contextText || "",
      evidence: compiled.evidence,
      verifiedHostPubkey: compiled.verifiedHostPubkey,
      rawResponse,
    };
  }
}
