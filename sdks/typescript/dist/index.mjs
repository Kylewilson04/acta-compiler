/**
 * @acta/sdk v1.7.1 — Zero-Dependency ESM Runtime for Acta Compiler v1.7.1
 *
 * Bit-for-bit compatible with Rust `acta-crypto`:
 * - Spec-exact pure-JS BLAKE3 (256-bit unkeyed + Keyed BLAKE3 MAC)
 * - Stateless 2-segment `acta_tk_v1:<tenant_id>:<64_hex_mac>` & 3-segment OAuth principal
 *   `acta_tk_v1:<tenant_id>:<github_login>:<64_hex_mac>` keys & `X-Acta-Tenant` locking
 * - RFC 8785 JSON Canonicalization Scheme (JCS) + 8-byte LE length-delimited hashing
 * - `ResolverManifest` verification, strip/tamper-proof `RefusalMetadata` (`b"acta:refusal_meta:v2"`
 *   + `b"acta:evidence_event:v2"`), signed `OverrideAttestation` (`b"acta:override:v1"`,
 *   `b"acta:override_client_sig:v1"`), and `LapsedOverrideRef` provenance verification
 * - RFC 6962 Merkle `SignedTreeHead` checkpoints (`b"acta:checkpoint:v1"`, `b"acta:checkpoint_sig:v1"`),
 *   `O(log N)` inclusion & consistency proofs, external witness cosignatures (`b"acta:witness_sig:v1"`),
 *   and `dumpArchivePreimages`
 * - Strict Ed25519 verification via `node:crypto` rejecting all 8 torsion weak keys & `S >= L`
 * - `ActaClient` + `ActaGeminiGuard` pre-prompt circuit-breakers for `@google/genai`
 */

import * as nodeCrypto from "node:crypto";

export const DEFAULT_CLOUDRUN_URL = "https://acta-server-998422936041.us-west1.run.app";
export const TENANT_TOKEN_PREFIX = "acta_tk_v1:";
export const DEFAULT_MIN_CONFIDENCE = 0.7;
export const DEFAULT_DECISIVENESS_THRESHOLD = 0.15;
export const DEFAULT_CORROBORATION_DAMPING = 0.5;
export const SCHEMA_VERSION = "acta-context-bundle/v1";
export const STATE_REBUILD_ARCHIVE_SCHEMA_V1 = "acta-state-rebuild-archive/v1";

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

function asHash32(h) {
  const b = hexToBytes(h);
  if (b.length !== 32) throw new Error("expected 32-byte hash");
  return b;
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

export function encodeLengthDelimited(parts) {
  const chunks = [];
  for (const raw of parts) {
    const p = typeof raw === "string" ? utf8Encoder.encode(raw) : raw;
    chunks.push(Buffer.from(u64LeBytes(BigInt(p.byteLength))), Buffer.from(p));
  }
  return Uint8Array.from(Buffer.concat(chunks));
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

export function computeSourceContentCommitment(sourceDescriptor, sourceContent) {
  const contentBytes =
    typeof sourceContent === "string" ? utf8Encoder.encode(sourceContent) : sourceContent;
  return bytesToHex(
    hashLengthDelimited(["acta:source_content:v1", String(sourceDescriptor), contentBytes])
  );
}

function encodeOptUtf8(val) {
  if (val == null) return new Uint8Array([0]);
  const b = utf8Encoder.encode(String(val));
  const out = new Uint8Array(1 + b.length);
  out[0] = 1;
  out.set(b, 1);
  return out;
}

export function witnessRegistrationPreimageBytes(
  regDomain,
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  registeredBy = "",
  description = null
) {
  const pk = asHash32(publicKeyHexOrBytes);
  if (regDomain === "acta:witness_reg:v1") {
    return encodeLengthDelimited(["acta:witness_reg:v1", String(tenantId), String(witnessId), pk]);
  }
  if (regDomain === "acta:witness_reg:v2") {
    return encodeLengthDelimited([
      "acta:witness_reg:v2",
      String(tenantId),
      String(witnessId),
      pk,
      String(registeredBy),
    ]);
  }
  if (regDomain === "acta:witness_reg:v3") {
    return encodeLengthDelimited([
      "acta:witness_reg:v3",
      String(tenantId),
      String(witnessId),
      pk,
      String(registeredBy),
      encodeOptUtf8(description),
    ]);
  }
  throw new Error(`unsupported witness registration_domain: ${regDomain}`);
}

export function computeWitnessRegistrationCommitment(tenantId, witnessId, publicKeyHexOrBytes) {
  const pre = witnessRegistrationPreimageBytes("acta:witness_reg:v1", tenantId, witnessId, publicKeyHexOrBytes);
  return new Blake3Hasher().update(pre).hexdigest();
}

export function computeWitnessRegistrationV2Commitment(
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  registeredBy
) {
  const preimageBytes = witnessRegistrationPreimageBytes(
    "acta:witness_reg:v2",
    tenantId,
    witnessId,
    publicKeyHexOrBytes,
    registeredBy
  );
  return {
    preimageHex: bytesToHex(preimageBytes),
    commitmentHex: new Blake3Hasher().update(preimageBytes).hexdigest(),
  };
}

export function computeWitnessRegistrationV3Commitment(
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  registeredBy,
  description = null
) {
  const preimageBytes = witnessRegistrationPreimageBytes(
    "acta:witness_reg:v3",
    tenantId,
    witnessId,
    publicKeyHexOrBytes,
    registeredBy,
    description
  );
  return {
    preimageHex: bytesToHex(preimageBytes),
    commitmentHex: new Blake3Hasher().update(preimageBytes).hexdigest(),
  };
}

export function witnessRevocationPreimageBytes(
  revokeDomain,
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  revokedBy,
  reason,
  revocationMode = "compromise",
  effectiveFromTreeSize = null
) {
  const pk = asHash32(publicKeyHexOrBytes);
  if (revokeDomain === "acta:witness_revoke:v1") {
    return encodeLengthDelimited([
      "acta:witness_revoke:v1",
      String(tenantId),
      String(witnessId),
      pk,
      String(revokedBy),
      String(reason),
    ]);
  }
  if (revokeDomain === "acta:witness_revoke:v2") {
    const modeStr = String(revocationMode || "compromise");
    if (modeStr === "compromise") {
      if (effectiveFromTreeSize != null) {
        throw new Error("acta:witness_revoke:v2 mode='compromise' must have effective_from_tree_size=null");
      }
    } else if (modeStr === "retire") {
      if (effectiveFromTreeSize == null || BigInt(effectiveFromTreeSize) < 1n) {
        throw new Error("acta:witness_revoke:v2 mode='retire' requires effective_from_tree_size >= 1");
      }
    } else {
      throw new Error(`unsupported witness revocation_mode '${modeStr}' (expected 'compromise' or 'retire')`);
    }
    return encodeLengthDelimited([
      "acta:witness_revoke:v2",
      String(tenantId),
      String(witnessId),
      pk,
      String(revokedBy),
      modeStr,
      encodeOptI64(effectiveFromTreeSize != null ? BigInt(effectiveFromTreeSize) : null),
      String(reason),
    ]);
  }
  throw new Error(`unsupported witness revocation_domain: ${revokeDomain}`);
}

export function computeWitnessRevocationCommitment(
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  revokedBy,
  reason
) {
  const preimageBytes = witnessRevocationPreimageBytes(
    "acta:witness_revoke:v1",
    tenantId,
    witnessId,
    publicKeyHexOrBytes,
    revokedBy,
    reason
  );
  return {
    preimageHex: bytesToHex(preimageBytes),
    commitmentHex: new Blake3Hasher().update(preimageBytes).hexdigest(),
  };
}

export function computeWitnessRevocationV2Commitment(
  tenantId,
  witnessId,
  publicKeyHexOrBytes,
  revokedBy,
  revocationMode,
  effectiveFromTreeSize,
  reason
) {
  const preimageBytes = witnessRevocationPreimageBytes(
    "acta:witness_revoke:v2",
    tenantId,
    witnessId,
    publicKeyHexOrBytes,
    revokedBy,
    reason,
    revocationMode,
    effectiveFromTreeSize
  );
  return {
    preimageHex: bytesToHex(preimageBytes),
    commitmentHex: new Blake3Hasher().update(preimageBytes).hexdigest(),
  };
}

export function blake3KeyedHash(key32, parts) {
  const hasher = new Blake3Hasher(key32);
  for (const raw of parts) {
    const p = typeof raw === "string" ? utf8Encoder.encode(raw) : raw;
    hasher.update(p);
  }
  return hasher.digest();
}

export function normalizeGithubSlug(raw) {
  const trimmed = String(raw || "").trim().replace(/^@+/, "").toLowerCase();
  let out = "";
  let prevDash = false;
  for (const ch of trimmed) {
    if ((ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9") || ch === "_" || ch === ".") {
      out += ch;
      prevDash = false;
    } else if (!prevDash) {
      out += "-";
      prevDash = true;
    }
  }
  const clean = out.replace(/^-+|-+$/g, "");
  if (!clean || clean.length > 100) {
    throw new Error("GitHub organization/user slug must be 1..100 valid characters");
  }
  return clean;
}

function validateTokenSegment(label, val) {
  const s = String(val || "");
  const b = utf8Encoder.encode(s);
  if (!s || b.length > 128) throw new Error(`${label} must be 1..128 bytes`);
  if (/[\s:\x00-\x1f\x7f]/.test(s)) {
    throw new Error(`${label} cannot contain whitespace, control characters, or ':'`);
  }
}

export function deriveTenantMacKey(masterApiKey) {
  return hashLengthDelimited(["acta:tenant_mac_key:v1", String(masterApiKey).trim()]);
}

function lengthDelimitedParts(parts) {
  const out = [];
  for (const raw of parts) {
    const p = typeof raw === "string" ? utf8Encoder.encode(raw) : raw;
    out.push(u64LeBytes(BigInt(p.length)), p);
  }
  return out;
}

export function mintTenantApiKey(masterApiKey, tenantId) {
  const masterClean = String(masterApiKey || "").trim();
  if (!masterClean) throw new Error("masterApiKey must be non-empty");
  const tenantClean = String(tenantId || "").trim();
  validateTokenSegment("tenantId", tenantClean);
  const key32 = deriveTenantMacKey(masterClean);
  const mac = blake3KeyedHash(key32, lengthDelimitedParts(["acta:tenant_token:v1", tenantClean]));
  return `${TENANT_TOKEN_PREFIX}${tenantClean}:${bytesToHex(mac)}`;
}

export function mintUserTenantApiKey(masterApiKey, tenantId, githubLogin) {
  const masterClean = String(masterApiKey || "").trim();
  if (!masterClean) throw new Error("masterApiKey must be non-empty");
  const tenantClean = String(tenantId || "").trim();
  const userClean = normalizeGithubSlug(githubLogin);
  validateTokenSegment("tenantId", tenantClean);
  validateTokenSegment("githubLogin", userClean);
  const key32 = deriveTenantMacKey(masterClean);
  const mac = blake3KeyedHash(
    key32,
    lengthDelimitedParts(["acta:tenant_user_token:v2", tenantClean, userClean])
  );
  return `${TENANT_TOKEN_PREFIX}${tenantClean}:${userClean}:${bytesToHex(mac)}`;
}

function parseActaTkSegments(token) {
  if (!token) return null;
  const clean = String(token).trim();
  if (!clean.startsWith(TENANT_TOKEN_PREFIX)) return null;
  const rest = clean.slice(TENANT_TOKEN_PREFIX.length);
  const parts = rest.split(":");
  let tenantPart;
  let userPart = null;
  let macHex;
  if (parts.length === 2) {
    [tenantPart, macHex] = parts;
    validateTokenSegment("tenantId", tenantPart);
  } else if (parts.length === 3) {
    [tenantPart, userPart, macHex] = parts;
    validateTokenSegment("tenantId", tenantPart);
    validateTokenSegment("githubLogin", userPart);
  } else {
    throw new Error("malformed acta_tk_v1 token");
  }
  if (!/^[0-9a-fA-F]{64}$/.test(macHex)) throw new Error("malformed acta_tk_v1 MAC");
  return { tenantPart, userPart, macHex };
}

export function extractTokenTenant(token) {
  const parsed = parseActaTkSegments(token);
  return parsed ? parsed.tenantPart : null;
}

export function extractTokenPrincipal(token) {
  const parsed = parseActaTkSegments(token);
  return parsed ? parsed.userPart : null;
}

export function verifyTenantApiKeyWithPrincipal(masterApiKey, token) {
  const parsed = parseActaTkSegments(token);
  if (!parsed) throw new Error("token does not start with acta_tk_v1:");
  const expectedStr = parsed.userPart
    ? mintUserTenantApiKey(masterApiKey, parsed.tenantPart, parsed.userPart)
    : mintTenantApiKey(masterApiKey, parsed.tenantPart);
  const expected = Buffer.from(expectedStr, "utf8");
  const provided = Buffer.from(String(token).trim().toLowerCase(), "utf8");
  const providedRaw = Buffer.from(String(token).trim(), "utf8");
  const okLower = expected.length === provided.length && nodeCrypto.timingSafeEqual(expected, provided);
  const okRaw = expected.length === providedRaw.length && nodeCrypto.timingSafeEqual(expected, providedRaw);
  if (!okLower && !okRaw) {
    throw new Error("invalid or forged tenant-bound API key MAC");
  }
  return { tenantId: parsed.tenantPart, principal: parsed.userPart };
}

export function verifyTenantApiKey(masterApiKey, token) {
  return verifyTenantApiKeyWithPrincipal(masterApiKey, token).tenantId;
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
    const b = asHash32(h);
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
    out.scope_state_commitment = bytesToHex(asHash32(meta.scope_state_commitment)).toLowerCase();
  }
  if (meta.attempted_checkpoint_hash != null) {
    out.attempted_checkpoint_hash = bytesToHex(asHash32(meta.attempted_checkpoint_hash)).toLowerCase();
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

export function objectContentPreimageBytes(obj) {
  return encodeLengthDelimited([
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
  ]);
}

export function computeObjectContentHash(obj) {
  return new Blake3Hasher().update(objectContentPreimageBytes(obj)).hexdigest();
}

export function claimGroupPreimageBytes(claim) {
  const v2Pre = encodeLengthDelimited([
    "acta:claim_group:v2",
    String(claim.tenant_id),
    String(claim.subject),
    String(claim.predicate),
    String(claim.scope),
  ]);
  const v2Hex = new Blake3Hasher().update(v2Pre).hexdigest();
  if (v2Hex === bytesToHex(asHash32(claim.claim_group_key)).toLowerCase()) {
    return { domain: "acta:claim_group:v2", preimageBytes: v2Pre };
  }
  const v1Pre = encodeLengthDelimited([
    String(claim.tenant_id),
    String(claim.subject),
    String(claim.predicate),
    String(claim.object_type),
    String(claim.scope),
  ]);
  return { domain: "legacy_v1_unprefixed", preimageBytes: v1Pre };
}

export function claimContentPreimageBytes(claim) {
  const sortedContradictions = [...(claim.contradiction_ids || [])]
    .map((u) => normalizeUuidString(u))
    .sort();
  return encodeLengthDelimited([
    "acta:claim:v1",
    uuidToBytes(claim.id),
    String(claim.tenant_id),
    asHash32(claim.claim_group_key),
    String(claim.scope),
    String(claim.subject),
    String(claim.predicate),
    toCanonicalBytes(claim.object_val),
    String(claim.object_type),
    f64LeBytes(claim.confidence),
    i32LeBytes(claim.source_provenance_class),
    String(claim.source_descriptor),
    asHash32(claim.source_commitment),
    String(claim.status),
    toCanonicalBytes(sortedContradictions),
    encodeOptI64(claim.valid_from != null ? parseRfc3339Micros(claim.valid_from) : null),
    encodeOptI64(claim.valid_to != null ? parseRfc3339Micros(claim.valid_to) : null),
    i32LeBytes(claim.version),
    encodeOptUuid(claim.predecessor_id ?? null),
    i64LeBytes(parseRfc3339Micros(claim.created_at)),
  ]);
}

export function computeClaimContentHash(claim) {
  return new Blake3Hasher().update(claimContentPreimageBytes(claim)).hexdigest();
}

export function objectClientIntentPreimageBytes({
  tenantId,
  objType,
  scope,
  lifecycleStatus = "active",
  priority = 0,
  importance = 0.5,
  tags = [],
  body,
  predecessorId = null,
}) {
  return encodeLengthDelimited([
    "acta:object_client_sig:v1",
    String(tenantId),
    String(objType),
    String(scope),
    String(lifecycleStatus),
    i32LeBytes(priority),
    f32LeBytes(importance),
    toCanonicalBytes(tags || []),
    toCanonicalBytes(body),
    encodeOptUuid(predecessorId ?? null),
  ]);
}

export function computeObjectClientIntentHash(params) {
  return new Blake3Hasher().update(objectClientIntentPreimageBytes(params)).hexdigest();
}

export function signObjectClientIntent(seedHexOrBytes, params) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digestHex = computeObjectClientIntentHash(params);
  const sigHex = bytesToHex(nodeCrypto.sign(null, Buffer.from(hexToBytes(digestHex)), privKey));
  return { clientSignatureHex: sigHex, clientPublicKeyHex: deriveEd25519PublicKeyHex(seed) };
}

export function claimClientIntentPreimageBytes({
  tenantId,
  scope,
  subject,
  predicate,
  objectVal,
  objectType,
  confidence,
  sourceProvenanceClass = 2,
  sourceDescriptor,
  sourceCommitment,
  status = "active",
  contradictionIds = [],
  validFrom = null,
  validTo = null,
  predecessorId = null,
}) {
  const sortedContradictions = [...(contradictionIds || [])]
    .map((u) => normalizeUuidString(u))
    .sort();
  return encodeLengthDelimited([
    "acta:claim_client_sig:v1",
    String(tenantId),
    String(scope),
    String(subject),
    String(predicate),
    toCanonicalBytes(objectVal),
    String(objectType),
    f64LeBytes(confidence),
    i32LeBytes(sourceProvenanceClass),
    String(sourceDescriptor),
    asHash32(sourceCommitment),
    String(status),
    toCanonicalBytes(sortedContradictions),
    encodeOptI64(validFrom != null ? parseRfc3339Micros(validFrom) : null),
    encodeOptI64(validTo != null ? parseRfc3339Micros(validTo) : null),
    encodeOptUuid(predecessorId ?? null),
  ]);
}

export function computeClaimClientIntentHash(params) {
  return new Blake3Hasher().update(claimClientIntentPreimageBytes(params)).hexdigest();
}

export function signClaimClientIntent(seedHexOrBytes, params) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  let srcComm = params.sourceCommitment;
  if (!srcComm) {
    srcComm =
      params.sourceContent != null
        ? computeSourceContentCommitment(params.sourceDescriptor, params.sourceContent)
        : bytesToHex(hashLengthDelimited(["acta:source:v1", String(params.sourceDescriptor)]));
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digestHex = computeClaimClientIntentHash({ ...params, sourceCommitment: srcComm });
  const sigHex = bytesToHex(nodeCrypto.sign(null, Buffer.from(hexToBytes(digestHex)), privKey));
  return { clientSignatureHex: sigHex, clientPublicKeyHex: deriveEd25519PublicKeyHex(seed) };
}

export function computeRetractClaimClientIntentHash({ tenantId, claimId, reason }) {
  return bytesToHex(
    hashLengthDelimited([
      "acta:retract_client_sig:v1",
      String(tenantId),
      uuidToBytes(claimId),
      String(reason),
    ])
  );
}

export function signRetractClaimClientIntent(seedHexOrBytes, { tenantId, claimId, reason }) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digestHex = computeRetractClaimClientIntentHash({ tenantId, claimId, reason });
  const sigHex = bytesToHex(nodeCrypto.sign(null, Buffer.from(hexToBytes(digestHex)), privKey));
  return { clientSignatureHex: sigHex, clientPublicKeyHex: deriveEd25519PublicKeyHex(seed) };
}

export function computeSubCommitment(hashes) {
  const rawList = (hashes || []).map((h) => Buffer.from(asHash32(h)));
  rawList.sort(Buffer.compare);
  return bytesToHex(hashLengthDelimited(rawList));
}

export function computeStateCommitment({
  schemaVersion = SCHEMA_VERSION,
  tenantId,
  scope,
  intentRoot,
  knowledgeRoot,
  memoryRoot,
  permissionRoot,
}) {
  return bytesToHex(
    hashLengthDelimited([
      String(schemaVersion),
      String(tenantId),
      String(scope),
      asHash32(intentRoot),
      asHash32(knowledgeRoot),
      asHash32(memoryRoot),
      asHash32(permissionRoot),
    ])
  );
}

export function computeTaskDependencyCommitment({
  tenantId,
  scope,
  permissionRoot,
  intentRoot,
  selectedMemoryRoot,
  relevantKnowledgeRoot,
}) {
  return bytesToHex(
    hashLengthDelimited([
      "acta:cache_dep_root:v1",
      String(tenantId),
      String(scope),
      asHash32(permissionRoot),
      asHash32(intentRoot),
      asHash32(selectedMemoryRoot),
      asHash32(relevantKnowledgeRoot),
    ])
  );
}

export function computeQueryTextHash(queryText) {
  return bytesToHex(hashLengthDelimited(["acta:query:v1", String(queryText ?? "")]));
}

export function computeAnswerTextHash(answerText) {
  return bytesToHex(hashLengthDelimited(["acta:answer:v1", String(answerText)]));
}

export function computeAnswerCacheClientIntentHash({
  tenantId,
  scope,
  taskId,
  queryHash,
  sourceBundleHash,
  stateCommitment,
  answerHash,
}) {
  return bytesToHex(
    hashLengthDelimited([
      "acta:answer_client_sig:v1",
      String(tenantId),
      String(scope),
      String(taskId),
      asHash32(queryHash),
      asHash32(sourceBundleHash),
      asHash32(stateCommitment),
      asHash32(answerHash),
    ])
  );
}

function normalizeWriteSummary(ws) {
  const out = {
    write_domain: String(ws.write_domain || "acta:write_event:v1"),
    operation: String(ws.operation),
    item_id: normalizeUuidString(ws.item_id),
    scope: String(ws.scope),
    version: Number(ws.version),
    content_hash: bytesToHex(asHash32(ws.content_hash)).toLowerCase(),
    written_by: String(ws.written_by),
    writer_auth_kind: String(ws.writer_auth_kind),
    record_snapshot: ws.record_snapshot,
  };
  if (ws.predecessor_id != null) out.predecessor_id = normalizeUuidString(ws.predecessor_id);
  if (ws.client_public_key != null) {
    out.client_public_key = bytesToHex(asHash32(ws.client_public_key)).toLowerCase();
  }
  if (ws.client_signature != null) {
    out.client_signature = bytesToHex(hexToBytes(ws.client_signature)).toLowerCase();
  }
  if (ws.retraction_reason != null) out.retraction_reason = String(ws.retraction_reason);
  return out;
}

export function computeWriteSummaryCommitment(ws) {
  return bytesToHex(
    hashLengthDelimited(["acta:write_event:v1", toCanonicalBytes(normalizeWriteSummary(ws))])
  );
}

function normalizeAnswerCacheSummary(acs) {
  const out = {
    cache_domain: String(acs.cache_domain || "acta:answer_cache:v1"),
    cache_id: normalizeUuidString(acs.cache_id),
    scope: String(acs.scope),
    task_id: String(acs.task_id),
    query_hash: bytesToHex(asHash32(acs.query_hash)).toLowerCase(),
    source_bundle_hash: bytesToHex(asHash32(acs.source_bundle_hash)).toLowerCase(),
    state_commitment: bytesToHex(asHash32(acs.state_commitment)).toLowerCase(),
    answer_hash: bytesToHex(asHash32(acs.answer_hash)).toLowerCase(),
    cached_by: String(acs.cached_by),
    cacher_auth_kind: String(acs.cacher_auth_kind),
  };
  if (acs.event_kind != null) out.event_kind = String(acs.event_kind);
  if (acs.validity_mode != null) out.validity_mode = String(acs.validity_mode);
  if (acs.task_dependency_commitment != null) {
    out.task_dependency_commitment = bytesToHex(asHash32(acs.task_dependency_commitment)).toLowerCase();
  }
  if (acs.client_public_key != null) {
    out.client_public_key = bytesToHex(asHash32(acs.client_public_key)).toLowerCase();
  }
  if (acs.client_signature != null) {
    out.client_signature = bytesToHex(hexToBytes(acs.client_signature)).toLowerCase();
  }
  if (acs.expires_at != null) out.expires_at = String(acs.expires_at);
  if (acs.invalidation_reason != null) out.invalidation_reason = String(acs.invalidation_reason);
  if (acs.observed_state_commitment != null) {
    out.observed_state_commitment = bytesToHex(asHash32(acs.observed_state_commitment)).toLowerCase();
  }
  if (acs.observed_dependency_commitment != null) {
    out.observed_dependency_commitment = bytesToHex(
      asHash32(acs.observed_dependency_commitment)
    ).toLowerCase();
  }
  return out;
}

export function computeAnswerCacheSummaryCommitment(acs) {
  return bytesToHex(
    hashLengthDelimited(["acta:answer_cache:v1", toCanonicalBytes(normalizeAnswerCacheSummary(acs))])
  );
}

export function answerCacheSigningPreimage(tenantId, evidenceSeqNum, cacheCommitment) {
  return hashLengthDelimited([
    "acta:answer_cache_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(evidenceSeqNum)),
    asHash32(cacheCommitment),
  ]);
}

export function verifyAnswerCacheSignature(
  pubkeyHexOrBytes,
  tenantId,
  evidenceSeqNum,
  cacheCommitment,
  sigHexOrBytes
) {
  const digest = answerCacheSigningPreimage(tenantId, evidenceSeqNum, cacheCommitment);
  return verifyEd25519Strict(pubkeyHexOrBytes, digest, sigHexOrBytes);
}

function verifyAuthKindAndSigPresence(label, authKind, hasSig, hasPk, ErrCls) {
  if (hasSig !== hasPk) {
    throw new ErrCls(`${label} inconsistent client_signature / client_public_key presence`);
  }
  if (authKind === "ed25519_client_sig") {
    if (!hasSig) {
      throw new ErrCls(`${label} auth_kind='ed25519_client_sig' requires client_signature + client_public_key`);
    }
  } else if (
    authKind === "oauth_github_principal" ||
    authKind === "tenant_session" ||
    authKind === "master_admin"
  ) {
    if (hasSig) {
      throw new ErrCls(`${label} auth_kind='${authKind}' cannot coexist with client_signature`);
    }
  } else {
    throw new ErrCls(`${label} unsupported auth_kind '${authKind}'`);
  }
}

function verifyObjectAuthorSig(obj, label, ErrCls) {
  const csig = obj.client_signature ?? null;
  const cpk = obj.client_public_key ?? null;
  if (csig == null && cpk == null) return;
  if (csig == null && cpk != null) {
    throw new ErrCls(`${label} has client_public_key without client_signature`);
  }
  if (csig != null && cpk != null) {
    const intentHex = computeObjectClientIntentHash({
      tenantId: obj.tenant_id,
      objType: obj.obj_type,
      scope: obj.scope,
      lifecycleStatus: obj.lifecycle_status,
      priority: obj.priority,
      importance: obj.importance,
      tags: obj.tags || [],
      body: obj.body,
      predecessorId: obj.predecessor_id ?? null,
    });
    const okIntent = verifyEd25519Strict(cpk, hexToBytes(intentHex), csig);
    const okFull = verifyEd25519Strict(cpk, asHash32(obj.content_hash), csig);
    if (!okIntent && !okFull) {
      throw new ErrCls(`client Ed25519 signature verification failed on ${label}`);
    }
  }
}

function verifyClaimAuthorSig(claim, retractionReason, label, ErrCls) {
  const csig = claim.client_signature ?? null;
  const cpk = claim.client_public_key ?? null;
  if (csig == null && cpk == null) return;
  if ((csig != null) !== (cpk != null)) {
    throw new ErrCls(`${label} inconsistent client_signature / client_public_key presence`);
  }
  const intentHex = computeClaimClientIntentHash({
    tenantId: claim.tenant_id,
    scope: claim.scope,
    subject: claim.subject,
    predicate: claim.predicate,
    objectVal: claim.object_val,
    objectType: claim.object_type,
    confidence: claim.confidence,
    sourceProvenanceClass: claim.source_provenance_class,
    sourceDescriptor: claim.source_descriptor,
    sourceCommitment: claim.source_commitment,
    status: claim.status,
    contradictionIds: claim.contradiction_ids || [],
    validFrom: claim.valid_from ?? null,
    validTo: claim.valid_to ?? null,
    predecessorId: claim.predecessor_id ?? null,
  });
  const okIntent = verifyEd25519Strict(cpk, hexToBytes(intentHex), csig);
  const okFull = verifyEd25519Strict(cpk, asHash32(claim.content_hash), csig);
  const effReason = retractionReason ?? claim.retraction_reason ?? null;
  let okRetract = false;
  if (String(claim.status) === "revoked" && effReason != null && claim.predecessor_id != null) {
    const rHex = computeRetractClaimClientIntentHash({
      tenantId: claim.tenant_id,
      claimId: claim.predecessor_id,
      reason: effReason,
    });
    okRetract = verifyEd25519Strict(cpk, hexToBytes(rHex), csig);
  }
  if (!okIntent && !okFull && !okRetract) {
    throw new ErrCls(`client Ed25519 signature verification failed on ${label}`);
  }
}

export function computeOverrideClientIntentHash({
  tenantId,
  scope,
  winningClaimId,
  adjudicatorId,
  justification,
}) {
  const tClean = String(tenantId).trim();
  const adjClean = String(adjudicatorId).trim();
  const effActor = adjClean.includes("::") ? adjClean : `${tClean}::${adjClean}`;
  return bytesToHex(
    hashLengthDelimited([
      "acta:override_client_sig:v1",
      tClean,
      String(scope).trim(),
      uuidToBytes(winningClaimId),
      effActor,
      String(justification).trim(),
    ])
  );
}

export function signOverrideClientIntent(
  seedHexOrBytes,
  { tenantId, scope, winningClaimId, adjudicatorId, justification }
) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digestHex = computeOverrideClientIntentHash({
    tenantId,
    scope,
    winningClaimId,
    adjudicatorId,
    justification,
  });
  const sigHex = bytesToHex(nodeCrypto.sign(null, Buffer.from(hexToBytes(digestHex)), privKey));
  const pkHex = deriveEd25519PublicKeyHex(seed);
  return { clientSignatureHex: sigHex, clientPublicKeyHex: pkHex };
}

function effectiveOverrideDomain(att) {
  const d = String(att.attestation_domain || "").trim();
  return d ? d : "acta:override:v1";
}

function effectiveOverrideAuthKind(att) {
  const k = String(att.adjudicator_auth_kind || "").trim();
  if (k) return k;
  if (att.client_signature != null) return "ed25519_client_sig";
  const adj = String(att.adjudicator_id || "");
  if (adj.includes("::oauth:")) return "oauth_github_principal";
  if (adj.endsWith("::master-admin")) return "master_admin";
  return "tenant_session";
}

function encodeOptSig64(sig) {
  if (sig == null) return new Uint8Array([0]);
  const b = typeof sig === "string" ? hexToBytes(sig) : new Uint8Array(sig);
  if (b.length !== 64) throw new Error(`client_signature must be 64 bytes, got ${b.length}`);
  const out = new Uint8Array(65);
  out[0] = 1;
  out.set(b, 1);
  return out;
}

function overrideAttestationPreimageBytes(att) {
  const sortedOverridden = [...(att.overridden_claims || [])]
    .map((x) => {
      const id = normalizeUuidString(x.id);
      const chBytes = asHash32(x.content_hash);
      return { id, content_hash: bytesToHex(chBytes).toLowerCase() };
    })
    .sort((a, b) =>
      a.id < b.id ? -1 : a.id > b.id ? 1 : a.content_hash < b.content_hash ? -1 : a.content_hash > b.content_hash ? 1 : 0
    );

  const domain = effectiveOverrideDomain(att);
  if (domain === "acta:override:v1") {
    return encodeLengthDelimited([
      "acta:override:v1",
      uuidToBytes(att.id),
      String(att.tenant_id),
      String(att.scope),
      asHash32(att.claim_group_key),
      String(att.subject),
      String(att.predicate),
      encodeOptHash32(att.source_bundle_hash ?? null),
      uuidToBytes(att.winning_claim_id),
      asHash32(att.winning_claim_content_hash),
      toCanonicalBytes(sortedOverridden),
      String(att.adjudicator_id),
      String(att.justification),
      i32LeBytes(att.version),
      encodeOptUuid(att.predecessor_id ?? null),
      i64LeBytes(parseRfc3339Micros(att.created_at)),
    ]);
  }
  if (domain === "acta:override:v2") {
    return encodeLengthDelimited([
      "acta:override:v2",
      uuidToBytes(att.id),
      String(att.tenant_id),
      String(att.scope),
      asHash32(att.claim_group_key),
      String(att.subject),
      String(att.predicate),
      encodeOptHash32(att.source_bundle_hash ?? null),
      uuidToBytes(att.winning_claim_id),
      asHash32(att.winning_claim_content_hash),
      toCanonicalBytes(sortedOverridden),
      String(att.adjudicator_id),
      effectiveOverrideAuthKind(att),
      String(att.justification),
      i32LeBytes(att.version),
      encodeOptUuid(att.predecessor_id ?? null),
      i64LeBytes(parseRfc3339Micros(att.created_at)),
      encodeOptHash32(att.client_public_key ?? null),
      encodeOptSig64(att.client_signature ?? null),
    ]);
  }
  throw new Error(`unsupported override attestation_domain: ${domain}`);
}

export function computeOverrideAttestationHash(att) {
  return new Blake3Hasher().update(overrideAttestationPreimageBytes(att)).hexdigest();
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
  writeSummary = null,
  answerCacheSummary = null,
}) {
  const micros = typeof createdAt === "bigint" ? createdAt : parseRfc3339Micros(createdAt);
  if (writeSummary != null || answerCacheSummary != null) {
    const writeTagged = encodeOptJcs(writeSummary != null ? normalizeWriteSummary(writeSummary) : null);
    const cacheTagged = encodeOptJcs(
      answerCacheSummary != null ? normalizeAnswerCacheSummary(answerCacheSummary) : null
    );
    return bytesToHex(
      hashLengthDelimited([
        "acta:evidence_event:v3",
        String(tenantId),
        i64LeBytes(BigInt(seqNum)),
        asHash32(prevHash),
        encodeOptHash32(bundleHash),
        encodeOptHash32(stateCommitment),
        String(policyResult),
        i64LeBytes(micros),
        writeTagged,
        cacheTagged,
      ])
    );
  }
  if (refusalMetadata == null && overrideSummary == null) {
    return bytesToHex(
      hashLengthDelimited([
        "acta:evidence_event:v1",
        String(tenantId),
        i64LeBytes(BigInt(seqNum)),
        asHash32(prevHash),
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
      asHash32(prevHash),
      encodeOptHash32(bundleHash),
      encodeOptHash32(stateCommitment),
      String(policyResult),
      i64LeBytes(micros),
      refusalTagged,
      overrideTagged,
    ])
  );
}

// ============================================================================
// Acta v1.6 RFC 6962 Binary Merkle Tree, Checkpoints & Witness Cosignatures
// ============================================================================
export function legacyBlake3MerkleEmptyRoot() {
  return bytesToHex(hashLengthDelimited(["acta:merkle_empty:v1"]));
}

export function legacyBlake3MerkleLeafHash(seqNum, eventHash) {
  return bytesToHex(
    hashLengthDelimited(["acta:merkle_leaf:v1", i64LeBytes(BigInt(seqNum)), asHash32(eventHash)])
  );
}

export function legacyBlake3MerkleNodeHash(left, right) {
  return bytesToHex(hashLengthDelimited(["acta:merkle_node:v1", asHash32(left), asHash32(right)]));
}

export function computeLegacyBlake3MerkleRootFromLeaves(leaves) {
  const n = leaves.length;
  if (n === 0) return legacyBlake3MerkleEmptyRoot();
  if (n === 1) return bytesToHex(asHash32(leaves[0])).toLowerCase();
  const k = largestPow2Lt(n);
  const left = computeLegacyBlake3MerkleRootFromLeaves(leaves.slice(0, k));
  const right = computeLegacyBlake3MerkleRootFromLeaves(leaves.slice(k));
  return legacyBlake3MerkleNodeHash(left, right);
}

export function computeLegacyBlake3MerkleRootFromEvents(events) {
  const leaves = events.map(([seq, ev]) => legacyBlake3MerkleLeafHash(seq, ev));
  return computeLegacyBlake3MerkleRootFromLeaves(leaves);
}

export function merkleEmptyRoot() {
  return nodeCrypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
}

export function merkleLeafHash(_seqNum, eventHash) {
  return nodeCrypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(asHash32(eventHash))]))
    .digest("hex");
}

export function merkleNodeHash(left, right) {
  return nodeCrypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(asHash32(left)),
        Buffer.from(asHash32(right)),
      ])
    )
    .digest("hex");
}

function largestPow2Lt(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function computeMerkleRootFromLeaves(leaves) {
  const n = leaves.length;
  if (n === 0) return merkleEmptyRoot();
  if (n === 1) return bytesToHex(asHash32(leaves[0])).toLowerCase();
  const k = largestPow2Lt(n);
  const left = computeMerkleRootFromLeaves(leaves.slice(0, k));
  const right = computeMerkleRootFromLeaves(leaves.slice(k));
  return merkleNodeHash(left, right);
}

function inclusionPathSlice(leaves, index, out) {
  const n = leaves.length;
  if (n <= 1) return;
  const k = largestPow2Lt(n);
  if (index < k) {
    inclusionPathSlice(leaves.slice(0, k), index, out);
    out.push(computeMerkleRootFromLeaves(leaves.slice(k)));
  } else {
    inclusionPathSlice(leaves.slice(k), index - k, out);
    out.push(computeMerkleRootFromLeaves(leaves.slice(0, k)));
  }
}

export function computeMerkleInclusionProof(leaves, leafIndex) {
  if (!leaves.length || leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error(`leafIndex ${leafIndex} out of bounds for tree_size ${leaves.length}`);
  }
  const out = [];
  inclusionPathSlice(leaves, leafIndex, out);
  return out;
}

export function verifyMerkleInclusionProof(seqNum, eventHash, treeSize, auditPath, expectedRoot) {
  const seq = BigInt(seqNum);
  const size = BigInt(treeSize);
  if (seq < 1n || size < 1n || seq > size) return false;
  let r = merkleLeafHash(seq, eventHash);
  const expHex = bytesToHex(asHash32(expectedRoot)).toLowerCase();
  if (size === 1n) {
    return auditPath.length === 0 && r === expHex;
  }
  let fnIdx = seq - 1n;
  let sn = size - 1n;
  for (const sib of auditPath) {
    if (sn === 0n) return false;
    const sibBytes = asHash32(sib);
    if ((fnIdx & 1n) === 1n || fnIdx === sn) {
      r = merkleNodeHash(sibBytes, r);
      while ((fnIdx & 1n) === 0n) {
        fnIdx >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = merkleNodeHash(r, sibBytes);
    }
    fnIdx >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && r === expHex;
}

function subproofSlice(m, leaves, isCompleteSubtree, out) {
  const n = leaves.length;
  if (m === n) {
    if (!isCompleteSubtree) out.push(computeMerkleRootFromLeaves(leaves));
    return;
  }
  const k = largestPow2Lt(n);
  if (m <= k) {
    subproofSlice(m, leaves.slice(0, k), isCompleteSubtree, out);
    out.push(computeMerkleRootFromLeaves(leaves.slice(k)));
  } else {
    subproofSlice(m - k, leaves.slice(k), false, out);
    out.push(computeMerkleRootFromLeaves(leaves.slice(0, k)));
  }
}

export function computeMerkleConsistencyProof(leaves, firstSize, secondSize) {
  if (firstSize < 1 || firstSize > secondSize || secondSize > leaves.length) {
    throw new Error(`invalid consistency proof bounds: first=${firstSize}, second=${secondSize}`);
  }
  if (firstSize === secondSize) return [];
  const out = [];
  subproofSlice(firstSize, leaves.slice(0, secondSize), true, out);
  return out;
}

export function verifyMerkleConsistencyProof(firstSize, firstRoot, secondSize, secondRoot, proof) {
  const fSize = BigInt(firstSize);
  const sSize = BigInt(secondSize);
  if (fSize < 1n || sSize < fSize) return false;
  const fHex = bytesToHex(asHash32(firstRoot)).toLowerCase();
  const sHex = bytesToHex(asHash32(secondRoot)).toLowerCase();
  if (fSize === sSize) return proof.length === 0 && fHex === sHex;
  if (!proof || proof.length === 0) return false;

  const isPow2 = (fSize & (fSize - 1n)) === 0n;
  const chain = isPow2 ? [fHex, ...proof] : [...proof];

  let fnIdx = fSize - 1n;
  let sn = sSize - 1n;
  while ((fnIdx & 1n) === 1n) {
    fnIdx >>= 1n;
    sn >>= 1n;
  }

  let fr = bytesToHex(asHash32(chain[0])).toLowerCase();
  let sr = fr;
  for (let i = 1; i < chain.length; i++) {
    if (sn === 0n) return false;
    const nodeBytes = asHash32(chain[i]);
    if ((fnIdx & 1n) === 1n || fnIdx === sn) {
      fr = merkleNodeHash(nodeBytes, fr);
      sr = merkleNodeHash(nodeBytes, sr);
      while ((fnIdx & 1n) === 0n) {
        fnIdx >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = merkleNodeHash(sr, nodeBytes);
    }
    fnIdx >>= 1n;
    sn >>= 1n;
  }

  return sn === 0n && fr === fHex && sr === sHex;
}

export function computeCheckpointHash({
  tenantId,
  treeSize,
  headEventHash,
  merkleRoot,
  issuedAt,
}) {
  const micros = typeof issuedAt === "bigint" ? issuedAt : parseRfc3339Micros(issuedAt);
  return bytesToHex(
    hashLengthDelimited([
      "acta:checkpoint:v1",
      String(tenantId),
      i64LeBytes(BigInt(treeSize)),
      asHash32(headEventHash),
      asHash32(merkleRoot),
      i64LeBytes(micros),
    ])
  );
}

export function evidenceSigningPreimage(tenantId, seqNum, prevHash, eventHash) {
  return hashLengthDelimited([
    "acta:evidence_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(seqNum)),
    asHash32(prevHash),
    asHash32(eventHash),
  ]);
}

export function overrideSigningPreimage(tenantId, evidenceSeqNum, attestationHash) {
  return hashLengthDelimited([
    "acta:override_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(evidenceSeqNum)),
    asHash32(attestationHash),
  ]);
}

export function checkpointSigningPreimage(tenantId, checkpointHash) {
  return hashLengthDelimited([
    "acta:checkpoint_sig:v1",
    String(tenantId),
    asHash32(checkpointHash),
  ]);
}

export function witnessAnchorSigningPreimage(tenantId, treeSize, checkpointHash) {
  return hashLengthDelimited([
    "acta:witness_sig:v1",
    String(tenantId),
    i64LeBytes(BigInt(treeSize)),
    asHash32(checkpointHash),
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

export function signCheckpointHead(seedHexOrBytes, tenantId, checkpointHash) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digest = checkpointSigningPreimage(tenantId, checkpointHash);
  return bytesToHex(nodeCrypto.sign(null, Buffer.from(digest), privKey));
}

export function signWitnessAnchor(seedHexOrBytes, tenantId, treeSize, checkpointHash) {
  const seed = hexToBytes(seedHexOrBytes);
  if (seed.length !== 32) throw new Error("Ed25519 private seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const digest = witnessAnchorSigningPreimage(tenantId, treeSize, checkpointHash);
  const sigHex = bytesToHex(nodeCrypto.sign(null, Buffer.from(digest), privKey));
  const pkHex = deriveEd25519PublicKeyHex(seed);
  return { witnessSignatureHex: sigHex, witnessPublicKeyHex: pkHex };
}

export function verifyOverrideSignature(pubkeyHexOrBytes, tenantId, evidenceSeqNum, attestationHash, sigHexOrBytes) {
  const digest = overrideSigningPreimage(tenantId, evidenceSeqNum, attestationHash);
  return verifyEd25519Strict(pubkeyHexOrBytes, digest, sigHexOrBytes);
}

export function verifyCheckpointSignature(pubkeyHexOrBytes, tenantId, checkpointHash, sigHexOrBytes) {
  const digest = checkpointSigningPreimage(tenantId, checkpointHash);
  return verifyEd25519Strict(pubkeyHexOrBytes, digest, sigHexOrBytes);
}

export function verifyWitnessAnchorSignature(witnessPubkeyHexOrBytes, tenantId, treeSize, checkpointHash, sigHexOrBytes) {
  const digest = witnessAnchorSigningPreimage(tenantId, treeSize, checkpointHash);
  return verifyEd25519Strict(witnessPubkeyHexOrBytes, digest, sigHexOrBytes);
}

export function verifySignedTreeHead(sth, expectedTenant, expectedPubkeyHex) {
  if (String(sth.tenant_id) !== String(expectedTenant)) {
    throw new ActaVerificationError(`checkpoint tenant_id '${sth.tenant_id}' != expected '${expectedTenant}'`);
  }
  const treeSize = Number(sth.tree_size);
  if (!Number.isInteger(treeSize) || treeSize < 1) {
    throw new ActaVerificationError(`invalid checkpoint tree_size=${sth.tree_size}`);
  }
  const recomputedCp = computeCheckpointHash({
    tenantId: sth.tenant_id,
    treeSize,
    headEventHash: sth.head_event_hash,
    merkleRoot: sth.merkle_root,
    issuedAt: sth.issued_at,
  });
  const storedCp = String(sth.checkpoint_hash).toLowerCase();
  if (recomputedCp !== storedCp) {
    throw new ActaVerificationError(
      `tampered SignedTreeHead: recomputed checkpoint_hash ${recomputedCp} != stored ${storedCp}`
    );
  }
  if (!verifyCheckpointSignature(expectedPubkeyHex, sth.tenant_id, recomputedCp, sth.host_signature)) {
    throw new ActaVerificationError("Ed25519 host_signature verification failed on SignedTreeHead");
  }
  const anchors = sth.witness_anchors || [];
  for (const anchor of anchors) {
    if (
      String(anchor.tenant_id) !== String(sth.tenant_id) ||
      Number(anchor.tree_size) !== treeSize ||
      String(anchor.checkpoint_hash).toLowerCase() !== storedCp
    ) {
      throw new ActaVerificationError(`witness_anchor[id=${anchor.id}] metadata mismatch against SignedTreeHead`);
    }
    if (
      !verifyWitnessAnchorSignature(
        anchor.witness_public_key,
        anchor.tenant_id,
        treeSize,
        recomputedCp,
        anchor.witness_signature
      )
    ) {
      throw new ActaVerificationError(
        `Ed25519 witness_signature verification failed on witness_anchor[id=${anchor.id}]`
      );
    }
  }
  return anchors.length;
}

export function deriveEd25519PublicKeyHex(seedHexOrBytes) {
  const seed = hexToBytes(seedHexOrBytes);
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privKey = nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = nodeCrypto.createPublicKey(privKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(12, 44).toString("hex");
}

export function verifyEvidenceEntry(entry, expectedPubkeyHex) {
  const expectedEvDomain =
    entry.write_summary != null || entry.answer_cache_summary != null
      ? "acta:evidence_event:v3"
      : entry.refusal_metadata == null && entry.override_summary == null
      ? "acta:evidence_event:v1"
      : "acta:evidence_event:v2";
  if (entry.event_domain != null && String(entry.event_domain) !== expectedEvDomain) {
    throw new ActaSignatureVerificationError(
      `tampered event_domain at seq_num=${entry.seq_num}: declared '${entry.event_domain}' != expected '${expectedEvDomain}'`
    );
  }

  if (entry.write_summary != null) {
    const ws = entry.write_summary;
    if (
      entry.bundle_hash != null ||
      entry.refusal_metadata != null ||
      entry.override_summary != null ||
      entry.answer_cache_summary != null ||
      entry.witness_reg_summary != null ||
      entry.witness_revoke_summary != null
    ) {
      throw new ActaSignatureVerificationError(
        `invalid evidence entry at seq_num=${entry.seq_num}: write_summary cannot coexist with other entry payloads`
      );
    }
    if (String(ws.write_domain || "acta:write_event:v1") !== "acta:write_event:v1") {
      throw new ActaSignatureVerificationError(`unsupported write_domain at seq_num=${entry.seq_num}`);
    }
    const lbl = `write_summary[seq_num=${entry.seq_num}, item_id=${ws.item_id}]`;
    verifyAuthKindAndSigPresence(
      lbl,
      String(ws.writer_auth_kind || "").trim(),
      ws.client_signature != null,
      ws.client_public_key != null,
      ActaSignatureVerificationError
    );
    const snap = { ...ws.record_snapshot };
    if (ws.operation === "ingest_object") {
      if (
        String(snap.tenant_id) !== String(entry.tenant_id) ||
        normalizeUuidString(snap.id) !== normalizeUuidString(ws.item_id) ||
        String(snap.scope) !== String(ws.scope) ||
        Number(snap.version) !== Number(ws.version)
      ) {
        throw new ActaSignatureVerificationError(`${lbl} metadata mismatch against record_snapshot`);
      }
      const recH = computeObjectContentHash(snap);
      if (
        recH !== String(snap.content_hash).toLowerCase() ||
        recH !== String(ws.content_hash).toLowerCase()
      ) {
        throw new ActaSignatureVerificationError(`${lbl} tampered object record_snapshot content_hash`);
      }
      snap.client_signature = ws.client_signature ?? null;
      snap.client_public_key = ws.client_public_key ?? null;
      verifyObjectAuthorSig(snap, lbl, ActaSignatureVerificationError);
    } else if (ws.operation === "ingest_claim" || ws.operation === "retract_claim") {
      if (
        String(snap.tenant_id) !== String(entry.tenant_id) ||
        normalizeUuidString(snap.id) !== normalizeUuidString(ws.item_id) ||
        String(snap.scope) !== String(ws.scope) ||
        Number(snap.version) !== Number(ws.version)
      ) {
        throw new ActaSignatureVerificationError(`${lbl} metadata mismatch against record_snapshot`);
      }
      const recH = computeClaimContentHash(snap);
      if (
        recH !== String(snap.content_hash).toLowerCase() ||
        recH !== String(ws.content_hash).toLowerCase()
      ) {
        throw new ActaSignatureVerificationError(`${lbl} tampered claim record_snapshot content_hash`);
      }
      if (
        ws.operation === "retract_claim" &&
        (String(snap.status) !== "revoked" || ws.predecessor_id == null || !String(ws.retraction_reason || "").trim())
      ) {
        throw new ActaSignatureVerificationError(`${lbl} retract_claim missing revoked status/predecessor_id/retraction_reason`);
      }
      snap.client_signature = ws.client_signature ?? null;
      snap.client_public_key = ws.client_public_key ?? null;
      verifyClaimAuthorSig(snap, ws.retraction_reason ?? null, lbl, ActaSignatureVerificationError);
    } else {
      throw new ActaSignatureVerificationError(`${lbl} unsupported operation '${ws.operation}'`);
    }
    const expWComm = computeWriteSummaryCommitment(ws);
    if (!entry.state_commitment || String(entry.state_commitment).toLowerCase() !== expWComm) {
      throw new ActaSignatureVerificationError(
        `tampered write_summary at seq_num=${entry.seq_num}: state_commitment mismatch`
      );
    }
  }

  if (entry.answer_cache_summary != null) {
    const acs = entry.answer_cache_summary;
    if (
      entry.bundle_hash != null ||
      entry.refusal_metadata != null ||
      entry.override_summary != null ||
      entry.write_summary != null ||
      entry.witness_reg_summary != null ||
      entry.witness_revoke_summary != null
    ) {
      throw new ActaSignatureVerificationError(
        `invalid evidence entry at seq_num=${entry.seq_num}: answer_cache_summary cannot coexist with other entry payloads`
      );
    }
    if (String(acs.cache_domain || "acta:answer_cache:v1") !== "acta:answer_cache:v1") {
      throw new ActaSignatureVerificationError(`unsupported cache_domain at seq_num=${entry.seq_num}`);
    }
    const lbl = `answer_cache_summary[seq_num=${entry.seq_num}, cache_id=${acs.cache_id}]`;
    const evKind = acs.event_kind ?? null;
    if (evKind === null || evKind === "cached") {
      if (
        acs.invalidation_reason != null ||
        acs.observed_state_commitment != null ||
        acs.observed_dependency_commitment != null
      ) {
        throw new ActaSignatureVerificationError(
          `${lbl} cached event_kind cannot carry invalidation fields`
        );
      }
    } else if (evKind === "invalidated") {
      if (
        acs.invalidation_reason !== "stale_dependency_commitment" &&
        acs.invalidation_reason !== "stale_state_commitment" &&
        acs.invalidation_reason !== "expired_ttl"
      ) {
        throw new ActaSignatureVerificationError(
          `${lbl} invalidation event has unsupported invalidation_reason '${acs.invalidation_reason}'`
        );
      }
      if (acs.observed_state_commitment == null) {
        throw new ActaSignatureVerificationError(
          `${lbl} invalidation event requires observed_state_commitment`
        );
      }
    } else {
      throw new ActaSignatureVerificationError(
        `${lbl} unsupported answer_cache event_kind '${evKind}'`
      );
    }
    verifyAuthKindAndSigPresence(
      lbl,
      String(acs.cacher_auth_kind || "").trim(),
      acs.client_signature != null,
      acs.client_public_key != null,
      ActaSignatureVerificationError
    );
    if (acs.client_signature != null && acs.client_public_key != null) {
      const intentHex = computeAnswerCacheClientIntentHash({
        tenantId: entry.tenant_id,
        scope: acs.scope,
        taskId: acs.task_id,
        queryHash: acs.query_hash,
        sourceBundleHash: acs.source_bundle_hash,
        stateCommitment: acs.state_commitment,
        answerHash: acs.answer_hash,
      });
      if (
        !verifyEd25519Strict(acs.client_public_key, hexToBytes(intentHex), acs.client_signature) &&
        !verifyEd25519Strict(acs.client_public_key, asHash32(acs.answer_hash), acs.client_signature)
      ) {
        throw new ActaSignatureVerificationError(`client Ed25519 signature verification failed on ${lbl}`);
      }
    }
    const expAcComm = computeAnswerCacheSummaryCommitment(acs);
    if (!entry.state_commitment || String(entry.state_commitment).toLowerCase() !== expAcComm) {
      throw new ActaSignatureVerificationError(
        `tampered answer_cache_summary at seq_num=${entry.seq_num}: state_commitment mismatch`
      );
    }
  }

  if (entry.witness_reg_summary != null) {
    const wreg = entry.witness_reg_summary;
    if (
      entry.bundle_hash != null ||
      entry.refusal_metadata != null ||
      entry.override_summary != null ||
      entry.witness_revoke_summary != null
    ) {
      throw new ActaSignatureVerificationError(
        `invalid evidence entry at seq_num=${entry.seq_num}: witness_reg_summary cannot coexist with bundle_hash, refusal_metadata, override_summary, or witness_revoke_summary`
      );
    }
    const expectedWPre = witnessRegistrationPreimageBytes(
      wreg.registration_domain,
      entry.tenant_id,
      wreg.witness_id,
      wreg.public_key,
      wreg.registered_by || "",
      wreg.description ?? null
    );
    const expectedWPreHex = bytesToHex(expectedWPre);
    if (String(wreg.registration_blake3_preimage_hex || "").trim().toLowerCase() !== expectedWPreHex) {
      throw new ActaSignatureVerificationError(
        `tampered witness_reg_summary.registration_blake3_preimage_hex at seq_num=${entry.seq_num}`
      );
    }
    const expectedWComm = new Blake3Hasher().update(expectedWPre).hexdigest();
    if (!entry.state_commitment || String(entry.state_commitment).toLowerCase() !== expectedWComm) {
      throw new ActaSignatureVerificationError(
        `tampered witness_reg_summary at seq_num=${entry.seq_num}: state_commitment mismatch`
      );
    }
  }

  if (entry.witness_revoke_summary != null) {
    const wrev = entry.witness_revoke_summary;
    if (
      entry.bundle_hash != null ||
      entry.refusal_metadata != null ||
      entry.override_summary != null ||
      entry.witness_reg_summary != null
    ) {
      throw new ActaSignatureVerificationError(
        `invalid evidence entry at seq_num=${entry.seq_num}: witness_revoke_summary cannot coexist with bundle_hash, refusal_metadata, override_summary, or witness_reg_summary`
      );
    }
    const expectedRPre = witnessRevocationPreimageBytes(
      wrev.revocation_domain,
      entry.tenant_id,
      wrev.witness_id,
      wrev.public_key,
      wrev.revoked_by,
      wrev.reason,
      wrev.revocation_mode || "compromise",
      wrev.effective_from_tree_size ?? null
    );
    const expectedRPreHex = bytesToHex(expectedRPre);
    if (String(wrev.revocation_blake3_preimage_hex || "").trim().toLowerCase() !== expectedRPreHex) {
      throw new ActaSignatureVerificationError(
        `tampered witness_revoke_summary.revocation_blake3_preimage_hex at seq_num=${entry.seq_num}`
      );
    }
    const expectedRComm = new Blake3Hasher().update(expectedRPre).hexdigest();
    if (!entry.state_commitment || String(entry.state_commitment).toLowerCase() !== expectedRComm) {
      throw new ActaSignatureVerificationError(
        `tampered witness_revoke_summary at seq_num=${entry.seq_num}: state_commitment mismatch`
      );
    }
  }

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
    writeSummary: entry.write_summary ?? null,
    answerCacheSummary: entry.answer_cache_summary ?? null,
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

function verifyEntryInclusion(proof, sth, expectedPubkeyHex) {
  const entry = proof.entry;
  if (String(entry.tenant_id) !== String(sth.tenant_id)) {
    throw new ActaVerificationError("merkle_proof entry tenant_id mismatch");
  }
  try {
    verifyEvidenceEntry(entry, expectedPubkeyHex);
  } catch (err) {
    throw new ActaVerificationError(err.message);
  }
  if (
    !verifyMerkleInclusionProof(
      entry.seq_num,
      entry.event_hash,
      sth.tree_size,
      proof.audit_path || [],
      sth.merkle_root
    )
  ) {
    throw new ActaVerificationError(
      `Merkle inclusion proof failed for seq_num=${entry.seq_num} against tree_size=${sth.tree_size}`
    );
  }
  if (
    Number(entry.seq_num) === Number(sth.tree_size) &&
    String(entry.event_hash).toLowerCase() !== String(sth.head_event_hash).toLowerCase()
  ) {
    throw new ActaVerificationError(`head entry event_hash mismatch at tree_size=${sth.tree_size}`);
  }
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
    verifyObjectAuthorSig(obj, `object[id=${id}]`, ActaVerificationError);
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
    verifyClaimAuthorSig(claim, null, `claim[id=${id}]`, ActaVerificationError);
    claimsById.set(id, claim);
  }

  const overridesById = new Map();
  for (const att of archive.override_attestations || []) {
    const aid = normalizeUuidString(att.id);
    if (String(att.tenant_id) !== String(bundle.tenant_id)) {
      throw new ActaVerificationError(`override_attestation[id=${aid}] tenant_id mismatch`);
    }
    const hasSig = att.client_signature != null;
    const hasPk = att.client_public_key != null;
    if (hasSig !== hasPk) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] inconsistent client_signature / client_public_key presence`
      );
    }
    const authKind = effectiveOverrideAuthKind(att);
    if (authKind === "ed25519_client_sig") {
      if (!hasSig) {
        throw new ActaVerificationError(
          `override_attestation[id=${aid}] adjudicator_auth_kind='ed25519_client_sig' requires client_signature + client_public_key`
        );
      }
    } else if (
      authKind === "oauth_github_principal" ||
      authKind === "tenant_session" ||
      authKind === "master_admin"
    ) {
      if (hasSig) {
        throw new ActaVerificationError(
          `override_attestation[id=${aid}] adjudicator_auth_kind='${authKind}' cannot coexist with client_signature`
        );
      }
    } else {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] unsupported adjudicator_auth_kind '${authKind}'`
      );
    }

    const storedAttHex = String(att.attestation_hash).toLowerCase();
    if (hasSig && hasPk) {
      const intentHex = computeOverrideClientIntentHash({
        tenantId: att.tenant_id,
        scope: att.scope,
        winningClaimId: att.winning_claim_id,
        adjudicatorId: att.adjudicator_id,
        justification: att.justification,
      });
      const okIntent = verifyEd25519Strict(
        att.client_public_key,
        hexToBytes(intentHex),
        att.client_signature
      );
      const okFull = verifyEd25519Strict(
        att.client_public_key,
        hexToBytes(storedAttHex),
        att.client_signature
      );
      if (!okIntent && !okFull) {
        throw new ActaVerificationError(
          `client Ed25519 signature verification failed on override_attestation[id=${aid}]`
        );
      }
    }

    const recomputedAtt = computeOverrideAttestationHash(att);
    if (recomputedAtt !== storedAttHex) {
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
    if (disp.lapsed_override != null) {
      const lapsed = disp.lapsed_override;
      const aid = normalizeUuidString(lapsed.attestation_id);
      const verifiedAtt = overridesById.get(aid);
      if (!verifiedAtt) {
        throw new ActaVerificationError(
          `dispute_record.lapsed_override references missing override_attestation[id=${aid}]`
        );
      }
      if (
        String(verifiedAtt.attestation_hash).toLowerCase() !== String(lapsed.attestation_hash).toLowerCase() ||
        normalizeUuidString(verifiedAtt.winning_claim_id) !== normalizeUuidString(lapsed.prior_winning_claim_id) ||
        String(verifiedAtt.adjudicator_id) !== String(lapsed.adjudicator_id) ||
        String(verifiedAtt.justification) !== String(lapsed.justification) ||
        Number(verifiedAtt.evidence_seq_num) !== Number(lapsed.evidence_seq_num)
      ) {
        throw new ActaVerificationError(
          `tampered lapsed_override reference on dispute_record[id=${aid}]`
        );
      }
    }
  }

  if (bundle.resolved_facts_omitted !== undefined && bundle.resolved_facts_omitted !== null) {
    const totalOmitted = Number((bundle.omission_record || {}).total_omitted_count || 0);
    if (Number(bundle.resolved_facts_omitted) < 0 || Number(bundle.resolved_facts_omitted) > totalOmitted) {
      throw new ActaVerificationError(`tampered resolved_facts_omitted (${bundle.resolved_facts_omitted}) exceeds total_omitted_count (${totalOmitted})`);
    }
  }
  const { hashHex: recomputedBundleHash } = computeBundleHash(bundle);
  if (recomputedBundleHash !== String(archive.bundle_hash).toLowerCase()) {
    throw new ActaVerificationError(
      `tampered ContextBundle: recomputed bundle_hash ${recomputedBundleHash} != archive ${archive.bundle_hash}`
    );
  }

  const chain = archive.evidence_chain || [];
  const merkleProof = archive.merkle_proof ?? null;
  if (chain.length === 0 && merkleProof == null) {
    throw new ActaVerificationError("ExportArchive must contain either evidence_chain or merkle_proof");
  }

  let foundBinding = false;
  let verifiedRefusals = 0;
  let verifiedWrites = 0;
  let verifiedAnswerCaches = 0;
  let verifiedEvidenceEntries = 0;
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
    if (entry.write_summary != null) verifiedWrites += 1;
    if (entry.answer_cache_summary != null) verifiedAnswerCaches += 1;
    try {
      verifyEvidenceEntry(entry, expectedClean);
    } catch (err) {
      throw new ActaVerificationError(err.message);
    }
    verifiedEvidenceEntries += 1;

    if (entry.bundle_hash && String(entry.bundle_hash).toLowerCase() === recomputedBundleHash) {
      if (String(entry.state_commitment).toLowerCase() !== String(bundle.state_commitment).toLowerCase()) {
        throw new ActaVerificationError("evidence state_commitment mismatch against ContextBundle");
      }
      foundBinding = true;
    }
    evidenceBySeq.set(Number(entry.seq_num), entry);
  }

  let merkleTreeSize = null;
  let merkleRootHex = null;
  let anchoredTreeSize = null;
  let anchoredMerkleRootHex = null;
  let verifiedWitnessAnchors = 0;

  if (merkleProof != null) {
    const sth = merkleProof.checkpoint;
    verifiedWitnessAnchors = verifySignedTreeHead(sth, bundle.tenant_id, expectedClean);
    verifyEntryInclusion(merkleProof.bundle_entry_proof, sth, expectedClean);
    const bEntry = merkleProof.bundle_entry_proof.entry;
    if (
      !bEntry.bundle_hash ||
      String(bEntry.bundle_hash).toLowerCase() !== recomputedBundleHash ||
      !bEntry.state_commitment ||
      String(bEntry.state_commitment).toLowerCase() !== String(bundle.state_commitment).toLowerCase()
    ) {
      throw new ActaVerificationError(
        "merkle_proof.bundle_entry_proof does not bind archive bundle_hash and state_commitment"
      );
    }
    foundBinding = true;
    if (chain.length === 0) verifiedEvidenceEntries += 1;
    evidenceBySeq.set(Number(bEntry.seq_num), bEntry);

    for (const ovrProof of merkleProof.override_entry_proofs || []) {
      verifyEntryInclusion(ovrProof, sth, expectedClean);
      const oEntry = ovrProof.entry;
      if (chain.length === 0 && !evidenceBySeq.has(Number(oEntry.seq_num))) {
        verifiedEvidenceEntries += 1;
      }
      evidenceBySeq.set(Number(oEntry.seq_num), oEntry);
    }

    for (const wrProof of merkleProof.write_entry_proofs || []) {
      verifyEntryInclusion(wrProof, sth, expectedClean);
      const wEntry = wrProof.entry;
      if (chain.length === 0 && !evidenceBySeq.has(Number(wEntry.seq_num))) {
        verifiedEvidenceEntries += 1;
        if (wEntry.write_summary != null) verifiedWrites += 1;
      }
      evidenceBySeq.set(Number(wEntry.seq_num), wEntry);
    }

    if (chain.length > 0 && Number(chain[0].seq_num) === 1 && chain.length === Number(sth.tree_size)) {
      const leaves = chain.map((e) => merkleLeafHash(e.seq_num, e.event_hash));
      const chainRoot = computeMerkleRootFromLeaves(leaves);
      if (chainRoot !== String(sth.merkle_root).toLowerCase()) {
        throw new ActaVerificationError("merkle_proof.checkpoint.merkle_root mismatch against evidence_chain");
      }
    }

    const consToAnchor = merkleProof.consistency_proof_to_anchor || [];
    const anchorSth = merkleProof.anchored_checkpoint ?? null;
    if (consToAnchor.length > 0 && anchorSth == null) {
      throw new ActaVerificationError(
        "merkle_proof.consistency_proof_to_anchor present without anchored_checkpoint"
      );
    }
    if (anchorSth != null) {
      const aSize = Number(anchorSth.tree_size);
      const cSize = Number(sth.tree_size);
      if (aSize < cSize) {
        throw new ActaVerificationError(
          `anchored_checkpoint.tree_size (${aSize}) < checkpoint.tree_size (${cSize})`
        );
      }
      const bridgedAnchors = verifySignedTreeHead(anchorSth, bundle.tenant_id, expectedClean);
      if (
        !verifyMerkleConsistencyProof(
          cSize,
          sth.merkle_root,
          aSize,
          anchorSth.merkle_root,
          consToAnchor
        )
      ) {
        throw new ActaVerificationError(
          `RFC 6962 consistency_proof_to_anchor verification failed from tree_size=${cSize} to anchored tree_size=${aSize}`
        );
      }
      if (aSize > cSize) verifiedWitnessAnchors += bridgedAnchors;
      anchoredTreeSize = aSize;
      anchoredMerkleRootHex = String(anchorSth.merkle_root).toLowerCase();
    } else if ((sth.witness_anchors || []).length > 0) {
      anchoredTreeSize = Number(sth.tree_size);
      anchoredMerkleRootHex = String(sth.merkle_root).toLowerCase();
    }

    merkleTreeSize = Number(sth.tree_size);
    merkleRootHex = String(sth.merkle_root).toLowerCase();
  }

  for (const [aid, att] of overridesById.entries()) {
    const ev = evidenceBySeq.get(Number(att.evidence_seq_num));
    if (!ev) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] references missing verified evidence seq_num=${att.evidence_seq_num}`
      );
    }
    if (!ev.state_commitment || String(ev.state_commitment).toLowerCase() !== String(att.attestation_hash).toLowerCase()) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] attestation_hash not bound in evidence seq_num=${att.evidence_seq_num}`
      );
    }
  }

  for (const [oid, obj] of objectsById.entries()) {
    if (obj.evidence_seq_num != null) {
      const ev = evidenceBySeq.get(Number(obj.evidence_seq_num));
      if (!ev) {
        throw new ActaVerificationError(
          `object[id=${oid}] references missing verified write evidence seq_num=${obj.evidence_seq_num}`
        );
      }
      const ws = ev.write_summary;
      if (
        !ws ||
        normalizeUuidString(ws.item_id) !== oid ||
        String(ws.content_hash).toLowerCase() !== String(obj.content_hash).toLowerCase()
      ) {
        throw new ActaVerificationError(
          `object[id=${oid}] content_hash mismatch against write_summary at seq_num=${obj.evidence_seq_num}`
        );
      }
    }
  }

  for (const [cid, clm] of claimsById.entries()) {
    if (clm.evidence_seq_num != null) {
      const ev = evidenceBySeq.get(Number(clm.evidence_seq_num));
      if (!ev) {
        throw new ActaVerificationError(
          `claim[id=${cid}] references missing verified write evidence seq_num=${clm.evidence_seq_num}`
        );
      }
      const ws = ev.write_summary;
      if (
        !ws ||
        normalizeUuidString(ws.item_id) !== cid ||
        String(ws.content_hash).toLowerCase() !== String(clm.content_hash).toLowerCase()
      ) {
        throw new ActaVerificationError(
          `claim[id=${cid}] content_hash mismatch against write_summary at seq_num=${clm.evidence_seq_num}`
        );
      }
    }
  }

  if (!foundBinding) {
    throw new ActaVerificationError(`no verified evidence_history entry binds bundle_hash ${recomputedBundleHash}`);
  }

  const verificationMode =
    chain.length > 0 && merkleProof != null
      ? "full_chain_and_merkle"
      : chain.length > 0
      ? "full_chain"
      : "merkle_inclusion";

  return {
    tenant_id: bundle.tenant_id,
    bundle_hash_hex: recomputedBundleHash,
    state_commitment_hex: String(bundle.state_commitment).toLowerCase(),
    verified_objects: objectsById.size,
    verified_claims: claimsById.size,
    verified_overrides: overridesById.size,
    verified_writes: verifiedWrites,
    verified_answer_caches: verifiedAnswerCaches,
    verified_refusals: verifiedRefusals,
    verified_evidence_entries: verifiedEvidenceEntries,
    verification_mode: verificationMode,
    merkle_tree_size: merkleTreeSize,
    merkle_root_hex: merkleRootHex,
    anchored_tree_size: anchoredTreeSize,
    anchored_merkle_root_hex: anchoredMerkleRootHex,
    verified_witness_anchors: verifiedWitnessAnchors,
    non_default_thresholds: rm != null ? Boolean(rm.non_default_thresholds) : false,
    resolver_manifest: rm,
  };
}

export function verifyAndRebuildScopeStateOffline(
  archiveOrResponse,
  expectedPubkeyHex,
  scopeOverride = undefined
) {
  const archive =
    archiveOrResponse && typeof archiveOrResponse.rebuild_proof_archive === "object" && archiveOrResponse.rebuild_proof_archive != null
      ? archiveOrResponse.rebuild_proof_archive
      : archiveOrResponse;
  const schemaVer = String(archive.schema_version || STATE_REBUILD_ARCHIVE_SCHEMA_V1);
  if (schemaVer !== STATE_REBUILD_ARCHIVE_SCHEMA_V1) {
    throw new ActaVerificationError(
      `unsupported StateRebuildArchive.schema_version '${schemaVer}' (expected '${STATE_REBUILD_ARCHIVE_SCHEMA_V1}')`
    );
  }
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

  const tenantId = String(archive.tenant_id);
  const targetScope =
    scopeOverride && String(scopeOverride).trim() ? String(scopeOverride).trim() : String(archive.scope);
  const upToSeq = Number(archive.up_to_seq);
  if (!Number.isInteger(upToSeq) || upToSeq < 0) {
    throw new ActaVerificationError(`invalid up_to_seq=${archive.up_to_seq}: must be >= 0`);
  }
  const chain = archive.evidence_chain || [];
  if (chain.length !== upToSeq) {
    throw new ActaVerificationError(
      `evidence_chain length (${chain.length}) != archive.up_to_seq (${upToSeq})`
    );
  }

  const objectsMap = new Map();
  const claimsMap = new Map();
  let writeEventsReplayed = 0;
  const expectedOverrideSeqs = new Map();
  const leaves = [];
  const zeroHex = "00".repeat(32);

  for (let idx = 0; idx < chain.length; idx++) {
    const entry = chain[idx];
    const expectedSeq = idx + 1;
    if (Number(entry.seq_num) !== expectedSeq) {
      throw new ActaVerificationError(
        `gap in evidence_chain at index ${idx}: expected seq_num=${expectedSeq}, got ${entry.seq_num}`
      );
    }
    if (String(entry.tenant_id) !== tenantId) {
      throw new ActaVerificationError("evidence_chain tenant_id mismatch");
    }
    const prevHex = bytesToHex(asHash32(entry.prev_hash)).toLowerCase();
    if (idx === 0) {
      if (prevHex !== zeroHex) {
        throw new ActaVerificationError(`tampered genesis seq_num=1: expected zero prev_hash, got ${prevHex}`);
      }
    } else {
      const priorEvHex = bytesToHex(asHash32(chain[idx - 1].event_hash)).toLowerCase();
      if (prevHex !== priorEvHex) {
        throw new ActaVerificationError(`broken prev_hash link at seq_num=${entry.seq_num}`);
      }
    }
    try {
      verifyEvidenceEntry(entry, expectedClean);
    } catch (err) {
      throw new ActaVerificationError(err.message);
    }
    leaves.push(merkleLeafHash(entry.seq_num, entry.event_hash));

    if (entry.write_summary != null && String(entry.write_summary.scope) === targetScope) {
      writeEventsReplayed += 1;
      const ws = entry.write_summary;
      const snap = ws.record_snapshot;
      if (ws.operation === "ingest_object") {
        objectsMap.set(normalizeUuidString(snap.id), snap);
      } else if (ws.operation === "ingest_claim" || ws.operation === "retract_claim") {
        claimsMap.set(normalizeUuidString(snap.id), snap);
      }
    }
    if (entry.override_summary != null && String(entry.override_summary.scope) === targetScope) {
      if (!entry.state_commitment) {
        throw new ActaVerificationError(
          `override evidence entry at seq_num=${entry.seq_num} missing state_commitment`
        );
      }
      expectedOverrideSeqs.set(Number(entry.seq_num), {
        attId: normalizeUuidString(entry.override_summary.attestation_id),
        attComm: bytesToHex(asHash32(entry.state_commitment)).toLowerCase(),
      });
    }
  }

  const verifiedOverridesBySeq = new Map();
  for (const att of archive.override_attestations || []) {
    const aid = normalizeUuidString(att.id);
    if (String(att.tenant_id) !== tenantId) {
      throw new ActaVerificationError(`override_attestation[id=${aid}] tenant_id mismatch`);
    }
    if (String(att.scope) !== targetScope) continue;
    const hasSig = att.client_signature != null;
    const hasPk = att.client_public_key != null;
    verifyAuthKindAndSigPresence(
      `override_attestation[id=${aid}]`,
      effectiveOverrideAuthKind(att),
      hasSig,
      hasPk,
      ActaVerificationError
    );
    const storedAttHex = bytesToHex(asHash32(att.attestation_hash)).toLowerCase();
    if (hasSig && hasPk) {
      const intentHex = computeOverrideClientIntentHash({
        tenantId: att.tenant_id,
        scope: att.scope,
        winningClaimId: att.winning_claim_id,
        adjudicatorId: att.adjudicator_id,
        justification: att.justification,
      });
      if (
        !verifyEd25519Strict(att.client_public_key, hexToBytes(intentHex), att.client_signature) &&
        !verifyEd25519Strict(att.client_public_key, hexToBytes(storedAttHex), att.client_signature)
      ) {
        throw new ActaVerificationError(
          `client Ed25519 signature verification failed on override_attestation[id=${aid}]`
        );
      }
    }
    const recomputedAtt = computeOverrideAttestationHash(att);
    if (recomputedAtt !== storedAttHex) {
      throw new ActaVerificationError(`tampered override_attestation[id=${aid}]`);
    }
    const evSeq = Number(att.evidence_seq_num);
    if (!verifyOverrideSignature(expectedClean, tenantId, evSeq, recomputedAtt, att.host_signature)) {
      throw new ActaVerificationError(
        `Ed25519 host_signature verification failed on override_attestation[id=${aid}]`
      );
    }
    const exp = expectedOverrideSeqs.get(evSeq);
    if (!exp || exp.attId !== aid || exp.attComm !== storedAttHex) {
      throw new ActaVerificationError(
        `override_attestation[id=${aid}] mismatch against evidence_chain seq_num=${evSeq}`
      );
    }
    verifiedOverridesBySeq.set(evSeq, att);
  }

  for (const [seqNum, exp] of expectedOverrideSeqs.entries()) {
    if (!verifiedOverridesBySeq.has(seqNum)) {
      throw new ActaVerificationError(
        `stripped override_attestation[id=${exp.attId}] notarized at evidence_chain seq_num=${seqNum} is missing from archive.override_attestations`
      );
    }
  }

  let merkleRootHex = null;
  let anchoredTreeSize = null;
  let verifiedWitnessAnchors = 0;

  if (upToSeq > 0) {
    const computedRoot = computeMerkleRootFromLeaves(leaves);
    if (archive.checkpoint != null) {
      const sth = archive.checkpoint;
      if (Number(sth.tree_size) !== upToSeq) {
        throw new ActaVerificationError("checkpoint.tree_size != archive.up_to_seq");
      }
      verifiedWitnessAnchors = verifySignedTreeHead(sth, tenantId, expectedClean);
      if (String(sth.merkle_root).toLowerCase() !== computedRoot) {
        throw new ActaVerificationError("checkpoint.merkle_root mismatch against evidence_chain");
      }
      if (
        String(sth.head_event_hash).toLowerCase() !==
        String(chain[chain.length - 1].event_hash).toLowerCase()
      ) {
        throw new ActaVerificationError("checkpoint.head_event_hash mismatch against chain tail");
      }
      if ((sth.witness_anchors || []).length > 0) anchoredTreeSize = Number(sth.tree_size);
    }
    merkleRootHex = computedRoot;

    if (archive.latest_anchored_checkpoint != null) {
      const anchorSth = archive.latest_anchored_checkpoint;
      const anchorCnt = verifySignedTreeHead(anchorSth, tenantId, expectedClean);
      if (anchorCnt === 0) {
        throw new ActaVerificationError(
          "latest_anchored_checkpoint contains zero verified witness_anchors"
        );
      }
      const aSize = Number(anchorSth.tree_size);
      const consNodes = archive.consistency_proof_from_latest_anchor || [];
      if (aSize <= upToSeq) {
        const prefixRoot = computeMerkleRootFromLeaves(leaves.slice(0, aSize));
        if (prefixRoot !== String(anchorSth.merkle_root).toLowerCase()) {
          throw new ActaVerificationError("latest_anchored_checkpoint merkle_root != prefix root");
        }
        if (
          !verifyMerkleConsistencyProof(
            aSize,
            anchorSth.merkle_root,
            upToSeq,
            computedRoot,
            consNodes
          )
        ) {
          throw new ActaVerificationError(
            "RFC 6962 consistency proof failed from latest_anchored_checkpoint to head"
          );
        }
      } else if (
        !verifyMerkleConsistencyProof(
          upToSeq,
          computedRoot,
          aSize,
          anchorSth.merkle_root,
          consNodes
        )
      ) {
        throw new ActaVerificationError(
          "RFC 6962 consistency proof failed from up_to_seq to latest_anchored_checkpoint"
        );
      }
      if (anchoredTreeSize !== aSize) {
        verifiedWitnessAnchors += anchorCnt;
        anchoredTreeSize = aSize;
      }
    }
  }

  const evalMicros = parseRfc3339Micros(archive.evaluated_at);
  const objPredIds = new Set();
  for (const obj of objectsMap.values()) {
    if (obj.predecessor_id != null) objPredIds.add(normalizeUuidString(obj.predecessor_id));
  }
  const clmPredIds = new Set();
  for (const clm of claimsMap.values()) {
    if (clm.predecessor_id != null) clmPredIds.add(normalizeUuidString(clm.predecessor_id));
  }
  const ovrPredIds = new Set();
  for (const ovr of verifiedOverridesBySeq.values()) {
    if (ovr.predecessor_id != null) ovrPredIds.add(normalizeUuidString(ovr.predecessor_id));
  }

  const intentHashes = [];
  const memoryHashes = [];
  let supersededOrRetracted = 0;

  for (const [oid, obj] of objectsMap.entries()) {
    if (objPredIds.has(oid) || String(obj.lifecycle_status) !== "active") {
      supersededOrRetracted += 1;
    } else if (String(obj.obj_type) === "intent") {
      intentHashes.push(obj.content_hash);
    } else {
      memoryHashes.push(obj.content_hash);
    }
  }

  const claimHashes = [];
  for (const [cid, clm] of claimsMap.entries()) {
    const withinFrom = clm.valid_from == null || parseRfc3339Micros(clm.valid_from) <= evalMicros;
    const withinTo = clm.valid_to == null || parseRfc3339Micros(clm.valid_to) >= evalMicros;
    if (clmPredIds.has(cid) || String(clm.status) !== "active" || !withinFrom || !withinTo) {
      supersededOrRetracted += 1;
    } else {
      claimHashes.push(clm.content_hash);
    }
  }

  const reconstructedActiveClaims = claimHashes.length;
  let activeOverridesCount = 0;
  for (const ovr of verifiedOverridesBySeq.values()) {
    const oid = normalizeUuidString(ovr.id);
    if (!ovrPredIds.has(oid)) {
      claimHashes.push(ovr.attestation_hash);
      activeOverridesCount += 1;
    }
  }

  const permRootHex = bytesToHex(asHash32(archive.permission_root)).toLowerCase();
  const intentRootHex = computeSubCommitment(intentHashes);
  const memoryRootHex = computeSubCommitment(memoryHashes);
  const knowledgeRootHex = computeSubCommitment(claimHashes);
  const stateCommitmentHex = computeStateCommitment({
    schemaVersion: SCHEMA_VERSION,
    tenantId,
    scope: targetScope,
    intentRoot: intentRootHex,
    knowledgeRoot: knowledgeRootHex,
    memoryRoot: memoryRootHex,
    permissionRoot: permRootHex,
  });

  return {
    tenant_id: tenantId,
    scope: targetScope,
    verified_up_to_seq: upToSeq,
    evaluated_at: String(archive.evaluated_at),
    verified_evidence_entries: chain.length,
    write_events_replayed: writeEventsReplayed,
    reconstructed_active_intents: intentHashes.length,
    reconstructed_active_memories: memoryHashes.length,
    reconstructed_active_claims: reconstructedActiveClaims,
    reconstructed_superseded_or_retracted_items: supersededOrRetracted,
    reconstructed_active_overrides: activeOverridesCount,
    reconstructed_intent_root_hex: intentRootHex,
    reconstructed_knowledge_root_hex: knowledgeRootHex,
    reconstructed_memory_root_hex: memoryRootHex,
    permission_root_hex: permRootHex,
    reconstructed_state_commitment_hex: stateCommitmentHex,
    merkle_root_hex: merkleRootHex,
    anchored_tree_size: anchoredTreeSize,
    verified_witness_anchors: verifiedWitnessAnchors,
  };
}

export function dumpArchivePreimages(archive) {
  const bundleJcs = toCanonicalBytes(archive.bundle);
  const bundlePreimage = encodeLengthDelimited(["acta:bundle:v1", bundleJcs]);

  const objectsDump = (archive.objects || []).map((obj) => ({
    id: normalizeUuidString(obj.id),
    obj_type: String(obj.obj_type),
    version: Number(obj.version),
    evidence_seq_num: obj.evidence_seq_num != null ? Number(obj.evidence_seq_num) : null,
    object_domain: "acta:object:v1",
    object_blake3_preimage_hex: bytesToHex(objectContentPreimageBytes(obj)),
    content_hash: bytesToHex(asHash32(obj.content_hash)),
    client_public_key_hex:
      obj.client_public_key != null ? bytesToHex(asHash32(obj.client_public_key)) : null,
    client_signature_hex:
      obj.client_signature != null ? bytesToHex(hexToBytes(obj.client_signature)) : null,
  }));

  const claimsDump = (archive.claims || []).map((claim) => {
    const grp = claimGroupPreimageBytes(claim);
    return {
      id: normalizeUuidString(claim.id),
      subject: String(claim.subject),
      predicate: String(claim.predicate),
      version: Number(claim.version),
      evidence_seq_num: claim.evidence_seq_num != null ? Number(claim.evidence_seq_num) : null,
      claim_group_domain: grp.domain,
      claim_group_blake3_preimage_hex: bytesToHex(grp.preimageBytes),
      claim_group_key: bytesToHex(asHash32(claim.claim_group_key)),
      claim_domain: "acta:claim:v1",
      claim_blake3_preimage_hex: bytesToHex(claimContentPreimageBytes(claim)),
      content_hash: bytesToHex(asHash32(claim.content_hash)),
      source_commitment_hex: bytesToHex(asHash32(claim.source_commitment)),
      client_public_key_hex:
        claim.client_public_key != null ? bytesToHex(asHash32(claim.client_public_key)) : null,
      client_signature_hex:
        claim.client_signature != null ? bytesToHex(hexToBytes(claim.client_signature)) : null,
    };
  });

  const overridesDump = (archive.override_attestations || []).map((att) => {
    const attDomain = effectiveOverrideDomain(att);
    const authKind = effectiveOverrideAuthKind(att);
    const attPreimage = overrideAttestationPreimageBytes(att);
    const hostSigPreimage = encodeLengthDelimited([
      "acta:override_sig:v1",
      String(att.tenant_id),
      i64LeBytes(BigInt(att.evidence_seq_num)),
      asHash32(att.attestation_hash),
    ]);
    let clientSigDomain = null;
    let clientSigPreHex = null;
    let clientSigDigestHex = null;
    if (att.client_signature != null) {
      const tClean = String(att.tenant_id).trim();
      const adjClean = String(att.adjudicator_id).trim();
      const effActor = adjClean.includes("::") ? adjClean : `${tClean}::${adjClean}`;
      const clientSigPreimage = encodeLengthDelimited([
        "acta:override_client_sig:v1",
        tClean,
        String(att.scope).trim(),
        uuidToBytes(att.winning_claim_id),
        effActor,
        String(att.justification).trim(),
      ]);
      clientSigDomain = "acta:override_client_sig:v1";
      clientSigPreHex = bytesToHex(clientSigPreimage);
      clientSigDigestHex = computeOverrideClientIntentHash({
        tenantId: tClean,
        scope: att.scope,
        winningClaimId: att.winning_claim_id,
        adjudicatorId: adjClean,
        justification: att.justification,
      });
    }
    return {
      id: normalizeUuidString(att.id),
      evidence_seq_num: Number(att.evidence_seq_num),
      adjudicator_auth_kind: authKind,
      attestation_domain: attDomain,
      attestation_blake3_preimage_hex: bytesToHex(attPreimage),
      attestation_hash: bytesToHex(asHash32(att.attestation_hash)),
      host_sig_preimage_domain: "acta:override_sig:v1",
      host_sig_blake3_preimage_hex: bytesToHex(hostSigPreimage),
      host_sig_digest_hex: bytesToHex(
        overrideSigningPreimage(att.tenant_id, att.evidence_seq_num, att.attestation_hash)
      ),
      host_signature_hex: String(att.host_signature).toLowerCase(),
      client_sig_domain: clientSigDomain,
      client_sig_blake3_preimage_hex: clientSigPreHex,
      client_sig_digest_hex: clientSigDigestHex,
      client_public_key_hex: att.client_public_key != null ? String(att.client_public_key).toLowerCase() : null,
      client_signature_hex: att.client_signature != null ? String(att.client_signature).toLowerCase() : null,
    };
  });

  let entriesSrc = [];
  if (archive.evidence_chain && archive.evidence_chain.length > 0) {
    entriesSrc = archive.evidence_chain;
  } else if (archive.merkle_proof != null) {
    const bEntry = archive.merkle_proof.bundle_entry_proof.entry;
    const seen = new Set([Number(bEntry.seq_num)]);
    entriesSrc = [bEntry];
    for (const op of archive.merkle_proof.override_entry_proofs || []) {
      const sq = Number(op.entry.seq_num);
      if (!seen.has(sq)) {
        seen.add(sq);
        entriesSrc.push(op.entry);
      }
    }
    for (const wp of archive.merkle_proof.write_entry_proofs || []) {
      const sq = Number(wp.entry.seq_num);
      if (!seen.has(sq)) {
        seen.add(sq);
        entriesSrc.push(wp.entry);
      }
    }
    entriesSrc.sort((a, b) => Number(a.seq_num) - Number(b.seq_num));
  }

  const evidenceDump = entriesSrc.map((entry) => {
    const micros = parseRfc3339Micros(entry.created_at);
    const isV3 = entry.write_summary != null || entry.answer_cache_summary != null;
    const isV1 = !isV3 && entry.refusal_metadata == null && entry.override_summary == null;
    const evDomain = isV3
      ? "acta:evidence_event:v3"
      : isV1
      ? "acta:evidence_event:v1"
      : "acta:evidence_event:v2";
    const evPreimage = isV3
      ? encodeLengthDelimited([
          "acta:evidence_event:v3",
          String(entry.tenant_id),
          i64LeBytes(BigInt(entry.seq_num)),
          asHash32(entry.prev_hash),
          encodeOptHash32(entry.bundle_hash ?? null),
          encodeOptHash32(entry.state_commitment ?? null),
          String(entry.policy_result),
          i64LeBytes(micros),
          encodeOptJcs(entry.write_summary != null ? normalizeWriteSummary(entry.write_summary) : null),
          encodeOptJcs(
            entry.answer_cache_summary != null ? normalizeAnswerCacheSummary(entry.answer_cache_summary) : null
          ),
        ])
      : isV1
      ? encodeLengthDelimited([
          "acta:evidence_event:v1",
          String(entry.tenant_id),
          i64LeBytes(BigInt(entry.seq_num)),
          asHash32(entry.prev_hash),
          encodeOptHash32(entry.bundle_hash ?? null),
          encodeOptHash32(entry.state_commitment ?? null),
          String(entry.policy_result),
          i64LeBytes(micros),
        ])
      : encodeLengthDelimited([
          "acta:evidence_event:v2",
          String(entry.tenant_id),
          i64LeBytes(BigInt(entry.seq_num)),
          asHash32(entry.prev_hash),
          encodeOptHash32(entry.bundle_hash ?? null),
          encodeOptHash32(entry.state_commitment ?? null),
          String(entry.policy_result),
          i64LeBytes(micros),
          encodeOptJcs(entry.refusal_metadata != null ? normalizeRefusalMetadata(entry.refusal_metadata) : null),
          encodeOptJcs(entry.override_summary != null ? normalizeOverrideSummary(entry.override_summary) : null),
        ]);
    const evHex = bytesToHex(asHash32(entry.event_hash));
    const sigPreimage = encodeLengthDelimited([
      "acta:evidence_sig:v1",
      String(entry.tenant_id),
      i64LeBytes(BigInt(entry.seq_num)),
      asHash32(entry.prev_hash),
      asHash32(entry.event_hash),
    ]);
    return {
      seq_num: Number(entry.seq_num),
      event_domain: evDomain,
      event_blake3_preimage_hex: bytesToHex(evPreimage),
      event_hash: evHex,
      merkle_leaf_sha256_preimage_hex: `00${evHex}`,
      merkle_leaf_hash: merkleLeafHash(entry.seq_num, entry.event_hash),
      host_sig_preimage_domain: "acta:evidence_sig:v1",
      host_sig_blake3_preimage_hex: bytesToHex(sigPreimage),
      host_sig_digest_hex: bytesToHex(
        evidenceSigningPreimage(entry.tenant_id, entry.seq_num, entry.prev_hash, entry.event_hash)
      ),
      host_signature_hex: String(entry.host_signature).toLowerCase(),
      refusal_metadata_canonical_jcs:
        entry.refusal_metadata != null ? toCanonicalJson(normalizeRefusalMetadata(entry.refusal_metadata)) : null,
      override_summary_canonical_jcs:
        entry.override_summary != null ? toCanonicalJson(normalizeOverrideSummary(entry.override_summary)) : null,
      write_summary_canonical_jcs:
        entry.write_summary != null ? toCanonicalJson(normalizeWriteSummary(entry.write_summary)) : null,
      answer_cache_summary_canonical_jcs:
        entry.answer_cache_summary != null ? toCanonicalJson(normalizeAnswerCacheSummary(entry.answer_cache_summary)) : null,
      witness_registration: entry.witness_reg_summary ?? null,
      witness_revocation: entry.witness_revoke_summary ?? null,
    };
  });

  function dumpSingleSth(sth, auditPathLen = null) {
    const issuedMicros = parseRfc3339Micros(sth.issued_at);
    const cpPreimage = encodeLengthDelimited([
      "acta:checkpoint:v1",
      String(sth.tenant_id),
      i64LeBytes(BigInt(sth.tree_size)),
      asHash32(sth.head_event_hash),
      asHash32(sth.merkle_root),
      i64LeBytes(issuedMicros),
    ]);
    const cpSigPreimage = encodeLengthDelimited([
      "acta:checkpoint_sig:v1",
      String(sth.tenant_id),
      asHash32(sth.checkpoint_hash),
    ]);
    const witnessDump = (sth.witness_anchors || []).map((a) => {
      const wPre = encodeLengthDelimited([
        "acta:witness_sig:v1",
        String(a.tenant_id),
        i64LeBytes(BigInt(a.tree_size)),
        asHash32(a.checkpoint_hash),
      ]);
      return {
        id: normalizeUuidString(a.id),
        witness_id: String(a.witness_id),
        witness_public_key_hex: bytesToHex(asHash32(a.witness_public_key)),
        witness_sig_domain: "acta:witness_sig:v1",
        witness_sig_blake3_preimage_hex: bytesToHex(wPre),
        witness_sig_digest_hex: bytesToHex(
          witnessAnchorSigningPreimage(a.tenant_id, a.tree_size, a.checkpoint_hash)
        ),
        witness_signature_hex: String(a.witness_signature).toLowerCase(),
      };
    });
    const obj = {
      tree_size: Number(sth.tree_size),
      head_event_hash: bytesToHex(asHash32(sth.head_event_hash)),
      merkle_root: bytesToHex(asHash32(sth.merkle_root)),
      issued_at_micros: Number(issuedMicros),
      checkpoint_domain: "acta:checkpoint:v1",
      checkpoint_blake3_preimage_hex: bytesToHex(cpPreimage),
      checkpoint_hash: bytesToHex(asHash32(sth.checkpoint_hash)),
      host_sig_preimage_domain: "acta:checkpoint_sig:v1",
      host_sig_blake3_preimage_hex: bytesToHex(cpSigPreimage),
      host_sig_digest_hex: bytesToHex(
        checkpointSigningPreimage(sth.tenant_id, sth.checkpoint_hash)
      ),
      host_signature_hex: String(sth.host_signature).toLowerCase(),
      witness_anchors: witnessDump,
    };
    if (auditPathLen !== null) obj.bundle_audit_path_len = auditPathLen;
    return obj;
  }

  const cpDump =
    archive.merkle_proof != null
      ? dumpSingleSth(
          archive.merkle_proof.checkpoint,
          (archive.merkle_proof.bundle_entry_proof.audit_path || []).length
        )
      : null;

  let anchoredCpDump = null;
  if (archive.merkle_proof?.anchored_checkpoint != null) {
    anchoredCpDump = dumpSingleSth(archive.merkle_proof.anchored_checkpoint, null);
    anchoredCpDump.from_tree_size = Number(archive.merkle_proof.checkpoint.tree_size);
    anchoredCpDump.consistency_proof_to_anchor = [
      ...(archive.merkle_proof.consistency_proof_to_anchor || []),
    ];
  }

  const outObj = {
    framing_spec:
      "BLAKE3 digests hash concat_i(u64_le(len(part_i)) || part_i); Ed25519 signatures sign raw 32-byte digest bytes; Merkle trees follow RFC 6962 §2.1 SHA-256.",
    merkle_spec: {
      scheme: "rfc6962-sha256-v1",
      empty_root_sha256_hex: merkleEmptyRoot(),
      leaf_formula: "SHA-256(0x00 || event_hash_32)",
      node_formula: "SHA-256(0x01 || left_32 || right_32)",
      legacy_v160_blake3_merkle_spec: {
        scheme: "acta-blake3-merkle-v1",
        empty_root_blake3_hex: legacyBlake3MerkleEmptyRoot(),
        leaf_formula: 'BLAKE3(encode_length_delimited([b"acta:merkle_leaf:v1", i64_le(seq_num), event_hash_32]))',
        node_formula: 'BLAKE3(encode_length_delimited([b"acta:merkle_node:v1", left_32, right_32]))',
      },
    },
    bundle_domain: "acta:bundle:v1",
    bundle_canonical_jcs_len: bundleJcs.length,
    bundle_canonical_jcs_utf8: Buffer.from(bundleJcs).toString("utf8"),
    bundle_blake3_preimage_hex: bytesToHex(bundlePreimage),
    bundle_hash: String(archive.bundle_hash).toLowerCase(),
    objects: objectsDump,
    claims: claimsDump,
    checkpoint: cpDump,
    override_attestations: overridesDump,
    evidence_entries: evidenceDump,
  };
  if (anchoredCpDump !== null) outObj.anchored_checkpoint = anchoredCpDump;
  return outObj;
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
    this.verifiedPrincipal = this.apiKey ? extractTokenPrincipal(this.apiKey) : null;
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

  async mintTenantKey(tenantId, principal = undefined) {
    const body = { tenant_id: tenantId };
    if (principal !== undefined) body.principal = principal;
    const { data } = await this._requestJson(
      "POST",
      "/v1/auth/mint-tenant-key",
      body,
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
    if (req.clientSignatureHex) body.client_signature_hex = req.clientSignatureHex;
    if (req.clientPublicKeyHex) body.client_public_key_hex = req.clientPublicKeyHex;
    const { data } = await this._requestJson("POST", "/v1/objects", body, [200, 201]);
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
    if (req.sourceContent) body.source_content = req.sourceContent;
    if (req.validFrom) body.valid_from = req.validFrom;
    if (req.validTo) body.valid_to = req.validTo;
    if (req.predecessorId) body.predecessor_id = req.predecessorId;
    if (req.clientSignatureHex) body.client_signature_hex = req.clientSignatureHex;
    if (req.clientPublicKeyHex) body.client_public_key_hex = req.clientPublicKeyHex;
    const { data } = await this._requestJson("POST", "/v1/claims", body, [200, 201]);
    return data;
  }

  async retractClaim(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      claim_id: req.claimId,
      reason: req.reason,
    };
    if (req.id) body.id = req.id;
    if (req.clientSignatureHex) body.client_signature_hex = req.clientSignatureHex;
    if (req.clientPublicKeyHex) body.client_public_key_hex = req.clientPublicKeyHex;
    const { data } = await this._requestJson("POST", "/v1/claims/retract", body, [200, 201]);
    return data;
  }

  async cacheAnswer(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const body = {
      tenant_id: effTenant,
      source_bundle_hash: req.sourceBundleHash,
      answer_text: req.answerText,
      query_text: req.queryText ?? "",
    };
    if (req.id) body.id = req.id;
    if (req.scope) body.scope = req.scope;
    if (req.taskId) body.task_id = req.taskId;
    if (req.answerMetadata) body.answer_metadata = req.answerMetadata;
    if (req.ttlSeconds !== undefined) body.ttl_seconds = req.ttlSeconds;
    if (req.validityMode !== undefined) body.validity_mode = req.validityMode;
    if (req.dependencyIds !== undefined) body.dependency_ids = req.dependencyIds;
    if (req.clientSignatureHex) body.client_signature_hex = req.clientSignatureHex;
    if (req.clientPublicKeyHex) body.client_public_key_hex = req.clientPublicKeyHex;
    const { data } = await this._requestJson("POST", "/v1/answers/cache", body, [200, 201]);
    verifyEvidenceEntry(data.evidence, hostPk);
    if (
      !verifyAnswerCacheSignature(
        hostPk,
        effTenant,
        data.receipt.evidence_seq_num,
        data.receipt.cache_commitment,
        data.receipt.host_signature
      )
    ) {
      throw new ActaSignatureVerificationError(
        "Ed25519 host_signature verification failed on cacheAnswer receipt"
      );
    }
    return data;
  }

  async lookupCachedAnswer(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const body = {
      tenant_id: effTenant,
      scope: req.scope,
      task_id: req.taskId || "mcp-task",
      query_text: req.queryText ?? "",
    };
    if (req.actorId) body.actor_id = req.actorId;
    const { data } = await this._requestJson(
      "POST",
      "/v1/answers/lookup",
      body,
      [200, 202, 403, 422]
    );
    if (data.cache_hit && data.receipt) {
      if (
        !verifyAnswerCacheSignature(
          hostPk,
          effTenant,
          data.receipt.evidence_seq_num,
          data.receipt.cache_commitment,
          data.receipt.host_signature
        )
      ) {
        throw new ActaSignatureVerificationError(
          "Ed25519 host_signature verification failed on lookupCachedAnswer receipt"
        );
      }
    }
    if (data.invalidation_evidence) {
      verifyEvidenceEntry(data.invalidation_evidence, hostPk);
    }
    return data;
  }

  async traceItemImpact(itemId, params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/impact/${encodeURIComponent(String(itemId).trim())}`,
      undefined,
      [200]
    );
    return data;
  }

  async rebuildScopeState(scope, params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const q = [`scope=${encodeURIComponent(scope)}`];
    if (params.upToSeq !== undefined) q.push(`up_to_seq=${Number(params.upToSeq)}`);
    if (params.includeProofArchive) q.push("include_proof_archive=true");
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/state-rebuild?${q.join("&")}`,
      undefined,
      [200]
    );
    if (params.includeProofArchive && data.rebuild_proof_archive) {
      const hostPk = await this.ensureHostPublicKey();
      const offline = verifyAndRebuildScopeStateOffline(data.rebuild_proof_archive, hostPk, scope);
      if (
        offline.reconstructed_state_commitment_hex !==
        String(data.reconstructed_state_commitment).toLowerCase()
      ) {
        throw new ActaVerificationError(
          "offline state rebuild state_commitment mismatch against server response"
        );
      }
    }
    return data;
  }

  async verifyStateRebuild(params = {}) {
    return this.rebuildScopeState(params.scope, params);
  }

  async attestOverride(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const body = {
      tenant_id: effTenant,
      scope: req.scope,
      winning_claim_id: req.winningClaimId,
      justification: req.justification,
    };
    if (req.adjudicatorId !== undefined) body.adjudicator_id = req.adjudicatorId;
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

  async getCheckpoint(params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const q = [];
    if (params.treeSize !== undefined) q.push(`tree_size=${Number(params.treeSize)}`);
    if (params.sinceSize !== undefined) q.push(`since_size=${Number(params.sinceSize)}`);
    const qs = q.length > 0 ? `?${q.join("&")}` : "";
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/checkpoint${qs}`,
      undefined,
      [200]
    );
    if (data.checkpoint) {
      verifySignedTreeHead(data.checkpoint, effTenant, hostPk);
      if (data.consistency_proof && data.prior_checkpoint) {
        verifySignedTreeHead(data.prior_checkpoint, effTenant, hostPk);
        if (
          !verifyMerkleConsistencyProof(
            data.prior_checkpoint.tree_size,
            data.prior_checkpoint.merkle_root,
            data.checkpoint.tree_size,
            data.checkpoint.merkle_root,
            data.consistency_proof
          )
        ) {
          throw new ActaVerificationError(
            `RFC 6962 consistency proof failed from first_size=${data.prior_checkpoint.tree_size} to second_size=${data.checkpoint.tree_size}`
          );
        }
      }
      if (data.latest_anchored_checkpoint) {
        verifySignedTreeHead(data.latest_anchored_checkpoint, effTenant, hostPk);
        const aSz = Number(data.latest_anchored_checkpoint.tree_size);
        const hSz = Number(data.checkpoint.tree_size);
        if (aSz < hSz && Array.isArray(data.consistency_proof_from_latest_anchor)) {
          if (
            !verifyMerkleConsistencyProof(
              aSz,
              data.latest_anchored_checkpoint.merkle_root,
              hSz,
              data.checkpoint.merkle_root,
              data.consistency_proof_from_latest_anchor
            )
          ) {
            throw new ActaVerificationError(
              `RFC 6962 consistency proof failed from latest_anchored_checkpoint (${aSz}) to head (${hSz})`
            );
          }
        }
      }
    }
    return data;
  }

  async registerWitness(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      witness_id: req.witnessId,
      witness_public_key_hex: req.witnessPublicKeyHex,
    };
    if (req.description) body.description = req.description;
    const { data } = await this._requestJson("POST", "/v1/witnesses", body, [200, 201]);
    return data;
  }

  async revokeWitness(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      witness_id: req.witnessId,
      mode: req.mode || req.revocationMode || "compromise",
      reason: req.reason,
    };
    const { data } = await this._requestJson("POST", "/v1/witnesses/revoke", body, [200, 201]);
    return data;
  }

  async listWitnesses(params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/witnesses`,
      undefined,
      [200]
    );
    return data;
  }

  async anchorCheckpoint(req) {
    const effTenant = this._enforceTenant(req.tenantId);
    const body = {
      tenant_id: effTenant,
      tree_size: req.treeSize,
      checkpoint_hash_hex: req.checkpointHashHex,
      witness_id: req.witnessId,
      witness_public_key_hex: req.witnessPublicKeyHex,
      witness_signature_hex: req.witnessSignatureHex,
    };
    if (req.externalUri) body.external_uri = req.externalUri;
    const { data } = await this._requestJson("POST", "/v1/anchors", body, [200, 201]);
    const anchor = data.anchor || data;
    if (
      !verifyWitnessAnchorSignature(
        anchor.witness_public_key,
        effTenant,
        anchor.tree_size,
        anchor.checkpoint_hash,
        anchor.witness_signature
      )
    ) {
      throw new ActaSignatureVerificationError(
        "Ed25519 witness_signature verification failed on anchorCheckpoint response"
      );
    }
    return data;
  }

  async listAnchors(params = {}) {
    const effTenant = this._enforceTenant(params.tenantId);
    const qs = params.treeSize !== undefined ? `?tree_size=${Number(params.treeSize)}` : "";
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/anchors${qs}`,
      undefined,
      [200]
    );
    return data;
  }

  async listTenantEvidence(tenantIdOrOpts = undefined) {
    const opts = (tenantIdOrOpts && typeof tenantIdOrOpts === "object") ? tenantIdOrOpts : { tenantId: tenantIdOrOpts };
    const effTenant = this._enforceTenant(opts.tenantId);
    const hostPk = await this.ensureHostPublicKey();
    const q = [];
    if (opts.fromSeq !== undefined) q.push(`from_seq=${Number(opts.fromSeq)}`);
    if (opts.limit !== undefined) q.push(`limit=${Number(opts.limit)}`);
    const qs = q.length ? `?${q.join("&")}` : "";
    const { data } = await this._requestJson(
      "GET",
      `/v1/tenants/${encodeURIComponent(effTenant)}/evidence${qs}`,
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
      contextTokenCount: data.context_token_count ?? null,
      contextTokenIds: data.context_token_ids ?? null,
      contextTokenBytesHex: data.context_token_bytes_hex ?? null,
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

  async exportBundle(bundleHash, mode = "full", anchorTreeSize = undefined) {
    const clean = encodeURIComponent(String(bundleHash).trim().toLowerCase());
    const params = [];
    if (mode === "merkle") params.push("mode=merkle");
    if (anchorTreeSize !== undefined && anchorTreeSize !== null) {
      params.push(`anchor_tree_size=${Number(anchorTreeSize)}`);
    }
    const qs = params.length > 0 ? `?${params.join("&")}` : "";
    const { data } = await this._requestJson("GET", `/v1/bundles/${clean}/export${qs}`, undefined, [200]);
    return data;
  }

  async verifyBundleOffline(bundleHash, expectedPubkeyHex = undefined, mode = "full", anchorTreeSize = undefined) {
    const pk = (expectedPubkeyHex || (await this.ensureHostPublicKey())).trim().toLowerCase();
    const archive = await this.exportBundle(bundleHash, mode, anchorTreeSize);
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
