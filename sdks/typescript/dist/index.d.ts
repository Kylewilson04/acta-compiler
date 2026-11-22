export declare const DEFAULT_CLOUDRUN_URL: string;
export declare const TENANT_TOKEN_PREFIX: string;
export declare const DEFAULT_MIN_CONFIDENCE: number;
export declare const DEFAULT_DECISIVENESS_THRESHOLD: number;
export declare const DEFAULT_CORROBORATION_DAMPING: number;
export declare const SYSTEM_GUARDRAIL_HEADER: string;

export type BudgetKind = "tokens" | "bytes" | "records";
export type ObjectType = "intent" | "memory";
export type LifecycleStatus = "active" | "revoked" | "expired" | "superseded";
export type PolicyResultTag = "allow" | "block" | "escalate";
export type ExportMode = "full" | "merkle";

export interface ContextBudget {
  kind: BudgetKind;
  limit: number;
}

export interface ResolverManifest {
  min_confidence: number;
  decisiveness_threshold: number;
  corroboration_damping: number;
  non_default_thresholds: boolean;
  budget: ContextBudget;
  permission_root: string;
}

export interface RefusalMetadata {
  operation: string;
  reason_code: string;
  target_scope?: string | null;
  summary: string;
  scope_state_commitment?: string | null;
}

export interface OverrideLedgerSummary {
  attestation_id: string;
  scope: string;
  subject: string;
  predicate: string;
  winning_claim_id: string;
  overridden_count: number;
  adjudicator_id: string;
  version: number;
}

export interface LapsedOverrideRef {
  attestation_id: string;
  attestation_hash: string;
  prior_winning_claim_id: string;
  adjudicator_id: string;
  justification: string;
  evidence_seq_num: number;
  version: number;
  attested_at: string;
  reopened_by_claim_ids: string[];
}

export interface ExternalWitnessAnchor {
  id: string;
  tenant_id: string;
  tree_size: number;
  checkpoint_hash: string;
  witness_id: string;
  witness_public_key: string;
  witness_signature: string;
  external_uri?: string | null;
  anchored_at: string;
}

export interface SignedTreeHead {
  tenant_id: string;
  tree_size: number;
  head_event_hash: string;
  merkle_root: string;
  issued_at: string;
  checkpoint_hash: string;
  host_signature: string;
  witness_anchors: ExternalWitnessAnchor[];
}

export interface PolicyDecision {
  decision: PolicyResultTag;
  reason?: string;
}

export interface EvidenceEntry {
  tenant_id: string;
  seq_num: number;
  prev_hash: string;
  event_hash: string;
  bundle_hash?: string | null;
  state_commitment?: string | null;
  policy_result: PolicyResultTag;
  refusal_metadata?: RefusalMetadata | null;
  override_summary?: OverrideLedgerSummary | null;
  host_signature: string;
  created_at: string;
}

export interface VerificationSummary {
  tenant_id: string;
  bundle_hash_hex: string;
  state_commitment_hex: string;
  verified_objects: number;
  verified_claims: number;
  verified_overrides: number;
  verified_refusals: number;
  verified_evidence_entries: number;
  verification_mode: "full_chain" | "merkle_inclusion" | "full_chain_and_merkle";
  merkle_tree_size: number | null;
  merkle_root_hex: string | null;
  verified_witness_anchors: number;
  non_default_thresholds: boolean;
  resolver_manifest: ResolverManifest | null;
}

export interface CompileResult {
  httpStatus: number;
  policyDecision: PolicyDecision;
  bundleHash: string | null;
  contextText: string | null;
  bundle: Record<string, any> | null;
  evidence: EvidenceEntry;
  verifiedHostPubkey: string;
}

export interface GuardedGenerationResult<T = unknown> {
  text: string;
  bundleHash: string;
  stateCommitment: string;
  dependencyCommitment: string;
  contextText: string;
  evidence: EvidenceEntry;
  verifiedHostPubkey: string;
  rawResponse: T;
}

export declare class Blake3Hasher {
  constructor(key32?: Uint8Array | null);
  update(input: Uint8Array | string): this;
  digest(): Uint8Array;
  hexdigest(): string;
}

export declare function toCanonicalJson(value: unknown): string;
export declare function toCanonicalBytes(value: unknown): Uint8Array;
export declare function hashLengthDelimited(parts: Array<Uint8Array | string>): Uint8Array;
export declare function blake3KeyedHash(key32: Uint8Array, parts: Array<Uint8Array | string>): Uint8Array;
export declare function normalizeGithubSlug(raw: string): string;
export declare function deriveTenantMacKey(masterApiKey: string): Uint8Array;
export declare function mintTenantApiKey(masterApiKey: string, tenantId: string): string;
export declare function mintUserTenantApiKey(masterApiKey: string, tenantId: string, githubLogin: string): string;
export declare function extractTokenTenant(token: string): string | null;
export declare function extractTokenPrincipal(token: string): string | null;
export declare function verifyTenantApiKeyWithPrincipal(
  masterApiKey: string,
  token: string
): { tenantId: string; principal: string | null };
export declare function verifyTenantApiKey(masterApiKey: string, token: string): string;
export declare function parseRfc3339Micros(ts: string): bigint;
export declare function computeClaimGroupKey(
  tenant: string,
  subject: string,
  predicate: string,
  objectType: string,
  scope: string
): string;
export declare function computeLogicalClaimGroupKey(
  tenant: string,
  subject: string,
  predicate: string,
  scope: string
): string;
export declare function computeRefusalMetadataCommitment(meta: RefusalMetadata): string;
export declare function computeObjectContentHash(obj: Record<string, any>): string;
export declare function computeClaimContentHash(claim: Record<string, any>): string;
export declare function computeOverrideClientIntentHash(params: {
  tenantId: string;
  scope: string;
  winningClaimId: string;
  adjudicatorId: string;
  justification: string;
}): string;
export declare function signOverrideClientIntent(
  seedHexOrBytes: string | Uint8Array,
  params: {
    tenantId: string;
    scope: string;
    winningClaimId: string;
    adjudicatorId: string;
    justification: string;
  }
): { clientSignatureHex: string; clientPublicKeyHex: string };
export declare function computeOverrideAttestationHash(att: Record<string, any>): string;
export declare function computeOmissionListHash(sortedItems: Array<{ id: string; reason: string }>): string;
export declare function computeBundleHash(bundle: Record<string, any>): { hashHex: string; canonicalBytes: Uint8Array };
export declare function computeEvidenceEventHash(params: {
  tenantId: string;
  seqNum: number | bigint;
  prevHash: string | Uint8Array;
  bundleHash?: string | Uint8Array | null;
  stateCommitment?: string | Uint8Array | null;
  policyResult: PolicyResultTag;
  createdAt: string | bigint;
  refusalMetadata?: RefusalMetadata | null;
  overrideSummary?: OverrideLedgerSummary | null;
}): string;
export declare function merkleEmptyRoot(): string;
export declare function merkleLeafHash(seqNum: number | bigint, eventHash: string | Uint8Array): string;
export declare function merkleNodeHash(left: string | Uint8Array, right: string | Uint8Array): string;
export declare function computeMerkleRootFromLeaves(leaves: Array<string | Uint8Array>): string;
export declare function computeMerkleInclusionProof(leaves: Array<string | Uint8Array>, leafIndex: number): string[];
export declare function verifyMerkleInclusionProof(
  seqNum: number | bigint,
  eventHash: string | Uint8Array,
  treeSize: number | bigint,
  auditPath: Array<string | Uint8Array>,
  expectedRoot: string | Uint8Array
): boolean;
export declare function computeMerkleConsistencyProof(
  leaves: Array<string | Uint8Array>,
  firstSize: number,
  secondSize: number
): string[];
export declare function verifyMerkleConsistencyProof(
  firstSize: number | bigint,
  firstRoot: string | Uint8Array,
  secondSize: number | bigint,
  secondRoot: string | Uint8Array,
  proof: Array<string | Uint8Array>
): boolean;
export declare function computeCheckpointHash(params: {
  tenantId: string;
  treeSize: number | bigint;
  headEventHash: string | Uint8Array;
  merkleRoot: string | Uint8Array;
  issuedAt: string | bigint;
}): string;
export declare function signEvidenceEntry(
  seedHexOrBytes: string | Uint8Array,
  tenantId: string,
  seqNum: number | bigint,
  prevHash: string | Uint8Array,
  eventHash: string | Uint8Array
): string;
export declare function signOverrideAttestation(
  seedHexOrBytes: string | Uint8Array,
  tenantId: string,
  evidenceSeqNum: number | bigint,
  attestationHash: string | Uint8Array
): string;
export declare function signCheckpointHead(
  seedHexOrBytes: string | Uint8Array,
  tenantId: string,
  checkpointHash: string | Uint8Array
): string;
export declare function signWitnessAnchor(
  seedHexOrBytes: string | Uint8Array,
  tenantId: string,
  treeSize: number | bigint,
  checkpointHash: string | Uint8Array
): { witnessSignatureHex: string; witnessPublicKeyHex: string };
export declare function verifyOverrideSignature(
  pubkeyHexOrBytes: string | Uint8Array,
  tenantId: string,
  evidenceSeqNum: number | bigint,
  attestationHash: string | Uint8Array,
  sigHexOrBytes: string | Uint8Array
): boolean;
export declare function verifyCheckpointSignature(
  pubkeyHexOrBytes: string | Uint8Array,
  tenantId: string,
  checkpointHash: string | Uint8Array,
  sigHexOrBytes: string | Uint8Array
): boolean;
export declare function verifyWitnessAnchorSignature(
  witnessPubkeyHexOrBytes: string | Uint8Array,
  tenantId: string,
  treeSize: number | bigint,
  checkpointHash: string | Uint8Array,
  sigHexOrBytes: string | Uint8Array
): boolean;
export declare function verifySignedTreeHead(
  sth: SignedTreeHead,
  expectedTenant: string,
  expectedPubkeyHex: string
): number;
export declare function deriveEd25519PublicKeyHex(seedHexOrBytes: string | Uint8Array): string;
export declare function verifyEd25519Strict(
  pubkeyHexOrBytes: string | Uint8Array,
  messageBytes: Uint8Array,
  sigHexOrBytes: string | Uint8Array
): boolean;
export declare function verifyEvidenceEntry(entry: EvidenceEntry, expectedPubkeyHex: string): void;
export declare function verifyExportArchive(
  archive: Record<string, any>,
  expectedPubkeyHex: string
): VerificationSummary;
export declare function dumpArchivePreimages(archive: Record<string, any>): Record<string, any>;
export declare function buildGuardedPrompt(compiledContext: string, userPrompt: string, bundleHash: string): string;

export declare class ActaError extends Error {}
export declare class ActaHttpError extends ActaError {
  statusCode: number;
  payload: unknown;
}
export declare class ActaAuthError extends ActaHttpError {}
export declare class ActaSignatureVerificationError extends ActaError {}
export declare class ActaVerificationError extends ActaError {}
export declare class ActaTenantLockError extends ActaError {}
export declare class ActaPolicyBlockedError extends ActaError {
  reason: string;
  evidence: EvidenceEntry;
  policyDecision: PolicyDecision;
}
export declare class ActaPolicyEscalatedError extends ActaError {
  reason: string;
  evidence: EvidenceEntry;
  policyDecision: PolicyDecision;
}
export declare class ActaDisputeEscalationError extends ActaError {
  bundleHash: string;
  disputes: Array<Record<string, any>>;
  evidence: EvidenceEntry;
  contextText: string;
}

export interface ActaClientOptions {
  baseUrl?: string;
  apiKey?: string;
  defaultTenantId?: string;
  pinnedHostPublicKey?: string;
  fetchImpl?: typeof fetch;
}

export declare class ActaClient {
  readonly baseUrl: string;
  readonly lockedTenant: string | null;
  readonly verifiedPrincipal: string | null;
  constructor(options?: ActaClientOptions);
  ensureHostPublicKey(): Promise<string>;
  health(): Promise<Record<string, any>>;
  mintTenantKey(tenantId: string, principal?: string): Promise<Record<string, any>>;
  inspectKey(): Promise<Record<string, any>>;
  ingestObject(req: {
    tenantId?: string;
    objType: ObjectType;
    scope: string;
    body: unknown;
    priority?: number;
    importance?: number;
    tags?: string[];
    lifecycleStatus?: LifecycleStatus;
    embedding?: number[];
    predecessorId?: string;
    id?: string;
  }): Promise<Record<string, any>>;
  ingestClaim(req: {
    tenantId?: string;
    scope: string;
    subject: string;
    predicate: string;
    objectVal: unknown;
    objectType: string;
    confidence: number;
    sourceDescriptor: string;
    sourceProvenanceClass?: number;
    sourceCommitmentHex?: string;
    status?: LifecycleStatus;
    contradictionIds?: string[];
    validFrom?: string;
    validTo?: string;
    predecessorId?: string;
    id?: string;
  }): Promise<Record<string, any>>;
  attestOverride(req: {
    tenantId?: string;
    scope: string;
    winningClaimId: string;
    adjudicatorId?: string;
    justification: string;
    sourceBundleHashHex?: string;
    id?: string;
    clientSignatureHex?: string;
    clientPublicKeyHex?: string;
  }): Promise<Record<string, any>>;
  listOverrides(params?: { tenantId?: string; scope?: string }): Promise<Record<string, any>>;
  getCheckpoint(params?: { tenantId?: string; treeSize?: number; sinceSize?: number }): Promise<Record<string, any>>;
  anchorCheckpoint(req: {
    tenantId?: string;
    treeSize: number;
    checkpointHashHex: string;
    witnessId: string;
    witnessPublicKeyHex: string;
    witnessSignatureHex: string;
    externalUri?: string;
  }): Promise<Record<string, any>>;
  listAnchors(params?: { tenantId?: string; treeSize?: number }): Promise<Record<string, any>>;
  listTenantEvidence(tenantId?: string): Promise<Record<string, any>>;
  compile(req: {
    tenantId?: string;
    actorId: string;
    scope: string;
    queryText: string;
    taskId?: string;
    budget?: ContextBudget;
    queryEmbedding?: number[];
    evaluationTime?: string;
  }): Promise<CompileResult>;
  compileGuarded(req: {
    tenantId?: string;
    actorId: string;
    scope: string;
    queryText: string;
    taskId?: string;
    budget?: ContextBudget;
    queryEmbedding?: number[];
    evaluationTime?: string;
    strictDisputes?: boolean;
    haltOnAnyDispute?: boolean;
  }): Promise<CompileResult>;
  replay(req: {
    tenantId?: string;
    actorId: string;
    scope: string;
    queryText: string;
    taskId?: string;
    budget?: ContextBudget;
    evaluationTime?: string;
    counterfactualEvaluationTime?: string;
    overrideMinConfidence?: number;
    overrideDecisivenessThreshold?: number;
    overridePolicyCedar?: string;
  }): Promise<Record<string, any>>;
  exportBundle(bundleHash: string, mode?: ExportMode): Promise<Record<string, any>>;
  verifyBundleOffline(bundleHash: string, expectedPubkeyHex?: string, mode?: ExportMode): Promise<VerificationSummary>;
}

export declare class ActaGeminiGuard {
  constructor(
    actaClient: ActaClient,
    genaiClient?: any,
    options?: { defaultModel?: string; strictDisputes?: boolean; haltOnAnyDispute?: boolean }
  );
  generateContent<T = unknown>(params: {
    tenantId?: string;
    actorId: string;
    scope: string;
    prompt: string;
    model?: string;
    taskId?: string;
    budget?: ContextBudget;
    config?: Record<string, any>;
    llmCallable?: (fullPrompt: string, compiled: CompileResult) => Promise<T> | T;
  }): Promise<GuardedGenerationResult<T>>;
}
