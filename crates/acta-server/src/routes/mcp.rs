use acta_crypto::{dump_archive_preimages, verify_export_archive, verify_signed_tree_head};
use acta_engine::{encode_token_spans, ResolverConfig};
use acta_store::{evidence_repo, overrides_repo};
use acta_types::{
    validate_budget, validate_identifier, validate_priority, validate_provenance_class,
    validate_query_text, validate_scope, AnchorCheckpointRequest, AttestOverrideRequest,
    CacheAnswerRequest, CompileRequest, ContextBudget, IngestClaimRequest, IngestObjectRequest,
    LifecycleStatus, LookupCachedAnswerRequest, ObjectType, PolicyDecision, PolicyResultTag,
    RegisterWitnessRequest, RetractClaimRequest, RevokeWitnessRequest,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::routes::{
    answers::{
        handle_cache_answer, handle_lookup_cached_answer, handle_rebuild_scope_state,
        handle_trace_item_impact, RebuildStateQueryParams,
    },
    checkpoints::{
        handle_anchor_checkpoint, handle_get_checkpoint, handle_register_witness,
        handle_revoke_witness, CheckpointQueryParams,
    },
    compile::handle_compile,
    export::build_export_archive_scoped,
    ingest::{handle_ingest_claim, handle_ingest_object, handle_retract_claim},
    oauth::apply_oauth_cors,
    overrides::handle_attest_override,
    verify::{handle_tenant_evidence, EvidenceQueryParams},
};
use crate::state::{AppState, BundleTenantFilter, VerifiedKeyInfo};

fn mcp_tools_schema() -> Value {
    json!([
        {
            "name": "acta_whoami",
            "description": "Returns the verified GitHub organization / tenant vault and OAuth principal locked to this MCP session, active resolver thresholds, host Ed25519 verifying key, Cedar permission root, latest RFC 6962 §2.1 SHA-256 SignedTreeHead checkpoint, cached_answer_count, active vs. lapsed vs. superseded override counts, active & revoked witnesses, full quarantined_anchors rows, and recent signed evidence_history entries.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "acta_compile_context",
            "description": "Compiles a deterministic, Ed25519-signed ContextBundle binding resolver_manifest inside the bundle, indexing every referenced claim/object in bundle_dependencies for O(k) impact recall, returning explicit cl100k_base context_token_count (with exact BPE context_token_ids + context_token_bytes_hex automatically populated whenever context_token_count <= 256 or include_token_spans=true), preserving compact override why=\"…\" justifications under tight token budgets, and surfacing LapsedOverrideRef provenance when unseen evidence reopens a prior override.",
            "inputSchema": {
                "type": "object",
                "required": ["scope", "query_text"],
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Optional when authenticated via GitHub OAuth 2.1 or acta_tk_v1 key; if provided, must match the locked organization."
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Agent identifier (e.g. 'claude', 'cursor', 'gemini'); defaults to '<org>::mcp-agent'."
                    },
                    "task_id": { "type": "string", "default": "mcp-task" },
                    "scope": { "type": "string" },
                    "query_text": { "type": "string" },
                    "token_budget": { "type": "integer", "minimum": 1, "maximum": 128000, "default": 2048 },
                    "evaluation_time": {
                        "type": "string",
                        "description": "Optional RFC 3339 UTC timestamp; when omitted, defaults to the scope's deterministic state watermark."
                    },
                    "include_token_spans": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, returns exact cl100k_base context_token_ids and context_token_bytes_hex partitioning context_text byte-for-byte."
                    }
                }
            }
        },
        {
            "name": "acta_ingest_object",
            "description": "Appends an immutable versioned intent or memory object (enforcing Policy-Before-Write), verifies optional Ed25519 author signature (acta:object_client_sig:v1 or content_hash), and atomically notarizes a strip-proof WriteLedgerSummary (acta:evidence_event:v3) on evidence_history.",
            "inputSchema": {
                "type": "object",
                "required": ["obj_type", "scope", "body"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "obj_type": { "type": "string", "enum": ["intent", "memory"] },
                    "scope": { "type": "string" },
                    "lifecycle_status": {
                        "type": "string",
                        "enum": ["active", "archived", "revoked"],
                        "default": "active"
                    },
                    "priority": { "type": "integer", "minimum": -1000, "maximum": 1000, "default": 50 },
                    "importance": { "type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.8 },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "body": { "type": "object" },
                    "predecessor_id": {
                        "type": "string",
                        "description": "Optional UUID of an earlier object in the same (scope, obj_type) to supersede explicitly."
                    },
                    "client_signature_hex": {
                        "type": "string",
                        "description": "Optional 64-byte Ed25519 author signature (128 hex chars) over compute_object_client_intent_hash (acta:object_client_sig:v1) or content_hash."
                    },
                    "client_public_key_hex": {
                        "type": "string",
                        "description": "Optional 32-byte Ed25519 author public key (64 hex chars) paired with client_signature_hex."
                    }
                }
            }
        },
        {
            "name": "acta_ingest_claim",
            "description": "Appends or supersedes a versioned structured knowledge claim (enforcing Policy-Before-Write, value-type bounds, explicit predecessor_id / contradiction_ids / valid_from / valid_to, and optional Ed25519 author signature over acta:claim_client_sig:v1), and atomically notarizes a strip-proof WriteLedgerSummary (acta:evidence_event:v3) on evidence_history.",
            "inputSchema": {
                "type": "object",
                "required": ["scope", "subject", "predicate", "object_val", "object_type", "confidence", "source_descriptor"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "subject": { "type": "string" },
                    "predicate": { "type": "string" },
                    "object_val": {
                        "description": "Claim value matching object_type (number/currency/percentage/integer, string/enum/date/uri, boolean, array, or object)."
                    },
                    "object_type": { "type": "string" },
                    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "source_provenance_class": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10,
                        "default": 2,
                        "description": "Authority tie-breaker tier in [0, 10]."
                    },
                    "source_descriptor": { "type": "string" },
                    "source_content": {
                        "type": "string",
                        "description": "Optional raw source document excerpt/text to bind into source_commitment via BLAKE3(acta:source_content:v1, source_descriptor, source_content)."
                    },
                    "source_commitment_hex": {
                        "type": "string",
                        "description": "Optional explicit 32-byte (64-hex) cryptographic commitment over the upstream source artifact."
                    },
                    "status": {
                        "type": "string",
                        "enum": ["active", "superseded", "revoked", "archived"],
                        "default": "active"
                    },
                    "predecessor_id": {
                        "type": "string",
                        "description": "Optional UUID of an earlier claim in the same (scope, subject, predicate) that this claim explicitly supersedes."
                    },
                    "contradiction_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional UUIDs of claims in the same scope explicitly contradicted by this claim (forces BLOCKING_CONTRADICTION dispute while target claim remains active)."
                    },
                    "valid_from": {
                        "type": "string",
                        "description": "Optional RFC 3339 UTC timestamp from which this claim is temporally valid."
                    },
                    "valid_to": {
                        "type": "string",
                        "description": "Optional RFC 3339 UTC timestamp until which this claim is temporally valid (must be >= valid_from)."
                    },
                    "client_signature_hex": {
                        "type": "string",
                        "description": "Optional 64-byte Ed25519 author signature (128 hex chars) over compute_claim_client_intent_hash (acta:claim_client_sig:v1) or content_hash."
                    },
                    "client_public_key_hex": {
                        "type": "string",
                        "description": "Optional 32-byte Ed25519 author public key (64 hex chars) paired with client_signature_hex."
                    }
                }
            }
        },
        {
            "name": "acta_retract_claim",
            "description": "Appends an immutable status='revoked' tombstone retiring claim_id (predecessor_id = claim_id) without mutating historical rows, verifies optional Ed25519 author signature (acta:retract_client_sig:v1), and notarizes WriteOperationKind::RetractClaim on evidence_history.",
            "inputSchema": {
                "type": "object",
                "required": ["claim_id", "reason"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "claim_id": {
                        "type": "string",
                        "description": "UUID of the claim to retract."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Single-line evidentiary reason why claim_id is retracted."
                    },
                    "client_signature_hex": {
                        "type": "string",
                        "description": "Optional 64-byte Ed25519 signature (128 hex chars) over compute_retract_claim_client_intent_hash (acta:retract_client_sig:v1)."
                    },
                    "client_public_key_hex": {
                        "type": "string",
                        "description": "Optional 32-byte Ed25519 public key (64 hex chars) paired with client_signature_hex."
                    }
                }
            }
        },
        {
            "name": "acta_attest_override",
            "description": "Cryptographically notarizes a dispute adjudication under acta:override:v2 (binding adjudicator_auth_kind, client_public_key, and client_signature directly into attestation_hash -> host_signature). Omit adjudicator_id to bind your verified GitHub OAuth 2.1 login (<tenant>::oauth:<github_login>); claiming a custom third-party/committee adjudicator_id or attesting on regulated/* scopes requires a valid 64-byte Ed25519 client_signature_hex + client_public_key_hex over acta:override_client_sig:v1.",
            "inputSchema": {
                "type": "object",
                "required": ["scope", "winning_claim_id", "justification"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "winning_claim_id": {
                        "type": "string",
                        "description": "UUID of the competing active claim adjudicated as authoritative."
                    },
                    "source_bundle_hash": {
                        "type": "string",
                        "description": "Optional 64-char hex bundle_hash where the [DISPUTE] was surfaced."
                    },
                    "adjudicator_id": {
                        "type": "string",
                        "description": "Optional; omit to attest as your verified GitHub OAuth identity (<tenant>::oauth:<github_login>). Custom committee/third-party IDs require client_signature_hex + client_public_key_hex."
                    },
                    "justification": {
                        "type": "string",
                        "description": "Single-line evidentiary justification citing why winning_claim_id supersedes the competing claim(s)."
                    },
                    "client_signature_hex": {
                        "type": "string",
                        "description": "64-byte Ed25519 signature (128 hex chars) over compute_override_client_intent_hash (acta:override_client_sig:v1)."
                    },
                    "client_public_key_hex": {
                        "type": "string",
                        "description": "32-byte Ed25519 public key (64 hex chars) corresponding to client_signature_hex."
                    }
                }
            }
        },
        {
            "name": "acta_cache_answer",
            "description": "Persists a state- or dependency-conditioned cached answer bound to a compiled ContextBundle (source_bundle_hash) and notarizes a signed AnswerCacheLedgerSummary (acta:answer_cache:v1 inside acta:evidence_event:v3) on evidence_history (PPA 1 Claims 19–27). Defaults to Claim 25 validity_mode='dependency_subset' (acta:cache_dep_root:v1) so unrelated writes in the same scope do not invalidate cached answers.",
            "inputSchema": {
                "type": "object",
                "required": ["source_bundle_hash", "answer_text"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "scope": {
                        "type": "string",
                        "description": "Optional scope; when provided, verified against source_bundle_hash's compiled scope."
                    },
                    "task_id": {
                        "type": "string",
                        "description": "Optional task_id; when provided, verified against source_bundle_hash's task_id."
                    },
                    "query_text": {
                        "type": "string",
                        "default": "",
                        "description": "Query string hashed via BLAKE3(acta:query:v1, query_text) for exact cache lookup."
                    },
                    "source_bundle_hash": {
                        "type": "string",
                        "description": "64-char hex bundle_hash of the compiled ContextBundle under which answer_text was produced."
                    },
                    "validity_mode": {
                        "type": "string",
                        "enum": ["dependency_subset", "scope_root"],
                        "default": "dependency_subset",
                        "description": "PPA 1 Claim 25 validity mode: 'dependency_subset' (default) invalidates only when referenced claim groups, incoming contradictions, selected memories, intents, or permissions change; 'scope_root' invalidates on any scope-wide state_commitment change."
                    },
                    "dependency_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional subset of claim/memory UUIDs from source_bundle_hash to narrow dependency_subset tracking further."
                    },
                    "answer_text": {
                        "type": "string",
                        "description": "Synthesized answer text hashed via BLAKE3(acta:answer:v1, answer_text) and re-verified before every cache hit."
                    },
                    "answer_metadata": {
                        "type": "object",
                        "description": "Optional structured JSON metadata stored alongside the cached answer."
                    },
                    "ttl_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 31536000,
                        "description": "Optional TTL in seconds (in addition to automatic O(1) commitment invalidation)."
                    },
                    "client_signature_hex": {
                        "type": "string",
                        "description": "Optional 64-byte Ed25519 signature (128 hex chars) over compute_answer_cache_client_intent_hash (acta:answer_client_sig:v1) or answer_hash."
                    },
                    "client_public_key_hex": {
                        "type": "string",
                        "description": "Optional 32-byte Ed25519 public key (64 hex chars) paired with client_signature_hex."
                    }
                }
            }
        },
        {
            "name": "acta_lookup_cached_answer",
            "description": "Looks up a state- or dependency-conditioned cached answer enforcing Policy-Before-Read, Claim 25 dependency_subset / scope_root commitment check, BLAKE3 answer_hash + Ed25519 host receipt verification, and one-time chained invalidation receipts (event_kind='invalidated' on evidence_history, returning invalidation_evidence_seq_num and invalidation_newly_recorded; PPA 1 Claims 19–27).",
            "inputSchema": {
                "type": "object",
                "required": ["scope"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "actor_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "task_id": { "type": "string", "default": "mcp-task" },
                    "query_text": { "type": "string", "default": "" }
                }
            }
        },
        {
            "name": "acta_trace_claim_impact",
            "description": "Executes an O(k) indexed reverse decision-recall lookup over bundle_dependencies and cached_answers for any claim or object UUID (item_id), returning its lifecycle status, superseding/retraction lineage, every historical ContextBundle that depended on it (with dependency_role and is_stale_now), and every cached answer derived from those bundles.",
            "inputSchema": {
                "type": "object",
                "required": ["item_id"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "item_id": {
                        "type": "string",
                        "description": "UUID of the structured claim or intent/memory object to trace across historical bundles and cached answers."
                    }
                }
            }
        },
        {
            "name": "acta_verify_state_rebuild",
            "description": "Cryptographically verifies the tenant's hash-chained evidence_history (v1/v2/v3) from seq 1..=up_to_seq and reconstructs active scope state and state_commitment from signed ledger events alone (PPA 1 Claim 1 & §11). Set include_proof_archive=true to export a portable StateRebuildArchive ('acta-state-rebuild-archive/v1') for standalone offline verification via acta-verify or acta_sdk.",
            "inputSchema": {
                "type": "object",
                "required": ["scope"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "up_to_seq": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional 1-based evidence_history prefix sequence number; defaults to latest ledger head."
                    },
                    "include_proof_archive": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, embeds rebuild_proof_archive (StateRebuildArchive) carrying evidence_chain, checkpoint, latest_anchored_checkpoint, consistency_proof_from_latest_anchor, and strip-checked override_attestations for offline acta-verify reconstruction."
                    }
                }
            }
        },
        {
            "name": "acta_replay_counterfactual",
            "description": "Simulates a time-pinned read-only counterfactual compile (filtering objects, claims, overrides, and supersessions to created_at <= pinned_evaluation_time) without mutating evidence_history on Allow. Returns replay_valid, resolution_changed (true iff resolved facts or disputed groups flip), bundle_hash_changed, state_commitment_changed, and explicit DisputeRecord.margin + LAPSED_OVERRIDE_REOPENED diagnostics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_bundle_hash": {
                        "type": "string",
                        "description": "Optional 64-char hex bundle_hash from an earlier compile."
                    },
                    "tenant_id": { "type": "string" },
                    "actor_id": { "type": "string" },
                    "task_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "query_text": { "type": "string" },
                    "token_budget": { "type": "integer", "minimum": 1, "maximum": 128000, "default": 2048 },
                    "evaluation_time": { "type": "string" },
                    "override_min_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "override_decisiveness_threshold": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
                }
            }
        },
        {
            "name": "acta_verify_bundle",
            "description": "Exports a persisted ContextBundle and runs full Ed25519 + RFC 8785 JCS + BLAKE3 + RFC 6962 §2.1 SHA-256 Merkle inclusion + cross-checkpoint witness bridging (anchored_checkpoint + consistency_proof_to_anchor) + resolver_manifest + author Ed25519 signatures + write_summary (acta:write_event:v1) + answer_cache_summary (acta:answer_cache:v1) + override v1/v2 + refusal_metadata + witness_reg_summary (v1/v2/v3) + witness_revoke_summary (v1/v2) verification. Supports proof_mode='merkle', selectable bridge target via anchor_tree_size (or alias anchored_tree_size), and dump_preimages=true.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["bundle_hash"],
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Optional when authenticated via GitHub OAuth 2.1 or acta_tk_v1 key; if provided, must match the locked organization."
                    },
                    "bundle_hash": { "type": "string", "description": "64-character hex bundle hash" },
                    "proof_mode": {
                        "type": "string",
                        "enum": ["full", "merkle"],
                        "default": "full",
                        "description": "'full' verifies the complete 1..=seq_num evidence_chain in server memory plus Merkle proof and returns a paginated evidence_chain slice; 'merkle' builds and verifies an O(log N) MerkleBundleProof (including write_entry_proofs and override_entry_proofs) with empty evidence_chain."
                    },
                    "from_seq": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1,
                        "description": "Starting 1-based evidence_chain sequence number returned in full mode (verification always checks 1..=seq_num)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 100,
                        "description": "Maximum evidence_chain entries returned per page in full mode (1..=500, default 100)."
                    },
                    "anchor_tree_size": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional newer checkpoint tree_size >= bundle seq_num to bridge via an O(log N) RFC 6962 consistency proof; when omitted, automatically bridges to the latest active witness-anchored checkpoint if one exists."
                    },
                    "anchored_tree_size": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Alias for anchor_tree_size (selects the target checkpoint tree_size >= bundle seq_num to bridge via an O(log N) RFC 6962 consistency proof)."
                    },
                    "include_archive": {
                        "type": "boolean",
                        "default": true
                    },
                    "dump_preimages": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, includes exact raw BLAKE3/SHA-256 byte preimages (*_preimage_hex) and canonical JCS UTF-8 (with null client_sig_* on unsigned overrides)."
                    }
                }
            }
        },
        {
            "name": "acta_list_evidence",
            "description": "Lists a paginated slice (default limit=100, max 500) of the append-only Ed25519-signed evidence_history chain (including total_count, next_seq, per-entry event_domain v1/v2/v3, write_summary, answer_cache_summary, refusal_metadata, override_summary, witness_reg_summary, and witness_revoke_summary) for your locked organization vault.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tenant_id": { "type": "string" },
                    "from_seq": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1,
                        "description": "1-based starting evidence seq_num (default 1)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 100,
                        "description": "Maximum entries to return in this page (1..=500, default 100)."
                    }
                }
            }
        },
        {
            "name": "acta_get_checkpoint",
            "description": "Returns the deterministic Ed25519-signed RFC 6962 §2.1 SHA-256 Merkle SignedTreeHead checkpoint for your vault (at latest head or optional tree_size), plus an O(log N) Merkle consistency_proof from since_size proving append-only prefix integrity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tenant_id": { "type": "string" },
                    "tree_size": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional ledger size N (defaults to latest head)."
                    },
                    "since_size": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional earlier checkpoint size M <= tree_size to generate an RFC 6962 consistency proof."
                    }
                }
            }
        },
        {
            "name": "acta_register_witness",
            "description": "Enrolls an immutable trusted external witness Ed25519 public key in trusted_witnesses (notarizing principal- and description-bound acta:witness_reg:v3 in evidence_history) so checkpoints can only be cosigned by pre-registered active witnesses.",
            "inputSchema": {
                "type": "object",
                "required": ["witness_id", "witness_public_key_hex"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "witness_id": { "type": "string", "description": "Unique identifier for the trusted witness (e.g. 'rekor-mirror-1', 'cfo-notary-v1')." },
                    "witness_public_key_hex": { "type": "string", "description": "32-byte Ed25519 public key (64 hex chars) to pin for witness_id." },
                    "description": { "type": "string", "description": "Optional human-readable description bound into acta:witness_reg:v3." }
                }
            }
        },
        {
            "name": "acta_revoke_witness",
            "description": "Revokes (mode='compromise', default) or gracefully retires (mode='retire') an enrolled external witness via append-only witness_revocations (notarizing mode-bound acta:witness_revoke:v2 in evidence_history without mutating trusted_witnesses). Both modes block all future anchors from witness_id; 'compromise' retroactively quarantines all historical cosignatures, whereas 'retire' preserves valid historical cosignatures at tree_size < effective_from_tree_size.",
            "inputSchema": {
                "type": "object",
                "required": ["witness_id", "reason"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "witness_id": { "type": "string", "description": "Identifier of the enrolled witness to revoke or retire." },
                    "mode": {
                        "type": "string",
                        "enum": ["compromise", "retire"],
                        "default": "compromise",
                        "description": "'compromise' retroactively quarantines all anchors from witness_id; 'retire' preserves historical anchors at tree_size < effective_from_tree_size while blocking future anchors."
                    },
                    "revocation_mode": {
                        "type": "string",
                        "enum": ["compromise", "retire"],
                        "description": "Alias for mode ('compromise' or 'retire')."
                    },
                    "reason": { "type": "string", "description": "Single-line evidentiary reason for revoking or retiring witness_id." }
                }
            }
        },
        {
            "name": "acta_anchor_checkpoint",
            "description": "Records an immutable external witness Ed25519 cosignature (acta:witness_sig:v1) anchoring a SignedTreeHead checkpoint at (tenant_id, tree_size, checkpoint_hash). Requires witness_id + witness_public_key_hex to be active (non-revoked) in trusted_witnesses.",
            "inputSchema": {
                "type": "object",
                "required": ["tree_size", "checkpoint_hash", "witness_id", "witness_public_key_hex", "witness_signature_hex"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "tree_size": { "type": "integer", "minimum": 1 },
                    "checkpoint_hash": { "type": "string", "description": "64-char hex checkpoint_hash from acta_get_checkpoint." },
                    "witness_id": { "type": "string", "description": "Active enrolled witness identifier in trusted_witnesses." },
                    "witness_public_key_hex": { "type": "string", "description": "32-byte Ed25519 public key (64 hex chars) matching trusted_witnesses." },
                    "witness_signature_hex": { "type": "string", "description": "64-byte Ed25519 signature (128 hex chars) over witness_anchor_signing_preimage." },
                    "external_uri": { "type": "string", "description": "Optional transparency log / anchor URI." }
                }
            }
        }
    ])
}

fn parse_mcp_token_budget(raw_val: Option<&Value>) -> Result<ContextBudget, String> {
    let Some(val) = raw_val else {
        return Ok(ContextBudget::Tokens(2048));
    };
    if val.is_null() {
        return Ok(ContextBudget::Tokens(2048));
    }
    let n = val
        .as_i64()
        .ok_or_else(|| format!("token_budget must be a positive integer, got {val}"))?;
    if n <= 0 {
        return Err(format!("token_budget must be >= 1 (got {n})"));
    }
    let budget = ContextBudget::Tokens(usize::try_from(n).map_err(|_| "token_budget overflow")?);
    validate_budget(budget).map_err(|e| e.to_string())?;
    Ok(budget)
}

fn build_mcp_oauth_401(state: &AppState, headers: &HeaderMap, detail: &str) -> Response {
    let base = state.resolve_public_base_url(headers);
    let prm_url = format!("{base}/.well-known/oauth-protected-resource");
    let www_auth = format!(
        "Bearer realm=\"acta-mcp\", resource_metadata=\"{prm_url}\", scope=\"mcp:tools\""
    );
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "unauthorized",
            "error_description": detail,
            "resource_metadata": prm_url,
            "authorization_server": format!("{base}/.well-known/oauth-authorization-server"),
        })),
    )
        .into_response();
    if let Ok(hv) = HeaderValue::from_str(&www_auth) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    apply_oauth_cors(resp)
}

async fn resolve_mcp_actor_audited(
    state: &AppState,
    headers: &HeaderMap,
    resolved_tenant: &str,
    raw_actor: Option<&str>,
) -> Result<String, String> {
    let Some(actor) = raw_actor.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(format!("{resolved_tenant}::mcp-agent"));
    };
    validate_identifier("actor_id", actor).map_err(|e| e.to_string())?;
    if let Some((explicit_tenant, _local)) = actor.split_once("::") {
        if explicit_tenant != resolved_tenant {
            let msg = format!(
                "actor_id '{actor}' belongs to tenant '{explicit_tenant}', cannot act in locked tenant '{resolved_tenant}'"
            );
            if let Some(ev) = state
                .append_refusal_audit_with_scope(
                    headers,
                    Some(resolved_tenant),
                    PolicyResultTag::Block,
                    "mcp_actor_gate",
                    "mcp_actor_tenant_mismatch",
                    None,
                    &msg,
                )
                .await
            {
                return Err(format!("{msg} [logged at evidence seq_num={}]", ev.seq_num));
            }
            return Err(msg);
        }
        Ok(actor.to_string())
    } else {
        Ok(format!("{resolved_tenant}::{actor}"))
    }
}

fn parse_optional_rfc3339_field(
    field_name: &str,
    raw: Option<&str>,
) -> Result<Option<DateTime<Utc>>, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(s)
        .map(|dt| Some(dt.with_timezone(&Utc).trunc_subsecs(6)))
        .map_err(|e| format!("invalid {field_name} RFC 3339 timestamp '{s}': {e}"))
}

fn parse_optional_rfc3339(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, String> {
    parse_optional_rfc3339_field("evaluation_time", raw)
}

fn parse_optional_uuid_field(field_name: &str, val: Option<&Value>) -> Result<Option<Uuid>, String> {
    match val {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Uuid::parse_str(trimmed)
                    .map(Some)
                    .map_err(|e| format!("invalid {field_name} UUID '{trimmed}': {e}"))
            }
        }
        Some(other) => Err(format!("{field_name} must be a UUID string, got {other}")),
    }
}

pub async fn handle_mcp_delete() -> Response {
    apply_oauth_cors(StatusCode::OK.into_response())
}

pub async fn handle_mcp_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("text/event-stream") {
        match state.mcp_requires_oauth_challenge(&headers) {
            Ok(true) => {
                return build_mcp_oauth_401(
                    &state,
                    &headers,
                    "Sign in with GitHub OAuth 2.1 to connect to your organization vault.",
                );
            }
            Err(err) => {
                return build_mcp_oauth_401(&state, &headers, &err);
            }
            Ok(false) => {
                return apply_oauth_cors(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
        }
    }

    let (locked_tenant, verified_principal) = state
        .inspect_caller_auth(&headers)
        .ok()
        .map(|info| match info {
            VerifiedKeyInfo::TenantBound {
                locked_tenant,
                verified_principal,
            } => (Some(locked_tenant), verified_principal),
            VerifiedKeyInfo::Master {
                header_locked_tenant,
            }
            | VerifiedKeyInfo::Anonymous {
                header_locked_tenant,
            } => (header_locked_tenant, None),
        })
        .unwrap_or((None, None));

    let base = state.resolve_public_base_url(&headers);
    let body = json!({
        "protocol": "mcp-streamable-http",
        "protocolVersion": "2025-11-25",
        "oauth": {
            "enabled": true,
            "github_oauth_configured": state.oauth.github_enabled(),
            "protected_resource_metadata": format!("{base}/.well-known/oauth-protected-resource"),
            "authorization_server_metadata": format!("{base}/.well-known/oauth-authorization-server"),
        },
        "serverInfo": {
            "name": "acta-compiler-mcp",
            "version": "1.7.1",
            "merkle_checkpoint_scheme": "rfc6962-sha256-v1",
            "host_public_key": hex::encode(state.host_public_key),
            "permission_root": hex::encode(state.policy_gate.permission_root()),
            "locked_tenant": locked_tenant,
            "verified_principal": verified_principal,
        },
        "tools": mcp_tools_schema()
    });
    apply_oauth_cors((StatusCode::OK, Json(body)).into_response())
}

fn jsonrpc_ok(id: Value, result: Value) -> Response {
    apply_oauth_cors(
        (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })),
        )
            .into_response(),
    )
}

fn jsonrpc_err(id: Value, code: i64, msg: impl Into<String>) -> Response {
    apply_oauth_cors(
        (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": code,
                    "message": msg.into()
                }
            })),
        )
            .into_response(),
    )
}

pub async fn handle_mcp_rpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rpc): Json<Value>,
) -> Response {
    match state.mcp_requires_oauth_challenge(&headers) {
        Ok(true) => {
            return build_mcp_oauth_401(
                &state,
                &headers,
                "Sign in with GitHub OAuth 2.1 to connect Claude or Cursor to your GitHub organization vault.",
            );
        }
        Err(err) => {
            return build_mcp_oauth_401(&state, &headers, &err);
        }
        Ok(false) => {}
    }

    let has_id = rpc.get("id").is_some();
    let id = rpc.get("id").cloned().unwrap_or(Value::Null);
    let method = rpc.get("method").and_then(Value::as_str).unwrap_or("");

    match method {
        "initialize" => {
            let requested_ver = rpc
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("2025-06-18");
            let negotiated_ver = match requested_ver {
                "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25" | "2026-07-28" => {
                    requested_ver
                }
                _ => "2025-11-25",
            };
            jsonrpc_ok(
                id,
                json!({
                    "protocolVersion": negotiated_ver,
                    "capabilities": {
                        "tools": {
                            "listChanged": true
                        }
                    },
                    "serverInfo": {
                        "name": "acta-compiler-mcp",
                        "version": "1.7.1"
                    }
                }),
            )
        }
        "notifications/initialized" => {
            if has_id {
                jsonrpc_ok(id, json!({}))
            } else {
                apply_oauth_cors(StatusCode::ACCEPTED.into_response())
            }
        }
        "ping" => jsonrpc_ok(id, json!({})),
        "tools/list" => jsonrpc_ok(id, json!({ "tools": mcp_tools_schema() })),
        "resources/list" => jsonrpc_ok(id, json!({ "resources": [] })),
        "prompts/list" => jsonrpc_ok(id, json!({ "prompts": [] })),
        "tools/call" => {
            let params = rpc.get("params").cloned().unwrap_or_else(|| json!({}));
            let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

            match dispatch_mcp_tool(state, headers, tool_name, args).await {
                Ok(payload) => jsonrpc_ok(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                        }],
                        "structuredContent": payload,
                        "isError": false
                    }),
                ),
                Err(err_msg) => jsonrpc_ok(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("ERROR: {err_msg}")
                        }],
                        "isError": true
                    }),
                ),
            }
        }
        other => jsonrpc_err(id, -32601, format!("unsupported MCP method: {other}")),
    }
}

async fn dispatch_mcp_tool(
    state: AppState,
    headers: HeaderMap,
    tool_name: &str,
    args: Value,
) -> Result<Value, String> {
    match tool_name {
        "acta_whoami" => {
            let info = state.inspect_caller_auth(&headers)?;
            let (key_kind, locked_tenant, verified_principal) = match info {
                VerifiedKeyInfo::TenantBound {
                    locked_tenant,
                    verified_principal,
                } => {
                    let kind = if verified_principal.is_some() {
                        "oauth_user_tenant_bound_blake3_mac"
                    } else {
                        "tenant_bound_blake3_mac"
                    };
                    (kind, Some(locked_tenant), verified_principal)
                }
                VerifiedKeyInfo::Master {
                    header_locked_tenant,
                } => ("master", header_locked_tenant, None),
                VerifiedKeyInfo::Anonymous {
                    header_locked_tenant,
                } => ("anonymous_sandbox", header_locked_tenant, None),
            };

            let (
                evidence_entry_count,
                recent_evidence_entries,
                cached_answer_count,
                active_override_count,
                lapsed_override_count,
                superseded_override_count,
                trusted_witness_count,
                trusted_witnesses,
                revoked_witness_count,
                compromised_witness_count,
                retired_witness_count,
                retired_witnesses,
                revoked_witnesses,
                quarantined_anchor_count,
                quarantined_anchors,
                latest_checkpoint,
                head_witnessed,
                latest_anchored_checkpoint,
                consistency_proof_from_latest_anchor,
                latest_anchor_consistency_verified,
                cache_invalidation_count,
            ) = if let Some(ref tid) = locked_tenant {
                let ev_count_fut = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint FROM evidence_history WHERE tenant_id = $1",
                )
                .bind(tid)
                .fetch_one(&state.pool);
                let ca_count_fut = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint FROM cached_answers WHERE tenant_id = $1",
                )
                .bind(tid)
                .fetch_one(&state.pool);
                let ov_fut =
                    overrides_repo::fetch_tenant_overrides_classified(&state.pool, tid, None);
                let tw_fut = evidence_repo::fetch_tenant_trusted_witnesses(&state.pool, tid);
                let qa_fut = evidence_repo::fetch_quarantined_witness_anchors(&state.pool, tid);
                let cai_count_fut = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint FROM cached_answer_invalidations WHERE tenant_id = $1",
                )
                .bind(tid)
                .fetch_one(&state.pool);
                let cp_fut = evidence_repo::build_signed_tree_head(
                    &state.pool,
                    &state.host_signing_key,
                    tid,
                    None,
                );
                let (ev_cnt_res, ca_cnt_res, cai_cnt_res, ov_res, tw_res, qa_res, cp_res) =
                    tokio::join!(ev_count_fut, ca_count_fut, cai_count_fut, ov_fut, tw_fut, qa_fut, cp_fut);

                let (total, tail) = match ev_cnt_res {
                    Ok(total_i64) => {
                        let total_usize = total_i64.max(0) as usize;
                        if total_i64 <= 0 {
                            (Some(0), Some(Vec::new()))
                        } else {
                            let start_seq = (total_i64 - 19).max(1);
                            match evidence_repo::fetch_tenant_evidence_page(
                                &state.pool,
                                tid,
                                start_seq,
                                20,
                                None,
                            )
                            .await
                            {
                                Ok((cnt, page)) => (Some(cnt), Some(page)),
                                Err(_) => (Some(total_usize), None),
                            }
                        }
                    }
                    Err(_) => (None, None),
                };
                let ca_cnt = ca_cnt_res.ok().map(|n| n.max(0) as usize);
                let (act_cnt, lap_cnt, sup_cnt) = match ov_res {
                    Ok(list) => {
                        let act = list
                            .iter()
                            .filter(|(_, st)| *st == overrides_repo::OverrideStateKind::Active)
                            .count();
                        let lap = list
                            .iter()
                            .filter(|(_, st)| *st == overrides_repo::OverrideStateKind::Lapsed)
                            .count();
                        let sup = list
                            .iter()
                            .filter(|(_, st)| *st == overrides_repo::OverrideStateKind::Superseded)
                            .count();
                        (Some(act), Some(lap), Some(sup))
                    }
                    Err(_) => (None, None, None),
                };
                let (tw_cnt, tw_list, rev_cnt, comp_cnt, ret_cnt, ret_list, rev_list) = match tw_res
                {
                    Ok(ws) => {
                        let mut active_ws = Vec::new();
                        let mut retired_ws = Vec::new();
                        let mut revoked_ws = Vec::new();
                        for w in ws {
                            if w.active {
                                active_ws.push(w);
                            } else {
                                if w.revocation_mode.as_deref() == Some("retire") {
                                    retired_ws.push(w.clone());
                                }
                                revoked_ws.push(w);
                            }
                        }
                        let total_rev = revoked_ws.len();
                        let total_ret = retired_ws.len();
                        let total_comp = total_rev.saturating_sub(total_ret);
                        (
                            Some(active_ws.len()),
                            Some(active_ws),
                            Some(total_rev),
                            Some(total_comp),
                            Some(total_ret),
                            Some(retired_ws),
                            Some(revoked_ws),
                        )
                    }
                    Err(_) => (None, None, None, None, None, None, None),
                };
                let (qa_cnt, qa_list) = match qa_res {
                    Ok(qas) => (Some(qas.len()), Some(qas)),
                    Err(_) => (None, None),
                };
                let cai_cnt = cai_cnt_res.ok().map(|n| n.max(0) as usize);
                let (cp, h_wit, lat_anch, lat_cons, lat_ok) = match cp_res.ok().flatten() {
                    Some((sth, leaves)) => {
                        let hw = !sth.witness_anchors.is_empty();
                        let (la, lc, lo) = evidence_repo::resolve_latest_anchored_for_head(
                            &state.pool,
                            &state.host_signing_key,
                            tid,
                            &sth,
                            &leaves,
                        )
                        .await
                        .unwrap_or((None, None, None));
                        (Some(sth), Some(hw), la, lc, lo)
                    }
                    None => (None, Some(false), None, None, None),
                };
                (
                    total, tail, ca_cnt, act_cnt, lap_cnt, sup_cnt, tw_cnt, tw_list, rev_cnt,
                    comp_cnt, ret_cnt, ret_list, rev_list, qa_cnt, qa_list, cp, h_wit, lat_anch,
                    lat_cons, lat_ok, cai_cnt,
                )
            } else {
                (
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None, None, None, None, None, None,
                )
            };

            let cfg = state.pipeline.config();
            Ok(json!({
                "connected": true,
                "version": "1.7.1",
                "merkle_checkpoint_scheme": "rfc6962-sha256-v1",
                "key_kind": key_kind,
                "locked_tenant": locked_tenant,
                "verified_principal": verified_principal,
                "github_oauth_enabled": state.oauth.github_enabled(),
                "host_public_key": hex::encode(state.host_public_key),
                "permission_root": hex::encode(state.policy_gate.permission_root()),
                "tokenizer": "cl100k_base (tiktoken-rs)",
                "resolver_defaults": {
                    "min_confidence": cfg.resolver.min_confidence,
                    "decisiveness_threshold": cfg.resolver.decisiveness_threshold,
                    "max_inline_omissions": cfg.max_inline_omissions,
                    "corroboration_formula": "min(0.9999, c_1 + (1.0 - c_1) * (1.0 - prod_{i>=2}(1.0 - 0.5 * c_i)))",
                },
                "head_witnessed": head_witnessed,
                "latest_checkpoint": latest_checkpoint,
                "latest_anchored_checkpoint": latest_anchored_checkpoint,
                "consistency_proof_from_latest_anchor": consistency_proof_from_latest_anchor,
                "latest_anchor_consistency_verified": latest_anchor_consistency_verified,
                "cached_answer_count": cached_answer_count,
                "cache_invalidation_count": cache_invalidation_count,
                "active_override_count": active_override_count,
                "lapsed_override_count": lapsed_override_count,
                "superseded_override_count": superseded_override_count,
                "trusted_witness_count": trusted_witness_count,
                "trusted_witnesses": trusted_witnesses,
                "revoked_witness_count": revoked_witness_count,
                "compromised_witness_count": compromised_witness_count,
                "retired_witness_count": retired_witness_count,
                "retired_witnesses": retired_witnesses,
                "revoked_witnesses": revoked_witnesses,
                "quarantined_anchor_count": quarantined_anchor_count,
                "quarantined_anchors": quarantined_anchors,
                "evidence_entry_count": evidence_entry_count,
                "recent_evidence_entries": recent_evidence_entries,
            }))
        }
        "acta_compile_context" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_compile_context",
                )
                .await?;
            let actor_id = resolve_mcp_actor_audited(
                &state,
                &headers,
                &tenant_id,
                args.get("actor_id").and_then(Value::as_str),
            )
            .await?;
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("mcp-task")
                .to_string();
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let query_text = args
                .get("query_text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let budget = parse_mcp_token_budget(args.get("token_budget"))?;
            let evaluation_time =
                parse_optional_rfc3339(args.get("evaluation_time").and_then(Value::as_str))?;
            let include_token_spans = args
                .get("include_token_spans")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let req = CompileRequest {
                tenant_id,
                actor_id,
                task_id,
                scope,
                query_text,
                query_embedding: None,
                budget,
                evaluation_time,
            };

            let (_status, Json(resp)) = handle_compile(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            let mut val = serde_json::to_value(&resp).map_err(|e| e.to_string())?;
            if include_token_spans && resp.context_token_ids.is_none() {
                if let Some(ref txt) = resp.context_text {
                    let (tok_ids, tok_bytes_hex) =
                        encode_token_spans(txt).map_err(|e| e.to_string())?;
                    val["context_token_ids"] = json!(tok_ids);
                    val["context_token_bytes_hex"] = json!(tok_bytes_hex);
                }
            }
            Ok(val)
        }
        "acta_ingest_object" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_ingest_object",
                )
                .await?;
            let obj_type_str = args
                .get("obj_type")
                .and_then(Value::as_str)
                .ok_or("missing obj_type")?;
            let obj_type = ObjectType::from_db_str(obj_type_str)?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let lifecycle_status = match args.get("lifecycle_status") {
                None | Some(Value::Null) => LifecycleStatus::Active,
                Some(Value::String(s)) if s.trim().is_empty() => LifecycleStatus::Active,
                Some(Value::String(s)) => LifecycleStatus::from_db_str(s.trim())?,
                Some(other) => {
                    return Err(format!(
                        "lifecycle_status must be a string ('active', 'archived', 'revoked'), got {other}"
                    ))
                }
            };
            let raw_priority = match args.get("priority") {
                Some(v) if !v.is_null() => v
                    .as_i64()
                    .ok_or_else(|| format!("priority must be an integer, got {v}"))?,
                _ => 50,
            };
            let priority = validate_priority(raw_priority).map_err(|e| e.to_string())?;
            let importance = args
                .get("importance")
                .and_then(Value::as_f64)
                .unwrap_or(0.8) as f32;
            let tags: Vec<String> = match args.get("tags") {
                Some(Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        let s = item
                            .as_str()
                            .ok_or("every element in tags must be a string")?;
                        out.push(s.to_string());
                    }
                    out
                }
                Some(Value::Null) | None => Vec::new(),
                _ => return Err("tags must be an array of strings".to_string()),
            };
            let body = args.get("body").cloned().unwrap_or_else(|| json!({}));
            let predecessor_id =
                parse_optional_uuid_field("predecessor_id", args.get("predecessor_id"))?;
            let client_signature_hex = args
                .get("client_signature_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_public_key_hex = args
                .get("client_public_key_hex")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = IngestObjectRequest {
                id: None,
                tenant_id,
                obj_type,
                scope,
                lifecycle_status,
                priority,
                importance,
                tags,
                body,
                embedding: None,
                predecessor_id,
                client_signature_hex,
                client_public_key_hex,
            };

            let (_status, Json(resp)) = handle_ingest_object(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_ingest_claim" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_ingest_claim",
                )
                .await?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let subject = args
                .get("subject")
                .and_then(Value::as_str)
                .ok_or("missing subject")?
                .to_string();
            let predicate = args
                .get("predicate")
                .and_then(Value::as_str)
                .ok_or("missing predicate")?
                .to_string();
            let object_val = args.get("object_val").cloned().ok_or("missing object_val")?;
            let object_type = args
                .get("object_type")
                .and_then(Value::as_str)
                .ok_or("missing object_type")?
                .to_string();
            let confidence = args
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or("missing confidence")?;
            let raw_prov = match args.get("source_provenance_class") {
                Some(v) if !v.is_null() => v.as_i64().ok_or_else(|| {
                    format!("source_provenance_class must be an integer, got {v}")
                })?,
                _ => 2,
            };
            let source_provenance_class =
                validate_provenance_class(raw_prov).map_err(|e| e.to_string())?;
            let source_descriptor = args
                .get("source_descriptor")
                .and_then(Value::as_str)
                .ok_or("missing source_descriptor")?
                .to_string();
            let source_commitment_hex = args
                .get("source_commitment_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let source_content = args
                .get("source_content")
                .and_then(Value::as_str)
                .map(str::to_string);
            let status = match args.get("status").or_else(|| args.get("lifecycle_status")) {
                None | Some(Value::Null) => LifecycleStatus::Active,
                Some(Value::String(s)) if s.trim().is_empty() => LifecycleStatus::Active,
                Some(Value::String(s)) => LifecycleStatus::from_db_str(s.trim())?,
                Some(other) => {
                    return Err(format!(
                        "status must be a string ('active', 'superseded', 'revoked', 'archived'), got {other}"
                    ))
                }
            };
            let predecessor_id =
                parse_optional_uuid_field("predecessor_id", args.get("predecessor_id"))?;
            let contradiction_ids: Vec<Uuid> = match args.get("contradiction_ids") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        let s = item
                            .as_str()
                            .ok_or("every element in contradiction_ids must be a UUID string")?;
                        let u = Uuid::parse_str(s.trim()).map_err(|e| {
                            format!("invalid UUID '{s}' in contradiction_ids: {e}")
                        })?;
                        out.push(u);
                    }
                    out
                }
                Some(other) => {
                    return Err(format!(
                        "contradiction_ids must be an array of UUID strings, got {other}"
                    ))
                }
            };
            let valid_from = parse_optional_rfc3339_field(
                "valid_from",
                args.get("valid_from").and_then(Value::as_str),
            )?;
            let valid_to = parse_optional_rfc3339_field(
                "valid_to",
                args.get("valid_to").and_then(Value::as_str),
            )?;
            let client_signature_hex = args
                .get("client_signature_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_public_key_hex = args
                .get("client_public_key_hex")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = IngestClaimRequest {
                id: None,
                tenant_id,
                scope,
                subject,
                predicate,
                object_val,
                object_type,
                confidence,
                source_provenance_class,
                source_descriptor,
                source_commitment_hex,
                source_content,
                status,
                contradiction_ids,
                valid_from,
                valid_to,
                predecessor_id,
                client_signature_hex,
                client_public_key_hex,
            };

            let (_status, Json(resp)) = handle_ingest_claim(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_retract_claim" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_retract_claim",
                )
                .await?;
            let raw_claim_id = args
                .get("claim_id")
                .and_then(Value::as_str)
                .ok_or("missing claim_id")?;
            let claim_id = Uuid::parse_str(raw_claim_id.trim())
                .map_err(|e| format!("invalid claim_id UUID '{raw_claim_id}': {e}"))?;
            let reason = args
                .get("reason")
                .and_then(Value::as_str)
                .ok_or("missing reason")?
                .to_string();
            let client_signature_hex = args
                .get("client_signature_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_public_key_hex = args
                .get("client_public_key_hex")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = RetractClaimRequest {
                id: None,
                tenant_id,
                claim_id,
                reason,
                client_signature_hex,
                client_public_key_hex,
            };

            let (_status, Json(resp)) = handle_retract_claim(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_attest_override" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_attest_override",
                )
                .await?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let raw_winner = args
                .get("winning_claim_id")
                .and_then(Value::as_str)
                .ok_or("missing winning_claim_id")?;
            let winning_claim_id = Uuid::parse_str(raw_winner.trim())
                .map_err(|e| format!("invalid winning_claim_id UUID '{raw_winner}': {e}"))?;
            let adjudicator_id = args
                .get("adjudicator_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let justification = args
                .get("justification")
                .and_then(Value::as_str)
                .ok_or("missing justification")?
                .to_string();
            let source_bundle_hash_hex = args
                .get("source_bundle_hash")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_signature_hex = args
                .get("client_signature_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_public_key_hex = args
                .get("client_public_key_hex")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = AttestOverrideRequest {
                id: None,
                tenant_id,
                scope,
                winning_claim_id,
                source_bundle_hash_hex,
                adjudicator_id,
                justification,
                client_signature_hex,
                client_public_key_hex,
            };

            let (_status, Json(resp)) = handle_attest_override(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_cache_answer" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_cache_answer",
                )
                .await?;
            let source_bundle_hash = args
                .get("source_bundle_hash")
                .and_then(Value::as_str)
                .ok_or("missing source_bundle_hash")?
                .to_string();
            let answer_text = args
                .get("answer_text")
                .and_then(Value::as_str)
                .ok_or("missing answer_text")?
                .to_string();
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .map(str::to_string);
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let query_text = args
                .get("query_text")
                .and_then(Value::as_str)
                .map(str::to_string);
            let answer_metadata = match args.get("answer_metadata") {
                None | Some(Value::Null) => None,
                Some(v @ Value::Object(_)) => Some(v.clone()),
                Some(other) => {
                    return Err(format!(
                        "answer_metadata must be a JSON object when provided, got {other}"
                    ))
                }
            };
            let ttl_seconds = match args.get("ttl_seconds") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let n = v.as_i64().ok_or_else(|| {
                        format!("ttl_seconds must be a positive integer, got {v}")
                    })?;
                    if n <= 0 {
                        return Err(format!("ttl_seconds must be >= 1 (got {n})"));
                    }
                    Some(u64::try_from(n).map_err(|_| "ttl_seconds overflow")?)
                }
            };
            let client_signature_hex = args
                .get("client_signature_hex")
                .and_then(Value::as_str)
                .map(str::to_string);
            let client_public_key_hex = args
                .get("client_public_key_hex")
                .and_then(Value::as_str)
                .map(str::to_string);

            let validity_mode = args
                .get("validity_mode")
                .and_then(Value::as_str)
                .map(str::to_string);
            let dependency_ids = match args.get("dependency_ids") {
                None | Some(Value::Null) => None,
                Some(Value::Array(arr)) => {
                    let mut ids = Vec::with_capacity(arr.len());
                    for item in arr {
                        let s = item
                            .as_str()
                            .ok_or("every element in dependency_ids must be a UUID string")?;
                        ids.push(
                            Uuid::parse_str(s.trim())
                                .map_err(|e| format!("invalid dependency_ids UUID '{s}': {e}"))?,
                        );
                    }
                    Some(ids)
                }
                Some(other) => {
                    return Err(format!(
                        "dependency_ids must be an array of UUID strings, got {other}"
                    ))
                }
            };

            let req = CacheAnswerRequest {
                id: None,
                tenant_id,
                scope,
                task_id,
                query_text,
                source_bundle_hash,
                answer_text,
                answer_metadata,
                ttl_seconds,
                validity_mode,
                dependency_ids,
                client_signature_hex,
                client_public_key_hex,
            };

            let (_status, Json(resp)) = handle_cache_answer(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_lookup_cached_answer" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_lookup_cached_answer",
                )
                .await?;
            let actor_id = resolve_mcp_actor_audited(
                &state,
                &headers,
                &tenant_id,
                args.get("actor_id").and_then(Value::as_str),
            )
            .await?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("mcp-task")
                .to_string();
            let query_text = args
                .get("query_text")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = LookupCachedAnswerRequest {
                tenant_id,
                actor_id: Some(actor_id),
                scope,
                task_id,
                query_text,
            };

            let (_status, Json(resp)) =
                handle_lookup_cached_answer(State(state), headers, Json(req))
                    .await
                    .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_trace_claim_impact" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_trace_claim_impact",
                )
                .await?;
            let raw_item_id = args
                .get("item_id")
                .or_else(|| args.get("claim_id"))
                .or_else(|| args.get("object_id"))
                .and_then(Value::as_str)
                .ok_or("missing item_id")?
                .to_string();

            let Json(resp) =
                handle_trace_item_impact(State(state), Path((tenant_id, raw_item_id)), headers)
                    .await
                    .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_verify_state_rebuild" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_verify_state_rebuild",
                )
                .await?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .ok_or("missing scope")?
                .to_string();
            let up_to_seq = match args.get("up_to_seq") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let s = v.as_i64().ok_or_else(|| {
                        format!("up_to_seq must be a positive integer, got {v}")
                    })?;
                    if s < 1 {
                        return Err(format!("up_to_seq must be >= 1 (got {s})"));
                    }
                    Some(s)
                }
            };

            let include_proof_archive = args
                .get("include_proof_archive")
                .and_then(Value::as_bool);

            let Json(resp) = handle_rebuild_scope_state(
                State(state),
                Path(tenant_id),
                Query(RebuildStateQueryParams {
                    scope: Some(scope),
                    up_to_seq,
                    include_proof_archive,
                }),
                headers,
            )
            .await
            .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_replay_counterfactual" => {
            let source_hash_opt = args
                .get("source_bundle_hash")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());

            let (
                tenant_id,
                scope,
                task_id,
                pinned_time_opt,
                base_compat,
                orig_manifest_opt,
            ) = if let Some(src_hex) = source_hash_opt {
                let filter = state
                    .resolve_bundle_lookup_scope(
                        &headers,
                        args.get("tenant_id").and_then(Value::as_str),
                        "acta_replay_counterfactual",
                        true,
                    )
                    .await?;
                let raw = hex::decode(src_hex)
                    .map_err(|e| format!("invalid source_bundle_hash hex: {e}"))?;
                let hash_arr: [u8; 32] = raw
                    .try_into()
                    .map_err(|_| "source_bundle_hash must be 64 hex chars".to_string())?;
                let lookup_scope = match &filter {
                    BundleTenantFilter::ExactTenant(tid) => {
                        evidence_repo::TenantLookupScope::Exact(tid.as_str())
                    }
                    BundleTenantFilter::SandboxPrefix(pfx) => {
                        evidence_repo::TenantLookupScope::SandboxPrefix(pfx.as_str())
                    }
                    BundleTenantFilter::UnrestrictedMaster => evidence_repo::TenantLookupScope::Any,
                };
                let (orig_bundle, _) = evidence_repo::fetch_bundle_with_evidence_slice_scoped(
                    &state.pool,
                    lookup_scope,
                    &hash_arr,
                )
                .await
                .map_err(|e| e.to_string())?;
                let has_v171_retraction_reasons = orig_bundle
                    .omission_record
                    .inline_items
                    .iter()
                    .any(|it| {
                        matches!(
                            it.reason,
                            acta_types::OmissionReason::Retracted
                                | acta_types::OmissionReason::RetractionTombstone
                        )
                    });
                let compat = acta_engine::SimulationCompat {
                    include_resolver_manifest: orig_bundle.resolver_manifest.is_some(),
                    legacy_pre_v166_disputes: !orig_bundle.dispute_records.is_empty()
                        && orig_bundle.dispute_records.iter().all(|d| d.margin.is_none()),
                    include_resolved_facts_omitted: orig_bundle.resolved_facts_omitted.is_some(),
                    legacy_pre_v171_resolver: !has_v171_retraction_reasons,
                };
                (
                    orig_bundle.tenant_id,
                    orig_bundle.scope,
                    orig_bundle.task_id,
                    Some(orig_bundle.issued_at.trunc_subsecs(6)),
                    compat,
                    orig_bundle.resolver_manifest,
                )
            } else {
                let t = state
                    .resolve_mcp_tenant_audited(
                        &headers,
                        args.get("tenant_id").and_then(Value::as_str),
                        "acta_replay_counterfactual",
                    )
                    .await?;
                let sc = args
                    .get("scope")
                    .and_then(Value::as_str)
                    .ok_or("missing scope (or pass source_bundle_hash)")?
                    .to_string();
                let tid = args
                    .get("task_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("mcp-task")
                    .to_string();
                let ts_opt =
                    parse_optional_rfc3339(args.get("evaluation_time").and_then(Value::as_str))?;
                (
                    t,
                    sc,
                    tid,
                    ts_opt,
                    acta_engine::SimulationCompat::default(),
                    None,
                )
            };

            validate_scope(&scope).map_err(|e| e.to_string())?;
            validate_identifier("task_id", &task_id).map_err(|e| e.to_string())?;

            let actor_id = resolve_mcp_actor_audited(
                &state,
                &headers,
                &tenant_id,
                args.get("actor_id").and_then(Value::as_str),
            )
            .await?;
            let query_text = args
                .get("query_text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            validate_query_text(&query_text).map_err(|e| e.to_string())?;

            let explicit_budget = match args.get("token_budget") {
                Some(v) if !v.is_null() => Some(parse_mcp_token_budget(Some(v))?),
                _ => None,
            };
            let base_budget = orig_manifest_opt
                .as_ref()
                .map(|m| m.budget)
                .or(explicit_budget)
                .unwrap_or(ContextBudget::Tokens(2048));
            let cf_budget = explicit_budget.unwrap_or(base_budget);

            let default_res = state.pipeline.config().resolver;
            let base_res = match orig_manifest_opt.as_ref() {
                Some(m) => ResolverConfig {
                    min_confidence: m.min_confidence,
                    decisiveness_threshold: m.decisiveness_threshold,
                },
                None => default_res,
            };
            let override_min = args.get("override_min_confidence").and_then(Value::as_f64);
            let override_dec = args
                .get("override_decisiveness_threshold")
                .and_then(Value::as_f64);
            if let Some(m) = override_min {
                if !m.is_finite() || !(0.0..=1.0).contains(&m) {
                    return Err("override_min_confidence must be in [0.0, 1.0]".to_string());
                }
            }
            if let Some(d) = override_dec {
                if !d.is_finite() || !(0.0..=1.0).contains(&d) {
                    return Err(
                        "override_decisiveness_threshold must be in [0.0, 1.0]".to_string()
                    );
                }
            }

            let cf_res = ResolverConfig {
                min_confidence: override_min.unwrap_or(base_res.min_confidence),
                decisiveness_threshold: override_dec.unwrap_or(base_res.decisiveness_threshold),
            };

            let base_req = CompileRequest {
                tenant_id: tenant_id.clone(),
                actor_id: actor_id.clone(),
                task_id: task_id.clone(),
                scope: scope.clone(),
                query_text: query_text.clone(),
                query_embedding: None,
                budget: base_budget,
                evaluation_time: pinned_time_opt,
            };
            let cf_req = CompileRequest {
                tenant_id: tenant_id.clone(),
                actor_id,
                task_id: task_id.clone(),
                scope: scope.clone(),
                query_text,
                query_embedding: None,
                budget: cf_budget,
                evaluation_time: pinned_time_opt,
            };

            // Auto-detect whether `source_bundle_hash` was compiled under v1.7.1+ or pre-v1.7.1 resolver rules:
            let mut modern_base_compat = base_compat;
            modern_base_compat.legacy_pre_v171_resolver = false;
            let mut base_sim = state
                .pipeline
                .simulate_compile_with_compat(
                    base_req.clone(),
                    None,
                    Some(base_res),
                    modern_base_compat,
                )
                .await
                .map_err(|e| e.to_string())?;

            let mut resolved_legacy_v171 = false;
            if let Some(src_hex) = source_hash_opt {
                if base_sim.bundle_hash.map(hex::encode).as_deref() != Some(src_hex)
                    && base_compat.legacy_pre_v171_resolver
                {
                    let leg_sim = state
                        .pipeline
                        .simulate_compile_with_compat(
                            base_req,
                            None,
                            Some(base_res),
                            base_compat,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    if leg_sim.bundle_hash.map(hex::encode).as_deref() == Some(src_hex) {
                        base_sim = leg_sim;
                        resolved_legacy_v171 = true;
                    }
                }
            }

            let no_cf_overrides =
                override_min.is_none() && override_dec.is_none() && explicit_budget.is_none();
            let cf_compat = acta_engine::SimulationCompat {
                include_resolver_manifest: if no_cf_overrides {
                    base_compat.include_resolver_manifest
                } else {
                    true
                },
                legacy_pre_v166_disputes: false,
                include_resolved_facts_omitted: if no_cf_overrides {
                    base_compat.include_resolved_facts_omitted
                } else {
                    true
                },
                legacy_pre_v171_resolver: no_cf_overrides && resolved_legacy_v171,
            };

            let cf_sim = state
                .pipeline
                .simulate_compile_with_compat(cf_req, None, Some(cf_res), cf_compat)
                .await
                .map_err(|e| e.to_string())?;

            let mut evidence_ledger_mutated = false;
            let mut refusal_evidence_seq_num = None;
            if !base_sim.policy_decision.is_allow() || !cf_sim.policy_decision.is_allow() {
                let tag = match (&base_sim.policy_decision, &cf_sim.policy_decision) {
                    (PolicyDecision::Block { .. }, _) | (_, PolicyDecision::Block { .. }) => {
                        PolicyResultTag::Block
                    }
                    _ => PolicyResultTag::Escalate,
                };
                if let Some(ev) = state
                    .append_refusal_audit_with_scope(
                        &headers,
                        Some(&tenant_id),
                        tag,
                        "acta_replay_counterfactual",
                        "mcp_replay_policy_refusal",
                        Some(&scope),
                        &format!("counterfactual replay refused on scope '{scope}'"),
                    )
                    .await
                {
                    evidence_ledger_mutated = true;
                    refusal_evidence_seq_num = Some(ev.seq_num);
                }
            }

            let effective_issued_at = base_sim
                .bundle
                .as_ref()
                .map(|b| b.issued_at)
                .or(pinned_time_opt);
            let base_hash_hex = base_sim.bundle_hash.map(hex::encode);
            let cf_hash_hex = cf_sim.bundle_hash.map(hex::encode);

            let reproduced_bit_for_bit = match (source_hash_opt, base_sim.bundle_hash.as_ref()) {
                (Some(src), _) => Some(base_hash_hex.as_deref() == Some(src)),
                (None, Some(h_bytes)) => sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM context_bundles WHERE tenant_id = $1 AND bundle_hash = $2)",
                )
                .bind(&tenant_id)
                .bind(h_bytes.as_slice())
                .fetch_one(&state.pool)
                .await
                .ok(),
                (None, None) => None,
            };

            let base_state_hex = base_sim
                .bundle
                .as_ref()
                .map(|b| hex::encode(b.state_commitment));
            let cf_state_hex = cf_sim
                .bundle
                .as_ref()
                .map(|b| hex::encode(b.state_commitment));
            let base_dep_hex = base_sim
                .bundle
                .as_ref()
                .map(|b| hex::encode(b.dependency_commitment));
            let resolution_changed = acta_engine::compute_resolution_changed(&base_sim, &cf_sim);
            let replay_valid = match source_hash_opt {
                Some(_) => reproduced_bit_for_bit == Some(true),
                None => base_sim.policy_decision.is_allow() && cf_sim.policy_decision.is_allow(),
            };
            let replay_invalid_reason = if !replay_valid {
                if source_hash_opt.is_some() && reproduced_bit_for_bit == Some(false) {
                    Some(
                        "baseline simulation did not reproduce source_bundle_hash bit-for-bit"
                            .to_string(),
                    )
                } else {
                    Some("policy denied counterfactual replay on target scope".to_string())
                }
            } else {
                None
            };

            let base_manifest = base_sim
                .bundle
                .as_ref()
                .and_then(|b| b.resolver_manifest.clone());
            let cf_manifest = cf_sim
                .bundle
                .as_ref()
                .and_then(|b| b.resolver_manifest.clone());
            let base_res_cnt = base_sim
                .bundle
                .as_ref()
                .map(|b| b.resolution_records.len())
                .unwrap_or(0);
            let cf_res_cnt = cf_sim
                .bundle
                .as_ref()
                .map(|b| b.resolution_records.len())
                .unwrap_or(0);
            let base_disp_cnt = base_sim
                .bundle
                .as_ref()
                .map(|b| b.dispute_records.len())
                .unwrap_or(0);
            let cf_disp_cnt = cf_sim
                .bundle
                .as_ref()
                .map(|b| b.dispute_records.len())
                .unwrap_or(0);
            let base_disputes = base_sim
                .bundle
                .as_ref()
                .map(|b| b.dispute_records.clone())
                .unwrap_or_default();
            let cf_disputes = cf_sim
                .bundle
                .as_ref()
                .map(|b| b.dispute_records.clone())
                .unwrap_or_default();

            let mut out_json = json!({
                "replay_valid": replay_valid,
                "pinned_task_id": task_id,
                "pinned_evaluation_time": effective_issued_at,
                "baseline_policy_decision": base_sim.policy_decision,
                "counterfactual_policy_decision": cf_sim.policy_decision,
                "reproduced_source_bundle_bit_for_bit": reproduced_bit_for_bit,
                "baseline_resolver_manifest": base_manifest,
                "counterfactual_resolver_manifest": cf_manifest,
                "baseline_thresholds": {
                    "min_confidence": base_res.min_confidence,
                    "decisiveness_threshold": base_res.decisiveness_threshold,
                },
                "counterfactual_thresholds": {
                    "min_confidence": cf_res.min_confidence,
                    "decisiveness_threshold": cf_res.decisiveness_threshold,
                },
                "baseline_bundle_hash": base_hash_hex,
                "counterfactual_bundle_hash": cf_hash_hex,
                "baseline_state_commitment": base_state_hex,
                "counterfactual_state_commitment": cf_state_hex,
                "dependency_commitment": base_dep_hex,
                "bundle_hash_changed": base_hash_hex != cf_hash_hex,
                "state_commitment_changed": base_state_hex != cf_state_hex,
                "resolution_changed": resolution_changed,
                "baseline_resolution_count": base_res_cnt,
                "counterfactual_resolution_count": cf_res_cnt,
                "baseline_dispute_count": base_disp_cnt,
                "counterfactual_dispute_count": cf_disp_cnt,
                "baseline_dispute_records": base_disputes,
                "counterfactual_dispute_records": cf_disputes,
                "baseline_resolved_facts_omitted": base_sim.bundle.as_ref().and_then(|b| b.resolved_facts_omitted),
                "counterfactual_resolved_facts_omitted": cf_sim.bundle.as_ref().and_then(|b| b.resolved_facts_omitted),
                "evidence_ledger_mutated": evidence_ledger_mutated,
                "refusal_evidence_seq_num": refusal_evidence_seq_num,
                "baseline_context_token_count": base_sim.context_token_count,
                "counterfactual_context_token_count": cf_sim.context_token_count,
                "baseline_context_text": base_sim.context_text,
                "counterfactual_context_text": cf_sim.context_text,
            });
            if let Some(reason) = replay_invalid_reason {
                out_json["replay_invalid_reason"] = json!(reason);
            }
            Ok(out_json)
        }
        "acta_verify_bundle" => {
            if let Some(obj) = args.as_object() {
                const ALLOWED_KEYS: &[&str] = &[
                    "tenant_id",
                    "bundle_hash",
                    "proof_mode",
                    "from_seq",
                    "limit",
                    "chain_from_seq",
                    "chain_limit",
                    "anchor_tree_size",
                    "anchored_tree_size",
                    "include_archive",
                    "dump_preimages",
                ];
                for key in obj.keys() {
                    if !ALLOWED_KEYS.contains(&key.as_str()) {
                        return Err(format!(
                            "unknown argument '{key}' on acta_verify_bundle (supported: tenant_id, bundle_hash, proof_mode, from_seq, limit, anchor_tree_size, anchored_tree_size, include_archive, dump_preimages)"
                        ));
                    }
                }
            }
            let explicit_tenant = args.get("tenant_id").and_then(Value::as_str);
            // Enforce tenant lock BEFORE validating bundle_hash so explicit cross-tenant probes are audited!
            let _preflight_scope = state
                .resolve_bundle_lookup_scope(
                    &headers,
                    explicit_tenant,
                    "acta_verify_bundle",
                    true,
                )
                .await?;

            let bundle_hash_hex = args
                .get("bundle_hash")
                .and_then(Value::as_str)
                .ok_or("missing bundle_hash")?;
            let proof_mode = args
                .get("proof_mode")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("full");
            let include_full_chain = match proof_mode {
                "" | "full" => true,
                "merkle" => false,
                other => {
                    return Err(format!(
                        "invalid proof_mode '{other}' (expected 'full' or 'merkle')"
                    ))
                }
            };
            let chain_from_seq = match args.get("from_seq").or_else(|| args.get("chain_from_seq")) {
                Some(v) if !v.is_null() => {
                    let s = v.as_i64().ok_or_else(|| {
                        format!("from_seq must be an integer >= 1, got {v}")
                    })?;
                    if s < 1 {
                        return Err(format!("from_seq must be >= 1 (got {s})"));
                    }
                    s
                }
                _ => 1,
            };
            let chain_limit = match args.get("limit").or_else(|| args.get("chain_limit")) {
                Some(v) if !v.is_null() => {
                    let lim = v.as_i64().ok_or_else(|| {
                        format!("limit must be an integer in 1..=500, got {v}")
                    })?;
                    if !(1..=500).contains(&lim) {
                        return Err(format!("limit must be between 1 and 500 (got {lim})"));
                    }
                    lim
                }
                _ => 100,
            };
            let opt_anchor = match args.get("anchor_tree_size") {
                Some(v) if !v.is_null() => Some(v.as_i64().ok_or_else(|| {
                    format!("anchor_tree_size must be a positive integer, got {v}")
                })?),
                _ => None,
            };
            let opt_anchored = match args.get("anchored_tree_size") {
                Some(v) if !v.is_null() => Some(v.as_i64().ok_or_else(|| {
                    format!("anchored_tree_size must be a positive integer, got {v}")
                })?),
                _ => None,
            };
            let anchor_tree_size = match (opt_anchor, opt_anchored) {
                (Some(a), Some(b)) if a != b => {
                    return Err(format!(
                        "conflicting anchor_tree_size ({a}) and anchored_tree_size ({b}); pass one or matching values"
                    ));
                }
                (a, b) => a.or(b),
            };
            let dump_preimages = args
                .get("dump_preimages")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let mut archive = build_export_archive_scoped(
                &state,
                bundle_hash_hex,
                Some(&headers),
                explicit_tenant,
                true,
                include_full_chain,
                anchor_tree_size,
            )
            .await
            .map_err(|e| e.message)?;

            let default_include = archive.objects.len() + archive.claims.len() <= 64;
            let include_archive = args
                .get("include_archive")
                .and_then(Value::as_bool)
                .unwrap_or(default_include);

            // Cryptographic verification ALWAYS runs over the full 1..=bundle_seq chain in memory!
            let summary = match verify_export_archive(&archive, &state.host_public_key) {
                Ok(s) => s,
                Err(err) => {
                    let ev_seq = state
                        .append_refusal_audit_with_scope(
                            &headers,
                            Some(&archive.bundle.tenant_id),
                            PolicyResultTag::Block,
                            "acta_verify_bundle",
                            "mcp_verify_bundle_failed",
                            Some(&archive.bundle.scope),
                            &err,
                        )
                        .await
                        .map(|e| e.seq_num);
                    let suffix = ev_seq
                        .map(|n| format!(" [logged at evidence seq_num={n}]"))
                        .unwrap_or_default();
                    return Err(format!("{err}{suffix}"));
                }
            };

            // Paginate returned evidence_chain slice (default limit=100, max 500) so large vaults never exceed MCP response limits.
            let chain_total_count = archive.evidence_chain.len();
            if include_full_chain {
                archive.evidence_chain = archive
                    .evidence_chain
                    .into_iter()
                    .filter(|e| e.seq_num >= chain_from_seq)
                    .take(chain_limit as usize)
                    .collect();
            }
            let chain_returned_count = archive.evidence_chain.len();
            let chain_next_seq = match archive.evidence_chain.last() {
                Some(last) if (last.seq_num as usize) < chain_total_count => Some(last.seq_num + 1),
                None if include_full_chain
                    && chain_total_count > 0
                    && (chain_from_seq as usize) <= chain_total_count =>
                {
                    Some(chain_from_seq)
                }
                _ => None,
            };
            let chain_has_more = chain_next_seq.is_some();

            let preimages_opt = if dump_preimages {
                Some(dump_archive_preimages(&archive)?)
            } else {
                None
            };

            let mut out = if include_archive {
                json!({
                    "verified": true,
                    "host_public_key": hex::encode(state.host_public_key),
                    "summary": summary,
                    "evidence_chain_total_count": chain_total_count,
                    "evidence_chain_returned_count": chain_returned_count,
                    "evidence_chain_from_seq": chain_from_seq,
                    "evidence_chain_limit": chain_limit,
                    "evidence_chain_has_more": chain_has_more,
                    "evidence_chain_next_seq": chain_next_seq,
                    "archive": archive,
                })
            } else {
                json!({
                    "verified": true,
                    "host_public_key": hex::encode(state.host_public_key),
                    "summary": summary,
                    "evidence_chain_total_count": chain_total_count,
                    "evidence_chain_returned_count": chain_returned_count,
                    "evidence_chain_from_seq": chain_from_seq,
                    "evidence_chain_limit": chain_limit,
                    "evidence_chain_has_more": chain_has_more,
                    "evidence_chain_next_seq": chain_next_seq,
                    "merkle_proof": archive.merkle_proof,
                    "evidence_chain": archive.evidence_chain,
                })
            };
            if let Some(p) = preimages_opt {
                out["preimages"] = p;
            }
            Ok(out)
        }
        "acta_list_evidence" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_list_evidence",
                )
                .await?;
            let from_seq = match args.get("from_seq") {
                Some(v) if !v.is_null() => Some(
                    v.as_i64()
                        .ok_or_else(|| format!("from_seq must be an integer >= 1, got {v}"))?,
                ),
                _ => None,
            };
            let limit = match args.get("limit") {
                Some(v) if !v.is_null() => Some(
                    v.as_i64()
                        .ok_or_else(|| format!("limit must be an integer in 1..=500, got {v}"))?,
                ),
                _ => None,
            };
            let Json(ev) = handle_tenant_evidence(
                State(state),
                Path(tenant_id),
                Query(EvidenceQueryParams { from_seq, limit }),
                headers,
            )
            .await
            .map_err(|e| e.message)?;
            serde_json::to_value(ev).map_err(|e| e.to_string())
        }
        "acta_get_checkpoint" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_get_checkpoint",
                )
                .await?;
            let tree_size = match args.get("tree_size") {
                Some(v) if !v.is_null() => Some(
                    v.as_i64()
                        .ok_or_else(|| format!("tree_size must be a positive integer, got {v}"))?,
                ),
                _ => None,
            };
            let since_size = match args.get("since_size") {
                Some(v) if !v.is_null() => Some(
                    v.as_i64()
                        .ok_or_else(|| format!("since_size must be a positive integer, got {v}"))?,
                ),
                _ => None,
            };

            let vk = VerifyingKey::from_bytes(&state.host_public_key)
                .map_err(|e| format!("host key error: {e}"))?;
            let Json(cp_resp) = handle_get_checkpoint(
                State(state),
                Path(tenant_id.clone()),
                Query(CheckpointQueryParams {
                    tree_size,
                    since_size,
                }),
                headers,
            )
            .await
            .map_err(|e| e.message)?;

            let mut verified = true;
            if let Some(ref sth) = cp_resp.checkpoint {
                verify_signed_tree_head(sth, &tenant_id, &vk)?;
            }
            if let Some(ref l_sth) = cp_resp.latest_anchored_checkpoint {
                verify_signed_tree_head(l_sth, &tenant_id, &vk)?;
            }
            if let Some(ref p_sth) = cp_resp.prior_checkpoint {
                verify_signed_tree_head(p_sth, &tenant_id, &vk)?;
            }
            if cp_resp.consistency_verified == Some(false)
                || cp_resp.latest_anchor_consistency_verified == Some(false)
            {
                verified = false;
            }

            let mut val = serde_json::to_value(cp_resp).map_err(|e| e.to_string())?;
            val["verified"] = json!(verified);
            Ok(val)
        }
        "acta_register_witness" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_register_witness",
                )
                .await?;
            let witness_id = args
                .get("witness_id")
                .and_then(Value::as_str)
                .ok_or("missing witness_id")?
                .to_string();
            let witness_public_key_hex = args
                .get("witness_public_key_hex")
                .and_then(Value::as_str)
                .ok_or("missing witness_public_key_hex")?
                .to_string();
            let description = args
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = RegisterWitnessRequest {
                tenant_id,
                witness_id,
                witness_public_key_hex,
                description,
            };

            let (_status, Json(resp)) =
                handle_register_witness(State(state), headers, Json(req))
                    .await
                    .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_revoke_witness" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_revoke_witness",
                )
                .await?;
            let witness_id = args
                .get("witness_id")
                .and_then(Value::as_str)
                .ok_or("missing witness_id")?
                .to_string();
            let reason = args
                .get("reason")
                .and_then(Value::as_str)
                .ok_or("missing reason")?
                .to_string();

            let raw_mode = args.get("mode").and_then(Value::as_str);
            let raw_rev_mode = args.get("revocation_mode").and_then(Value::as_str);
            let mode = match (raw_mode, raw_rev_mode) {
                (Some(a), Some(b)) if a.trim() != b.trim() => {
                    return Err(format!(
                        "conflicting mode ('{a}') and revocation_mode ('{b}') on acta_revoke_witness"
                    ));
                }
                (a, b) => a.or(b).map(str::to_string),
            };

            let req = RevokeWitnessRequest {
                tenant_id,
                witness_id,
                mode,
                reason,
            };

            let (_status, Json(resp)) =
                handle_revoke_witness(State(state), headers, Json(req))
                    .await
                    .map_err(|e| e.message)?;
            serde_json::to_value(resp).map_err(|e| e.to_string())
        }
        "acta_anchor_checkpoint" => {
            let tenant_id = state
                .resolve_mcp_tenant_audited(
                    &headers,
                    args.get("tenant_id").and_then(Value::as_str),
                    "acta_anchor_checkpoint",
                )
                .await?;
            let tree_size = args
                .get("tree_size")
                .and_then(Value::as_i64)
                .ok_or("missing integer tree_size")?;
            let checkpoint_hash_hex = args
                .get("checkpoint_hash")
                .or_else(|| args.get("checkpoint_hash_hex"))
                .and_then(Value::as_str)
                .ok_or("missing checkpoint_hash")?
                .to_string();
            let witness_id = args
                .get("witness_id")
                .and_then(Value::as_str)
                .ok_or("missing witness_id")?
                .to_string();
            let witness_public_key_hex = args
                .get("witness_public_key_hex")
                .and_then(Value::as_str)
                .ok_or("missing witness_public_key_hex")?
                .to_string();
            let witness_signature_hex = args
                .get("witness_signature_hex")
                .and_then(Value::as_str)
                .ok_or("missing witness_signature_hex")?
                .to_string();
            let external_uri = args
                .get("external_uri")
                .and_then(Value::as_str)
                .map(str::to_string);

            let req = AnchorCheckpointRequest {
                id: None,
                tenant_id,
                tree_size,
                checkpoint_hash_hex,
                witness_id,
                witness_public_key_hex,
                witness_signature_hex,
                external_uri,
            };

            let (_status, Json(anchor)) = handle_anchor_checkpoint(State(state), headers, Json(req))
                .await
                .map_err(|e| e.message)?;
            serde_json::to_value(anchor).map_err(|e| e.to_string())
        }
        unknown => Err(format!("unknown MCP tool: {unknown}")),
    }
}
