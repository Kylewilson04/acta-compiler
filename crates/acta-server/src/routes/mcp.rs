use acta_crypto::{dump_archive_preimages, verify_export_archive, verify_signed_tree_head};
use acta_engine::ResolverConfig;
use acta_store::{evidence_repo, overrides_repo};
use acta_types::{
    validate_budget, validate_identifier, validate_priority, validate_provenance_class,
    validate_query_text, validate_scope, AnchorCheckpointRequest, AttestOverrideRequest,
    CompileRequest, ContextBudget, IngestClaimRequest, IngestObjectRequest, LifecycleStatus,
    ObjectType, PolicyDecision, PolicyResultTag,
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
    checkpoints::{handle_anchor_checkpoint, handle_get_checkpoint, CheckpointQueryParams},
    compile::handle_compile,
    export::build_export_archive_with_mode,
    ingest::{handle_ingest_claim, handle_ingest_object},
    oauth::apply_oauth_cors,
    overrides::handle_attest_override,
    verify::handle_tenant_evidence,
};
use crate::state::{AppState, VerifiedKeyInfo};

fn mcp_tools_schema() -> Value {
    json!([
        {
            "name": "acta_whoami",
            "description": "Returns the verified GitHub organization / tenant vault and OAuth principal locked to this MCP session, active resolver thresholds, host Ed25519 verifying key, Cedar permission root, latest RFC 6962 SignedTreeHead checkpoint, active overrides, and recent signed evidence_history entries.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "acta_compile_context",
            "description": "Compiles a deterministic, Ed25519-signed ContextBundle binding resolver_manifest inside the bundle, preserving compact override why=\"...\" justifications under tight token budgets, and surfacing LapsedOverrideRef provenance when unseen evidence reopens a prior override.",
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
                    }
                }
            }
        },
        {
            "name": "acta_ingest_object",
            "description": "Appends an immutable versioned intent or memory object (enforcing Policy-Before-Write) to your authenticated GitHub organization vault.",
            "inputSchema": {
                "type": "object",
                "required": ["obj_type", "scope", "body"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "obj_type": { "type": "string", "enum": ["intent", "memory"] },
                    "scope": { "type": "string" },
                    "priority": { "type": "integer", "minimum": -1000, "maximum": 1000, "default": 50 },
                    "importance": { "type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.8 },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "body": { "type": "object" }
                }
            }
        },
        {
            "name": "acta_ingest_claim",
            "description": "Appends or auto-supersedes a versioned structured knowledge claim (enforcing Policy-Before-Write and anti-forgery identifier validation) in your authenticated GitHub organization vault.",
            "inputSchema": {
                "type": "object",
                "required": ["scope", "subject", "predicate", "object_val", "object_type", "confidence", "source_descriptor"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "scope": { "type": "string" },
                    "subject": { "type": "string" },
                    "predicate": { "type": "string" },
                    "object_val": {
                        "description": "Claim value as native JSON number, string, boolean, array, or object (pass strings directly without extra surrounding quotes)."
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
                    "source_descriptor": { "type": "string" }
                }
            }
        },
        {
            "name": "acta_attest_override",
            "description": "Cryptographically notarizes a dispute adjudication (enforcing Policy-Before-Attest and Principal-Bound Identity). Omit adjudicator_id to bind your verified GitHub OAuth 2.1 login (<tenant>::oauth:<github_login>); claiming a custom third-party/committee adjudicator_id or attesting on regulated/* scopes requires a valid 64-byte Ed25519 client_signature_hex + client_public_key_hex over acta:override_client_sig:v1.",
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
            "name": "acta_replay_counterfactual",
            "description": "Simulates a read-only counterfactual compile under alternative confidence/decisiveness thresholds without mutating evidence_history on Allow (logging a signed refusal entry with refusal_metadata if targeting a restricted/denied scope).",
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
            "description": "Exports a persisted ContextBundle and runs full Ed25519 + RFC 8785 JCS + BLAKE3 + RFC 6962 Merkle inclusion + resolver_manifest + override/lapsed_override + refusal_metadata verification. Supports proof_mode='merkle' for O(log N) verification without fetching the full linear evidence_chain, plus dump_preimages=true.",
            "inputSchema": {
                "type": "object",
                "required": ["bundle_hash"],
                "properties": {
                    "bundle_hash": { "type": "string", "description": "64-character hex bundle hash" },
                    "proof_mode": {
                        "type": "string",
                        "enum": ["full", "merkle"],
                        "default": "full",
                        "description": "'full' verifies both linear evidence_chain and Merkle proof; 'merkle' builds and verifies an O(log N) MerkleBundleProof with empty evidence_chain."
                    },
                    "include_archive": {
                        "type": "boolean",
                        "default": true
                    },
                    "dump_preimages": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, includes explicit domain-separated preimage digests and canonical JCS metadata for independent verification."
                    }
                }
            }
        },
        {
            "name": "acta_list_evidence",
            "description": "Lists the append-only Ed25519-signed evidence_history chain (including readable refusal_metadata and override_summary entries) for your locked organization vault.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tenant_id": { "type": "string" }
                }
            }
        },
        {
            "name": "acta_get_checkpoint",
            "description": "Returns the deterministic Ed25519-signed RFC 6962 Merkle SignedTreeHead checkpoint for your vault (at latest head or optional tree_size), plus an O(log N) Merkle consistency_proof from since_size proving append-only prefix integrity.",
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
            "name": "acta_anchor_checkpoint",
            "description": "Records an immutable external witness Ed25519 cosignature (acta:witness_sig:v1) anchoring a SignedTreeHead checkpoint at (tenant_id, tree_size, checkpoint_hash).",
            "inputSchema": {
                "type": "object",
                "required": ["tree_size", "checkpoint_hash", "witness_id", "witness_public_key_hex", "witness_signature_hex"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "tree_size": { "type": "integer", "minimum": 1 },
                    "checkpoint_hash": { "type": "string", "description": "64-char hex checkpoint_hash from acta_get_checkpoint." },
                    "witness_id": { "type": "string", "description": "Identifier of the external witness (e.g. 'rekor-mirror-1', 'cfo-notary')." },
                    "witness_public_key_hex": { "type": "string", "description": "32-byte Ed25519 public key (64 hex chars)." },
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

fn parse_optional_rfc3339(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(s)
        .map(|dt| Some(dt.with_timezone(&Utc).trunc_subsecs(6)))
        .map_err(|e| format!("invalid evaluation_time RFC 3339 timestamp '{s}': {e}"))
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
            "version": "1.6.0",
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
                        "version": "1.6.0"
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
                active_override_count,
                latest_checkpoint,
            ) = if let Some(ref tid) = locked_tenant {
                let ev_fut = evidence_repo::fetch_tenant_evidence_chain(&state.pool, tid, None);
                let ov_fut = overrides_repo::fetch_tenant_overrides(&state.pool, tid, None);
                let cp_fut = evidence_repo::build_signed_tree_head(
                    &state.pool,
                    &state.host_signing_key,
                    tid,
                    None,
                );
                let (ev_res, ov_res, cp_res) = tokio::join!(ev_fut, ov_fut, cp_fut);
                let (total, tail) = match ev_res {
                    Ok(entries) => {
                        let total = entries.len();
                        let tail = entries
                            .into_iter()
                            .rev()
                            .take(20)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<Vec<_>>();
                        (Some(total), Some(tail))
                    }
                    Err(_) => (None, None),
                };
                let ov_cnt = ov_res
                    .ok()
                    .map(|v| v.into_iter().filter(|(_, sup)| !*sup).count());
                let cp = cp_res.ok().flatten().map(|(sth, _)| sth);
                (total, tail, ov_cnt, cp)
            } else {
                (None, None, None, None)
            };

            let cfg = state.pipeline.config();
            Ok(json!({
                "connected": true,
                "version": "1.6.0",
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
                "latest_checkpoint": latest_checkpoint,
                "active_override_count": active_override_count,
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
            serde_json::to_value(resp).map_err(|e| e.to_string())
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

            let req = IngestObjectRequest {
                id: None,
                tenant_id,
                obj_type,
                scope,
                lifecycle_status: LifecycleStatus::Active,
                priority,
                importance,
                tags,
                body,
                embedding: None,
                predecessor_id: None,
                client_signature_hex: None,
                client_public_key_hex: None,
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
                source_commitment_hex: None,
                status: LifecycleStatus::Active,
                contradiction_ids: vec![],
                valid_from: None,
                valid_to: None,
                predecessor_id: None,
                client_signature_hex: None,
                client_public_key_hex: None,
            };

            let (_status, Json(resp)) = handle_ingest_claim(State(state), headers, Json(req))
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
        "acta_replay_counterfactual" => {
            let source_hash_opt = args
                .get("source_bundle_hash")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());

            let (tenant_id, scope, task_id, pinned_time_opt, base_has_manifest) =
                if let Some(src_hex) = source_hash_opt {
                    let raw = hex::decode(src_hex)
                        .map_err(|e| format!("invalid source_bundle_hash hex: {e}"))?;
                    let hash_arr: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| "source_bundle_hash must be 64 hex chars".to_string())?;
                    let (orig_bundle, _) =
                        evidence_repo::fetch_bundle_with_evidence_slice(&state.pool, &hash_arr)
                            .await
                            .map_err(|e| e.to_string())?;
                    state
                        .check_tenant_auth_audited(
                            &headers,
                            &orig_bundle.tenant_id,
                            "acta_replay_counterfactual",
                        )
                        .await?;
                    let had_manifest = orig_bundle.resolver_manifest.is_some();
                    (
                        orig_bundle.tenant_id,
                        orig_bundle.scope,
                        orig_bundle.task_id,
                        Some(orig_bundle.issued_at.trunc_subsecs(6)),
                        had_manifest,
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
                    let ts_opt = parse_optional_rfc3339(
                        args.get("evaluation_time").and_then(Value::as_str),
                    )?;
                    (t, sc, tid, ts_opt, true)
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
            let budget = parse_mcp_token_budget(args.get("token_budget"))?;

            let base_res = state.pipeline.config().resolver;
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

            let req = CompileRequest {
                tenant_id: tenant_id.clone(),
                actor_id,
                task_id: task_id.clone(),
                scope: scope.clone(),
                query_text,
                query_embedding: None,
                budget,
                evaluation_time: pinned_time_opt,
            };

            let (base_sim, cf_sim) = tokio::try_join!(
                state.pipeline.simulate_compile_with_manifest_mode(
                    req.clone(),
                    None,
                    None,
                    base_has_manifest
                ),
                state
                    .pipeline
                    .simulate_compile(req, None, Some(cf_res)),
            )
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
            let base_manifest = base_sim
                .bundle
                .as_ref()
                .and_then(|b| b.resolver_manifest.clone());
            let cf_manifest = cf_sim
                .bundle
                .as_ref()
                .and_then(|b| b.resolver_manifest.clone());

            Ok(json!({
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
                "state_commitment_changed": base_state_hex != cf_state_hex,
                "evidence_ledger_mutated": evidence_ledger_mutated,
                "refusal_evidence_seq_num": refusal_evidence_seq_num,
                "baseline_context_text": base_sim.context_text,
                "counterfactual_context_text": cf_sim.context_text,
            }))
        }
        "acta_verify_bundle" => {
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
            let dump_preimages = args
                .get("dump_preimages")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let archive = build_export_archive_with_mode(
                &state,
                bundle_hash_hex,
                Some(&headers),
                include_full_chain,
            )
            .await
            .map_err(|e| e.message)?;

            let default_include = archive.objects.len() + archive.claims.len() <= 64;
            let include_archive = args
                .get("include_archive")
                .and_then(Value::as_bool)
                .unwrap_or(default_include);

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
                    "archive": archive,
                })
            } else {
                json!({
                    "verified": true,
                    "host_public_key": hex::encode(state.host_public_key),
                    "summary": summary,
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
            let Json(ev) = handle_tenant_evidence(State(state), Path(tenant_id), headers)
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
            if let Some(ref p_sth) = cp_resp.prior_checkpoint {
                verify_signed_tree_head(p_sth, &tenant_id, &vk)?;
            }
            if cp_resp.consistency_verified == Some(false) {
                verified = false;
            }

            let mut val = serde_json::to_value(cp_resp).map_err(|e| e.to_string())?;
            val["verified"] = json!(verified);
            Ok(val)
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
