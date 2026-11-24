"""Git-Aware Global `stdio` MCP Bridge & Machine Setup for Acta Compiler (`acta-mcp`).

Solves multi-repo, multi-business context routing with ZERO per-repo secret files:
1. Stored once in `~/.config/acta/credentials.json` (`chmod 0600`) outside Git.
2. On startup in any directory, inspects:
   - Optional commit-safe `.acta.json` (`{"tenant": "...", "default_scope": "..."}`)
   - `git config --get remote.origin.url` (`github.com/<owner>/<repo>.git` -> `tenant=<owner>`, `scope=<repo>`)
   - Fallback `default_tenant` from `~/.config/acta/credentials.json` + directory basename.
3. Mints the exact `acta_tk_v1:<tenant>:<mac>` token in RAM (when master key is configured),
   attaches `X-Acta-Tenant`, auto-fills omitted `tenant_id` & `scope`, and verifies Ed25519
   receipts + RFC 6962 Merkle checkpoints locally on the client before returning results.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from .client import DEFAULT_CLOUDRUN_URL, ActaClient
from .crypto import (
    dump_archive_preimages,
    extract_token_tenant,
    mint_tenant_api_key,
    verify_export_archive,
)

DEFAULT_CREDENTIALS_PATH = Path.home() / ".config" / "acta" / "credentials.json"
DEFAULT_LIVE_HOST_PUBKEY = "e4611d0a9bf54101e68d30cf21fff1de38abeb3d294e879b05fcc7f6e2d1c52f"

_GIT_REMOTE_RE = re.compile(
    r"(?:[:/])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _sanitize_slug(raw: str, fallback: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", raw.strip().lower()).strip("-")
    return cleaned[:128] if cleaned else fallback


def parse_git_remote_url(remote_url: str) -> tuple[str, str] | None:
    """Extracts `(owner_slug, repo_slug)` from SSH or HTTPS Git remote URLs."""
    url = remote_url.strip()
    if not url:
        return None
    m = _GIT_REMOTE_RE.search(url)
    if not m:
        return None
    owner = _sanitize_slug(m.group(1), "default-org")
    repo = _sanitize_slug(m.group(2), "default-scope")
    return owner, repo


def _find_git_root_and_acta_config(start_dir: Path) -> tuple[Path | None, Path | None]:
    curr = start_dir.resolve()
    git_root: Path | None = None
    acta_cfg: Path | None = None
    for candidate in [curr, *curr.parents]:
        if acta_cfg is None and (candidate / ".acta.json").is_file():
            acta_cfg = candidate / ".acta.json"
        if git_root is None and (candidate / ".git").exists():
            git_root = candidate
            break
    return git_root, acta_cfg


def _read_git_origin_url(git_root: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(git_root), "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
        ).strip()
        return out or None
    except Exception:
        cfg_file = git_root / ".git" / "config"
        if cfg_file.is_file():
            text = cfg_file.read_text(encoding="utf-8", errors="replace")
            m = re.search(r'\[remote\s+"origin"\][^\[]*?url\s*=\s*(\S+)', text, re.S)
            if m:
                return m.group(1).strip()
        return None


@dataclass(frozen=True)
class WorkspaceRouting:
    tenant_id: str
    default_scope: str
    source: str
    git_remote: str | None
    cwd: str


def resolve_git_workspace_context(
    cwd: Path | str | None = None,
    *,
    fallback_tenant: str = "sandbox-local",
) -> WorkspaceRouting:
    work_dir = Path(cwd or os.getcwd()).resolve()
    git_root, acta_cfg = _find_git_root_and_acta_config(work_dir)
    remote_url = _read_git_origin_url(git_root) if git_root else None
    parsed_remote = parse_git_remote_url(remote_url) if remote_url else None

    if acta_cfg is not None:
        raw_cfg = json.loads(acta_cfg.read_text(encoding="utf-8"))
        cfg_tenant = _sanitize_slug(
            str(raw_cfg.get("tenant") or (parsed_remote[0] if parsed_remote else fallback_tenant)),
            fallback_tenant,
        )
        cfg_scope = _sanitize_slug(
            str(
                raw_cfg.get("default_scope")
                or (parsed_remote[1] if parsed_remote else work_dir.name)
            ),
            "default-scope",
        )
        return WorkspaceRouting(
            tenant_id=cfg_tenant,
            default_scope=cfg_scope,
            source=f".acta.json:{acta_cfg}",
            git_remote=remote_url,
            cwd=str(work_dir),
        )

    env_tenant = (os.environ.get("ACTA_TENANT_ID") or "").strip()
    env_scope = (os.environ.get("ACTA_DEFAULT_SCOPE") or "").strip()
    if env_tenant:
        return WorkspaceRouting(
            tenant_id=_sanitize_slug(env_tenant, fallback_tenant),
            default_scope=_sanitize_slug(
                env_scope or (parsed_remote[1] if parsed_remote else work_dir.name),
                "default-scope",
            ),
            source="env:ACTA_TENANT_ID",
            git_remote=remote_url,
            cwd=str(work_dir),
        )

    if parsed_remote is not None:
        return WorkspaceRouting(
            tenant_id=parsed_remote[0],
            default_scope=parsed_remote[1],
            source="git:remote.origin.url",
            git_remote=remote_url,
            cwd=str(work_dir),
        )

    dir_slug = _sanitize_slug((git_root or work_dir).name, "workspace")
    return WorkspaceRouting(
        tenant_id=_sanitize_slug(fallback_tenant, "sandbox-local"),
        default_scope=dir_slug,
        source="fallback:cwd",
        git_remote=None,
        cwd=str(work_dir),
    )


def save_credentials(
    *,
    base_url: str = DEFAULT_CLOUDRUN_URL,
    master_key: str | None = None,
    tenant_key: str | None = None,
    default_tenant: str = "ardyn-intelligence",
    pinned_host_public_key: str = DEFAULT_LIVE_HOST_PUBKEY,
    path: Path | None = None,
) -> Path:
    cred_path = path or DEFAULT_CREDENTIALS_PATH
    cred_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "base_url": base_url.rstrip("/"),
        "default_tenant": _sanitize_slug(default_tenant, "ardyn-intelligence"),
        "pinned_host_public_key": pinned_host_public_key.strip().lower(),
    }
    if master_key:
        payload["master_key"] = master_key.strip()
    if tenant_key:
        payload["tenant_key"] = tenant_key.strip()
    cred_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(cred_path, stat.S_IRUSR | stat.S_IWUSR)
    return cred_path


def load_credentials(path: Path | None = None) -> dict[str, Any]:
    cred_path = path or DEFAULT_CREDENTIALS_PATH
    if not cred_path.is_file():
        return {}
    return json.loads(cred_path.read_text(encoding="utf-8"))


def _upsert_mcp_json_config(target_path: Path, command_path: str) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if target_path.is_file():
        try:
            existing = json.loads(target_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    servers = existing.setdefault("mcpServers", {})
    servers["acta"] = {
        "command": command_path,
        "args": ["serve"],
    }
    target_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")


def install_global_mcp_configs(home_dir: Path | None = None) -> list[Path]:
    home = home_dir or Path.home()
    python_exe = sys.executable
    wrapper_bin = home / ".local" / "bin" / "acta-mcp"
    wrapper_bin.parent.mkdir(parents=True, exist_ok=True)
    sdk_dir = Path(__file__).resolve().parents[1]
    wrapper_bin.write_text(
        f'#!/usr/bin/env bash\nPYTHONPATH="{sdk_dir}:${{PYTHONPATH:-}}" exec "{python_exe}" -m acta_sdk.cli "$@"\n',
        encoding="utf-8",
    )
    os.chmod(wrapper_bin, 0o755)

    cmd_str = str(wrapper_bin)
    targets = [
        home / ".claude.json",
        home / ".gemini" / "settings.json",
        home / ".cursor" / "mcp.json",
    ]
    macos_claude = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if macos_claude.parent.exists():
        targets.append(macos_claude)

    updated: list[Path] = []
    for t in targets:
        _upsert_mcp_json_config(t, cmd_str)
        updated.append(t)

    return updated


class ActaGitMcpBridge:
    """Zero-trust local `stdio` MCP server that routes by Git repo & verifies Ed25519/Merkle receipts."""

    def __init__(
        self,
        *,
        cwd: Path | str | None = None,
        credentials_path: Path | None = None,
        base_url: str | None = None,
        master_key: str | None = None,
        api_key: str | None = None,
        pinned_host_public_key: str | None = None,
    ) -> None:
        creds = load_credentials(credentials_path)
        fallback_tenant = str(creds.get("default_tenant") or "sandbox-local")
        self.routing = resolve_git_workspace_context(cwd, fallback_tenant=fallback_tenant)

        resolved_url = (
            base_url
            or os.environ.get("ACTA_BASE_URL")
            or creds.get("base_url")
            or DEFAULT_CLOUDRUN_URL
        )
        eff_master = master_key or os.environ.get("ACTA_MASTER_KEY") or creds.get("master_key")
        eff_api_key = api_key or os.environ.get("ACTA_API_KEY") or creds.get("tenant_key")

        if eff_api_key and extract_token_tenant(eff_api_key):
            bound_tenant = extract_token_tenant(eff_api_key)
            assert bound_tenant is not None
            self.routing = WorkspaceRouting(
                tenant_id=bound_tenant,
                default_scope=self.routing.default_scope,
                source="token:acta_tk_v1",
                git_remote=self.routing.git_remote,
                cwd=self.routing.cwd,
            )
            active_key: str | None = eff_api_key
        elif eff_master:
            active_key = mint_tenant_api_key(str(eff_master), self.routing.tenant_id)
        elif eff_api_key:
            active_key = mint_tenant_api_key(str(eff_api_key), self.routing.tenant_id)
        else:
            active_key = None

        pinned_pk = (
            pinned_host_public_key
            or os.environ.get("ACTA_HOST_PUBLIC_KEY")
            or creds.get("pinned_host_public_key")
            or None
        )
        self.client = ActaClient(
            resolved_url,
            api_key=active_key,
            default_tenant_id=self.routing.tenant_id,
            pinned_host_public_key=pinned_pk,
        )

    def close(self) -> None:
        self.client.close()

    def tools_schema(self) -> list[dict[str, Any]]:
        t = self.routing.tenant_id
        s = self.routing.default_scope
        return [
            {
                "name": "acta_workspace_status",
                "description": f"Returns active Git-bound Acta tenant ('{t}'), default repo scope ('{s}'), and pinned Ed25519 key.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "acta_compile_context",
                "description": f"Compiles deterministic Ed25519-signed context for Git tenant '{t}' (defaults scope to '{s}').",
                "inputSchema": {
                    "type": "object",
                    "required": ["query_text"],
                    "properties": {
                        "scope": {"type": "string", "default": s},
                        "actor_id": {"type": "string", "default": "mcp-agent"},
                        "query_text": {"type": "string"},
                        "token_budget": {"type": "integer", "default": 2048},
                    },
                },
            },
            {
                "name": "acta_ingest_object",
                "description": f"Appends an immutable intent or memory object to Git tenant '{t}' (defaults scope to '{s}').",
                "inputSchema": {
                    "type": "object",
                    "required": ["obj_type", "body"],
                    "properties": {
                        "obj_type": {"type": "string", "enum": ["intent", "memory"]},
                        "scope": {"type": "string", "default": s},
                        "priority": {"type": "integer", "default": 50},
                        "importance": {"type": "number", "default": 0.8},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "body": {"type": "object"},
                    },
                },
            },
            {
                "name": "acta_ingest_claim",
                "description": f"Appends an immutable structured claim to Git tenant '{t}' (defaults scope to '{s}').",
                "inputSchema": {
                    "type": "object",
                    "required": [
                        "subject",
                        "predicate",
                        "object_val",
                        "object_type",
                        "confidence",
                        "source_descriptor",
                    ],
                    "properties": {
                        "scope": {"type": "string", "default": s},
                        "subject": {"type": "string"},
                        "predicate": {"type": "string"},
                        "object_val": {},
                        "object_type": {"type": "string"},
                        "confidence": {"type": "number"},
                        "source_provenance_class": {"type": "integer", "default": 2},
                        "source_descriptor": {"type": "string"},
                        "source_content": {"type": "string"},
                        "source_commitment_hex": {"type": "string"},
                    },
                },
            },
            {
                "name": "acta_attest_override",
                "description": f"Signs and notarizes an immutable dispute-override attestation on Git tenant '{t}'. Custom adjudicator_id requires client_signature_hex + client_public_key_hex.",
                "inputSchema": {
                    "type": "object",
                    "required": ["winning_claim_id", "justification"],
                    "properties": {
                        "scope": {"type": "string", "default": s},
                        "winning_claim_id": {"type": "string"},
                        "source_bundle_hash_hex": {"type": "string"},
                        "adjudicator_id": {"type": "string"},
                        "justification": {"type": "string"},
                        "client_signature_hex": {"type": "string"},
                        "client_public_key_hex": {"type": "string"},
                    },
                },
            },
            {
                "name": "acta_get_checkpoint",
                "description": f"Returns the RFC 6962 Ed25519-signed Merkle SignedTreeHead checkpoint (and optional O(log N) consistency proof) for Git tenant '{t}'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tree_size": {"type": "integer"},
                        "since_size": {"type": "integer"},
                    },
                },
            },
            {
                "name": "acta_register_witness",
                "description": f"Enrolls a trusted witness Ed25519 public key in trusted_witnesses on Git tenant '{t}'.",
                "inputSchema": {
                    "type": "object",
                    "required": ["witness_id", "witness_public_key_hex"],
                    "properties": {
                        "witness_id": {"type": "string"},
                        "witness_public_key_hex": {"type": "string"},
                        "description": {"type": "string"},
                    },
                },
            },
            {
                "name": "acta_revoke_witness",
                "description": f"Revokes an enrolled witness via append-only witness_revocations on Git tenant '{t}'.",
                "inputSchema": {
                    "type": "object",
                    "required": ["witness_id", "reason"],
                    "properties": {
                        "witness_id": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                },
            },
            {
                "name": "acta_anchor_checkpoint",
                "description": f"Appends an external witness Ed25519 cosignature to a SignedTreeHead checkpoint on Git tenant '{t}'.",
                "inputSchema": {
                    "type": "object",
                    "required": [
                        "tree_size",
                        "checkpoint_hash_hex",
                        "witness_id",
                        "witness_public_key_hex",
                        "witness_signature_hex",
                    ],
                    "properties": {
                        "tree_size": {"type": "integer"},
                        "checkpoint_hash_hex": {"type": "string"},
                        "witness_id": {"type": "string"},
                        "witness_public_key_hex": {"type": "string"},
                        "witness_signature_hex": {"type": "string"},
                        "external_uri": {"type": "string"},
                    },
                },
            },
            {
                "name": "acta_replay_counterfactual",
                "description": f"Simulates counterfactual threshold changes on Git tenant '{t}' without mutating evidence_history.",
                "inputSchema": {
                    "type": "object",
                    "required": ["query_text"],
                    "properties": {
                        "scope": {"type": "string", "default": s},
                        "actor_id": {"type": "string", "default": "mcp-agent"},
                        "query_text": {"type": "string"},
                        "override_min_confidence": {"type": "number"},
                        "override_decisiveness_threshold": {"type": "number"},
                    },
                },
            },
            {
                "name": "acta_verify_bundle",
                "description": "Downloads ExportArchive (`merkle` O(log N) or `full` linear chain) and verifies RFC 8785 JCS + BLAKE3 + Ed25519 signatures locally.",
                "inputSchema": {
                    "type": "object",
                    "required": ["bundle_hash"],
                    "properties": {
                        "bundle_hash": {"type": "string"},
                        "proof_mode": {"type": "string", "enum": ["merkle", "full"], "default": "merkle"},
                        "dump_preimages": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "acta_list_evidence",
                "description": f"Lists Ed25519-verified evidence ledger entries (including readable refusal_metadata and override_summary) for Git tenant '{t}'.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def _resolve_scope(self, args: Mapping[str, Any]) -> str:
        raw = str(args.get("scope") or "").strip()
        return raw if raw else self.routing.default_scope

    def call_tool(self, name: str, args: Mapping[str, Any]) -> dict[str, Any]:
        if name == "acta_workspace_status":
            pk = self.client.ensure_host_public_key()
            return {
                "tenant_id": self.routing.tenant_id,
                "default_scope": self.routing.default_scope,
                "routing_source": self.routing.source,
                "git_remote": self.routing.git_remote,
                "cwd": self.routing.cwd,
                "server_url": self.client.base_url,
                "pinned_host_public_key": pk,
            }

        if args.get("tenant_id") and str(args["tenant_id"]).strip() != self.routing.tenant_id:
            raise ValueError(
                f"Git workspace tenant lock violation: requested '{args['tenant_id']}', "
                f"but active repository is locked to '{self.routing.tenant_id}'"
            )

        scope = self._resolve_scope(args)
        actor_raw = str(args.get("actor_id") or "mcp-agent").strip()
        actor_id = (
            actor_raw
            if "::" in actor_raw
            else f"{self.routing.tenant_id}::{actor_raw}"
        )

        if name == "acta_compile_context":
            budget_tok = int(args.get("token_budget") or 2048)
            res = self.client.compile(
                actor_id=actor_id,
                scope=scope,
                query_text=str(args.get("query_text") or ""),
                budget={"kind": "tokens", "limit": budget_tok},
            )
            return {
                "tenant_id": self.routing.tenant_id,
                "scope": scope,
                "policy_decision": res.policy_decision,
                "bundle_hash": res.bundle_hash,
                "context_text": res.context_text,
                "dispute_count": len(res.dispute_records),
                "resolver_manifest": res.bundle.get("resolver_manifest") if res.bundle else None,
                "evidence": res.evidence,
                "ed25519_verified_locally": True,
            }

        if name == "acta_ingest_object":
            return self.client.ingest_object(
                obj_type=args["obj_type"],
                scope=scope,
                priority=int(args.get("priority", 50)),
                importance=float(args.get("importance", 0.8)),
                tags=list(args.get("tags") or []),
                body=args["body"],
            )

        if name == "acta_ingest_claim":
            return self.client.ingest_claim(
                scope=scope,
                subject=str(args["subject"]),
                predicate=str(args["predicate"]),
                object_val=args["object_val"],
                object_type=str(args["object_type"]),
                confidence=float(args["confidence"]),
                source_provenance_class=int(args.get("source_provenance_class", 2)),
                source_descriptor=str(args["source_descriptor"]),
                source_commitment_hex=(
                    str(args["source_commitment_hex"])
                    if args.get("source_commitment_hex") is not None
                    else None
                ),
                source_content=(
                    str(args["source_content"])
                    if args.get("source_content") is not None
                    else None
                ),
            )

        if name == "acta_attest_override":
            adj_opt = str(args["adjudicator_id"]).strip() if args.get("adjudicator_id") else None
            return self.client.attest_override(
                scope=scope,
                winning_claim_id=str(args["winning_claim_id"]),
                source_bundle_hash_hex=(
                    str(args["source_bundle_hash_hex"])
                    if args.get("source_bundle_hash_hex") is not None
                    else None
                ),
                adjudicator_id=adj_opt,
                justification=str(args["justification"]),
                client_signature_hex=(
                    str(args["client_signature_hex"])
                    if args.get("client_signature_hex") is not None
                    else None
                ),
                client_public_key_hex=(
                    str(args["client_public_key_hex"])
                    if args.get("client_public_key_hex") is not None
                    else None
                ),
            )

        if name == "acta_get_checkpoint":
            return self.client.get_checkpoint(
                tree_size=int(args["tree_size"]) if args.get("tree_size") is not None else None,
                since_size=int(args["since_size"]) if args.get("since_size") is not None else None,
            )

        if name == "acta_register_witness":
            return self.client.register_witness(
                witness_id=str(args["witness_id"]),
                witness_public_key_hex=str(args["witness_public_key_hex"]),
                description=(
                    str(args["description"]) if args.get("description") is not None else None
                ),
            )

        if name == "acta_revoke_witness":
            return self.client.revoke_witness(
                witness_id=str(args["witness_id"]),
                reason=str(args["reason"]),
            )

        if name == "acta_anchor_checkpoint":
            return self.client.anchor_checkpoint(
                tree_size=int(args["tree_size"]),
                checkpoint_hash_hex=str(args["checkpoint_hash_hex"]),
                witness_id=str(args["witness_id"]),
                witness_public_key_hex=str(args["witness_public_key_hex"]),
                witness_signature_hex=str(args["witness_signature_hex"]),
                external_uri=str(args["external_uri"]) if args.get("external_uri") is not None else None,
            )

        if name == "acta_replay_counterfactual":
            return self.client.replay(
                actor_id=actor_raw,
                scope=scope,
                query_text=str(args.get("query_text") or ""),
                override_min_confidence=(
                    float(args["override_min_confidence"])
                    if args.get("override_min_confidence") is not None
                    else None
                ),
                override_decisiveness_threshold=(
                    float(args["override_decisiveness_threshold"])
                    if args.get("override_decisiveness_threshold") is not None
                    else None
                ),
            )

        if name == "acta_verify_bundle":
            mode = "full" if str(args.get("proof_mode") or "merkle") == "full" else "merkle"
            pk = self.client.ensure_host_public_key()
            archive = self.client.export_bundle(str(args["bundle_hash"]), mode=mode)
            summary = verify_export_archive(archive, pk)
            out: dict[str, Any] = {
                "verified_locally": True,
                "verification_mode": summary.verification_mode,
                "tenant_id": summary.tenant_id,
                "bundle_hash_hex": summary.bundle_hash_hex,
                "state_commitment_hex": summary.state_commitment_hex,
                "verified_objects": summary.verified_objects,
                "verified_claims": summary.verified_claims,
                "verified_overrides": summary.verified_overrides,
                "verified_writes": summary.verified_writes,
                "verified_answer_caches": summary.verified_answer_caches,
                "verified_refusals": summary.verified_refusals,
                "verified_evidence_entries": summary.verified_evidence_entries,
                "merkle_tree_size": summary.merkle_tree_size,
                "merkle_root_hex": summary.merkle_root_hex,
                "verified_witness_anchors": summary.verified_witness_anchors,
                "non_default_thresholds": summary.non_default_thresholds,
                "resolver_manifest": summary.resolver_manifest,
            }
            if args.get("dump_preimages"):
                out["preimages"] = dump_archive_preimages(archive)
            return out

        if name == "acta_retract_claim":
            return self.client.retract_claim(
                claim_id=str(args["claim_id"]),
                reason=str(args["reason"]),
                client_signature_hex=(
                    str(args["client_signature_hex"])
                    if args.get("client_signature_hex") is not None
                    else None
                ),
                client_public_key_hex=(
                    str(args["client_public_key_hex"])
                    if args.get("client_public_key_hex") is not None
                    else None
                ),
            )

        if name == "acta_cache_answer":
            return self.client.cache_answer(
                source_bundle_hash=str(args["source_bundle_hash"]),
                answer_text=str(args["answer_text"]),
                query_text=str(args.get("query_text") or ""),
                scope=str(args["scope"]) if args.get("scope") is not None else None,
                task_id=str(args["task_id"]) if args.get("task_id") is not None else None,
                ttl_seconds=int(args["ttl_seconds"]) if args.get("ttl_seconds") is not None else None,
                validity_mode=str(args["validity_mode"]) if args.get("validity_mode") is not None else None,
                dependency_ids=list(args["dependency_ids"]) if args.get("dependency_ids") is not None else None,
                client_signature_hex=(
                    str(args["client_signature_hex"])
                    if args.get("client_signature_hex") is not None
                    else None
                ),
                client_public_key_hex=(
                    str(args["client_public_key_hex"])
                    if args.get("client_public_key_hex") is not None
                    else None
                ),
            )

        if name == "acta_lookup_cached_answer":
            return self.client.lookup_cached_answer(
                scope=scope,
                task_id=str(args.get("task_id") or "mcp-task"),
                query_text=str(args.get("query_text") or ""),
                actor_id=actor_raw,
            )

        if name == "acta_trace_claim_impact":
            return self.client.trace_item_impact(str(args["item_id"]))

        if name == "acta_verify_state_rebuild":
            return self.client.rebuild_scope_state(
                scope,
                up_to_seq=int(args["up_to_seq"]) if args.get("up_to_seq") is not None else None,
                include_proof_archive=bool(args.get("include_proof_archive", False)),
            )

        if name == "acta_list_evidence":
            return self.client.list_tenant_evidence(
                from_seq=int(args["from_seq"]) if args.get("from_seq") is not None else None,
                limit=int(args["limit"]) if args.get("limit") is not None else None,
            )

        raise ValueError(f"unknown MCP tool: {name}")

    def handle_rpc_dict(self, rpc: Mapping[str, Any]) -> dict[str, Any] | None:
        has_id = "id" in rpc
        req_id = rpc.get("id")
        method = str(rpc.get("method") or "")

        if method == "notifications/initialized" and not has_id:
            return None

        if method == "initialize":
            client_proto = (
                rpc.get("params", {}).get("protocolVersion")
                if isinstance(rpc.get("params"), Mapping)
                else None
            ) or "2025-06-18"
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": client_proto,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "acta-mcp-git-bridge",
                        "version": "1.7.1",
                    },
                },
            }

        if method in ("ping", "notifications/initialized"):
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.tools_schema()},
            }

        if method == "tools/call":
            params = rpc.get("params") if isinstance(rpc.get("params"), Mapping) else {}
            t_name = str(params.get("name") or "")
            t_args = params.get("arguments") if isinstance(params.get("arguments"), Mapping) else {}
            try:
                payload = self.call_tool(t_name, t_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                        "structuredContent": payload,
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"ERROR: {exc}"}],
                        "isError": True,
                    },
                }

        if not has_id:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unsupported method: {method}"},
        }

    def serve_stdio(
        self,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> None:
        in_stream = stdin or sys.stdin.buffer
        out_stream = stdout or sys.stdout.buffer

        while True:
            line = in_stream.readline()
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                continue

            use_content_length = stripped.lower().startswith(b"content-length:")
            if use_content_length:
                length = int(stripped.split(b":", 1)[1].strip())
                while True:
                    hdr = in_stream.readline()
                    if not hdr or hdr in (b"\r\n", b"\n"):
                        break
                raw_body = in_stream.read(length)
            else:
                raw_body = stripped

            try:
                rpc_msg = json.loads(raw_body.decode("utf-8"))
            except Exception as exc:
                err_resp = json.dumps(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
                ).encode("utf-8")
                out_stream.write(err_resp + b"\n")
                out_stream.flush()
                continue

            reply = self.handle_rpc_dict(rpc_msg)
            if reply is None:
                continue
            encoded = json.dumps(reply, separators=(",", ":")).encode("utf-8")
            if use_content_length:
                out_stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
            else:
                out_stream.write(encoded + b"\n")
            out_stream.flush()


def main_mcp_entry() -> int:
    from .cli import main

    argv = sys.argv[1:]
    if not argv or argv[0] == "serve":
        bridge = ActaGitMcpBridge()
        try:
            bridge.serve_stdio()
        finally:
            bridge.close()
        return 0
    return main(argv)
