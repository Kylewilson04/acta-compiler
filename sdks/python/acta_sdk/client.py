"""Sync and Async Zero-Trust HTTP Clients for Acta Compiler v1.7.1.

Features:
- Stateless Keyed-BLAKE3 Tenant & OAuth Principal Tokens (`acta_tk_v1:<tenant>[:<login>]:<mac>`) + `X-Acta-Tenant` locking
- Automatic default `tenant_id` inference from `acta_tk_v1` keys so callers never mix up clients
- Local BLAKE3 `event_hash` (`v1`/`v2`) + strict Ed25519 `host_signature` verification on every `compile()`
- Signed Dispute-Override Attestations (`attest_override` / `list_overrides`) with Principal-Bound OAuth or offline Ed25519 signatures
- RFC 6962 Merkle `SignedTreeHead` checkpoints (`get_checkpoint`), `O(log N)` compact bundle verification (`mode="merkle"`),
  and external witness cosignature anchoring (`anchor_checkpoint`)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Mapping, Sequence

from .crypto import (
    VerificationSummary,
    extract_token_principal,
    extract_token_tenant,
    verify_evidence_entry,
    verify_and_rebuild_scope_state_offline,
    verify_export_archive,
    verify_merkle_consistency_proof,
    verify_answer_cache_signature,
    verify_override_signature,
    verify_signed_tree_head,
    verify_witness_anchor_signature,
)
from .errors import (
    ActaAuthError,
    ActaDisputeEscalationError,
    ActaHttpError,
    ActaPolicyBlockedError,
    ActaPolicyEscalatedError,
    ActaSignatureVerificationError,
    ActaTenantLockError,
    ActaVerificationError,
)
from .models import CompileResult, ContextBudget, LifecycleLiteral, ObjectTypeLiteral

try:
    import httpx as _httpx  # type: ignore[import-not-found]
except ImportError:
    _httpx = None

DEFAULT_CLOUDRUN_URL = "https://acta-server-998422936041.us-west1.run.app"


def _parse_api_error(status: int, raw_body: bytes) -> ActaHttpError:
    msg = raw_body.decode("utf-8", errors="replace")
    parsed: Any = None
    try:
        parsed = json.loads(msg)
        if isinstance(parsed, dict) and "error" in parsed:
            msg = str(parsed["error"])
    except Exception:
        pass
    if status == 401:
        return ActaAuthError(status, msg, parsed)
    return ActaHttpError(status, msg, parsed)


def _resolve_client_tenant_lock(api_key: str | None, explicit_default_tenant: str | None) -> str | None:
    tok_tenant = extract_token_tenant(api_key) if api_key else None
    env_or_explicit = (explicit_default_tenant or os.environ.get("ACTA_TENANT_ID") or "").strip() or None
    if tok_tenant and env_or_explicit and tok_tenant != env_or_explicit:
        raise ActaTenantLockError(
            f"default_tenant_id '{env_or_explicit}' conflicts with acta_tk_v1 key bound to '{tok_tenant}'"
        )
    return tok_tenant or env_or_explicit


def _enforce_tenant(locked_tenant: str | None, requested_tenant: str | None) -> str:
    clean_req = (requested_tenant or "").strip() or None
    if locked_tenant and clean_req and clean_req != locked_tenant:
        raise ActaTenantLockError(
            f"client is locked to tenant '{locked_tenant}', cannot issue request for '{clean_req}'"
        )
    resolved = clean_req or locked_tenant
    if not resolved:
        raise ValueError(
            "tenant_id is required when client is not initialized with an acta_tk_v1 key or default_tenant_id"
        )
    return resolved


def _enforce_guarded_compile(
    res: CompileResult,
    *,
    strict_disputes: bool = True,
    halt_on_any_dispute: bool = False,
) -> CompileResult:
    decision_tag = res.policy_decision.get("decision")
    reason = str(res.policy_decision.get("reason", "policy denied"))
    if decision_tag == "block":
        raise ActaPolicyBlockedError(reason, res.evidence, res.policy_decision)
    if decision_tag == "escalate":
        raise ActaPolicyEscalatedError(reason, res.evidence, res.policy_decision)

    disputes = res.dispute_records
    if disputes and strict_disputes:
        trigger = disputes if halt_on_any_dispute else [
            d for d in disputes if d.get("escalation_required", True)
        ]
        if trigger:
            raise ActaDisputeEscalationError(
                bundle_hash=res.bundle_hash or "",
                disputes=trigger,
                evidence=res.evidence,
                context_text=res.context_text or "",
            )
    return res


class ActaClient:
    """Synchronous Zero-Trust client for Acta Compiler v1.7.1."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        default_tenant_id: str | None = None,
        pinned_host_public_key: str | None = None,
        timeout: float = 15.0,
        httpx_client: Any = None,
    ) -> None:
        resolved_url = base_url or os.environ.get("ACTA_BASE_URL") or DEFAULT_CLOUDRUN_URL
        self.base_url = resolved_url.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACTA_API_KEY")
        self.locked_tenant = _resolve_client_tenant_lock(self.api_key, default_tenant_id)
        self.verified_principal = extract_token_principal(self.api_key) if self.api_key else None
        self._pinned_pubkey = (
            pinned_host_public_key or os.environ.get("ACTA_HOST_PUBLIC_KEY") or None
        )
        if self._pinned_pubkey:
            self._pinned_pubkey = self._pinned_pubkey.strip().lower()
        self.timeout = timeout
        self._owns_httpx = False
        if httpx_client is not None:
            self._http = httpx_client
        elif _httpx is not None:
            self._http = _httpx.Client(base_url=self.base_url, timeout=timeout)
            self._owns_httpx = True
        else:
            self._http = None

    def close(self) -> None:
        if self._owns_httpx and self._http is not None:
            self._http.close()

    def __enter__(self) -> "ActaClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _headers(self, *, include_tenant_lock: bool = True) -> dict[str, str]:
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)",
        }
        if self.api_key:
            hdrs["X-Acta-Api-Key"] = self.api_key
        if include_tenant_lock and self.locked_tenant:
            hdrs["X-Acta-Tenant"] = self.locked_tenant
        return hdrs

    def _request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        allowed_statuses: tuple[int, ...] = (200, 201),
        include_tenant_lock: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        headers = self._headers(include_tenant_lock=include_tenant_lock)

        if self._http is not None:
            resp = self._http.request(method, path, content=payload_bytes, headers=headers)
            status = int(resp.status_code)
            raw = resp.content
        else:
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(url, data=payload_bytes, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = int(resp.status)
                    raw = resp.read()
            except urllib.error.HTTPError as exc:
                status = int(exc.code)
                raw = exc.read()

        if status not in allowed_statuses:
            raise _parse_api_error(status, raw)
        return status, json.loads(raw.decode("utf-8"))

    def ensure_host_public_key(self) -> str:
        if self._pinned_pubkey:
            return self._pinned_pubkey
        health = self.health()
        pk = str(health["host_public_key"]).strip().lower()
        if len(bytes.fromhex(pk)) != 32:
            raise ActaSignatureVerificationError("server /v1/health returned invalid host_public_key")
        self._pinned_pubkey = pk
        return pk

    def health(self) -> dict[str, Any]:
        _, data = self._request_json(
            "GET", "/v1/health", allowed_statuses=(200,), include_tenant_lock=False
        )
        if self._pinned_pubkey and str(data.get("host_public_key", "")).lower() != self._pinned_pubkey:
            raise ActaSignatureVerificationError(
                f"host_public_key mismatch on /v1/health: server reported {data.get('host_public_key')}, "
                f"expected pinned {self._pinned_pubkey}"
            )
        return data

    def mint_tenant_key(self, tenant_id: str, *, principal: str | None = None) -> dict[str, Any]:
        """Mints a stateless `acta_tk_v1` key via `POST /v1/auth/mint-tenant-key` (requires master key)."""
        req: dict[str, Any] = {"tenant_id": tenant_id}
        if principal is not None:
            req["principal"] = principal
        _, data = self._request_json(
            "POST",
            "/v1/auth/mint-tenant-key",
            req,
            allowed_statuses=(200,),
            include_tenant_lock=False,
        )
        return data

    def inspect_key(self) -> dict[str, Any]:
        _, data = self._request_json("GET", "/v1/auth/inspect-key", allowed_statuses=(200,))
        return data

    def ingest_object(
        self,
        *,
        obj_type: ObjectTypeLiteral,
        scope: str,
        body: Any,
        tenant_id: str | None = None,
        priority: int = 0,
        importance: float = 0.5,
        tags: Sequence[str] = (),
        lifecycle_status: LifecycleLiteral = "active",
        embedding: Sequence[float] | None = None,
        predecessor_id: str | None = None,
        object_id: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "obj_type": obj_type,
            "scope": scope,
            "lifecycle_status": lifecycle_status,
            "priority": int(priority),
            "importance": float(importance),
            "tags": list(tags),
            "body": body,
        }
        if object_id is not None:
            req["id"] = object_id
        if embedding is not None:
            req["embedding"] = [float(x) for x in embedding]
        if predecessor_id is not None:
            req["predecessor_id"] = predecessor_id
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex

        _, data = self._request_json("POST", "/v1/objects", req, allowed_statuses=(200, 201))
        return data

    def ingest_claim(
        self,
        *,
        scope: str,
        subject: str,
        predicate: str,
        object_val: Any,
        object_type: str,
        confidence: float,
        source_descriptor: str,
        tenant_id: str | None = None,
        source_provenance_class: int = 1,
        source_commitment_hex: str | None = None,
        source_content: str | None = None,
        status: LifecycleLiteral = "active",
        contradiction_ids: Sequence[str] = (),
        valid_from: str | None = None,
        valid_to: str | None = None,
        predecessor_id: str | None = None,
        claim_id: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "scope": scope,
            "subject": subject,
            "predicate": predicate,
            "object_val": object_val,
            "object_type": object_type,
            "confidence": float(confidence),
            "source_provenance_class": int(source_provenance_class),
            "source_descriptor": source_descriptor,
            "status": status,
            "contradiction_ids": list(contradiction_ids),
        }
        if claim_id is not None:
            req["id"] = claim_id
        if source_commitment_hex is not None:
            req["source_commitment_hex"] = source_commitment_hex
        if source_content is not None:
            req["source_content"] = source_content
        if valid_from is not None:
            req["valid_from"] = valid_from
        if valid_to is not None:
            req["valid_to"] = valid_to
        if predecessor_id is not None:
            req["predecessor_id"] = predecessor_id
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex

        _, data = self._request_json("POST", "/v1/claims", req, allowed_statuses=(200, 201))
        return data

    def retract_claim(
        self,
        *,
        claim_id: str,
        reason: str,
        tenant_id: str | None = None,
        tombstone_id: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "claim_id": str(claim_id),
            "reason": reason,
        }
        if tombstone_id is not None:
            req["id"] = tombstone_id
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex
        _, data = self._request_json("POST", "/v1/claims/retract", req, allowed_statuses=(200, 201))
        return data

    def cache_answer(
        self,
        *,
        source_bundle_hash: str,
        answer_text: str,
        query_text: str = "",
        scope: str | None = None,
        task_id: str | None = None,
        answer_metadata: Mapping[str, Any] | None = None,
        ttl_seconds: int | None = None,
        validity_mode: str | None = None,
        dependency_ids: Sequence[str] | None = None,
        tenant_id: str | None = None,
        cache_id: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "source_bundle_hash": source_bundle_hash,
            "answer_text": answer_text,
            "query_text": query_text,
        }
        if cache_id is not None:
            req["id"] = cache_id
        if scope is not None:
            req["scope"] = scope
        if task_id is not None:
            req["task_id"] = task_id
        if answer_metadata is not None:
            req["answer_metadata"] = dict(answer_metadata)
        if ttl_seconds is not None:
            req["ttl_seconds"] = int(ttl_seconds)
        if validity_mode is not None:
            req["validity_mode"] = str(validity_mode)
        if dependency_ids is not None:
            req["dependency_ids"] = [str(d) for d in dependency_ids]
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex

        _, data = self._request_json("POST", "/v1/answers/cache", req, allowed_statuses=(200, 201))
        receipt = data["receipt"]
        ev = data["evidence"]
        verify_evidence_entry(ev, host_pk)
        if not verify_answer_cache_signature(
            host_pk,
            eff_tenant,
            int(receipt["evidence_seq_num"]),
            str(receipt["cache_commitment"]),
            str(receipt["host_signature"]),
        ):
            raise ActaSignatureVerificationError(
                "Ed25519 host_signature verification failed on cache_answer receipt"
            )
        return data

    def lookup_cached_answer(
        self,
        *,
        scope: str,
        task_id: str = "mcp-task",
        query_text: str = "",
        actor_id: str | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "scope": scope,
            "task_id": task_id,
            "query_text": query_text,
        }
        if actor_id is not None:
            req["actor_id"] = actor_id
        _, data = self._request_json(
            "POST", "/v1/answers/lookup", req, allowed_statuses=(200, 202, 403, 422)
        )
        if data.get("cache_hit") and data.get("receipt") is not None:
            rcp = data["receipt"]
            if not verify_answer_cache_signature(
                host_pk,
                eff_tenant,
                int(rcp["evidence_seq_num"]),
                str(rcp["cache_commitment"]),
                str(rcp["host_signature"]),
            ):
                raise ActaSignatureVerificationError(
                    "Ed25519 host_signature verification failed on lookup_cached_answer receipt"
                )
        if isinstance(data.get("invalidation_evidence"), Mapping):
            try:
                verify_evidence_entry(data["invalidation_evidence"], host_pk)
            except ValueError as exc:
                raise ActaSignatureVerificationError(str(exc)) from exc
        return data

    def trace_item_impact(
        self,
        item_id: str,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/impact/{urllib.parse.quote(str(item_id).strip())}",
            allowed_statuses=(200,),
        )
        return data

    def rebuild_scope_state(
        self,
        scope: str,
        *,
        up_to_seq: int | None = None,
        include_proof_archive: bool = False,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        qparts = [f"scope={urllib.parse.quote(scope)}"]
        if up_to_seq is not None:
            qparts.append(f"up_to_seq={int(up_to_seq)}")
        if include_proof_archive:
            qparts.append("include_proof_archive=true")
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/state-rebuild?{'&'.join(qparts)}",
            allowed_statuses=(200,),
        )
        if include_proof_archive and isinstance(data.get("rebuild_proof_archive"), Mapping):
            host_pk = self.ensure_host_public_key()
            try:
                offline = verify_and_rebuild_scope_state_offline(
                    data["rebuild_proof_archive"], host_pk, scope_override=scope
                )
            except ValueError as exc:
                raise ActaVerificationError(str(exc)) from exc
            if (
                offline.reconstructed_state_commitment_hex
                != str(data["reconstructed_state_commitment"]).lower()
            ):
                raise ActaVerificationError(
                    "offline state rebuild state_commitment mismatch against server response"
                )
        return data

    verify_state_rebuild = rebuild_scope_state

    def attest_override(
        self,
        *,
        scope: str,
        winning_claim_id: str,
        justification: str,
        adjudicator_id: str | None = None,
        tenant_id: str | None = None,
        source_bundle_hash_hex: str | None = None,
        override_id: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        """Signs and notarizes an immutable dispute-override attestation via `POST /v1/overrides`."""
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "scope": scope,
            "winning_claim_id": str(winning_claim_id),
            "justification": justification,
        }
        if adjudicator_id is not None:
            req["adjudicator_id"] = adjudicator_id
        if source_bundle_hash_hex is not None:
            req["source_bundle_hash_hex"] = source_bundle_hash_hex
        if override_id is not None:
            req["id"] = override_id
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex

        _, data = self._request_json("POST", "/v1/overrides", req, allowed_statuses=(200, 201))
        if not verify_override_signature(
            host_pk,
            eff_tenant,
            int(data["evidence_seq_num"]),
            str(data["attestation_hash"]),
            str(data["host_signature"]),
        ):
            raise ActaSignatureVerificationError(
                "Ed25519 host_signature verification failed on attest_override response"
            )
        return data

    def list_overrides(
        self,
        *,
        tenant_id: str | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        qs = f"?scope={urllib.parse.quote(scope)}" if scope else ""
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/overrides{qs}",
            allowed_statuses=(200,),
        )
        return data

    def get_checkpoint(
        self,
        *,
        tenant_id: str | None = None,
        tree_size: int | None = None,
        since_size: int | None = None,
    ) -> dict[str, Any]:
        """Fetches and locally verifies a RFC 6962 `SignedTreeHead` checkpoint (`GET /v1/tenants/:id/checkpoint`)."""
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        qparts: list[str] = []
        if tree_size is not None:
            qparts.append(f"tree_size={int(tree_size)}")
        if since_size is not None:
            qparts.append(f"since_size={int(since_size)}")
        qs = f"?{'&'.join(qparts)}" if qparts else ""

        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/checkpoint{qs}",
            allowed_statuses=(200,),
        )
        sth = data.get("checkpoint")
        if sth is not None:
            try:
                verify_signed_tree_head(sth, eff_tenant, host_pk)
            except ValueError as exc:
                raise ActaSignatureVerificationError(str(exc)) from exc
            cproof = data.get("consistency_proof")
            prior_sth = data.get("prior_checkpoint")
            if cproof is not None and prior_sth is not None:
                try:
                    verify_signed_tree_head(prior_sth, eff_tenant, host_pk)
                except ValueError as exc:
                    raise ActaSignatureVerificationError(str(exc)) from exc
                if not verify_merkle_consistency_proof(
                    int(prior_sth["tree_size"]),
                    str(prior_sth["merkle_root"]),
                    int(sth["tree_size"]),
                    str(sth["merkle_root"]),
                    cproof,
                ):
                    raise ActaVerificationError(
                        f"RFC 6962 consistency proof failed from first_size={prior_sth['tree_size']} to second_size={sth['tree_size']}"
                    )
            latest_anc = data.get("latest_anchored_checkpoint")
            anc_proof = data.get("consistency_proof_from_latest_anchor")
            if latest_anc is not None:
                try:
                    verify_signed_tree_head(latest_anc, eff_tenant, host_pk)
                except ValueError as exc:
                    raise ActaSignatureVerificationError(str(exc)) from exc
                a_sz = int(latest_anc["tree_size"])
                h_sz = int(sth["tree_size"])
                if a_sz < h_sz and anc_proof is not None:
                    if not verify_merkle_consistency_proof(
                        a_sz,
                        str(latest_anc["merkle_root"]),
                        h_sz,
                        str(sth["merkle_root"]),
                        anc_proof,
                    ):
                        raise ActaVerificationError(
                            f"RFC 6962 consistency proof failed from latest_anchored_checkpoint ({a_sz}) to head ({h_sz})"
                        )
        return data

    def register_witness(
        self,
        *,
        witness_id: str,
        witness_public_key_hex: str,
        description: str | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Enrolls an immutable trusted external witness Ed25519 key (`POST /v1/witnesses`)."""
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "witness_id": witness_id,
            "witness_public_key_hex": witness_public_key_hex,
        }
        if description is not None:
            req["description"] = description
        _, data = self._request_json("POST", "/v1/witnesses", req, allowed_statuses=(200, 201))
        return data

    def revoke_witness(
        self,
        *,
        witness_id: str,
        reason: str,
        mode: str = "compromise",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Revokes (`mode='compromise'`) or retires (`mode='retire'`) an enrolled witness (`POST /v1/witnesses/revoke`)."""
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "witness_id": witness_id,
            "mode": mode,
            "reason": reason,
        }
        _, data = self._request_json("POST", "/v1/witnesses/revoke", req, allowed_statuses=(200, 201))
        return data

    def list_witnesses(
        self,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/witnesses",
            allowed_statuses=(200,),
        )
        return data

    def anchor_checkpoint(
        self,
        *,
        tree_size: int,
        checkpoint_hash_hex: str,
        witness_id: str,
        witness_public_key_hex: str,
        witness_signature_hex: str,
        external_uri: str | None = None,
        anchor_id: str | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Appends an external witness Ed25519 cosignature to a `SignedTreeHead` (`POST /v1/anchors`)."""
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "tree_size": int(tree_size),
            "checkpoint_hash_hex": checkpoint_hash_hex,
            "witness_id": witness_id,
            "witness_public_key_hex": witness_public_key_hex,
            "witness_signature_hex": witness_signature_hex,
        }
        if anchor_id is not None:
            req["id"] = anchor_id
        if external_uri is not None:
            req["external_uri"] = external_uri

        _, data = self._request_json("POST", "/v1/anchors", req, allowed_statuses=(200, 201))
        anchor = data.get("anchor", data)
        if not verify_witness_anchor_signature(
            anchor["witness_public_key"],
            eff_tenant,
            int(anchor["tree_size"]),
            anchor["checkpoint_hash"],
            anchor["witness_signature"],
        ):
            raise ActaSignatureVerificationError(
                "Ed25519 witness_signature verification failed on anchor_checkpoint response"
            )
        return anchor

    def list_anchors(
        self,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/anchors",
            allowed_statuses=(200,),
        )
        return data

    def compile(
        self,
        *,
        actor_id: str,
        scope: str,
        query_text: str,
        tenant_id: str | None = None,
        task_id: str | None = None,
        budget: ContextBudget | Mapping[str, Any] | None = None,
        query_embedding: Sequence[float] | None = None,
        evaluation_time: str | None = None,
    ) -> CompileResult:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        budget_dict = (
            budget.to_dict()
            if isinstance(budget, ContextBudget)
            else dict(budget)
            if budget is not None
            else ContextBudget.tokens(4096).to_dict()
        )
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "actor_id": actor_id,
            "task_id": task_id or f"task-{uuid.uuid4().hex[:12]}",
            "scope": scope,
            "query_text": query_text,
            "budget": budget_dict,
        }
        if query_embedding is not None:
            req["query_embedding"] = [float(x) for x in query_embedding]
        if evaluation_time is not None:
            req["evaluation_time"] = evaluation_time

        status, payload = self._request_json(
            "POST", "/v1/compile", req, allowed_statuses=(200, 202, 403)
        )
        evidence = payload.get("evidence")
        if not isinstance(evidence, Mapping):
            raise ActaSignatureVerificationError("compile response missing signed evidence entry")

        try:
            verify_evidence_entry(evidence, host_pk)
        except ValueError as exc:
            raise ActaSignatureVerificationError(str(exc)) from exc

        return CompileResult.from_wire(status, payload, host_pk)

    def compile_guarded(
        self,
        *,
        actor_id: str,
        scope: str,
        query_text: str,
        tenant_id: str | None = None,
        task_id: str | None = None,
        budget: ContextBudget | Mapping[str, Any] | None = None,
        query_embedding: Sequence[float] | None = None,
        evaluation_time: str | None = None,
        strict_disputes: bool = True,
        halt_on_any_dispute: bool = False,
    ) -> CompileResult:
        res = self.compile(
            tenant_id=tenant_id,
            actor_id=actor_id,
            scope=scope,
            query_text=query_text,
            task_id=task_id,
            budget=budget,
            query_embedding=query_embedding,
            evaluation_time=evaluation_time,
        )
        return _enforce_guarded_compile(
            res,
            strict_disputes=strict_disputes,
            halt_on_any_dispute=halt_on_any_dispute,
        )

    def replay(
        self,
        *,
        actor_id: str,
        scope: str,
        query_text: str,
        tenant_id: str | None = None,
        task_id: str = "sdk-replay",
        budget: ContextBudget | Mapping[str, Any] | None = None,
        evaluation_time: str | None = None,
        counterfactual_evaluation_time: str | None = None,
        override_min_confidence: float | None = None,
        override_decisiveness_threshold: float | None = None,
        override_policy_cedar: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        budget_dict = (
            budget.to_dict()
            if isinstance(budget, ContextBudget)
            else dict(budget)
            if budget is not None
            else ContextBudget.tokens(4096).to_dict()
        )
        compile_req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "actor_id": actor_id,
            "task_id": task_id,
            "scope": scope,
            "query_text": query_text,
            "budget": budget_dict,
        }
        if evaluation_time is not None:
            compile_req["evaluation_time"] = evaluation_time

        body: dict[str, Any] = {"request": compile_req}
        if counterfactual_evaluation_time is not None:
            body["counterfactual_evaluation_time"] = counterfactual_evaluation_time
        if override_min_confidence is not None:
            body["override_min_confidence"] = float(override_min_confidence)
        if override_decisiveness_threshold is not None:
            body["override_decisiveness_threshold"] = float(override_decisiveness_threshold)
        if override_policy_cedar is not None:
            body["override_policy_cedar"] = override_policy_cedar

        _, data = self._request_json("POST", "/v1/replay", body, allowed_statuses=(200,))
        return data

    def export_bundle(
        self,
        bundle_hash: str,
        *,
        mode: str = "full",
        anchor_tree_size: int | None = None,
        anchored_tree_size: int | None = None,
    ) -> dict[str, Any]:
        if (
            anchor_tree_size is not None
            and anchored_tree_size is not None
            and int(anchor_tree_size) != int(anchored_tree_size)
        ):
            raise ValueError(
                f"conflicting anchor_tree_size ({anchor_tree_size}) and anchored_tree_size ({anchored_tree_size})"
            )
        eff_anchor = anchor_tree_size if anchor_tree_size is not None else anchored_tree_size
        clean = bundle_hash.strip().lower()
        params: list[str] = []
        if mode == "merkle":
            params.append("mode=merkle")
        if eff_anchor is not None:
            params.append(f"anchor_tree_size={int(eff_anchor)}")
        qs = ("?" + "&".join(params)) if params else ""
        _, data = self._request_json(
            "GET",
            f"/v1/bundles/{urllib.parse.quote(clean)}/export{qs}",
            allowed_statuses=(200,),
        )
        return data

    def verify_bundle_offline(
        self,
        bundle_hash: str,
        *,
        expected_pubkey_hex: str | None = None,
        mode: str = "full",
        anchor_tree_size: int | None = None,
        anchored_tree_size: int | None = None,
    ) -> VerificationSummary:
        pubkey = (expected_pubkey_hex or self.ensure_host_public_key()).strip().lower()
        archive = self.export_bundle(
            bundle_hash,
            mode=mode,
            anchor_tree_size=anchor_tree_size,
            anchored_tree_size=anchored_tree_size,
        )
        try:
            return verify_export_archive(archive, pubkey)
        except ValueError as exc:
            raise ActaVerificationError(str(exc)) from exc

    def verify_archive_remote(
        self,
        archive: Mapping[str, Any],
        *,
        expected_pubkey_hex: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"archive": dict(archive)}
        if expected_pubkey_hex is not None:
            body["expected_pubkey_hex"] = expected_pubkey_hex
        status, data = self._request_json(
            "POST", "/v1/verify", body, allowed_statuses=(200, 422)
        )
        if status == 422 or not data.get("verified"):
            raise ActaVerificationError(str(data.get("error", "archive verification failed")))
        return data

    def list_tenant_evidence(
        self,
        tenant_id: str | None = None,
        *,
        from_seq: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = self.ensure_host_public_key()
        qparts: list[str] = []
        if from_seq is not None:
            qparts.append(f"from_seq={int(from_seq)}")
        if limit is not None:
            qparts.append(f"limit={int(limit)}")
        qs = f"?{'&'.join(qparts)}" if qparts else ""
        _, data = self._request_json(
            "GET",
            f"/v1/tenants/{urllib.parse.quote(eff_tenant)}/evidence{qs}",
            allowed_statuses=(200,),
        )
        entries = data.get("entries", [])
        for idx, entry in enumerate(entries):
            try:
                verify_evidence_entry(entry, host_pk)
            except ValueError as exc:
                raise ActaSignatureVerificationError(f"entry[{idx}]: {exc}") from exc
        return data

    def mcp_call(self, method: str, params: Mapping[str, Any] | None = None, rpc_id: int = 1) -> dict[str, Any]:
        body = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": method,
            "params": dict(params or {}),
        }
        _, data = self._request_json("POST", "/mcp", body, allowed_statuses=(200,))
        return data


class AsyncActaClient:
    """Asynchronous Zero-Trust client for Acta Compiler v1.7.1 (requires `httpx`)."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        default_tenant_id: str | None = None,
        pinned_host_public_key: str | None = None,
        timeout: float = 15.0,
        httpx_async_client: Any = None,
    ) -> None:
        if _httpx is None and httpx_async_client is None:
            raise RuntimeError("AsyncActaClient requires `httpx` to be installed")
        resolved_url = base_url or os.environ.get("ACTA_BASE_URL") or DEFAULT_CLOUDRUN_URL
        self.base_url = resolved_url.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACTA_API_KEY")
        self.locked_tenant = _resolve_client_tenant_lock(self.api_key, default_tenant_id)
        self.verified_principal = extract_token_principal(self.api_key) if self.api_key else None
        self._pinned_pubkey = (
            pinned_host_public_key or os.environ.get("ACTA_HOST_PUBLIC_KEY") or None
        )
        if self._pinned_pubkey:
            self._pinned_pubkey = self._pinned_pubkey.strip().lower()
        self._owns_client = httpx_async_client is None
        self._http = (
            httpx_async_client
            if httpx_async_client is not None
            else _httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncActaClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    def _headers(self, *, include_tenant_lock: bool = True) -> dict[str, str]:
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)",
        }
        if self.api_key:
            hdrs["X-Acta-Api-Key"] = self.api_key
        if include_tenant_lock and self.locked_tenant:
            hdrs["X-Acta-Tenant"] = self.locked_tenant
        return hdrs

    async def _request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        allowed_statuses: tuple[int, ...] = (200, 201),
        include_tenant_lock: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        resp = await self._http.request(
            method, path, content=payload_bytes, headers=self._headers(include_tenant_lock=include_tenant_lock)
        )
        status = int(resp.status_code)
        if status not in allowed_statuses:
            raise _parse_api_error(status, resp.content)
        return status, resp.json()

    async def ensure_host_public_key(self) -> str:
        if self._pinned_pubkey:
            return self._pinned_pubkey
        _, health = await self._request_json(
            "GET", "/v1/health", allowed_statuses=(200,), include_tenant_lock=False
        )
        pk = str(health["host_public_key"]).strip().lower()
        if len(bytes.fromhex(pk)) != 32:
            raise ActaSignatureVerificationError("server /v1/health returned invalid host_public_key")
        self._pinned_pubkey = pk
        return pk

    async def attest_override(
        self,
        *,
        scope: str,
        winning_claim_id: str,
        justification: str,
        adjudicator_id: str | None = None,
        tenant_id: str | None = None,
        source_bundle_hash_hex: str | None = None,
        client_signature_hex: str | None = None,
        client_public_key_hex: str | None = None,
    ) -> dict[str, Any]:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = await self.ensure_host_public_key()
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "scope": scope,
            "winning_claim_id": str(winning_claim_id),
            "justification": justification,
        }
        if adjudicator_id is not None:
            req["adjudicator_id"] = adjudicator_id
        if source_bundle_hash_hex is not None:
            req["source_bundle_hash_hex"] = source_bundle_hash_hex
        if client_signature_hex is not None:
            req["client_signature_hex"] = client_signature_hex
        if client_public_key_hex is not None:
            req["client_public_key_hex"] = client_public_key_hex
        _, data = await self._request_json("POST", "/v1/overrides", req, allowed_statuses=(200, 201))
        if not verify_override_signature(
            host_pk,
            eff_tenant,
            int(data["evidence_seq_num"]),
            str(data["attestation_hash"]),
            str(data["host_signature"]),
        ):
            raise ActaSignatureVerificationError(
                "Ed25519 host_signature verification failed on attest_override response"
            )
        return data

    async def compile_guarded(
        self,
        *,
        actor_id: str,
        scope: str,
        query_text: str,
        tenant_id: str | None = None,
        task_id: str | None = None,
        budget: ContextBudget | Mapping[str, Any] | None = None,
        strict_disputes: bool = True,
        halt_on_any_dispute: bool = False,
    ) -> CompileResult:
        eff_tenant = _enforce_tenant(self.locked_tenant, tenant_id)
        host_pk = await self.ensure_host_public_key()
        budget_dict = (
            budget.to_dict()
            if isinstance(budget, ContextBudget)
            else dict(budget)
            if budget is not None
            else ContextBudget.tokens(4096).to_dict()
        )
        req: dict[str, Any] = {
            "tenant_id": eff_tenant,
            "actor_id": actor_id,
            "task_id": task_id or f"task-{uuid.uuid4().hex[:12]}",
            "scope": scope,
            "query_text": query_text,
            "budget": budget_dict,
        }
        status, payload = await self._request_json(
            "POST", "/v1/compile", req, allowed_statuses=(200, 202, 403)
        )
        try:
            verify_evidence_entry(payload["evidence"], host_pk)
        except ValueError as exc:
            raise ActaSignatureVerificationError(str(exc)) from exc

        res = CompileResult.from_wire(status, payload, host_pk)
        return _enforce_guarded_compile(
            res,
            strict_disputes=strict_disputes,
            halt_on_any_dispute=halt_on_any_dispute,
        )
