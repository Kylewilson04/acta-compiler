#!/usr/bin/env python3
"""Drop-in Acta Compiler v1.7.3 Governed Agent Runtime (`acta_sdk` >= 1.7.3).

Wires deterministic context governance into any live Python agent or LLM loop:
  1. Ed25519 Author Signing (`ed25519_client_sig`):
     Signs directives (`acta:object_client_sig:v1`), structured claims
     (`acta:claim_client_sig:v1`), cached answers (`acta:answer_client_sig:v1`),
     retractions (`acta:retract_client_sig:v1`), and dispute overrides (`acta:override:v2`)
     with synchronized canonical parameters so intent digests never drift.
  2. Pre-Turn O(1) Claim 25 Answer Cache Lookup (`lookup_cached_answer`):
     Verifies host Ed25519 cache receipts locally before compiling or calling the LLM,
     and verifies inline invalidation receipts on `stale_dependency_commitment`,
     `stale_state_commitment`, or `expired_ttl`.
  3. Pre-Inference Compilation Circuit Breaker (`compile_guarded`):
     Compiles an `acta-context-bundle/v2` (`acta:state:v2` commitment) and halts
     before spending a single LLM token when Cedar blocks/escalates or when
     competing claims trigger `ActaDisputeEscalationError`.
  4. Narrowed `dependency_ids` Cache Persistence & `409` Race Recovery (`cache_answer`):
     Pins Claim 25 tracking strictly to winning claims + selected memory objects
     (or explicit model-cited UUIDs) and handles concurrent writes during LLM
     inference (`409 bundle_stale_at_cache_time`) cleanly without crashing the turn.
  5. Salted-Commitment Ephemeral Secret Lifecycle (`erasable` / `erase_secret`):
     Keeps volatile secrets off `evidence_history` (`$acta_erasable_commitment`)
     and scrubs live secret storage on session teardown.

Run `python3 acta_governed_agent.py --selftest` to execute an offline, zero-network
end-to-end cryptographic verification across all six runtime paths.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from acta_sdk import (
    DEFAULT_CLOUDRUN_URL,
    ActaClient,
    ActaDisputeEscalationError,
    ActaHttpError,
    ActaPolicyBlockedError,
    ActaPolicyEscalatedError,
    ContextBudget,
    build_guarded_prompt,
    sign_answer_cache_client_intent,
    sign_claim_client_intent,
    sign_object_client_intent,
    sign_override_client_intent,
    sign_retract_claim_client_intent,
    verify_and_rebuild_scope_state_offline,
)
from acta_sdk.gemini import SYSTEM_GUARDRAIL_HEADER

PRODUCTION_HOST_PUBKEY_HEX = (
    "e4611d0a9bf54101e68d30cf21fff1de38abeb3d294e879b05fcc7f6e2d1c52f"
)


@dataclass(frozen=True)
class AgentKeyring:
    """Manages the agent's 32-byte Ed25519 author signing seed."""

    seed_bytes: bytes
    public_key_hex: str

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "AgentKeyring":
        raw = bytes.fromhex(seed_hex.strip())
        if len(raw) != 32:
            raise ValueError(f"Expected 32-byte Ed25519 seed (64 hex chars), got {len(raw)} bytes")
        _, pub_hex = sign_retract_claim_client_intent(
            raw,
            tenant_id="probe",
            claim_id="00000000-0000-0000-0000-000000000000",
            reason="probe",
        )
        return cls(seed_bytes=raw, public_key_hex=pub_hex)

    @classmethod
    def from_env_or_file(
        cls,
        env_var: str = "ACTA_AGENT_SEED_HEX",
        seed_path: str | Path = "~/.config/acta/agent_ed25519.seed",
    ) -> "AgentKeyring":
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            return cls.from_seed_hex(env_val)
        path = Path(seed_path).expanduser()
        if path.exists():
            return cls.from_seed_hex(path.read_text(encoding="utf-8").strip())
        path.parent.mkdir(parents=True, exist_ok=True)
        fresh_hex = os.urandom(32).hex()
        path.write_text(fresh_hex + "\n", encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return cls.from_seed_hex(fresh_hex)


@dataclass
class TurnOutcome:
    """Structured telemetry and cryptographic provenance returned by every governed turn."""

    status: str  # "cache_hit" | "compiled_and_generated" | "dispute_halted" | "policy_blocked" | "policy_escalated"
    answer_text: str | None
    llm_invoked: bool
    scope: str
    task_id: str
    bundle_hash: str | None = None
    state_commitment: str | None = None
    cache_id: str | None = None
    cache_write_status: str | None = None  # "cached" | "skipped_stale_bundle" | "disabled" | None
    pinned_dependency_ids: list[str] = field(default_factory=list)
    invalidation_reason: str | None = None
    invalidation_seq_num: int | None = None
    disputes: list[dict[str, Any]] = field(default_factory=list)
    policy_reason: str | None = None
    evidence_seq_num: int | None = None


LlmCallable = Callable[[str, str, Any], str | tuple[str, Sequence[str]]]


def extract_bundle_dependency_ids(
    bundle: Mapping[str, Any],
    cited_item_ids: Sequence[str] | None = None,
) -> tuple[str, list[str]]:
    """Computes the narrowest sound Claim 25 `(validity_mode, dependency_ids)` pair for `bundle`."""
    valid_bundle_ids: set[str] = set()
    winning_claim_ids: list[str] = []
    memory_ids: list[str] = []

    for obj in bundle.get("selected_objects") or []:
        oid = str(obj["id"])
        valid_bundle_ids.add(oid)
        if obj.get("obj_type") == "memory":
            memory_ids.append(oid)

    for rec in bundle.get("resolution_records") or []:
        w_id = str(rec["winning_claim"]["id"])
        valid_bundle_ids.add(w_id)
        winning_claim_ids.append(w_id)
        for sup_id in rec.get("suppressed_claim_ids") or []:
            valid_bundle_ids.add(str(sup_id))

    if cited_item_ids:
        cleaned = sorted({str(x).strip() for x in cited_item_ids if str(x).strip()})
        unknown = [x for x in cleaned if x not in valid_bundle_ids]
        if unknown:
            raise ValueError(
                f"Model cited item IDs not present in compiled ContextBundle: {unknown}"
            )
        return "dependency_subset", cleaned

    auto_pinned = sorted(set(winning_claim_ids + memory_ids))
    if auto_pinned:
        return "dependency_subset", auto_pinned
    return "scope_root", []


class ActaGovernedAgent:
    """Production runtime binding `ActaClient` (`v1.7.3`) into an autonomous agent workflow."""

    def __init__(
        self,
        *,
        client: ActaClient,
        keyring: AgentKeyring,
        tenant_id: str,
        actor_id: str = "governed-agent@local",
        default_budget_tokens: int = 2048,
        strict_disputes: bool = True,
        halt_on_any_dispute: bool = False,
    ) -> None:
        self.client = client
        self.keyring = keyring
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.default_budget = ContextBudget(kind="tokens", limit=default_budget_tokens)
        self.strict_disputes = strict_disputes
        self.halt_on_any_dispute = halt_on_any_dispute

    @classmethod
    def from_env(cls, *, actor_id: str = "governed-agent@local") -> "ActaGovernedAgent":
        base_url = os.environ.get("ACTA_BASE_URL", DEFAULT_CLOUDRUN_URL).strip()
        api_key = os.environ.get("ACTA_API_KEY", "").strip() or None
        tenant_id = os.environ.get("ACTA_TENANT_ID", "kylewilson04").strip()
        host_pk = os.environ.get("ACTA_HOST_PUBKEY", PRODUCTION_HOST_PUBKEY_HEX).strip()
        keyring = AgentKeyring.from_env_or_file()
        client = ActaClient(
            base_url=base_url,
            api_key=api_key,
            default_tenant_id=tenant_id,
            pinned_host_public_key=host_pk,
        )
        return cls(client=client, keyring=keyring, tenant_id=tenant_id, actor_id=actor_id)

    def record_directive(
        self,
        *,
        scope: str,
        body: Mapping[str, Any] | str,
        obj_type: str = "intent",
        priority: int = 90,
        importance: float = 1.0,
        tags: Sequence[str] = (),
        lifecycle_status: str = "active",
        predecessor_id: str | None = None,
    ) -> dict[str, Any]:
        """Appends an Ed25519-signed `[INTENT]` or `[MEMORY]` object (`acta:object_client_sig:v1`)."""
        sig_hex, pub_hex = sign_object_client_intent(
            self.keyring.seed_bytes,
            tenant_id=self.tenant_id,
            obj_type=obj_type,
            scope=scope,
            body=body,
            lifecycle_status=lifecycle_status,
            priority=priority,
            importance=importance,
            tags=list(tags),
            predecessor_id=predecessor_id,
        )
        return self.client.ingest_object(
            tenant_id=self.tenant_id,
            obj_type=obj_type,  # type: ignore[arg-type]
            scope=scope,
            body=body,
            priority=priority,
            importance=importance,
            tags=list(tags),
            lifecycle_status=lifecycle_status,  # type: ignore[arg-type]
            predecessor_id=predecessor_id,
            client_signature_hex=sig_hex,
            client_public_key_hex=pub_hex,
        )

    def record_claim(
        self,
        *,
        scope: str,
        subject: str,
        predicate: str,
        object_val: Any,
        object_type: str,
        source_descriptor: str,
        confidence: float = 0.85,
        source_provenance_class: int = 2,
        source_content: str | None = None,
        contradiction_ids: Sequence[str] = (),
        valid_from: str | None = None,
        valid_to: str | None = None,
        predecessor_id: str | None = None,
        erasable: bool = False,
    ) -> dict[str, Any]:
        """Appends an Ed25519-signed claim (`acta:claim_client_sig:v1`) with synchronized fields."""
        sig_hex, pub_hex = sign_claim_client_intent(
            self.keyring.seed_bytes,
            tenant_id=self.tenant_id,
            scope=scope,
            subject=subject,
            predicate=predicate,
            object_val=object_val,
            object_type=object_type,
            confidence=confidence,
            source_descriptor=source_descriptor,
            source_provenance_class=source_provenance_class,
            source_content=source_content,
            status="active",
            contradiction_ids=list(contradiction_ids),
            valid_from=valid_from,
            valid_to=valid_to,
            predecessor_id=predecessor_id,
        )
        return self.client.ingest_claim(
            tenant_id=self.tenant_id,
            scope=scope,
            subject=subject,
            predicate=predicate,
            object_val=object_val,
            object_type=object_type,
            confidence=confidence,
            source_descriptor=source_descriptor,
            source_provenance_class=source_provenance_class,
            source_content=source_content,
            status="active",
            contradiction_ids=list(contradiction_ids),
            valid_from=valid_from,
            valid_to=valid_to,
            predecessor_id=predecessor_id,
            erasable=True if erasable else None,
            client_signature_hex=sig_hex,
            client_public_key_hex=pub_hex,
        )

    def teardown_ephemeral_secret(
        self,
        *,
        scope: str,
        claim_id: str,
        reason: str = "Session complete; volatile secret scrubbed",
    ) -> dict[str, Any]:
        """Retracts an `erasable=True` claim and scrubs its cleartext secret (`erase_secret=True`)."""
        sig_hex, pub_hex = sign_retract_claim_client_intent(
            self.keyring.seed_bytes,
            tenant_id=self.tenant_id,
            claim_id=claim_id,
            reason=reason,
        )
        return self.client.retract_claim(
            tenant_id=self.tenant_id,
            scope=scope,
            claim_id=claim_id,
            reason=reason,
            erase_secret=True,
            client_signature_hex=sig_hex,
            client_public_key_hex=pub_hex,
        )

    def adjudicate_dispute(
        self,
        *,
        scope: str,
        winning_claim_id: str,
        justification: str,
        adjudicator_id: str | None = None,
        source_bundle_hash: str | None = None,
    ) -> dict[str, Any]:
        """Notarizes a signed `acta:override:v2` adjudication to unblock a disputed claim group."""
        eff_adj = adjudicator_id or self.actor_id
        sig_hex, pub_hex = sign_override_client_intent(
            self.keyring.seed_bytes,
            tenant_id=self.tenant_id,
            scope=scope,
            winning_claim_id=winning_claim_id,
            adjudicator_id=eff_adj,
            justification=justification,
        )
        return self.client.attest_override(
            tenant_id=self.tenant_id,
            scope=scope,
            winning_claim_id=winning_claim_id,
            adjudicator_id=eff_adj,
            justification=justification,
            source_bundle_hash_hex=source_bundle_hash,
            client_signature_hex=sig_hex,
            client_public_key_hex=pub_hex,
        )

    def run_turn(
        self,
        *,
        scope: str,
        task_id: str,
        query_text: str,
        llm_callable: LlmCallable,
        ttl_seconds: int | None = 3600,
        cache_enabled: bool = True,
        extra_system_instruction: str | None = None,
        budget: ContextBudget | None = None,
    ) -> TurnOutcome:
        """Executes the 4-stage governed turn: Cache Lookup -> Compile Gate -> LLM -> Narrowed Cache Write."""
        invalidation_reason: str | None = None
        invalidation_seq: int | None = None

        # Stage 1: O(1) Claim 25 dependency-conditioned cache pre-check
        if cache_enabled:
            lookup = self.client.lookup_cached_answer(
                tenant_id=self.tenant_id,
                scope=scope,
                task_id=task_id,
                query_text=query_text,
                actor_id=self.actor_id,
            )
            if lookup.get("cache_hit"):
                rcp = lookup["receipt"]
                return TurnOutcome(
                    status="cache_hit",
                    answer_text=str(lookup["answer_text"]),
                    llm_invoked=False,
                    scope=scope,
                    task_id=task_id,
                    bundle_hash=str(rcp["source_bundle_hash"]),
                    state_commitment=str(rcp["state_commitment"]),
                    cache_id=str(rcp["cache_id"]),
                    pinned_dependency_ids=[str(x) for x in rcp.get("dependency_ids") or []],
                    evidence_seq_num=int(rcp["evidence_seq_num"]),
                )
            inv_ev = lookup.get("invalidation_evidence")
            if isinstance(inv_ev, Mapping):
                acs = inv_ev.get("answer_cache_summary") or {}
                invalidation_reason = acs.get("invalidation_reason") or lookup.get("status")
                invalidation_seq = int(inv_ev["seq_num"])

        # Stage 2: Pre-LLM compilation & contradiction/policy circuit breaker
        try:
            compiled = self.client.compile_guarded(
                tenant_id=self.tenant_id,
                actor_id=self.actor_id,
                scope=scope,
                task_id=task_id,
                query_text=query_text,
                budget=budget or self.default_budget,
                strict_disputes=self.strict_disputes,
                halt_on_any_dispute=self.halt_on_any_dispute,
            )
        except ActaDisputeEscalationError as exc:
            return TurnOutcome(
                status="dispute_halted",
                answer_text=None,
                llm_invoked=False,
                scope=scope,
                task_id=task_id,
                bundle_hash=exc.bundle_hash,
                disputes=list(exc.disputes),
                invalidation_reason=invalidation_reason,
                invalidation_seq_num=invalidation_seq,
                evidence_seq_num=int(exc.evidence["seq_num"]),
            )
        except ActaPolicyBlockedError as exc:
            return TurnOutcome(
                status="policy_blocked",
                answer_text=None,
                llm_invoked=False,
                scope=scope,
                task_id=task_id,
                policy_reason=exc.reason,
                evidence_seq_num=int(exc.evidence["seq_num"]),
            )
        except ActaPolicyEscalatedError as exc:
            return TurnOutcome(
                status="policy_escalated",
                answer_text=None,
                llm_invoked=False,
                scope=scope,
                task_id=task_id,
                policy_reason=exc.reason,
                evidence_seq_num=int(exc.evidence["seq_num"]),
            )

        assert compiled.bundle is not None and compiled.bundle_hash is not None
        state_comm = str(compiled.bundle["state_commitment"])

        # Stage 3: Guarded LLM call inside the verified ContextBundle envelope
        sys_inst = (
            f"{SYSTEM_GUARDRAIL_HEADER}\n\n{extra_system_instruction}"
            if extra_system_instruction
            else SYSTEM_GUARDRAIL_HEADER
        )
        guarded_prompt = build_guarded_prompt(
            compiled.context_text or "", query_text, compiled.bundle_hash
        )
        llm_out = llm_callable(guarded_prompt, sys_inst, compiled)
        if isinstance(llm_out, tuple):
            answer_text, cited_ids = str(llm_out[0]), list(llm_out[1])
        else:
            answer_text, cited_ids = str(llm_out), None

        if not cache_enabled:
            return TurnOutcome(
                status="compiled_and_generated",
                answer_text=answer_text,
                llm_invoked=True,
                scope=scope,
                task_id=task_id,
                bundle_hash=compiled.bundle_hash,
                state_commitment=state_comm,
                cache_write_status="disabled",
                invalidation_reason=invalidation_reason,
                invalidation_seq_num=invalidation_seq,
                evidence_seq_num=int(compiled.evidence["seq_num"]),
            )

        # Stage 4: Narrowed Claim 25 cache write + graceful 409 stale-bundle race handling
        validity_mode, dep_ids = extract_bundle_dependency_ids(compiled.bundle, cited_ids)
        ans_sig_hex, ans_pub_hex = sign_answer_cache_client_intent(
            self.keyring.seed_bytes,
            tenant_id=self.tenant_id,
            scope=scope,
            task_id=task_id,
            query_text=query_text,
            source_bundle_hash=compiled.bundle_hash,
            state_commitment=state_comm,
            answer_text=answer_text,
        )
        try:
            cached = self.client.cache_answer(
                tenant_id=self.tenant_id,
                scope=scope,
                task_id=task_id,
                query_text=query_text,
                source_bundle_hash=compiled.bundle_hash,
                answer_text=answer_text,
                ttl_seconds=ttl_seconds,
                validity_mode=validity_mode,
                dependency_ids=dep_ids if dep_ids else None,
                client_signature_hex=ans_sig_hex,
                client_public_key_hex=ans_pub_hex,
            )
            rcp = cached["receipt"]
            return TurnOutcome(
                status="compiled_and_generated",
                answer_text=answer_text,
                llm_invoked=True,
                scope=scope,
                task_id=task_id,
                bundle_hash=compiled.bundle_hash,
                state_commitment=state_comm,
                cache_id=str(rcp["cache_id"]),
                cache_write_status="cached",
                pinned_dependency_ids=[str(x) for x in rcp.get("dependency_ids") or []],
                invalidation_reason=invalidation_reason,
                invalidation_seq_num=invalidation_seq,
                evidence_seq_num=int(rcp["evidence_seq_num"]),
            )
        except ActaHttpError as exc:
            if exc.status_code == 409:
                return TurnOutcome(
                    status="compiled_and_generated",
                    answer_text=answer_text,
                    llm_invoked=True,
                    scope=scope,
                    task_id=task_id,
                    bundle_hash=compiled.bundle_hash,
                    state_commitment=state_comm,
                    cache_write_status="skipped_stale_bundle",
                    pinned_dependency_ids=dep_ids,
                    invalidation_reason=invalidation_reason,
                    invalidation_seq_num=invalidation_seq,
                    evidence_seq_num=int(compiled.evidence["seq_num"]),
                )
            raise

    def export_and_verify_scope_offline(self, scope: str) -> Any:
        """Exports a signed `StateRebuildArchive/v2` and verifies state reconstruction locally."""
        resp = self.client.verify_state_rebuild(scope, include_proof_archive=True)
        host_pk = self.client.ensure_host_public_key()
        return verify_and_rebuild_scope_state_offline(resp, host_pk, scope)


# ============================================================================
# Offline Self-Test Harness (Zero Network Traffic, Real Ed25519 + BLAKE3 Crypto)
# ============================================================================


def _run_offline_selftest() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from acta_sdk.crypto import (
        SCHEMA_VERSION_V2,
        answer_cache_signing_preimage,
        compute_answer_cache_client_intent_hash,
        compute_answer_cache_summary_commitment,
        compute_answer_text_hash,
        compute_bundle_hash,
        compute_claim_client_intent_hash,
        compute_erasable_claim_commitment,
        compute_evidence_event_hash,
        compute_object_client_intent_hash,
        compute_query_text_hash,
        compute_retract_claim_client_intent_hash,
        compute_state_commitment,
        compute_sub_commitment_v2,
        hash_length_delimited,
        sign_evidence_entry,
    )

    host_seed = os.urandom(32)
    host_sk = Ed25519PrivateKey.from_private_bytes(host_seed)
    host_pk_hex = (
        host_sk.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    agent_keyring = AgentKeyring.from_seed_hex(os.urandom(32).hex())
    tenant_id = "ardyn-selftest"
    scope = "agent/ardyn/ops"
    perm_root = "3ff40da50dd7f2aa32ce30409426f6d485bcf376caa4ff862f3aeb071410772a"

    class _InMemoryV173Transport:
        """Minimal spec-faithful v1.7.3 mock verifying client signatures & signing host receipts."""

        def __init__(self) -> None:
            self.seq = 0
            self.prev_hash = "0" * 64
            self.objects: dict[str, dict[str, Any]] = {}
            self.claims: dict[str, dict[str, Any]] = {}
            self.bundles: dict[str, dict[str, Any]] = {}
            self.caches: dict[tuple[str, str, str], dict[str, Any]] = {}
            self.secrets: dict[str, Any] = {}
            self.force_next_cache_409 = False

        def _append_event(
            self,
            *,
            bundle_hash: str | None = None,
            state_commitment: str | None = None,
            policy_result: str = "allow",
            answer_cache_summary: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            self.seq += 1
            created_at = f"2026-11-25T02:00:{self.seq:02d}.000000Z"
            ev_hash = compute_evidence_event_hash(
                tenant_id,
                self.seq,
                self.prev_hash,
                bundle_hash,
                state_commitment,
                policy_result,
                created_at,
                answer_cache_summary=answer_cache_summary,
            ).hex()
            ev: dict[str, Any] = {
                "tenant_id": tenant_id,
                "seq_num": self.seq,
                "event_domain": "acta:evidence_event:v3" if answer_cache_summary else "acta:evidence_event:v1",
                "prev_hash": self.prev_hash,
                "event_hash": ev_hash,
                "bundle_hash": bundle_hash,
                "state_commitment": state_commitment,
                "policy_result": policy_result,
                "created_at": created_at,
                "host_signature": sign_evidence_entry(
                    host_seed, tenant_id, self.seq, self.prev_hash, ev_hash
                ).hex(),
            }
            if answer_cache_summary is not None:
                ev["answer_cache_summary"] = answer_cache_summary
            self.prev_hash = ev_hash
            return ev

        def _live_state_commitment(self) -> str:
            i_root = compute_sub_commitment_v2([]).hex()
            k_root = compute_sub_commitment_v2(
                [
                    hash_length_delimited([b"clm", cid.encode()]).hex()
                    for cid, c in sorted(self.claims.items())
                    if c["status"] == "active"
                ]
            ).hex()
            m_root = compute_sub_commitment_v2([]).hex()
            return compute_state_commitment(
                SCHEMA_VERSION_V2,
                tenant_id,
                scope,
                i_root,
                k_root,
                m_root,
                perm_root,
            ).hex()

        def request_json(
            self,
            method: str,
            path: str,
            body: Mapping[str, Any] | None = None,
            *,
            allowed_statuses: Sequence[int] = (200,),
        ) -> tuple[int, Any]:
            payload = dict(body or {})
            if path == "/v1/objects":
                digest = compute_object_client_intent_hash(
                    payload["tenant_id"],
                    payload["obj_type"],
                    payload["scope"],
                    payload["lifecycle_status"],
                    payload["priority"],
                    payload["importance"],
                    payload["tags"],
                    payload["body"],
                    payload.get("predecessor_id"),
                )
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload["client_public_key_hex"])).verify(
                    bytes.fromhex(payload["client_signature_hex"]), digest
                )
                oid = str(uuid.uuid4())
                self.objects[oid] = {"id": oid, **payload}
                ev = self._append_event(state_commitment=self._live_state_commitment())
                return 201, {"object": self.objects[oid], "evidence": ev}

            if path == "/v1/claims":
                src_comm = hash_length_delimited([b"acta:source:v1", payload["source_descriptor"].encode()])
                digest = compute_claim_client_intent_hash(
                    payload["tenant_id"],
                    payload["scope"],
                    payload["subject"],
                    payload["predicate"],
                    payload["object_val"],
                    payload["object_type"],
                    payload["confidence"],
                    payload["source_provenance_class"],
                    payload["source_descriptor"],
                    src_comm,
                    payload["status"],
                    payload["contradiction_ids"],
                    payload.get("valid_from"),
                    payload.get("valid_to"),
                    payload.get("predecessor_id"),
                )
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload["client_public_key_hex"])).verify(
                    bytes.fromhex(payload["client_signature_hex"]), digest
                )
                if payload.get("predecessor_id") and payload["predecessor_id"] in self.claims:
                    self.claims[payload["predecessor_id"]]["status"] = "superseded"
                cid = str(uuid.uuid4())
                rec = {"id": cid, **payload}
                if payload.get("erasable"):
                    comm = compute_erasable_claim_commitment(
                        cid, os.urandom(32), payload["object_val"], src_comm
                    ).hex()
                    self.secrets[cid] = payload["object_val"]
                    rec["object_val"] = {"$acta_erasable_commitment": comm}
                    rec["erasure_commitment_hex"] = comm
                self.claims[cid] = rec
                ev = self._append_event(state_commitment=self._live_state_commitment())
                return 201, {"claim": rec, "evidence": ev}

            if path == "/v1/claims/retract":
                digest = compute_retract_claim_client_intent_hash(
                    payload["tenant_id"], payload["claim_id"], payload["reason"]
                )
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload["client_public_key_hex"])).verify(
                    bytes.fromhex(payload["client_signature_hex"]), digest
                )
                cid = payload["claim_id"]
                self.claims[cid]["status"] = "revoked"
                erased = False
                if payload.get("erase_secret") and cid in self.secrets:
                    del self.secrets[cid]
                    erased = True
                ev = self._append_event(state_commitment=self._live_state_commitment())
                return 200, {"tombstone_id": str(uuid.uuid4()), "secret_erased": erased, "evidence": ev}

            if path == "/v1/compile":
                active_claims = [
                    c for c in self.claims.values()
                    if c["status"] == "active" and not isinstance(c["object_val"], dict)
                ]
                vals = {c["object_val"] for c in active_claims if c["predicate"] == "lead_days"}
                disputes = []
                resolutions = []
                if len(vals) > 1:
                    disputes.append({
                        "claim_group_key": "deadbeef" * 8,
                        "subject": "supplier:vortex",
                        "predicate": "lead_days",
                        "escalation_required": True,
                        "competing_claims": active_claims,
                    })
                elif active_claims:
                    lead_claims = [c for c in active_claims if c["predicate"] == "lead_days"]
                    if lead_claims:
                        winner = lead_claims[0]
                        resolutions.append({
                            "claim_group_key": "cafebabe" * 8,
                            "winning_claim": {
                                "id": winner["id"],
                                "subject": winner["subject"],
                                "predicate": winner["predicate"],
                                "object_val": winner["object_val"],
                                "object_type": winner["object_type"],
                                "confidence": winner["confidence"],
                                "source_provenance_class": winner["source_provenance_class"],
                                "source_descriptor": winner["source_descriptor"],
                                "source_commitment": "11" * 32,
                                "content_hash": "22" * 32,
                                "version": 1,
                                "created_at": "2026-11-25T02:00:00Z",
                                "corroborating_count": len(lead_claims),
                                "corroborating_sources": [c["source_descriptor"] for c in lead_claims],
                                "effective_confidence": 0.9,
                            },
                            "margin": None,
                            "suppressed_claim_ids": [c["id"] for c in lead_claims[1:]],
                        })
                sc = self._live_state_commitment()
                bundle = {
                    "schema_version": SCHEMA_VERSION_V2,
                    "tenant_id": tenant_id,
                    "task_id": payload.get("task_id") or "default",
                    "scope": payload["scope"],
                    "policy_result": "allow",
                    "embedding_model_version": "text-embedding-3-small-1536",
                    "resolver_manifest": {
                        "min_confidence": 0.7,
                        "decisiveness_threshold": 0.15,
                        "corroboration_damping": 0.5,
                        "non_default_thresholds": False,
                        "budget": {"kind": "tokens", "limit": 2048},
                        "permission_root": perm_root,
                        "resolver_version": "v1.7.3",
                    },
                    "selected_objects": [
                        {"id": oid, "obj_type": o["obj_type"], "version": 1, "content_hash": "33" * 32}
                        for oid, o in self.objects.items()
                    ],
                    "resolution_records": resolutions,
                    "dispute_records": disputes,
                    "omission_record": {
                        "inline_items": [],
                        "total_omitted_count": 0,
                        "full_excluded_hash": "44" * 32,
                        "has_unresolved_claims": bool(disputes),
                    },
                    "resolved_facts_omitted": 0,
                    "state_commitment": sc,
                    "dependency_commitment": "55" * 32,
                    "issued_at": "2026-11-25T02:00:00Z",
                }
                b_hash_bytes, _ = compute_bundle_hash(bundle)
                b_hash = b_hash_bytes.hex()
                self.bundles[b_hash] = bundle
                ev = self._append_event(bundle_hash=b_hash, state_commitment=sc)
                return 200, {
                    "policy_decision": {"decision": "allow"},
                    "bundle_hash": b_hash,
                    "context_text": "[FACT] supplier:vortex.lead_days = 12",
                    "bundle": bundle,
                    "evidence": ev,
                }

            if path == "/v1/answers/cache":
                if self.force_next_cache_409:
                    self.force_next_cache_409 = False
                    raise ActaHttpError(409, {"reason_code": "bundle_stale_at_cache_time"})
                b = self.bundles[payload["source_bundle_hash"]]
                q_hash = compute_query_text_hash(payload["query_text"]).hex()
                a_hash = compute_answer_text_hash(payload["answer_text"]).hex()
                digest = compute_answer_cache_client_intent_hash(
                    tenant_id,
                    payload["scope"],
                    payload["task_id"],
                    q_hash,
                    payload["source_bundle_hash"],
                    b["state_commitment"],
                    a_hash,
                )
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload["client_public_key_hex"])).verify(
                    bytes.fromhex(payload["client_signature_hex"]), digest
                )
                cache_id = str(uuid.uuid4())
                dep_ids = list(payload.get("dependency_ids") or [])
                acs = {
                    "cache_domain": "acta:answer_cache:v1",
                    "event_kind": "cached",
                    "cache_id": cache_id,
                    "scope": payload["scope"],
                    "task_id": payload["task_id"],
                    "query_hash": q_hash,
                    "source_bundle_hash": payload["source_bundle_hash"],
                    "state_commitment": b["state_commitment"],
                    "validity_mode": payload.get("validity_mode", "dependency_subset"),
                    "task_dependency_commitment": "66" * 32,
                    "dependency_ids": dep_ids,
                    "answer_hash": a_hash,
                    "cached_by": f"{tenant_id}::sdk",
                    "cacher_auth_kind": "ed25519_client_sig",
                    "client_public_key": payload["client_public_key_hex"],
                    "client_signature": payload["client_signature_hex"],
                }
                cc_hex = compute_answer_cache_summary_commitment(acs).hex()
                ev = self._append_event(state_commitment=cc_hex, answer_cache_summary=acs)
                rcp_sig = host_sk.sign(answer_cache_signing_preimage(tenant_id, ev["seq_num"], cc_hex)).hex()
                receipt = {
                    "cache_id": cache_id,
                    "tenant_id": tenant_id,
                    "scope": payload["scope"],
                    "task_id": payload["task_id"],
                    "query_hash": q_hash,
                    "source_bundle_hash": payload["source_bundle_hash"],
                    "state_commitment": b["state_commitment"],
                    "validity_mode": acs["validity_mode"],
                    "task_dependency_commitment": "66" * 32,
                    "dependency_ids": dep_ids,
                    "answer_hash": a_hash,
                    "cache_domain": "acta:answer_cache:v1",
                    "cache_commitment": cc_hex,
                    "evidence_seq_num": ev["seq_num"],
                    "host_signature": rcp_sig,
                    "cached_by": acs["cached_by"],
                    "cacher_auth_kind": "ed25519_client_sig",
                    "client_public_key_hex": payload["client_public_key_hex"],
                    "client_signature_hex": payload["client_signature_hex"],
                    "created_at": ev["created_at"],
                }
                self.caches[(payload["scope"], payload["task_id"], payload["query_text"])] = {
                    "answer_text": payload["answer_text"],
                    "receipt": receipt,
                    "acs": acs,
                }
                return 201, {"receipt": receipt, "evidence": ev}

            if path == "/v1/answers/lookup":
                key = (payload["scope"], payload["task_id"], payload["query_text"])
                entry = self.caches.get(key)
                if not entry:
                    return 200, {"cache_hit": False, "status": "miss"}
                for dep_id in entry["receipt"]["dependency_ids"]:
                    if dep_id in self.claims and self.claims[dep_id]["status"] != "active":
                        del self.caches[key]
                        inv_acs = {
                            **entry["acs"],
                            "event_kind": "invalidated",
                            "invalidation_reason": "stale_dependency_commitment",
                            "invalidated_by": f"{tenant_id}::sdk",
                            "invalidator_auth_kind": "oauth_github_principal",
                            "observed_state_commitment": self._live_state_commitment(),
                            "observed_dependency_commitment": "77" * 32,
                        }
                        inv_cc_hex = compute_answer_cache_summary_commitment(inv_acs).hex()
                        inv_ev = self._append_event(
                            state_commitment=inv_cc_hex,
                            answer_cache_summary=inv_acs,
                        )
                        return 200, {
                            "cache_hit": False,
                            "status": "stale_dependency_commitment",
                            "invalidation_newly_recorded": True,
                            "invalidation_evidence": inv_ev,
                        }
                return 200, {
                    "cache_hit": True,
                    "status": "hit",
                    "answer_text": entry["answer_text"],
                    "receipt": entry["receipt"],
                }

            raise AssertionError(f"Unhandled mock route: {method} {path}")

    mock = _InMemoryV173Transport()
    client = ActaClient(
        base_url="https://mock.acta.local",
        default_tenant_id=tenant_id,
        pinned_host_public_key=host_pk_hex,
    )
    client._request_json = mock.request_json  # type: ignore[method-assign]

    agent = ActaGovernedAgent(
        client=client,
        keyring=agent_keyring,
        tenant_id=tenant_id,
        actor_id="ardyn-agent@omarchy",
    )

    # 1. Signed directive + signed corroborated claims
    agent.record_directive(scope=scope, body={"rule": "Never guess disputed supplier lead times"})
    c1 = agent.record_claim(
        scope=scope,
        subject="supplier:vortex",
        predicate="lead_days",
        object_val=12,
        object_type="int",
        source_descriptor="erp-primary",
        confidence=0.80,
    )["claim"]
    c2 = agent.record_claim(
        scope=scope,
        subject="supplier:vortex",
        predicate="lead_days",
        object_val=12,
        object_type="int",
        source_descriptor="carrier-bol",
        confidence=0.65,
    )["claim"]

    # 2. First turn: cache miss -> compile_guarded -> LLM -> narrowed dependency_ids cache write
    llm_calls = 0

    def fake_llm(prompt: str, sys_inst: str, compiled: Any) -> str:
        nonlocal llm_calls
        llm_calls += 1
        assert "VERIFIED ACTA CONTEXT BUNDLE" in prompt
        assert "binding constraints" in sys_inst
        return "Vortex lead time is 12 days per corroborated ERP records."

    t1 = agent.run_turn(
        scope=scope,
        task_id="po:lead-check",
        query_text="What is Vortex lead time?",
        llm_callable=fake_llm,
    )
    assert t1.status == "compiled_and_generated" and t1.llm_invoked is True
    assert t1.cache_write_status == "cached" and t1.pinned_dependency_ids == [c1["id"]]
    assert llm_calls == 1

    # 3. Second turn + non-pinned corroborator churn (c2 superseded): narrowed cache MUST STILL HIT!
    agent.record_claim(
        scope=scope,
        subject="supplier:vortex",
        predicate="lead_days",
        object_val=12,
        object_type="int",
        source_descriptor="carrier-bol",
        confidence=0.75,
        predecessor_id=c2["id"],
    )
    t2 = agent.run_turn(
        scope=scope,
        task_id="po:lead-check",
        query_text="What is Vortex lead time?",
        llm_callable=fake_llm,
    )
    assert t2.status == "cache_hit" and t2.llm_invoked is False
    assert llm_calls == 1

    # 4. Supersede pinned winning claim c1 + simulate 409 bundle_stale_at_cache_time race
    c1_v2 = agent.record_claim(
        scope=scope,
        subject="supplier:vortex",
        predicate="lead_days",
        object_val=12,
        object_type="int",
        source_descriptor="erp-primary",
        confidence=0.92,
        predecessor_id=c1["id"],
    )["claim"]
    mock.force_next_cache_409 = True
    t3 = agent.run_turn(
        scope=scope,
        task_id="po:lead-check",
        query_text="What is Vortex lead time?",
        llm_callable=fake_llm,
    )
    assert t3.invalidation_reason == "stale_dependency_commitment"
    assert t3.cache_write_status == "skipped_stale_bundle" and t3.llm_invoked is True

    # 5. Conflicting claim -> pre-LLM ActaDisputeEscalationError circuit breaker (0 LLM tokens!)
    llm_before_dispute = llm_calls
    agent.record_claim(
        scope=scope,
        subject="supplier:vortex",
        predicate="lead_days",
        object_val=45,
        object_type="int",
        source_descriptor="port-strike-bulletin",
        confidence=0.91,
        contradiction_ids=[c1_v2["id"]],
    )
    t4 = agent.run_turn(
        scope=scope,
        task_id="po:lead-check",
        query_text="Can we release PO?",
        llm_callable=fake_llm,
    )
    assert t4.status == "dispute_halted" and t4.llm_invoked is False
    assert llm_calls == llm_before_dispute and len(t4.disputes) == 1

    # 6. Salted-commitment ephemeral secret ingest & teardown (zero cleartext on chain)
    sec_clm = agent.record_claim(
        scope=scope,
        subject="vault:erp-session",
        predicate="bearer_token",
        object_val="BEARER-ULTRA-SENSITIVE-99182",
        object_type="string",
        source_descriptor="ardyn-session-broker",
        erasable=True,
    )["claim"]
    assert list(sec_clm["object_val"].keys()) == ["$acta_erasable_commitment"]
    retract_res = agent.teardown_ephemeral_secret(scope=scope, claim_id=sec_clm["id"])
    assert retract_res["secret_erased"] is True and sec_clm["id"] not in mock.secrets

    print(
        "SELFTEST_OK "
        f"author_pubkey={agent_keyring.public_key_hex[:16]}... "
        f"events_notarized={mock.seq} "
        "verified=[ed25519_client_sig, narrowed_cache_hit, invalidation_receipt, "
        "race_409_recovery, pre_llm_dispute_halt, erasable_secret_teardown]"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acta v1.7.3 Governed Agent Runtime")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run offline cryptographic & state-machine verification (zero network calls)",
    )
    args = parser.parse_args(argv)
    if args.selftest:
        _run_offline_selftest()
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())