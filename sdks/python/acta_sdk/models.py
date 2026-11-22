"""Typed request and response models for Acta Compiler v1.0."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping


BudgetKind = Literal["tokens", "bytes", "records"]
ObjectTypeLiteral = Literal["intent", "memory"]
LifecycleLiteral = Literal["active", "revoked", "expired", "superseded"]


@dataclass(frozen=True)
class ContextBudget:
    kind: BudgetKind = "tokens"
    limit: int = 4096

    @classmethod
    def tokens(cls, limit: int = 4096) -> "ContextBudget":
        return cls(kind="tokens", limit=limit)

    @classmethod
    def bytes(cls, limit: int = 16384) -> "ContextBudget":
        return cls(kind="bytes", limit=limit)

    @classmethod
    def records(cls, limit: int = 32) -> "ContextBudget":
        return cls(kind="records", limit=limit)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "limit": int(self.limit)}


@dataclass(frozen=True)
class CompileResult:
    http_status: int
    policy_decision: dict[str, Any]
    bundle_hash: str | None
    context_text: str | None
    bundle: dict[str, Any] | None
    evidence: dict[str, Any]
    verified_host_pubkey: str

    @property
    def is_allow(self) -> bool:
        return self.policy_decision.get("decision") == "allow"

    @property
    def dispute_records(self) -> list[dict[str, Any]]:
        if not self.bundle:
            return []
        return list(self.bundle.get("dispute_records", []))

    @property
    def requires_dispute_escalation(self) -> bool:
        return any(bool(d.get("escalation_required")) for d in self.dispute_records)

    @classmethod
    def from_wire(
        cls,
        http_status: int,
        payload: Mapping[str, Any],
        verified_host_pubkey: str,
    ) -> "CompileResult":
        return cls(
            http_status=http_status,
            policy_decision=dict(payload["policy_decision"]),
            bundle_hash=payload.get("bundle_hash"),
            context_text=payload.get("context_text"),
            bundle=dict(payload["bundle"]) if payload.get("bundle") is not None else None,
            evidence=dict(payload["evidence"]),
            verified_host_pubkey=verified_host_pubkey,
        )


@dataclass(frozen=True)
class GuardedGenerationResult:
    """Returned by `ActaGeminiGuard` after verified pre-prompt context compilation + LLM generation."""

    text: str
    bundle_hash: str
    state_commitment: str
    dependency_commitment: str
    context_text: str
    evidence: dict[str, Any]
    verified_host_pubkey: str
    raw_response: Any = field(repr=False, default=None)
