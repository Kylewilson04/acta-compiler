"""Exception hierarchy and deterministic circuit-breakers for Acta SDK."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class ActaError(Exception):
    """Base error for all Acta SDK failures."""


class ActaHttpError(ActaError):
    """Raised on unexpected HTTP transport or API errors."""

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.payload = payload


class ActaAuthError(ActaHttpError):
    """Raised when X-Acta-Api-Key is missing or invalid for a protected tenant (HTTP 401)."""


class ActaSignatureVerificationError(ActaError):
    """Raised when an Ed25519 host signature or BLAKE3 event_hash fails client-side verification."""


class ActaVerificationError(ActaError):
    """Raised when an ExportArchive fails offline or remote cryptographic verification."""


class ActaPolicyBlockedError(ActaError):
    """Circuit-breaker raised when Cedar blocks a compile request before any SQL read (HTTP 403)."""

    def __init__(
        self,
        reason: str,
        evidence: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
    ) -> None:
        super().__init__(f"Acta Cedar Policy BLOCKED request before read: {reason}")
        self.reason = reason
        self.evidence = dict(evidence)
        self.policy_decision = dict(policy_decision)


class ActaPolicyEscalatedError(ActaError):
    """Circuit-breaker raised when Cedar requires supervisor escalation before any SQL read (HTTP 202)."""

    def __init__(
        self,
        reason: str,
        evidence: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
    ) -> None:
        super().__init__(f"Acta Cedar Policy ESCALATED request before read: {reason}")
        self.reason = reason
        self.evidence = dict(evidence)
        self.policy_decision = dict(policy_decision)


class ActaDisputeEscalationError(ActaError):
    """Circuit-breaker raised by `compile_guarded` when competing claims violate decisiveness bounds."""

    def __init__(
        self,
        bundle_hash: str,
        disputes: Sequence[Mapping[str, Any]],
        evidence: Mapping[str, Any],
        context_text: str,
    ) -> None:
        super().__init__(
            f"Acta halted LLM execution: {len(disputes)} unresolved claim dispute(s) in bundle {bundle_hash}"
        )
        self.bundle_hash = bundle_hash
        self.disputes = [dict(d) for d in disputes]
        self.evidence = dict(evidence)
        self.context_text = context_text


class ActaTenantLockError(ActaError):
    """Raised locally or by the server when a request violates the active tenant lock."""
