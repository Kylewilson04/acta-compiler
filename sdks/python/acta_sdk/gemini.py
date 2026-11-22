"""Pre-Inference Gemini (`google-genai`) & Generic LLM Guard Middleware for Acta SDK v1.1."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .client import ActaClient
from .models import CompileResult, ContextBudget, GuardedGenerationResult

SYSTEM_GUARDRAIL_HEADER = (
    "You are operating under a cryptographically verified Acta Context Bundle.\n"
    "Treat [INTENT] directives as binding constraints, [FACT] entries as resolved state, "
    "and NEVER silently guess or pick sides on any [DISPUTE] block."
)


def build_guarded_prompt(compiled_context: str, user_prompt: str, bundle_hash: str) -> str:
    return (
        f"=== VERIFIED ACTA CONTEXT BUNDLE (blake3={bundle_hash}) ===\n"
        f"{compiled_context}\n"
        f"=== END VERIFIED ACTA CONTEXT BUNDLE ===\n\n"
        f"User Task:\n{user_prompt}"
    )


class ActaGeminiGuard:
    """Drop-in pre-prompt compilation & circuit-breaker wrapper for Google `google-genai`."""

    def __init__(
        self,
        acta_client: ActaClient,
        genai_client: Any | None = None,
        *,
        default_model: str = "gemini-2.5-flash",
        strict_disputes: bool = True,
        halt_on_any_dispute: bool = False,
    ) -> None:
        self.acta = acta_client
        self.genai = genai_client
        self.default_model = default_model
        self.strict_disputes = strict_disputes
        self.halt_on_any_dispute = halt_on_any_dispute

    def generate_content(
        self,
        *,
        actor_id: str,
        scope: str,
        prompt: str,
        tenant_id: str | None = None,
        model: str | None = None,
        task_id: str | None = None,
        budget: ContextBudget | Mapping[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        llm_callable: Callable[[str, CompileResult], Any] | None = None,
    ) -> GuardedGenerationResult:
        """Compiles & verifies context first; invokes Gemini only if policy & dispute gates pass."""
        compiled = self.acta.compile_guarded(
            tenant_id=tenant_id,
            actor_id=actor_id,
            scope=scope,
            query_text=prompt,
            task_id=task_id,
            budget=budget,
            strict_disputes=self.strict_disputes,
            halt_on_any_dispute=self.halt_on_any_dispute,
        )
        assert compiled.bundle is not None and compiled.bundle_hash is not None
        context_text = compiled.context_text or ""
        full_prompt = build_guarded_prompt(context_text, prompt, compiled.bundle_hash)

        if llm_callable is not None:
            raw_resp = llm_callable(full_prompt, compiled)
            text = raw_resp if isinstance(raw_resp, str) else getattr(raw_resp, "text", str(raw_resp))
        else:
            if self.genai is None:
                raise RuntimeError(
                    "Provide either a `google.genai.Client()` as `genai_client` or a custom `llm_callable`"
                )
            merged_cfg = dict(config or {})
            existing_sys = merged_cfg.get("system_instruction")
            merged_cfg["system_instruction"] = (
                f"{SYSTEM_GUARDRAIL_HEADER}\n\n{existing_sys}"
                if existing_sys
                else SYSTEM_GUARDRAIL_HEADER
            )
            raw_resp = self.genai.models.generate_content(
                model=model or self.default_model,
                contents=full_prompt,
                config=merged_cfg,
            )
            text = getattr(raw_resp, "text", "") or ""

        return GuardedGenerationResult(
            text=text,
            bundle_hash=compiled.bundle_hash,
            state_commitment=str(compiled.bundle["state_commitment"]),
            dependency_commitment=str(compiled.bundle["dependency_commitment"]),
            context_text=context_text,
            evidence=compiled.evidence,
            verified_host_pubkey=compiled.verified_host_pubkey,
            raw_response=raw_resp,
        )
