#!/usr/bin/env python3
"""Live end-to-end verification of `acta-sdk` v1.5.0 (Python) against Cloud Run."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parents[1] / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from acta_sdk import (  # noqa: E402
    DEFAULT_CLOUDRUN_URL,
    ActaClient,
    ActaDisputeEscalationError,
    ActaGeminiGuard,
    ActaPolicyEscalatedError,
    ActaTenantLockError,
    extract_token_tenant,
)


def main() -> None:
    base_url = os.environ.get("ACTA_BASE_URL", DEFAULT_CLOUDRUN_URL)
    api_key = os.environ.get("ACTA_API_KEY")
    tok_tenant = extract_token_tenant(api_key) if api_key else None
    explicit_tenant = None if tok_tenant else ("prod-py-sdk" if api_key else "sandbox-py-sdk")
    scope = f"settlement-{secrets.token_hex(3)}"

    with ActaClient(base_url, api_key=api_key, default_tenant_id=explicit_tenant) as client:
        active_tenant = client.locked_tenant or explicit_tenant
        print(f"[py-sdk v1.5] Connected to {base_url} (locked_tenant={active_tenant}, scope={scope})")
        health = client.health()
        print(f"[py-sdk v1.5] Health v{health.get('version')} OK -> host Ed25519 key: {health['host_public_key']}")

        # 1. Verify local cross-tenant lock prevents accidental cross-business calls before network!
        try:
            client.compile(
                tenant_id="other-unrelated-business",
                actor_id="claude",
                scope=scope,
                query_text="cross-tenant probe",
            )
            raise AssertionError("Expected ActaTenantLockError")
        except ActaTenantLockError:
            print(f"[py-sdk v1.5] Local tenant lock verified: blocked cross-tenant call from '{active_tenant}'")

        # 2. Ingest standing intent + two competing claims (290 bps vs 240 bps)
        client.ingest_object(
            obj_type="intent",
            scope=scope,
            priority=100,
            importance=1.0,
            tags=["sdk-v1.5"],
            body={"directive": "Halt automated payout when fee_bps is disputed"},
        )
        client.ingest_claim(
            scope=scope,
            subject="merchant:global",
            predicate="fee_bps",
            object_val=290,
            object_type="int",
            confidence=0.82,
            source_provenance_class=2,
            source_descriptor="ledger-v1",
        )
        c2 = client.ingest_claim(
            scope=scope,
            subject="merchant:global",
            predicate="fee_bps",
            object_val=240,
            object_type="int",
            confidence=0.76,
            source_provenance_class=2,
            source_descriptor="crm-contract",
        )

        guard = ActaGeminiGuard(client, strict_disputes=True)
        llm_invoked = False

        def never_called(_prompt: str, _compiled: object) -> str:
            nonlocal llm_invoked
            llm_invoked = True
            return "bad"

        disputed_hash = ""
        try:
            guard.generate_content(
                actor_id="python-sdk-auditor",
                scope=scope,
                prompt="Approve merchant:global payout.",
                llm_callable=never_called,
            )
            raise AssertionError("Expected ActaDisputeEscalationError")
        except ActaDisputeEscalationError as err:
            assert not llm_invoked
            disputed_hash = err.bundle_hash
            print(
                f"[py-sdk v1.5] Dispute circuit-breaker TRIPPED before LLM! "
                f"bundle_hash={disputed_hash} (seq=#{err.evidence['seq_num']} Ed25519 verified locally)"
            )

        # 3. Verify Policy-Before-Read refusal logs readable v2 RefusalMetadata!
        try:
            guard.generate_content(
                actor_id="python-sdk-auditor",
                scope="restricted/signing-vault",
                prompt="Read vault keys",
                llm_callable=never_called,
            )
            raise AssertionError("Expected ActaPolicyEscalatedError")
        except ActaPolicyEscalatedError as err:
            assert not llm_invoked
            rmeta = err.evidence.get("refusal_metadata") or {}
            assert rmeta.get("reason_code") == "POLICY_ESCALATE", f"missing refusal_metadata: {err.evidence}"
            print(
                f"[py-sdk v1.5] Policy-Before-Read Escalate TRIPPED with v2 RefusalMetadata! "
                f"seq=#{err.evidence['seq_num']} target_scope={rmeta.get('target_scope')}"
            )

        # 4. Attest signed human dispute override for contract 240 bps claim & re-compile!
        att = client.attest_override(
            scope=scope,
            winning_claim_id=str(c2["id"]),
            source_bundle_hash_hex=disputed_hash,
            adjudicator_id="cfo-review",
            justification="Signed enterprise MSA schedule §4.2 confirms 240 bps",
        )
        print(
            f"[py-sdk v1.5] Signed OverrideAttestation notarized! "
            f"id={att['id']} seq=#{att['evidence_seq_num']}"
        )

        adjudicated = guard.generate_content(
            actor_id="python-sdk-auditor",
            scope=scope,
            prompt="Approve merchant:global payout.",
            llm_callable=lambda prompt, _comp: "OK" if "OVERRIDE" in prompt else "MISSING",
        )
        assert adjudicated.text == "OK"

        # 5. Offline ExportArchive audit verifying ResolverManifest + RefusalMetadata + OverrideAttestation!
        summary = client.verify_bundle_offline(adjudicated.bundle_hash)
        assert summary.verified_overrides == 1
        assert summary.resolver_manifest is not None
        print(
            f"[py-sdk v1.5] Offline zero-trust ExportArchive audit PASSED: "
            f"tenant={summary.tenant_id}, claims={summary.verified_claims}, "
            f"overrides={summary.verified_overrides}, refusals={summary.verified_refusals}, "
            f"decisiveness_threshold={summary.resolver_manifest['decisiveness_threshold']}"
        )


if __name__ == "__main__":
    main()
