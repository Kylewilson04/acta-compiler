#!/usr/bin/env python3
"""Live end-to-end verification of `acta-sdk` v1.7.1 (Python) against Cloud Run."""

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
    ActaHttpError,
    ActaPolicyEscalatedError,
    ActaTenantLockError,
    ContextBudget,
    extract_token_tenant,
    sign_override_client_intent,
    sign_witness_anchor,
)


def main() -> None:
    base_url = os.environ.get("ACTA_BASE_URL", DEFAULT_CLOUDRUN_URL)
    api_key = os.environ.get("ACTA_API_KEY")
    tok_tenant = extract_token_tenant(api_key) if api_key else None
    explicit_tenant = None if tok_tenant else ("prod-py-sdk" if api_key else "sandbox-py-sdk")
    scope = f"settlement-{secrets.token_hex(3)}"

    with ActaClient(base_url, api_key=api_key, default_tenant_id=explicit_tenant) as client:
        active_tenant = client.locked_tenant or explicit_tenant or "sandbox-py-sdk"
        print(f"[py-sdk v1.6] Connected to {base_url} (locked_tenant={active_tenant}, scope={scope})")
        health = client.health()
        print(f"[py-sdk v1.6] Health v{health.get('version')} OK -> host Ed25519 key: {health['host_public_key']}")

        # 1. Local cross-tenant lock prevents accidental cross-business calls before network!
        try:
            client.compile(
                tenant_id="other-unrelated-business",
                actor_id="claude",
                scope=scope,
                query_text="cross-tenant probe",
            )
            raise AssertionError("Expected ActaTenantLockError")
        except ActaTenantLockError:
            print(f"[py-sdk v1.6] Local tenant lock verified: blocked cross-tenant call from '{active_tenant}'")

        # 2. Ingest standing intent + two competing claims (290 bps vs 240 bps)
        client.ingest_object(
            obj_type="intent",
            scope=scope,
            priority=100,
            importance=1.0,
            tags=["sdk-v1.6"],
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
                f"[py-sdk v1.6] Dispute circuit-breaker TRIPPED before LLM! "
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
            assert "escalate" in str(rmeta.get("reason_code", "")).lower(), f"missing refusal_metadata: {err.evidence}"
            print(
                f"[py-sdk v1.6] Policy-Before-Read Escalate TRIPPED with v2 RefusalMetadata! "
                f"seq=#{err.evidence['seq_num']} target_scope={rmeta.get('target_scope')}"
            )

        # 4. Verify v1.5.1 Gap 1: Unauthenticated custom adjudicator_id ("cfo-committee") is REFUSED (403)!
        justification = "Signed enterprise MSA schedule §4.2 confirms 240 bps"
        try:
            client.attest_override(
                scope=scope,
                winning_claim_id=str(c2["id"]),
                source_bundle_hash_hex=disputed_hash,
                adjudicator_id="cfo-committee",
                justification=justification,
            )
            raise AssertionError("Expected HTTP 403 on unsigned custom adjudicator_id")
        except ActaHttpError as err:
            assert err.status_code == 403, f"expected 403, got {err.status_code}"
            print("[py-sdk v1.6] Unsigned custom adjudicator_id 'cfo-committee' REFUSED (HTTP 403) as required!")

        # 5. Sign override intent offline with committee Ed25519 key & notarize!
        committee_seed = secrets.token_bytes(32)
        csig_hex, cpk_hex = sign_override_client_intent(
            committee_seed,
            tenant_id=active_tenant,
            scope=scope,
            winning_claim_id=str(c2["id"]),
            adjudicator_id="cfo-committee",
            justification=justification,
        )
        att = client.attest_override(
            scope=scope,
            winning_claim_id=str(c2["id"]),
            source_bundle_hash_hex=disputed_hash,
            adjudicator_id="cfo-committee",
            justification=justification,
            client_signature_hex=csig_hex,
            client_public_key_hex=cpk_hex,
        )
        assert att.get("adjudicator_auth_kind") == "ed25519_client_sig"
        print(
            f"[py-sdk v1.6] Ed25519 Client-Signed OverrideAttestation notarized! "
            f"id={att['id']} seq=#{att['evidence_seq_num']} auth={att['adjudicator_auth_kind']}"
        )

        # 6. Verify v1.5.1 Gap 3: Tight budget (80 tokens) preserves bounded `why="..."` snippet!
        tight = client.compile_guarded(
            actor_id="python-sdk-auditor",
            scope=scope,
            query_text="Approve merchant:global payout.",
            budget=ContextBudget.tokens(80),
        )
        assert tight.context_text and 'why="Signed enterprise' in tight.context_text, (
            f"expected bounded why snippet at budget 80, got: {tight.context_text}"
        )
        print(f"[py-sdk v1.6] Tight-budget (80 tokens) justification snippet preserved: {tight.context_text}")

        # 7. Verify v1.6 Merkle SignedTreeHead checkpoint + external witness cosignature + compact O(log N) verify!
        cp_resp = client.get_checkpoint()
        sth = cp_resp["checkpoint"]
        witness_seed = secrets.token_bytes(32)
        wsig_hex, wpk_hex = sign_witness_anchor(
            witness_seed, active_tenant, int(sth["tree_size"]), str(sth["checkpoint_hash"])
        )
        client.anchor_checkpoint(
            tree_size=int(sth["tree_size"]),
            checkpoint_hash_hex=str(sth["checkpoint_hash"]),
            witness_id="e2e-witness-log",
            witness_public_key_hex=wpk_hex,
            witness_signature_hex=wsig_hex,
            external_uri="https://witness.ardyn.example/v1",
        )
        merkle_summary = client.verify_bundle_offline(tight.bundle_hash or "", mode="merkle")
        assert merkle_summary.verification_mode == "merkle_inclusion"
        assert merkle_summary.verified_overrides == 1
        assert merkle_summary.verified_witness_anchors >= 1
        print(
            f"[py-sdk v1.6] Compact O(log N) Merkle ExportArchive audit PASSED: "
            f"tree_size={merkle_summary.merkle_tree_size}, entries_checked={merkle_summary.verified_evidence_entries}, "
            f"witness_anchors={merkle_summary.verified_witness_anchors}"
        )

        # 8. Verify v1.5.1 Gap 2: Unseen conflicting Claim C (310 bps) re-escalates with `lapsed_override`!
        c3 = client.ingest_claim(
            scope=scope,
            subject="merchant:global",
            predicate="fee_bps",
            object_val=310,
            object_type="int",
            confidence=0.79,
            source_provenance_class=2,
            source_descriptor="erp-amendment",
        )
        reopened = client.compile(
            actor_id="python-sdk-auditor",
            scope=scope,
            query_text="Approve merchant:global payout.",
        )
        lapsed = reopened.dispute_records[0].get("lapsed_override")
        assert lapsed is not None and str(c3["id"]) in lapsed.get("reopened_by_claim_ids", [])
        reopened_summary = client.verify_bundle_offline(reopened.bundle_hash or "", mode="merkle")
        assert reopened_summary.verified_overrides == 1
        print(
            f"[py-sdk v1.6] LapsedOverrideRef verified on re-escalated dispute! "
            f"reopened_by={lapsed['reopened_by_claim_ids']} prior_seq=#{lapsed['evidence_seq_num']}"
        )


if __name__ == "__main__":
    main()
