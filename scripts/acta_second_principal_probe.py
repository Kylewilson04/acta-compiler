#!/usr/bin/env python3
"""Acta v1.7.3 Bidirectional Second-Principal Cross-Tenant Zero-Oracle Verification Probe.

Supports two execution modes:
  1. Single-direction live/Cloud Run probe (`--victim-tenant` + `--attacker-tenant` / `--attacker-token`),
     preserving 100% read-only safety on `kylewilson04`.
  2. Full bidirectional two-tenant pilot-readiness rehearsal (`--bidirectional --master-key <key>`),
     minting two distinct OAuth-principal-bound tokens (`acta_tk_v1:tenant-alpha:alice:<mac>` and
     `acta_tk_v1:tenant-beta:bob:<mac>`), seeding real objects, claims, bundles, cached answers,
     overrides, and witnesses in BOTH tenants, and probing `B -> A` AND `A -> B` across all 11
     target MCP tools while proving `0` victim ledger mutations and zero cross-tenant oracle!
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SDK_PATH = REPO_ROOT / "sdks" / "python"
if SDK_PATH.exists():
    sys.path.insert(0, str(SDK_PATH))

from acta_sdk.crypto import mint_user_tenant_api_key  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

USER_AGENT = (
    "Mozilla/5.0 (compatible; Google-Agent; "
    "+https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)"
)


def mcp_call(
    mcp_url: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    bearer_token: str | None = None,
    tenant_header: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if tenant_header:
        headers["X-Acta-Tenant"] = tenant_header
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    ).encode("utf-8")
    req = urllib.request.Request(mcp_url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30.0) as resp:
        return json.loads(resp.read().decode("utf-8"))["result"]


def strip_seq_suffix(err_text: str) -> str:
    idx = err_text.find(" [logged at evidence seq_num=")
    return err_text[:idx] if idx != -1 else err_text


def run_probe(
    base_url: str,
    victim_tenant: str,
    victim_bundle_hash: str,
    victim_claim_id: str,
    victim_witness_id: str,
    attacker_tenant: str,
    attacker_token: str | None = None,
    victim_token_for_seq_check: str | None = None,
) -> dict[str, Any]:
    mcp_url = base_url.rstrip("/") + "/mcp"
    th = None if attacker_token else attacker_tenant

    victim_seq_before: int | None = None
    if victim_token_for_seq_check:
        victim_seq_before = int(
            mcp_call(mcp_url, "acta_whoami", {}, bearer_token=victim_token_for_seq_check)[
                "structuredContent"
            ]["evidence_entry_count"]
        )

    who_before = mcp_call(
        mcp_url, "acta_whoami", {}, bearer_token=attacker_token, tenant_header=th
    )["structuredContent"]

    explicit_probes = [
        ("acta_get_checkpoint", {"tenant_id": victim_tenant}),
        ("acta_list_evidence", {"tenant_id": victim_tenant}),
        ("acta_verify_bundle", {"tenant_id": victim_tenant, "bundle_hash": victim_bundle_hash}),
        ("acta_replay_counterfactual", {"tenant_id": victim_tenant, "source_bundle_hash": victim_bundle_hash}),
        (
            "acta_attest_override",
            {
                "tenant_id": victim_tenant,
                "scope": "acta-test/v173-isolation",
                "winning_claim_id": victim_claim_id,
                "justification": "Cross-tenant probe",
            },
        ),
        (
            "acta_anchor_checkpoint",
            {
                "tenant_id": victim_tenant,
                "tree_size": 1,
                "checkpoint_hash": "00" * 32,
                "witness_id": victim_witness_id,
                "witness_public_key_hex": "11" * 32,
                "witness_signature_hex": "00" * 64,
            },
        ),
        (
            "acta_retract_claim",
            {
                "tenant_id": victim_tenant,
                "claim_id": victim_claim_id,
                "reason": "Cross-tenant retraction probe",
            },
        ),
        (
            "acta_cache_answer",
            {
                "tenant_id": victim_tenant,
                "source_bundle_hash": victim_bundle_hash,
                "answer_text": "Cross-tenant cache poison attempt",
            },
        ),
        (
            "acta_lookup_cached_answer",
            {
                "tenant_id": victim_tenant,
                "scope": "acta-test/v173-isolation",
            },
        ),
        (
            "acta_trace_claim_impact",
            {
                "tenant_id": victim_tenant,
                "item_id": victim_claim_id,
            },
        ),
        (
            "acta_verify_state_rebuild",
            {
                "tenant_id": victim_tenant,
                "scope": "acta-test/v173-isolation",
            },
        ),
    ]
    explicit_results = []
    for tool, args in explicit_probes:
        res = mcp_call(mcp_url, tool, args, bearer_token=attacker_token, tenant_header=th)
        txt = res["content"][0]["text"]
        assert res["isError"] is True, f"expected error on {tool}: {res}"
        explicit_results.append({"tool": tool, "rejected": True, "message": txt})

    fake_hash = "ff" * 32
    fake_claim = str(uuid.UUID(int=0xDEADBEEF))
    fake_witness = "nonexistent-witness-zero-oracle"

    who_mid = mcp_call(mcp_url, "acta_whoami", {}, bearer_token=attacker_token, tenant_header=th)["structuredContent"]
    v_real = mcp_call(mcp_url, "acta_verify_bundle", {"bundle_hash": victim_bundle_hash}, bearer_token=attacker_token, tenant_header=th)
    v_fake = mcp_call(mcp_url, "acta_verify_bundle", {"bundle_hash": fake_hash}, bearer_token=attacker_token, tenant_header=th)
    r_real = mcp_call(mcp_url, "acta_replay_counterfactual", {"source_bundle_hash": victim_bundle_hash}, bearer_token=attacker_token, tenant_header=th)
    r_fake = mcp_call(mcp_url, "acta_replay_counterfactual", {"source_bundle_hash": fake_hash}, bearer_token=attacker_token, tenant_header=th)
    imp_real = mcp_call(mcp_url, "acta_trace_claim_impact", {"item_id": victim_claim_id}, bearer_token=attacker_token, tenant_header=th)
    imp_fake = mcp_call(mcp_url, "acta_trace_claim_impact", {"item_id": fake_claim}, bearer_token=attacker_token, tenant_header=th)
    ret_real = mcp_call(mcp_url, "acta_retract_claim", {"claim_id": victim_claim_id, "reason": "Zero oracle retract check"}, bearer_token=attacker_token, tenant_header=th)
    ret_fake = mcp_call(mcp_url, "acta_retract_claim", {"claim_id": fake_claim, "reason": "Zero oracle retract check"}, bearer_token=attacker_token, tenant_header=th)
    ca_real = mcp_call(mcp_url, "acta_cache_answer", {"source_bundle_hash": victim_bundle_hash, "answer_text": "Zero oracle cache check"}, bearer_token=attacker_token, tenant_header=th)
    ca_fake = mcp_call(mcp_url, "acta_cache_answer", {"source_bundle_hash": fake_hash, "answer_text": "Zero oracle cache check"}, bearer_token=attacker_token, tenant_header=th)
    who_after_reads = mcp_call(mcp_url, "acta_whoami", {}, bearer_token=attacker_token, tenant_header=th)["structuredContent"]

    assert v_real["content"][0]["text"].replace(victim_bundle_hash, "<HASH>") == v_fake["content"][0]["text"].replace(fake_hash, "<HASH>")
    assert r_real["content"][0]["text"].replace(victim_bundle_hash, "<HASH>") == r_fake["content"][0]["text"].replace(fake_hash, "<HASH>")
    assert imp_real["content"][0]["text"].replace(victim_claim_id, "<UUID>") == imp_fake["content"][0]["text"].replace(fake_claim, "<UUID>")
    assert ret_real["content"][0]["text"].replace(victim_claim_id, "<UUID>") == ret_fake["content"][0]["text"].replace(fake_claim, "<UUID>")
    assert ca_real["content"][0]["text"].replace(victim_bundle_hash, "<HASH>") == ca_fake["content"][0]["text"].replace(fake_hash, "<HASH>")
    assert who_after_reads["evidence_entry_count"] == who_mid["evidence_entry_count"], (
        "not_found lookups mutated evidence_history!"
    )

    a_real = mcp_call(
        mcp_url,
        "acta_attest_override",
        {"scope": "acta-test/v173-isolation", "winning_claim_id": victim_claim_id, "justification": "Zero oracle check"},
        bearer_token=attacker_token,
        tenant_header=th,
    )
    a_fake = mcp_call(
        mcp_url,
        "acta_attest_override",
        {"scope": "acta-test/v173-isolation", "winning_claim_id": fake_claim, "justification": "Zero oracle check"},
        bearer_token=attacker_token,
        tenant_header=th,
    )
    assert strip_seq_suffix(a_real["content"][0]["text"]).replace(victim_claim_id, "<UUID>") == strip_seq_suffix(a_fake["content"][0]["text"]).replace(fake_claim, "<UUID>")

    w_real = mcp_call(
        mcp_url,
        "acta_anchor_checkpoint",
        {
            "tree_size": 1,
            "checkpoint_hash": "00" * 32,
            "witness_id": victim_witness_id,
            "witness_public_key_hex": "11" * 32,
            "witness_signature_hex": "00" * 64,
        },
        bearer_token=attacker_token,
        tenant_header=th,
    )
    w_fake = mcp_call(
        mcp_url,
        "acta_anchor_checkpoint",
        {
            "tree_size": 1,
            "checkpoint_hash": "00" * 32,
            "witness_id": fake_witness,
            "witness_public_key_hex": "11" * 32,
            "witness_signature_hex": "00" * 64,
        },
        bearer_token=attacker_token,
        tenant_header=th,
    )
    assert strip_seq_suffix(w_real["content"][0]["text"]).replace(victim_witness_id, "<WITNESS>") == strip_seq_suffix(w_fake["content"][0]["text"]).replace(fake_witness, "<WITNESS>")

    victim_zero_mutations = None
    if victim_token_for_seq_check and victim_seq_before is not None:
        victim_seq_after = int(
            mcp_call(mcp_url, "acta_whoami", {}, bearer_token=victim_token_for_seq_check)[
                "structuredContent"
            ]["evidence_entry_count"]
        )
        assert victim_seq_after == victim_seq_before, (
            f"victim {victim_tenant} ledger mutated from {victim_seq_before} to {victim_seq_after}!"
        )
        victim_zero_mutations = True

    return {
        "server_version": who_before["version"],
        "attacker_tenant": attacker_tenant,
        "attacker_principal": who_before.get("verified_principal"),
        "victim_tenant_tested": victim_tenant,
        "explicit_cross_tenant_probes_rejected": len(explicit_results),
        "zero_oracle_verify_bundle_identical": True,
        "zero_oracle_replay_counterfactual_identical": True,
        "zero_oracle_trace_claim_impact_identical": True,
        "zero_oracle_retract_claim_identical": True,
        "zero_oracle_cache_answer_identical": True,
        "zero_oracle_attest_override_identical": True,
        "zero_oracle_anchor_witness_identical": True,
        "read_not_found_zero_ledger_mutation": True,
        "victim_ledger_zero_mutations_verified": victim_zero_mutations,
    }


def _seed_tenant_vault(mcp_url: str, token: str, label: str) -> dict[str, str]:
    scope = "acta-test/v173-isolation"
    mcp_call(
        mcp_url,
        "acta_ingest_object",
        {
            "obj_type": "intent",
            "scope": scope,
            "priority": 90,
            "importance": 1.0,
            "tags": ["isolation"],
            "body": {"directive": f"Tenant {label} confidential policy"},
        },
        bearer_token=token,
    )
    c1 = mcp_call(
        mcp_url,
        "acta_ingest_claim",
        {
            "scope": scope,
            "subject": f"vendor:{label}",
            "predicate": "rate_bps",
            "object_val": 175,
            "object_type": "int",
            "confidence": 0.92,
            "source_descriptor": f"erp-{label}",
            "source_content": f"Confidential rate_bps=175 for {label}",
        },
        bearer_token=token,
    )["structuredContent"]
    b1 = mcp_call(
        mcp_url,
        "acta_compile_context",
        {"scope": scope, "task_id": f"task-{label}", "query_text": "check rate_bps", "token_budget": 1024},
        bearer_token=token,
    )["structuredContent"]
    mcp_call(
        mcp_url,
        "acta_cache_answer",
        {
            "source_bundle_hash": b1["bundle_hash"],
            "query_text": "check rate_bps",
            "answer_text": f"{label} rate is 175 bps.",
        },
        bearer_token=token,
    )
    wit_sk = Ed25519PrivateKey.generate()
    wit_pk_hex = wit_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    wit_id = f"wit-{label}"
    mcp_call(
        mcp_url,
        "acta_register_witness",
        {"witness_id": wit_id, "witness_public_key_hex": wit_pk_hex, "description": f"Witness {label}"},
        bearer_token=token,
    )
    return {
        "claim_id": c1["id"],
        "bundle_hash": b1["bundle_hash"],
        "witness_id": wit_id,
    }


def run_bidirectional_probe(
    base_url: str,
    master_key: str,
    tenant_a: str = "tenant-alpha",
    principal_a: str = "alice",
    tenant_b: str = "tenant-beta",
    principal_b: str = "bob",
) -> dict[str, Any]:
    mcp_url = base_url.rstrip("/") + "/mcp"
    tok_a = mint_user_tenant_api_key(master_key, tenant_a, principal_a)
    tok_b = mint_user_tenant_api_key(master_key, tenant_b, principal_b)

    seeded_a = _seed_tenant_vault(mcp_url, tok_a, "alpha")
    seeded_b = _seed_tenant_vault(mcp_url, tok_b, "beta")

    res_b_attacks_a = run_probe(
        base_url=base_url,
        victim_tenant=tenant_a,
        victim_bundle_hash=seeded_a["bundle_hash"],
        victim_claim_id=seeded_a["claim_id"],
        victim_witness_id=seeded_a["witness_id"],
        attacker_tenant=tenant_b,
        attacker_token=tok_b,
        victim_token_for_seq_check=tok_a,
    )
    res_a_attacks_b = run_probe(
        base_url=base_url,
        victim_tenant=tenant_b,
        victim_bundle_hash=seeded_b["bundle_hash"],
        victim_claim_id=seeded_b["claim_id"],
        victim_witness_id=seeded_b["witness_id"],
        attacker_tenant=tenant_a,
        attacker_token=tok_a,
        victim_token_for_seq_check=tok_b,
    )

    reb_a = mcp_call(
        mcp_url,
        "acta_verify_state_rebuild",
        {"scope": "acta-test/v173-isolation", "include_proof_archive": True},
        bearer_token=tok_a,
    )["structuredContent"]
    reb_b = mcp_call(
        mcp_url,
        "acta_verify_state_rebuild",
        {"scope": "acta-test/v173-isolation", "include_proof_archive": True},
        bearer_token=tok_b,
    )["structuredContent"]
    assert reb_a["matches_live_store_bit_for_bit"] is True
    assert reb_b["matches_live_store_bit_for_bit"] is True

    return {
        "mode": "bidirectional_two_principal",
        "tenant_a": f"{tenant_a}::oauth:{principal_a}",
        "tenant_b": f"{tenant_b}::oauth:{principal_b}",
        "b_attacks_a": res_b_attacks_a,
        "a_attacks_b": res_a_attacks_b,
        "tenant_a_rebuild_bit_for_bit": True,
        "tenant_b_rebuild_bit_for_bit": True,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Acta v1.7.3 Second-Principal Zero-Oracle Probe")
    p.add_argument("--url", default=os.environ.get("ACTA_BASE_URL", "https://acta-server-998422936041.us-west1.run.app"))
    p.add_argument("--bidirectional", action="store_true")
    p.add_argument("--master-key", default=os.environ.get("ACTA_MASTER_API_KEY"))
    p.add_argument("--tenant-a", default=f"tenant-alpha-{uuid.uuid4().hex[:6]}")
    p.add_argument("--tenant-b", default=f"tenant-beta-{uuid.uuid4().hex[:6]}")
    p.add_argument("--victim-tenant", default="kylewilson04")
    p.add_argument("--victim-bundle-hash", default="")
    p.add_argument("--victim-claim-id", default="")
    p.add_argument("--victim-witness-id", default="claude-witness-v171")
    p.add_argument("--attacker-tenant", default=f"sandbox-v173-p2-{uuid.uuid4().hex[:8]}")
    p.add_argument("--attacker-token", default=os.environ.get("ACTA_SECOND_PRINCIPAL_TOKEN"))
    args = p.parse_args()

    if args.bidirectional:
        if not args.master_key:
            raise SystemExit("--bidirectional requires --master-key or ACTA_MASTER_API_KEY")
        out = run_bidirectional_probe(
            base_url=args.url,
            master_key=args.master_key,
            tenant_a=args.tenant_a,
            tenant_b=args.tenant_b,
        )
    else:
        if not args.victim_bundle_hash or not args.victim_claim_id:
            raise SystemExit("Single-direction mode requires --victim-bundle-hash and --victim-claim-id")
        out = run_probe(
            base_url=args.url,
            victim_tenant=args.victim_tenant,
            victim_bundle_hash=args.victim_bundle_hash,
            victim_claim_id=args.victim_claim_id,
            victim_witness_id=args.victim_witness_id,
            attacker_tenant=args.attacker_tenant,
            attacker_token=args.attacker_token,
        )
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
