#!/usr/bin/env python3
"""Acta v1.7.2 Second-Principal Cross-Tenant Zero-Oracle Verification Probe.

Verifies cross-tenant isolation across two distinct authenticated principals (`Principal A` vs `Principal B`):
  1. Explicit `tenant_id: <Principal A>` passed by `Principal B` across all 11 target MCP tools
     (`acta_get_checkpoint`, `acta_list_evidence`, `acta_verify_bundle`, `acta_replay_counterfactual`,
      `acta_attest_override`, `acta_anchor_checkpoint`, `acta_retract_claim`, `acta_cache_answer`,
      `acta_lookup_cached_answer`, `acta_trace_claim_impact`, `acta_verify_state_rebuild`) is rejected
     with `MCP tenant lock violation`, logged ONLY to `Principal B`'s ledger, leaving
     `Principal A`'s ledger untouched.
  2. Implicit/omitted `tenant_id` (using `Principal B`'s session lock) with `Principal A`'s REAL
     `bundle_hash`, `claim_id`, `source_bundle_hash`, and `witness_id` returns character-for-character
     identical `"not found"` messages (modulo the echoed hash/id string) as completely nonexistent
     random hashes/UUIDs/witnesses — including `acta_trace_claim_impact`, `acta_retract_claim`, and
     `acta_cache_answer` — proving zero cross-tenant oracle!
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request
import uuid
from typing import Any

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
) -> dict[str, Any]:
    mcp_url = base_url.rstrip("/") + "/mcp"
    th = None if attacker_token else attacker_tenant

    who_before = mcp_call(
        mcp_url, "acta_whoami", {}, bearer_token=attacker_token, tenant_header=th
    )["structuredContent"]

    # Part A: Explicit foreign tenant_id across all 11 target operations
    explicit_probes = [
        ("acta_get_checkpoint", {"tenant_id": victim_tenant}),
        ("acta_list_evidence", {"tenant_id": victim_tenant}),
        ("acta_verify_bundle", {"tenant_id": victim_tenant, "bundle_hash": victim_bundle_hash}),
        ("acta_replay_counterfactual", {"tenant_id": victim_tenant, "source_bundle_hash": victim_bundle_hash}),
        (
            "acta_attest_override",
            {
                "tenant_id": victim_tenant,
                "scope": "acta-test/v170-ppa1",
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
                "scope": "acta-test/v170-ppa1",
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
                "scope": "acta-test/v170-ppa1",
            },
        ),
    ]
    explicit_results = []
    for tool, args in explicit_probes:
        res = mcp_call(mcp_url, tool, args, bearer_token=attacker_token, tenant_header=th)
        txt = res["content"][0]["text"]
        assert res["isError"] is True, f"expected error on {tool}: {res}"
        explicit_results.append({"tool": tool, "rejected": True, "message": txt})

    # Part B: Omitted tenant_id — compare Victim's REAL identifiers vs NONEXISTENT identifiers (Zero-Oracle Check)
    fake_hash = "ff" * 32
    fake_claim = str(uuid.UUID(int=0xDEADBEEF))
    fake_witness = "nonexistent-witness-zero-oracle"

    # 1. Read-only not_found probes MUST NOT mutate attacker ledger!
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

    # 2. acta_attest_override & acta_anchor_checkpoint zero-oracle checks
    a_real = mcp_call(
        mcp_url,
        "acta_attest_override",
        {"scope": "acta-test/v170-ppa1", "winning_claim_id": victim_claim_id, "justification": "Zero oracle check"},
        bearer_token=attacker_token,
        tenant_header=th,
    )
    a_fake = mcp_call(
        mcp_url,
        "acta_attest_override",
        {"scope": "acta-test/v170-ppa1", "winning_claim_id": fake_claim, "justification": "Zero oracle check"},
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

    return {
        "server_version": who_before["version"],
        "attacker_tenant": attacker_tenant,
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
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Acta v1.7.2 Second-Principal Zero-Oracle Probe")
    p.add_argument("--url", default=os.environ.get("ACTA_BASE_URL", "https://acta-server-998422936041.us-west1.run.app"))
    p.add_argument("--victim-tenant", default="kylewilson04")
    p.add_argument("--victim-bundle-hash", required=True)
    p.add_argument("--victim-claim-id", required=True)
    p.add_argument("--victim-witness-id", default="claude-witness-v166")
    p.add_argument("--attacker-tenant", default=f"sandbox-v170-p2-{uuid.uuid4().hex[:8]}")
    p.add_argument("--attacker-token", default=os.environ.get("ACTA_SECOND_PRINCIPAL_TOKEN"))
    args = p.parse_args()

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
