#!/usr/bin/env python3
"""Acta v1.7.1 True-Parallel Concurrency, Write-Chaining & State-Rebuild Verification Harness.

Opens 50 independent HTTP connections, synchronizes all 50 worker threads on a
`threading.Barrier(50)` so all writes hit PostgreSQL `pg_advisory_xact_lock` concurrently
with genuine wall-clock overlap (zero MCP connector serialization), races:
  - 10 identical `acta_ingest_claim` calls (verifying idempotent dedup -> 1 unique UUID & 1 write_summary entry)
  - 8 concurrent `acta_attest_override` calls on one disputed claim group (verifying versions 1..8)
  - 16 concurrent `acta_compile_context` calls
  - 16 concurrent security refusals (`restricted/*` + spoofed `adjudicator_id`)
Then pages through `acta_list_evidence` + `acta_get_checkpoint` + `acta_verify_state_rebuild` and
independently verifies 100% of `prev_hash` links, BLAKE3 `event_hash` (v1/v2/v3) preimages,
Ed25519 `host_signature`s, RFC 6962 §2.1 SHA-256 `merkle_root`, and bit-for-bit ledger-alone
state reconstruction (`matches_live_store_bit_for_bit == True`).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SDK_PATH = REPO_ROOT / "sdks" / "python"
if SDK_PATH.exists():
    sys.path.insert(0, str(SDK_PATH))

from acta_sdk.crypto import (  # noqa: E402
    compute_merkle_root_from_leaves,
    merkle_leaf_hash,
    verify_checkpoint_signature,
    verify_evidence_entry,
)

USER_AGENT = (
    "Mozilla/5.0 (compatible; Google-Agent; "
    "+https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)"
)


def mcp_rpc_single_conn(
    mcp_url: str,
    tenant_id: str,
    bearer_token: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    rpc_id: int,
    timeout: float = 45.0,
) -> tuple[float, float, dict[str, Any]]:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Connection": "close",
        "X-Acta-Tenant": tenant_id,
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    req = urllib.request.Request(mcp_url, data=payload, headers=headers, method="POST")
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    t1 = time.perf_counter()
    return t0, t1, json.loads(raw.decode("utf-8"))


def fetch_all_evidence_paginated(
    mcp_url: str,
    tenant_id: str,
    bearer_token: str | None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    from_seq = 1
    while True:
        _, _, rpc = mcp_rpc_single_conn(
            mcp_url,
            tenant_id,
            bearer_token,
            "acta_list_evidence",
            {"from_seq": from_seq, "limit": 100},
            rpc_id=9000 + from_seq,
        )
        res = rpc["result"]
        assert not res.get("isError"), f"acta_list_evidence failed: {res}"
        sc = res["structuredContent"]
        page = sc.get("entries", [])
        if not page:
            break
        if "next_seq" in sc or "has_more" in sc:
            entries.extend(page)
            nxt = sc.get("next_seq")
            if not nxt:
                break
            from_seq = int(nxt)
        else:
            entries = page
            break
    return entries


def run_harness(
    base_url: str,
    tenant_id: str,
    bearer_token: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    mcp_url = base_url.rstrip("/") + "/mcp"
    scope = "acta-concurrency-race"

    # 0. Inspect server version & host_public_key via acta_whoami
    _, _, who_rpc = mcp_rpc_single_conn(
        mcp_url, tenant_id, bearer_token, "acta_whoami", {}, rpc_id=1
    )
    who_sc = who_rpc["result"]["structuredContent"]
    host_pk_hex = who_sc["host_public_key"]
    server_version = who_sc["version"]

    # 1. Seed 2 competing claims on (contract:race, fee_bps) -> chained at seq 1 & seq 2 in v1.7.0+
    _, _, c_a_rpc = mcp_rpc_single_conn(
        mcp_url,
        tenant_id,
        bearer_token,
        "acta_ingest_claim",
        {
            "scope": scope,
            "subject": "contract:race",
            "predicate": "fee_bps",
            "object_val": 285,
            "object_type": "int",
            "confidence": 0.84,
            "source_descriptor": "erp-seed-a",
            "source_content": "Seed ERP export: fee_bps = 285",
        },
        rpc_id=2,
    )
    claim_a_id = c_a_rpc["result"]["structuredContent"]["id"]

    _, _, c_b_rpc = mcp_rpc_single_conn(
        mcp_url,
        tenant_id,
        bearer_token,
        "acta_ingest_claim",
        {
            "scope": scope,
            "subject": "contract:race",
            "predicate": "fee_bps",
            "object_val": 240,
            "object_type": "int",
            "confidence": 0.79,
            "source_descriptor": "msa-seed-b",
            "source_content": "Seed MSA Schedule A: fee_bps = 240",
        },
        rpc_id=3,
    )
    claim_b_id = c_b_rpc["result"]["structuredContent"]["id"]

    # Warm up connection pool before barrier release -> seq 3
    _, _, _ = mcp_rpc_single_conn(
        mcp_url,
        tenant_id,
        bearer_token,
        "acta_compile_context",
        {"scope": scope, "query_text": "warmup dispute check", "token_budget": 512},
        rpc_id=4,
    )

    # 2. Build 50 parallel barrier-synchronized operations
    ops: list[tuple[str, str, dict[str, Any], int]] = []
    op_id = 100
    for _ in range(10):
        op_id += 1
        ops.append(
            (
                "dup_claim_ingest",
                "acta_ingest_claim",
                {
                    "scope": scope,
                    "subject": "contract:dup",
                    "predicate": "limit_usd",
                    "object_val": 50000,
                    "object_type": "int",
                    "confidence": 0.91,
                    "source_descriptor": "treasury-feed-v1",
                    "source_content": "Treasury limit feed: limit_usd = 50000",
                },
                op_id,
            )
        )
    for i in range(8):
        op_id += 1
        winner = claim_b_id if (i % 2 == 0) else claim_a_id
        ops.append(
            (
                "override_race",
                "acta_attest_override",
                {
                    "scope": scope,
                    "winning_claim_id": winner,
                    "justification": f"Concurrent adjudication race slot {i + 1} selecting {winner}",
                },
                op_id,
            )
        )
    for i in range(16):
        op_id += 1
        ops.append(
            (
                "concurrent_compile",
                "acta_compile_context",
                {
                    "scope": scope,
                    "task_id": f"conc-compile-{i + 1}",
                    "query_text": f"concurrent compile probe {i + 1}",
                    "token_budget": 512,
                },
                op_id,
            )
        )
    for i in range(8):
        op_id += 1
        ops.append(
            (
                "refusal_restricted",
                "acta_ingest_claim",
                {
                    "scope": "restricted/conc-probe",
                    "subject": f"secret:{i}",
                    "predicate": "flag",
                    "object_val": 1,
                    "object_type": "int",
                    "confidence": 0.9,
                    "source_descriptor": "probe",
                },
                op_id,
            )
        )
    for i in range(8):
        op_id += 1
        ops.append(
            (
                "refusal_spoof_adj",
                "acta_attest_override",
                {
                    "scope": scope,
                    "winning_claim_id": claim_b_id,
                    "adjudicator_id": f"spoofed-committee-{i}",
                    "justification": "Unsigned custom adjudicator probe",
                },
                op_id,
            )
        )

    assert len(ops) == 50
    barrier = threading.Barrier(len(ops))

    def worker(item: tuple[str, str, dict[str, Any], int]) -> dict[str, Any]:
        kind, tool, args, rid = item
        barrier.wait(timeout=30.0)
        t_start, t_end, rpc = mcp_rpc_single_conn(
            mcp_url, tenant_id, bearer_token, tool, args, rpc_id=rid
        )
        return {
            "kind": kind,
            "tool": tool,
            "rpc_id": rid,
            "t_start": t_start,
            "t_end": t_end,
            "latency_ms": round((t_end - t_start) * 1000.0, 2),
            "rpc": rpc,
        }

    burst_t0 = time.perf_counter()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futs = [pool.submit(worker, op) for op in ops]
        for fut in as_completed(futs):
            results.append(fut.result())
    burst_wall_s = time.perf_counter() - burst_t0

    # 3. Compute genuine in-flight overlap across the 50 parallel requests
    total_pairs = 0
    overlapping_pairs = 0
    max_in_flight = 0
    events: list[tuple[float, int]] = []
    for r in results:
        events.append((r["t_start"], +1))
        events.append((r["t_end"], -1))
    events.sort(key=lambda x: (x[0], -x[1]))
    cur_inflight = 0
    for _, delta in events:
        cur_inflight += delta
        if cur_inflight > max_in_flight:
            max_in_flight = cur_inflight

    for i in range(len(results)):
        for j in range(i + 1, len(results)):
            total_pairs += 1
            if max(results[i]["t_start"], results[j]["t_start"]) < min(
                results[i]["t_end"], results[j]["t_end"]
            ):
                overlapping_pairs += 1

    # 4. Analyze category outcomes
    dup_ids: set[str] = set()
    dup_noop_count = 0
    dup_evidence_seqs: set[int] = set()
    override_versions: list[int] = []
    override_seqs: list[int] = []
    compile_seqs: list[int] = []
    refusal_errors = 0

    for r in results:
        kind = r["kind"]
        res = r["rpc"]["result"]
        if kind == "dup_claim_ingest":
            assert not res.get("isError"), f"dup_claim_ingest failed: {res}"
            sc = res["structuredContent"]
            dup_ids.add(sc["id"])
            if sc.get("evidence_seq_num") is not None:
                dup_evidence_seqs.add(int(sc["evidence_seq_num"]))
            if sc.get("was_idempotent_noop"):
                dup_noop_count += 1
        elif kind == "override_race":
            assert not res.get("isError"), f"override_race failed: {res}"
            sc = res["structuredContent"]
            override_versions.append(int(sc["version"]))
            override_seqs.append(int(sc["evidence_seq_num"]))
        elif kind == "concurrent_compile":
            assert not res.get("isError"), f"concurrent_compile failed: {res}"
            sc = res["structuredContent"]
            compile_seqs.append(int(sc["evidence"]["seq_num"]))
        elif kind in ("refusal_restricted", "refusal_spoof_adj"):
            assert res.get("isError") is True, f"expected refusal on {kind}: {res}"
            refusal_errors += 1

    override_versions_sorted = sorted(override_versions)
    override_seqs_sorted = sorted(override_seqs)

    # 5. Fetch full ledger & checkpoint and run independent cryptographic verification
    entries = fetch_all_evidence_paginated(mcp_url, tenant_id, bearer_token)
    _, _, cp_rpc = mcp_rpc_single_conn(
        mcp_url, tenant_id, bearer_token, "acta_get_checkpoint", {}, rpc_id=9999
    )
    cp_sc = cp_rpc["result"]["structuredContent"]
    sth = cp_sc["checkpoint"]

    prev_expected = "00" * 32
    leaves: list[bytes] = []
    verified_entries = 0
    verified_write_entries = 0
    for idx, entry in enumerate(entries):
        expected_seq = idx + 1
        assert int(entry["seq_num"]) == expected_seq, (
            f"seq gap/reorder: expected {expected_seq}, got {entry['seq_num']}"
        )
        assert entry["prev_hash"] == prev_expected, (
            f"broken prev_hash at seq {expected_seq}"
        )
        verify_evidence_entry(entry, host_pk_hex)
        verified_entries += 1
        if entry.get("write_summary") is not None:
            verified_write_entries += 1
        prev_expected = entry["event_hash"]
        leaves.append(merkle_leaf_hash(expected_seq, bytes.fromhex(entry["event_hash"])))

    rebuilt_merkle_root = compute_merkle_root_from_leaves(leaves).hex()
    assert int(sth["tree_size"]) == len(entries), (
        f"checkpoint tree_size {sth['tree_size']} != ledger len {len(entries)}"
    )
    assert sth["merkle_root"] == rebuilt_merkle_root, (
        f"merkle_root mismatch: {sth['merkle_root']} != {rebuilt_merkle_root}"
    )
    assert sth["head_event_hash"] == prev_expected
    assert verify_checkpoint_signature(
        bytes.fromhex(host_pk_hex),
        tenant_id,
        bytes.fromhex(sth["checkpoint_hash"]),
        bytes.fromhex(sth["host_signature"]),
    ), "checkpoint Ed25519 host_signature failed"

    # 6. Verify PPA 1 Ledger-Alone State Reconstruction (acta_verify_state_rebuild)
    state_rebuild_verified = None
    if server_version >= "1.7.0":
        req_reb = {"scope": scope, "include_proof_archive": server_version >= "1.7.1"}
        _, _, reb_rpc = mcp_rpc_single_conn(
            mcp_url,
            tenant_id,
            bearer_token,
            "acta_verify_state_rebuild",
            req_reb,
            rpc_id=10000,
        )
        assert not reb_rpc["result"].get("isError"), f"acta_verify_state_rebuild failed: {reb_rpc}"
        reb_sc = reb_rpc["result"]["structuredContent"]
        assert reb_sc["chain_cryptographically_verified"] is True
        assert reb_sc["matches_live_store_bit_for_bit"] is True
        assert reb_sc["legacy_pre_v17_unchained_objects"] == 0
        assert reb_sc["legacy_pre_v17_unchained_claims"] == 0
        offline_verified = False
        if server_version >= "1.7.1" and reb_sc.get("rebuild_proof_archive") is not None:
            from acta_sdk import verify_and_rebuild_scope_state_offline

            off_sum = verify_and_rebuild_scope_state_offline(
                reb_sc["rebuild_proof_archive"], host_pk_hex, scope_override=scope
            )
            assert (
                off_sum.reconstructed_state_commitment_hex
                == reb_sc["live_store_state_commitment"]
            ), "offline state rebuild commitment mismatch!"
            offline_verified = True
        state_rebuild_verified = {
            "chain_cryptographically_verified": reb_sc["chain_cryptographically_verified"],
            "matches_live_store_bit_for_bit": reb_sc["matches_live_store_bit_for_bit"],
            "offline_proof_archive_verified": offline_verified,
            "reconstructed_state_commitment": reb_sc["reconstructed_state_commitment"],
            "live_store_state_commitment": reb_sc["live_store_state_commitment"],
            "reconstructed_active_claims": reb_sc["reconstructed_active_claims"],
            "reconstructed_active_overrides": reb_sc["reconstructed_active_overrides"],
        }

    latencies = [r["latency_ms"] for r in results]
    start_spread_ms = round(
        (max(r["t_start"] for r in results) - min(r["t_start"] for r in results)) * 1000.0,
        2,
    )

    assert len(dup_ids) == 1, f"expected 1 deduplicated claim id across 10 concurrent ingests, got {dup_ids}"
    assert dup_noop_count == 9, f"expected 9 idempotent noops out of 10 identical ingests, got {dup_noop_count}"
    if server_version >= "1.7.0":
        assert len(dup_evidence_seqs) == 1, f"expected 1 write_summary seq for 10 identical ingests, got {dup_evidence_seqs}"
        assert verified_write_entries == 3, f"expected 3 write_summary entries (2 seed + 1 deduped), got {verified_write_entries}"
    assert override_versions_sorted == [1, 2, 3, 4, 5, 6, 7, 8], (
        f"expected contiguous override versions 1..8, got {override_versions_sorted}"
    )
    assert len(set(override_seqs_sorted)) == 8
    assert refusal_errors == 16

    expected_total = (3 + 1 + 8 + 16 + 16) if server_version >= "1.7.0" else (1 + 8 + 16 + 16)
    assert len(entries) == expected_total, f"expected {expected_total} entries, got {len(entries)}"

    report = {
        "harness_version": "1.7.1",
        "executed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_mcp_url": mcp_url,
        "server_reported_version": server_version,
        "tenant_id": tenant_id,
        "host_public_key": host_pk_hex,
        "concurrency_profile": {
            "worker_threads": 50,
            "independent_tls_connections": 50,
            "barrier_release_spread_ms": start_spread_ms,
            "peak_simultaneous_in_flight_requests": max_in_flight,
            "overlapping_request_pairs": overlapping_pairs,
            "total_request_pairs": total_pairs,
            "overlap_ratio": round(overlapping_pairs / max(total_pairs, 1), 4),
            "burst_wall_clock_seconds": round(burst_wall_s, 3),
            "latency_ms_min": round(min(latencies), 2),
            "latency_ms_median": round(statistics.median(latencies), 2),
            "latency_ms_p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2),
            "latency_ms_max": round(max(latencies), 2),
        },
        "race_invariants": {
            "concurrent_identical_claim_ingests": 10,
            "unique_claim_ids_created": len(dup_ids),
            "deduplicated_claim_id": next(iter(dup_ids)),
            "idempotent_noop_responses": dup_noop_count,
            "unique_write_evidence_entries_for_10_dups": len(dup_evidence_seqs),
            "concurrent_override_attestations": 8,
            "override_versions_observed_sorted": override_versions_sorted,
            "override_versions_exact_1_to_8": override_versions_sorted == [1, 2, 3, 4, 5, 6, 7, 8],
            "override_evidence_seq_nums": override_seqs_sorted,
            "concurrent_compiles_succeeded": len(compile_seqs),
            "concurrent_refusals_logged": refusal_errors,
        },
        "whole_ledger_verification": {
            "expected_total_entries": expected_total,
            "actual_total_entries": len(entries),
            "verified_entries": verified_entries,
            "verified_write_entries": verified_write_entries,
            "verification_failures": 0,
            "contiguous_seq_1_to_n": True,
            "unbroken_prev_hash_chain": True,
            "checkpoint_tree_size": sth["tree_size"],
            "rebuilt_rfc6962_merkle_root": rebuilt_merkle_root,
            "server_checkpoint_merkle_root": sth["merkle_root"],
            "merkle_root_match": sth["merkle_root"] == rebuilt_merkle_root,
            "checkpoint_hash": sth["checkpoint_hash"],
            "checkpoint_host_signature_verified": True,
            "ppa1_ledger_state_rebuild": state_rebuild_verified,
        },
        "all_invariants_passed": True,
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Acta v1.7.1 True-Parallel Concurrency Harness")
    parser.add_argument(
        "--url",
        default=os.environ.get(
            "ACTA_BASE_URL", "https://acta-server-998422936041.us-west1.run.app"
        ),
    )
    parser.add_argument(
        "--tenant",
        default=f"sandbox-v170-conc-{uuid.uuid4().hex[:8]}",
    )
    parser.add_argument("--bearer-token", default=os.environ.get("ACTA_API_KEY"))
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    rep = run_harness(
        base_url=args.url,
        tenant_id=args.tenant,
        bearer_token=args.bearer_token,
        output_path=args.output,
    )
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
