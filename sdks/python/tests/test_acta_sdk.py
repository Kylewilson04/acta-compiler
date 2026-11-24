"""Comprehensive cryptographic, RFC 6962 Merkle & live-mock HTTP test suite for `acta_sdk` v1.7.1."""

from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acta_sdk import (
    ActaAuthError,
    ActaClient,
    ActaDisputeEscalationError,
    ActaGeminiGuard,
    ActaPolicyBlockedError,
    ActaPolicyEscalatedError,
    ActaSignatureVerificationError,
    ActaTenantLockError,
    AsyncActaClient,
    compute_bundle_hash,
    compute_checkpoint_hash,
    compute_claim_content_hash,
    compute_claim_group_key,
    compute_evidence_event_hash,
    compute_logical_claim_group_key,
    compute_merkle_consistency_proof,
    compute_merkle_inclusion_proof,
    compute_merkle_root_from_leaves,
    compute_object_content_hash,
    compute_omission_list_hash,
    compute_override_attestation_hash,
    compute_refusal_metadata_commitment,
    dump_archive_preimages,
    extract_token_principal,
    extract_token_tenant,
    merkle_leaf_hash,
    mint_tenant_api_key,
    mint_user_tenant_api_key,
    sign_checkpoint_head,
    sign_evidence_entry,
    sign_override_attestation,
    sign_override_client_intent,
    sign_witness_anchor,
    to_canonical_json,
    verify_ed25519_strict,
    verify_export_archive,
    verify_merkle_consistency_proof,
    verify_merkle_inclusion_proof,
    verify_tenant_api_key,
    verify_tenant_api_key_with_principal,
)
from acta_sdk.crypto import ED25519_L, hash_length_delimited


def _raw_pubkey_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _build_signed_fixture(seed: bytes = b"\x42" * 32, disputed: bool = True) -> tuple[str, dict[str, Any]]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_hex = _raw_pubkey_hex(sk)
    ts = "2026-11-20T16:37:01.215313Z"
    tenant = "sandbox-live"
    scope = "payments-audit-1795192619"

    obj_id = "8b934fdc-0a70-43d8-9070-3b89ffb44ba2"
    obj: dict[str, Any] = {
        "id": obj_id,
        "tenant_id": tenant,
        "obj_type": "intent",
        "scope": scope,
        "lifecycle_status": "active",
        "priority": 100,
        "importance": 1.0,
        "tags": ["compliance"],
        "body": {"directive": "Never silently resolve competing merchant fee claims"},
        "content_hash": "",
        "version": 1,
        "predecessor_id": None,
        "created_at": ts,
    }
    obj["content_hash"] = compute_object_content_hash(obj).hex()

    cgk_hex = compute_claim_group_key(tenant, "merchant:global", "fee_bps", "int", scope).hex()
    src1 = hash_length_delimited([b"acta:source:v1", b"ledger-v1"]).hex()
    claim1: dict[str, Any] = {
        "id": "54e00c71-af84-4104-b180-0dd284829ac4",
        "tenant_id": tenant,
        "claim_group_key": cgk_hex,
        "scope": scope,
        "subject": "merchant:global",
        "predicate": "fee_bps",
        "object_val": 290,
        "object_type": "int",
        "confidence": 0.81,
        "source_provenance_class": 2,
        "source_descriptor": "ledger-v1",
        "source_commitment": src1,
        "content_hash": "",
        "status": "active",
        "contradiction_ids": [],
        "valid_from": None,
        "valid_to": None,
        "version": 1,
        "predecessor_id": None,
        "created_at": ts,
    }
    claim1["content_hash"] = compute_claim_content_hash(claim1).hex()

    cand1 = {
        "id": claim1["id"],
        "subject": claim1["subject"],
        "predicate": claim1["predicate"],
        "object_val": claim1["object_val"],
        "object_type": claim1["object_type"],
        "confidence": claim1["confidence"],
        "source_provenance_class": claim1["source_provenance_class"],
        "source_descriptor": claim1["source_descriptor"],
        "source_commitment": claim1["source_commitment"],
        "content_hash": claim1["content_hash"],
        "version": 1,
        "created_at": ts,
    }

    claims = [claim1]
    resolutions = []
    disputes = []
    if disputed:
        src2 = hash_length_delimited([b"acta:source:v1", b"crm-contract"]).hex()
        claim2 = copy.deepcopy(claim1)
        claim2["id"] = "652a3897-b0a8-410f-a18c-c8d80b3ae7b2"
        claim2["object_val"] = 240
        claim2["confidence"] = 0.74
        claim2["source_descriptor"] = "crm-contract"
        claim2["source_commitment"] = src2
        claim2["content_hash"] = compute_claim_content_hash(claim2).hex()
        claims.append(claim2)
        cand2 = {
            **cand1,
            "id": claim2["id"],
            "object_val": 240,
            "confidence": 0.74,
            "source_descriptor": "crm-contract",
            "source_commitment": src2,
            "content_hash": claim2["content_hash"],
        }
        disputes.append(
            {
                "claim_group_key": cgk_hex,
                "competing_claims": [cand1, cand2],
                "reason_code": "INSUFFICIENT_MARGIN",
                "escalation_required": True,
            }
        )
    else:
        resolutions.append(
            {
                "claim_group_key": cgk_hex,
                "winning_claim": cand1,
                "margin": None,
                "suppressed_claim_ids": [],
            }
        )

    omission_hash = compute_omission_list_hash([]).hex()
    state_comm = "a7c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd041"
    dep_comm = "b8c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd042"

    bundle: dict[str, Any] = {
        "schema_version": "acta-context-bundle/v1",
        "tenant_id": tenant,
        "task_id": "ui-compile-1",
        "scope": scope,
        "policy_result": "allow",
        "embedding_model_version": "text-embedding-3-small-1536",
        "selected_objects": [
            {
                "id": obj["id"],
                "obj_type": "intent",
                "version": 1,
                "content_hash": obj["content_hash"],
            }
        ],
        "resolution_records": resolutions,
        "dispute_records": disputes,
        "omission_record": {
            "inline_items": [],
            "total_omitted_count": 0,
            "full_excluded_hash": omission_hash,
            "has_unresolved_claims": disputed,
        },
        "state_commitment": state_comm,
        "dependency_commitment": dep_comm,
        "issued_at": ts,
    }
    bundle_hash_bytes, _ = compute_bundle_hash(bundle)
    bundle_hash_hex = bundle_hash_bytes.hex()

    zero_prev = "00" * 32
    ev1_hash = compute_evidence_event_hash(
        tenant_id=tenant,
        seq_num=1,
        prev_hash=zero_prev,
        bundle_hash=bundle_hash_hex,
        state_commitment=state_comm,
        policy_result="allow",
        created_at=ts,
    ).hex()
    ev1_sig = sign_evidence_entry(seed, tenant, 1, zero_prev, ev1_hash).hex()
    ev1 = {
        "tenant_id": tenant,
        "seq_num": 1,
        "prev_hash": zero_prev,
        "event_hash": ev1_hash,
        "bundle_hash": bundle_hash_hex,
        "state_commitment": state_comm,
        "policy_result": "allow",
        "host_signature": ev1_sig,
        "created_at": ts,
    }

    archive = {
        "bundle_hash": bundle_hash_hex,
        "bundle": bundle,
        "objects": [obj],
        "claims": claims,
        "evidence_chain": [ev1],
        "host_public_key": pk_hex,
    }
    return pk_hex, archive


class TestActaCryptoAndLiveCloudRunParity(unittest.TestCase):
    def test_jcs_canonicalization_rfc8785(self) -> None:
        a = {"zeta": 100, "alpha": {"b": True, "a": [3, 2, 1.0]}, "meta": -0.0}
        b = {"meta": 0, "alpha": {"a": [3, 2, 1], "b": True}, "zeta": 100}
        self.assertEqual(
            to_canonical_json(a),
            '{"alpha":{"a":[3,2,1],"b":true},"meta":0,"zeta":100}',
        )
        self.assertEqual(to_canonical_json(a), to_canonical_json(b))
        self.assertEqual(to_canonical_json(1e20), "100000000000000000000")
        self.assertEqual(to_canonical_json(1e21), "1e+21")
        self.assertEqual(to_canonical_json(1e-6), "0.000001")
        self.assertEqual(to_canonical_json(1e-7), "1e-7")

    def test_live_cloudrun_production_vectors_bit_for_bit(self) -> None:
        cedar_path = pathlib.Path(__file__).resolve().parents[3] / "policies" / "default.cedar"
        canonical_policy = cedar_path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
        self.assertIn('Action::"attest"', canonical_policy)
        perm_root_v15 = hash_length_delimited(
            [
                b"acta:permission_root:v1",
                canonical_policy.encode("utf-8"),
                b"{}",
                b'["pii","regulated","restricted"]',
                b"\x01",
            ]
        ).hex()
        self.assertEqual(len(perm_root_v15), 64)
        self.assertNotEqual(
            perm_root_v15,
            "a885276369e22c385c756739f83d771e5874db13dfcd2f424268fc3fbda76a9a",
        )

        cgk = compute_claim_group_key(
            "sandbox-live",
            "merchant:global",
            "fee_bps",
            "int",
            "payments-audit-1795192619",
        ).hex()
        self.assertEqual(
            cgk,
            "c16dcc121d6c232910e0148b405abdfd8f0dc53c185724f4b7304ad2994bf958",
        )

        ev1 = compute_evidence_event_hash(
            tenant_id="sandbox-live",
            seq_num=1,
            prev_hash="00" * 32,
            bundle_hash="e39ff7e41347d1547b107de9bfa3339e9ef30fa75742d8d1f33a51599be4b562",
            state_commitment="a7c7e692c4ddee3d84dca094c470716ac48e14988deb389375889065622fd041",
            policy_result="allow",
            created_at="2026-11-20T16:37:01.215313Z",
        ).hex()
        self.assertTrue(ev1.startswith("5538aa5fc6559d1e"))

        ev2 = compute_evidence_event_hash(
            tenant_id="sandbox-live",
            seq_num=2,
            prev_hash=ev1,
            bundle_hash=None,
            state_commitment=None,
            policy_result="escalate",
            created_at="2026-11-20T16:37:13.789999Z",
        ).hex()
        self.assertEqual(
            ev2,
            "1e1aa455fbcea3e6e698dce7efd85219ac006bd2470d70429452463bfd938753",
        )

    def test_v16_merkle_inclusion_consistency_lapsed_override_and_witness_anchor(self) -> None:
        # 1. RFC 6962 inclusion & consistency across sizes 1..25
        events = [
            hash_length_delimited([b"ev", i.to_bytes(8, "little")]) for i in range(1, 26)
        ]
        leaves = [merkle_leaf_hash(i + 1, ev) for i, ev in enumerate(events)]
        for size in range(1, 26):
            root = compute_merkle_root_from_leaves(leaves[:size])
            for idx in range(size):
                path = compute_merkle_inclusion_proof(leaves[:size], idx)
                self.assertTrue(
                    verify_merkle_inclusion_proof(idx + 1, events[idx], size, path, root)
                )
            for first in range(1, size + 1):
                first_root = compute_merkle_root_from_leaves(leaves[:first])
                cproof = compute_merkle_consistency_proof(leaves, first, size)
                self.assertTrue(
                    verify_merkle_consistency_proof(first, first_root, size, root, cproof)
                )
                if first < size:
                    bad_first = bytearray(first_root)
                    bad_first[0] ^= 0x01
                    self.assertFalse(
                        verify_merkle_consistency_proof(
                            first, bytes(bad_first), size, root, cproof
                        )
                    )

        # 2. Compact O(log N) Merkle-only ExportArchive with client-signed LapsedOverrideRef & WitnessAnchor
        seed = b"\x42" * 32
        pk_hex, base_archive = _build_signed_fixture(seed=seed, disputed=True)
        tenant = base_archive["bundle"]["tenant_id"]
        scope = base_archive["bundle"]["scope"]
        claim1, claim2 = base_archive["claims"][0], base_archive["claims"][1]
        logical_group = compute_logical_claim_group_key(
            tenant, claim1["subject"], claim1["predicate"], scope
        ).hex()

        ts1 = "2026-11-22T04:10:00.000000Z"
        ts2 = "2026-11-22T04:10:05.000000Z"
        ts3 = "2026-11-22T04:10:10.000000Z"
        zero_prev = "00" * 32

        rmeta = {
            "operation": "attest_override",
            "reason_code": "adjudicator_signature_required",
            "target_scope": scope,
            "summary": "Custom adjudicator requires offline Ed25519 signature",
        }
        rcomm = compute_refusal_metadata_commitment(rmeta).hex()
        ev1_hash = compute_evidence_event_hash(
            tenant, 1, zero_prev, None, rcomm, "block", ts1, refusal_metadata=rmeta
        ).hex()
        ev1 = {
            "tenant_id": tenant,
            "seq_num": 1,
            "prev_hash": zero_prev,
            "event_hash": ev1_hash,
            "bundle_hash": None,
            "state_commitment": rcomm,
            "policy_result": "block",
            "refusal_metadata": rmeta,
            "host_signature": sign_evidence_entry(seed, tenant, 1, zero_prev, ev1_hash).hex(),
            "created_at": ts1,
        }

        committee_seed = b"\x99" * 32
        justification = "Signed MSA addendum §4.2 supersedes legacy ledger rate"
        csig_hex, cpk_hex = sign_override_client_intent(
            committee_seed,
            tenant_id=tenant,
            scope=scope,
            winning_claim_id=claim2["id"],
            adjudicator_id="cfo-committee",
            justification=justification,
        )
        att_id = "99999999-1111-4222-8333-444444444444"
        att: dict[str, Any] = {
            "id": att_id,
            "tenant_id": tenant,
            "scope": scope,
            "claim_group_key": logical_group,
            "subject": claim2["subject"],
            "predicate": claim2["predicate"],
            "source_bundle_hash": base_archive["bundle_hash"],
            "winning_claim_id": claim2["id"],
            "winning_claim_content_hash": claim2["content_hash"],
            "overridden_claims": [{"id": claim1["id"], "content_hash": claim1["content_hash"]}],
            "adjudicator_id": f"{tenant}::cfo-committee",
            "justification": justification,
            "version": 1,
            "predecessor_id": None,
            "created_at": ts2,
            "attestation_hash": "",
            "evidence_seq_num": 2,
            "host_signature": "",
            "client_signature": csig_hex,
            "client_public_key": cpk_hex,
        }
        att["attestation_hash"] = compute_override_attestation_hash(att).hex()
        att["host_signature"] = sign_override_attestation(
            seed, tenant, 2, att["attestation_hash"]
        ).hex()

        osummary = {
            "attestation_id": att_id,
            "scope": scope,
            "subject": claim2["subject"],
            "predicate": claim2["predicate"],
            "winning_claim_id": claim2["id"],
            "overridden_count": 1,
            "adjudicator_id": att["adjudicator_id"],
            "version": 1,
        }
        ev2_hash = compute_evidence_event_hash(
            tenant, 2, ev1_hash, None, att["attestation_hash"], "allow", ts2, override_summary=osummary
        ).hex()
        ev2 = {
            "tenant_id": tenant,
            "seq_num": 2,
            "prev_hash": ev1_hash,
            "event_hash": ev2_hash,
            "bundle_hash": None,
            "state_commitment": att["attestation_hash"],
            "policy_result": "allow",
            "override_summary": osummary,
            "host_signature": sign_evidence_entry(seed, tenant, 2, ev1_hash, ev2_hash).hex(),
            "created_at": ts2,
        }

        # Claim C arrives and reopens the dispute with LapsedOverrideRef!
        claim3 = copy.deepcopy(claim1)
        claim3["id"] = "20b6b7a6-8c52-4590-9987-a6487f7cf185"
        claim3["object_val"] = 310
        claim3["confidence"] = 0.79
        claim3["source_descriptor"] = "erp-v3"
        claim3["content_hash"] = compute_claim_content_hash(claim3).hex()
        cand3 = {
            **base_archive["bundle"]["dispute_records"][0]["competing_claims"][0],
            "id": claim3["id"],
            "object_val": 310,
            "confidence": 0.79,
            "source_descriptor": "erp-v3",
            "content_hash": claim3["content_hash"],
        }

        bundle_v16 = copy.deepcopy(base_archive["bundle"])
        bundle_v16["dispute_records"][0]["claim_group_key"] = logical_group
        bundle_v16["dispute_records"][0]["competing_claims"].append(cand3)
        bundle_v16["dispute_records"][0]["lapsed_override"] = {
            "attestation_id": att_id,
            "attestation_hash": att["attestation_hash"],
            "prior_winning_claim_id": claim2["id"],
            "adjudicator_id": att["adjudicator_id"],
            "justification": justification,
            "evidence_seq_num": 2,
            "version": 1,
            "attested_at": ts2,
            "reopened_by_claim_ids": [claim3["id"]],
        }
        b_hash_v16, _ = compute_bundle_hash(bundle_v16)
        b_hex_v16 = b_hash_v16.hex()

        ev3_hash = compute_evidence_event_hash(
            tenant, 3, ev2_hash, b_hex_v16, bundle_v16["state_commitment"], "allow", ts3
        ).hex()
        ev3 = {
            "tenant_id": tenant,
            "seq_num": 3,
            "prev_hash": ev2_hash,
            "event_hash": ev3_hash,
            "bundle_hash": b_hex_v16,
            "state_commitment": bundle_v16["state_commitment"],
            "policy_result": "allow",
            "host_signature": sign_evidence_entry(seed, tenant, 3, ev2_hash, ev3_hash).hex(),
            "created_at": ts3,
        }

        chain_leaves = [
            merkle_leaf_hash(1, ev1_hash),
            merkle_leaf_hash(2, ev2_hash),
            merkle_leaf_hash(3, ev3_hash),
        ]
        merkle_root_hex = compute_merkle_root_from_leaves(chain_leaves).hex()
        cp_hash_hex = compute_checkpoint_hash(tenant, 3, ev3_hash, merkle_root_hex, ts3).hex()
        cp_sig_hex = sign_checkpoint_head(seed, tenant, cp_hash_hex).hex()

        witness_seed = b"\x77" * 32
        wsig_hex, wpk_hex = sign_witness_anchor(witness_seed, tenant, 3, cp_hash_hex)
        anchor = {
            "id": "11111111-2222-4333-8444-555555555555",
            "tenant_id": tenant,
            "tree_size": 3,
            "checkpoint_hash": cp_hash_hex,
            "witness_id": "rekor-transparency-mirror",
            "witness_public_key": wpk_hex,
            "witness_signature": wsig_hex,
            "anchored_at": ts3,
        }
        sth = {
            "tenant_id": tenant,
            "tree_size": 3,
            "head_event_hash": ev3_hash,
            "merkle_root": merkle_root_hex,
            "issued_at": ts3,
            "checkpoint_hash": cp_hash_hex,
            "host_signature": cp_sig_hex,
            "witness_anchors": [anchor],
        }

        merkle_only_archive = {
            "bundle_hash": b_hex_v16,
            "bundle": bundle_v16,
            "objects": base_archive["objects"],
            "claims": [claim1, claim2, claim3],
            "override_attestations": [att],
            "evidence_chain": [],
            "merkle_proof": {
                "checkpoint": sth,
                "bundle_entry_proof": {
                    "entry": ev3,
                    "audit_path": [
                        p.hex() for p in compute_merkle_inclusion_proof(chain_leaves, 2)
                    ],
                },
                "override_entry_proofs": [
                    {
                        "entry": ev2,
                        "audit_path": [
                            p.hex() for p in compute_merkle_inclusion_proof(chain_leaves, 1)
                        ],
                    }
                ],
            },
            "host_public_key": pk_hex,
        }

        summary = verify_export_archive(merkle_only_archive, pk_hex)
        self.assertEqual(summary.verification_mode, "merkle_inclusion")
        self.assertEqual(summary.verified_overrides, 1)
        self.assertEqual(summary.verified_evidence_entries, 2)
        self.assertEqual(summary.merkle_tree_size, 3)
        self.assertEqual(summary.verified_witness_anchors, 1)

        preimages = dump_archive_preimages(merkle_only_archive)
        self.assertEqual(preimages["checkpoint"]["tree_size"], 3)
        self.assertEqual(len(preimages["override_attestations"]), 1)

        # Forging client_signature on committee override must fail!
        bad_csig = copy.deepcopy(merkle_only_archive)
        bad_csig["override_attestations"][0]["client_signature"] = "00" * 64
        with self.assertRaisesRegex(ValueError, "client Ed25519 signature"):
            verify_export_archive(bad_csig, pk_hex)

        # Tampering lapsed_override.evidence_seq_num must fail!
        bad_lapsed = copy.deepcopy(merkle_only_archive)
        bad_lapsed["bundle"]["dispute_records"][0]["lapsed_override"]["evidence_seq_num"] = 99
        with self.assertRaisesRegex(ValueError, "tampered lapsed_override"):
            verify_export_archive(bad_lapsed, pk_hex)

    def test_offline_archive_verification_and_tamper_rejection(self) -> None:
        pk_hex, archive = _build_signed_fixture()
        summary = verify_export_archive(archive, pk_hex)
        self.assertEqual(summary.tenant_id, "sandbox-live")
        self.assertEqual(summary.verified_objects, 1)
        self.assertEqual(summary.verified_claims, 2)
        self.assertEqual(summary.verified_evidence_entries, 1)
        self.assertEqual(summary.verification_mode, "full_chain")

        forged_claim = copy.deepcopy(archive)
        forged_claim["claims"][0]["object_val"] = 999999
        with self.assertRaisesRegex(ValueError, "tampered claim"):
            verify_export_archive(forged_claim, pk_hex)

        forged_bundle = copy.deepcopy(archive)
        forged_bundle["bundle"]["omission_record"]["total_omitted_count"] = 5
        with self.assertRaisesRegex(ValueError, "tampered ContextBundle"):
            verify_export_archive(forged_bundle, pk_hex)

        forged_sig = copy.deepcopy(archive)
        raw_sig = bytearray.fromhex(forged_sig["evidence_chain"][0]["host_signature"])
        raw_sig[10] ^= 0x01
        forged_sig["evidence_chain"][0]["host_signature"] = bytes(raw_sig).hex()
        with self.assertRaisesRegex(ValueError, "Ed25519 host_signature verification failed"):
            verify_export_archive(forged_sig, pk_hex)

        s_plus_l = int.from_bytes(raw_sig[32:64], "little") + ED25519_L
        malleable = bytes(raw_sig[:32]) + s_plus_l.to_bytes(32, "little")
        self.assertFalse(verify_ed25519_strict(bytes.fromhex(pk_hex), b"msg", malleable))


class _MockActaHandler(BaseHTTPRequestHandler):
    seed = b"\x55" * 32
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_hex = _raw_pubkey_hex(sk)
    api_key = "secret-prod-key"
    forged_sig_mode = False

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/v1/health":
            self._send(
                200,
                {
                    "status": "ok",
                    "service": "acta-compiler",
                    "version": "1.7.1",
                    "host_public_key": self.pk_hex,
                    "permission_root": "26" * 32,
                },
            )
            return
        if self.path.startswith("/v1/bundles/") and "/export" in self.path:
            _, archive = _build_signed_fixture(self.seed, disputed=True)
            self._send(200, archive)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        if self.path == "/v1/overrides":
            tenant = body["tenant_id"]
            att_hash = hash_length_delimited([b"mock-override", tenant.encode("utf-8")]).hex()
            sig = sign_override_attestation(self.seed, tenant, 7, att_hash).hex()
            self._send(
                201,
                {
                    "id": "99999999-1111-4222-8333-444444444444",
                    "version": 1,
                    "claim_group_key": "aa" * 32,
                    "subject": "merchant:global",
                    "predicate": "fee_bps",
                    "winning_claim_id": body["winning_claim_id"],
                    "winning_claim_content_hash": "bb" * 32,
                    "overridden_claim_ids": ["54e00c71-af84-4104-b180-0dd284829ac4"],
                    "adjudicator_id": body.get("adjudicator_id", f"{tenant}::session"),
                    "adjudicator_auth_kind": "master_api_key",
                    "justification": body["justification"],
                    "attestation_hash": att_hash,
                    "evidence_seq_num": 7,
                    "host_signature": sig,
                    "was_idempotent_noop": False,
                    "created_at": "2026-11-22T04:10:05.000000Z",
                },
            )
            return

        if self.path == "/v1/compile":
            tenant = body["tenant_id"]
            if not tenant.startswith("sandbox") and self.headers.get("X-Acta-Api-Key") != self.api_key:
                self._send(401, {"error": "missing or invalid API key"})
                return

            scope = body["scope"]
            ts = "2026-11-20T16:37:01.215313Z"
            zero_prev = "00" * 32

            if scope.startswith("restricted/"):
                rmeta = {
                    "operation": "compile",
                    "reason_code": "POLICY_ESCALATE",
                    "target_scope": scope,
                    "summary": "Restricted scope requires supervisor escalation approval",
                }
                rcomm = compute_refusal_metadata_commitment(rmeta).hex()
                ev_hash = compute_evidence_event_hash(
                    tenant, 1, zero_prev, None, rcomm, "escalate", ts, refusal_metadata=rmeta
                ).hex()
                sig = sign_evidence_entry(self.seed, tenant, 1, zero_prev, ev_hash).hex()
                self._send(
                    202,
                    {
                        "policy_decision": {
                            "decision": "escalate",
                            "reason": "Restricted scope requires supervisor escalation approval",
                        },
                        "evidence": {
                            "tenant_id": tenant,
                            "seq_num": 1,
                            "prev_hash": zero_prev,
                            "event_hash": ev_hash,
                            "bundle_hash": None,
                            "state_commitment": rcomm,
                            "policy_result": "escalate",
                            "refusal_metadata": rmeta,
                            "host_signature": sig,
                            "created_at": ts,
                        },
                    },
                )
                return

            if scope.startswith("blocked/"):
                rmeta = {
                    "operation": "compile",
                    "reason_code": "POLICY_BLOCK",
                    "target_scope": scope,
                    "summary": "Cross-tenant access denied",
                }
                rcomm = compute_refusal_metadata_commitment(rmeta).hex()
                ev_hash = compute_evidence_event_hash(
                    tenant, 1, zero_prev, None, rcomm, "block", ts, refusal_metadata=rmeta
                ).hex()
                sig = sign_evidence_entry(self.seed, tenant, 1, zero_prev, ev_hash).hex()
                self._send(
                    403,
                    {
                        "policy_decision": {"decision": "block", "reason": "Cross-tenant access denied"},
                        "evidence": {
                            "tenant_id": tenant,
                            "seq_num": 1,
                            "prev_hash": zero_prev,
                            "event_hash": ev_hash,
                            "bundle_hash": None,
                            "state_commitment": rcomm,
                            "policy_result": "block",
                            "refusal_metadata": rmeta,
                            "host_signature": sig,
                            "created_at": ts,
                        },
                    },
                )
                return

            disputed = "dispute" in scope
            _, archive = _build_signed_fixture(self.seed, disputed=disputed)
            archive["bundle"]["tenant_id"] = tenant
            archive["bundle"]["scope"] = scope
            b_hash, _ = compute_bundle_hash(archive["bundle"])
            b_hex = b_hash.hex()
            ev_hash = compute_evidence_event_hash(
                tenant,
                1,
                zero_prev,
                b_hex,
                archive["bundle"]["state_commitment"],
                "allow",
                ts,
            ).hex()
            sig_bytes = bytearray(sign_evidence_entry(self.seed, tenant, 1, zero_prev, ev_hash))
            if self.__class__.forged_sig_mode:
                sig_bytes[0] ^= 0xFF
            self._send(
                200,
                {
                    "policy_decision": {"decision": "allow"},
                    "bundle_hash": b_hex,
                    "context_text": "[DISPUTE: INSUFFICIENT_MARGIN]" if disputed else "[FACT] fee_bps = 290",
                    "bundle": archive["bundle"],
                    "evidence": {
                        "tenant_id": tenant,
                        "seq_num": 1,
                        "prev_hash": zero_prev,
                        "event_hash": ev_hash,
                        "bundle_hash": b_hex,
                        "state_commitment": archive["bundle"]["state_commitment"],
                        "policy_result": "allow",
                        "host_signature": bytes(sig_bytes).hex(),
                        "created_at": ts,
                    },
                },
            )
            return
        self._send(404, {"error": "not found"})


class TestActaClientAndGeminiGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _MockActaHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _MockActaHandler.forged_sig_mode = False

    def test_gemini_guard_halts_llm_on_policy_and_disputes(self) -> None:
        llm_calls: list[str] = []

        def fake_gemini(prompt: str, _compiled: Any) -> str:
            llm_calls.append(prompt)
            return "Approved 290 bps settlement."

        with ActaClient(self.base_url, api_key="secret-prod-key") as client:
            guard = ActaGeminiGuard(client, strict_disputes=True)

            ok = guard.generate_content(
                tenant_id="prod-acme",
                actor_id="auditor-1",
                scope="clean-settlement",
                prompt="Confirm fee_bps",
                llm_callable=fake_gemini,
            )
            self.assertEqual(len(llm_calls), 1)
            self.assertIn("[FACT] fee_bps = 290", llm_calls[0])
            self.assertEqual(ok.verified_host_pubkey, _MockActaHandler.pk_hex)

            with self.assertRaises(ActaDisputeEscalationError) as disp_ctx:
                guard.generate_content(
                    tenant_id="prod-acme",
                    actor_id="auditor-1",
                    scope="dispute-settlement",
                    prompt="Confirm fee_bps",
                    llm_callable=fake_gemini,
                )
            self.assertEqual(len(llm_calls), 1)
            self.assertEqual(len(disp_ctx.exception.disputes), 1)

            ovr = client.attest_override(
                tenant_id="prod-acme",
                scope="dispute-settlement",
                winning_claim_id="652a3897-b0a8-410f-a18c-c8d80b3ae7b2",
                justification="Verified signed MSA schedule",
            )
            self.assertEqual(ovr["evidence_seq_num"], 7)

            with self.assertRaises(ActaPolicyEscalatedError) as esc_ctx:
                guard.generate_content(
                    tenant_id="prod-acme",
                    actor_id="auditor-1",
                    scope="restricted/keys",
                    prompt="Read vault",
                    llm_callable=fake_gemini,
                )
            self.assertEqual(len(llm_calls), 1)
            self.assertEqual(esc_ctx.exception.evidence["policy_result"], "escalate")
            self.assertEqual(
                esc_ctx.exception.evidence["refusal_metadata"]["target_scope"],
                "restricted/keys",
            )

            with self.assertRaises(ActaPolicyBlockedError):
                guard.generate_content(
                    tenant_id="prod-acme",
                    actor_id="auditor-1",
                    scope="blocked/other",
                    prompt="Read other tenant",
                    llm_callable=fake_gemini,
                )
            self.assertEqual(len(llm_calls), 1)

            summary = client.verify_bundle_offline(ok.bundle_hash)
            self.assertEqual(summary.verified_claims, 2)

            _MockActaHandler.forged_sig_mode = True
            with self.assertRaises(ActaSignatureVerificationError):
                guard.generate_content(
                    tenant_id="prod-acme",
                    actor_id="auditor-1",
                    scope="clean-settlement",
                    prompt="Confirm fee_bps",
                    llm_callable=fake_gemini,
                )
            self.assertEqual(len(llm_calls), 1)

        with ActaClient(self.base_url) as unauth_client:
            with self.assertRaises(ActaAuthError):
                unauth_client.compile(
                    tenant_id="prod-acme",
                    actor_id="auditor-1",
                    scope="clean-settlement",
                    query_text="ping",
                )

    def test_async_client_compile_guarded(self) -> None:
        async def _run() -> None:
            async with AsyncActaClient(self.base_url, api_key="secret-prod-key") as aclient:
                res = await aclient.compile_guarded(
                    tenant_id="prod-acme",
                    actor_id="async-agent",
                    scope="clean-settlement",
                    query_text="Confirm fee",
                )
                self.assertTrue(res.is_allow)
                self.assertEqual(res.verified_host_pubkey, _MockActaHandler.pk_hex)

        asyncio.run(_run())


class TestActaV16TenantAndPrincipalTokens(unittest.TestCase):
    def test_stateless_2part_and_3part_principal_tokens_and_client_lock(self) -> None:
        master = "acta_live_master_secret_998877"
        tk_ardyn = mint_tenant_api_key(master, "ardyn-core")
        tk_acme = mint_tenant_api_key(master, "client-acme")
        self.assertTrue(tk_ardyn.startswith("acta_tk_v1:ardyn-core:"))
        self.assertNotEqual(tk_ardyn, tk_acme)
        self.assertEqual(verify_tenant_api_key(master, tk_ardyn), "ardyn-core")
        self.assertIsNone(extract_token_principal(tk_ardyn))

        tk_user = mint_user_tenant_api_key(master, "ardyn-core", "KyleWilson04")
        self.assertTrue(tk_user.startswith("acta_tk_v1:ardyn-core:kylewilson04:"))
        self.assertEqual(extract_token_tenant(tk_user), "ardyn-core")
        self.assertEqual(extract_token_principal(tk_user), "kylewilson04")
        self.assertEqual(
            verify_tenant_api_key_with_principal(master, tk_user),
            ("ardyn-core", "kylewilson04"),
        )

        # Swapping principal login inside 3-segment token must fail MAC!
        mac_user = tk_user.rsplit(":", 1)[1]
        with self.assertRaises(ValueError):
            verify_tenant_api_key_with_principal(
                master, f"acta_tk_v1:ardyn-core:cfo-committee:{mac_user}"
            )

        with ActaClient("http://127.0.0.1:9", api_key=tk_user) as locked_client:
            self.assertEqual(locked_client.locked_tenant, "ardyn-core")
            self.assertEqual(locked_client.verified_principal, "kylewilson04")
            with self.assertRaises(ActaTenantLockError):
                locked_client.compile(
                    tenant_id="client-acme",
                    actor_id="claude",
                    scope="ops",
                    query_text="attempt cross-tenant",
                )


class TestActaGitMcpBridge(unittest.TestCase):
    def test_git_origin_and_acta_json_auto_routing_and_stdio_rpc(self) -> None:
        import io
        import subprocess
        import tempfile
        from acta_sdk.mcp_bridge import ActaGitMcpBridge, resolve_git_workspace_context

        with tempfile.TemporaryDirectory() as tmp:
            repo_a = pathlib.Path(tmp) / "ads-platform"
            repo_a.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo_a, check=True)
            subprocess.run(
                ["git", "remote", "add", "origin", "git@github.com:ardyn-intelligence/ads-platform.git"],
                cwd=repo_a,
                check=True,
            )
            r_a = resolve_git_workspace_context(repo_a)
            self.assertEqual(r_a.tenant_id, "ardyn-intelligence")
            self.assertEqual(r_a.default_scope, "ads-platform")

            _MockActaHandler.forged_sig_mode = False
            srv = HTTPServer(("127.0.0.1", 0), _MockActaHandler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                (repo_a / ".acta.json").write_text(
                    '{"tenant": "sandbox-ardyn", "default_scope": "ads-core"}',
                    encoding="utf-8",
                )
                bridge = ActaGitMcpBridge(
                    cwd=repo_a,
                    base_url=f"http://127.0.0.1:{srv.server_port}",
                    pinned_host_public_key=_MockActaHandler.pk_hex,
                )
                try:
                    in_buf = io.BytesIO(
                        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n'
                        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"acta_workspace_status","arguments":{}}}\n'
                        b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"acta_compile_context","arguments":{"query_text":"Check status"}}}\n'
                        b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"acta_compile_context","arguments":{"tenant_id":"other-org","query_text":"Attempt hop"}}}\n'
                    )
                    out_buf = io.BytesIO()
                    bridge.serve_stdio(in_buf, out_buf)
                    lines = [
                        json.loads(line)
                        for line in out_buf.getvalue().decode("utf-8").splitlines()
                        if line.strip()
                    ]
                    self.assertEqual(len(lines), 4)
                    self.assertEqual(
                        lines[0]["result"]["serverInfo"]["version"], "1.7.1"
                    )
                    self.assertEqual(
                        lines[1]["result"]["structuredContent"]["tenant_id"], "sandbox-ardyn"
                    )
                    self.assertFalse(lines[2]["result"]["isError"])
                    self.assertTrue(lines[3]["result"]["isError"])
                finally:
                    bridge.close()
            finally:
                srv.shutdown()
                srv.server_close()




class TestV162WitnessRegAndCrossCheckpointBridge(unittest.TestCase):
    def test_live_seq_58_witness_reg_v1_and_v2_principal_binding(self) -> None:
        from acta_sdk import (
            blake3_hash,
            compute_witness_registration_commitment,
            compute_witness_registration_v2_commitment,
            witness_registration_preimage_bytes,
        )

        pk58 = "e5b050185444bd8e1b0892678934c70ff65f896602e9bf0faa87a4702a7ad9e4"
        pre_v1 = witness_registration_preimage_bytes(
            "acta:witness_reg:v1",
            "kylewilson04",
            "claude-witness-v161",
            pk58,
            "kylewilson04::session",
        )
        self.assertEqual(
            blake3_hash([pre_v1]).hex(),
            "e28df78841329df7b66aef44558586b81d952d1434a48f6605d0a6431e080fec",
        )
        self.assertEqual(
            compute_witness_registration_commitment("kylewilson04", "claude-witness-v161", pk58).hex(),
            "e28df78841329df7b66aef44558586b81d952d1434a48f6605d0a6431e080fec",
        )
        pre_v2, comm_v2 = compute_witness_registration_v2_commitment(
            "kylewilson04",
            "claude-witness-v162",
            pk58,
            "kylewilson04::oauth:kylewilson04",
        )
        _, comm_v2_session = compute_witness_registration_v2_commitment(
            "kylewilson04",
            "claude-witness-v162",
            pk58,
            "kylewilson04::session",
        )
        self.assertNotEqual(comm_v2, comm_v2_session)
        self.assertEqual(blake3_hash([pre_v2]), comm_v2)

        from acta_sdk import (
            compute_witness_registration_v3_commitment,
            compute_witness_revocation_commitment,
        )

        pre_v3_a, comm_v3_a = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            pk58,
            "kylewilson04::oauth:kylewilson04",
            "Claude v1.6.5 Witness",
        )
        _, comm_v3_b = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            pk58,
            "kylewilson04::oauth:kylewilson04",
            "Tampered",
        )
        _, comm_v3_none = compute_witness_registration_v3_commitment(
            "kylewilson04",
            "claude-witness-v163",
            pk58,
            "kylewilson04::oauth:kylewilson04",
            None,
        )
        self.assertNotEqual(comm_v3_a, comm_v3_b)
        self.assertNotEqual(comm_v3_a, comm_v3_none)
        self.assertEqual(blake3_hash([pre_v3_a]), comm_v3_a)

        rev_pre, rev_comm = compute_witness_revocation_commitment(
            "kylewilson04",
            "claude-revoke-probe-v163",
            pk58,
            "kylewilson04::session",
            "Key rotation",
        )
        self.assertEqual(blake3_hash([rev_pre]), rev_comm)


if __name__ == "__main__":
    unittest.main()


def test_v164_witness_retirement_v2_vectors():
    from acta_sdk import compute_witness_revocation_v2_commitment
    from acta_sdk.crypto import witness_revocation_preimage_bytes

    pk = "aa" * 32
    pre_ret, comm_ret = compute_witness_revocation_v2_commitment(
        "kylewilson04",
        "claude-retire-probe-v164",
        pk,
        "kylewilson04::oauth:kylewilson04",
        "retire",
        86,
        "Graceful key rotation after anchoring head 85",
    )
    pre_comp, comm_comp = compute_witness_revocation_v2_commitment(
        "kylewilson04",
        "claude-retire-probe-v164",
        pk,
        "kylewilson04::oauth:kylewilson04",
        "compromise",
        None,
        "Graceful key rotation after anchoring head 85",
    )
    assert comm_ret != comm_comp
    assert pre_ret != pre_comp
    try:
        witness_revocation_preimage_bytes(
            "acta:witness_revoke:v2",
            "kylewilson04",
            "claude-retire-probe-v164",
            pk,
            "kylewilson04::oauth:kylewilson04",
            "Bad combination",
            revocation_mode="retire",
            effective_from_tree_size=None,
        )
        raise AssertionError("expected ValueError")
    except ValueError:
        pass



class TestV171Claim25AndOfflineRebuild(unittest.TestCase):
    def test_v171_task_dependency_commitment_invalidation_and_offline_rebuild(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from acta_sdk import (
            SCHEMA_VERSION,
            STATE_REBUILD_ARCHIVE_SCHEMA_V1,
            compute_answer_cache_summary_commitment,
            compute_answer_text_hash,
            compute_checkpoint_hash,
            compute_claim_content_hash,
            compute_evidence_event_hash,
            compute_logical_claim_group_key,
            compute_merkle_consistency_proof,
            compute_merkle_root_from_leaves,
            compute_object_content_hash,
            compute_query_text_hash,
            compute_state_commitment,
            compute_sub_commitment,
            compute_task_dependency_commitment,
            compute_write_summary_commitment,
            merkle_leaf_hash,
            sign_checkpoint_head,
            sign_evidence_entry,
            sign_witness_anchor,
            verify_and_rebuild_scope_state_offline,
            verify_evidence_entry,
        )

        host_seed = "44" * 32
        host_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(host_seed))
        host_pk_hex = host_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        wit_seed = "55" * 32
        perm_root = "3ff40da50dd7f2aa32ce30409426f6d485bcf376caa4ff862f3aeb071410772a"
        tenant = "kylewilson04"
        scope = "acta-test/v171-sdk"
        ts = "2026-11-24T17:00:00.000000Z"

        # 1. Task dependency commitment invariance under unrelated writes
        dep_a = compute_task_dependency_commitment(
            tenant,
            scope,
            perm_root,
            compute_sub_commitment([]),
            compute_sub_commitment([]),
            compute_sub_commitment(["aa" * 32]),
        )
        dep_b = compute_task_dependency_commitment(
            tenant,
            scope,
            perm_root,
            compute_sub_commitment([]),
            compute_sub_commitment([]),
            compute_sub_commitment(["bb" * 32]),
        )
        self.assertEqual(len(dep_a), 32)
        self.assertNotEqual(dep_a, dep_b)

        # 2. Build chained write + cache invalidation + anchored checkpoint at seq 2 + head at seq 3
        obj = {
            "id": "11111111-1111-4111-8111-111111111111",
            "tenant_id": tenant,
            "obj_type": "intent",
            "scope": scope,
            "lifecycle_status": "active",
            "priority": 90,
            "importance": 1.0,
            "tags": ["v171"],
            "body": {"directive": "Pool corroborating sources"},
            "version": 1,
            "predecessor_id": None,
            "created_at": ts,
        }
        obj["content_hash"] = compute_object_content_hash(obj).hex()
        ws1 = {
            "write_domain": "acta:write_event:v1",
            "operation": "ingest_object",
            "item_id": obj["id"],
            "scope": scope,
            "version": 1,
            "content_hash": obj["content_hash"],
            "written_by": f"{tenant}::oauth:{tenant}",
            "writer_auth_kind": "oauth_github_principal",
            "record_snapshot": obj,
        }
        ws1_comm = compute_write_summary_commitment(ws1).hex()
        ev1_hash = compute_evidence_event_hash(
            tenant, 1, "00" * 32, None, ws1_comm, "allow", ts, write_summary=ws1
        ).hex()
        entry1 = {
            "tenant_id": tenant,
            "seq_num": 1,
            "event_domain": "acta:evidence_event:v3",
            "prev_hash": "00" * 32,
            "event_hash": ev1_hash,
            "bundle_hash": None,
            "state_commitment": ws1_comm,
            "policy_result": "allow",
            "write_summary": ws1,
            "host_signature": sign_evidence_entry(host_seed, tenant, 1, "00" * 32, ev1_hash).hex(),
            "created_at": ts,
        }

        gkey = compute_logical_claim_group_key(tenant, "supplier:titan", "lead_days", scope).hex()
        clm = {
            "id": "22222222-2222-4222-8222-222222222222",
            "tenant_id": tenant,
            "claim_group_key": gkey,
            "scope": scope,
            "subject": "supplier:titan",
            "predicate": "lead_days",
            "object_val": 14,
            "object_type": "int",
            "confidence": 0.60,
            "source_provenance_class": 2,
            "source_descriptor": "msa-a",
            "source_commitment": "cc" * 32,
            "status": "active",
            "contradiction_ids": [],
            "valid_from": None,
            "valid_to": None,
            "version": 1,
            "predecessor_id": None,
            "created_at": ts,
        }
        clm["content_hash"] = compute_claim_content_hash(clm).hex()
        ws2 = {
            "write_domain": "acta:write_event:v1",
            "operation": "ingest_claim",
            "item_id": clm["id"],
            "scope": scope,
            "version": 1,
            "content_hash": clm["content_hash"],
            "written_by": f"{tenant}::oauth:{tenant}",
            "writer_auth_kind": "oauth_github_principal",
            "record_snapshot": clm,
        }
        ws2_comm = compute_write_summary_commitment(ws2).hex()
        ev2_hash = compute_evidence_event_hash(
            tenant, 2, ev1_hash, None, ws2_comm, "allow", ts, write_summary=ws2
        ).hex()
        entry2 = {
            "tenant_id": tenant,
            "seq_num": 2,
            "event_domain": "acta:evidence_event:v3",
            "prev_hash": ev1_hash,
            "event_hash": ev2_hash,
            "bundle_hash": None,
            "state_commitment": ws2_comm,
            "policy_result": "allow",
            "write_summary": ws2,
            "host_signature": sign_evidence_entry(host_seed, tenant, 2, ev1_hash, ev2_hash).hex(),
            "created_at": ts,
        }

        # Entry 3: Chained AnswerCacheLedgerSummary invalidation receipt
        acs_inv = {
            "cache_domain": "acta:answer_cache:v1",
            "event_kind": "invalidated",
            "cache_id": "33333333-3333-4333-8333-333333333333",
            "scope": scope,
            "task_id": "po-check",
            "query_hash": compute_query_text_hash("lead_days?").hex(),
            "source_bundle_hash": "dd" * 32,
            "state_commitment": "ee" * 32,
            "validity_mode": "dependency_subset",
            "task_dependency_commitment": dep_a.hex(),
            "answer_hash": compute_answer_text_hash("14 days").hex(),
            "cached_by": f"{tenant}::oauth:{tenant}",
            "cacher_auth_kind": "oauth_github_principal",
            "invalidation_reason": "stale_dependency_commitment",
            "observed_state_commitment": "ff" * 32,
            "observed_dependency_commitment": dep_b.hex(),
        }
        acs_comm = compute_answer_cache_summary_commitment(acs_inv).hex()
        ev3_hash = compute_evidence_event_hash(
            tenant, 3, ev2_hash, None, acs_comm, "allow", ts, answer_cache_summary=acs_inv
        ).hex()
        entry3 = {
            "tenant_id": tenant,
            "seq_num": 3,
            "event_domain": "acta:evidence_event:v3",
            "prev_hash": ev2_hash,
            "event_hash": ev3_hash,
            "bundle_hash": None,
            "state_commitment": acs_comm,
            "policy_result": "allow",
            "answer_cache_summary": acs_inv,
            "host_signature": sign_evidence_entry(host_seed, tenant, 3, ev2_hash, ev3_hash).hex(),
            "created_at": ts,
        }
        verify_evidence_entry(entry3, host_pk_hex)

        # Invalidated event missing observed_state_commitment must fail verification
        bad_inv = json.loads(json.dumps(entry3))
        del bad_inv["answer_cache_summary"]["observed_state_commitment"]
        with self.assertRaises(ValueError):
            verify_evidence_entry(bad_inv, host_pk_hex)

        leaves_all = [
            merkle_leaf_hash(1, ev1_hash),
            merkle_leaf_hash(2, ev2_hash),
            merkle_leaf_hash(3, ev3_hash),
        ]
        mroot_2 = compute_merkle_root_from_leaves(leaves_all[:2]).hex()
        mroot_3 = compute_merkle_root_from_leaves(leaves_all).hex()
        cp2_hash = compute_checkpoint_hash(tenant, 2, ev2_hash, mroot_2, ts).hex()
        cp3_hash = compute_checkpoint_hash(tenant, 3, ev3_hash, mroot_3, ts).hex()
        wsig2, wpk = sign_witness_anchor(wit_seed, tenant, 2, cp2_hash)
        cons_2_to_3 = [h.hex() for h in compute_merkle_consistency_proof(leaves_all, 2, 3)]

        rebuild_archive = {
            "schema_version": STATE_REBUILD_ARCHIVE_SCHEMA_V1,
            "tenant_id": tenant,
            "scope": scope,
            "up_to_seq": 3,
            "evaluated_at": ts,
            "host_public_key": host_pk_hex,
            "permission_root": perm_root,
            "override_attestations": [],
            "evidence_chain": [entry1, entry2, entry3],
            "checkpoint": {
                "tenant_id": tenant,
                "tree_size": 3,
                "head_event_hash": ev3_hash,
                "merkle_root": mroot_3,
                "issued_at": ts,
                "checkpoint_hash": cp3_hash,
                "host_signature": sign_checkpoint_head(host_seed, tenant, cp3_hash).hex(),
                "witness_anchors": [],
            },
            "latest_anchored_checkpoint": {
                "tenant_id": tenant,
                "tree_size": 2,
                "head_event_hash": ev2_hash,
                "merkle_root": mroot_2,
                "issued_at": ts,
                "checkpoint_hash": cp2_hash,
                "host_signature": sign_checkpoint_head(host_seed, tenant, cp2_hash).hex(),
                "witness_anchors": [
                    {
                        "id": "44444444-4444-4444-8444-444444444444",
                        "tenant_id": tenant,
                        "tree_size": 2,
                        "checkpoint_hash": cp2_hash,
                        "witness_id": "claude-witness-v171",
                        "witness_public_key": wpk,
                        "witness_signature": wsig2,
                        "anchored_at": ts,
                    }
                ],
            },
            "consistency_proof_from_latest_anchor": cons_2_to_3,
        }

        rebuilt = verify_and_rebuild_scope_state_offline(rebuild_archive, host_pk_hex)
        expected_sc = compute_state_commitment(
            SCHEMA_VERSION,
            tenant,
            scope,
            compute_sub_commitment([obj["content_hash"]]),
            compute_sub_commitment([clm["content_hash"]]),
            compute_sub_commitment([]),
            perm_root,
        ).hex()
        self.assertEqual(rebuilt.reconstructed_state_commitment_hex, expected_sc)
        self.assertEqual(rebuilt.reconstructed_active_intents, 1)
        self.assertEqual(rebuilt.reconstructed_active_claims, 1)
        self.assertEqual(rebuilt.anchored_tree_size, 2)
        self.assertEqual(rebuilt.verified_witness_anchors, 1)

        # Tampering snapshot inside write_summary must fail offline state rebuild
        tampered = json.loads(json.dumps(rebuild_archive))
        tampered["evidence_chain"][1]["write_summary"]["record_snapshot"]["object_val"] = 999
        with self.assertRaises(ValueError):
            verify_and_rebuild_scope_state_offline(tampered, host_pk_hex)
