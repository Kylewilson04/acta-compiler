"""Comprehensive cryptographic & live-mock HTTP test suite for `acta_sdk` v1.5.0."""

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
    AsyncActaClient,
    compute_bundle_hash,
    compute_claim_content_hash,
    compute_claim_group_key,
    compute_evidence_event_hash,
    compute_logical_claim_group_key,
    compute_object_content_hash,
    compute_omission_list_hash,
    compute_override_attestation_hash,
    compute_refusal_metadata_commitment,
    sign_evidence_entry,
    sign_override_attestation,
    to_canonical_json,
    verify_ed25519_strict,
    verify_export_archive,
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

    def test_v15_epistemic_notary_manifest_refusal_and_override_verification(self) -> None:
        seed = b"\x42" * 32
        pk_hex, base_archive = _build_signed_fixture(seed=seed, disputed=True)
        ts1 = "2026-11-22T04:10:00.000000Z"
        ts2 = "2026-11-22T04:10:05.000000Z"
        ts3 = "2026-11-22T04:10:10.000000Z"
        tenant = base_archive["bundle"]["tenant_id"]
        scope = base_archive["bundle"]["scope"]
        claim1, claim2 = base_archive["claims"][0], base_archive["claims"][1]
        logical_group = compute_logical_claim_group_key(
            tenant, claim1["subject"], claim1["predicate"], scope
        ).hex()

        # Seq 1: v2 Refusal entry with readable RefusalMetadata
        rmeta = {
            "operation": "ingest_claim",
            "reason_code": "POLICY_ESCALATE",
            "target_scope": "restricted/signing-keys",
            "summary": "Restricted scope requires supervisor escalation approval",
        }
        rcomm = compute_refusal_metadata_commitment(rmeta).hex()
        zero_prev = "00" * 32
        ev1_hash = compute_evidence_event_hash(
            tenant,
            1,
            zero_prev,
            None,
            rcomm,
            "escalate",
            ts1,
            refusal_metadata=rmeta,
        ).hex()
        ev1 = {
            "tenant_id": tenant,
            "seq_num": 1,
            "prev_hash": zero_prev,
            "event_hash": ev1_hash,
            "bundle_hash": None,
            "state_commitment": rcomm,
            "policy_result": "escalate",
            "refusal_metadata": rmeta,
            "host_signature": sign_evidence_entry(seed, tenant, 1, zero_prev, ev1_hash).hex(),
            "created_at": ts1,
        }

        # Seq 2: Signed OverrideAttestation adjudicating claim2 (240 bps contract) over claim1 (290 bps)
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
            "overridden_claims": [
                {"id": claim1["id"], "content_hash": claim1["content_hash"]}
            ],
            "adjudicator_id": f"{tenant}::kyle-cfo",
            "justification": "Signed MSA addendum §4.2 supersedes legacy ledger rate",
            "version": 1,
            "predecessor_id": None,
            "created_at": ts2,
            "attestation_hash": "",
            "evidence_seq_num": 2,
            "host_signature": "",
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
            tenant,
            2,
            ev1_hash,
            None,
            att["attestation_hash"],
            "allow",
            ts2,
            override_summary=osummary,
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

        # Seq 3: Compiled bundle with ResolverManifest (custom 0.05 threshold flagged) + override resolution
        win_cand = base_archive["bundle"]["dispute_records"][0]["competing_claims"][1]
        bundle_v15 = copy.deepcopy(base_archive["bundle"])
        bundle_v15["resolver_manifest"] = {
            "min_confidence": 0.70,
            "decisiveness_threshold": 0.05,
            "corroboration_damping": 0.50,
            "non_default_thresholds": True,
            "budget": {"kind": "tokens", "limit": 2048},
            "permission_root": "ab" * 32,
        }
        bundle_v15["dispute_records"] = []
        bundle_v15["omission_record"]["has_unresolved_claims"] = False
        bundle_v15["resolution_records"] = [
            {
                "claim_group_key": logical_group,
                "winning_claim": win_cand,
                "margin": None,
                "suppressed_claim_ids": [claim1["id"]],
                "override_attestation": {
                    "attestation_id": att_id,
                    "attestation_hash": att["attestation_hash"],
                    "adjudicator_id": att["adjudicator_id"],
                    "justification": att["justification"],
                    "source_bundle_hash": base_archive["bundle_hash"],
                    "evidence_seq_num": 2,
                    "version": 1,
                    "attested_at": ts2,
                },
            }
        ]
        b_hash_v15, _ = compute_bundle_hash(bundle_v15)
        b_hex_v15 = b_hash_v15.hex()

        ev3_hash = compute_evidence_event_hash(
            tenant,
            3,
            ev2_hash,
            b_hex_v15,
            bundle_v15["state_commitment"],
            "allow",
            ts3,
        ).hex()
        ev3 = {
            "tenant_id": tenant,
            "seq_num": 3,
            "prev_hash": ev2_hash,
            "event_hash": ev3_hash,
            "bundle_hash": b_hex_v15,
            "state_commitment": bundle_v15["state_commitment"],
            "policy_result": "allow",
            "host_signature": sign_evidence_entry(seed, tenant, 3, ev2_hash, ev3_hash).hex(),
            "created_at": ts3,
        }

        archive_v15 = {
            "bundle_hash": b_hex_v15,
            "bundle": bundle_v15,
            "objects": base_archive["objects"],
            "claims": base_archive["claims"],
            "override_attestations": [att],
            "evidence_chain": [ev1, ev2, ev3],
            "host_public_key": pk_hex,
        }

        summary = verify_export_archive(archive_v15, pk_hex)
        self.assertEqual(summary.verified_overrides, 1)
        self.assertEqual(summary.verified_refusals, 1)
        self.assertEqual(summary.verified_evidence_entries, 3)
        self.assertTrue(summary.non_default_thresholds)

        # Stripping refusal_metadata must fail v2 event_hash verification!
        stripped_refusal = copy.deepcopy(archive_v15)
        del stripped_refusal["evidence_chain"][0]["refusal_metadata"]
        with self.assertRaisesRegex(ValueError, "tampered evidence entry at seq_num=1"):
            verify_export_archive(stripped_refusal, pk_hex)

        # Lying about non_default_thresholds=False on a 0.05 threshold must fail!
        lied_manifest = copy.deepcopy(archive_v15)
        lied_manifest["bundle"]["resolver_manifest"]["non_default_thresholds"] = False
        with self.assertRaisesRegex(ValueError, "inconsistent resolver_manifest"):
            verify_export_archive(lied_manifest, pk_hex)

        # Tampering justification on override_attestation must fail!
        forged_att = copy.deepcopy(archive_v15)
        forged_att["override_attestations"][0]["justification"] = "Forged justification"
        with self.assertRaisesRegex(ValueError, "tampered override_attestation"):
            verify_export_archive(forged_att, pk_hex)

    def test_offline_archive_verification_and_tamper_rejection(self) -> None:
        pk_hex, archive = _build_signed_fixture()
        summary = verify_export_archive(archive, pk_hex)
        self.assertEqual(summary.tenant_id, "sandbox-live")
        self.assertEqual(summary.verified_objects, 1)
        self.assertEqual(summary.verified_claims, 2)
        self.assertEqual(summary.verified_evidence_entries, 1)

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
                    "version": "1.5.0",
                    "host_public_key": self.pk_hex,
                    "permission_root": "26" * 32,
                },
            )
            return
        if self.path.startswith("/v1/bundles/") and self.path.endswith("/export"):
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
                    "adjudicator_id": body["adjudicator_id"],
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
                adjudicator_id="prod-acme::cfo",
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


class TestActaV11TenantTokens(unittest.TestCase):
    def test_stateless_keyed_blake3_tenant_tokens_and_client_lock(self) -> None:
        from acta_sdk import (
            ActaTenantLockError,
            mint_tenant_api_key,
            verify_tenant_api_key,
        )

        master = "acta_live_master_secret_998877"
        tk_ardyn = mint_tenant_api_key(master, "ardyn-core")
        tk_acme = mint_tenant_api_key(master, "client-acme")
        self.assertTrue(tk_ardyn.startswith("acta_tk_v1:ardyn-core:"))
        self.assertNotEqual(tk_ardyn, tk_acme)
        self.assertEqual(verify_tenant_api_key(master, tk_ardyn), "ardyn-core")
        self.assertEqual(verify_tenant_api_key(master, tk_acme), "client-acme")

        mac_only = tk_ardyn.rsplit(":", 1)[1]
        with self.assertRaises(ValueError):
            verify_tenant_api_key(master, f"acta_tk_v1:client-acme:{mac_only}")

        with ActaClient("http://127.0.0.1:9", api_key=tk_acme) as locked_client:
            self.assertEqual(locked_client.locked_tenant, "client-acme")
            with self.assertRaises(ActaTenantLockError):
                locked_client.compile(
                    tenant_id="ardyn-core",
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

            repo_b = pathlib.Path(tmp) / "client-portal"
            repo_b.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo_b, check=True)
            subprocess.run(
                ["git", "remote", "add", "origin", "https://github.com/Acme-Corp/Billing_V2.git"],
                cwd=repo_b,
                check=True,
            )
            r_b = resolve_git_workspace_context(repo_b)
            self.assertEqual(r_b.tenant_id, "acme-corp")
            self.assertEqual(r_b.default_scope, "billing_v2")

            (repo_b / ".acta.json").write_text(
                '{"tenant": "client-custom", "default_scope": "settlements"}',
                encoding="utf-8",
            )
            r_override = resolve_git_workspace_context(repo_b)
            self.assertEqual(r_override.tenant_id, "client-custom")
            self.assertEqual(r_override.default_scope, "settlements")

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
                        lines[1]["result"]["structuredContent"]["tenant_id"], "sandbox-ardyn"
                    )
                    self.assertEqual(
                        lines[1]["result"]["structuredContent"]["default_scope"], "ads-core"
                    )
                    self.assertFalse(lines[2]["result"]["isError"])
                    self.assertTrue(
                        lines[2]["result"]["structuredContent"]["ed25519_verified_locally"]
                    )
                    self.assertTrue(lines[3]["result"]["isError"])
                finally:
                    bridge.close()
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
