"""Acta Compiler v1.6.0 Cryptographic Primitives, RFC 6962 Merkle Verifier & Epistemic Notary.

Bit-for-bit compatible with Rust `acta-crypto`:
- RFC 8785 JSON Canonicalization Scheme (JCS) (`serde_jcs`)
- 8-byte little-endian length-delimited BLAKE3 hashing (Invariant 5)
- `ResolverManifest` threshold & policy root verification inside `ContextBundle`
- Strip/tamper-proof `RefusalMetadata` (`b"acta:refusal_meta:v2"`) & `b"acta:evidence_event:v2"`
- Signed `OverrideAttestation` (`b"acta:override:v1"`, `b"acta:override_sig:v1"`, `b"acta:override_client_sig:v1"`)
  and `LapsedOverrideRef` provenance verification on re-escalated disputes
- Principal-bound OAuth 2.1 tokens (`acta_tk_v1:<tenant>:<github_login>:<mac>`, `b"acta:tenant_user_token:v2"`)
- RFC 6962 Merkle `SignedTreeHead` checkpoints (`b"acta:checkpoint:v1"`, `b"acta:checkpoint_sig:v1"`),
  `O(log N)` inclusion & consistency proofs, external witness cosignatures (`b"acta:witness_sig:v1"`),
  and `--dump-preimages` digest inspection
- Strict Ed25519 signature verification rejecting all 8 torsion low-order keys
  and non-canonical `S >= L` signature scalars (`ed25519_dalek::verify_strict`).
"""

from __future__ import annotations

import datetime
import hmac as _hmac
import math
import struct
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .blake3_pure import blake3_hash, blake3_keyed_hash

ED25519_L = (1 << 252) + 27742317777372353535851937790883648493

DEFAULT_MIN_CONFIDENCE = 0.70
DEFAULT_DECISIVENESS_THRESHOLD = 0.15
DEFAULT_CORROBORATION_DAMPING = 0.50

_WEAK_ED25519_PUBKEYS: frozenset[bytes] = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )
)

_UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _ed25519_pubkey_raw(vk: Ed25519PublicKey) -> bytes:
    return vk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _utf16_sort_key(s: str) -> bytes:
    return s.encode("utf-16-be")


def _format_jcs_string(s: str) -> str:
    out: list[str] = ['"']
    for ch in s:
        code = ord(ch)
        if code == 0x22:
            out.append('\\"')
        elif code == 0x5C:
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0D:
            out.append("\\r")
        elif code == 0x09:
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _format_jcs_float(v: float) -> str:
    if not math.isfinite(v):
        raise ValueError("RFC 8785 JCS forbids NaN and Infinity")
    if v == 0.0:
        return "0"

    sign = "-" if v < 0 else ""
    s = repr(abs(v))
    if "e" in s or "E" in s:
        mant, exp_str = s.lower().split("e")
        digits = mant.replace(".", "")
        n = int(exp_str) + 1
    else:
        if "." in s:
            int_part, frac_part = s.split(".")
            if int_part == "0":
                stripped = frac_part.lstrip("0")
                zeros = len(frac_part) - len(stripped)
                digits = stripped
                n = -zeros
            else:
                digits = int_part + frac_part
                n = len(int_part)
        else:
            digits = s
            n = len(s)

    digits = digits.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return f"{sign}{digits}{'0' * (n - k)}"
    if 0 < n <= 21:
        return f"{sign}{digits[:n]}.{digits[n:]}"
    if -6 < n <= 0:
        return f"{sign}0.{'0' * (-n)}{digits}"

    exp = n - 1
    exp_sign = "+" if exp >= 0 else "-"
    if k == 1:
        return f"{sign}{digits}e{exp_sign}{abs(exp)}"
    return f"{sign}{digits[0]}.{digits[1:]}e{exp_sign}{abs(exp)}"


def to_canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _format_jcs_float(value)
    if isinstance(value, str):
        return _format_jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(to_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(
            ((str(k), v) for k, v in value.items()),
            key=lambda kv: _utf16_sort_key(kv[0]),
        )
        return (
            "{"
            + ",".join(
                f"{_format_jcs_string(k)}:{to_canonical_json(v)}" for k, v in items
            )
            + "}"
        )
    raise TypeError(f"Unsupported type for RFC 8785 JCS canonicalization: {type(value)!r}")


def to_canonical_bytes(value: Any) -> bytes:
    return to_canonical_json(value).encode("utf-8")


def hash_length_delimited(parts: Sequence[bytes]) -> bytes:
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(struct.pack("<Q", len(part)))
        chunks.append(part)
    return blake3_hash(chunks)


def parse_rfc3339_micros(ts: str | datetime.datetime) -> int:
    if isinstance(ts, datetime.datetime):
        dt = ts.astimezone(datetime.timezone.utc) if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    else:
        norm = ts.strip()
        if norm.endswith("Z") or norm.endswith("z"):
            norm = norm[:-1] + "+00:00"
        if "." in norm:
            head, rest = norm.split(".", 1)
            tz_idx = max(rest.find("+"), rest.find("-"))
            if tz_idx != -1:
                frac, tz_part = rest[:tz_idx], rest[tz_idx:]
            else:
                frac, tz_part = rest, ""
            frac = (frac + "000000")[:6]
            norm = f"{head}.{frac}{tz_part}"
        dt = datetime.datetime.fromisoformat(norm).astimezone(datetime.timezone.utc)

    delta = dt - _UNIX_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _encode_opt_uuid(u: str | uuid.UUID | None) -> bytes:
    if u is None:
        return b"\x00" * 17
    uid = u if isinstance(u, uuid.UUID) else uuid.UUID(str(u))
    return b"\x01" + uid.bytes


def _encode_opt_i64(val: int | None) -> bytes:
    if val is None:
        return b"\x00" * 9
    return b"\x01" + struct.pack("<q", val)


def _encode_opt_hash32(h: bytes | str | None) -> bytes:
    if h is None:
        return b"\x00" * 33
    raw = bytes.fromhex(h) if isinstance(h, str) else bytes(h)
    if len(raw) != 32:
        raise ValueError("expected 32-byte hash")
    return b"\x01" + raw


def _encode_opt_jcs(val: Any | None) -> bytes:
    if val is None:
        return b"\x00"
    return b"\x01" + to_canonical_bytes(val)


def _as_hash32(h: bytes | str) -> bytes:
    raw = bytes.fromhex(h.strip()) if isinstance(h, str) else bytes(h)
    if len(raw) != 32:
        raise ValueError("expected 32-byte hash")
    return raw


def _normalize_refusal_metadata(meta: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "operation": str(meta["operation"]),
        "reason_code": str(meta["reason_code"]),
        "summary": str(meta["summary"]),
    }
    if meta.get("target_scope") is not None:
        out["target_scope"] = str(meta["target_scope"])
    if meta.get("scope_state_commitment") is not None:
        sc = meta["scope_state_commitment"]
        out["scope_state_commitment"] = _as_hash32(sc).hex()
    return out


def _normalize_override_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "attestation_id": str(uuid.UUID(str(summary["attestation_id"]))).lower(),
        "scope": str(summary["scope"]),
        "subject": str(summary["subject"]),
        "predicate": str(summary["predicate"]),
        "winning_claim_id": str(uuid.UUID(str(summary["winning_claim_id"]))).lower(),
        "overridden_count": int(summary["overridden_count"]),
        "adjudicator_id": str(summary["adjudicator_id"]),
        "version": int(summary["version"]),
    }


def _f32_bits_le(val: float) -> bytes:
    return struct.pack("<f", float(val))


def _f64_bits_le(val: float) -> bytes:
    return struct.pack("<d", float(val))


def compute_claim_group_key(
    tenant: str,
    subject: str,
    predicate: str,
    object_type: str,
    scope: str,
) -> bytes:
    return hash_length_delimited(
        [
            tenant.encode("utf-8"),
            subject.encode("utf-8"),
            predicate.encode("utf-8"),
            object_type.encode("utf-8"),
            scope.encode("utf-8"),
        ]
    )


def compute_logical_claim_group_key(
    tenant: str,
    subject: str,
    predicate: str,
    scope: str,
) -> bytes:
    return hash_length_delimited(
        [
            b"acta:claim_group:v2",
            tenant.encode("utf-8"),
            subject.encode("utf-8"),
            predicate.encode("utf-8"),
            scope.encode("utf-8"),
        ]
    )


def compute_refusal_metadata_commitment(meta: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_refusal_metadata(meta))
    return hash_length_delimited([b"acta:refusal_meta:v2", canonical])


def compute_object_content_hash(obj: Mapping[str, Any]) -> bytes:
    uid = uuid.UUID(str(obj["id"]))
    canonical_tags = to_canonical_bytes(list(obj.get("tags", [])))
    canonical_body = to_canonical_bytes(obj["body"])
    priority_le = struct.pack("<i", int(obj["priority"]))
    importance_le = _f32_bits_le(float(obj["importance"]))
    version_le = struct.pack("<i", int(obj["version"]))
    pred_bytes = _encode_opt_uuid(obj.get("predecessor_id"))
    created_micros_le = struct.pack("<q", parse_rfc3339_micros(obj["created_at"]))

    return hash_length_delimited(
        [
            b"acta:object:v1",
            uid.bytes,
            str(obj["tenant_id"]).encode("utf-8"),
            str(obj["obj_type"]).encode("utf-8"),
            str(obj["scope"]).encode("utf-8"),
            str(obj["lifecycle_status"]).encode("utf-8"),
            priority_le,
            importance_le,
            canonical_tags,
            canonical_body,
            version_le,
            pred_bytes,
            created_micros_le,
        ]
    )


def compute_claim_content_hash(claim: Mapping[str, Any]) -> bytes:
    uid = uuid.UUID(str(claim["id"]))
    group_key = _as_hash32(claim["claim_group_key"])
    source_comm = _as_hash32(claim["source_commitment"])
    canonical_val = to_canonical_bytes(claim["object_val"])
    sorted_contradictions = sorted(
        (uuid.UUID(str(cid)) for cid in claim.get("contradiction_ids", [])),
        key=lambda u: u.bytes,
    )
    canonical_contradictions = to_canonical_bytes([str(u) for u in sorted_contradictions])

    conf_le = _f64_bits_le(float(claim["confidence"]))
    prov_le = struct.pack("<i", int(claim["source_provenance_class"]))
    valid_from = claim.get("valid_from")
    valid_to = claim.get("valid_to")
    vf_bytes = _encode_opt_i64(parse_rfc3339_micros(valid_from) if valid_from is not None else None)
    vt_bytes = _encode_opt_i64(parse_rfc3339_micros(valid_to) if valid_to is not None else None)
    version_le = struct.pack("<i", int(claim["version"]))
    pred_bytes = _encode_opt_uuid(claim.get("predecessor_id"))
    created_micros_le = struct.pack("<q", parse_rfc3339_micros(claim["created_at"]))

    return hash_length_delimited(
        [
            b"acta:claim:v1",
            uid.bytes,
            str(claim["tenant_id"]).encode("utf-8"),
            group_key,
            str(claim["scope"]).encode("utf-8"),
            str(claim["subject"]).encode("utf-8"),
            str(claim["predicate"]).encode("utf-8"),
            canonical_val,
            str(claim["object_type"]).encode("utf-8"),
            conf_le,
            prov_le,
            str(claim["source_descriptor"]).encode("utf-8"),
            source_comm,
            str(claim["status"]).encode("utf-8"),
            canonical_contradictions,
            vf_bytes,
            vt_bytes,
            version_le,
            pred_bytes,
            created_micros_le,
        ]
    )


def compute_override_client_intent_hash(
    tenant_id: str,
    scope: str,
    winning_claim_id: str | uuid.UUID,
    adjudicator_id: str,
    justification: str,
) -> bytes:
    """Clock-free client-intent digest (`b"acta:override_client_sig:v1"`) for offline human/committee Ed25519 keys."""
    winning_uid = (
        winning_claim_id
        if isinstance(winning_claim_id, uuid.UUID)
        else uuid.UUID(str(winning_claim_id))
    )
    t_clean = tenant_id.strip()
    adj_clean = adjudicator_id.strip()
    eff_actor = adj_clean if "::" in adj_clean else f"{t_clean}::{adj_clean}"
    return hash_length_delimited(
        [
            b"acta:override_client_sig:v1",
            t_clean.encode("utf-8"),
            scope.strip().encode("utf-8"),
            winning_uid.bytes,
            eff_actor.encode("utf-8"),
            justification.strip().encode("utf-8"),
        ]
    )


def sign_override_client_intent(
    private_key_seed: bytes | str,
    *,
    tenant_id: str,
    scope: str,
    winning_claim_id: str | uuid.UUID,
    adjudicator_id: str,
    justification: str,
) -> tuple[str, str]:
    """Signs an offline human/committee override intent and returns `(client_signature_hex, client_public_key_hex)`."""
    digest = compute_override_client_intent_hash(
        tenant_id, scope, winning_claim_id, adjudicator_id, justification
    )
    return sign_client_content_hash(private_key_seed, digest)


def compute_override_attestation_hash(att: Mapping[str, Any]) -> bytes:
    att_id = uuid.UUID(str(att["id"]))
    winning_id = uuid.UUID(str(att["winning_claim_id"]))
    group_key = _as_hash32(att["claim_group_key"])
    winning_hash = _as_hash32(att["winning_claim_content_hash"])

    overridden_norm = []
    for item in att.get("overridden_claims", []):
        oid = uuid.UUID(str(item["id"]))
        ohash = _as_hash32(item["content_hash"])
        overridden_norm.append((oid.bytes, ohash, {"id": str(oid).lower(), "content_hash": ohash.hex()}))
    overridden_norm.sort(key=lambda tup: (tup[0], tup[1]))
    canonical_overridden = to_canonical_bytes([tup[2] for tup in overridden_norm])

    src_bundle_bytes = _encode_opt_hash32(att.get("source_bundle_hash"))
    version_le = struct.pack("<i", int(att["version"]))
    pred_bytes = _encode_opt_uuid(att.get("predecessor_id"))
    created_micros_le = struct.pack("<q", parse_rfc3339_micros(att["created_at"]))

    return hash_length_delimited(
        [
            b"acta:override:v1",
            att_id.bytes,
            str(att["tenant_id"]).encode("utf-8"),
            str(att["scope"]).encode("utf-8"),
            group_key,
            str(att["subject"]).encode("utf-8"),
            str(att["predicate"]).encode("utf-8"),
            src_bundle_bytes,
            winning_id.bytes,
            winning_hash,
            canonical_overridden,
            str(att["adjudicator_id"]).encode("utf-8"),
            str(att["justification"]).encode("utf-8"),
            version_le,
            pred_bytes,
            created_micros_le,
        ]
    )


def compute_omission_list_hash(sorted_items: Sequence[Mapping[str, Any]]) -> bytes:
    parts: list[bytes] = [b"acta:omissions:v1"]
    for item in sorted_items:
        uid_str = str(uuid.UUID(str(item["id"]))).lower()
        reason_str = str(item["reason"])
        parts.append(f'{{"id":"{uid_str}","reason":"{reason_str}"}}'.encode("utf-8"))
    return hash_length_delimited(parts)


def compute_bundle_hash(bundle: Mapping[str, Any]) -> tuple[bytes, bytes]:
    canonical = to_canonical_bytes(bundle)
    digest = hash_length_delimited([b"acta:bundle:v1", canonical])
    return digest, canonical


def compute_evidence_event_hash(
    tenant_id: str,
    seq_num: int,
    prev_hash: bytes | str,
    bundle_hash: bytes | str | None,
    state_commitment: bytes | str | None,
    policy_result: str,
    created_at: int | str | datetime.datetime,
    *,
    refusal_metadata: Mapping[str, Any] | None = None,
    override_summary: Mapping[str, Any] | None = None,
) -> bytes:
    prev_raw = _as_hash32(prev_hash)
    created_micros = (
        created_at if isinstance(created_at, int) else parse_rfc3339_micros(created_at)
    )
    if refusal_metadata is None and override_summary is None:
        return hash_length_delimited(
            [
                b"acta:evidence_event:v1",
                tenant_id.encode("utf-8"),
                struct.pack("<q", int(seq_num)),
                prev_raw,
                _encode_opt_hash32(bundle_hash),
                _encode_opt_hash32(state_commitment),
                policy_result.encode("utf-8"),
                struct.pack("<q", created_micros),
            ]
        )

    refusal_tagged = _encode_opt_jcs(
        _normalize_refusal_metadata(refusal_metadata) if refusal_metadata is not None else None
    )
    override_tagged = _encode_opt_jcs(
        _normalize_override_summary(override_summary) if override_summary is not None else None
    )
    return hash_length_delimited(
        [
            b"acta:evidence_event:v2",
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(seq_num)),
            prev_raw,
            _encode_opt_hash32(bundle_hash),
            _encode_opt_hash32(state_commitment),
            policy_result.encode("utf-8"),
            struct.pack("<q", created_micros),
            refusal_tagged,
            override_tagged,
        ]
    )


# ==============================================================================
# Acta v1.6 RFC 6962 Binary Merkle Tree, Checkpoints & External Witness Anchors
# ==============================================================================
def merkle_empty_root() -> bytes:
    return hash_length_delimited([b"acta:merkle_empty:v1"])


def merkle_leaf_hash(seq_num: int, event_hash: bytes | str) -> bytes:
    ev_raw = _as_hash32(event_hash)
    return hash_length_delimited(
        [b"acta:merkle_leaf:v1", struct.pack("<q", int(seq_num)), ev_raw]
    )


def merkle_node_hash(left: bytes | str, right: bytes | str) -> bytes:
    return hash_length_delimited(
        [b"acta:merkle_node:v1", _as_hash32(left), _as_hash32(right)]
    )


def _largest_pow2_lt(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def compute_merkle_root_from_leaves(leaves: Sequence[bytes | str]) -> bytes:
    norm = [_as_hash32(x) for x in leaves]
    n = len(norm)
    if n == 0:
        return merkle_empty_root()
    if n == 1:
        return norm[0]
    k = _largest_pow2_lt(n)
    left = compute_merkle_root_from_leaves(norm[:k])
    right = compute_merkle_root_from_leaves(norm[k:])
    return merkle_node_hash(left, right)


def _inclusion_path_slice(leaves: list[bytes], index: int, out: list[bytes]) -> None:
    n = len(leaves)
    if n <= 1:
        return
    k = _largest_pow2_lt(n)
    if index < k:
        _inclusion_path_slice(leaves[:k], index, out)
        out.append(compute_merkle_root_from_leaves(leaves[k:]))
    else:
        _inclusion_path_slice(leaves[k:], index - k, out)
        out.append(compute_merkle_root_from_leaves(leaves[:k]))


def compute_merkle_inclusion_proof(
    leaves: Sequence[bytes | str],
    leaf_index: int,
) -> list[bytes]:
    norm = [_as_hash32(x) for x in leaves]
    if not norm or leaf_index < 0 or leaf_index >= len(norm):
        raise ValueError(f"leaf_index {leaf_index} out of bounds for tree_size {len(norm)}")
    out: list[bytes] = []
    _inclusion_path_slice(norm, leaf_index, out)
    return out


def verify_merkle_inclusion_proof(
    seq_num: int,
    event_hash: bytes | str,
    tree_size: int,
    audit_path: Sequence[bytes | str],
    expected_root: bytes | str,
) -> bool:
    if seq_num < 1 or tree_size < 1 or seq_num > tree_size:
        return False
    r = merkle_leaf_hash(seq_num, event_hash)
    exp_raw = _as_hash32(expected_root)
    path_raw = [_as_hash32(node) for node in audit_path]
    if tree_size == 1:
        return len(path_raw) == 0 and r == exp_raw

    fn_idx = seq_num - 1
    sn = tree_size - 1
    for sibling in path_raw:
        if sn == 0:
            return False
        if (fn_idx & 1) == 1 or fn_idx == sn:
            r = merkle_node_hash(sibling, r)
            while (fn_idx & 1) == 0:
                fn_idx >>= 1
                sn >>= 1
        else:
            r = merkle_node_hash(r, sibling)
        fn_idx >>= 1
        sn >>= 1
    return sn == 0 and r == exp_raw


def _subproof_slice(
    m: int,
    leaves: list[bytes],
    is_complete_subtree: bool,
    out: list[bytes],
) -> None:
    n = len(leaves)
    if m == n:
        if not is_complete_subtree:
            out.append(compute_merkle_root_from_leaves(leaves))
        return
    k = _largest_pow2_lt(n)
    if m <= k:
        _subproof_slice(m, leaves[:k], is_complete_subtree, out)
        out.append(compute_merkle_root_from_leaves(leaves[k:]))
    else:
        _subproof_slice(m - k, leaves[k:], False, out)
        out.append(compute_merkle_root_from_leaves(leaves[:k]))


def compute_merkle_consistency_proof(
    leaves: Sequence[bytes | str],
    first_size: int,
    second_size: int,
) -> list[bytes]:
    norm = [_as_hash32(x) for x in leaves]
    if first_size < 1 or first_size > second_size or second_size > len(norm):
        raise ValueError(
            f"invalid consistency proof bounds: first={first_size}, second={second_size}, available={len(norm)}"
        )
    if first_size == second_size:
        return []
    out: list[bytes] = []
    _subproof_slice(first_size, norm[:second_size], True, out)
    return out


def verify_merkle_consistency_proof(
    first_size: int,
    first_root: bytes | str,
    second_size: int,
    second_root: bytes | str,
    proof: Sequence[bytes | str],
) -> bool:
    if first_size < 1 or second_size < first_size:
        return False
    f_raw = _as_hash32(first_root)
    s_raw = _as_hash32(second_root)
    p_raw = [_as_hash32(node) for node in proof]
    if first_size == second_size:
        return len(p_raw) == 0 and f_raw == s_raw
    if not p_raw:
        return False

    is_pow2 = (first_size & (first_size - 1)) == 0
    chain = ([f_raw] if is_pow2 else []) + p_raw

    fn_idx = first_size - 1
    sn = second_size - 1
    while (fn_idx & 1) == 1:
        fn_idx >>= 1
        sn >>= 1

    fr = chain[0]
    sr = chain[0]
    for node in chain[1:]:
        if sn == 0:
            return False
        if (fn_idx & 1) == 1 or fn_idx == sn:
            fr = merkle_node_hash(node, fr)
            sr = merkle_node_hash(node, sr)
            while (fn_idx & 1) == 0:
                fn_idx >>= 1
                sn >>= 1
        else:
            sr = merkle_node_hash(sr, node)
        fn_idx >>= 1
        sn >>= 1

    return sn == 0 and fr == f_raw and sr == s_raw


def compute_checkpoint_hash(
    tenant_id: str,
    tree_size: int,
    head_event_hash: bytes | str,
    merkle_root: bytes | str,
    issued_at: int | str | datetime.datetime,
) -> bytes:
    micros = issued_at if isinstance(issued_at, int) else parse_rfc3339_micros(issued_at)
    return hash_length_delimited(
        [
            b"acta:checkpoint:v1",
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(tree_size)),
            _as_hash32(head_event_hash),
            _as_hash32(merkle_root),
            struct.pack("<q", micros),
        ]
    )


def evidence_signing_preimage(
    tenant: str,
    seq_num: int,
    prev_hash: bytes | str,
    event_hash: bytes | str,
) -> bytes:
    prev_raw = _as_hash32(prev_hash)
    event_raw = _as_hash32(event_hash)
    return hash_length_delimited(
        [
            b"acta:evidence_sig:v1",
            tenant.encode("utf-8"),
            struct.pack("<q", int(seq_num)),
            prev_raw,
            event_raw,
        ]
    )


def override_signing_preimage(
    tenant: str,
    evidence_seq_num: int,
    attestation_hash: bytes | str,
) -> bytes:
    att_raw = _as_hash32(attestation_hash)
    return hash_length_delimited(
        [
            b"acta:override_sig:v1",
            tenant.encode("utf-8"),
            struct.pack("<q", int(evidence_seq_num)),
            att_raw,
        ]
    )


def checkpoint_signing_preimage(tenant: str, checkpoint_hash: bytes | str) -> bytes:
    return hash_length_delimited(
        [
            b"acta:checkpoint_sig:v1",
            tenant.encode("utf-8"),
            _as_hash32(checkpoint_hash),
        ]
    )


def witness_anchor_signing_preimage(
    tenant: str,
    tree_size: int,
    checkpoint_hash: bytes | str,
) -> bytes:
    return hash_length_delimited(
        [
            b"acta:witness_sig:v1",
            tenant.encode("utf-8"),
            struct.pack("<q", int(tree_size)),
            _as_hash32(checkpoint_hash),
        ]
    )


def is_weak_ed25519_pubkey(pubkey_bytes: bytes) -> bool:
    return len(pubkey_bytes) != 32 or pubkey_bytes in _WEAK_ED25519_PUBKEYS


def verify_ed25519_strict(pubkey_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    if len(pubkey_bytes) != 32 or len(signature_bytes) != 64:
        return False
    if is_weak_ed25519_pubkey(pubkey_bytes):
        return False
    s_scalar = int.from_bytes(signature_bytes[32:64], "little")
    if s_scalar >= ED25519_L:
        return False
    try:
        vk = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        vk.verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_evidence_signature(
    pubkey: bytes | str,
    tenant: str,
    seq_num: int,
    prev_hash: bytes | str,
    event_hash: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    digest = evidence_signing_preimage(tenant, seq_num, prev_hash, event_hash)
    return verify_ed25519_strict(pk_raw, digest, sig_raw)


def verify_override_signature(
    pubkey: bytes | str,
    tenant: str,
    evidence_seq_num: int,
    attestation_hash: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    digest = override_signing_preimage(tenant, evidence_seq_num, attestation_hash)
    return verify_ed25519_strict(pk_raw, digest, sig_raw)


def verify_checkpoint_signature(
    pubkey: bytes | str,
    tenant: str,
    checkpoint_hash: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    digest = checkpoint_signing_preimage(tenant, checkpoint_hash)
    return verify_ed25519_strict(pk_raw, digest, sig_raw)


def verify_witness_anchor_signature(
    witness_pubkey: bytes | str,
    tenant: str,
    tree_size: int,
    checkpoint_hash: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(witness_pubkey) if isinstance(witness_pubkey, str) else bytes(witness_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    digest = witness_anchor_signing_preimage(tenant, tree_size, checkpoint_hash)
    return verify_ed25519_strict(pk_raw, digest, sig_raw)


def verify_signed_tree_head(
    sth: Mapping[str, Any],
    expected_tenant: str,
    expected_pubkey: bytes | str,
) -> int:
    """Verifies a `SignedTreeHead` checkpoint and all attached external witness cosignatures."""
    if str(sth["tenant_id"]) != expected_tenant:
        raise ValueError(
            f"checkpoint tenant_id '{sth['tenant_id']}' != expected '{expected_tenant}'"
        )
    tree_size = int(sth["tree_size"])
    if tree_size < 1:
        raise ValueError(f"invalid checkpoint tree_size={tree_size}")

    recomputed_cp = compute_checkpoint_hash(
        str(sth["tenant_id"]),
        tree_size,
        sth["head_event_hash"],
        sth["merkle_root"],
        sth["issued_at"],
    )
    stored_cp_hex = str(sth["checkpoint_hash"]).lower()
    if recomputed_cp.hex() != stored_cp_hex:
        raise ValueError(
            f"tampered SignedTreeHead: recomputed checkpoint_hash {recomputed_cp.hex()} != stored {stored_cp_hex}"
        )
    if not verify_checkpoint_signature(
        expected_pubkey,
        str(sth["tenant_id"]),
        recomputed_cp,
        sth["host_signature"],
    ):
        raise ValueError("Ed25519 host_signature verification failed on SignedTreeHead")

    anchors = sth.get("witness_anchors") or []
    for anchor in anchors:
        if (
            str(anchor["tenant_id"]) != str(sth["tenant_id"])
            or int(anchor["tree_size"]) != tree_size
            or str(anchor["checkpoint_hash"]).lower() != stored_cp_hex
        ):
            raise ValueError(
                f"witness_anchor[id={anchor.get('id')}] metadata mismatch against SignedTreeHead"
            )
        if not verify_witness_anchor_signature(
            anchor["witness_public_key"],
            str(anchor["tenant_id"]),
            tree_size,
            recomputed_cp,
            anchor["witness_signature"],
        ):
            raise ValueError(
                f"Ed25519 witness_signature verification failed on witness_anchor[id={anchor.get('id')}, witness={anchor.get('witness_id')}]"
            )
    return len(anchors)


def verify_evidence_entry(entry: Mapping[str, Any], expected_pubkey: bytes | str) -> None:
    rmeta = entry.get("refusal_metadata")
    ometa = entry.get("override_summary")

    if rmeta is not None:
        if entry.get("bundle_hash") is not None:
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: refusal_metadata cannot coexist with bundle_hash"
            )
        expected_refusal_comm = compute_refusal_metadata_commitment(rmeta).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = (
            stored_sc.lower()
            if isinstance(stored_sc, str)
            else bytes(stored_sc).hex()
            if stored_sc is not None
            else None
        )
        if stored_sc_hex != expected_refusal_comm:
            raise ValueError(
                f"tampered refusal_metadata at seq_num={entry['seq_num']}: state_commitment mismatch"
            )

    recomputed_event = compute_evidence_event_hash(
        tenant_id=str(entry["tenant_id"]),
        seq_num=int(entry["seq_num"]),
        prev_hash=entry["prev_hash"],
        bundle_hash=entry.get("bundle_hash"),
        state_commitment=entry.get("state_commitment"),
        policy_result=str(entry["policy_result"]),
        created_at=entry["created_at"],
        refusal_metadata=rmeta,
        override_summary=ometa,
    )
    stored_event_hex = (
        entry["event_hash"].lower()
        if isinstance(entry["event_hash"], str)
        else bytes(entry["event_hash"]).hex()
    )
    if recomputed_event.hex() != stored_event_hex:
        raise ValueError(
            f"tampered evidence entry at seq_num={entry['seq_num']}: "
            f"recomputed event_hash {recomputed_event.hex()} != stored {stored_event_hex}"
        )
    if not verify_evidence_signature(
        expected_pubkey,
        str(entry["tenant_id"]),
        int(entry["seq_num"]),
        entry["prev_hash"],
        recomputed_event,
        entry["host_signature"],
    ):
        raise ValueError(
            f"Ed25519 host_signature verification failed at evidence seq_num={entry['seq_num']}"
        )


def sign_evidence_entry(
    private_key_seed: bytes | str,
    tenant: str,
    seq_num: int,
    prev_hash: bytes | str,
    event_hash: bytes | str,
) -> bytes:
    seed = (
        bytes.fromhex(private_key_seed)
        if isinstance(private_key_seed, str)
        else bytes(private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    digest = evidence_signing_preimage(tenant, seq_num, prev_hash, event_hash)
    return sk.sign(digest)


def sign_override_attestation(
    private_key_seed: bytes | str,
    tenant: str,
    evidence_seq_num: int,
    attestation_hash: bytes | str,
) -> bytes:
    seed = (
        bytes.fromhex(private_key_seed)
        if isinstance(private_key_seed, str)
        else bytes(private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    digest = override_signing_preimage(tenant, evidence_seq_num, attestation_hash)
    return sk.sign(digest)


def sign_checkpoint_head(
    private_key_seed: bytes | str,
    tenant: str,
    checkpoint_hash: bytes | str,
) -> bytes:
    seed = (
        bytes.fromhex(private_key_seed)
        if isinstance(private_key_seed, str)
        else bytes(private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    digest = checkpoint_signing_preimage(tenant, checkpoint_hash)
    return sk.sign(digest)


def sign_witness_anchor(
    witness_private_key_seed: bytes | str,
    tenant: str,
    tree_size: int,
    checkpoint_hash: bytes | str,
) -> tuple[str, str]:
    """Signs `(tenant, tree_size, checkpoint_hash)` (`b"acta:witness_sig:v1"`) and returns `(sig_hex, pubkey_hex)`."""
    seed = (
        bytes.fromhex(witness_private_key_seed)
        if isinstance(witness_private_key_seed, str)
        else bytes(witness_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_hex = _ed25519_pubkey_raw(sk.public_key()).hex()
    digest = witness_anchor_signing_preimage(tenant, tree_size, checkpoint_hash)
    return sk.sign(digest).hex(), pk_hex


def sign_client_content_hash(private_key_seed: bytes | str, content_hash: bytes | str) -> tuple[str, str]:
    seed = (
        bytes.fromhex(private_key_seed)
        if isinstance(private_key_seed, str)
        else bytes(private_key_seed)
    )
    digest = _as_hash32(content_hash)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_hex = _ed25519_pubkey_raw(sk.public_key()).hex()
    sig_hex = sk.sign(digest).hex()
    return sig_hex, pk_hex


def _expected_non_default_flag(rm: Mapping[str, Any]) -> bool:
    min_c = float(rm["min_confidence"])
    dec_t = float(rm["decisiveness_threshold"])
    damp = float(rm["corroboration_damping"])
    return (
        abs(min_c - DEFAULT_MIN_CONFIDENCE) > 1e-9
        or abs(dec_t - DEFAULT_DECISIVENESS_THRESHOLD) > 1e-9
        or abs(damp - DEFAULT_CORROBORATION_DAMPING) > 1e-9
    )


@dataclass(frozen=True)
class VerificationSummary:
    tenant_id: str
    bundle_hash_hex: str
    state_commitment_hex: str
    verified_objects: int
    verified_claims: int
    verified_evidence_entries: int
    verified_overrides: int = 0
    verified_refusals: int = 0
    non_default_thresholds: bool = False
    resolver_manifest: Mapping[str, Any] | None = None
    verification_mode: str = "full_chain"
    merkle_tree_size: int | None = None
    merkle_root_hex: str | None = None
    verified_witness_anchors: int = 0


def _verify_entry_inclusion(
    proof: Mapping[str, Any],
    sth: Mapping[str, Any],
    expected_pk: bytes,
) -> None:
    entry = proof["entry"]
    if str(entry["tenant_id"]) != str(sth["tenant_id"]):
        raise ValueError(
            f"evidence entry seq_num={entry['seq_num']} tenant_id '{entry['tenant_id']}' != checkpoint tenant_id '{sth['tenant_id']}'"
        )
    verify_evidence_entry(entry, expected_pk)
    seq_num = int(entry["seq_num"])
    tree_size = int(sth["tree_size"])
    if not verify_merkle_inclusion_proof(
        seq_num,
        entry["event_hash"],
        tree_size,
        proof.get("audit_path", []),
        sth["merkle_root"],
    ):
        raise ValueError(
            f"Merkle inclusion proof failed for seq_num={seq_num} against tree_size={tree_size} merkle_root={sth['merkle_root']}"
        )
    if (
        seq_num == tree_size
        and str(entry["event_hash"]).lower() != str(sth["head_event_hash"]).lower()
    ):
        raise ValueError(f"head entry event_hash mismatch at tree_size={tree_size}")


def verify_export_archive(
    archive: Mapping[str, Any],
    expected_pubkey: bytes | str,
) -> VerificationSummary:
    expected_pk = _as_hash32(expected_pubkey)
    archive_pk = _as_hash32(archive["host_public_key"])
    if archive_pk != expected_pk:
        raise ValueError(
            f"host_public_key mismatch: archive contains {archive_pk.hex()}, expected {expected_pk.hex()}"
        )
    if is_weak_ed25519_pubkey(expected_pk):
        raise ValueError("rejected weak low-order Ed25519 public key")

    bundle = archive["bundle"]
    rm = bundle.get("resolver_manifest")
    if rm is not None:
        min_c = float(rm["min_confidence"])
        dec_t = float(rm["decisiveness_threshold"])
        damp = float(rm["corroboration_damping"])
        if (
            not math.isfinite(min_c)
            or not (0.0 <= min_c <= 1.0)
            or not math.isfinite(dec_t)
            or not (0.0 <= dec_t <= 1.0)
            or not math.isfinite(damp)
            or not (0.0 <= damp <= 1.0)
        ):
            raise ValueError("invalid resolver_manifest threshold bounds in ContextBundle")
        if bool(rm["non_default_thresholds"]) != _expected_non_default_flag(rm):
            raise ValueError(
                f"inconsistent resolver_manifest.non_default_thresholds={rm['non_default_thresholds']}"
            )

    objects_by_id: dict[str, Mapping[str, Any]] = {}
    for obj in archive.get("objects", []):
        oid = str(uuid.UUID(str(obj["id"]))).lower()
        recomputed = compute_object_content_hash(obj)
        stored_hex = str(obj["content_hash"]).lower()
        if recomputed.hex() != stored_hex:
            raise ValueError(
                f"tampered object[id={oid}]: recomputed content_hash {recomputed.hex()} != stored {stored_hex}"
            )
        objects_by_id[oid] = obj

    claims_by_id: dict[str, Mapping[str, Any]] = {}
    for claim in archive.get("claims", []):
        cid = str(uuid.UUID(str(claim["id"]))).lower()
        expected_v2 = compute_logical_claim_group_key(
            str(claim["tenant_id"]),
            str(claim["subject"]),
            str(claim["predicate"]),
            str(claim["scope"]),
        )
        expected_v1 = compute_claim_group_key(
            str(claim["tenant_id"]),
            str(claim["subject"]),
            str(claim["predicate"]),
            str(claim["object_type"]),
            str(claim["scope"]),
        )
        stored_group = str(claim["claim_group_key"]).lower()
        if stored_group not in (expected_v2.hex(), expected_v1.hex()):
            raise ValueError(
                f"tampered claim[id={cid}].claim_group_key: recomputed {expected_v2.hex()} != stored {stored_group}"
            )
        recomputed = compute_claim_content_hash(claim)
        stored_hex = str(claim["content_hash"]).lower()
        if recomputed.hex() != stored_hex:
            raise ValueError(
                f"tampered claim[id={cid}] body/metadata: recomputed content_hash {recomputed.hex()} != stored {stored_hex}"
            )
        claims_by_id[cid] = claim

    overrides_by_id: dict[str, Mapping[str, Any]] = {}
    for att in archive.get("override_attestations", []):
        aid = str(uuid.UUID(str(att["id"]))).lower()
        if str(att["tenant_id"]) != str(bundle["tenant_id"]):
            raise ValueError(
                f"override_attestation[id={aid}] tenant_id '{att['tenant_id']}' != bundle tenant_id '{bundle['tenant_id']}'"
            )
        recomputed_att = compute_override_attestation_hash(att)
        stored_att_hex = str(att["attestation_hash"]).lower()
        if recomputed_att.hex() != stored_att_hex:
            raise ValueError(
                f"tampered override_attestation[id={aid}]: recomputed attestation_hash {recomputed_att.hex()} != stored {stored_att_hex}"
            )
        if not verify_override_signature(
            expected_pk,
            str(att["tenant_id"]),
            int(att["evidence_seq_num"]),
            recomputed_att,
            att["host_signature"],
        ):
            raise ValueError(
                f"Ed25519 host_signature verification failed on override_attestation[id={aid}]"
            )
        csig = att.get("client_signature")
        cpk = att.get("client_public_key")
        if csig is not None and cpk is not None:
            csig_raw = bytes.fromhex(csig) if isinstance(csig, str) else bytes(csig)
            cpk_raw = _as_hash32(cpk)
            intent_hash = compute_override_client_intent_hash(
                str(att["tenant_id"]),
                str(att["scope"]),
                str(att["winning_claim_id"]),
                str(att["adjudicator_id"]),
                str(att["justification"]),
            )
            ok_intent = verify_ed25519_strict(cpk_raw, intent_hash, csig_raw)
            ok_full = verify_ed25519_strict(cpk_raw, recomputed_att, csig_raw)
            if not ok_intent and not ok_full:
                raise ValueError(
                    f"client Ed25519 signature verification failed on override_attestation[id={aid}]"
                )
        overrides_by_id[aid] = att

    for sel in bundle.get("selected_objects", []):
        sid = str(uuid.UUID(str(sel["id"]))).lower()
        obj = objects_by_id.get(sid)
        if obj is None:
            raise ValueError(f"bundle selected_objects references missing object[id={sid}]")
        if (
            str(sel["content_hash"]).lower() != str(obj["content_hash"]).lower()
            or int(sel["version"]) != int(obj["version"])
        ):
            raise ValueError(
                f"tampered bundle selected_objects[id={sid}]: reference mismatch against verified object"
            )

    for res in bundle.get("resolution_records", []):
        win = res["winning_claim"]
        cid = str(uuid.UUID(str(win["id"]))).lower()
        stored = claims_by_id.get(cid)
        if stored is None:
            raise ValueError(f"bundle resolution_records references missing claim[id={cid}]")
        valid_res_groups = {
            str(stored["claim_group_key"]).lower(),
            compute_logical_claim_group_key(
                str(stored["tenant_id"]),
                str(stored["subject"]),
                str(stored["predicate"]),
                str(stored["scope"]),
            ).hex(),
        }
        if (
            str(win["content_hash"]).lower() != str(stored["content_hash"]).lower()
            or str(res["claim_group_key"]).lower() not in valid_res_groups
        ):
            raise ValueError(
                f"tampered resolution_record for claim[id={cid}]: content_hash != verified claim"
            )
        ovr_ref = res.get("override_attestation")
        if ovr_ref is not None:
            aid = str(uuid.UUID(str(ovr_ref["attestation_id"]))).lower()
            verified_att = overrides_by_id.get(aid)
            if verified_att is None:
                raise ValueError(
                    f"resolution_record references missing override_attestation[id={aid}]"
                )
            if (
                str(verified_att["attestation_hash"]).lower()
                != str(ovr_ref["attestation_hash"]).lower()
                or str(uuid.UUID(str(verified_att["winning_claim_id"]))).lower() != cid
                or str(verified_att["winning_claim_content_hash"]).lower()
                != str(win["content_hash"]).lower()
                or str(verified_att["adjudicator_id"]) != str(ovr_ref["adjudicator_id"])
                or str(verified_att["justification"]) != str(ovr_ref["justification"])
                or int(verified_att["evidence_seq_num"]) != int(ovr_ref["evidence_seq_num"])
            ):
                raise ValueError(
                    f"tampered override_attestation reference on resolution_record for claim[id={cid}]"
                )

    for disp in bundle.get("dispute_records", []):
        competing = disp.get("competing_claims", [])
        if not competing:
            raise ValueError("invalid dispute_record with empty competing_claims")
        for cand in competing:
            cid = str(uuid.UUID(str(cand["id"]))).lower()
            stored = claims_by_id.get(cid)
            if stored is None:
                raise ValueError(f"bundle dispute_records references missing claim[id={cid}]")
            valid_disp_groups = {
                str(stored["claim_group_key"]).lower(),
                compute_logical_claim_group_key(
                    str(stored["tenant_id"]),
                    str(stored["subject"]),
                    str(stored["predicate"]),
                    str(stored["scope"]),
                ).hex(),
            }
            if (
                str(cand["content_hash"]).lower() != str(stored["content_hash"]).lower()
                or str(disp["claim_group_key"]).lower() not in valid_disp_groups
            ):
                raise ValueError(
                    f"tampered dispute_record candidate claim[id={cid}]: content_hash != verified claim"
                )
        lapsed = disp.get("lapsed_override")
        if lapsed is not None:
            aid = str(uuid.UUID(str(lapsed["attestation_id"]))).lower()
            verified_att = overrides_by_id.get(aid)
            if verified_att is None:
                raise ValueError(
                    f"dispute_record.lapsed_override references missing override_attestation[id={aid}]"
                )
            if (
                str(verified_att["attestation_hash"]).lower()
                != str(lapsed["attestation_hash"]).lower()
                or str(uuid.UUID(str(verified_att["winning_claim_id"]))).lower()
                != str(uuid.UUID(str(lapsed["prior_winning_claim_id"]))).lower()
                or str(verified_att["adjudicator_id"]) != str(lapsed["adjudicator_id"])
                or str(verified_att["justification"]) != str(lapsed["justification"])
                or int(verified_att["evidence_seq_num"]) != int(lapsed["evidence_seq_num"])
            ):
                raise ValueError(
                    f"tampered lapsed_override reference on dispute_record[id={aid}]"
                )

    recomputed_bundle_hash, _ = compute_bundle_hash(bundle)
    archive_bundle_hex = str(archive["bundle_hash"]).lower()
    if recomputed_bundle_hash.hex() != archive_bundle_hex:
        raise ValueError(
            f"tampered ContextBundle: recomputed bundle_hash {recomputed_bundle_hash.hex()} != archive bundle_hash {archive_bundle_hex}"
        )

    evidence_chain = archive.get("evidence_chain") or []
    merkle_proof = archive.get("merkle_proof")
    if not evidence_chain and merkle_proof is None:
        raise ValueError("ExportArchive must contain either evidence_chain or merkle_proof")

    found_matching_bundle_entry = False
    verified_refusals = 0
    verified_evidence_entries = 0
    evidence_by_seq: dict[int, Mapping[str, Any]] = {}
    zero_hex = "00" * 32

    for idx, entry in enumerate(evidence_chain):
        if str(entry["tenant_id"]) != str(bundle["tenant_id"]):
            raise ValueError(
                f"evidence_chain[{idx}] tenant_id '{entry['tenant_id']}' != bundle tenant_id '{bundle['tenant_id']}'"
            )
        seq_num = int(entry["seq_num"])
        prev_hex = str(entry["prev_hash"]).lower()
        if idx == 0:
            if seq_num == 1 and prev_hex != zero_hex:
                raise ValueError(
                    f"tampered genesis evidence_chain[0]: seq_num=1 must have zero prev_hash, got {prev_hex}"
                )
            if seq_num < 1:
                raise ValueError(f"tampered evidence_chain[0].seq_num={seq_num}: must be >= 1")
        else:
            prev_entry = evidence_chain[idx - 1]
            expected_seq = int(prev_entry["seq_num"]) + 1
            if seq_num != expected_seq:
                raise ValueError(
                    f"tampered evidence seq_num at index {idx}: expected {expected_seq}, got {seq_num}"
                )
            prior_event_hex = str(prev_entry["event_hash"]).lower()
            if prev_hex != prior_event_hex:
                raise ValueError(
                    f"broken evidence prev_hash link at seq_num={seq_num}: prev_hash {prev_hex} != prior event_hash {prior_event_hex}"
                )

        if entry.get("refusal_metadata") is not None:
            verified_refusals += 1

        verify_evidence_entry(entry, expected_pk)
        verified_evidence_entries += 1

        eb_hash = entry.get("bundle_hash")
        if eb_hash is not None and str(eb_hash).lower() == recomputed_bundle_hash.hex():
            es_comm = entry.get("state_commitment")
            if es_comm is None or str(es_comm).lower() != str(bundle["state_commitment"]).lower():
                raise ValueError(
                    f"evidence seq_num={seq_num} state_commitment mismatch against ContextBundle"
                )
            found_matching_bundle_entry = True

        evidence_by_seq[seq_num] = entry

    merkle_tree_size: int | None = None
    merkle_root_hex: str | None = None
    verified_witness_anchors = 0

    if merkle_proof is not None:
        sth = merkle_proof["checkpoint"]
        verified_witness_anchors = verify_signed_tree_head(
            sth, str(bundle["tenant_id"]), expected_pk
        )
        b_proof = merkle_proof["bundle_entry_proof"]
        _verify_entry_inclusion(b_proof, sth, expected_pk)
        b_entry = b_proof["entry"]
        if (
            b_entry.get("bundle_hash") is None
            or str(b_entry["bundle_hash"]).lower() != recomputed_bundle_hash.hex()
            or b_entry.get("state_commitment") is None
            or str(b_entry["state_commitment"]).lower() != str(bundle["state_commitment"]).lower()
        ):
            raise ValueError(
                "merkle_proof.bundle_entry_proof does not bind archive bundle_hash and state_commitment"
            )
        found_matching_bundle_entry = True
        b_seq = int(b_entry["seq_num"])
        if not evidence_chain:
            verified_evidence_entries += 1
        evidence_by_seq[b_seq] = b_entry

        for ovr_proof in merkle_proof.get("override_entry_proofs", []):
            _verify_entry_inclusion(ovr_proof, sth, expected_pk)
            o_entry = ovr_proof["entry"]
            o_seq = int(o_entry["seq_num"])
            if not evidence_chain and o_seq != b_seq:
                verified_evidence_entries += 1
            evidence_by_seq[o_seq] = o_entry

        if (
            evidence_chain
            and int(evidence_chain[0]["seq_num"]) == 1
            and len(evidence_chain) == int(sth["tree_size"])
        ):
            leaves = [
                merkle_leaf_hash(int(e["seq_num"]), e["event_hash"])
                for e in evidence_chain
            ]
            chain_root = compute_merkle_root_from_leaves(leaves).hex()
            if chain_root != str(sth["merkle_root"]).lower():
                raise ValueError(
                    f"merkle_proof.checkpoint.merkle_root {sth['merkle_root']} != root {chain_root} computed from evidence_chain"
                )

        merkle_tree_size = int(sth["tree_size"])
        merkle_root_hex = str(sth["merkle_root"]).lower()

    for aid, att in overrides_by_id.items():
        seq_ref = int(att["evidence_seq_num"])
        ev = evidence_by_seq.get(seq_ref)
        if ev is None:
            raise ValueError(
                f"override_attestation[id={aid}] references missing verified evidence seq_num={seq_ref}"
            )
        ev_sc = ev.get("state_commitment")
        if ev_sc is None or str(ev_sc).lower() != str(att["attestation_hash"]).lower():
            raise ValueError(
                f"override_attestation[id={aid}] attestation_hash not bound in evidence seq_num={seq_ref}"
            )

    if not found_matching_bundle_entry:
        raise ValueError(
            f"no verified evidence_history entry binds bundle_hash {recomputed_bundle_hash.hex()}"
        )

    if evidence_chain and merkle_proof is not None:
        v_mode = "full_chain_and_merkle"
    elif evidence_chain:
        v_mode = "full_chain"
    else:
        v_mode = "merkle_inclusion"

    non_default = bool(rm["non_default_thresholds"]) if rm is not None else False

    return VerificationSummary(
        tenant_id=str(bundle["tenant_id"]),
        bundle_hash_hex=recomputed_bundle_hash.hex(),
        state_commitment_hex=str(bundle["state_commitment"]).lower(),
        verified_objects=len(objects_by_id),
        verified_claims=len(claims_by_id),
        verified_evidence_entries=verified_evidence_entries,
        verified_overrides=len(overrides_by_id),
        verified_refusals=verified_refusals,
        non_default_thresholds=non_default,
        resolver_manifest=dict(rm) if isinstance(rm, Mapping) else None,
        verification_mode=v_mode,
        merkle_tree_size=merkle_tree_size,
        merkle_root_hex=merkle_root_hex,
        verified_witness_anchors=verified_witness_anchors,
    )


def dump_archive_preimages(archive: Mapping[str, Any]) -> dict[str, Any]:
    """Dumps explicit domain-separated cryptographic preimages inside `archive` (`--dump-preimages` parity)."""
    bundle_jcs = to_canonical_bytes(archive["bundle"])
    overrides_dump = []
    for att in archive.get("override_attestations", []):
        host_sig_digest = override_signing_preimage(
            str(att["tenant_id"]),
            int(att["evidence_seq_num"]),
            att["attestation_hash"],
        )
        client_intent = compute_override_client_intent_hash(
            str(att["tenant_id"]),
            str(att["scope"]),
            str(att["winning_claim_id"]),
            str(att["adjudicator_id"]),
            str(att["justification"]),
        )
        overrides_dump.append(
            {
                "id": str(uuid.UUID(str(att["id"]))).lower(),
                "evidence_seq_num": int(att["evidence_seq_num"]),
                "attestation_hash": str(att["attestation_hash"]).lower(),
                "host_sig_preimage_domain": "acta:override_sig:v1",
                "host_sig_digest_hex": host_sig_digest.hex(),
                "client_sig_domain": "acta:override_client_sig:v1",
                "client_sig_digest_hex": client_intent.hex(),
            }
        )

    entries_src: list[Mapping[str, Any]] = []
    if archive.get("evidence_chain"):
        entries_src = list(archive["evidence_chain"])
    elif archive.get("merkle_proof") is not None:
        mp = archive["merkle_proof"]
        entries_src = [mp["bundle_entry_proof"]["entry"]] + [
            op["entry"] for op in mp.get("override_entry_proofs", [])
        ]

    evidence_dump = []
    for entry in entries_src:
        ev_domain = (
            "acta:evidence_event:v1"
            if entry.get("refusal_metadata") is None and entry.get("override_summary") is None
            else "acta:evidence_event:v2"
        )
        sig_digest = evidence_signing_preimage(
            str(entry["tenant_id"]),
            int(entry["seq_num"]),
            entry["prev_hash"],
            entry["event_hash"],
        )
        refusal_jcs = (
            to_canonical_json(_normalize_refusal_metadata(entry["refusal_metadata"]))
            if entry.get("refusal_metadata") is not None
            else None
        )
        evidence_dump.append(
            {
                "seq_num": int(entry["seq_num"]),
                "event_domain": ev_domain,
                "event_hash": str(entry["event_hash"]).lower(),
                "merkle_leaf_hash": merkle_leaf_hash(
                    int(entry["seq_num"]), entry["event_hash"]
                ).hex(),
                "host_sig_preimage_domain": "acta:evidence_sig:v1",
                "host_sig_digest_hex": sig_digest.hex(),
                "refusal_metadata_canonical_jcs": refusal_jcs,
            }
        )

    mp_opt = archive.get("merkle_proof")
    cp_dump = None
    if mp_opt is not None:
        sth = mp_opt["checkpoint"]
        cp_sig_digest = checkpoint_signing_preimage(
            str(sth["tenant_id"]), sth["checkpoint_hash"]
        )
        cp_dump = {
            "tree_size": int(sth["tree_size"]),
            "merkle_root": str(sth["merkle_root"]).lower(),
            "checkpoint_hash": str(sth["checkpoint_hash"]).lower(),
            "host_sig_preimage_domain": "acta:checkpoint_sig:v1",
            "host_sig_digest_hex": cp_sig_digest.hex(),
            "bundle_audit_path_len": len(mp_opt["bundle_entry_proof"].get("audit_path", [])),
        }

    return {
        "bundle_domain": "acta:bundle:v1",
        "bundle_canonical_jcs_len": len(bundle_jcs),
        "bundle_hash": str(archive["bundle_hash"]).lower(),
        "checkpoint": cp_dump,
        "override_attestations": overrides_dump,
        "evidence_entries": evidence_dump,
    }


# ==============================================================================
# Acta v1.1 / v1.6 Stateless Keyed-BLAKE3 Tenant & OAuth Principal Tokens
# ==============================================================================
TENANT_TOKEN_PREFIX = "acta_tk_v1:"


def normalize_github_slug(raw: str) -> str:
    trimmed = raw.strip().lstrip("@").lower()
    out: list[str] = []
    prev_dash = False
    for ch in trimmed:
        if ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in ("_", "."):
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    clean = "".join(out).strip("-")
    if not clean or len(clean) > 100:
        raise ValueError("GitHub organization/user slug must be 1..=100 valid characters")
    return clean


def _validate_token_segment(label: str, val: str) -> None:
    if not val or len(val.encode("utf-8")) > 128:
        raise ValueError(f"{label} must be 1..=128 bytes")
    if any(ch.isspace() or ord(ch) < 32 or ch == ":" for ch in val):
        raise ValueError(f"{label} cannot contain whitespace, control characters, or ':'")


def derive_tenant_mac_key(master_api_key: str) -> bytes:
    return hash_length_delimited(
        [b"acta:tenant_mac_key:v1", master_api_key.strip().encode("utf-8")]
    )


def _length_delimited_preimage_parts(parts: Sequence[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for p in parts:
        out.append(struct.pack("<Q", len(p)))
        out.append(p)
    return out


def mint_tenant_api_key(master_api_key: str, tenant_id: str) -> str:
    """Mints a stateless `acta_tk_v1:<tenant_id>:<64_hex_mac>` key matching Rust `acta-crypto`."""
    master_clean = master_api_key.strip()
    if not master_clean:
        raise ValueError("master_api_key must be non-empty")
    tenant_clean = tenant_id.strip()
    _validate_token_segment("tenant_id", tenant_clean)

    key_32 = derive_tenant_mac_key(master_clean)
    mac = blake3_keyed_hash(
        key_32,
        _length_delimited_preimage_parts(
            [b"acta:tenant_token:v1", tenant_clean.encode("utf-8")]
        ),
    )
    return f"{TENANT_TOKEN_PREFIX}{tenant_clean}:{mac.hex()}"


def mint_user_tenant_api_key(
    master_api_key: str,
    tenant_id: str,
    github_login: str,
) -> str:
    """Mints a 3-segment principal-bound OAuth key `acta_tk_v1:<tenant_id>:<github_login>:<64_hex_mac>`."""
    master_clean = master_api_key.strip()
    if not master_clean:
        raise ValueError("master_api_key must be non-empty")
    tenant_clean = tenant_id.strip()
    user_clean = normalize_github_slug(github_login)
    _validate_token_segment("tenant_id", tenant_clean)
    _validate_token_segment("github_login", user_clean)

    key_32 = derive_tenant_mac_key(master_clean)
    mac = blake3_keyed_hash(
        key_32,
        _length_delimited_preimage_parts(
            [
                b"acta:tenant_user_token:v2",
                tenant_clean.encode("utf-8"),
                user_clean.encode("utf-8"),
            ]
        ),
    )
    return f"{TENANT_TOKEN_PREFIX}{tenant_clean}:{user_clean}:{mac.hex()}"


def _parse_acta_tk_segments(token: str) -> tuple[str, str | None, str] | None:
    clean = token.strip()
    if not clean.startswith(TENANT_TOKEN_PREFIX):
        return None
    rest = clean[len(TENANT_TOKEN_PREFIX) :]
    parts = rest.split(":")
    if len(parts) == 2:
        tenant_part, mac_hex = parts
        _validate_token_segment("tenant_id", tenant_part)
        user_part: str | None = None
    elif len(parts) == 3:
        tenant_part, user_part, mac_hex = parts
        _validate_token_segment("tenant_id", tenant_part)
        _validate_token_segment("github_login", user_part)
    else:
        raise ValueError("malformed acta_tk_v1 token")
    if len(mac_hex) != 64:
        raise ValueError("malformed acta_tk_v1 token MAC length")
    bytes.fromhex(mac_hex)
    return tenant_part, user_part, mac_hex


def extract_token_tenant(token: str) -> str | None:
    """Extracts `<tenant_id>` from 2-segment or 3-segment `acta_tk_v1` tokens (unverified)."""
    parsed = _parse_acta_tk_segments(token)
    return parsed[0] if parsed is not None else None


def extract_token_principal(token: str) -> str | None:
    """Extracts `<github_login>` from 3-segment `acta_tk_v1:<tenant>:<login>:<mac>` tokens (unverified)."""
    parsed = _parse_acta_tk_segments(token)
    return parsed[1] if parsed is not None else None


def verify_tenant_api_key_with_principal(
    master_api_key: str,
    token: str,
) -> tuple[str, str | None]:
    """Verifies a 2-segment or 3-segment `acta_tk_v1` token in constant time -> `(tenant_id, principal)`."""
    parsed = _parse_acta_tk_segments(token)
    if parsed is None:
        raise ValueError("token does not start with acta_tk_v1:")
    tenant_part, user_part, _ = parsed
    expected_token = (
        mint_tenant_api_key(master_api_key, tenant_part)
        if user_part is None
        else mint_user_tenant_api_key(master_api_key, tenant_part, user_part)
    )
    if not _hmac.compare_digest(
        expected_token.encode("ascii"), token.strip().lower().encode("ascii")
    ) and not _hmac.compare_digest(
        expected_token.encode("ascii"), token.strip().encode("ascii")
    ):
        raise ValueError("invalid or forged tenant-bound API key MAC")
    return tenant_part, user_part


def verify_tenant_api_key(master_api_key: str, token: str) -> str:
    """Verifies an `acta_tk_v1` token in constant time and returns its bound `tenant_id`."""
    tenant_part, _ = verify_tenant_api_key_with_principal(master_api_key, token)
    return tenant_part
