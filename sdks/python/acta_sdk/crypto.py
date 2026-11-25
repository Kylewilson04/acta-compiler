"""Acta Compiler v1.7.3 Cryptographic Primitives, RFC 6962 §2.1 SHA-256 Merkle Verifier & Epistemic Notary.

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
import hashlib
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
SCHEMA_VERSION_V1 = "acta-context-bundle/v1"
SCHEMA_VERSION_V2 = "acta-context-bundle/v2"
SCHEMA_VERSION = SCHEMA_VERSION_V2
SUB_COMMITMENT_DOMAIN_V2 = "acta:sub_commitment:v2"
STATE_COMMITMENT_DOMAIN_V2 = "acta:state:v2"
STATE_REBUILD_ARCHIVE_SCHEMA_V1 = "acta-state-rebuild-archive/v1"
STATE_REBUILD_ARCHIVE_SCHEMA_V2 = "acta-state-rebuild-archive/v2"
STATE_REBUILD_ARCHIVE_SCHEMA = STATE_REBUILD_ARCHIVE_SCHEMA_V2
REBUILD_HEADER_DOMAIN_V1 = "acta:rebuild_header:v1"
REBUILD_SIG_DOMAIN_V1 = "acta:rebuild_sig:v1"
HOST_KEY_ROTATE_DOMAIN_V1 = "acta:host_key_rotate:v1"
HOST_KEY_ROTATE_OLD_SIG_DOMAIN_V1 = "acta:host_key_rotate_old_sig:v1"
HOST_KEY_ROTATE_NEW_SIG_DOMAIN_V1 = "acta:host_key_rotate_new_sig:v1"
ERASABLE_CLAIM_DOMAIN_V1 = "acta:erasable_claim:v1"

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


def encode_length_delimited(parts: Sequence[bytes]) -> bytes:
    out = bytearray()
    for part in parts:
        out.extend(struct.pack("<Q", len(part)))
        out.extend(part)
    return bytes(out)


def hash_length_delimited(parts: Sequence[bytes]) -> bytes:
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(struct.pack("<Q", len(part)))
        chunks.append(part)
    return blake3_hash(chunks)


def compute_source_content_commitment(
    source_descriptor: str,
    source_content: bytes | str,
) -> bytes:
    raw = source_content.encode("utf-8") if isinstance(source_content, str) else bytes(source_content)
    return hash_length_delimited(
        [b"acta:source_content:v1", source_descriptor.encode("utf-8"), raw]
    )


def _encode_opt_utf8(val: str | None) -> bytes:
    if val is None:
        return b"\x00"
    return b"\x01" + val.encode("utf-8")


def witness_registration_preimage_bytes(
    reg_domain: str,
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    registered_by: str = "",
    description: str | None = None,
) -> bytes:
    pk_raw = _as_hash32(public_key)
    if reg_domain == "acta:witness_reg:v1":
        return encode_length_delimited(
            [
                b"acta:witness_reg:v1",
                tenant_id.encode("utf-8"),
                witness_id.encode("utf-8"),
                pk_raw,
            ]
        )
    if reg_domain == "acta:witness_reg:v2":
        return encode_length_delimited(
            [
                b"acta:witness_reg:v2",
                tenant_id.encode("utf-8"),
                witness_id.encode("utf-8"),
                pk_raw,
                registered_by.encode("utf-8"),
            ]
        )
    if reg_domain == "acta:witness_reg:v3":
        return encode_length_delimited(
            [
                b"acta:witness_reg:v3",
                tenant_id.encode("utf-8"),
                witness_id.encode("utf-8"),
                pk_raw,
                registered_by.encode("utf-8"),
                _encode_opt_utf8(description),
            ]
        )
    raise ValueError(f"unsupported witness registration_domain: {reg_domain}")


def compute_witness_registration_commitment(
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
) -> bytes:
    pre = witness_registration_preimage_bytes(
        "acta:witness_reg:v1", tenant_id, witness_id, public_key
    )
    return blake3_hash([pre])


def compute_witness_registration_v2_commitment(
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    registered_by: str,
) -> tuple[bytes, bytes]:
    pre = witness_registration_preimage_bytes(
        "acta:witness_reg:v2", tenant_id, witness_id, public_key, registered_by
    )
    return pre, blake3_hash([pre])


def compute_witness_registration_v3_commitment(
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    registered_by: str,
    description: str | None = None,
) -> tuple[bytes, bytes]:
    pre = witness_registration_preimage_bytes(
        "acta:witness_reg:v3",
        tenant_id,
        witness_id,
        public_key,
        registered_by,
        description,
    )
    return pre, blake3_hash([pre])


def witness_revocation_preimage_bytes(
    revoke_domain: str,
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    revoked_by: str,
    reason: str,
    revocation_mode: str = "compromise",
    effective_from_tree_size: int | None = None,
) -> bytes:
    pk_raw = _as_hash32(public_key)
    if revoke_domain == "acta:witness_revoke:v1":
        return encode_length_delimited(
            [
                b"acta:witness_revoke:v1",
                tenant_id.encode("utf-8"),
                witness_id.encode("utf-8"),
                pk_raw,
                revoked_by.encode("utf-8"),
                reason.encode("utf-8"),
            ]
        )
    if revoke_domain == "acta:witness_revoke:v2":
        if revocation_mode == "compromise":
            if effective_from_tree_size is not None:
                raise ValueError(
                    "acta:witness_revoke:v2 mode='compromise' must have effective_from_tree_size=None"
                )
        elif revocation_mode == "retire":
            if effective_from_tree_size is None or int(effective_from_tree_size) < 1:
                raise ValueError(
                    "acta:witness_revoke:v2 mode='retire' requires effective_from_tree_size >= 1"
                )
        else:
            raise ValueError(
                f"unsupported witness revocation_mode '{revocation_mode}' (expected 'compromise' or 'retire')"
            )
        eff_val = int(effective_from_tree_size) if effective_from_tree_size is not None else None
        return encode_length_delimited(
            [
                b"acta:witness_revoke:v2",
                tenant_id.encode("utf-8"),
                witness_id.encode("utf-8"),
                pk_raw,
                revoked_by.encode("utf-8"),
                revocation_mode.encode("utf-8"),
                _encode_opt_i64(eff_val),
                reason.encode("utf-8"),
            ]
        )
    raise ValueError(f"unsupported witness revocation_domain: {revoke_domain}")


def compute_witness_revocation_commitment(
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    revoked_by: str,
    reason: str,
) -> tuple[bytes, bytes]:
    pre = witness_revocation_preimage_bytes(
        "acta:witness_revoke:v1", tenant_id, witness_id, public_key, revoked_by, reason
    )
    return pre, blake3_hash([pre])


def compute_witness_revocation_v2_commitment(
    tenant_id: str,
    witness_id: str,
    public_key: bytes | str,
    revoked_by: str,
    revocation_mode: str,
    effective_from_tree_size: int | None,
    reason: str,
) -> tuple[bytes, bytes]:
    pre = witness_revocation_preimage_bytes(
        "acta:witness_revoke:v2",
        tenant_id,
        witness_id,
        public_key,
        revoked_by,
        reason,
        revocation_mode=revocation_mode,
        effective_from_tree_size=effective_from_tree_size,
    )
    return pre, blake3_hash([pre])


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
    if meta.get("attempted_checkpoint_hash") is not None:
        ach = meta["attempted_checkpoint_hash"]
        out["attempted_checkpoint_hash"] = _as_hash32(ach).hex()
    if meta.get("signing_domain") is not None:
        out["signing_domain"] = str(meta["signing_domain"])
    if meta.get("expected_intent_digest_hex") is not None:
        out["expected_intent_digest_hex"] = _as_hash32(meta["expected_intent_digest_hex"]).hex()
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


def object_content_preimage_bytes(obj: Mapping[str, Any]) -> bytes:
    uid = uuid.UUID(str(obj["id"]))
    canonical_tags = to_canonical_bytes(list(obj.get("tags", [])))
    canonical_body = to_canonical_bytes(obj["body"])
    priority_le = struct.pack("<i", int(obj["priority"]))
    importance_le = _f32_bits_le(float(obj["importance"]))
    version_le = struct.pack("<i", int(obj["version"]))
    pred_bytes = _encode_opt_uuid(obj.get("predecessor_id"))
    created_micros_le = struct.pack("<q", parse_rfc3339_micros(obj["created_at"]))

    return encode_length_delimited(
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


def compute_object_content_hash(obj: Mapping[str, Any]) -> bytes:
    return blake3_hash([object_content_preimage_bytes(obj)])


def claim_group_preimage_bytes(claim: Mapping[str, Any]) -> tuple[str, bytes]:
    v2_pre = encode_length_delimited(
        [
            b"acta:claim_group:v2",
            str(claim["tenant_id"]).encode("utf-8"),
            str(claim["subject"]).encode("utf-8"),
            str(claim["predicate"]).encode("utf-8"),
            str(claim["scope"]).encode("utf-8"),
        ]
    )
    if blake3_hash([v2_pre]) == _as_hash32(claim["claim_group_key"]):
        return "acta:claim_group:v2", v2_pre
    v1_pre = encode_length_delimited(
        [
            str(claim["tenant_id"]).encode("utf-8"),
            str(claim["subject"]).encode("utf-8"),
            str(claim["predicate"]).encode("utf-8"),
            str(claim["object_type"]).encode("utf-8"),
            str(claim["scope"]).encode("utf-8"),
        ]
    )
    return "legacy_v1_unprefixed", v1_pre


def claim_content_preimage_bytes(claim: Mapping[str, Any]) -> bytes:
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

    return encode_length_delimited(
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


def compute_claim_content_hash(claim: Mapping[str, Any]) -> bytes:
    return blake3_hash([claim_content_preimage_bytes(claim)])


def object_client_intent_preimage_bytes(
    tenant_id: str,
    obj_type: str,
    scope: str,
    lifecycle_status: str,
    priority: int,
    importance: float,
    tags: Sequence[str],
    body: Any,
    predecessor_id: str | uuid.UUID | None = None,
) -> bytes:
    canonical_tags = to_canonical_bytes(list(tags))
    canonical_body = to_canonical_bytes(body)
    return encode_length_delimited(
        [
            b"acta:object_client_sig:v1",
            tenant_id.encode("utf-8"),
            obj_type.encode("utf-8"),
            scope.encode("utf-8"),
            lifecycle_status.encode("utf-8"),
            struct.pack("<i", int(priority)),
            _f32_bits_le(float(importance)),
            canonical_tags,
            canonical_body,
            _encode_opt_uuid(predecessor_id),
        ]
    )


def compute_object_client_intent_hash(
    tenant_id: str,
    obj_type: str,
    scope: str,
    lifecycle_status: str,
    priority: int,
    importance: float,
    tags: Sequence[str],
    body: Any,
    predecessor_id: str | uuid.UUID | None = None,
) -> bytes:
    return blake3_hash(
        [
            object_client_intent_preimage_bytes(
                tenant_id,
                obj_type,
                scope,
                lifecycle_status,
                priority,
                importance,
                tags,
                body,
                predecessor_id,
            )
        ]
    )


def sign_object_client_intent(
    private_key_seed: bytes | str,
    *,
    tenant_id: str,
    obj_type: str,
    scope: str,
    body: Any,
    lifecycle_status: str = "active",
    priority: int = 0,
    importance: float = 0.5,
    tags: Sequence[str] = (),
    predecessor_id: str | uuid.UUID | None = None,
) -> tuple[str, str]:
    digest = compute_object_client_intent_hash(
        tenant_id,
        obj_type,
        scope,
        lifecycle_status,
        priority,
        importance,
        tags,
        body,
        predecessor_id,
    )
    return sign_client_content_hash(private_key_seed, digest)


def claim_client_intent_preimage_bytes(
    tenant_id: str,
    scope: str,
    subject: str,
    predicate: str,
    object_val: Any,
    object_type: str,
    confidence: float,
    source_provenance_class: int,
    source_descriptor: str,
    source_commitment: bytes | str,
    status: str = "active",
    contradiction_ids: Sequence[str | uuid.UUID] = (),
    valid_from: str | datetime.datetime | None = None,
    valid_to: str | datetime.datetime | None = None,
    predecessor_id: str | uuid.UUID | None = None,
) -> bytes:
    canonical_val = to_canonical_bytes(object_val)
    sorted_contradictions = sorted(
        (uuid.UUID(str(cid)) for cid in contradiction_ids),
        key=lambda u: u.bytes,
    )
    canonical_contradictions = to_canonical_bytes([str(u) for u in sorted_contradictions])
    vf_bytes = _encode_opt_i64(parse_rfc3339_micros(valid_from) if valid_from is not None else None)
    vt_bytes = _encode_opt_i64(parse_rfc3339_micros(valid_to) if valid_to is not None else None)
    return encode_length_delimited(
        [
            b"acta:claim_client_sig:v1",
            tenant_id.encode("utf-8"),
            scope.encode("utf-8"),
            subject.encode("utf-8"),
            predicate.encode("utf-8"),
            canonical_val,
            object_type.encode("utf-8"),
            _f64_bits_le(float(confidence)),
            struct.pack("<i", int(source_provenance_class)),
            source_descriptor.encode("utf-8"),
            _as_hash32(source_commitment),
            status.encode("utf-8"),
            canonical_contradictions,
            vf_bytes,
            vt_bytes,
            _encode_opt_uuid(predecessor_id),
        ]
    )


def compute_claim_client_intent_hash(
    tenant_id: str,
    scope: str,
    subject: str,
    predicate: str,
    object_val: Any,
    object_type: str,
    confidence: float,
    source_provenance_class: int,
    source_descriptor: str,
    source_commitment: bytes | str,
    status: str = "active",
    contradiction_ids: Sequence[str | uuid.UUID] = (),
    valid_from: str | datetime.datetime | None = None,
    valid_to: str | datetime.datetime | None = None,
    predecessor_id: str | uuid.UUID | None = None,
) -> bytes:
    return blake3_hash(
        [
            claim_client_intent_preimage_bytes(
                tenant_id,
                scope,
                subject,
                predicate,
                object_val,
                object_type,
                confidence,
                source_provenance_class,
                source_descriptor,
                source_commitment,
                status,
                contradiction_ids,
                valid_from,
                valid_to,
                predecessor_id,
            )
        ]
    )


def sign_claim_client_intent(
    private_key_seed: bytes | str,
    *,
    tenant_id: str,
    scope: str,
    subject: str,
    predicate: str,
    object_val: Any,
    object_type: str,
    confidence: float,
    source_descriptor: str,
    source_provenance_class: int = 2,
    source_commitment: bytes | str | None = None,
    source_content: bytes | str | None = None,
    status: str = "active",
    contradiction_ids: Sequence[str | uuid.UUID] = (),
    valid_from: str | datetime.datetime | None = None,
    valid_to: str | datetime.datetime | None = None,
    predecessor_id: str | uuid.UUID | None = None,
) -> tuple[str, str]:
    if source_commitment is not None:
        src_comm = _as_hash32(source_commitment)
    elif source_content is not None:
        src_comm = compute_source_content_commitment(source_descriptor, source_content)
    else:
        src_comm = hash_length_delimited([b"acta:source:v1", source_descriptor.encode("utf-8")])
    digest = compute_claim_client_intent_hash(
        tenant_id,
        scope,
        subject,
        predicate,
        object_val,
        object_type,
        confidence,
        source_provenance_class,
        source_descriptor,
        src_comm,
        status,
        contradiction_ids,
        valid_from,
        valid_to,
        predecessor_id,
    )
    return sign_client_content_hash(private_key_seed, digest)


def compute_retract_claim_client_intent_hash(
    tenant_id: str,
    claim_id: str | uuid.UUID,
    reason: str,
) -> bytes:
    uid = claim_id if isinstance(claim_id, uuid.UUID) else uuid.UUID(str(claim_id))
    return hash_length_delimited(
        [
            b"acta:retract_client_sig:v1",
            tenant_id.encode("utf-8"),
            uid.bytes,
            reason.encode("utf-8"),
        ]
    )


def sign_retract_claim_client_intent(
    private_key_seed: bytes | str,
    *,
    tenant_id: str,
    claim_id: str | uuid.UUID,
    reason: str,
) -> tuple[str, str]:
    digest = compute_retract_claim_client_intent_hash(tenant_id, claim_id, reason)
    return sign_client_content_hash(private_key_seed, digest)


def is_v2_state_schema(schema_version: str) -> bool:
    return str(schema_version) in (
        "acta-context-bundle/v2",
        "acta-state-rebuild-archive/v2",
        "v2",
    )


def canonical_bundle_schema_for_state(schema_version: str) -> str:
    return SCHEMA_VERSION_V2 if is_v2_state_schema(schema_version) else SCHEMA_VERSION_V1


def compute_sub_commitment(hashes: Sequence[bytes | str]) -> bytes:
    sorted_raw = sorted(_as_hash32(h) for h in hashes)
    return hash_length_delimited(sorted_raw)


def compute_sub_commitment_v2(hashes: Sequence[bytes | str]) -> bytes:
    sorted_raw = sorted(_as_hash32(h) for h in hashes)
    return hash_length_delimited([b"acta:sub_commitment:v2", *sorted_raw])


def compute_sub_commitment_for_schema(
    schema_version: str,
    hashes: Sequence[bytes | str],
) -> bytes:
    if is_v2_state_schema(schema_version):
        return compute_sub_commitment_v2(hashes)
    return compute_sub_commitment(hashes)


def compute_state_commitment(
    schema_version: str,
    tenant_id: str,
    scope: str,
    intent_root: bytes | str,
    knowledge_root: bytes | str,
    memory_root: bytes | str,
    permission_root: bytes | str,
) -> bytes:
    sv = str(schema_version)
    if is_v2_state_schema(sv):
        bundle_schema = (
            SCHEMA_VERSION_V2
            if sv in ("acta-state-rebuild-archive/v2", "v2")
            else sv
        )
        return hash_length_delimited(
            [
                b"acta:state:v2",
                bundle_schema.encode("utf-8"),
                tenant_id.encode("utf-8"),
                scope.encode("utf-8"),
                _as_hash32(intent_root),
                _as_hash32(knowledge_root),
                _as_hash32(memory_root),
                _as_hash32(permission_root),
            ]
        )
    bundle_schema = (
        SCHEMA_VERSION_V1
        if sv in ("acta-state-rebuild-archive/v1", "v1")
        else sv
    )
    return hash_length_delimited(
        [
            bundle_schema.encode("utf-8"),
            tenant_id.encode("utf-8"),
            scope.encode("utf-8"),
            _as_hash32(intent_root),
            _as_hash32(knowledge_root),
            _as_hash32(memory_root),
            _as_hash32(permission_root),
        ]
    )


def compute_erasable_claim_commitment(
    claim_id: str | uuid.UUID,
    salt_32: bytes | str,
    object_val: Any,
    source_commitment: bytes | str,
) -> bytes:
    uid = claim_id if isinstance(claim_id, uuid.UUID) else uuid.UUID(str(claim_id))
    return hash_length_delimited(
        [
            b"acta:erasable_claim:v1",
            uid.bytes,
            _as_hash32(salt_32),
            to_canonical_bytes(object_val),
            _as_hash32(source_commitment),
        ]
    )


def compute_task_dependency_commitment(
    tenant_id: str,
    scope: str,
    permission_root: bytes | str,
    intent_root: bytes | str,
    selected_memory_root: bytes | str,
    relevant_knowledge_root: bytes | str,
) -> bytes:
    return hash_length_delimited(
        [
            b"acta:cache_dep_root:v1",
            tenant_id.encode("utf-8"),
            scope.encode("utf-8"),
            _as_hash32(permission_root),
            _as_hash32(intent_root),
            _as_hash32(selected_memory_root),
            _as_hash32(relevant_knowledge_root),
        ]
    )


def compute_query_text_hash(query_text: str) -> bytes:
    return hash_length_delimited([b"acta:query:v1", query_text.encode("utf-8")])


def compute_answer_text_hash(answer_text: str) -> bytes:
    return hash_length_delimited([b"acta:answer:v1", answer_text.encode("utf-8")])


def compute_answer_cache_client_intent_hash(
    tenant_id: str,
    scope: str,
    task_id: str,
    query_hash: bytes | str,
    source_bundle_hash: bytes | str,
    state_commitment: bytes | str,
    answer_hash: bytes | str,
) -> bytes:
    return hash_length_delimited(
        [
            b"acta:answer_client_sig:v1",
            tenant_id.encode("utf-8"),
            scope.encode("utf-8"),
            task_id.encode("utf-8"),
            _as_hash32(query_hash),
            _as_hash32(source_bundle_hash),
            _as_hash32(state_commitment),
            _as_hash32(answer_hash),
        ]
    )

def sign_answer_cache_client_intent(
    private_key_seed_hex: str | bytes,
    *,
    tenant_id: str,
    scope: str,
    task_id: str,
    query_text: str,
    source_bundle_hash: bytes | str,
    state_commitment: bytes | str,
    answer_text: str,
) -> tuple[str, str]:
    """Computes `b"acta:answer_client_sig:v1"` intent digest and returns `(signature_hex, public_key_hex)`."""
    seed = bytes.fromhex(private_key_seed_hex) if isinstance(private_key_seed_hex, str) else bytes(private_key_seed_hex)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    q_hash = compute_query_text_hash(query_text)
    a_hash = compute_answer_text_hash(answer_text)
    digest = compute_answer_cache_client_intent_hash(
        tenant_id,
        scope,
        task_id,
        q_hash,
        source_bundle_hash,
        state_commitment,
        a_hash,
    )
    sig = sk.sign(digest)
    return sig.hex(), pk_bytes.hex()


sign_answer_client_intent = sign_answer_cache_client_intent



def _normalize_write_summary(ws: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "write_domain": str(ws.get("write_domain") or "acta:write_event:v1"),
        "operation": str(ws["operation"]),
        "item_id": str(uuid.UUID(str(ws["item_id"]))).lower(),
        "scope": str(ws["scope"]),
        "version": int(ws["version"]),
        "content_hash": _as_hash32(ws["content_hash"]).hex(),
        "written_by": str(ws["written_by"]),
        "writer_auth_kind": str(ws["writer_auth_kind"]),
        "record_snapshot": ws["record_snapshot"],
    }
    if ws.get("predecessor_id") is not None:
        out["predecessor_id"] = str(uuid.UUID(str(ws["predecessor_id"]))).lower()
    if ws.get("client_public_key") is not None:
        out["client_public_key"] = _as_hash32(ws["client_public_key"]).hex()
    if ws.get("client_signature") is not None:
        sig_raw = (
            bytes.fromhex(ws["client_signature"])
            if isinstance(ws["client_signature"], str)
            else bytes(ws["client_signature"])
        )
        out["client_signature"] = sig_raw.hex()
    if ws.get("retraction_reason") is not None:
        out["retraction_reason"] = str(ws["retraction_reason"])
    return out


def compute_write_summary_commitment(ws: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_write_summary(ws))
    return hash_length_delimited([b"acta:write_event:v1", canonical])


def _normalize_answer_cache_summary(acs: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "cache_domain": str(acs.get("cache_domain") or "acta:answer_cache:v1"),
        "cache_id": str(uuid.UUID(str(acs["cache_id"]))).lower(),
        "scope": str(acs["scope"]),
        "task_id": str(acs["task_id"]),
        "query_hash": _as_hash32(acs["query_hash"]).hex(),
        "source_bundle_hash": _as_hash32(acs["source_bundle_hash"]).hex(),
        "state_commitment": _as_hash32(acs["state_commitment"]).hex(),
        "answer_hash": _as_hash32(acs["answer_hash"]).hex(),
        "cached_by": str(acs["cached_by"]),
        "cacher_auth_kind": str(acs["cacher_auth_kind"]),
    }
    if acs.get("event_kind") is not None:
        out["event_kind"] = str(acs["event_kind"])
    if acs.get("validity_mode") is not None:
        out["validity_mode"] = str(acs["validity_mode"])
    if acs.get("task_dependency_commitment") is not None:
        out["task_dependency_commitment"] = _as_hash32(acs["task_dependency_commitment"]).hex()
    dep_ids = acs.get("dependency_ids")
    if dep_ids:
        out["dependency_ids"] = [str(uuid.UUID(str(u))).lower() for u in dep_ids]
    dep_ids = acs.get("dependency_ids")
    if dep_ids:
        out["dependency_ids"] = [str(uuid.UUID(str(u))).lower() for u in dep_ids]
    dep_ids = acs.get("dependency_ids")
    if dep_ids:
        out["dependency_ids"] = [str(uuid.UUID(str(u))).lower() for u in dep_ids]
    dep_ids = acs.get("dependency_ids")
    if dep_ids:
        out["dependency_ids"] = [str(uuid.UUID(str(u))).lower() for u in dep_ids]
    dep_ids = acs.get("dependency_ids")
    if dep_ids:
        out["dependency_ids"] = [str(uuid.UUID(str(u))).lower() for u in dep_ids]
    if acs.get("client_public_key") is not None:
        out["client_public_key"] = _as_hash32(acs["client_public_key"]).hex()
    if acs.get("client_signature") is not None:
        sig_raw = (
            bytes.fromhex(acs["client_signature"])
            if isinstance(acs["client_signature"], str)
            else bytes(acs["client_signature"])
        )
        out["client_signature"] = sig_raw.hex()
    if acs.get("expires_at") is not None:
        out["expires_at"] = str(acs["expires_at"])
    if acs.get("invalidation_reason") is not None:
        out["invalidation_reason"] = str(acs["invalidation_reason"])
    if acs.get("invalidated_by") is not None:
        out["invalidated_by"] = str(acs["invalidated_by"])
    if acs.get("invalidator_auth_kind") is not None:
        out["invalidator_auth_kind"] = str(acs["invalidator_auth_kind"])
    if acs.get("observed_state_commitment") is not None:
        out["observed_state_commitment"] = _as_hash32(acs["observed_state_commitment"]).hex()
    if acs.get("observed_dependency_commitment") is not None:
        out["observed_dependency_commitment"] = _as_hash32(
            acs["observed_dependency_commitment"]
        ).hex()
    return out


def _normalize_witness_reg_summary(wreg: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "witness_id": str(wreg["witness_id"]),
        "public_key": _as_hash32(wreg["public_key"]).hex(),
        "registered_by": str(wreg["registered_by"]),
        "registration_domain": str(wreg["registration_domain"]),
        "registration_blake3_preimage_hex": str(wreg["registration_blake3_preimage_hex"]),
    }
    if wreg.get("description") is not None:
        out["description"] = str(wreg["description"])
    return out


def _normalize_witness_revoke_summary(wrev: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "witness_id": str(wrev["witness_id"]),
        "public_key": _as_hash32(wrev["public_key"]).hex(),
        "revoked_by": str(wrev["revoked_by"]),
        "revocation_mode": str(wrev.get("revocation_mode") or "compromise"),
        "reason": str(wrev["reason"]),
        "revocation_domain": str(wrev["revocation_domain"]),
        "revocation_blake3_preimage_hex": str(wrev["revocation_blake3_preimage_hex"]),
    }
    if wrev.get("effective_from_tree_size") is not None:
        out["effective_from_tree_size"] = int(wrev["effective_from_tree_size"])
    return out


def _normalize_host_key_rotation_summary(rot: Mapping[str, Any]) -> dict[str, Any]:
    new_sig_raw = (
        bytes.fromhex(rot["new_key_signature"])
        if isinstance(rot["new_key_signature"], str)
        else bytes(rot["new_key_signature"])
    )
    if len(new_sig_raw) != 64:
        raise ValueError("new_key_signature must be 64 bytes")
    out: dict[str, Any] = {
        "rotation_domain": str(rot.get("rotation_domain") or HOST_KEY_ROTATE_DOMAIN_V1),
        "old_public_key": _as_hash32(rot["old_public_key"]).hex(),
        "new_public_key": _as_hash32(rot["new_public_key"]).hex(),
        "effective_from_seq": int(rot["effective_from_seq"]),
        "rotation_mode": str(rot["rotation_mode"]),
        "reason": str(rot["reason"]),
        "rotated_by": str(rot["rotated_by"]),
        "new_key_signature": new_sig_raw.hex(),
    }
    if rot.get("compromised_from_seq") is not None:
        out["compromised_from_seq"] = int(rot["compromised_from_seq"])
    if rot.get("old_key_signature") is not None:
        old_sig_raw = (
            bytes.fromhex(rot["old_key_signature"])
            if isinstance(rot["old_key_signature"], str)
            else bytes(rot["old_key_signature"])
        )
        if len(old_sig_raw) != 64:
            raise ValueError("old_key_signature must be 64 bytes")
        out["old_key_signature"] = old_sig_raw.hex()
    return out


def compute_host_key_rotation_commitment(rot: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_host_key_rotation_summary(rot))
    return hash_length_delimited([b"acta:host_key_rotate:v1", canonical])


def host_key_rotation_signing_digest(
    domain: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    dom_bytes = domain.encode("utf-8") if isinstance(domain, str) else bytes(domain)
    return hash_length_delimited(
        [
            dom_bytes,
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(effective_from_seq)),
            _as_hash32(old_public_key),
            _as_hash32(new_public_key),
            rotation_mode.encode("utf-8"),
            reason.encode("utf-8"),
        ]
    )


def sign_host_key_rotation_old(
    old_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(old_private_key_seed)
        if isinstance(old_private_key_seed, str)
        else bytes(old_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def sign_host_key_rotation_new(
    new_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(new_private_key_seed)
        if isinstance(new_private_key_seed, str)
        else bytes(new_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def verify_host_key_rotation_old(
    old_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(old_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def verify_host_key_rotation_new(
    new_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(new_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def verify_host_key_rotation_new(
    new_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(new_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def _normalize_host_key_rotation_summary(rot: Mapping[str, Any]) -> dict[str, Any]:
    new_sig_raw = (
        bytes.fromhex(rot["new_key_signature"])
        if isinstance(rot["new_key_signature"], str)
        else bytes(rot["new_key_signature"])
    )
    if len(new_sig_raw) != 64:
        raise ValueError("new_key_signature must be 64 bytes")
    out: dict[str, Any] = {
        "rotation_domain": str(rot.get("rotation_domain") or HOST_KEY_ROTATE_DOMAIN_V1),
        "old_public_key": _as_hash32(rot["old_public_key"]).hex(),
        "new_public_key": _as_hash32(rot["new_public_key"]).hex(),
        "effective_from_seq": int(rot["effective_from_seq"]),
        "rotation_mode": str(rot["rotation_mode"]),
        "reason": str(rot["reason"]),
        "rotated_by": str(rot["rotated_by"]),
        "new_key_signature": new_sig_raw.hex(),
    }
    if rot.get("compromised_from_seq") is not None:
        out["compromised_from_seq"] = int(rot["compromised_from_seq"])
    if rot.get("old_key_signature") is not None:
        old_sig_raw = (
            bytes.fromhex(rot["old_key_signature"])
            if isinstance(rot["old_key_signature"], str)
            else bytes(rot["old_key_signature"])
        )
        if len(old_sig_raw) != 64:
            raise ValueError("old_key_signature must be 64 bytes")
        out["old_key_signature"] = old_sig_raw.hex()
    return out


def compute_host_key_rotation_commitment(rot: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_host_key_rotation_summary(rot))
    return hash_length_delimited([b"acta:host_key_rotate:v1", canonical])


def host_key_rotation_signing_digest(
    domain: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    dom_bytes = domain.encode("utf-8") if isinstance(domain, str) else bytes(domain)
    return hash_length_delimited(
        [
            dom_bytes,
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(effective_from_seq)),
            _as_hash32(old_public_key),
            _as_hash32(new_public_key),
            rotation_mode.encode("utf-8"),
            reason.encode("utf-8"),
        ]
    )


def sign_host_key_rotation_old(
    old_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(old_private_key_seed)
        if isinstance(old_private_key_seed, str)
        else bytes(old_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def sign_host_key_rotation_new(
    new_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(new_private_key_seed)
        if isinstance(new_private_key_seed, str)
        else bytes(new_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def verify_host_key_rotation_old(
    old_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(old_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def verify_host_key_rotation_new(
    new_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(new_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def _normalize_host_key_rotation_summary(rot: Mapping[str, Any]) -> dict[str, Any]:
    new_sig_raw = (
        bytes.fromhex(rot["new_key_signature"])
        if isinstance(rot["new_key_signature"], str)
        else bytes(rot["new_key_signature"])
    )
    if len(new_sig_raw) != 64:
        raise ValueError("new_key_signature must be 64 bytes")
    out: dict[str, Any] = {
        "rotation_domain": str(rot.get("rotation_domain") or HOST_KEY_ROTATE_DOMAIN_V1),
        "old_public_key": _as_hash32(rot["old_public_key"]).hex(),
        "new_public_key": _as_hash32(rot["new_public_key"]).hex(),
        "effective_from_seq": int(rot["effective_from_seq"]),
        "rotation_mode": str(rot["rotation_mode"]),
        "reason": str(rot["reason"]),
        "rotated_by": str(rot["rotated_by"]),
        "new_key_signature": new_sig_raw.hex(),
    }
    if rot.get("compromised_from_seq") is not None:
        out["compromised_from_seq"] = int(rot["compromised_from_seq"])
    if rot.get("old_key_signature") is not None:
        old_sig_raw = (
            bytes.fromhex(rot["old_key_signature"])
            if isinstance(rot["old_key_signature"], str)
            else bytes(rot["old_key_signature"])
        )
        if len(old_sig_raw) != 64:
            raise ValueError("old_key_signature must be 64 bytes")
        out["old_key_signature"] = old_sig_raw.hex()
    return out


def compute_host_key_rotation_commitment(rot: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_host_key_rotation_summary(rot))
    return hash_length_delimited([b"acta:host_key_rotate:v1", canonical])


def host_key_rotation_signing_digest(
    domain: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    dom_bytes = domain.encode("utf-8") if isinstance(domain, str) else bytes(domain)
    return hash_length_delimited(
        [
            dom_bytes,
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(effective_from_seq)),
            _as_hash32(old_public_key),
            _as_hash32(new_public_key),
            rotation_mode.encode("utf-8"),
            reason.encode("utf-8"),
        ]
    )


def sign_host_key_rotation_old(
    old_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(old_private_key_seed)
        if isinstance(old_private_key_seed, str)
        else bytes(old_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def sign_host_key_rotation_new(
    new_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(new_private_key_seed)
        if isinstance(new_private_key_seed, str)
        else bytes(new_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def verify_host_key_rotation_old(
    old_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(old_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def verify_host_key_rotation_new(
    new_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(new_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def _normalize_host_key_rotation_summary(rot: Mapping[str, Any]) -> dict[str, Any]:
    new_sig_raw = (
        bytes.fromhex(rot["new_key_signature"])
        if isinstance(rot["new_key_signature"], str)
        else bytes(rot["new_key_signature"])
    )
    if len(new_sig_raw) != 64:
        raise ValueError("new_key_signature must be 64 bytes")
    out: dict[str, Any] = {
        "rotation_domain": str(rot.get("rotation_domain") or HOST_KEY_ROTATE_DOMAIN_V1),
        "old_public_key": _as_hash32(rot["old_public_key"]).hex(),
        "new_public_key": _as_hash32(rot["new_public_key"]).hex(),
        "effective_from_seq": int(rot["effective_from_seq"]),
        "rotation_mode": str(rot["rotation_mode"]),
        "reason": str(rot["reason"]),
        "rotated_by": str(rot["rotated_by"]),
        "new_key_signature": new_sig_raw.hex(),
    }
    if rot.get("compromised_from_seq") is not None:
        out["compromised_from_seq"] = int(rot["compromised_from_seq"])
    if rot.get("old_key_signature") is not None:
        old_sig_raw = (
            bytes.fromhex(rot["old_key_signature"])
            if isinstance(rot["old_key_signature"], str)
            else bytes(rot["old_key_signature"])
        )
        if len(old_sig_raw) != 64:
            raise ValueError("old_key_signature must be 64 bytes")
        out["old_key_signature"] = old_sig_raw.hex()
    return out


def compute_host_key_rotation_commitment(rot: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_host_key_rotation_summary(rot))
    return hash_length_delimited([b"acta:host_key_rotate:v1", canonical])


def host_key_rotation_signing_digest(
    domain: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    dom_bytes = domain.encode("utf-8") if isinstance(domain, str) else bytes(domain)
    return hash_length_delimited(
        [
            dom_bytes,
            tenant_id.encode("utf-8"),
            struct.pack("<q", int(effective_from_seq)),
            _as_hash32(old_public_key),
            _as_hash32(new_public_key),
            rotation_mode.encode("utf-8"),
            reason.encode("utf-8"),
        ]
    )


def sign_host_key_rotation_old(
    old_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(old_private_key_seed)
        if isinstance(old_private_key_seed, str)
        else bytes(old_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def sign_host_key_rotation_new(
    new_private_key_seed: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
) -> bytes:
    seed = (
        bytes.fromhex(new_private_key_seed)
        if isinstance(new_private_key_seed, str)
        else bytes(new_private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return sk.sign(msg)


def verify_host_key_rotation_old(
    old_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(old_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_old_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def verify_host_key_rotation_new(
    new_pubkey: bytes | str,
    tenant_id: str,
    effective_from_seq: int,
    old_public_key: bytes | str,
    new_public_key: bytes | str,
    rotation_mode: str,
    reason: str,
    signature: bytes | str,
) -> bool:
    pk_raw = _as_hash32(new_pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    msg = host_key_rotation_signing_digest(
        b"acta:host_key_rotate_new_sig:v1",
        tenant_id,
        effective_from_seq,
        old_public_key,
        new_public_key,
        rotation_mode,
        reason,
    )
    return verify_ed25519_strict(pk_raw, msg, sig_raw)


def rebuild_archive_header_preimage_bytes(
    schema_version: str,
    tenant_id: str,
    scope: str,
    up_to_seq: int,
    evaluated_at: int | str | datetime.datetime,
    permission_root: bytes | str,
) -> bytes:
    eval_micros = evaluated_at if isinstance(evaluated_at, int) else parse_rfc3339_micros(evaluated_at)
    return encode_length_delimited(
        [
            b"acta:rebuild_header:v1",
            schema_version.encode("utf-8"),
            tenant_id.encode("utf-8"),
            scope.encode("utf-8"),
            struct.pack("<q", int(up_to_seq)),
            struct.pack("<q", eval_micros),
            _as_hash32(permission_root),
        ]
    )


def compute_rebuild_archive_header_hash(
    schema_version: str,
    tenant_id: str,
    scope: str,
    up_to_seq: int,
    evaluated_at: int | str | datetime.datetime,
    permission_root: bytes | str,
) -> bytes:
    return blake3_hash(
        [
            rebuild_archive_header_preimage_bytes(
                schema_version,
                tenant_id,
                scope,
                up_to_seq,
                evaluated_at,
                permission_root,
            )
        ]
    )


def rebuild_header_signing_preimage(tenant: str, header_hash: bytes | str) -> bytes:
    return hash_length_delimited(
        [
            b"acta:rebuild_sig:v1",
            tenant.encode("utf-8"),
            _as_hash32(header_hash),
        ]
    )


def sign_rebuild_archive_header(
    private_key_seed: bytes | str,
    tenant: str,
    header_hash: bytes | str,
) -> bytes:
    seed = (
        bytes.fromhex(private_key_seed)
        if isinstance(private_key_seed, str)
        else bytes(private_key_seed)
    )
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.sign(rebuild_header_signing_preimage(tenant, header_hash))


def verify_rebuild_archive_header_signature(
    pubkey: bytes | str,
    tenant: str,
    header_hash: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    return verify_ed25519_strict(
        pk_raw,
        rebuild_header_signing_preimage(tenant, header_hash),
        sig_raw,
    )


def _json_value_family_tag(val: Any) -> int:
    if val is None:
        return 0
    if isinstance(val, bool):
        return 1
    if isinstance(val, (int, float)):
        return 2
    if isinstance(val, str):
        return 3
    if isinstance(val, list):
        return 4
    if isinstance(val, Mapping):
        return 5
    return 6


def claims_share_winning_value_bucket(
    winner: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> bool:
    if _json_value_family_tag(winner["object_val"]) != _json_value_family_tag(candidate["object_val"]):
        return False
    return to_canonical_bytes(winner["object_val"]) == to_canonical_bytes(candidate["object_val"])


def _round_9_rust(val: float) -> float:
    scaled = val * 1_000_000_000.0
    rounded = math.floor(scaled + 0.5) if scaled >= 0.0 else math.ceil(scaled - 0.5)
    return rounded / 1_000_000_000.0


def recompute_winning_bucket_corroboration(
    bucket_claims: Sequence[Mapping[str, Any]],
    damping: float,
) -> tuple[int, list[str], float]:
    if not bucket_claims:
        raise ValueError("winning value bucket cannot be empty")
    sorted_claims = sorted(
        bucket_claims,
        key=lambda c: (
            -float(c["confidence"]),
            -int(c["source_provenance_class"]),
            -parse_rfc3339_micros(c["created_at"]),
            -int(c["version"]),
            uuid.UUID(str(c["id"])).bytes,
        ),
    )
    seen_sources: set[str] = set()
    for c in sorted_claims:
        sd = str(c["source_descriptor"])
        if sd in seen_sources:
            raise ValueError(f"duplicate source_descriptor '{sd}' inside corroborating value bucket")
        seen_sources.add(sd)
    lead_conf = float(sorted_claims[0]["confidence"])
    if len(sorted_claims) == 1:
        eff = _round_9_rust(lead_conf)
    else:
        unconvinced = 1.0
        for c in sorted_claims[1:]:
            factor = max(0.0, min(1.0, 1.0 - float(damping) * float(c["confidence"])))
            unconvinced *= factor
        eff = _round_9_rust(min(lead_conf + (1.0 - lead_conf) * (1.0 - unconvinced), 0.9999))
    return len(sorted_claims), [str(c["source_descriptor"]) for c in sorted_claims], eff


def compute_answer_cache_summary_commitment(acs: Mapping[str, Any]) -> bytes:
    canonical = to_canonical_bytes(_normalize_answer_cache_summary(acs))
    return hash_length_delimited([b"acta:answer_cache:v1", canonical])


def answer_cache_signing_preimage(
    tenant: str,
    evidence_seq_num: int,
    cache_commitment: bytes | str,
) -> bytes:
    return hash_length_delimited(
        [
            b"acta:answer_cache_sig:v1",
            tenant.encode("utf-8"),
            struct.pack("<q", int(evidence_seq_num)),
            _as_hash32(cache_commitment),
        ]
    )


def verify_answer_cache_signature(
    pubkey: bytes | str,
    tenant: str,
    evidence_seq_num: int,
    cache_commitment: bytes | str,
    signature: bytes | str,
) -> bool:
    pk_raw = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
    sig_raw = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
    digest = answer_cache_signing_preimage(tenant, evidence_seq_num, cache_commitment)
    return verify_ed25519_strict(pk_raw, digest, sig_raw)


def _verify_auth_kind_and_sig_presence(
    label: str,
    auth_kind: str,
    has_sig: bool,
    has_pk: bool,
) -> None:
    if has_sig != has_pk:
        raise ValueError(f"{label} inconsistent client_signature / client_public_key presence")
    if auth_kind == "ed25519_client_sig":
        if not has_sig:
            raise ValueError(
                f"{label} auth_kind='ed25519_client_sig' requires client_signature + client_public_key"
            )
    elif auth_kind in ("oauth_github_principal", "tenant_session", "master_admin"):
        if has_sig:
            raise ValueError(f"{label} auth_kind='{auth_kind}' cannot coexist with client_signature")
    else:
        raise ValueError(f"{label} unsupported auth_kind '{auth_kind}'")


def _verify_object_author_signature(obj: Mapping[str, Any], label: str) -> None:
    csig = obj.get("client_signature")
    cpk = obj.get("client_public_key")
    if csig is None and cpk is None:
        return
    if csig is None and cpk is not None:
        raise ValueError(f"{label} has client_public_key without client_signature")
    if csig is not None and cpk is not None:
        sig_raw = bytes.fromhex(csig) if isinstance(csig, str) else bytes(csig)
        pk_raw = _as_hash32(cpk)
        intent = compute_object_client_intent_hash(
            str(obj["tenant_id"]),
            str(obj["obj_type"]),
            str(obj["scope"]),
            str(obj["lifecycle_status"]),
            int(obj["priority"]),
            float(obj["importance"]),
            list(obj.get("tags", [])),
            obj["body"],
            obj.get("predecessor_id"),
        )
        ok_intent = verify_ed25519_strict(pk_raw, intent, sig_raw)
        ok_full = verify_ed25519_strict(pk_raw, _as_hash32(obj["content_hash"]), sig_raw)
        if not ok_intent and not ok_full:
            raise ValueError(f"client Ed25519 signature verification failed on {label}")


def _verify_claim_author_signature(
    claim: Mapping[str, Any],
    retraction_reason: str | None,
    label: str,
) -> None:
    csig = claim.get("client_signature")
    cpk = claim.get("client_public_key")
    if csig is None and cpk is None:
        return
    if (csig is not None) != (cpk is not None):
        raise ValueError(f"{label} inconsistent client_signature / client_public_key presence")
    assert csig is not None and cpk is not None
    sig_raw = bytes.fromhex(csig) if isinstance(csig, str) else bytes(csig)
    pk_raw = _as_hash32(cpk)
    intent = compute_claim_client_intent_hash(
        str(claim["tenant_id"]),
        str(claim["scope"]),
        str(claim["subject"]),
        str(claim["predicate"]),
        claim["object_val"],
        str(claim["object_type"]),
        float(claim["confidence"]),
        int(claim["source_provenance_class"]),
        str(claim["source_descriptor"]),
        claim["source_commitment"],
        str(claim["status"]),
        list(claim.get("contradiction_ids", [])),
        claim.get("valid_from"),
        claim.get("valid_to"),
        claim.get("predecessor_id"),
    )
    ok_intent = verify_ed25519_strict(pk_raw, intent, sig_raw)
    ok_full = verify_ed25519_strict(pk_raw, _as_hash32(claim["content_hash"]), sig_raw)
    eff_reason = retraction_reason or claim.get("retraction_reason")
    ok_retract = False
    if (
        str(claim["status"]) == "revoked"
        and eff_reason is not None
        and claim.get("predecessor_id") is not None
    ):
        r_hash = compute_retract_claim_client_intent_hash(
            str(claim["tenant_id"]),
            claim["predecessor_id"],
            str(eff_reason),
        )
        ok_retract = verify_ed25519_strict(pk_raw, r_hash, sig_raw)
    if not ok_intent and not ok_full and not ok_retract:
        raise ValueError(f"client Ed25519 signature verification failed on {label}")


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

    return blake3_hash([_override_attestation_preimage_bytes(att)])


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
    write_summary: Mapping[str, Any] | None = None,
    answer_cache_summary: Mapping[str, Any] | None = None,
    witness_reg_summary: Mapping[str, Any] | None = None,
    witness_revoke_summary: Mapping[str, Any] | None = None,
    witness_in_v3: bool = False,
    host_key_rotation_summary: Mapping[str, Any] | None = None,
) -> bytes:
    prev_raw = _as_hash32(prev_hash)
    created_micros = (
        created_at if isinstance(created_at, int) else parse_rfc3339_micros(created_at)
    )
    if host_key_rotation_summary is not None:
        rot_tagged = _encode_opt_jcs(_normalize_host_key_rotation_summary(host_key_rotation_summary))
        return hash_length_delimited(
            [
                b"acta:evidence_event:v3",
                tenant_id.encode("utf-8"),
                struct.pack("<q", int(seq_num)),
                prev_raw,
                _encode_opt_hash32(bundle_hash),
                _encode_opt_hash32(state_commitment),
                policy_result.encode("utf-8"),
                struct.pack("<q", created_micros),
                b"\x00",
                b"\x00",
                b"\x00",
                b"\x00",
                rot_tagged,
            ]
        )
    if write_summary is not None or answer_cache_summary is not None:
        write_tagged = _encode_opt_jcs(
            _normalize_write_summary(write_summary) if write_summary is not None else None
        )
        cache_tagged = _encode_opt_jcs(
            _normalize_answer_cache_summary(answer_cache_summary)
            if answer_cache_summary is not None
            else None
        )
        return hash_length_delimited(
            [
                b"acta:evidence_event:v3",
                tenant_id.encode("utf-8"),
                struct.pack("<q", int(seq_num)),
                prev_raw,
                _encode_opt_hash32(bundle_hash),
                _encode_opt_hash32(state_commitment),
                policy_result.encode("utf-8"),
                struct.pack("<q", created_micros),
                write_tagged,
                cache_tagged,
            ]
        )
    if witness_in_v3 and (witness_reg_summary is not None or witness_revoke_summary is not None):
        wreg_tagged = _encode_opt_jcs(
            _normalize_witness_reg_summary(witness_reg_summary)
            if witness_reg_summary is not None
            else None
        )
        wrev_tagged = _encode_opt_jcs(
            _normalize_witness_revoke_summary(witness_revoke_summary)
            if witness_revoke_summary is not None
            else None
        )
        return hash_length_delimited(
            [
                b"acta:evidence_event:v3",
                tenant_id.encode("utf-8"),
                struct.pack("<q", int(seq_num)),
                prev_raw,
                _encode_opt_hash32(bundle_hash),
                _encode_opt_hash32(state_commitment),
                policy_result.encode("utf-8"),
                struct.pack("<q", created_micros),
                b"\x00",
                b"\x00",
                wreg_tagged,
                wrev_tagged,
            ]
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
def legacy_blake3_merkle_empty_root() -> bytes:
    return hash_length_delimited([b"acta:merkle_empty:v1"])


def legacy_blake3_merkle_leaf_hash(seq_num: int, event_hash: bytes | str) -> bytes:
    return hash_length_delimited(
        [b"acta:merkle_leaf:v1", struct.pack("<q", int(seq_num)), _as_hash32(event_hash)]
    )


def legacy_blake3_merkle_node_hash(left: bytes | str, right: bytes | str) -> bytes:
    return hash_length_delimited(
        [b"acta:merkle_node:v1", _as_hash32(left), _as_hash32(right)]
    )


def compute_legacy_blake3_merkle_root_from_leaves(leaves: Sequence[bytes | str]) -> bytes:
    norm = [_as_hash32(x) for x in leaves]
    n = len(norm)
    if n == 0:
        return legacy_blake3_merkle_empty_root()
    if n == 1:
        return norm[0]
    k = _largest_pow2_lt(n)
    left = compute_legacy_blake3_merkle_root_from_leaves(norm[:k])
    right = compute_legacy_blake3_merkle_root_from_leaves(norm[k:])
    return legacy_blake3_merkle_node_hash(left, right)


def compute_legacy_blake3_merkle_root_from_events(
    events: Sequence[tuple[int, bytes | str]],
) -> bytes:
    leaves = [legacy_blake3_merkle_leaf_hash(seq, ev) for seq, ev in events]
    return compute_legacy_blake3_merkle_root_from_leaves(leaves)


def merkle_empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def merkle_leaf_hash(seq_num: int, event_hash: bytes | str) -> bytes:
    _ = seq_num
    return hashlib.sha256(b"\x00" + _as_hash32(event_hash)).digest()


def merkle_node_hash(left: bytes | str, right: bytes | str) -> bytes:
    return hashlib.sha256(b"\x01" + _as_hash32(left) + _as_hash32(right)).digest()


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
    wmeta = entry.get("write_summary")
    acmeta = entry.get("answer_cache_summary")
    rotmeta = entry.get("host_key_rotation_summary")
    rotmeta = entry.get("host_key_rotation_summary")
    rotmeta = entry.get("host_key_rotation_summary")
    rotmeta = entry.get("host_key_rotation_summary")
    rotmeta = entry.get("host_key_rotation_summary")

    if rmeta is not None:
        if entry.get("bundle_hash") is not None or wmeta is not None or acmeta is not None:
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

    witness_in_v3 = (
        (entry.get("witness_reg_summary") is not None or entry.get("witness_revoke_summary") is not None)
        and entry.get("event_domain") == "acta:evidence_event:v3"
    )
    if wmeta is not None or acmeta is not None or witness_in_v3 or rotmeta is not None:
        expected_ev_domain = "acta:evidence_event:v3"
    elif rmeta is not None or ometa is not None:
        expected_ev_domain = "acta:evidence_event:v2"
    else:
        expected_ev_domain = "acta:evidence_event:v1"
    declared_ev_domain = entry.get("event_domain")
    if declared_ev_domain is not None and str(declared_ev_domain) != expected_ev_domain:
        raise ValueError(
            f"tampered event_domain at seq_num={entry['seq_num']}: declared '{declared_ev_domain}' != expected '{expected_ev_domain}'"
        )

    if wmeta is not None:
        if (
            entry.get("bundle_hash") is not None
            or rmeta is not None
            or ometa is not None
            or acmeta is not None
            or entry.get("witness_reg_summary") is not None
            or entry.get("witness_revoke_summary") is not None
        ):
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: write_summary cannot coexist with other entry payloads"
            )
        if str(wmeta.get("write_domain") or "acta:write_event:v1") != "acta:write_event:v1":
            raise ValueError(f"unsupported write_domain at seq_num={entry['seq_num']}")
        lbl = f"write_summary[seq_num={entry['seq_num']}, item_id={wmeta.get('item_id')}]"
        _verify_auth_kind_and_sig_presence(
            lbl,
            str(wmeta["writer_auth_kind"]).strip(),
            wmeta.get("client_signature") is not None,
            wmeta.get("client_public_key") is not None,
        )
        snap = dict(wmeta["record_snapshot"])
        op = str(wmeta["operation"])
        if op in ("ingest_object", "legacy_import_object"):
            if (
                str(snap["tenant_id"]) != str(entry["tenant_id"])
                or str(uuid.UUID(str(snap["id"]))).lower() != str(uuid.UUID(str(wmeta["item_id"]))).lower()
                or str(snap["scope"]) != str(wmeta["scope"])
                or int(snap["version"]) != int(wmeta["version"])
            ):
                raise ValueError(f"{lbl} metadata mismatch against record_snapshot")
            rec_h = compute_object_content_hash(snap).hex()
            if rec_h != _as_hash32(snap["content_hash"]).hex() or rec_h != _as_hash32(wmeta["content_hash"]).hex():
                raise ValueError(f"{lbl} tampered object record_snapshot content_hash")
            snap["client_signature"] = wmeta.get("client_signature")
            snap["client_public_key"] = wmeta.get("client_public_key")
            _verify_object_author_signature(snap, lbl)
        elif op in ("ingest_claim", "retract_claim", "legacy_import_claim"):
            if (
                str(snap["tenant_id"]) != str(entry["tenant_id"])
                or str(uuid.UUID(str(snap["id"]))).lower() != str(uuid.UUID(str(wmeta["item_id"]))).lower()
                or str(snap["scope"]) != str(wmeta["scope"])
                or int(snap["version"]) != int(wmeta["version"])
            ):
                raise ValueError(f"{lbl} metadata mismatch against record_snapshot")
            rec_h = compute_claim_content_hash(snap).hex()
            if rec_h != _as_hash32(snap["content_hash"]).hex() or rec_h != _as_hash32(wmeta["content_hash"]).hex():
                raise ValueError(f"{lbl} tampered claim record_snapshot content_hash")
            if op == "retract_claim" and (
                str(snap["status"]) != "revoked"
                or wmeta.get("predecessor_id") is None
                or not str(wmeta.get("retraction_reason") or "").strip()
            ):
                raise ValueError(f"{lbl} retract_claim missing revoked status/predecessor_id/retraction_reason")
            snap["client_signature"] = wmeta.get("client_signature")
            snap["client_public_key"] = wmeta.get("client_public_key")
            _verify_claim_author_signature(snap, wmeta.get("retraction_reason"), lbl)
        else:
            raise ValueError(f"{lbl} unsupported operation '{op}'")
        exp_w_comm = compute_write_summary_commitment(wmeta).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = _as_hash32(stored_sc).hex() if stored_sc is not None else None
        if stored_sc_hex != exp_w_comm:
            raise ValueError(f"tampered write_summary at seq_num={entry['seq_num']}: state_commitment mismatch")

    if acmeta is not None:
        if (
            entry.get("bundle_hash") is not None
            or rmeta is not None
            or ometa is not None
            or wmeta is not None
            or entry.get("witness_reg_summary") is not None
            or entry.get("witness_revoke_summary") is not None
        ):
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: answer_cache_summary cannot coexist with other entry payloads"
            )
        if str(acmeta.get("cache_domain") or "acta:answer_cache:v1") != "acta:answer_cache:v1":
            raise ValueError(f"unsupported cache_domain at seq_num={entry['seq_num']}")
        lbl = f"answer_cache_summary[seq_num={entry['seq_num']}, cache_id={acmeta.get('cache_id')}]"
        ev_kind = acmeta.get("event_kind")
        if ev_kind in (None, "cached"):
            if (
                acmeta.get("invalidation_reason") is not None
                or acmeta.get("invalidated_by") is not None
                or acmeta.get("invalidator_auth_kind") is not None
                or acmeta.get("observed_state_commitment") is not None
                or acmeta.get("observed_dependency_commitment") is not None
            ):
                raise ValueError(f"{lbl} cached event_kind cannot carry invalidation fields")
        elif ev_kind == "invalidated":
            if acmeta.get("invalidation_reason") not in (
                "stale_dependency_commitment",
                "stale_state_commitment",
                "expired_ttl",
            ):
                raise ValueError(
                    f"{lbl} invalidation event has unsupported invalidation_reason {acmeta.get('invalidation_reason')!r}"
                )
            if acmeta.get("observed_state_commitment") is None:
                raise ValueError(f"{lbl} invalidation event requires observed_state_commitment")
            inv_kind = acmeta.get("invalidator_auth_kind")
            if inv_kind is not None and str(inv_kind).strip() not in (
                "oauth_github_principal",
                "ed25519_client_sig",
                "tenant_session",
                "master_admin",
            ):
                raise ValueError(f"{lbl} unsupported invalidator_auth_kind {inv_kind!r}")
        else:
            raise ValueError(f"{lbl} unsupported answer_cache event_kind {ev_kind!r}")
        _verify_auth_kind_and_sig_presence(
            lbl,
            str(acmeta["cacher_auth_kind"]).strip(),
            acmeta.get("client_signature") is not None,
            acmeta.get("client_public_key") is not None,
        )
        if acmeta.get("client_signature") is not None and acmeta.get("client_public_key") is not None:
            sig_raw = (
                bytes.fromhex(acmeta["client_signature"])
                if isinstance(acmeta["client_signature"], str)
                else bytes(acmeta["client_signature"])
            )
            pk_raw = _as_hash32(acmeta["client_public_key"])
            intent = compute_answer_cache_client_intent_hash(
                str(entry["tenant_id"]),
                str(acmeta["scope"]),
                str(acmeta["task_id"]),
                acmeta["query_hash"],
                acmeta["source_bundle_hash"],
                acmeta["state_commitment"],
                acmeta["answer_hash"],
            )
            if not verify_ed25519_strict(pk_raw, intent, sig_raw) and not verify_ed25519_strict(
                pk_raw, _as_hash32(acmeta["answer_hash"]), sig_raw
            ):
                raise ValueError(f"client Ed25519 signature verification failed on {lbl}")
        exp_ac_comm = compute_answer_cache_summary_commitment(acmeta).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = _as_hash32(stored_sc).hex() if stored_sc is not None else None
        if stored_sc_hex != exp_ac_comm:
            raise ValueError(
                f"tampered answer_cache_summary at seq_num={entry['seq_num']}: state_commitment mismatch"
            )

    wreg = entry.get("witness_reg_summary")
    wrev = entry.get("witness_revoke_summary")
    if wreg is not None:
        if (
            entry.get("bundle_hash") is not None
            or rmeta is not None
            or ometa is not None
            or wrev is not None
        ):
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: witness_reg_summary cannot coexist with bundle_hash, refusal_metadata, override_summary, or witness_revoke_summary"
            )
        expected_wpre = witness_registration_preimage_bytes(
            str(wreg["registration_domain"]),
            str(entry["tenant_id"]),
            str(wreg["witness_id"]),
            wreg["public_key"],
            str(wreg.get("registered_by", "")),
            str(wreg["description"]) if wreg.get("description") is not None else None,
        )
        if str(wreg["registration_blake3_preimage_hex"]).strip().lower() != expected_wpre.hex():
            raise ValueError(
                f"tampered witness_reg_summary.registration_blake3_preimage_hex at seq_num={entry['seq_num']}"
            )
        expected_wcomm = blake3_hash([expected_wpre]).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = (
            stored_sc.lower()
            if isinstance(stored_sc, str)
            else bytes(stored_sc).hex()
            if stored_sc is not None
            else None
        )
        if stored_sc_hex != expected_wcomm:
            raise ValueError(
                f"tampered witness_reg_summary at seq_num={entry['seq_num']}: state_commitment mismatch"
            )

    if wrev is not None:
        if (
            entry.get("bundle_hash") is not None
            or rmeta is not None
            or ometa is not None
            or wreg is not None
        ):
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: witness_revoke_summary cannot coexist with bundle_hash, refusal_metadata, override_summary, or witness_reg_summary"
            )
        expected_rpre = witness_revocation_preimage_bytes(
            str(wrev["revocation_domain"]),
            str(entry["tenant_id"]),
            str(wrev["witness_id"]),
            wrev["public_key"],
            str(wrev["revoked_by"]),
            str(wrev["reason"]),
            revocation_mode=str(wrev.get("revocation_mode") or "compromise"),
            effective_from_tree_size=(
                int(wrev["effective_from_tree_size"])
                if wrev.get("effective_from_tree_size") is not None
                else None
            ),
        )
        if str(wrev["revocation_blake3_preimage_hex"]).strip().lower() != expected_rpre.hex():
            raise ValueError(
                f"tampered witness_revoke_summary.revocation_blake3_preimage_hex at seq_num={entry['seq_num']}"
            )
        expected_rcomm = blake3_hash([expected_rpre]).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = (
            stored_sc.lower()
            if isinstance(stored_sc, str)
            else bytes(stored_sc).hex()
            if stored_sc is not None
            else None
        )
        if stored_sc_hex != expected_rcomm:
            raise ValueError(
                f"tampered witness_revoke_summary at seq_num={entry['seq_num']}: state_commitment mismatch"
            )

    if rotmeta is not None:
        if (
            entry.get("bundle_hash") is not None
            or rmeta is not None
            or ometa is not None
            or wmeta is not None
            or acmeta is not None
            or wreg is not None
            or wrev is not None
        ):
            raise ValueError(
                f"invalid evidence entry at seq_num={entry['seq_num']}: host_key_rotation_summary cannot coexist with other entry payloads"
            )
        if str(rotmeta.get("rotation_domain") or HOST_KEY_ROTATE_DOMAIN_V1) != HOST_KEY_ROTATE_DOMAIN_V1:
            raise ValueError(f"unsupported rotation_domain at seq_num={entry['seq_num']}")
        if int(rotmeta["effective_from_seq"]) != int(entry["seq_num"]):
            raise ValueError(f"host_key_rotation_summary.effective_from_seq mismatch at seq_num={entry['seq_num']}")
        exp_pk_bytes = _as_hash32(expected_pubkey)
        old_pk_bytes = _as_hash32(rotmeta["old_public_key"])
        new_pk_bytes = _as_hash32(rotmeta["new_public_key"])
        if old_pk_bytes != exp_pk_bytes:
            raise ValueError(f"host_key_rotation_summary.old_public_key mismatch against active host key at seq_num={entry['seq_num']}")
        if is_weak_ed25519_pubkey(new_pk_bytes):
            raise ValueError(f"rejected weak low-order new_public_key at seq_num={entry['seq_num']}")
        rmode = str(rotmeta["rotation_mode"])
        if rmode == "scheduled":
            if rotmeta.get("old_key_signature") is None:
                raise ValueError(f"scheduled host_key_rotation_summary at seq_num={entry['seq_num']} requires old_key_signature")
            if not verify_host_key_rotation_old(
                exp_pk_bytes,
                str(entry["tenant_id"]),
                int(rotmeta["effective_from_seq"]),
                old_pk_bytes,
                new_pk_bytes,
                rmode,
                str(rotmeta["reason"]),
                rotmeta["old_key_signature"],
            ):
                raise ValueError(f"old_key_signature verification failed at seq_num={entry['seq_num']}")
        elif rmode == "compromise_recovery":
            if rotmeta.get("compromised_from_seq") is None:
                raise ValueError(f"compromise_recovery at seq_num={entry['seq_num']} requires compromised_from_seq")
        else:
            raise ValueError(f"unsupported rotation_mode '{rmode}' at seq_num={entry['seq_num']}")
        if not verify_host_key_rotation_new(
            new_pk_bytes,
            str(entry["tenant_id"]),
            int(rotmeta["effective_from_seq"]),
            old_pk_bytes,
            new_pk_bytes,
            rmode,
            str(rotmeta["reason"]),
            rotmeta["new_key_signature"],
        ):
            raise ValueError(f"new_key_signature verification failed at seq_num={entry['seq_num']}")
        exp_rot_comm = compute_host_key_rotation_commitment(rotmeta).hex()
        stored_sc = entry.get("state_commitment")
        stored_sc_hex = _as_hash32(stored_sc).hex() if stored_sc is not None else None
        if stored_sc_hex != exp_rot_comm:
            raise ValueError(f"tampered host_key_rotation_summary at seq_num={entry['seq_num']}: state_commitment mismatch")

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
        write_summary=wmeta,
        answer_cache_summary=acmeta,
        witness_reg_summary=wreg,
        witness_revoke_summary=wrev,
        witness_in_v3=witness_in_v3,
        host_key_rotation_summary=rotmeta,
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
    sig_ok = verify_evidence_signature(
        expected_pubkey,
        str(entry["tenant_id"]),
        int(entry["seq_num"]),
        entry["prev_hash"],
        recomputed_event,
        entry["host_signature"],
    ) or (
        rotmeta is not None
        and str(rotmeta.get("rotation_mode")) == "compromise_recovery"
        and verify_evidence_signature(
            rotmeta["new_public_key"],
            str(entry["tenant_id"]),
            int(entry["seq_num"]),
            entry["prev_hash"],
            recomputed_event,
            entry["host_signature"],
        )
    )
    if not sig_ok:
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
    verified_corroborated_resolutions: int = 0
    verified_overrides: int = 0
    verified_writes: int = 0
    verified_answer_caches: int = 0
    verified_refusals: int = 0
    non_default_thresholds: bool = False
    resolver_manifest: Mapping[str, Any] | None = None
    verification_mode: str = "full_chain"
    merkle_tree_size: int | None = None
    merkle_root_hex: str | None = None
    anchored_tree_size: int | None = None
    anchored_merkle_root_hex: str | None = None
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
    first_rot_old_pk: bytes | None = None
    for _ev in archive.get("evidence_chain") or []:
        if _ev.get("host_key_rotation_summary") is not None:
            first_rot_old_pk = _as_hash32(_ev["host_key_rotation_summary"]["old_public_key"])
            break
    if first_rot_old_pk is None and archive.get("merkle_proof") is not None:
        for _rp in archive["merkle_proof"].get("rotation_entry_proofs") or []:
            _rot = _rp["entry"].get("host_key_rotation_summary")
            if _rot is not None:
                first_rot_old_pk = _as_hash32(_rot["old_public_key"])
                break
    if first_rot_old_pk is None and archive.get("merkle_proof") is not None:
        for _rp in archive["merkle_proof"].get("rotation_entry_proofs") or []:
            _rot = _rp["entry"].get("host_key_rotation_summary")
            if _rot is not None:
                first_rot_old_pk = _as_hash32(_rot["old_public_key"])
                break
    if expected_pk != archive_pk and (first_rot_old_pk is None or expected_pk != first_rot_old_pk):
        raise ValueError(
            f"host_public_key mismatch: archive contains {archive_pk.hex()}, expected {expected_pk.hex()}"
        )
    expected_pk = archive_pk
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
        _verify_object_author_signature(obj, f"object[id={oid}]")
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
        _verify_claim_author_signature(claim, None, f"claim[id={cid}]")
        claims_by_id[cid] = claim

    overrides_by_id: dict[str, Mapping[str, Any]] = {}
    for att in archive.get("override_attestations", []):
        aid = str(uuid.UUID(str(att["id"]))).lower()
        if str(att["tenant_id"]) != str(bundle["tenant_id"]):
            raise ValueError(
                f"override_attestation[id={aid}] tenant_id '{att['tenant_id']}' != bundle tenant_id '{bundle['tenant_id']}'"
            )
        csig = att.get("client_signature")
        cpk = att.get("client_public_key")
        if (csig is not None) != (cpk is not None):
            raise ValueError(
                f"override_attestation[id={aid}] inconsistent client_signature / client_public_key presence"
            )
        auth_kind = _effective_override_auth_kind(att)
        if auth_kind == "ed25519_client_sig":
            if csig is None:
                raise ValueError(
                    f"override_attestation[id={aid}] adjudicator_auth_kind='ed25519_client_sig' requires client_signature + client_public_key"
                )
        elif auth_kind in ("oauth_github_principal", "tenant_session", "master_admin"):
            if csig is not None:
                raise ValueError(
                    f"override_attestation[id={aid}] adjudicator_auth_kind='{auth_kind}' cannot coexist with client_signature"
                )
        else:
            raise ValueError(
                f"override_attestation[id={aid}] unsupported adjudicator_auth_kind '{auth_kind}'"
            )

        stored_att_raw = _as_hash32(att["attestation_hash"])
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
            ok_full = verify_ed25519_strict(cpk_raw, stored_att_raw, csig_raw)
            if not ok_intent and not ok_full:
                raise ValueError(
                    f"client Ed25519 signature verification failed on override_attestation[id={aid}]"
                )

        recomputed_att = compute_override_attestation_hash(att)
        if recomputed_att != stored_att_raw:
            raise ValueError(
                f"tampered override_attestation[id={aid}]: recomputed attestation_hash {recomputed_att.hex()} != stored {stored_att_raw.hex()}"
            )
        if not verify_override_signature(
            expected_pk,
            str(att["tenant_id"]),
            int(att["evidence_seq_num"]),
            recomputed_att,
            att["host_signature"],
        ) and not (
            first_rot_old_pk is not None
            and verify_override_signature(
                first_rot_old_pk,
                str(att["tenant_id"]),
                int(att["evidence_seq_num"]),
                recomputed_att,
                att["host_signature"],
            )
        ):
            raise ValueError(
                f"Ed25519 host_signature verification failed on override_attestation[id={aid}]"
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

    corroboration_damping = (
        float(rm["corroboration_damping"])
        if rm is not None
        else DEFAULT_CORROBORATION_DAMPING
    )
    verified_corroborated_resolutions = 0
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
        elif int(win.get("corroborating_count") or 1) > 1 or win.get("effective_confidence") is not None:
            expected_count = max(int(win.get("corroborating_count") or 1), 2)
            bucket_claims: list[Mapping[str, Any]] = [stored]
            for raw_sid in res.get("suppressed_claim_ids", []):
                sid = str(uuid.UUID(str(raw_sid))).lower()
                if sid == cid:
                    continue
                sup_stored = claims_by_id.get(sid)
                if sup_stored is not None:
                    sup_groups = {
                        str(sup_stored["claim_group_key"]).lower(),
                        compute_logical_claim_group_key(
                            str(sup_stored["tenant_id"]),
                            str(sup_stored["subject"]),
                            str(sup_stored["predicate"]),
                            str(sup_stored["scope"]),
                        ).hex(),
                    }
                    if str(res["claim_group_key"]).lower() not in sup_groups:
                        raise ValueError(
                            f"corroborating claim[id={sid}] does not match resolution claim_group_key"
                        )
                    if claims_share_winning_value_bucket(win, sup_stored):
                        bucket_claims.append(sup_stored)
            if len(bucket_claims) != expected_count:
                raise ValueError(
                    f"resolution_record for claim[id={cid}] declares corroborating_count={expected_count}, "
                    f"but archive.claims contains {len(bucket_claims)} winning-bucket claim(s); "
                    "all corroborating claims must be proven in archive.claims"
                )
            rec_cnt, rec_sources, rec_eff = recompute_winning_bucket_corroboration(
                bucket_claims, corroboration_damping
            )
            if rec_cnt != expected_count:
                raise ValueError(
                    f"corroborating_count mismatch on claim[id={cid}]: recomputed {rec_cnt} != {expected_count}"
                )
            claimed_sources = list(win.get("corroborating_sources") or [])
            if claimed_sources and rec_sources != claimed_sources:
                raise ValueError(
                    f"corroborating_sources mismatch on claim[id={cid}]: recomputed {rec_sources} != {claimed_sources}"
                )
            if win.get("effective_confidence") is not None:
                claimed_eff = float(win["effective_confidence"])
                if abs(claimed_eff - rec_eff) > 1e-9:
                    raise ValueError(
                        f"tampered effective_confidence on claim[id={cid}]: recomputed {rec_eff:.9f} != bundle {claimed_eff:.9f}"
                    )
            verified_corroborated_resolutions += 1

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

    omitted_facts = bundle.get("resolved_facts_omitted")
    if omitted_facts is not None:
        total_omitted = int(bundle.get("omission_record", {}).get("total_omitted_count", 0))
        if int(omitted_facts) < 0 or int(omitted_facts) > total_omitted:
            raise ValueError(
                f"tampered resolved_facts_omitted ({omitted_facts}) exceeds total_omitted_count ({total_omitted})"
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
    verified_writes = 0
    verified_answer_caches = 0
    verified_evidence_entries = 0
    evidence_by_seq: dict[int, Mapping[str, Any]] = {}
    zero_hex = "00" * 32
    chain_pk = first_rot_old_pk if first_rot_old_pk is not None else expected_pk

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
        if entry.get("write_summary") is not None:
            verified_writes += 1
        if entry.get("answer_cache_summary") is not None:
            verified_answer_caches += 1

        verify_evidence_entry(entry, chain_pk)
        if entry.get("host_key_rotation_summary") is not None:
            chain_pk = _as_hash32(entry["host_key_rotation_summary"]["new_public_key"])
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
    anchored_tree_size: int | None = None
    anchored_merkle_root_hex: str | None = None
    verified_witness_anchors = 0

    if merkle_proof is not None:
        sth = merkle_proof["checkpoint"]
        verified_witness_anchors = verify_signed_tree_head(
            sth, str(bundle["tenant_id"]), expected_pk
        )
        key_epochs: list[tuple[int, bytes]] = [(1, first_rot_old_pk if first_rot_old_pk is not None else expected_pk)]
        if merkle_proof.get("rotation_entry_proofs"):
            cur_pk = key_epochs[0][1]
            for r_proof in merkle_proof["rotation_entry_proofs"]:
                _verify_entry_inclusion(r_proof, sth, cur_pk)
                r_sum = r_proof["entry"]["host_key_rotation_summary"]
                nxt_pk = _as_hash32(r_sum["new_public_key"])
                cur_pk = nxt_pk
                key_epochs.append((int(r_sum["effective_from_seq"]) + 1, nxt_pk))
        elif evidence_chain:
            for e_item in evidence_chain:
                if e_item.get("host_key_rotation_summary") is not None:
                    r_sum = e_item["host_key_rotation_summary"]
                    key_epochs.append((int(r_sum["effective_from_seq"]) + 1, _as_hash32(r_sum["new_public_key"])))

        def _pk_for_seq(s: int) -> bytes:
            chosen = key_epochs[0][1]
            for st_s, k_b in key_epochs:
                if s >= st_s:
                    chosen = k_b
            return chosen

        b_proof = merkle_proof["bundle_entry_proof"]
        _verify_entry_inclusion(b_proof, sth, _pk_for_seq(int(b_proof["entry"]["seq_num"])))
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
            _verify_entry_inclusion(ovr_proof, sth, _pk_for_seq(int(ovr_proof["entry"]["seq_num"])))
            o_entry = ovr_proof["entry"]
            o_seq = int(o_entry["seq_num"])
            if not evidence_chain and o_seq not in evidence_by_seq:
                verified_evidence_entries += 1
            evidence_by_seq[o_seq] = o_entry

        for wr_proof in merkle_proof.get("write_entry_proofs", []):
            _verify_entry_inclusion(wr_proof, sth, _pk_for_seq(int(wr_proof["entry"]["seq_num"])))
            w_entry = wr_proof["entry"]
            w_seq = int(w_entry["seq_num"])
            if not evidence_chain and w_seq not in evidence_by_seq:
                verified_evidence_entries += 1
                if w_entry.get("write_summary") is not None:
                    verified_writes += 1
            evidence_by_seq[w_seq] = w_entry

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

        cons_to_anchor = merkle_proof.get("consistency_proof_to_anchor") or []
        anchor_sth = merkle_proof.get("anchored_checkpoint")
        if cons_to_anchor and anchor_sth is None:
            raise ValueError(
                "merkle_proof.consistency_proof_to_anchor present without anchored_checkpoint"
            )
        if anchor_sth is not None:
            a_size = int(anchor_sth["tree_size"])
            c_size = int(sth["tree_size"])
            if a_size < c_size:
                raise ValueError(
                    f"anchored_checkpoint.tree_size ({a_size}) < checkpoint.tree_size ({c_size})"
                )
            bridged_anchors = verify_signed_tree_head(
                anchor_sth, str(bundle["tenant_id"]), expected_pk
            )
            if not verify_merkle_consistency_proof(
                c_size,
                sth["merkle_root"],
                a_size,
                anchor_sth["merkle_root"],
                cons_to_anchor,
            ):
                raise ValueError(
                    f"RFC 6962 consistency_proof_to_anchor verification failed from tree_size={c_size} to anchored tree_size={a_size}"
                )
            if a_size > c_size:
                verified_witness_anchors += bridged_anchors
            anchored_tree_size = a_size
            anchored_merkle_root_hex = str(anchor_sth["merkle_root"]).lower()
        elif sth.get("witness_anchors"):
            anchored_tree_size = int(sth["tree_size"])
            anchored_merkle_root_hex = str(sth["merkle_root"]).lower()

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

    for oid, obj in objects_by_id.items():
        if obj.get("evidence_seq_num") is not None:
            w_seq = int(obj["evidence_seq_num"])
            ev = evidence_by_seq.get(w_seq)
            if ev is None:
                raise ValueError(
                    f"object[id={oid}] references missing verified write evidence seq_num={w_seq}"
                )
            ws = ev.get("write_summary")
            if ws is None or str(uuid.UUID(str(ws["item_id"]))).lower() != oid or _as_hash32(ws["content_hash"]) != _as_hash32(obj["content_hash"]):
                raise ValueError(
                    f"object[id={oid}] content_hash mismatch against write_summary at seq_num={w_seq}"
                )

    for cid, clm in claims_by_id.items():
        if clm.get("evidence_seq_num") is not None:
            w_seq = int(clm["evidence_seq_num"])
            ev = evidence_by_seq.get(w_seq)
            if ev is None:
                raise ValueError(
                    f"claim[id={cid}] references missing verified write evidence seq_num={w_seq}"
                )
            ws = ev.get("write_summary")
            if ws is None or str(uuid.UUID(str(ws["item_id"]))).lower() != cid or _as_hash32(ws["content_hash"]) != _as_hash32(clm["content_hash"]):
                raise ValueError(
                    f"claim[id={cid}] content_hash mismatch against write_summary at seq_num={w_seq}"
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
        verified_corroborated_resolutions=verified_corroborated_resolutions,
        verified_overrides=len(overrides_by_id),
        verified_writes=verified_writes,
        verified_answer_caches=verified_answer_caches,
        verified_refusals=verified_refusals,
        non_default_thresholds=non_default,
        resolver_manifest=dict(rm) if isinstance(rm, Mapping) else None,
        verification_mode=v_mode,
        merkle_tree_size=merkle_tree_size,
        merkle_root_hex=merkle_root_hex,
        anchored_tree_size=anchored_tree_size,
        anchored_merkle_root_hex=anchored_merkle_root_hex,
        verified_witness_anchors=verified_witness_anchors,
    )


@dataclass(frozen=True)
class OfflineStateRebuildSummary:
    tenant_id: str
    scope: str
    verified_up_to_seq: int
    evaluated_at: str
    verified_evidence_entries: int
    write_events_replayed: int
    reconstructed_active_intents: int
    reconstructed_active_memories: int
    reconstructed_active_claims: int
    reconstructed_superseded_or_retracted_items: int
    reconstructed_active_overrides: int
    reconstructed_intent_root_hex: str
    reconstructed_knowledge_root_hex: str
    reconstructed_memory_root_hex: str
    permission_root_hex: str
    reconstructed_state_commitment_hex: str
    merkle_root_hex: str | None = None
    anchored_tree_size: int | None = None
    verified_witness_anchors: int = 0
    header_hash_hex: str = ""
    header_signature_verified: bool = True
    quarantined_compromised_seqs: tuple[int, ...] = ()


def verify_and_rebuild_scope_state_offline(
    archive_or_response: Mapping[str, Any],
    expected_pubkey: bytes | str,
    scope_override: str | None = None,
) -> OfflineStateRebuildSummary:
    """Verifies a portable `StateRebuildArchive` (`v1` or `v2`) and reconstructs scope `state_commitment` completely offline."""
    archive = (
        archive_or_response["rebuild_proof_archive"]
        if isinstance(archive_or_response.get("rebuild_proof_archive"), Mapping)
        else archive_or_response
    )
    schema_ver = str(archive.get("schema_version") or STATE_REBUILD_ARCHIVE_SCHEMA_V1)
    if schema_ver == STATE_REBUILD_ARCHIVE_SCHEMA_V1:
        bundle_state_schema = SCHEMA_VERSION_V1
    elif schema_ver == STATE_REBUILD_ARCHIVE_SCHEMA_V2:
        bundle_state_schema = SCHEMA_VERSION_V2
    else:
        raise ValueError(
            f"unsupported StateRebuildArchive.schema_version '{schema_ver}' (expected '{STATE_REBUILD_ARCHIVE_SCHEMA_V1}' or '{STATE_REBUILD_ARCHIVE_SCHEMA_V2}')"
        )
    expected_pk_arg = _as_hash32(expected_pubkey)
    archive_pk = _as_hash32(archive["host_public_key"])
    genesis_pk = (
        _as_hash32(archive["genesis_host_public_key"])
        if archive.get("genesis_host_public_key") is not None
        else archive_pk
    )
    if expected_pk_arg != archive_pk and expected_pk_arg != genesis_pk:
        raise ValueError(
            f"host_public_key mismatch: archive tail={archive_pk.hex()} (genesis={genesis_pk.hex()}), expected {expected_pk_arg.hex()}"
        )
    expected_pk = archive_pk
    if is_weak_ed25519_pubkey(expected_pk) or is_weak_ed25519_pubkey(genesis_pk):
        raise ValueError("rejected weak low-order Ed25519 public key")
    active_pk = genesis_pk

    tenant_id = str(archive["tenant_id"])
    target_scope = (
        scope_override.strip()
        if scope_override is not None and scope_override.strip()
        else str(archive["scope"])
    )
    up_to_seq = int(archive["up_to_seq"])
    if up_to_seq < 0:
        raise ValueError(f"invalid up_to_seq={up_to_seq}: must be >= 0")

    if archive.get("header_hash") is None or archive.get("host_header_signature") is None:
        raise ValueError(
            "StateRebuildArchive missing required signed header fields (header_hash, host_header_signature)"
        )
    recomputed_header = compute_rebuild_archive_header_hash(
        schema_ver,
        tenant_id,
        str(archive["scope"]),
        up_to_seq,
        archive["evaluated_at"],
        archive["permission_root"],
    )
    stored_header = _as_hash32(archive["header_hash"])
    if recomputed_header != stored_header:
        raise ValueError(
            f"tampered StateRebuildArchive header (scope / up_to_seq / evaluated_at / permission_root): "
            f"recomputed header_hash {recomputed_header.hex()} != stored {stored_header.hex()}"
        )
    if not verify_rebuild_archive_header_signature(
        expected_pk,
        tenant_id,
        recomputed_header,
        archive["host_header_signature"],
    ):
        raise ValueError(
            "Ed25519 host_header_signature verification failed on StateRebuildArchive header"
        )

    evidence_chain = list(archive.get("evidence_chain") or [])
    if len(evidence_chain) != up_to_seq:
        raise ValueError(
            f"evidence_chain length ({len(evidence_chain)}) != archive.up_to_seq ({up_to_seq})"
        )

    objects_map: dict[str, Mapping[str, Any]] = {}
    claims_map: dict[str, Mapping[str, Any]] = {}
    write_events_replayed = 0
    expected_override_seqs: dict[int, tuple[str, str, bytes]] = {}
    leaves: list[bytes] = []
    zero_hex = "00" * 32

    for idx, entry in enumerate(evidence_chain):
        expected_seq = idx + 1
        seq_num = int(entry["seq_num"])
        if seq_num != expected_seq:
            raise ValueError(
                f"gap in evidence_chain at index {idx}: expected seq_num={expected_seq}, got {seq_num}"
            )
        if str(entry["tenant_id"]) != tenant_id:
            raise ValueError(
                f"evidence_chain[{idx}] tenant_id '{entry['tenant_id']}' != archive tenant_id '{tenant_id}'"
            )
        prev_hex = _as_hash32(entry["prev_hash"]).hex()
        if idx == 0:
            if prev_hex != zero_hex:
                raise ValueError(
                    f"tampered genesis seq_num=1: expected zero prev_hash, got {prev_hex}"
                )
        else:
            prior_ev_hex = _as_hash32(evidence_chain[idx - 1]["event_hash"]).hex()
            if prev_hex != prior_ev_hex:
                raise ValueError(f"broken prev_hash link at seq_num={seq_num}")

        entry_pk = active_pk
        verify_evidence_entry(entry, entry_pk)
        if entry.get("host_key_rotation_summary") is not None:
            active_pk = _as_hash32(entry["host_key_rotation_summary"]["new_public_key"])
        leaves.append(merkle_leaf_hash(seq_num, entry["event_hash"]))

        ws = entry.get("write_summary")
        if ws is not None and str(ws["scope"]) == target_scope:
            write_events_replayed += 1
            snap = dict(ws["record_snapshot"])
            op = str(ws["operation"])
            if op in ("ingest_object", "legacy_import_object"):
                objects_map[str(uuid.UUID(str(snap["id"]))).lower()] = snap
            elif op in ("ingest_claim", "retract_claim", "legacy_import_claim"):
                claims_map[str(uuid.UUID(str(snap["id"]))).lower()] = snap

        ovs = entry.get("override_summary")
        if ovs is not None and str(ovs["scope"]) == target_scope:
            if entry.get("state_commitment") is None:
                raise ValueError(
                    f"override evidence entry at seq_num={seq_num} missing state_commitment"
                )
            expected_override_seqs[seq_num] = (
                str(uuid.UUID(str(ovs["attestation_id"]))).lower(),
                _as_hash32(entry["state_commitment"]).hex(),
                entry_pk,
            )

    verified_overrides_by_seq: dict[int, Mapping[str, Any]] = {}
    for att in archive.get("override_attestations") or []:
        aid = str(uuid.UUID(str(att["id"]))).lower()
        if str(att["tenant_id"]) != tenant_id:
            raise ValueError(
                f"override_attestation[id={aid}] tenant_id '{att['tenant_id']}' != archive tenant_id '{tenant_id}'"
            )
        if str(att["scope"]) != target_scope:
            continue
        csig = att.get("client_signature")
        cpk = att.get("client_public_key")
        auth_kind = _effective_override_auth_kind(att)
        _verify_auth_kind_and_sig_presence(
            f"override_attestation[id={aid}]",
            auth_kind,
            csig is not None,
            cpk is not None,
        )
        stored_att_raw = _as_hash32(att["attestation_hash"])
        if csig is not None and cpk is not None:
            sig_raw = bytes.fromhex(csig) if isinstance(csig, str) else bytes(csig)
            pk_raw = _as_hash32(cpk)
            intent_hash = compute_override_client_intent_hash(
                str(att["tenant_id"]),
                str(att["scope"]),
                str(att["winning_claim_id"]),
                str(att["adjudicator_id"]),
                str(att["justification"]),
            )
            if not verify_ed25519_strict(pk_raw, intent_hash, sig_raw) and not verify_ed25519_strict(
                pk_raw, stored_att_raw, sig_raw
            ):
                raise ValueError(
                    f"client Ed25519 signature verification failed on override_attestation[id={aid}]"
                )
        recomputed_att = compute_override_attestation_hash(att)
        if recomputed_att != stored_att_raw:
            raise ValueError(
                f"tampered override_attestation[id={aid}]: recomputed {recomputed_att.hex()} != stored {stored_att_raw.hex()}"
            )
        if up_to_seq > 0 and active_pk != expected_pk:
            raise ValueError("active host key after replaying chain != archive.host_public_key")
        ev_seq = int(att["evidence_seq_num"])
        exp_pair = expected_override_seqs.get(ev_seq)
        if exp_pair is None:
            raise ValueError(
                f"unlinked override_attestation[id={aid}] at evidence_seq_num={ev_seq} not present in evidence_chain"
            )
        if not verify_override_signature(
            exp_pair[2],
            tenant_id,
            ev_seq,
            recomputed_att,
            att["host_signature"],
        ):
            raise ValueError(
                f"Ed25519 host_signature verification failed on override_attestation[id={aid}]"
            )
        if exp_pair[0] != aid or exp_pair[1] != stored_att_raw.hex():
            raise ValueError(
                f"override_attestation[id={aid}] mismatch against evidence_chain seq_num={ev_seq}"
            )
        verified_overrides_by_seq[ev_seq] = att

    if up_to_seq > 0 and active_pk != expected_pk:
        raise ValueError("active host key after replaying chain != archive.host_public_key")

    for seq_num, (att_id, _, _) in expected_override_seqs.items():
        if seq_num not in verified_overrides_by_seq:
            raise ValueError(
                f"stripped override_attestation[id={att_id}] notarized at evidence_chain seq_num={seq_num} is missing from archive.override_attestations"
            )

    merkle_root_hex: str | None = None
    anchored_tree_size: int | None = None
    verified_witness_anchors = 0

    if up_to_seq > 0:
        computed_root = compute_merkle_root_from_leaves(leaves)
        sth = archive.get("checkpoint")
        if sth is not None:
            if int(sth["tree_size"]) != up_to_seq:
                raise ValueError(
                    f"checkpoint.tree_size ({sth['tree_size']}) != archive.up_to_seq ({up_to_seq})"
                )
            verified_witness_anchors = verify_signed_tree_head(sth, tenant_id, expected_pk)
            if _as_hash32(sth["merkle_root"]) != computed_root:
                raise ValueError(
                    f"checkpoint.merkle_root {sth['merkle_root']} != root {computed_root.hex()} computed from evidence_chain"
                )
            if _as_hash32(sth["head_event_hash"]) != _as_hash32(evidence_chain[-1]["event_hash"]):
                raise ValueError("checkpoint.head_event_hash mismatch against chain tail")
            if sth.get("witness_anchors"):
                anchored_tree_size = int(sth["tree_size"])
        merkle_root_hex = computed_root.hex()

        anchor_sth = archive.get("latest_anchored_checkpoint")
        if anchor_sth is not None:
            try:
                anchor_cnt = verify_signed_tree_head(anchor_sth, tenant_id, expected_pk)
            except ValueError:
                anchor_cnt = verify_signed_tree_head(anchor_sth, tenant_id, genesis_pk)
            if anchor_cnt == 0:
                raise ValueError("latest_anchored_checkpoint contains zero verified witness_anchors")
            a_size = int(anchor_sth["tree_size"])
            cons_nodes = list(archive.get("consistency_proof_from_latest_anchor") or [])
            if a_size <= up_to_seq:
                prefix_root = compute_merkle_root_from_leaves(leaves[:a_size])
                if prefix_root != _as_hash32(anchor_sth["merkle_root"]):
                    raise ValueError(
                        f"latest_anchored_checkpoint merkle_root {anchor_sth['merkle_root']} != prefix root {prefix_root.hex()} at tree_size={a_size}"
                    )
                if not verify_merkle_consistency_proof(
                    a_size,
                    anchor_sth["merkle_root"],
                    up_to_seq,
                    computed_root,
                    cons_nodes,
                ):
                    raise ValueError(
                        f"RFC 6962 consistency proof failed from latest_anchored_checkpoint ({a_size}) to head ({up_to_seq})"
                    )
            elif not verify_merkle_consistency_proof(
                up_to_seq,
                computed_root,
                a_size,
                anchor_sth["merkle_root"],
                cons_nodes,
            ):
                raise ValueError(
                    f"RFC 6962 consistency proof failed from up_to_seq ({up_to_seq}) to latest_anchored_checkpoint ({a_size})"
                )
            if anchored_tree_size != a_size:
                verified_witness_anchors += anchor_cnt
                anchored_tree_size = a_size

    eval_micros = parse_rfc3339_micros(archive["evaluated_at"])
    obj_pred_ids = {
        str(uuid.UUID(str(o["predecessor_id"]))).lower()
        for o in objects_map.values()
        if o.get("predecessor_id") is not None
    }
    clm_pred_ids = {
        str(uuid.UUID(str(c["predecessor_id"]))).lower()
        for c in claims_map.values()
        if c.get("predecessor_id") is not None
    }
    ovr_pred_ids = {
        str(uuid.UUID(str(o["predecessor_id"]))).lower()
        for o in verified_overrides_by_seq.values()
        if o.get("predecessor_id") is not None
    }

    intent_hashes: list[bytes] = []
    memory_hashes: list[bytes] = []
    superseded_or_retracted = 0

    for oid, obj in objects_map.items():
        if oid in obj_pred_ids or str(obj["lifecycle_status"]) != "active":
            superseded_or_retracted += 1
        elif str(obj["obj_type"]) == "intent":
            intent_hashes.append(_as_hash32(obj["content_hash"]))
        else:
            memory_hashes.append(_as_hash32(obj["content_hash"]))

    claim_hashes: list[bytes] = []
    for cid, clm in claims_map.items():
        vf = clm.get("valid_from")
        vt = clm.get("valid_to")
        within_from = True if vf is None else parse_rfc3339_micros(vf) <= eval_micros
        within_to = True if vt is None else parse_rfc3339_micros(vt) >= eval_micros
        if cid in clm_pred_ids or str(clm["status"]) != "active" or not within_from or not within_to:
            superseded_or_retracted += 1
        else:
            claim_hashes.append(_as_hash32(clm["content_hash"]))

    reconstructed_active_claims = len(claim_hashes)
    active_overrides_count = 0
    for ovr in verified_overrides_by_seq.values():
        oid = str(uuid.UUID(str(ovr["id"]))).lower()
        if oid not in ovr_pred_ids:
            claim_hashes.append(_as_hash32(ovr["attestation_hash"]))
            active_overrides_count += 1

    perm_root = _as_hash32(archive["permission_root"])
    intent_root = compute_sub_commitment_for_schema(bundle_state_schema, intent_hashes)
    memory_root = compute_sub_commitment_for_schema(bundle_state_schema, memory_hashes)
    knowledge_root = compute_sub_commitment_for_schema(bundle_state_schema, claim_hashes)
    state_commitment = compute_state_commitment(
        bundle_state_schema,
        tenant_id,
        target_scope,
        intent_root,
        knowledge_root,
        memory_root,
        perm_root,
    )

    quarantined_seqs: list[int] = []
    for entry in evidence_chain:
        rot = entry.get("host_key_rotation_summary")
        if rot is not None and str(rot.get("rotation_mode")) == "compromise_recovery":
            comp_start = rot.get("compromised_from_seq")
            if comp_start is not None:
                eff_seq = int(rot["effective_from_seq"])
                protected = (
                    anchored_tree_size
                    if anchored_tree_size is not None and anchored_tree_size < eff_seq
                    else 0
                )
                for s in range(max(int(comp_start), protected + 1), eff_seq):
                    if s not in quarantined_seqs:
                        quarantined_seqs.append(s)

    return OfflineStateRebuildSummary(
        tenant_id=tenant_id,
        scope=target_scope,
        verified_up_to_seq=up_to_seq,
        evaluated_at=str(archive["evaluated_at"]),
        verified_evidence_entries=len(evidence_chain),
        write_events_replayed=write_events_replayed,
        reconstructed_active_intents=len(intent_hashes),
        reconstructed_active_memories=len(memory_hashes),
        reconstructed_active_claims=reconstructed_active_claims,
        reconstructed_superseded_or_retracted_items=superseded_or_retracted,
        reconstructed_active_overrides=active_overrides_count,
        reconstructed_intent_root_hex=intent_root.hex(),
        reconstructed_knowledge_root_hex=knowledge_root.hex(),
        reconstructed_memory_root_hex=memory_root.hex(),
        permission_root_hex=perm_root.hex(),
        reconstructed_state_commitment_hex=state_commitment.hex(),
        merkle_root_hex=merkle_root_hex,
        anchored_tree_size=anchored_tree_size,
        verified_witness_anchors=verified_witness_anchors,
        header_hash_hex=recomputed_header.hex(),
        header_signature_verified=True,
        quarantined_compromised_seqs=tuple(quarantined_seqs),
    )


def _effective_override_domain(att: Mapping[str, Any]) -> str:
    raw = str(att.get("attestation_domain") or "").strip()
    return raw if raw else "acta:override:v1"


def _effective_override_auth_kind(att: Mapping[str, Any]) -> str:
    raw = str(att.get("adjudicator_auth_kind") or "").strip()
    if raw:
        return raw
    if att.get("client_signature") is not None:
        return "ed25519_client_sig"
    adj = str(att.get("adjudicator_id") or "")
    if "::oauth:" in adj:
        return "oauth_github_principal"
    if adj.endswith("::master-admin"):
        return "master_admin"
    return "tenant_session"


def _encode_opt_sig64(sig: bytes | str | None) -> bytes:
    if sig is None:
        return b"\x00"
    raw = bytes.fromhex(sig) if isinstance(sig, str) else bytes(sig)
    if len(raw) != 64:
        raise ValueError(f"client_signature must be 64 bytes, got {len(raw)}")
    return b"\x01" + raw


def _override_attestation_preimage_bytes(att: Mapping[str, Any]) -> bytes:
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
    domain = _effective_override_domain(att)
    if domain == "acta:override:v1":
        return encode_length_delimited(
            [
                b"acta:override:v1",
                att_id.bytes,
                str(att["tenant_id"]).encode("utf-8"),
                str(att["scope"]).encode("utf-8"),
                group_key,
                str(att["subject"]).encode("utf-8"),
                str(att["predicate"]).encode("utf-8"),
                _encode_opt_hash32(att.get("source_bundle_hash")),
                winning_id.bytes,
                winning_hash,
                canonical_overridden,
                str(att["adjudicator_id"]).encode("utf-8"),
                str(att["justification"]).encode("utf-8"),
                struct.pack("<i", int(att["version"])),
                _encode_opt_uuid(att.get("predecessor_id")),
                struct.pack("<q", parse_rfc3339_micros(att["created_at"])),
            ]
        )
    if domain == "acta:override:v2":
        auth_kind = _effective_override_auth_kind(att)
        return encode_length_delimited(
            [
                b"acta:override:v2",
                att_id.bytes,
                str(att["tenant_id"]).encode("utf-8"),
                str(att["scope"]).encode("utf-8"),
                group_key,
                str(att["subject"]).encode("utf-8"),
                str(att["predicate"]).encode("utf-8"),
                _encode_opt_hash32(att.get("source_bundle_hash")),
                winning_id.bytes,
                winning_hash,
                canonical_overridden,
                str(att["adjudicator_id"]).encode("utf-8"),
                auth_kind.encode("utf-8"),
                str(att["justification"]).encode("utf-8"),
                struct.pack("<i", int(att["version"])),
                _encode_opt_uuid(att.get("predecessor_id")),
                struct.pack("<q", parse_rfc3339_micros(att["created_at"])),
                _encode_opt_hash32(att.get("client_public_key")),
                _encode_opt_sig64(att.get("client_signature")),
            ]
        )
    raise ValueError(f"unsupported override attestation_domain: {domain}")


def _evidence_event_preimage_bytes(entry: Mapping[str, Any]) -> tuple[str, bytes]:
    prev_raw = _as_hash32(entry["prev_hash"])
    created_micros = parse_rfc3339_micros(entry["created_at"])
    rmeta = entry.get("refusal_metadata")
    osumm = entry.get("override_summary")
    wsumm = entry.get("write_summary")
    acsumm = entry.get("answer_cache_summary")
    wreg = entry.get("witness_reg_summary")
    wrev = entry.get("witness_revoke_summary")
    rotsumm = entry.get("host_key_rotation_summary")
    witness_in_v3 = (
        (wreg is not None or wrev is not None)
        and entry.get("event_domain") == "acta:evidence_event:v3"
    )
    if rotsumm is not None:
        rot_tagged = _encode_opt_jcs(_normalize_host_key_rotation_summary(rotsumm))
        return (
            "acta:evidence_event:v3",
            encode_length_delimited(
                [
                    b"acta:evidence_event:v3",
                    str(entry["tenant_id"]).encode("utf-8"),
                    struct.pack("<q", int(entry["seq_num"])),
                    prev_raw,
                    _encode_opt_hash32(entry.get("bundle_hash")),
                    _encode_opt_hash32(entry.get("state_commitment")),
                    str(entry["policy_result"]).encode("utf-8"),
                    struct.pack("<q", created_micros),
                    b"\x00",
                    b"\x00",
                    b"\x00",
                    b"\x00",
                    rot_tagged,
                ]
            ),
        )
    if wsumm is not None or acsumm is not None:
        write_tagged = _encode_opt_jcs(_normalize_write_summary(wsumm) if wsumm is not None else None)
        cache_tagged = _encode_opt_jcs(
            _normalize_answer_cache_summary(acsumm) if acsumm is not None else None
        )
        return (
            "acta:evidence_event:v3",
            encode_length_delimited(
                [
                    b"acta:evidence_event:v3",
                    str(entry["tenant_id"]).encode("utf-8"),
                    struct.pack("<q", int(entry["seq_num"])),
                    prev_raw,
                    _encode_opt_hash32(entry.get("bundle_hash")),
                    _encode_opt_hash32(entry.get("state_commitment")),
                    str(entry["policy_result"]).encode("utf-8"),
                    struct.pack("<q", created_micros),
                    write_tagged,
                    cache_tagged,
                ]
            ),
        )
    if witness_in_v3:
        wreg_tagged = _encode_opt_jcs(_normalize_witness_reg_summary(wreg) if wreg is not None else None)
        wrev_tagged = _encode_opt_jcs(_normalize_witness_revoke_summary(wrev) if wrev is not None else None)
        return (
            "acta:evidence_event:v3",
            encode_length_delimited(
                [
                    b"acta:evidence_event:v3",
                    str(entry["tenant_id"]).encode("utf-8"),
                    struct.pack("<q", int(entry["seq_num"])),
                    prev_raw,
                    _encode_opt_hash32(entry.get("bundle_hash")),
                    _encode_opt_hash32(entry.get("state_commitment")),
                    str(entry["policy_result"]).encode("utf-8"),
                    struct.pack("<q", created_micros),
                    b"\x00",
                    b"\x00",
                    wreg_tagged,
                    wrev_tagged,
                ]
            ),
        )
    if rmeta is None and osumm is None:
        return (
            "acta:evidence_event:v1",
            encode_length_delimited(
                [
                    b"acta:evidence_event:v1",
                    str(entry["tenant_id"]).encode("utf-8"),
                    struct.pack("<q", int(entry["seq_num"])),
                    prev_raw,
                    _encode_opt_hash32(entry.get("bundle_hash")),
                    _encode_opt_hash32(entry.get("state_commitment")),
                    str(entry["policy_result"]).encode("utf-8"),
                    struct.pack("<q", created_micros),
                ]
            ),
        )
    refusal_tagged = _encode_opt_jcs(_normalize_refusal_metadata(rmeta) if rmeta is not None else None)
    override_tagged = _encode_opt_jcs(_normalize_override_summary(osumm) if osumm is not None else None)
    return (
        "acta:evidence_event:v2",
        encode_length_delimited(
            [
                b"acta:evidence_event:v2",
                str(entry["tenant_id"]).encode("utf-8"),
                struct.pack("<q", int(entry["seq_num"])),
                prev_raw,
                _encode_opt_hash32(entry.get("bundle_hash")),
                _encode_opt_hash32(entry.get("state_commitment")),
                str(entry["policy_result"]).encode("utf-8"),
                struct.pack("<q", created_micros),
                refusal_tagged,
                override_tagged,
            ]
        ),
    )


def dump_archive_preimages(archive: Mapping[str, Any]) -> dict[str, Any]:
    """Dumps explicit raw byte preimages and canonical JCS UTF-8 inside `archive` (`--dump-preimages` parity)."""
    bundle_jcs = to_canonical_bytes(archive["bundle"])
    bundle_preimage = encode_length_delimited([b"acta:bundle:v1", bundle_jcs])

    objects_dump = []
    for obj in archive.get("objects", []):
        obj_pre = object_content_preimage_bytes(obj)
        objects_dump.append(
            {
                "id": str(uuid.UUID(str(obj["id"]))).lower(),
                "obj_type": str(obj["obj_type"]),
                "version": int(obj["version"]),
                "evidence_seq_num": (
                    int(obj["evidence_seq_num"]) if obj.get("evidence_seq_num") is not None else None
                ),
                "object_domain": "acta:object:v1",
                "object_blake3_preimage_hex": obj_pre.hex(),
                "content_hash": _as_hash32(obj["content_hash"]).hex(),
                "client_public_key_hex": (
                    _as_hash32(obj["client_public_key"]).hex()
                    if obj.get("client_public_key") is not None
                    else None
                ),
                "client_signature_hex": (
                    (
                        bytes.fromhex(obj["client_signature"])
                        if isinstance(obj["client_signature"], str)
                        else bytes(obj["client_signature"])
                    ).hex()
                    if obj.get("client_signature") is not None
                    else None
                ),
            }
        )

    claims_dump = []
    for claim in archive.get("claims", []):
        grp_domain, grp_pre = claim_group_preimage_bytes(claim)
        clm_pre = claim_content_preimage_bytes(claim)
        claims_dump.append(
            {
                "id": str(uuid.UUID(str(claim["id"]))).lower(),
                "subject": str(claim["subject"]),
                "predicate": str(claim["predicate"]),
                "version": int(claim["version"]),
                "evidence_seq_num": (
                    int(claim["evidence_seq_num"])
                    if claim.get("evidence_seq_num") is not None
                    else None
                ),
                "claim_group_domain": grp_domain,
                "claim_group_blake3_preimage_hex": grp_pre.hex(),
                "claim_group_key": _as_hash32(claim["claim_group_key"]).hex(),
                "claim_domain": "acta:claim:v1",
                "claim_blake3_preimage_hex": clm_pre.hex(),
                "content_hash": _as_hash32(claim["content_hash"]).hex(),
                "source_commitment_hex": _as_hash32(claim["source_commitment"]).hex(),
                "client_public_key_hex": (
                    _as_hash32(claim["client_public_key"]).hex()
                    if claim.get("client_public_key") is not None
                    else None
                ),
                "client_signature_hex": (
                    (
                        bytes.fromhex(claim["client_signature"])
                        if isinstance(claim["client_signature"], str)
                        else bytes(claim["client_signature"])
                    ).hex()
                    if claim.get("client_signature") is not None
                    else None
                ),
            }
        )

    overrides_dump = []
    for att in archive.get("override_attestations", []):
        att_preimage = _override_attestation_preimage_bytes(att)
        att_hash_raw = _as_hash32(att["attestation_hash"])
        host_sig_preimage = encode_length_delimited(
            [
                b"acta:override_sig:v1",
                str(att["tenant_id"]).encode("utf-8"),
                struct.pack("<q", int(att["evidence_seq_num"])),
                att_hash_raw,
            ]
        )
        host_sig_digest = override_signing_preimage(
            str(att["tenant_id"]),
            int(att["evidence_seq_num"]),
            att_hash_raw,
        )
        att_domain = _effective_override_domain(att)
        auth_kind = _effective_override_auth_kind(att)
        if att.get("client_signature") is not None:
            t_clean = str(att["tenant_id"]).strip()
            adj_clean = str(att["adjudicator_id"]).strip()
            eff_actor = adj_clean if "::" in adj_clean else f"{t_clean}::{adj_clean}"
            client_sig_preimage = encode_length_delimited(
                [
                    b"acta:override_client_sig:v1",
                    t_clean.encode("utf-8"),
                    str(att["scope"]).strip().encode("utf-8"),
                    uuid.UUID(str(att["winning_claim_id"])).bytes,
                    eff_actor.encode("utf-8"),
                    str(att["justification"]).strip().encode("utf-8"),
                ]
            )
            client_intent = compute_override_client_intent_hash(
                t_clean,
                str(att["scope"]),
                str(att["winning_claim_id"]),
                adj_clean,
                str(att["justification"]),
            )
            c_domain: str | None = "acta:override_client_sig:v1"
            c_pre_hex: str | None = client_sig_preimage.hex()
            c_dig_hex: str | None = client_intent.hex()
        else:
            c_domain = None
            c_pre_hex = None
            c_dig_hex = None

        overrides_dump.append(
            {
                "id": str(uuid.UUID(str(att["id"]))).lower(),
                "evidence_seq_num": int(att["evidence_seq_num"]),
                "adjudicator_auth_kind": auth_kind,
                "attestation_domain": att_domain,
                "attestation_blake3_preimage_hex": att_preimage.hex(),
                "attestation_hash": att_hash_raw.hex(),
                "host_sig_preimage_domain": "acta:override_sig:v1",
                "host_sig_blake3_preimage_hex": host_sig_preimage.hex(),
                "host_sig_digest_hex": host_sig_digest.hex(),
                "host_signature_hex": str(att["host_signature"]).lower(),
                "client_sig_domain": c_domain,
                "client_sig_blake3_preimage_hex": c_pre_hex,
                "client_sig_digest_hex": c_dig_hex,
                "client_public_key_hex": (
                    str(att["client_public_key"]).lower()
                    if att.get("client_public_key") is not None
                    else None
                ),
                "client_signature_hex": (
                    str(att["client_signature"]).lower()
                    if att.get("client_signature") is not None
                    else None
                ),
            }
        )

    entries_src: list[Mapping[str, Any]] = []
    if archive.get("evidence_chain"):
        entries_src = list(archive["evidence_chain"])
    elif archive.get("merkle_proof") is not None:
        mp = archive["merkle_proof"]
        b_entry = mp["bundle_entry_proof"]["entry"]
        seen_seqs = {int(b_entry["seq_num"])}
        entries_src = [b_entry]
        for op in mp.get("override_entry_proofs", []):
            sq = int(op["entry"]["seq_num"])
            if sq not in seen_seqs:
                seen_seqs.add(sq)
                entries_src.append(op["entry"])
        for wp in mp.get("write_entry_proofs", []):
            sq = int(wp["entry"]["seq_num"])
            if sq not in seen_seqs:
                seen_seqs.add(sq)
                entries_src.append(wp["entry"])
        entries_src.sort(key=lambda e: int(e["seq_num"]))

    evidence_dump = []
    for entry in entries_src:
        ev_domain, ev_preimage = _evidence_event_preimage_bytes(entry)
        ev_raw = _as_hash32(entry["event_hash"])
        prev_raw = _as_hash32(entry["prev_hash"])
        sig_preimage = encode_length_delimited(
            [
                b"acta:evidence_sig:v1",
                str(entry["tenant_id"]).encode("utf-8"),
                struct.pack("<q", int(entry["seq_num"])),
                prev_raw,
                ev_raw,
            ]
        )
        sig_digest = evidence_signing_preimage(
            str(entry["tenant_id"]),
            int(entry["seq_num"]),
            prev_raw,
            ev_raw,
        )
        leaf_preimage = b"\x00" + ev_raw
        refusal_jcs = (
            to_canonical_json(_normalize_refusal_metadata(entry["refusal_metadata"]))
            if entry.get("refusal_metadata") is not None
            else None
        )
        override_jcs = (
            to_canonical_json(_normalize_override_summary(entry["override_summary"]))
            if entry.get("override_summary") is not None
            else None
        )
        evidence_dump.append(
            {
                "seq_num": int(entry["seq_num"]),
                "event_domain": ev_domain,
                "event_blake3_preimage_hex": ev_preimage.hex(),
                "event_hash": ev_raw.hex(),
                "merkle_leaf_sha256_preimage_hex": leaf_preimage.hex(),
                "merkle_leaf_hash": merkle_leaf_hash(int(entry["seq_num"]), ev_raw).hex(),
                "host_sig_preimage_domain": "acta:evidence_sig:v1",
                "host_sig_blake3_preimage_hex": sig_preimage.hex(),
                "host_sig_digest_hex": sig_digest.hex(),
                "host_signature_hex": str(entry["host_signature"]).lower(),
                "refusal_metadata_canonical_jcs": refusal_jcs,
                "override_summary_canonical_jcs": override_jcs,
                "write_summary_canonical_jcs": (
                    to_canonical_json(_normalize_write_summary(entry["write_summary"]))
                    if entry.get("write_summary") is not None
                    else None
                ),
                "answer_cache_summary_canonical_jcs": (
                    to_canonical_json(_normalize_answer_cache_summary(entry["answer_cache_summary"]))
                    if entry.get("answer_cache_summary") is not None
                    else None
                ),
                "witness_reg_summary_canonical_jcs": (
                    to_canonical_json(_normalize_witness_reg_summary(entry["witness_reg_summary"]))
                    if entry.get("witness_reg_summary") is not None
                    else None
                ),
                "witness_revoke_summary_canonical_jcs": (
                    to_canonical_json(_normalize_witness_revoke_summary(entry["witness_revoke_summary"]))
                    if entry.get("witness_revoke_summary") is not None
                    else None
                ),
                "witness_registration": entry.get("witness_reg_summary"),
                "witness_revocation": entry.get("witness_revoke_summary"),
            }
        )

    def _dump_single_sth(sth: Mapping[str, Any], audit_path_len: int | None = None) -> dict[str, Any]:
        issued_micros = parse_rfc3339_micros(sth["issued_at"])
        head_raw = _as_hash32(sth["head_event_hash"])
        mroot_raw = _as_hash32(sth["merkle_root"])
        cph_raw = _as_hash32(sth["checkpoint_hash"])
        cp_preimage = encode_length_delimited(
            [
                b"acta:checkpoint:v1",
                str(sth["tenant_id"]).encode("utf-8"),
                struct.pack("<q", int(sth["tree_size"])),
                head_raw,
                mroot_raw,
                struct.pack("<q", issued_micros),
            ]
        )
        cp_sig_preimage = encode_length_delimited(
            [
                b"acta:checkpoint_sig:v1",
                str(sth["tenant_id"]).encode("utf-8"),
                cph_raw,
            ]
        )
        cp_sig_digest = checkpoint_signing_preimage(str(sth["tenant_id"]), cph_raw)
        witness_dump = []
        for a in sth.get("witness_anchors", []):
            acph = _as_hash32(a["checkpoint_hash"])
            w_pre = encode_length_delimited(
                [
                    b"acta:witness_sig:v1",
                    str(a["tenant_id"]).encode("utf-8"),
                    struct.pack("<q", int(a["tree_size"])),
                    acph,
                ]
            )
            w_dig = witness_anchor_signing_preimage(
                str(a["tenant_id"]), int(a["tree_size"]), acph
            )
            witness_dump.append(
                {
                    "id": str(uuid.UUID(str(a["id"]))).lower(),
                    "witness_id": str(a["witness_id"]),
                    "witness_public_key_hex": _as_hash32(a["witness_public_key"]).hex(),
                    "witness_sig_domain": "acta:witness_sig:v1",
                    "witness_sig_blake3_preimage_hex": w_pre.hex(),
                    "witness_sig_digest_hex": w_dig.hex(),
                    "witness_signature_hex": str(a["witness_signature"]).lower(),
                }
            )
        d: dict[str, Any] = {
            "tree_size": int(sth["tree_size"]),
            "head_event_hash": head_raw.hex(),
            "merkle_root": mroot_raw.hex(),
            "issued_at_micros": issued_micros,
            "checkpoint_domain": "acta:checkpoint:v1",
            "checkpoint_blake3_preimage_hex": cp_preimage.hex(),
            "checkpoint_hash": cph_raw.hex(),
            "host_sig_preimage_domain": "acta:checkpoint_sig:v1",
            "host_sig_blake3_preimage_hex": cp_sig_preimage.hex(),
            "host_sig_digest_hex": cp_sig_digest.hex(),
            "host_signature_hex": str(sth["host_signature"]).lower(),
            "witness_anchors": witness_dump,
        }
        if audit_path_len is not None:
            d["bundle_audit_path_len"] = audit_path_len
        return d

    mp_opt = archive.get("merkle_proof")
    cp_dump = None
    anchored_cp_dump = None
    if mp_opt is not None:
        cp_dump = _dump_single_sth(
            mp_opt["checkpoint"],
            len(mp_opt["bundle_entry_proof"].get("audit_path", [])),
        )
        if mp_opt.get("anchored_checkpoint") is not None:
            anchored_cp_dump = _dump_single_sth(mp_opt["anchored_checkpoint"], None)
            anchored_cp_dump["from_tree_size"] = int(mp_opt["checkpoint"]["tree_size"])
            anchored_cp_dump["consistency_proof_to_anchor"] = list(
                mp_opt.get("consistency_proof_to_anchor") or []
            )

    out_dict: dict[str, Any] = {
        "framing_spec": "BLAKE3 digests hash concat_i(u64_le(len(part_i)) || part_i); Ed25519 signatures sign raw 32-byte digest bytes; Merkle trees follow RFC 6962 §2.1 SHA-256.",
        "merkle_spec": {
            "scheme": "rfc6962-sha256-v1",
            "empty_root_sha256_hex": merkle_empty_root().hex(),
            "leaf_formula": "SHA-256(0x00 || event_hash_32)",
            "node_formula": "SHA-256(0x01 || left_32 || right_32)",
            "legacy_v160_blake3_merkle_spec": {
                "scheme": "acta-blake3-merkle-v1",
                "empty_root_blake3_hex": legacy_blake3_merkle_empty_root().hex(),
                "leaf_formula": 'BLAKE3(encode_length_delimited([b"acta:merkle_leaf:v1", i64_le(seq_num), event_hash_32]))',
                "node_formula": 'BLAKE3(encode_length_delimited([b"acta:merkle_node:v1", left_32, right_32]))',
            },
        },
        "bundle_domain": "acta:bundle:v1",
        "bundle_canonical_jcs_len": len(bundle_jcs),
        "bundle_canonical_jcs_utf8": bundle_jcs.decode("utf-8"),
        "bundle_blake3_preimage_hex": bundle_preimage.hex(),
        "bundle_hash": str(archive["bundle_hash"]).lower(),
        "objects": objects_dump,
        "claims": claims_dump,
        "checkpoint": cp_dump,
        "override_attestations": overrides_dump,
        "evidence_entries": evidence_dump,
    }
    if anchored_cp_dump is not None:
        out_dict["anchored_checkpoint"] = anchored_cp_dump
    return out_dict


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
