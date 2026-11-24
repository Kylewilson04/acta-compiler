# Acta Compiler Cryptographic Wire-Format Specification (`v1.7.2`)

This specification defines every canonical serialization, domain-separation tag, integer/float byte width, Ed25519 signing preimage, and Merkle tree construction used by Acta Compiler (`v1.0` through `v1.7.2`) so any independent verifier can reproduce every digest, bundle proof, and scope state reconstruction from scratch without consulting the Rust or SDK source code.

---

## 1. Universal Framing & Primitive Rules

### 1.1 Length-Delimited BLAKE3 (`encode_length_delimited` / `hash_length_delimited`)
Every multi-part BLAKE3 digest in Acta hashes the concatenation of 8-byte unsigned little-endian byte lengths followed immediately by each raw byte slice:

$$\text{encode\_length\_delimited}([p_0, p_1, \dots, p_{k-1}]) = \Vert_{i=0}^{k-1} \left(\text{u64\_le}(\text{len}(p_i)) \;\Vert\; p_i\right)$$

$$\text{hash\_length\_delimited}(P) = \text{BLAKE3-256}(\text{encode\_length\_delimited}(P))$$

When $P = []$ ($0$ slices), $\text{encode\_length\_delimited}([]) = \text{b""}$ and $\text{hash\_length\_delimited}([]) = \text{BLAKE3-256}(\text{b""}) = \texttt{af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262}$.

### 1.2 Tagged Optional Encoding (`0x00` / `0x01`)
Optional fields inside binary preimages use fixed or length-delimited tagged encodings:

| Helper | `None` / `null` Bytes | `Some(v)` Bytes |
| :----- | :-------------------- | :-------------- |
| `encode_opt_uuid` (`17` bytes fixed) | `0x00 * 17` (`17` zero bytes) | `0x01 \|\| uuid_be_16` (`17` bytes) |
| `encode_opt_i64` (`9` bytes fixed) | `0x00 * 9` (`9` zero bytes) | `0x01 \|\| i64_le(v)` (`9` bytes) |
| `encode_opt_hash32` (`33` bytes fixed) | `0x00 * 33` (`33` zero bytes) | `0x01 \|\| hash_32` (`33` bytes) |
| `encode_opt_sig64` (`1` or `65` bytes) | `0x00` (`1` byte) | `0x01 \|\| sig_64` (`65` bytes) |
| `encode_opt_utf8` (`1` or `1 + N` bytes) | `0x00` (`1` byte) | `0x01 \|\| utf8(v)` |
| `encode_opt_jcs` (`1` or `1 + N` bytes) | `0x00` (`1` byte) | `0x01 \|\| rfc8785_jcs_utf8(v)` |

### 1.3 Timestamps, Numbers & Canonical JSON
* **Timestamps**: Truncated to microsecond precision and encoded as signed 64-bit little-endian microseconds since `1970-01-01T00:00:00Z` (`i64_le(timestamp_micros)`).
* **JSON Canonicalization**: RFC 8785 JSON Canonicalization Scheme (JCS) UTF-8 bytes (object keys sorted lexicographically by UTF-16 code units, no insignificant whitespace, IEEE-754 shortest round-trip decimal formatting, `-0.0` serialized as `0`).
* **Strict Ed25519 Verification**: Signatures sign the raw **32-byte** BLAKE3 digest (never hex ASCII). Verifiers MUST reject all low-order torsion public keys (`ed25519_dalek::VerifyingKey::is_weak()`) and non-canonical scalars `S >= L` (`verify_strict`).

---

## 2. Object, Claim & Bundle Commitments

### 2.1 Source Content Commitment (`b"acta:source_content:v1"`)
```text
hash_length_delimited([
  b"acta:source_content:v1",
  utf8(source_descriptor),
  raw_bytes(source_content),
])
```
*(When neither `source_commitment_hex` nor `source_content` is supplied on claim ingest, the default descriptor commitment is `hash_length_delimited([b"acta:source:v1", utf8(source_descriptor)])`.)*

### 2.2 Stored Object `content_hash` (`b"acta:object:v1"`, 13 parts)
```text
hash_length_delimited([
  b"acta:object:v1",
  uuid_be_16(id),
  utf8(tenant_id),
  utf8(obj_type),                  // "intent" | "memory"
  utf8(scope),
  utf8(lifecycle_status),          // "active" | "revoked" | "expired" | "superseded"
  i32_le(priority),                // 4-byte signed little-endian i32
  u32_le(f32_bits(importance)),    // 4-byte IEEE-754 binary32 little-endian
  jcs_utf8(tags),                  // e.g. b'["audit"]'
  jcs_utf8(body),
  i32_le(version),                 // 4-byte signed little-endian i32
  encode_opt_uuid(predecessor_id), // 17 bytes
  i64_le(created_at_micros),       // 8-byte signed little-endian i64
])
```

### 2.3 Claim Group Key (`v1.4+` `b"acta:claim_group:v2"`, 5 parts)
```text
hash_length_delimited([
  b"acta:claim_group:v2",
  utf8(tenant_id),
  utf8(subject),
  utf8(predicate),
  utf8(scope),
])
```
*(Legacy `v1.0–v1.3` `claim_group_key` hashed `[utf8(tenant_id), utf8(subject), utf8(predicate), utf8(object_type), utf8(scope)]` without a domain prefix.)*

### 2.4 Knowledge Claim `content_hash` (`b"acta:claim:v1"`, 20 parts)
`contradiction_ids` are sorted ascending by 16-byte UUID value and formatted as lower-case hyphenated UUID strings in RFC 8785 JCS (`jcs_utf8(sorted_contradiction_ids)`):
```text
hash_length_delimited([
  b"acta:claim:v1",
  uuid_be_16(id),
  utf8(tenant_id),
  claim_group_key_32,
  utf8(scope),
  utf8(subject),
  utf8(predicate),
  jcs_utf8(object_val),
  utf8(object_type),
  u64_le(f64_bits(confidence)),       // 8-byte IEEE-754 binary64 little-endian
  i32_le(source_provenance_class),    // 4-byte signed little-endian i32
  utf8(source_descriptor),
  source_commitment_32,
  utf8(status),
  jcs_utf8(sorted_contradiction_ids),
  encode_opt_i64(valid_from_micros),  // 9 bytes
  encode_opt_i64(valid_to_micros),    // 9 bytes
  i32_le(version),                    // 4-byte signed little-endian i32
  encode_opt_uuid(predecessor_id),    // 17 bytes
  i64_le(created_at_micros),          // 8-byte signed little-endian i64
])
```

### 2.5 Omission List & State Commitments (`commitment.rs` Exact Wire Layout)
* **`full_excluded_hash` (`b"acta:omissions:v1"`)**: `hash_length_delimited([b"acta:omissions:v1", jcs_item_0, jcs_item_1, ...])` where each item is `{"id":"<lowercase-uuid>","reason":"<snake_case_reason>"}`.
* **Sub-commitment (`compute_sub_commitment` for `intent_root`, `knowledge_root`, `memory_root`, and `dependency_commitment`)**:
  Sort 32-byte hashes ascending lexicographically (`h_0 <= h_1 <= ...`), then hash them directly via length-delimited framing **with no domain prefix**:
  ```text
  compute_sub_commitment([h_0, h_1, ...]) = hash_length_delimited([h_0, h_1, ...])
  ```
  * Empty sub-commitment (`0` active items): `BLAKE3-256(b"") == af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`.
  * `knowledge_root` hashes all active non-superseded, non-retracted, temporally valid (`valid_from <= eval_ts <= valid_to`) `KnowledgeClaim.content_hash`es **plus** all active non-superseded `OverrideAttestation.attestation_hash`es in `(tenant_id, scope)` sorted ascending together.
* **`state_commitment` (`compute_state_commitment`, 7 parts, no separate prefix before `schema_version`)**:
  ```text
  compute_state_commitment = hash_length_delimited([
    utf8(schema_version),     // "acta-context-bundle/v1"
    utf8(tenant_id),
    utf8(scope),
    intent_root_32,
    knowledge_root_32,
    memory_root_32,
    permission_root_32,
  ])
  ```
  Commits strictly to the input vault state and Cedar policy root prior to threshold resolution (for example, `kylewilson04` scope `acta-test/v171-audit` at `seq 184` deterministically yields `d0bf021294bc7e0e60cbeeca4ece2c8dcc79bf8b82a4be89c481f9cabd13068a`).
* **`bundle_hash` (`b"acta:bundle:v1"`)**: `hash_length_delimited([b"acta:bundle:v1", jcs_utf8(bundle)])`.

---

## 3. Dispute Override Attestations (`v1` & `v2`)

### 3.1 Offline Client Intent Digest (`b"acta:override_client_sig:v1"`, 6 parts)
`effective_adjudicator` is `adjudicator_id` if it already contains `"::"`, otherwise `f"{tenant_id}::{adjudicator_id}"`:
```text
hash_length_delimited([
  b"acta:override_client_sig:v1",
  utf8(tenant_id),
  utf8(scope),
  uuid_be_16(winning_claim_id),
  utf8(effective_adjudicator),
  utf8(justification),
])
```

### 3.2 Auth-Bound Override Attestation (`b"acta:override:v2"`, 19 parts, `v1.6.3+`)
`overridden_claims` are sorted ascending by `(uuid_be_16(id), content_hash_32)` and serialized via JCS as `[{"content_hash":"...","id":"..."}]`:
```text
hash_length_delimited([
  b"acta:override:v2",
  uuid_be_16(id),
  utf8(tenant_id),
  utf8(scope),
  claim_group_key_32,
  utf8(subject),
  utf8(predicate),
  encode_opt_hash32(source_bundle_hash), // 33 bytes
  uuid_be_16(winning_claim_id),
  winning_claim_content_hash_32,
  jcs_utf8(sorted_overridden_claims),
  utf8(adjudicator_id),
  utf8(adjudicator_auth_kind),           // "oauth_github_principal" | "ed25519_client_sig" | "tenant_session" | "master_admin"
  utf8(justification),
  i32_le(version),
  encode_opt_uuid(predecessor_id),       // 17 bytes
  i64_le(created_at_micros),
  encode_opt_hash32(client_public_key),  // 33 bytes
  encode_opt_sig64(client_signature),    // 1 byte (0x00) or 65 bytes (0x01 || sig_64)
])
```
*(Legacy `b"acta:override:v1"` has 16 parts: identical layout omitting `adjudicator_auth_kind`, `client_public_key`, and `client_signature`.)*

* **Host Signature (`b"acta:override_sig:v1"`)**: Host Ed25519 signs `hash_length_delimited([b"acta:override_sig:v1", utf8(tenant_id), i64_le(evidence_seq_num), attestation_hash_32])`.

---

## 4. Evidence Ledger & Witness Registry Commitments

### 4.1 Evidence Event Hash (`v1`, `v2`, and `v3`)
* **Domain Selection Rule**:
  1. **`b"acta:evidence_event:v3"` (10 parts — Write & Answer-Cache Events)**: Selected whenever `write_summary.is_some() || answer_cache_summary.is_some()`.
  2. **`b"acta:evidence_event:v3"` (12 parts — `v1.7.2+` Witness Registration & Revocation Events)**: Selected whenever `(witness_reg_summary.is_some() || witness_revoke_summary.is_some()) && entry.event_domain == Some("acta:evidence_event:v3")`. (Pre-`v1.7.2` witness entries such as `seq 109` and `seq 183` carry `entry.event_domain == Some("acta:evidence_event:v1")` and verify under `v1` below.)
  3. **`b"acta:evidence_event:v2"` (10 parts — Refusals & Dispute Overrides)**: Selected whenever `refusal_metadata.is_some() || override_summary.is_some()`.
  4. **`b"acta:evidence_event:v1"` (8 parts — Compile Allows & Legacy Pre-`v1.7.2` Witness Events)**: Selected otherwise.
* **`b"acta:evidence_event:v1"` (`8` parts)**:
  `[b"acta:evidence_event:v1", utf8(tenant_id), i64_le(seq_num), prev_hash_32, encode_opt_hash32(bundle_hash), encode_opt_hash32(state_commitment), utf8(policy_result), i64_le(created_at_micros)]`
* **`b"acta:evidence_event:v2"` (`10` parts)**:
  Appends `encode_opt_jcs(refusal_metadata)` and `encode_opt_jcs(override_summary)` to the 8-part base layout. When `refusal_metadata` is present, `state_commitment == hash_length_delimited([b"acta:refusal_meta:v2", jcs_utf8(refusal_metadata)])`.
  * **`RefusalMetadata` Canonical JCS Fields**: Required string keys `operation`, `reason_code`, `summary`; optional keys omitted when `None`/`null`: `target_scope` (`String`), `scope_state_commitment` (`64`-char lowercase hex), `attempted_checkpoint_hash` (`64`-char lowercase hex on `anchor_checkpoint` refusals), `signing_domain` (`String`, e.g. `"acta:object_client_sig:v1"` on `v1.7.2+` signature refusals), and `expected_intent_digest_hex` (`64`-char lowercase hex on `v1.7.2+` signature refusals).
* **`b"acta:evidence_event:v3"` (`10` parts for `write_summary` / `answer_cache_summary`; `12` parts for `v1.7.2+` `witness_reg_summary` / `witness_revoke_summary`)**:
  * For `write_summary` or `answer_cache_summary` (`10` parts):
    `[b"acta:evidence_event:v3", utf8(tenant_id), i64_le(seq_num), prev_hash_32, encode_opt_hash32(bundle_hash), encode_opt_hash32(state_commitment), utf8(policy_result), i64_le(created_at_micros), encode_opt_jcs(write_summary), encode_opt_jcs(answer_cache_summary)]`
  * For `v1.7.2+` `witness_reg_summary` or `witness_revoke_summary` (`12` parts, binding the canonical JCS witness summary directly into `event_hash`):
    `[b"acta:evidence_event:v3", utf8(tenant_id), i64_le(seq_num), prev_hash_32, encode_opt_hash32(bundle_hash), encode_opt_hash32(state_commitment), utf8(policy_result), i64_le(created_at_micros), 0x00, 0x00, encode_opt_jcs(witness_reg_summary), encode_opt_jcs(witness_revoke_summary)]`
* **Host Signature (`b"acta:evidence_sig:v1"`)**: Host Ed25519 signs `hash_length_delimited([b"acta:evidence_sig:v1", utf8(tenant_id), i64_le(seq_num), prev_hash_32, event_hash_32])`.

### 4.2 Witness Registration & Revocation `state_commitment` Domains
* **`b"acta:witness_reg:v1"` (4 parts)**: `[b"acta:witness_reg:v1", utf8(tenant_id), utf8(witness_id), pubkey_32]`
* **`b"acta:witness_reg:v2"` (5 parts)**: `[b"acta:witness_reg:v2", utf8(tenant_id), utf8(witness_id), pubkey_32, utf8(registered_by)]`
* **`b"acta:witness_reg:v3"` (6 parts, `v1.6.3+`)**: `[b"acta:witness_reg:v3", utf8(tenant_id), utf8(witness_id), pubkey_32, utf8(registered_by), encode_opt_utf8(description)]`
* **`b"acta:witness_revoke:v1"` (6 parts, `v1.6.3`)**: `[b"acta:witness_revoke:v1", utf8(tenant_id), utf8(witness_id), pubkey_32, utf8(revoked_by), utf8(reason)]`
* **`b"acta:witness_revoke:v2"` (8 parts, `v1.6.4+`)**:
  `[b"acta:witness_revoke:v2", utf8(tenant_id), utf8(witness_id), pubkey_32, utf8(revoked_by), utf8(revocation_mode), encode_opt_i64(effective_from_tree_size), utf8(reason)]`
  * `revocation_mode == "compromise"` requires `effective_from_tree_size == None` (`0x00 * 9`) and retroactively quarantines all anchors by `witness_id`.
  * `revocation_mode == "retire"` requires `effective_from_tree_size == Some(revocation_seq_num)` (`0x01 || i64_le(seq)`) and preserves historical anchors at `tree_size < effective_from_tree_size` while blocking all post-retirement anchors.

---

## 5. Merkle Checkpoints & Witness Cosignatures

### 5.1 Active Scheme: `rfc6962-sha256-v1` (`v1.6.1+`)
Follows RFC 6962 §2.1 binary Merkle tree hashing over `event_hash` leaves `1..=tree_size`:
* **Empty Root**: `SHA-256(b"")`
* **Leaf Hash**: `SHA-256(0x00 || event_hash_32)`
* **Interior Node Hash**: `SHA-256(0x01 || left_32 || right_32)`
* **Tree Split**: For `n > 1`, `k = largest_power_of_two_less_than(n)`, `MTH(D[0..n]) = SHA-256(0x01 || MTH(D[0..k]) || MTH(D[k..n]))`.

### 5.2 Historical Quarantined Scheme: `acta-blake3-merkle-v1` (`v1.6.0` Only)
Used solely prior to `v1.6.1` (quarantined anchor rows recorded under `v1.6.0` and preserved by PostgreSQL's append-only trigger):
* **Empty Root**: `hash_length_delimited([b"acta:merkle_empty:v1"])`
* **Leaf Hash**: `hash_length_delimited([b"acta:merkle_leaf:v1", i64_le(seq_num), event_hash_32])`
* **Interior Node Hash**: `hash_length_delimited([b"acta:merkle_node:v1", left_32, right_32])`
* **Tree Split**: Identical RFC 6962 `largest_power_of_two_less_than(n)` binary tree split.

### 5.3 Checkpoint & Witness Signatures
* **`checkpoint_hash` (`b"acta:checkpoint:v1"`, 6 parts)**: `hash_length_delimited([b"acta:checkpoint:v1", utf8(tenant_id), i64_le(tree_size), head_event_hash_32, merkle_root_32, i64_le(issued_at_micros)])`
* **Host Checkpoint Signature (`b"acta:checkpoint_sig:v1"`)**: Host Ed25519 signs `hash_length_delimited([b"acta:checkpoint_sig:v1", utf8(tenant_id), checkpoint_hash_32])`
* **External Witness Cosignature (`b"acta:witness_sig:v1"`)**: Witness Ed25519 signs `hash_length_delimited([b"acta:witness_sig:v1", utf8(tenant_id), i64_le(tree_size), checkpoint_hash_32])`.

---

## 6. Epistemic Dispute Resolution, Asymmetric Contradictions & Counterfactual Replay (`v1.6.6`–`v1.7.2`)

### 6.1 `DisputeRecord.margin`, Asymmetric `contradiction_ids` & `LAPSED_OVERRIDE_REOPENED`
* **Universal `DisputeRecord.margin` (`v1.6.6+`)**: Every `DisputeRecord` carries `margin: f64` computed by grouping `competing_claims` by `(type_family, jcs(object_val))` into `ValueBucket`s, computing corroborated `effective_confidence`, sorting buckets descending, and setting `margin = round_9(buckets[0].effective_confidence - buckets[1].effective_confidence)` when `buckets.len() >= 2` (or `0.0` when `buckets.len() < 2`). Pre-`v1.6.6` stored bundles omit `margin` (`None`) so historical `bundle_hash` values verify unchanged.
* **Asymmetric Contradiction Edges (`v1.7.2+`)**: When an active claim `C` declares `contradiction_ids: [target_id]` and `target_id` is active, only `target_id` is marked in `contradicted_active_ids`. If `C` is in the same logical group as `target_id`, the shared group halts with `BLOCKING_CONTRADICTION` over both claims; if `C` is in its own separate logical group (e.g., `dock_strike = true` contradicting `lead_days = 14`), `target_id`'s group halts with `BLOCKING_CONTRADICTION` while `C`'s own group resolves normally rather than disputing itself.
* **Reopened Lapsed Override Escalation (`LAPSED_OVERRIDE_REOPENED`)**: When an active signed `OverrideAttestation` lapses because unseen conflicting evidence arrived (`lapsed_override.is_some()`), escalation is mandatory (`reason_code: "LAPSED_OVERRIDE_REOPENED"`).

### 6.2 Time-Pinned Counterfactual Replay & Observable `resolver_compat` (`v1.7.2+`)
* **Strict `as_of` Snapshot & Supersession Cutoff**: Filters `objects`, `knowledge_claims`, `override_attestations`, and active-hash scans to `created_at <= pinned_evaluation_time`, treating any supersession with `succ.created_at > pinned_evaluation_time` as not yet applied.
* **Observable `resolver_compat`**: Replay responses expose `resolver_compat` (`"legacy_pre_v171"` for pre-`v1.7.1` source bundles, `"legacy_v171"` for `v1.7.1` bidirectional-contradiction bundles such as `seq 171`, or `"v172_current"` for `v1.7.2+` compiles) so legacy compatibility mode is directly observable while reproducing every historical `source_bundle_hash` bit-for-bit.

---

## 7. `v1.6.7` Production-Readiness Rules

* **Read-Tool Non-Logging Rule**: Read-only endpoints (`acta_verify_bundle`, `GET /v1/bundles/:hash/export`, `acta_replay_counterfactual`, `acta_get_checkpoint`, `acta_list_evidence`, `acta_trace_claim_impact`, `acta_verify_state_rebuild`) NEVER append to `evidence_history` on malformed hex, wrong-length hex, out-of-bounds selectors, or `not_found` hashes. Refusal logging on read endpoints is reserved strictly for security-relevant events (explicit cross-tenant lock violations, Cedar policy blocks/escalations, and tampered archive signatures).
* **Rendered Body & Value Escaping (`context_text`)**: Escapes `[` (`\u005b`), `]` (`\u005d`), `U+2028`, `U+2029`, and C0/C1 control characters inside `context_text` atoms while keeping `StoredObject.body` and `KnowledgeClaim.object_val` untouched for RFC 8785 JCS hashing.
* **Zero-Oracle Cross-Tenant Isolation**: Foreign `bundle_hash`, `item_id`, `winning_claim_id`, `source_bundle_hash`, and `witness_id` probes return character-for-character identical `not found` errors as nonexistent identifiers.

---

## 8. `v1.7.0` PPA 1 Full Parity & Reverse Decision Recall Wire Formats

### 8.1 `WriteLedgerSummary` & `AnswerCacheLedgerSummary` Commitments
* **`WriteLedgerSummary` Commitment (`b"acta:write_event:v1"`, 2 parts)**:
  `hash_length_delimited([b"acta:write_event:v1", rfc8785_jcs_utf8(write_summary)])` (stored in `evidence_history.state_commitment` for write events).
* **`AnswerCacheLedgerSummary` Commitment (`b"acta:answer_cache:v1"`, 2 parts)**:
  `hash_length_delimited([b"acta:answer_cache:v1", rfc8785_jcs_utf8(answer_cache_summary)])` (stored in `evidence_history.state_commitment` for answer-cache events).

### 8.2 State-Conditioned Answer Cache Receipts (PPA 1 Independent Claim 19, Claims 19–27)
* **Query Text Digest (`b"acta:query:v1"`, 2 parts)**: `hash_length_delimited([b"acta:query:v1", utf8(query_text)])`
* **Answer Text Digest (`b"acta:answer:v1"`, 2 parts)**: `hash_length_delimited([b"acta:answer:v1", utf8(answer_text)])`
* **Host Receipt Signature (`b"acta:answer_cache_sig:v1"`, 4 parts)**:
  Host Ed25519 signs `hash_length_delimited([b"acta:answer_cache_sig:v1", utf8(tenant_id), i64_le(evidence_seq_num), cache_commitment_32])`.

### 8.3 Clock-Free Client Ed25519 Author Signing Preimages & Refusal Digests (`v1.7.0`–`v1.7.2`)
Clients signing content offline sign either raw `content_hash` or the clock-free intent preimages below (`ed25519_sign(sk, BLAKE3-256(preimage))`):

* **`b"acta:object_client_sig:v1"` (`10` parts, refusal code `invalid_object_client_sig` / `invalid_object_client_signature`)**:
  `[b"acta:object_client_sig:v1", utf8(tenant_id), utf8(obj_type), utf8(scope), utf8(lifecycle_status), i32_le(priority), u32_le(f32_bits(importance)), jcs(tags), jcs(body), encode_opt_uuid(predecessor_id)]`
* **`b"acta:claim_client_sig:v1"` (`16` parts, refusal code `invalid_claim_client_signature`)**:
  `[b"acta:claim_client_sig:v1", utf8(tenant_id), utf8(scope), utf8(subject), utf8(predicate), jcs(object_val), utf8(object_type), u64_le(f64_bits(confidence)), i32_le(source_provenance_class), utf8(source_descriptor), source_commitment_32, utf8(status), jcs(sorted_contradiction_ids), encode_opt_i64(valid_from_micros), encode_opt_i64(valid_to_micros), encode_opt_uuid(predecessor_id)]`
* **`b"acta:retract_client_sig:v1"` (`4` parts, refusal code `invalid_retract_client_signature`)**:
  `[b"acta:retract_client_sig:v1", utf8(tenant_id), uuid_be_16(claim_id), utf8(reason)]`
* **`b"acta:answer_client_sig:v1"` (`8` parts, refusal code `invalid_answer_client_signature`)**:
  `[b"acta:answer_client_sig:v1", utf8(tenant_id), utf8(scope), utf8(task_id), query_hash_32, source_bundle_hash_32, state_commitment_32, answer_hash_32]`

On any failed client Ed25519 signature (`v1.7.2+`), both the HTTP/MCP error body and `RefusalMetadata` include the tool-specific `reason_code`, `signing_domain`, and `expected_intent_digest_hex`.

---

## 9. `v1.7.1` & `v1.7.2` PPA 1 Refinements, Corroboration Proofs, Claim 25 Cache & Signed State Rebuild

### 9.1 Post-Corroboration `min_confidence` & Full Winning-Bucket Bundle Proofs (`v1.7.2+`)
* **ValueBucket Pooling Prior to `min_confidence`**: Active claims in a logical group (`b"acta:claim_group:v2"`) are pooled by `(type_family, rfc8785_jcs(object_val))` into `ValueBucket`s and corroborated via damped noisy-OR (`eff = min(0.9999, c_0 + sum_{i>=1} (1 - eff) * (damping * c_i))`, default `damping = 0.50`, rounded to 9 decimals) **before** evaluating `min_confidence` (`0.70`).
* **Corroborating Claims in `ExportArchive` (`v1.7.2+`)**: Whenever a `ResolutionRecord` has `override_attestation == None` and `winning_claim.corroborating_count > 1`, `GET /v1/bundles/:hash/export` and `acta_verify_bundle` include **every corroborating claim in the winning `ValueBucket`** (from `suppressed_claim_ids`) in both `archive.claims` and `merkle_proof.write_entry_proofs`. Offline verifiers (`acta-verify`, Python `acta_sdk`, and TypeScript `@acta/sdk`) verify every corroborating claim's `content_hash`, author signature, and write-entry Merkle inclusion proof, and independently re-derive `effective_confidence`, `corroborating_count`, and `corroborating_sources`.

### 9.2 Explicit Retraction Omission Labels (`OmissionReason`)
* **`"retracted"`**: Emitted on a claim or object withdrawn by a `revoked` successor (`predecessor_id = item.id`), distinct from `"superseded"`.
* **`"retraction_tombstone"`**: Emitted on the `revoked` tombstone row itself inside `OmissionRecord` (`b"acta:omissions:v1"`), distinct from `"lifecycle_expired"`.

### 9.3 PPA 1 Claim 25 Dependency-Scoped Answer Cache & Claim-ID Narrowing (`b"acta:cache_dep_root:v1"`, 7 parts)
* **`validity_mode`**: Defaults to `"dependency_subset"` (alongside selectable `"scope_root"` and optional `dependency_ids` narrowing).
* **`task_dependency_commitment` (`b"acta:cache_dep_root:v1"`)**:
  ```text
  hash_length_delimited([
    b"acta:cache_dep_root:v1",
    utf8(tenant_id),
    utf8(scope),
    permission_root_32,
    intent_root_32,
    selected_memory_root_32,
    relevant_knowledge_root_32,
  ])
  ```
  * When `dependency_ids` is omitted (`pinned_claim_ids` empty), `relevant_knowledge_root_32` hashes all active claims and active overrides in the referenced `claim_group_key`s (plus active incoming `contradiction_ids` targeting them).
  * When `dependency_ids` explicitly narrows to specific claim UUIDs (`pinned_claim_ids` non-empty, `v1.7.2+`), `relevant_knowledge_root_32` hashes only the active claims in `pinned_claim_ids` (plus active incoming `contradiction_ids` targeting `pinned_claim_ids`), so mutations to non-listed claims — even in the same `(subject, predicate)` group — leave `task_dependency_commitment` unchanged and preserve a cache hit.

### 9.4 Chained One-Time Cache Invalidation Receipts Preserving Cacher Auth (`v1.7.2+`)
* On first stale (`"stale_dependency_commitment"` or `"stale_state_commitment"`) or TTL-expired (`"expired_ttl"`) lookup, PostgreSQL atomically inserts one row in `cached_answer_invalidations` and appends **at most one** `AnswerCacheLedgerSummary` (`event_kind = "invalidated"`) onto `evidence_history` (`b"acta:evidence_event:v3"`).
* **Preserved Cacher Auth (`v1.7.2+`)**: Invalidation summaries preserve the original cached entry's `cached_by`, `cacher_auth_kind` (e.g. `"ed25519_client_sig"`), `client_public_key`, and `client_signature` unchanged, recording the lookup caller separately in optional `invalidated_by` and `invalidator_auth_kind`.
* **Inline Evidence & Impact Reason (`v1.7.2+`)**: `acta_lookup_cached_answer` returns `invalidation_evidence` inline alongside `invalidation_evidence_seq_num` and `invalidation_newly_recorded`, and `acta_trace_claim_impact` exposes `invalidation_reason` on each `impacted_cached_answers` row.

### 9.5 Host-Signed Standalone Offline State Rebuild Archive (`"acta-state-rebuild-archive/v1"`, `v1.7.2+`)
* `StateRebuildArchive` always serializes `"override_attestations"` (as `[]` when empty) and binds its evaluation clock and scope header with a host Ed25519 signature so `evaluated_at` cannot be swapped offline:
  * **Rebuild Archive Header Hash (`b"acta:rebuild_header:v1"`, 7 parts)**:
    ```text
    header_hash = hash_length_delimited([
      b"acta:rebuild_header:v1",
      utf8(schema_version),
      utf8(tenant_id),
      utf8(scope),
      i64_le(up_to_seq),
      i64_le(evaluated_at_micros),
      permission_root_32,
    ])
    ```
  * **Host Rebuild Header Signature (`b"acta:rebuild_sig:v1"`, 3 parts)**:
    Host Ed25519 signs `hash_length_delimited([b"acta:rebuild_sig:v1", utf8(tenant_id), header_hash_32])`.
* When `up_to_seq` is explicitly specified (`acta_verify_state_rebuild(scope, up_to_seq)`), `evaluated_at` defaults deterministically to `evidence_chain[up_to_seq - 1].created_at` so historical prefix rebuilds (such as `acta-test/v171-audit` at `up_to_seq = 184`) are time-invariant across future wall-clock dates.
