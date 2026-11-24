# Acta Compiler Cryptographic Wire-Format Specification (`v1.7.1`)

This specification defines every canonical serialization, domain-separation tag, integer/float byte width, Ed25519 signing preimage, and Merkle tree construction used by Acta Compiler (`v1.0` through `v1.7.1`) so any independent verifier can reproduce every digest and signature from scratch without consulting the Rust or SDK source code.

---

## 1. Universal Framing & Primitive Rules

### 1.1 Length-Delimited BLAKE3 (`encode_length_delimited` / `hash_length_delimited`)
Every multi-part BLAKE3 digest in Acta hashes the concatenation of 8-byte unsigned little-endian byte lengths followed immediately by each raw byte slice:

$$\text{encode\_length\_delimited}([p_0, p_1, \dots, p_{k-1}]) = \Vert_{i=0}^{k-1} \left(\text{u64\_le}(\text{len}(p_i)) \;\Vert\; p_i\right)$$

$$\text{hash\_length\_delimited}(P) = \text{BLAKE3-256}(\text{encode\_length\_delimited}(P))$$

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

### 2.5 Omission List & State Commitments
* **`full_excluded_hash` (`b"acta:omissions:v1"`)**: `hash_length_delimited([b"acta:omissions:v1", jcs_item_0, jcs_item_1, ...])` where each item is `{"id":"<lowercase-uuid>","reason":"<snake_case_reason>"}`.
* **Sub-commitment (`intent_root`, `knowledge_root`, `memory_root`)**: Sort 32-byte active content hashes ascending, then `hash_length_delimited([b"acta:sub_commitment:v1", h_0, h_1, ...])`.
* **`state_commitment` (`b"acta:state:v1"`)**: `hash_length_delimited([b"acta:state:v1", utf8(schema_version), utf8(tenant_id), utf8(scope), intent_root_32, knowledge_root_32, memory_root_32, permission_root_32])`. Commits strictly to the input vault state and Cedar policy root prior to threshold resolution.
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

### 4.1 Evidence Event Hash (`b"acta:evidence_event:v1"` vs `b"acta:evidence_event:v2"`)
* **Domain Rule**: An entry uses `b"acta:evidence_event:v1"` when **both** `refusal_metadata` and `override_summary` are `None` (including compile allows, witness registrations, and witness revocations/retirements, whose structured preimages are bound into `state_commitment`). It uses `b"acta:evidence_event:v2"` iff `refusal_metadata` or `override_summary` is present.
* **`b"acta:evidence_event:v1"` (8 parts)**:
  `[b"acta:evidence_event:v1", utf8(tenant_id), i64_le(seq_num), prev_hash_32, encode_opt_hash32(bundle_hash), encode_opt_hash32(state_commitment), utf8(policy_result), i64_le(created_at_micros)]`
* **`b"acta:evidence_event:v2"` (10 parts)**:
  Appends `encode_opt_jcs(refusal_metadata)` and `encode_opt_jcs(override_summary)` to the 8-part layout above. When `refusal_metadata` is present, `state_commitment == hash_length_delimited([b"acta:refusal_meta:v2", jcs_utf8(refusal_metadata)])`.
  * **`RefusalMetadata` Canonical JCS Fields**: Required string keys `operation`, `reason_code`, `summary`; optional keys omitted when `None`/`null`: `target_scope` (`String`), `scope_state_commitment` (`64`-char lowercase hex), and `attempted_checkpoint_hash` (`64`-char lowercase hex, populated on all `anchor_checkpoint` refusals in `v1.6.6+`).
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
Used solely prior to `v1.6.1` (e.g., quarantined anchor rows recorded under `v1.6.0` and preserved by PostgreSQL's append-only trigger):
* **Empty Root**: `hash_length_delimited([b"acta:merkle_empty:v1"])`
* **Leaf Hash**: `hash_length_delimited([b"acta:merkle_leaf:v1", i64_le(seq_num), event_hash_32])`
* **Interior Node Hash**: `hash_length_delimited([b"acta:merkle_node:v1", left_32, right_32])`
* **Tree Split**: Identical RFC 6962 `largest_power_of_two_less_than(n)` binary tree split.

### 5.3 Checkpoint & Witness Signatures
* **`checkpoint_hash` (`b"acta:checkpoint:v1"`, 6 parts)**: `hash_length_delimited([b"acta:checkpoint:v1", utf8(tenant_id), i64_le(tree_size), head_event_hash_32, merkle_root_32, i64_le(issued_at_micros)])`
* **Host Checkpoint Signature (`b"acta:checkpoint_sig:v1"`)**: Host Ed25519 signs `hash_length_delimited([b"acta:checkpoint_sig:v1", utf8(tenant_id), checkpoint_hash_32])`
* **External Witness Cosignature (`b"acta:witness_sig:v1"`)**: Witness Ed25519 signs `hash_length_delimited([b"acta:witness_sig:v1", utf8(tenant_id), i64_le(tree_size), checkpoint_hash_32])`.

---

## 6. Epistemic Dispute Resolution & Time-Pinned Counterfactual Replay (`v1.6.6+`)

### 6.1 `DisputeRecord.margin` & Reopened Override Ruling (`LAPSED_OVERRIDE_REOPENED`)
* **Universal `DisputeRecord.margin` (`v1.6.6+`)**: Every `DisputeRecord` carries `margin: f64` computed by grouping `competing_claims` by `(type_family, jcs(object_val))` into `ValueBucket`s, computing corroborated `effective_confidence`, sorting buckets descending, and setting `margin = round_9(buckets[0].effective_confidence - buckets[1].effective_confidence)` when `buckets.len() >= 2` (or `0.0` when `buckets.len() < 2`). Pre-`v1.6.6` stored bundles omit `margin` (`None`) so historical `bundle_hash` values verify unchanged.
* **Reopened Lapsed Override Escalation (`LAPSED_OVERRIDE_REOPENED`)**: When an active signed `OverrideAttestation` lapses because unseen conflicting evidence arrived (`lapsed_override.is_some()`), escalation is mandatory regardless of numeric confidence margin so automated ingestion can never silently overturn a human or committee adjudication. Unless superseded by structural `BLOCKING_CONTRADICTION`, `INSUFFICIENT_CONFIDENCE`, or `TYPE_MISMATCH`, the dispute emits `reason_code: "LAPSED_OVERRIDE_REOPENED"` alongside `margin`.

### 6.2 Time-Pinned Counterfactual Replay (`acta_replay_counterfactual` / `POST /v1/replay`)
* **Strict `as_of` Snapshot & Supersession Cutoff**: When replaying `source_bundle_hash` (pinned to `orig_bundle.issued_at`) or an explicit `evaluation_time`, retrieval filters `objects`, `knowledge_claims`, `override_attestations`, and active-hash scans to `created_at <= pinned_evaluation_time`, and treats any supersession (`succ.predecessor_id = row.id`) with `succ.created_at > pinned_evaluation_time` as not yet applied.
* **Validity & Outcome Diff Flags**:
  * `replay_valid: bool`: `true` iff `reproduced_source_bundle_bit_for_bit == true` (when `source_bundle_hash` is supplied) and policy allows simulation.
  * `resolution_changed: bool`: `true` iff policy decision class, resolved `(claim_group_key, winning_claim_id, winning_claim_content_hash, override_attestation_hash)` tuples, or disputed `(claim_group_key, normalized_reason_code, candidate_id_hashes)` tuples differ between baseline and counterfactual.

## 7. `v1.6.7` Production-Readiness Rules

* **Read-Tool Non-Logging Rule**: Read-only endpoints (`acta_verify_bundle`, `GET /v1/bundles/:hash/export`, `acta_replay_counterfactual`, `acta_get_checkpoint`, `acta_list_evidence`) NEVER append to `evidence_history` on malformed hex, wrong-length hex, out-of-bounds selectors, or `not_found` hashes. Refusal logging on read endpoints is reserved strictly for security-relevant events (explicit cross-tenant lock violations, Cedar policy blocks/escalations, and tampered archive signatures).
* **Rendered Body & Value Escaping (`context_text`)**: Inside `context_text`, all JSON string literals in object bodies (`[INTENT ...]`, `[MEMORY ...]`) and claim `object_val` values — as well as header metadata atoms — escape `[` (`\u005b`), `]` (`\u005d`), `U+2028` (`\u2028`), `U+2029` (`\u2029`), and all C0/C1 control characters (`U+0000..=U+001F`, `U+007F..=U+009F`). No substring matching `[FACT `, `[DISPUTE`, `[INTENT`, or `[MEMORY` can appear anywhere in `context_text` except at column 0 of an Acta-emitted line, while stored `StoredObject.body` and `KnowledgeClaim.object_val` remain untouched for canonical RFC 8785 JCS hashing.
* **Claim `object_type` Validation**: `acta_ingest_claim` / `POST /v1/claims` validates `object_val` against `object_type` (`int`, `uint`, `float`/`number`, `bool`, `string`, `array`, `object`) prior to policy/DB writes, rejecting mismatches with `400` and zero ledger mutation.
* **Paginated Evidence & Full-Chain Verification**: `acta_list_evidence` (`GET /v1/tenants/:id/evidence`) and `acta_verify_bundle` (`proof_mode = "full"`) accept `from_seq` (`>= 1`, default `1`) and `limit` (`1..=500`, default `100`), returning `total_count`, `from_seq`, `limit`, `has_more`, and `next_seq` while `acta_verify_bundle` still verifies the complete `1..=bundle_seq` chain in server memory.
* **Override-Adjudicated Fact Tiering & `resolved_facts_omitted`**: Signed human/committee override-adjudicated `ResolutionRecord`s are reserved in Tier 1b ahead of background intents (`Tier 1c`), and both `ContextBundle` (`skip_serializing_if = "Option::is_none"`) and `CompileResponse` emit `resolved_facts_omitted: usize`.
* **Zero-Oracle Cross-Tenant Isolation**: Every lookup filters `WHERE tenant_id = $caller_tenant` prior to returning results; foreign `bundle_hash`, `winning_claim_id`, `source_bundle_hash`, and `witness_id` probes return character-for-character identical `not found` errors as nonexistent identifiers.

---

## 8. `v1.7.0` PPA 1 Full Parity & Reverse Decision Recall Wire Formats

### 8.1 `acta:evidence_event:v3` (`WriteLedgerSummary` & `AnswerCacheLedgerSummary`)
To preserve 100% bit-for-bit backward compatibility with all `v1.0`–`v1.6.7` ledger entries (`acta:evidence_event:v1` and `acta:evidence_event:v2`), `acta:evidence_event:v3` is selected **if and only if** `write_summary.is_some() || answer_cache_summary.is_some()`:

* **`b"acta:evidence_event:v3"` (`10` length-delimited parts)**:
  `[b"acta:evidence_event:v3", utf8(tenant_id), i64_le(seq_num), prev_hash_32, encode_opt_hash32(bundle_hash), encode_opt_hash32(state_commitment), utf8(policy_result), i64_le(created_at_micros), encode_opt_jcs(write_summary), encode_opt_jcs(answer_cache_summary)]`
* **`WriteLedgerSummary` Commitment (`b"acta:write_event:v1"`, 2 parts)**:
  `hash_length_delimited([b"acta:write_event:v1", rfc8785_jcs_utf8(write_summary)])` (stored in `evidence_history.state_commitment` for write events). Each accepted non-noop `ingest_object`, `ingest_claim`, and `retract_claim` embeds the complete canonical `StoredObject` or `KnowledgeClaim` inside `write_summary` so `acta_verify_state_rebuild` can verify `content_hash`, client Ed25519 signatures, and scope `state_commitment` from `evidence_history` alone.
* **`AnswerCacheLedgerSummary` Commitment (`b"acta:answer_cache:v1"`, 2 parts)**:
  `hash_length_delimited([b"acta:answer_cache:v1", rfc8785_jcs_utf8(answer_cache_summary)])` (stored in `evidence_history.state_commitment` for answer-cache write events).

### 8.2 State-Conditioned Answer Cache Receipts (PPA 1 Independent Claim 19, Claims 19–27)
* **Query Text Digest (`b"acta:query:v1"`, 2 parts)**: `hash_length_delimited([b"acta:query:v1", utf8(query_text)])`
* **Answer Text Digest (`b"acta:answer:v1"`, 2 parts)**: `hash_length_delimited([b"acta:answer:v1", utf8(answer_text)])`
* **Host Receipt Signature (`b"acta:answer_cache_sig:v1"`, 4 parts)**:
  Host Ed25519 signs `hash_length_delimited([b"acta:answer_cache_sig:v1", utf8(tenant_id), i64_le(evidence_seq_num), cache_commitment_32])`.
* **Lookup Re-Verification & `O(1)` Invalidation**: `acta_lookup_cached_answer` computes live `current_state_commitment` for `(tenant_id, scope)` without compiling or scanning prior bundles, returning a cache hit only if `current_state_commitment == cached.state_commitment`, `expires_at > now`, `compute_answer_text_hash(answer_text) == cached.answer_hash`, and `verify_answer_cache_signature` passes (tampered stored text or receipt signatures log a signed `tampered_cached_answer` refusal).

### 8.3 Clock-Free Client Ed25519 Author Signing Preimages (PPA 1 Claim 8)
Clients signing content offline without knowing the server's microsecond `created_at` clock or server-assigned UUID may sign either raw `content_hash` (`b"acta:client_sig:v1"`) or the clock-free intent preimages below (`ed25519_sign(sk, BLAKE3-256(preimage))`):

* **`b"acta:object_client_sig:v1"` (`10` parts)**:
  `[b"acta:object_client_sig:v1", utf8(tenant_id), utf8(obj_type), utf8(scope), utf8(lifecycle_status), i32_le(priority), u32_le(f32_bits(importance)), jcs(tags), jcs(body), encode_opt_uuid(predecessor_id)]`
* **`b"acta:claim_client_sig:v1"` (`16` parts)**:
  `[b"acta:claim_client_sig:v1", utf8(tenant_id), utf8(scope), utf8(subject), utf8(predicate), jcs(object_val), utf8(object_type), u64_le(f64_bits(confidence)), i32_le(source_provenance_class), utf8(source_descriptor), source_commitment_32, utf8(status), jcs(sorted_contradiction_ids), encode_opt_i64(valid_from_micros), encode_opt_i64(valid_to_micros), encode_opt_uuid(predecessor_id)]`
* **`b"acta:retract_client_sig:v1"` (`4` parts)**:
  `[b"acta:retract_client_sig:v1", utf8(tenant_id), uuid_be_16(claim_id), utf8(reason)]`
* **`b"acta:answer_client_sig:v1"` (`8` parts)**:
  `[b"acta:answer_client_sig:v1", utf8(tenant_id), utf8(scope), utf8(task_id), query_hash_32, source_bundle_hash_32, state_commitment_32, answer_hash_32]`

---

## 9. `v1.7.1` Six-Point PPA 1 Refinements, Claim 25 Dependency Cache & Offline State Rebuild

### 9.1 Post-Corroboration `min_confidence` & Historical Replay Compatibility
* **ValueBucket Pooling Prior to `min_confidence`**: Active claims in a logical group (`b"acta:claim_group:v2"`) are pooled by `(type_family, rfc8785_jcs(object_val))` into `ValueBucket`s and corroborated via damped noisy-OR (`eff = c_0 + sum_{i>=1} (1 - eff) * (damping * c_i)`, default `damping = 0.50`) **before** evaluating `min_confidence` (`0.70`). Two independent agreeing claims at `0.60` corroborate to `0.60 + (1.0 - 0.60) * (0.50 * 0.60) = 0.72 >= 0.70` and resolve as `[FACT ... effective_confidence=0.7200 corroborated_by=2 ...]`. If `buckets[0].effective_confidence < min_confidence`, the group escalates with `INSUFFICIENT_CONFIDENCE`.
* **Historical Bundle Replay (`SimulationCompat.legacy_pre_v171_resolver`)**: `acta_replay_counterfactual` automatically detects pre-`v1.7.1` source bundles when bit-for-bit baseline verification runs so historical `seq 1..head` bundles reproduce bit-for-bit.

### 9.2 Explicit Retraction Omission Labels (`OmissionReason`)
* **`"retracted"`**: Emitted on a target claim withdrawn by `acta_retract_claim` (where an active `status = "revoked"` tombstone has `predecessor_id = claim.id`), distinct from `"superseded"` (where an active replacement claim advances the value).
* **`"retraction_tombstone"`**: Emitted on the `status = "revoked"` tombstone row itself inside `OmissionRecord` (`b"acta:omissions:v1"`), distinct from `"lifecycle_expired"`.

### 9.3 PPA 1 Claim 25 Dependency-Scoped Answer Cache (`b"acta:cache_dep_root:v1"`, 7 parts)
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
  where `relevant_knowledge_root_32` is `compute_sub_commitment` over active claim `content_hash`es and active `OverrideAttestation.attestation_hash`es in the referenced `claim_group_key`s (plus any explicit `contradiction_ids` edges targeting referenced claims). Unrelated claims or memories in the same scope leave `task_dependency_commitment` unchanged.

### 9.4 Chained One-Time Cache Invalidation Receipts (`AnswerCacheLedgerSummary`)
* When `acta_lookup_cached_answer` detects a stale (`"stale_dependency_commitment"` or `"stale_state_commitment"`) or TTL-expired (`"expired_ttl"`) cached answer, PostgreSQL atomically inserts one row in `cached_answer_invalidations` (`PRIMARY KEY (tenant_id, cache_id)`) and appends **at most one** `AnswerCacheLedgerSummary` (`event_kind = "invalidated"`) onto `evidence_history` (`b"acta:evidence_event:v3"`), returning `invalidation_evidence_seq_num` and `invalidation_newly_recorded` (`true` on first invalidation, `false` on repeat lookups). Lookups for uncached queries (`"miss_not_found"`) never mutate `evidence_history`.
* **Optional `v1.7.1` Fields on `AnswerCacheLedgerSummary`** (`skip_serializing_if = "Option::is_none"` so all `v1.7.0` entries serialize identically): `event_kind` (`"cached"` | `"invalidated"`), `validity_mode` (`"dependency_subset"` | `"scope_root"`), `task_dependency_commitment` (64-hex), `invalidation_reason`, `observed_state_commitment` (64-hex), and `observed_dependency_commitment` (64-hex).

### 9.5 `latest_anchored_checkpoint` Visibility
* `acta_get_checkpoint` (`GET /v1/tenants/:id/checkpoint`) and `acta_whoami` expose `head_witnessed: bool`, `latest_anchored_checkpoint: Option<SignedTreeHead>`, `consistency_proof_from_latest_anchor: Vec<String>`, and `latest_anchor_consistency_verified: Option<bool>` whenever head `tree_size` moves ahead of the latest witness-cosigned checkpoint `M < N`.

### 9.6 Standalone Offline State Rebuild Archive (`"acta-state-rebuild-archive/v1"`)
* `acta_verify_state_rebuild(include_proof_archive: true)` (`GET /v1/tenants/:id/state-rebuild?scope=...&include_proof_archive=true`) exports a self-contained `StateRebuildArchive` (`schema_version = "acta-state-rebuild-archive/v1"`) containing `evidence_chain` (`1..=up_to_seq`), scoped `override_attestations` (bijectively verified against `override_summary` entries so none can be stripped or injected), `permission_root`, `checkpoint`, `latest_anchored_checkpoint`, and `consistency_proof_from_latest_anchor`.
* Offline verifiers (`acta-verify <rebuild.json> --pubkey <hex> [--rebuild-scope <scope>]`, Python `verify_and_rebuild_scope_state_offline`, and TypeScript `verifyAndRebuildScopeStateOffline`) verify every hash link, `v1`/`v2`/`v3` event preimage, host/client/witness Ed25519 signature, RFC 6962 Merkle root, and consistency proof, then deterministically reconstruct active scope state and `state_commitment` (`compute_state_commitment("acta-context-bundle/v1", tenant_id, scope, intent_root, knowledge_root, memory_root, permission_root)`) with zero server trust.
