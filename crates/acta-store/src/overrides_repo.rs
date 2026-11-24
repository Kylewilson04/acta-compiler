use std::collections::{HashMap, HashSet};

use acta_crypto::{
    compute_evidence_event_hash_with_meta, compute_override_attestation_hash,
    compute_override_client_intent_hash, sign_evidence_entry, sign_override_attestation,
    verify_client_content_signature, OverrideHashInput,
};
use acta_types::{
    infer_override_auth_kind, ActaError, ActaResult, EvidenceEntry, OverriddenClaimRef,
    OverrideAttestation, OverrideLedgerSummary, PolicyResultTag, OVERRIDE_DOMAIN_V2,
};
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::evidence_repo::fetch_evidence_by_seq;

pub struct NewOverrideInput {
    pub id: Uuid,
    pub tenant_id: String,
    pub scope: String,
    pub claim_group_key: [u8; 32],
    pub subject: String,
    pub predicate: String,
    pub source_bundle_hash: Option<[u8; 32]>,
    pub winning_claim_id: Uuid,
    pub winning_claim_content_hash: [u8; 32],
    pub overridden_claims: Vec<OverriddenClaimRef>,
    pub adjudicator_id: String,
    pub adjudicator_auth_kind: String,
    pub justification: String,
    pub client_signature: Option<Vec<u8>>,
    pub client_public_key: Option<[u8; 32]>,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct OverrideRow {
    id: Uuid,
    tenant_id: String,
    scope: String,
    claim_group_key: Vec<u8>,
    subject: String,
    predicate: String,
    source_bundle_hash: Option<Vec<u8>>,
    winning_claim_id: Uuid,
    winning_claim_content_hash: Vec<u8>,
    overridden_claims: Value,
    adjudicator_id: String,
    adjudicator_auth_kind: Option<String>,
    justification: String,
    version: i32,
    predecessor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    att_domain: String,
    attestation_hash: Vec<u8>,
    evidence_seq_num: i64,
    host_signature: Vec<u8>,
    client_signature: Option<Vec<u8>>,
    client_public_key: Option<Vec<u8>>,
    is_superseded: bool,
}

impl OverrideRow {
    fn into_domain(self) -> ActaResult<(OverrideAttestation, bool)> {
        let claim_group_key: [u8; 32] = self
            .claim_group_key
            .try_into()
            .map_err(|_| ActaError::Storage("override claim_group_key is not 32 bytes".to_string()))?;
        let source_bundle_hash: Option<[u8; 32]> = self
            .source_bundle_hash
            .map(|v| {
                v.try_into().map_err(|_| {
                    ActaError::Storage("override source_bundle_hash is not 32 bytes".to_string())
                })
            })
            .transpose()?;
        let winning_claim_content_hash: [u8; 32] = self
            .winning_claim_content_hash
            .try_into()
            .map_err(|_| {
                ActaError::Storage(
                    "override winning_claim_content_hash is not 32 bytes".to_string(),
                )
            })?;
        let mut overridden_claims: Vec<OverriddenClaimRef> =
            serde_json::from_value(self.overridden_claims).map_err(|e| {
                ActaError::Storage(format!("overridden_claims deserialization failed: {e}"))
            })?;
        overridden_claims.sort_unstable();
        let attestation_hash: [u8; 32] = self
            .attestation_hash
            .try_into()
            .map_err(|_| ActaError::Storage("attestation_hash is not 32 bytes".to_string()))?;
        let host_signature: [u8; 64] = self
            .host_signature
            .try_into()
            .map_err(|_| ActaError::Storage("override host_signature is not 64 bytes".to_string()))?;
        let client_public_key: Option<[u8; 32]> = self
            .client_public_key
            .map(|v| {
                v.try_into().map_err(|_| {
                    ActaError::Storage("override client_public_key is not 32 bytes".to_string())
                })
            })
            .transpose()?;

        let adjudicator_auth_kind = self.adjudicator_auth_kind.unwrap_or_else(|| {
            infer_override_auth_kind(&self.adjudicator_id, self.client_signature.is_some())
                .to_string()
        });

        Ok((
            OverrideAttestation {
                id: self.id,
                tenant_id: self.tenant_id,
                scope: self.scope,
                claim_group_key,
                subject: self.subject,
                predicate: self.predicate,
                source_bundle_hash,
                winning_claim_id: self.winning_claim_id,
                winning_claim_content_hash,
                overridden_claims,
                adjudicator_id: self.adjudicator_id,
                adjudicator_auth_kind,
                justification: self.justification,
                version: self.version,
                predecessor_id: self.predecessor_id,
                created_at: self.created_at,
                attestation_domain: self.att_domain,
                attestation_hash,
                evidence_seq_num: self.evidence_seq_num,
                host_signature,
                client_signature: self.client_signature,
                client_public_key,
            },
            self.is_superseded,
        ))
    }
}

pub async fn attest_override_tx(
    pool: &PgPool,
    host_key: &SigningKey,
    mut input: NewOverrideInput,
) -> ActaResult<(OverrideAttestation, EvidenceEntry, bool)> {
    input.created_at = input.created_at.trunc_subsecs(6);
    input.overridden_claims.sort_unstable();
    input.overridden_claims.dedup();

    if input.adjudicator_auth_kind.trim().is_empty() {
        input.adjudicator_auth_kind =
            infer_override_auth_kind(&input.adjudicator_id, input.client_signature.is_some())
                .to_string();
    }

    if let Some(ref csig) = input.client_signature {
        let sig_arr: [u8; 64] = csig
            .as_slice()
            .try_into()
            .map_err(|_| ActaError::Validation("client_signature must be 64 bytes".to_string()))?;
        let Some(ref cpk) = input.client_public_key else {
            return Err(ActaError::Validation(
                "client_public_key_hex is required when client_signature_hex is supplied"
                    .to_string(),
            ));
        };
        let intent_digest = compute_override_client_intent_hash(
            &input.tenant_id,
            &input.scope,
            input.winning_claim_id,
            &input.adjudicator_id,
            &input.justification,
        );
        if !verify_client_content_signature(cpk, &intent_digest, &sig_arr) {
            return Err(ActaError::Validation(
                "client Ed25519 signature verification failed over override intent digest"
                    .to_string(),
            ));
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ActaError::Storage(format!("begin override transaction failed: {e}")))?;

    let (prev_seq, prev_hash) =
        crate::evidence_repo::lock_and_read_latest_evidence_tx(&mut tx, &input.tenant_id).await?;

    let existing_head_row = sqlx::query_as::<_, OverrideRow>(
        r#"
        SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
               o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
               o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
               o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
               o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
               FALSE AS is_superseded
        FROM override_attestations o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND o.claim_group_key = $3
          AND NOT EXISTS (
              SELECT 1 FROM override_attestations succ
              WHERE succ.tenant_id = o.tenant_id
                AND succ.predecessor_id = o.id
          )
        ORDER BY o.version DESC, o.created_at DESC, o.id DESC
        LIMIT 1
        "#,
    )
    .bind(&input.tenant_id)
    .bind(&input.scope)
    .bind(input.claim_group_key.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("query active override head failed: {e}")))?;

    let (version, predecessor_id) = if let Some(prev_row) = existing_head_row {
        let (prev_att, _) = prev_row.into_domain()?;
        if prev_att.winning_claim_id == input.winning_claim_id
            && prev_att.winning_claim_content_hash == input.winning_claim_content_hash
            && prev_att.overridden_claims == input.overridden_claims
            && prev_att.adjudicator_id == input.adjudicator_id
            && prev_att.effective_auth_kind() == input.adjudicator_auth_kind
            && prev_att.justification == input.justification
            && prev_att.client_public_key == input.client_public_key
        {
            tx.rollback().await.ok();
            let existing_ev =
                fetch_evidence_by_seq(pool, &prev_att.tenant_id, prev_att.evidence_seq_num)
                    .await?
                    .ok_or_else(|| {
                        ActaError::Storage(format!(
                            "missing notarizing evidence entry seq_num={} for override {}",
                            prev_att.evidence_seq_num, prev_att.id
                        ))
                    })?;
            return Ok((prev_att, existing_ev, true));
        }
        (prev_att.version + 1, Some(prev_att.id))
    } else {
        (1, None)
    };


    let seq_num = prev_seq + 1;

    let attestation_hash = compute_override_attestation_hash(&OverrideHashInput {
        attestation_domain: OVERRIDE_DOMAIN_V2,
        id: input.id,
        tenant_id: &input.tenant_id,
        scope: &input.scope,
        claim_group_key: &input.claim_group_key,
        subject: &input.subject,
        predicate: &input.predicate,
        source_bundle_hash: input.source_bundle_hash.as_ref(),
        winning_claim_id: input.winning_claim_id,
        winning_claim_content_hash: &input.winning_claim_content_hash,
        overridden_claims: &input.overridden_claims,
        adjudicator_id: &input.adjudicator_id,
        adjudicator_auth_kind: &input.adjudicator_auth_kind,
        justification: &input.justification,
        version,
        predecessor_id,
        created_at: input.created_at,
        client_public_key: input.client_public_key.as_ref(),
        client_signature: input.client_signature.as_deref(),
    })?;

    let att_host_sig =
        sign_override_attestation(host_key, &input.tenant_id, seq_num, &attestation_hash);

    let override_summary = OverrideLedgerSummary {
        attestation_id: input.id,
        scope: input.scope.clone(),
        subject: input.subject.clone(),
        predicate: input.predicate.clone(),
        winning_claim_id: input.winning_claim_id,
        overridden_count: input.overridden_claims.len(),
        adjudicator_id: input.adjudicator_id.clone(),
        version,
    };

    let ev_hash = compute_evidence_event_hash_with_meta(
        &input.tenant_id,
        seq_num,
        &prev_hash,
        None,
        Some(&attestation_hash),
        PolicyResultTag::Allow,
        input.created_at.timestamp_micros(),
        None,
        Some(&override_summary),
    )?;
    let ev_host_sig =
        sign_evidence_entry(host_key, &input.tenant_id, seq_num, &prev_hash, &ev_hash);

    let override_meta_json = serde_json::to_value(&override_summary)
        .map_err(|e| ActaError::Storage(format!("serialize override_meta failed: {e}")))?;
    let overridden_json = serde_json::to_value(&input.overridden_claims)
        .map_err(|e| ActaError::Storage(format!("serialize overridden_claims failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO evidence_history (
            tenant_id, seq_num, prev_hash, event_hash,
            bundle_hash, state_commitment, policy_result,
            refusal_meta, override_meta, host_signature, created_at
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'allow', NULL, $6, $7, $8)
        "#,
    )
    .bind(&input.tenant_id)
    .bind(seq_num)
    .bind(prev_hash.as_slice())
    .bind(ev_hash.as_slice())
    .bind(attestation_hash.as_slice())
    .bind(override_meta_json)
    .bind(ev_host_sig.as_slice())
    .bind(input.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert override evidence_history failed: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO override_attestations (
            id, tenant_id, scope, claim_group_key, subject, predicate,
            source_bundle_hash, winning_claim_id, winning_claim_content_hash,
            overridden_claims, adjudicator_id, adjudicator_auth_kind, justification,
            version, predecessor_id, created_at,
            att_domain, attestation_hash, evidence_seq_num, host_signature,
            client_signature, client_public_key
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9,
            $10, $11, $12, $13,
            $14, $15, $16,
            $17, $18, $19, $20,
            $21, $22
        )
        "#,
    )
    .bind(input.id)
    .bind(&input.tenant_id)
    .bind(&input.scope)
    .bind(input.claim_group_key.as_slice())
    .bind(&input.subject)
    .bind(&input.predicate)
    .bind(input.source_bundle_hash.as_ref().map(|h| h.as_slice()))
    .bind(input.winning_claim_id)
    .bind(input.winning_claim_content_hash.as_slice())
    .bind(overridden_json)
    .bind(&input.adjudicator_id)
    .bind(&input.adjudicator_auth_kind)
    .bind(&input.justification)
    .bind(version)
    .bind(predecessor_id)
    .bind(input.created_at)
    .bind(OVERRIDE_DOMAIN_V2)
    .bind(attestation_hash.as_slice())
    .bind(seq_num)
    .bind(att_host_sig.as_slice())
    .bind(input.client_signature.as_deref())
    .bind(input.client_public_key.as_ref().map(|pk| pk.as_slice()))
    .execute(&mut *tx)
    .await
    .map_err(|e| ActaError::Storage(format!("insert override_attestations failed: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| ActaError::Storage(format!("commit override transaction failed: {e}")))?;

    let att = OverrideAttestation {
        id: input.id,
        tenant_id: input.tenant_id.clone(),
        scope: input.scope,
        claim_group_key: input.claim_group_key,
        subject: input.subject,
        predicate: input.predicate,
        source_bundle_hash: input.source_bundle_hash,
        winning_claim_id: input.winning_claim_id,
        winning_claim_content_hash: input.winning_claim_content_hash,
        overridden_claims: input.overridden_claims,
        adjudicator_id: input.adjudicator_id,
        adjudicator_auth_kind: input.adjudicator_auth_kind,
        justification: input.justification,
        version,
        predecessor_id,
        created_at: input.created_at,
        attestation_domain: OVERRIDE_DOMAIN_V2.to_string(),
        attestation_hash,
        evidence_seq_num: seq_num,
        host_signature: att_host_sig,
        client_signature: input.client_signature,
        client_public_key: input.client_public_key,
    };

    let ev = EvidenceEntry {
        tenant_id: input.tenant_id,
        seq_num,
        event_domain: Some("acta:evidence_event:v2".to_string()),
        prev_hash,
        event_hash: ev_hash,
        bundle_hash: None,
        state_commitment: Some(attestation_hash),
        policy_result: PolicyResultTag::Allow,
        refusal_metadata: None,
        override_summary: Some(override_summary),
        write_summary: None,
        answer_cache_summary: None,
        witness_reg_summary: None,
        witness_revoke_summary: None,
        host_signature: ev_host_sig,
        created_at: input.created_at,
    };

    Ok((att, ev, false))
}

pub async fn fetch_active_scoped_overrides(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
) -> ActaResult<Vec<OverrideAttestation>> {
    let rows = sqlx::query_as::<_, OverrideRow>(
        r#"
        SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
               o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
               o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
               o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
               o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
               FALSE AS is_superseded
        FROM override_attestations o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND NOT EXISTS (
              SELECT 1 FROM override_attestations succ
              WHERE succ.tenant_id = o.tenant_id
                AND succ.predecessor_id = o.id
          )
        ORDER BY o.claim_group_key ASC, o.version DESC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_active_scoped_overrides failed: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (att, _) = row.into_domain()?;
        out.push(att);
    }
    Ok(out)
}

/// Time-pinned variant of `fetch_active_scoped_overrides` (`created_at <= cutoff` + supersession cutoff).
pub async fn fetch_active_scoped_overrides_as_of(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    as_of: Option<DateTime<Utc>>,
) -> ActaResult<Vec<OverrideAttestation>> {
    let rows = sqlx::query_as::<_, OverrideRow>(
        r#"
        SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
               o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
               o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
               o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
               o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
               FALSE AS is_superseded
        FROM override_attestations o
        WHERE o.tenant_id = $1
          AND o.scope = $2
          AND ($3::timestamptz IS NULL OR o.created_at <= $3)
          AND NOT EXISTS (
              SELECT 1 FROM override_attestations succ
              WHERE succ.tenant_id = o.tenant_id
                AND succ.predecessor_id = o.id
                AND ($3::timestamptz IS NULL OR succ.created_at <= $3)
          )
        ORDER BY o.claim_group_key ASC, o.version DESC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scope)
    .bind(as_of)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_active_scoped_overrides_as_of failed: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (att, _) = row.into_domain()?;
        out.push(att);
    }
    Ok(out)
}

pub async fn fetch_overrides_by_ids(
    pool: &PgPool,
    tenant_id: &str,
    ids: &[Uuid],
) -> ActaResult<Vec<OverrideAttestation>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, OverrideRow>(
        r#"
        SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
               o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
               o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
               o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
               o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
               EXISTS (
                   SELECT 1 FROM override_attestations succ
                   WHERE succ.tenant_id = o.tenant_id
                     AND succ.predecessor_id = o.id
               ) AS is_superseded
        FROM override_attestations o
        WHERE o.tenant_id = $1
          AND o.id = ANY($2)
        ORDER BY o.evidence_seq_num ASC, o.id ASC
        "#,
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch_overrides_by_ids failed: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (att, _) = row.into_domain()?;
        out.push(att);
    }
    Ok(out)
}

pub async fn fetch_tenant_overrides(
    pool: &PgPool,
    tenant_id: &str,
    scope_filter: Option<&str>,
) -> ActaResult<Vec<(OverrideAttestation, bool)>> {
    let rows = match scope_filter {
        Some(sc) => {
            sqlx::query_as::<_, OverrideRow>(
                r#"
                SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
                       o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
                       o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
                       o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
                       o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
                       EXISTS (
                           SELECT 1 FROM override_attestations succ
                           WHERE succ.tenant_id = o.tenant_id
                             AND succ.predecessor_id = o.id
                       ) AS is_superseded
                FROM override_attestations o
                WHERE o.tenant_id = $1 AND o.scope = $2
                ORDER BY o.created_at DESC, o.version DESC
                LIMIT 200
                "#,
            )
            .bind(tenant_id)
            .bind(sc)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, OverrideRow>(
                r#"
                SELECT o.id, o.tenant_id, o.scope, o.claim_group_key, o.subject, o.predicate,
                       o.source_bundle_hash, o.winning_claim_id, o.winning_claim_content_hash,
                       o.overridden_claims, o.adjudicator_id, o.adjudicator_auth_kind, o.justification,
                       o.version, o.predecessor_id, o.created_at, o.att_domain, o.attestation_hash,
                       o.evidence_seq_num, o.host_signature, o.client_signature, o.client_public_key,
                       EXISTS (
                           SELECT 1 FROM override_attestations succ
                           WHERE succ.tenant_id = o.tenant_id
                             AND succ.predecessor_id = o.id
                       ) AS is_superseded
                FROM override_attestations o
                WHERE o.tenant_id = $1
                ORDER BY o.created_at DESC, o.version DESC
                LIMIT 200
                "#,
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(|e| ActaError::Storage(format!("fetch_tenant_overrides failed: {e}")))?;

    rows.into_iter().map(OverrideRow::into_domain).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideStateKind {
    Active,
    Lapsed,
    Superseded,
}

#[derive(sqlx::FromRow)]
struct ActiveHeadClaimRow {
    id: Uuid,
    scope: String,
    subject: String,
    predicate: String,
    source_descriptor: String,
    object_val: Value,
    content_hash: Vec<u8>,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
}

fn canonical_val_sig(v: &Value) -> (u8, Vec<u8>) {
    let tag = match v {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Object(_) => 5,
    };
    (tag, acta_crypto::to_canonical_bytes(v).unwrap_or_default())
}

/// Classifies all stored overrides for `tenant_id` (optionally filtered by `scope_filter`) into
/// `Active`, `Lapsed`, or `Superseded`.
pub async fn fetch_tenant_overrides_classified(
    pool: &PgPool,
    tenant_id: &str,
    scope_filter: Option<&str>,
) -> ActaResult<Vec<(OverrideAttestation, OverrideStateKind)>> {
    let pairs = fetch_tenant_overrides(pool, tenant_id, scope_filter).await?;
    if pairs.is_empty() {
        return Ok(Vec::new());
    }

    let now = Utc::now();
    let head_claims = sqlx::query_as::<_, ActiveHeadClaimRow>(
        r#"
        SELECT c.id, c.scope, c.subject, c.predicate, c.source_descriptor,
               c.object_val, c.content_hash, c.valid_from, c.valid_to
        FROM knowledge_claims c
        WHERE c.tenant_id = $1
          AND c.status = 'active'
          AND ($2::text IS NULL OR c.scope = $2)
          AND NOT EXISTS (
              SELECT 1 FROM knowledge_claims succ
              WHERE succ.tenant_id = c.tenant_id
                AND succ.predecessor_id = c.id
          )
        ORDER BY c.version DESC, c.created_at DESC, c.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(scope_filter)
    .fetch_all(pool)
    .await
    .map_err(|e| ActaError::Storage(format!("fetch active head claims for overrides failed: {e}")))?;

    let mut seen_source_head: HashSet<(String, String, String, String)> = HashSet::new();
    let mut claims_by_slot: HashMap<(String, String, String), Vec<&ActiveHeadClaimRow>> =
        HashMap::new();

    for c in &head_claims {
        if c.valid_from.is_some_and(|vf| now < vf) || c.valid_to.is_some_and(|vt| now > vt) {
            continue;
        }
        let src_key = (
            c.scope.clone(),
            c.subject.clone(),
            c.predicate.clone(),
            c.source_descriptor.clone(),
        );
        if !seen_source_head.insert(src_key) {
            continue;
        }
        claims_by_slot
            .entry((c.scope.clone(), c.subject.clone(), c.predicate.clone()))
            .or_default()
            .push(c);
    }

    let mut out = Vec::with_capacity(pairs.len());
    for (att, is_superseded) in pairs {
        if is_superseded {
            out.push((att, OverrideStateKind::Superseded));
            continue;
        }
        let slot_key = (
            att.scope.clone(),
            att.subject.clone(),
            att.predicate.clone(),
        );
        let group = claims_by_slot.get(&slot_key).map(Vec::as_slice).unwrap_or(&[]);
        let winner_opt = group.iter().copied().find(|c| {
            c.id == att.winning_claim_id
                && c.content_hash.as_slice() == att.winning_claim_content_hash.as_slice()
        });
        let Some(winner) = winner_opt else {
            out.push((att, OverrideStateKind::Lapsed));
            continue;
        };
        let win_sig = canonical_val_sig(&winner.object_val);
        let has_unseen_conflict = group.iter().any(|c| {
            if c.id == winner.id || canonical_val_sig(&c.object_val) == win_sig {
                return false;
            }
            !att.overridden_claims
                .iter()
                .any(|oc| oc.id == c.id && oc.content_hash.as_slice() == c.content_hash.as_slice())
        });
        let state = if has_unseen_conflict {
            OverrideStateKind::Lapsed
        } else {
            OverrideStateKind::Active
        };
        out.push((att, state));
    }
    Ok(out)
}

/// Fetches all `OverrideAttestation`s (both active and superseded) in `(tenant_id, scope)`
/// up to `up_to_seq` so `StateRebuildArchive` carries every override notarized in `evidence_chain`.
pub async fn fetch_all_scoped_overrides_up_to_seq(
    pool: &PgPool,
    tenant_id: &str,
    scope: &str,
    up_to_seq: Option<i64>,
) -> ActaResult<Vec<OverrideAttestation>> {
    let all = fetch_tenant_overrides_classified(pool, tenant_id, Some(scope)).await?;
    let mut out: Vec<OverrideAttestation> = all
        .into_iter()
        .map(|(att, _)| att)
        .filter(|att| up_to_seq.map_or(true, |lim| att.evidence_seq_num <= lim))
        .collect();
    out.sort_by_key(|a| a.evidence_seq_num);
    Ok(out)
}
