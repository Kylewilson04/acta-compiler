use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::str::FromStr;

use acta_crypto::{hash_length_delimited, to_canonical_bytes};
use acta_types::{ActaError, ActaResult, CompileRequest, PolicyDecision};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, Policy, PolicyId, PolicySet, Request,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Compile,
    Ingest,
    Replay,
    Attest,
}

impl PolicyAction {
    pub fn as_cedar_id(&self) -> &'static str {
        match self {
            PolicyAction::Compile => "compile",
            PolicyAction::Ingest => "ingest",
            PolicyAction::Replay => "replay",
            PolicyAction::Attest => "attest",
        }
    }
}

/// Canonical actor record bound into `permission_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorRoleRecord {
    pub tenant_id: String,
    pub authorized: bool,
    pub roles: BTreeSet<String>,
}

/// Embedded Cedar policy engine enforcing Policy-Before-Read, Policy-Before-Write, Policy-Before-Replay,
/// and Policy-Before-Attest.
#[derive(Clone)]
pub struct PolicyGate {
    policy_set: PolicySet,
    policies_by_id: HashMap<PolicyId, Policy>,
    actor_roles: BTreeMap<String, ActorRoleRecord>,
    restricted_scope_prefixes: BTreeSet<String>,
    allow_unlisted_same_tenant_actors: bool,
    permission_root: [u8; 32],
}

impl PolicyGate {
    /// Loads a Cedar policy file from disk and computes `permission_root`.
    pub fn from_file(
        policy_path: impl AsRef<Path>,
        actor_roles: BTreeMap<String, ActorRoleRecord>,
    ) -> ActaResult<Self> {
        let raw_text = std::fs::read_to_string(policy_path.as_ref()).map_err(|e| {
            ActaError::PolicyEngine(format!(
                "failed to read policy file {}: {e}",
                policy_path.as_ref().display()
            ))
        })?;
        Self::from_policy_str(&raw_text, actor_roles)
    }

    /// Parses Cedar policy source text and computes deterministic `permission_root`.
    pub fn from_policy_str(
        policy_text: &str,
        actor_roles: BTreeMap<String, ActorRoleRecord>,
    ) -> ActaResult<Self> {
        let canonical_policy_text = normalize_policy_text(policy_text);
        let policy_set = PolicySet::from_str(&canonical_policy_text)
            .map_err(|e| ActaError::PolicyEngine(format!("Cedar policy parse error: {e}")))?;

        let mut policies_by_id = HashMap::new();
        for p in policy_set.policies() {
            policies_by_id.insert(p.id().clone(), p.clone());
        }

        let mut restricted_scope_prefixes = BTreeSet::new();
        restricted_scope_prefixes.insert("restricted".to_string());
        restricted_scope_prefixes.insert("pii".to_string());
        restricted_scope_prefixes.insert("regulated".to_string());

        let permission_root = compute_permission_root(
            &canonical_policy_text,
            &actor_roles,
            &restricted_scope_prefixes,
            true,
        )?;

        Ok(Self {
            policy_set,
            policies_by_id,
            actor_roles,
            restricted_scope_prefixes,
            allow_unlisted_same_tenant_actors: true,
            permission_root,
        })
    }

    /// Configures strict directory-only mode (unlisted actors default to `authorized = false`).
    pub fn with_strict_actor_directory(mut self, canonical_policy_text: &str) -> ActaResult<Self> {
        self.allow_unlisted_same_tenant_actors = false;
        self.permission_root = compute_permission_root(
            &normalize_policy_text(canonical_policy_text),
            &self.actor_roles,
            &self.restricted_scope_prefixes,
            self.allow_unlisted_same_tenant_actors,
        )?;
        Ok(self)
    }

    /// Returns the active 32-byte `permission_root`.
    pub fn permission_root(&self) -> [u8; 32] {
        self.permission_root
    }

    /// Evaluates a `CompileRequest` against the embedded Cedar `PolicySet`, returning
    /// `(PolicyDecision, permission_root)` before any storage read may occur.
    pub fn evaluate(&self, req: &CompileRequest) -> (PolicyDecision, [u8; 32]) {
        self.evaluate_action(
            &req.tenant_id,
            &req.actor_id,
            &req.task_id,
            &req.scope,
            PolicyAction::Compile,
        )
    }

    /// Evaluates an arbitrary action (`Compile`, `Ingest`, `Replay`, `Attest`) before touching storage.
    pub fn evaluate_action(
        &self,
        tenant_id: &str,
        actor_id: &str,
        task_id: &str,
        scope: &str,
        action: PolicyAction,
    ) -> (PolicyDecision, [u8; 32]) {
        match self.evaluate_inner(tenant_id, actor_id, task_id, scope, action) {
            Ok(decision) => (decision, self.permission_root),
            Err(err) => (
                PolicyDecision::Block {
                    reason: format!("policy evaluation error: {err}"),
                },
                self.permission_root,
            ),
        }
    }

    fn evaluate_inner(
        &self,
        tenant_id: &str,
        actor_id: &str,
        task_id: &str,
        scope: &str,
        action: PolicyAction,
    ) -> ActaResult<PolicyDecision> {
        let (actor_tenant, actor_authorized, roles_vec) =
            self.resolve_actor_attributes(tenant_id, actor_id);
        let is_restricted = self.is_restricted_scope(scope);

        let principal_entity = Entity::from_json_value(
            json!({
                "uid": { "type": "Actor", "id": actor_id },
                "attrs": {
                    "tenant_id": actor_tenant,
                    "authorized": actor_authorized,
                    "roles": roles_vec,
                },
                "parents": []
            }),
            None,
        )
        .map_err(|e| ActaError::PolicyEngine(format!("principal entity build error: {e}")))?;

        let action_entity = Entity::from_json_value(
            json!({
                "uid": { "type": "Action", "id": action.as_cedar_id() },
                "attrs": {},
                "parents": []
            }),
            None,
        )
        .map_err(|e| ActaError::PolicyEngine(format!("action entity build error: {e}")))?;

        let resource_id = format!("{tenant_id}:{scope}");
        let resource_entity = Entity::from_json_value(
            json!({
                "uid": { "type": "Scope", "id": resource_id },
                "attrs": {
                    "tenant_id": tenant_id,
                    "scope": scope,
                    "restricted": is_restricted,
                },
                "parents": []
            }),
            None,
        )
        .map_err(|e| ActaError::PolicyEngine(format!("resource entity build error: {e}")))?;

        let principal_uid = principal_entity.uid();
        let action_uid = action_entity.uid();
        let resource_uid = resource_entity.uid();

        let entities = Entities::from_entities(
            [principal_entity, action_entity, resource_entity],
            None,
        )
        .map_err(|e| ActaError::PolicyEngine(format!("entities store build error: {e}")))?;

        let context = Context::from_json_value(
            json!({
                "task_id": task_id,
                "scope": scope,
            }),
            None,
        )
        .map_err(|e| ActaError::PolicyEngine(format!("context build error: {e}")))?;

        let cedar_req = Request::new(principal_uid, action_uid, resource_uid, context, None)
            .map_err(|e| ActaError::PolicyEngine(format!("request validation error: {e}")))?;

        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&cedar_req, &self.policy_set, &entities);

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
            return Ok(PolicyDecision::Block {
                reason: format!("Cedar authorization error: {}", errors.join("; ")),
            });
        }

        let mut matching_ids: Vec<&PolicyId> = response.diagnostics().reason().collect();
        matching_ids.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

        match response.decision() {
            Decision::Allow => {
                for pid in &matching_ids {
                    if let Some(policy) = self.policies_by_id.get(pid) {
                        if let Some(esc_msg) = policy.annotation("escalate") {
                            let reason = if esc_msg.is_empty() {
                                format!("escalation required by policy {pid}")
                            } else {
                                esc_msg.to_string()
                            };
                            return Ok(PolicyDecision::Escalate { reason });
                        }
                    }
                }
                Ok(PolicyDecision::Allow)
            }
            Decision::Deny => {
                if matching_ids.is_empty() {
                    return Ok(PolicyDecision::Block {
                        reason: "implicit deny: no matching permit policy".to_string(),
                    });
                }

                let mut escalate_reasons = Vec::new();
                let mut hard_block_reasons = Vec::new();

                for pid in &matching_ids {
                    if let Some(policy) = self.policies_by_id.get(pid) {
                        if let Some(esc_msg) = policy.annotation("escalate") {
                            let reason = if esc_msg.is_empty() {
                                format!("escalation required by policy {pid}")
                            } else {
                                esc_msg.to_string()
                            };
                            escalate_reasons.push(reason);
                        } else if let Some(block_msg) = policy.annotation("reason") {
                            let reason = if block_msg.is_empty() {
                                format!("denied by policy {pid}")
                            } else {
                                block_msg.to_string()
                            };
                            hard_block_reasons.push(reason);
                        } else {
                            hard_block_reasons.push(format!("denied by policy {pid}"));
                        }
                    }
                }

                if !hard_block_reasons.is_empty() {
                    Ok(PolicyDecision::Block {
                        reason: hard_block_reasons.join("; "),
                    })
                } else {
                    Ok(PolicyDecision::Escalate {
                        reason: escalate_reasons.join("; "),
                    })
                }
            }
        }
    }

    fn resolve_actor_attributes(&self, tenant_id: &str, actor_id: &str) -> (String, bool, Vec<String>) {
        if let Some(record) = self.actor_roles.get(actor_id) {
            let roles: Vec<String> = record.roles.iter().cloned().collect();
            return (record.tenant_id.clone(), record.authorized, roles);
        }

        if let Some(rest) = actor_id.strip_prefix("unauthorized::") {
            let _ = rest;
            return (tenant_id.to_string(), false, Vec::new());
        }
        if let Some((explicit_tenant, _actor_local)) = actor_id.split_once("::") {
            return (
                explicit_tenant.to_string(),
                self.allow_unlisted_same_tenant_actors,
                vec!["reader".to_string()],
            );
        }

        if self.allow_unlisted_same_tenant_actors {
            (
                tenant_id.to_string(),
                true,
                vec!["reader".to_string()],
            )
        } else {
            (tenant_id.to_string(), false, Vec::new())
        }
    }

    /// Case-insensitive, path-segment-aware restricted scope matcher.
    pub fn is_restricted_scope(&self, scope: &str) -> bool {
        let normalized = scope.trim_matches('/').to_ascii_lowercase();
        if normalized.split('/').any(|seg| seg == "..") {
            return true;
        }
        for prefix in &self.restricted_scope_prefixes {
            if normalized == *prefix
                || normalized
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/') || rest.starts_with(':'))
            {
                return true;
            }
        }
        false
    }
}

fn normalize_policy_text(text: &str) -> String {
    text.replace("\r\n", "\n").trim().to_string()
}

fn compute_permission_root(
    canonical_policy_text: &str,
    actor_roles: &BTreeMap<String, ActorRoleRecord>,
    restricted_prefixes: &BTreeSet<String>,
    allow_unlisted: bool,
) -> ActaResult<[u8; 32]> {
    let roles_bytes = to_canonical_bytes(actor_roles)?;
    let prefixes_bytes = to_canonical_bytes(restricted_prefixes)?;
    let unlisted_flag = [u8::from(allow_unlisted)];

    Ok(hash_length_delimited(&[
        b"acta:permission_root:v1",
        canonical_policy_text.as_bytes(),
        &roles_bytes,
        &prefixes_bytes,
        &unlisted_flag,
    ]))
}
