pub mod gate;

pub use gate::{ActorRoleRecord, PolicyAction, PolicyGate};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use acta_types::{CompileRequest, ContextBudget, PolicyDecision};

    use super::*;

    const DEFAULT_CEDAR: &str = include_str!("../../../policies/default.cedar");

    #[allow(dead_code)]
    fn sample_request(tenant_id: &str, actor_id: &str, scope: &str) -> CompileRequest {
        CompileRequest {
            tenant_id: tenant_id.to_string(),
            actor_id: actor_id.to_string(),
            task_id: "task-test-1".to_string(),
            scope: scope.to_string(),
            query_text: "Summarize policy state".to_string(),
            query_embedding: None,
            budget: ContextBudget::Tokens(1024),
            evaluation_time: None,
        }
    }

    fn sample_roles() -> BTreeMap<String, ActorRoleRecord> {
        let mut map = BTreeMap::new();
        map.insert(
            "alice".to_string(),
            ActorRoleRecord {
                tenant_id: "tenant-a".to_string(),
                authorized: true,
                roles: BTreeSet::from(["reader".to_string()]),
            },
        );
        map.insert(
            "supervisor-bob".to_string(),
            ActorRoleRecord {
                tenant_id: "tenant-a".to_string(),
                authorized: true,
                roles: BTreeSet::from(["reader".to_string(), "compliance_override".to_string()]),
            },
        );
        map.insert(
            "mallory-b".to_string(),
            ActorRoleRecord {
                tenant_id: "tenant-b".to_string(),
                authorized: true,
                roles: BTreeSet::from(["reader".to_string()]),
            },
        );
        map
    }

    #[test]
    fn test_allow_block_and_escalate_decisions_across_compile_ingest_and_replay() {
        let gate = PolicyGate::from_policy_str(DEFAULT_CEDAR, sample_roles()).unwrap();

        for action in [PolicyAction::Compile, PolicyAction::Ingest, PolicyAction::Replay] {
            let (dec_allow, root_1) = gate.evaluate_action(
                "tenant-a",
                "alice",
                "task-1",
                "engineering/backend",
                action,
            );
            assert_eq!(dec_allow, PolicyDecision::Allow);
            assert_eq!(root_1, gate.permission_root());

            let (dec_block, _) = gate.evaluate_action(
                "tenant-a",
                "mallory-b",
                "task-1",
                "engineering/backend",
                action,
            );
            assert!(matches!(dec_block, PolicyDecision::Block { .. }));

            for rscope in ["restricted/payroll", "Restricted/signing-keys", "RESTRICTED"] {
                let (dec_escalate, _) =
                    gate.evaluate_action("tenant-a", "alice", "task-1", rscope, action);
                assert!(matches!(dec_escalate, PolicyDecision::Escalate { .. }));
            }

            let (dec_override, _) = gate.evaluate_action(
                "tenant-a",
                "supervisor-bob",
                "task-1",
                "restricted/payroll",
                action,
            );
            assert_eq!(dec_override, PolicyDecision::Allow);
        }
    }

    #[test]
    fn test_permission_root_changes_on_policy_or_role_change() {
        let base_roles = sample_roles();
        let gate_base = PolicyGate::from_policy_str(DEFAULT_CEDAR, base_roles.clone()).unwrap();

        let mut modified_roles = base_roles.clone();
        modified_roles
            .get_mut("alice")
            .unwrap()
            .roles
            .insert("auditor".to_string());
        let gate_role_changed = PolicyGate::from_policy_str(DEFAULT_CEDAR, modified_roles).unwrap();
        assert_ne!(gate_base.permission_root(), gate_role_changed.permission_root());

        let modified_policy = format!(
            "{DEFAULT_CEDAR}\n@id(\"forbid-archived\")\nforbid(principal, action, resource) when {{ resource.scope == \"archived\" }};"
        );
        let gate_policy_changed =
            PolicyGate::from_policy_str(&modified_policy, base_roles).unwrap();
        assert_ne!(gate_base.permission_root(), gate_policy_changed.permission_root());
    }
}
