// Baseline Cedar Authorization Policy for Acta Compiler
// Enforces same-tenant authorization, forbids cross-tenant access, and triggers
// human/supervisor escalation on restricted scopes across compile, ingest, replay, and attest.

// 1. Permit same-tenant authorized actors on standard (non-restricted) scopes.
@id("permit-same-tenant-standard")
permit(
    principal,
    action in [Action::"compile", Action::"ingest", Action::"replay", Action::"attest"],
    resource
) when {
    principal has tenant_id &&
    resource has tenant_id &&
    principal.tenant_id == resource.tenant_id &&
    principal has authorized &&
    principal.authorized == true &&
    resource has restricted &&
    resource.restricted == false
};

// 2. Permit same-tenant authorized actors on restricted scopes ONLY when they hold
//    the "compliance_override" role.
@id("permit-same-tenant-restricted-override")
permit(
    principal,
    action in [Action::"compile", Action::"ingest", Action::"replay", Action::"attest"],
    resource
) when {
    principal has tenant_id &&
    resource has tenant_id &&
    principal.tenant_id == resource.tenant_id &&
    principal has authorized &&
    principal.authorized == true &&
    resource has restricted &&
    resource.restricted == true &&
    principal has roles &&
    principal.roles.contains("compliance_override")
};

// 3. Escalate same-tenant authorized actors accessing restricted scopes without override.
@id("escalate-restricted-scope")
@escalate("Restricted scope requires supervisor escalation approval")
forbid(
    principal,
    action in [Action::"compile", Action::"ingest", Action::"replay", Action::"attest"],
    resource
) when {
    principal has tenant_id &&
    resource has tenant_id &&
    principal.tenant_id == resource.tenant_id &&
    principal has authorized &&
    principal.authorized == true &&
    resource has restricted &&
    resource.restricted == true &&
    (!(principal has roles) || !(principal.roles.contains("compliance_override")))
};

// 4. Hard-forbid cross-tenant access under all circumstances.
@id("forbid-cross-tenant")
@reason("Cross-tenant context access is strictly forbidden")
forbid(
    principal,
    action,
    resource
) when {
    !(principal has tenant_id) ||
    !(resource has tenant_id) ||
    principal.tenant_id != resource.tenant_id
};

// 5. Hard-forbid suspended or explicitly unauthorized actors.
@id("forbid-unauthorized-actor")
@reason("Actor is not authorized for tenant compilation")
forbid(
    principal,
    action,
    resource
) when {
    !(principal has authorized) ||
    principal.authorized == false
};
