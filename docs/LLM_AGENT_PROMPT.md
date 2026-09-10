# Fabric Capacity Governance POC — Coding Agent Prompt

Copy the prompt below into Codex, Claude Code, GitHub Copilot, or another capable coding agent after cloning this repository.

---

You are working in the `fabric-capacity-governance-poc` repository.

First read:

* README.md
* AGENTS.md
* docs/ARCHITECTURE.md
* docs/SECURITY_PUBLIC_REPO.md
* docs/POC_FINDINGS.md

Your goal is to help me deploy and validate this Fabric Capacity Governance POC in my Azure environment.

The POC demonstrates:

1. Microsoft Fabric capacity pause/resume automation.
2. Azure RBAC controls for Fabric capacity management.
3. Azure Policy enforcement of approved Fabric F-SKUs.

Do not redesign the project unless required.

Before making changes:

1. Inspect the repository.
2. Run the existing unit tests.
3. Review the current Microsoft documentation referenced by the repository.
4. Verify that any Azure/Fabric API versions used by the implementation are still supported.
5. Verify the current Azure Policy aliases for `Microsoft.Fabric/capacities`.

Security requirements:

* Never commit credentials.
* Never commit Azure tokens.
* Never commit my tenant ID, subscription ID, object IDs, email addresses, resource group names, capacity names, or other environment-specific values.
* Store environment configuration only in ignored local configuration/environment files.
* Never print access tokens.
* Preserve all public-repository security controls.

Use my currently authenticated Azure CLI context where appropriate.

Determine whether I want to:

```text
CAPACITY_MODE=existing
```

or:

```text
CAPACITY_MODE=create
```

If I use an existing capacity:

* do not delete it
* do not resize it
* do not change administrators
* do not pause/resume it without explicit authorization
* preserve its original state

If I create a POC capacity:

* use the smallest practical SKU, normally F2
* tag it as a POC resource
* leave it paused after testing
* do not delete it without explicit authorization

For the Azure Policy POC:

* discover the current Fabric capacity SKU policy alias first
* do not assume an alias exists
* do not invent unsupported aliases
* start with Audit unless I explicitly approve Deny
* do not test Deny by resizing an existing production/customer capacity
* prefer a dedicated POC resource group

For RBAC:

* apply least privilege
* clearly distinguish Azure RBAC from Fabric Admin roles
* clearly distinguish RBAC from Azure Policy
* do not create identities unless necessary
* do not grant broad Owner/Contributor permissions when a narrower scope/role is sufficient

Proceed through:

1. preflight
2. configuration
3. deployment
4. pause/resume test
5. RBAC validation
6. policy alias discovery
7. SKU policy validation
8. result collection
9. public-repo security check

Run tests after changes.

At completion, update `docs/POC_FINDINGS.md` using only evidence actually collected.

Summarize:

* resources created/reused
* tests executed
* what passed
* what failed
* what remains unverified
* any manual actions required
* current Fabric capacity state
* whether any billable POC resources remain active

Do not claim a control works unless it was actually tested.
