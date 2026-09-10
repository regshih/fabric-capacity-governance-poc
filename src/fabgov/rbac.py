"""Azure RBAC custom role definition for Fabric capacity lifecycle management.

The action list here is taken from Microsoft's documented prerequisites for
pausing and resuming a Fabric capacity:
https://learn.microsoft.com/en-us/fabric/enterprise/pause-resume

An honest caveat that this POC surfaces rather than hides: the documented set
includes ``Microsoft.Fabric/capacities/write``, whose description is "Creates or
updates the specified Fabric Capacity". That is the *same* action used to change
a capacity's SKU. A role built to let an operator pause a capacity overnight to
save money therefore also lets that operator scale the capacity up. Azure
exposes no finer-grained split today, so this role should not be described as
"pause/resume only". See docs/RBAC.md.
"""

from __future__ import annotations

# The four actions Microsoft documents as required for pause/resume.
PAUSE_RESUME_ACTIONS = (
    "Microsoft.Fabric/capacities/read",
    "Microsoft.Fabric/capacities/write",
    "Microsoft.Fabric/capacities/suspend/action",
    "Microsoft.Fabric/capacities/resume/action",
)

# Provider-level actions that can read Fabric long-running-operation URLs.
# They do not become effective when this role is assigned at an individual
# capacity because those operation URLs sit outside the capacity resource
# scope. The default role deliberately excludes them and the runbook falls
# back to polling the capacity state with capacities/read.
LRO_POLLING_ACTIONS = (
    "Microsoft.Fabric/locations/operationstatuses/read",
    "Microsoft.Fabric/locations/operationresults/read",
)

# Actions deliberately excluded, with the reason, so reviewers can see that
# the omissions are choices rather than oversights.
EXCLUDED_ACTIONS = {
    "Microsoft.Fabric/capacities/delete": "Deleting a capacity is never part of a lifecycle operator's job.",
    "Microsoft.Authorization/roleAssignments/write": "Would let the holder grant themselves more access.",
}

ROLE_NAME = "Fabric Capacity Lifecycle Operator"
ROLE_DESCRIPTION = (
    "Read, pause, and resume Microsoft Fabric capacities. Note: the documented "
    "permission set includes Microsoft.Fabric/capacities/write, which also permits "
    "changing a capacity's SKU. This role is not restricted to pause/resume alone."
)


def role_actions(include_lro_polling: bool = False) -> list:
    """The full action list for the custom role."""
    actions = list(PAUSE_RESUME_ACTIONS)
    if include_lro_polling:
        actions.extend(LRO_POLLING_ACTIONS)
    return actions


def build_role_definition(
    *,
    subscription_id: str,
    role_name: str = ROLE_NAME,
    description: str = ROLE_DESCRIPTION,
    assignable_scopes=None,
    include_lro_polling: bool = False,
) -> dict:
    """Build a custom role definition body for ARM.

    ``assignableScopes`` defaults to the subscription, which is the narrowest
    scope that still allows the role to be assigned at either the resource
    group or an individual capacity beneath it.
    """
    if not subscription_id:
        raise ValueError("subscription_id is required to build a role definition.")
    scopes = list(assignable_scopes or ["/subscriptions/{0}".format(subscription_id)])
    return {
        "properties": {
            "roleName": role_name,
            "description": description,
            "type": "CustomRole",
            "permissions": [
                {
                    "actions": role_actions(include_lro_polling),
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                }
            ],
            "assignableScopes": scopes,
        }
    }


def role_definition_id(subscription_id: str, role_definition_guid: str) -> str:
    """ARM id of a custom role definition."""
    return "/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}".format(
        subscription_id, role_definition_guid
    )


def build_role_assignment(
    *, role_definition_id_value: str, principal_object_id: str, principal_type: str = "User"
) -> dict:
    """Build a role assignment body.

    ``principalType`` matters: omitting it on a freshly created service
    principal causes a replication-lag failure that reads as a permissions
    error.
    """
    if not role_definition_id_value:
        raise ValueError("role_definition_id_value is required.")
    if not principal_object_id:
        raise ValueError("principal_object_id is required.")
    return {
        "properties": {
            "roleDefinitionId": role_definition_id_value,
            "principalId": principal_object_id,
            "principalType": principal_type,
        }
    }


def assignment_commands(
    *,
    role_name: str = ROLE_NAME,
    scope_placeholder: str = "<SCOPE>",
    principal_placeholder: str = "<OBJECT_ID>",
) -> list:
    """Azure CLI commands a customer can run to assign the role themselves.

    Returned with placeholders so they can be printed to a terminal, pasted
    into documentation, or committed - none of them carry real identifiers.
    """
    return [
        "# Assign at an individual Fabric capacity (narrowest useful scope)",
        "az role assignment create \\",
        "  --assignee-object-id {0} \\".format(principal_placeholder),
        "  --assignee-principal-type User \\",
        '  --role "{0}" \\'.format(role_name),
        "  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"
        "/providers/Microsoft.Fabric/capacities/<CAPACITY_NAME>",
        "",
        "# Assign at the resource group (also permits creating NEW capacities there)",
        "az role assignment create \\",
        "  --assignee-object-id {0} \\".format(principal_placeholder),
        "  --assignee-principal-type User \\",
        '  --role "{0}" \\'.format(role_name),
        "  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>",
    ]


def scope_behavior_matrix() -> list:
    """The expected effect of assigning this role at each scope.

    These are *expectations* derived from how Azure RBAC inheritance works, not
    test results. scripts/validate.py records what was actually observed;
    docs/RBAC.md keeps the two clearly separated.
    """
    return [
        {
            "scope": "Individual Fabric capacity",
            "canReadThatCapacity": "Yes",
            "canPauseResumeThatCapacity": "Yes",
            "canUpdateThatCapacity": "Yes (write action permits SKU change)",
            "canCreateNewCapacity": "No - create requires write at a container scope",
            "notes": "Narrowest scope. Grants nothing over any other capacity.",
        },
        {
            "scope": "Resource group",
            "canReadThatCapacity": "Yes, for every capacity in the group",
            "canPauseResumeThatCapacity": "Yes, for every capacity in the group",
            "canUpdateThatCapacity": "Yes, for every capacity in the group",
            "canCreateNewCapacity": "Yes - write at a resource group permits creating capacities in it",
            "notes": "Inherited by all current and future capacities in the group.",
        },
        {
            "scope": "Subscription",
            "canReadThatCapacity": "Yes, subscription-wide",
            "canPauseResumeThatCapacity": "Yes, subscription-wide",
            "canUpdateThatCapacity": "Yes, subscription-wide",
            "canCreateNewCapacity": "Yes, in any resource group in the subscription",
            "notes": "Broadest scope. Rarely appropriate for a lifecycle operator.",
        },
    ]
