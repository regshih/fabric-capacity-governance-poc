# Azure RBAC for Fabric capacity

## RBAC and Policy answer different questions

These get conflated constantly, and the difference matters for how you design
governance:

| | Azure RBAC | Azure Policy |
|---|---|---|
| Question | **Who** may perform an operation? | **What** configurations are allowed? |
| Evaluated on | The caller's identity | The resource's properties |
| Failure | `403 AuthorizationFailed` | `403 RequestDisallowedByPolicy` |
| Example | "Dana may pause this capacity" | "No capacity above F8 may exist here" |

Neither substitutes for the other. This POC uses both because the pause/resume
role necessarily includes an action that also permits resizing — Policy is what
closes that gap.

## A third thing that is neither: Fabric admin roles

Azure RBAC governs the **Azure resource** (`Microsoft.Fabric/capacities`) — the
control plane where a capacity is created, paused, resumed, resized, deleted.

**Fabric capacity administrators** (`properties.administration.members`) and
Fabric workspace roles govern what happens **inside** Fabric: workspaces, items,
tenant settings. That is a separate permission system with separate membership.

Holding Owner on the Azure resource does not by itself give you rights inside
the Fabric workspaces the capacity hosts, and being a Fabric capacity admin does
not let you pause the Azure resource. This POC governs only the Azure side.

## The custom role

`rbac/lifecycle-operator-role.json` defines **Fabric Capacity Lifecycle
Operator**, carrying exactly the four actions Microsoft documents as required
for pause and resume:

```
Microsoft.Fabric/capacities/read
Microsoft.Fabric/capacities/write
Microsoft.Fabric/capacities/suspend/action
Microsoft.Fabric/capacities/resume/action
```

Source: [Pause and resume your capacity](https://learn.microsoft.com/en-us/fabric/enterprise/pause-resume),
"Prerequisites". That page also notes these actions are included in the
privileged built-in roles, but recommends **against** using those because they
grant more than necessary — a custom role is the documented path.

Deliberately excluded:

| Action | Why not |
|---|---|
| `Microsoft.Fabric/capacities/delete` | Deleting a capacity is not a lifecycle operator's job. |
| `Microsoft.Authorization/roleAssignments/write` | Would let the holder grant themselves more access. |

### The `write` caveat — read this before you grant it

**This role is not "pause/resume only", and this repository does not claim it
is.**

`Microsoft.Fabric/capacities/write` is described by Microsoft as *"Creates or
updates the specified Fabric Capacity"*. That is the same action used to change
a capacity's SKU. So a role handed out to let someone pause a capacity overnight
to save money **also permits scaling that capacity up**, which increases spend.

Azure exposes no finer-grained split today. There is no
`capacities/pauseOnly/action`.

Practical mitigations:

1. **Pair the role with the SKU policy from this POC.** RBAC lets them call
   `write`; Policy constrains what `write` may set. This is the single most
   effective control.
2. **Assign at the narrowest scope** — an individual capacity, not a resource
   group or subscription.
3. **Prefer a managed identity over a human.** Give the role to the Automation
   account's identity so the schedule can act, and let people trigger the
   runbook rather than holding the capacity permission themselves.
4. **Monitor `write` on capacities** in Azure Activity Log, especially SKU
   changes.

### Long-running operation polling — tested, not needed

Pause and resume return HTTP 202 with an operation URL to poll. Those URLs live
under `Microsoft.Fabric/locations/...`, which is **outside** the capacity
resource, so provider-level read actions granted at capacity scope would not
apply to them anyway.

An earlier iteration of this role included
`Microsoft.Fabric/locations/operationstatuses/read` and
`.../operationresults/read`. They were removed and the runbook was re-run: it
still completed a full `Paused -> Active` transition. The four documented
actions are sufficient, so the narrower role is what ships. See
[POC_FINDINGS.md](POC_FINDINGS.md).

## Scope

Assign the role at the narrowest scope that does the job. Scope determines both
*which* capacities are affected and whether **new** capacities can be created.

```
User A
  |
  +-- Fabric capacity resource scope
      |
      +-- Can manage that capacity only

User B
  |
  +-- Resource group scope
      |
      +-- Can manage every capacity in the group,
          and create new ones there
```

The critical difference: `write` at a **container** scope (resource group or
subscription) permits *creating* capacities in it. `write` at an **individual
capacity** does not — there is no container to create into.

### Permission matrix — expectations

These are derived from how Azure RBAC inheritance works. They are **not** test
results; see the validated matrix below.

| Role / Scope | View capacity | Pause/Resume | Update (incl. SKU) | Create another capacity |
|---|---:|---:|---:|---:|
| Reader @ capacity | Yes | No | No | No |
| Lifecycle Operator @ capacity | Yes | Yes | Yes | No |
| Lifecycle Operator @ resource group | Yes (all in RG) | Yes (all in RG) | Yes (all in RG) | Yes (in that RG) |
| Lifecycle Operator @ subscription | Yes (all) | Yes (all) | Yes (all) | Yes (anywhere in sub) |

### Permission matrix — validated results

Only what this repository actually executed.

| Role / Scope | View | Pause/Resume | Update | Create another |
|---|---|---|---|---|
| Lifecycle Operator @ capacity (managed identity) | **VALIDATED — Yes** | **VALIDATED — Yes** | NOT VALIDATED | NOT VALIDATED |
| Lifecycle Operator @ resource group | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Lifecycle Operator @ subscription | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Reader @ capacity | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| No role assigned | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |

**Why so much is NOT VALIDATED:** properly testing a row means signing in as a
principal holding only that role at that scope and observing the result. This
POC does not create identities, and it will not weaken a control to manufacture
a green result. The capacity-scope row was validated because the Automation
account's managed identity already exists for a legitimate reason and is the
correct production pattern.

To validate more rows in your own environment, supply an existing principal:

```ini
TEST_PRINCIPAL_OBJECT_ID=<OBJECT_ID>
TEST_PRINCIPAL_TYPE=User          # or Group, or ServicePrincipal
```

`TEST_PRINCIPAL_TYPE` must match the real principal. A managed identity or app
registration is a `ServicePrincipal`, **not** a `User` — a mismatch produces an
opaque `400 UnmatchedPrincipalType`.

## Assigning the role yourself

Placeholders only — never commit real values.

```bash
# Narrowest useful scope: one capacity
az role assignment create \
  --assignee-object-id <OBJECT_ID> \
  --assignee-principal-type User \
  --role "Fabric Capacity Lifecycle Operator" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Fabric/capacities/<CAPACITY_NAME>

# Resource group scope - ALSO permits creating new capacities there
az role assignment create \
  --assignee-object-id <OBJECT_ID> \
  --assignee-principal-type User \
  --role "Fabric Capacity Lifecycle Operator" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>
```

For a managed identity, use `--assignee-principal-type ServicePrincipal`.

## Verifying an assignment

```bash
az role assignment list \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Fabric/capacities/<CAPACITY_NAME> \
  --output table
```

Or through this repository, which also checks the action list matches:

```bash
python scripts/validate.py --only rbac
```
