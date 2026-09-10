# Azure RBAC design

Azure RBAC answers **who may perform an ARM operation**. Azure Policy separately constrains **what configuration is permitted**. Neither replaces Fabric tenant, workspace, or administrator roles.

## Lifecycle role

`lifecycle-operator-role.json` is a placeholder-safe representation of the generated custom role. Current Microsoft guidance for pause/resume includes `read`, `write`, `suspend/action`, and `resume/action` on `Microsoft.Fabric/capacities`.

Because `capacities/write` can permit update operations such as SKU or administrator changes, the role is not strictly pause/resume-only. Resource scope is therefore important.

## Scope behavior

| Assignment | Effective reach |
|---|---|
| Individual capacity | Listed actions apply to that capacity only |
| Resource group | Listed actions apply to Fabric capacities in that group; creation also depends on ARM/RBAC semantics and any policy |
| Subscription | Listed actions apply across the subscription |

The deployer assigns the Automation managed identity at the individual capacity. It does not create test users or service principals. If `TEST_PRINCIPAL_OBJECT_ID` is blank, human-principal validation remains `NOT VALIDATED` and the CLI emits placeholder-safe guidance.

## Validated results

| Role / scope | View | Pause/resume | Update capacity | Create another capacity |
|---|---:|---:|---:|---:|
| Reader | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Lifecycle Operator @ capacity | VERIFIED for Automation identity | VERIFIED for Automation identity | NOT VALIDATED | No outside assigned resource by scope; creation NOT VALIDATED |
| Capacity manager @ resource group | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |

These entries describe only the reference deployment's executed tests. They are not claims about every environment.

## Example assignment

```powershell
az role assignment create `
  --assignee-object-id <OBJECT_ID> `
  --assignee-principal-type ServicePrincipal `
  --role "Fabric Capacity Lifecycle Operator" `
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Fabric/capacities/<CAPACITY_NAME>
```
