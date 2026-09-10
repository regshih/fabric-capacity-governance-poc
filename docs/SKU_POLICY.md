# Restricting Fabric SKUs with Azure Policy

## The goal

Permit an approved set of Fabric capacity sizes and prevent everything else:

```
Allowed:   F2, F4, F8
Prevented: F16, F32, F64, F128, ...
```

The allowed list is a **parameter**, so changing it is an assignment change, not
a policy rewrite.

## Why this pairs with RBAC

The pause/resume role in this POC must include
`Microsoft.Fabric/capacities/write`, and that action also permits changing a
capacity's SKU (see [RBAC.md](RBAC.md)). RBAC alone therefore cannot stop a
lifecycle operator from selecting a larger available SKU.

Policy is what closes that gap. RBAC decides *who* may call `write`; Policy
constrains *what* `write` is allowed to set.

## Verify the alias first — this is not optional

An unverified alias can make policy deployment fail or make evaluation differ
from the operator's intent. The POC therefore refuses to generate or deploy the
policy unless the target Azure environment reports a usable SKU alias.

So the alias is discovered from the live provider and verified before any policy
is generated:

```bash
python scripts/discover_policy_aliases.py
```

Exit codes: `0` alias verified, `3` no usable SKU alias (a real finding),
`1` the discovery call itself failed.

Equivalent native commands:

```bash
az provider show --namespace Microsoft.Fabric \
  --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='capacities'].aliases[].name"
```

```powershell
Get-AzPolicyAlias -NamespaceMatch 'Microsoft.Fabric' `
                  -ResourceTypeMatch 'capacities' -ListAvailable
```

### What discovery returned

In the reference run, eight aliases exist for `Microsoft.Fabric/capacities`:

```
Microsoft.Fabric/capacities/provisioningState   -> properties.provisioningState
Microsoft.Fabric/capacities/state               -> properties.state
Microsoft.Fabric/capacities/administration      -> properties.administration
Microsoft.Fabric/capacities/administration.members
Microsoft.Fabric/capacities/administration.members[*]
Microsoft.Fabric/capacities/sku                 -> sku
Microsoft.Fabric/capacities/sku.name            -> sku.name
Microsoft.Fabric/capacities/sku.tier            -> sku.tier
```

**Verified:** `Microsoft.Fabric/capacities/sku.name`, default path `sku.name`.

Re-verify in your own subscription. Aliases are provider-published and can
change.

### If the alias is ever missing

`build_sku_policy_rule()` raises rather than emitting a policy. Do not work
around it. The correct response is to:

1. Stop the SKU-policy deployment.
2. Record the discovery output.
3. Document the limitation.
4. Mark it `NOT VERIFIED` in [POC_FINDINGS.md](POC_FINDINGS.md).
5. Consider alternatives — and be honest that they are **not** equivalent:
   - **Azure Policy on the resource group** blocking `Microsoft.Fabric/capacities`
     entirely, with capacities pre-provisioned by a controlled pipeline. Blunt,
     but real enforcement.
   - **Deployment-pipeline validation.** Only covers resources created through
     that pipeline; anyone with `write` and the portal bypasses it.
   - **Azure Monitor alerts on capacity `write`.** Detective, not preventive —
     it tells you afterwards.
   - **Budgets and cost alerts.** Detective, and lagging.

## The policy

`policy/allowed-fabric-skus.json`:

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Fabric/capacities" },
      { "not": { "field": "Microsoft.Fabric/capacities/sku.name",
                 "in": "[parameters('allowedSkus')]" } }
    ]
  },
  "then": { "effect": "[parameters('effect')]" }
}
```

Parameters:

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `allowedSkus` | Array | `["F2","F4","F8"]` | The permitted SKU names |
| `effect` | String | `Audit` | `Audit`, `Deny`, or `Disabled` |

The definition records the verified alias in
`properties.metadata.verifiedAlias`, so a reviewer can see what the policy
depends on and re-check it.

## Scope

Assigned at the **POC resource group** by default:

```
Policy assignment scope
       |
       v
POC Resource Group
```

This POC never assigns a restrictive policy at subscription or management group
scope automatically. A `Deny` at subscription scope blocks capacity creation for
everyone in it, and that is not a change any tool should make on your behalf.

To go broader, do it deliberately and stage it: assign in `Audit` first, review
compliance, then move to `Deny`.

## Audit before Deny

```
Create policy
      |
      v
Audit mode              <-- default; records non-compliance, blocks nothing
      |
      v
Review compliance       <-- find what already violates the rule
      |
      v
Explicit approval
      |
      v
Deny mode               <-- requires POLICY_EFFECT=Deny
```

`Audit` is the default and the POC will not move to `Deny` on its own. Going
straight to `Deny` in an environment you have not surveyed will block
deployments you did not know about.

```ini
POLICY_EFFECT=Deny
```

then re-run `python scripts/deploy.py`.

## Validating it

### Positive test — an allowed SKU is not blocked

The POC's own F2 capacity sits inside the assignment scope and is compliant.
Using the existing capacity avoids creating a second billable resource just to
prove a negative.

### Negative test — a disallowed SKU is refused

```bash
python scripts/validate.py --policy-negative-test
```

This **attempts to create** a new `F64` capacity inside the POC resource group
and asserts Azure refuses it.

**It never resizes an existing capacity.** Resizing to test a policy would
change a real resource and, if the policy failed to block it, start billing at
the larger SKU. An attempted create that gets denied leaves nothing behind.

Observed result:

```json
{
  "attemptedSku": "F64",
  "httpStatus": 403,
  "errorCode": "RequestDisallowedByPolicy",
  "note": "Azure Policy refused the deployment. No capacity was created."
}
```

followed by a confirmation that nothing exists at that name:

```json
{ "capacity": "<CAPACITY_NAME>", "exists": false }
```

The test only runs meaningfully when the assignment effect is `Deny`. Under
`Audit` it reports `NOT VALIDATED` with the reason — an audit assignment records
non-compliance but does not block, so a denial cannot be observed.

As a final safety net, if Azure ever *accepts* the disallowed create, the script
reports a failure and immediately deletes the capacity so it does not bill.

## Timing

Azure Policy is not instantaneous. Allow a minute or so between assignment and
expecting a `Deny` to take effect; the validation flow waits before testing.

Compliance *reporting* takes longer still — a full evaluation cycle can take up
to ~30 minutes. Trigger an on-demand scan with:

```bash
az policy state trigger-scan --resource-group <RESOURCE_GROUP>
```

## Scope of enforcement

This policy governs the **ARM control plane**: creating and updating
`Microsoft.Fabric/capacities`. It does not govern anything inside Fabric —
workspaces, items, or Fabric admin-portal settings are separate systems with
their own controls.
