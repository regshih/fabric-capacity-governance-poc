# Allowed Fabric SKU policy

The custom policy constrains `Microsoft.Fabric/capacities` by the live-discovered SKU alias. The checked-in JSON is illustrative; deployment regenerates the rule only after Azure reports `Microsoft.Fabric/capacities/sku.name` in the selected subscription.

Parameters:

- `allowedSkus`: default `F2`, `F4`, and `F8`.
- `effect`: `Audit`, `Deny`, or `Disabled`; default `Audit`.

The assignment is scoped to the dedicated POC resource group. The deployer does not assign restrictive policy at subscription or management-group scope.

## Safe validation

1. Deploy in Audit and inspect the assignment/compliance state.
2. Set `POLICY_EFFECT=Deny` only after explicit approval.
3. Use `python scripts/validate.py --only policy --policy-negative-test`.
4. The validator attempts a temporary capacity creation with a disallowed SKU; it never resizes the selected capacity.
5. A passing negative test requires Azure's `RequestDisallowedByPolicy` response and confirmation that no test resource exists.
6. Restore Audit for the ongoing POC posture if Deny is no longer desired.

If Azure does not expose the alias, deployment stops this control and records it as not verified rather than publishing a nonfunctional policy.
