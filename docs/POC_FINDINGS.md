# POC findings

Reference execution date: 2026-09-09. Environment identifiers and raw evidence are intentionally retained only in ignored local results.

## VERIFIED

- A dedicated F2 Fabric capacity was safely created through the stable ARM API, read successfully, and left Paused.
- Direct API lifecycle validation completed the sequence Paused -> Active -> Paused. Final states were read back, and a repeated request demonstrated idempotency.
- Azure reported the policy alias `Microsoft.Fabric/capacities/sku.name`; the implementation discovered it dynamically before deployment.
- A resource-group-scoped custom policy accepted the allowed F2 POC capacity.
- With an explicit temporary Deny configuration, creation of a separate F64 test capacity returned `RequestDisallowedByPolicy`; a follow-up GET confirmed that no test capacity existed.
- An Azure Automation account with a system-assigned managed identity and a published lifecycle runbook was deployed.
- The custom lifecycle role was created and assigned to the Automation identity at the individual capacity scope.
- The runbook was executed as an Azure Automation job and completed the transition Paused -> Active, authenticating solely with the system-assigned managed identity (`Connect-AzAccount -Identity`). Job status: Completed.
- A second Automation job completed the Active -> Paused transition, and an independent capacity read confirmed the required final Paused state.
- The lifecycle role was narrowed to only the four documented actions (`capacities/read`, `write`, `suspend/action`, `resume/action`) and the runbook was re-run successfully, showing that provider-level `locations/operationstatuses/read` and `operationresults/read` are not required at capacity scope.

## PARTIALLY VERIFIED

- RBAC scope behavior is implemented and the capacity-scoped assignment was inspected. No separate human test principal was supplied, so Reader and resource-group-scoped comparison rows were not executed.
- Daily resume/pause schedule definitions are implemented and unit tested. Live schedules were intentionally not created because `ENABLE_SCHEDULES=false` is the safe default, so no schedule was observed firing at its scheduled time.

## NOT VERIFIED

- Whether a human principal with the lifecycle role can use `capacities/write` to change SKU or administrators was intentionally not tested. The repository makes no pause/resume-only claim.
- Subscription-scope or management-group policy assignment was not tested and is outside this POC's safe deployment scope.
- Production workload behavior, Fabric job interruption semantics, holiday scheduling, and cost savings were not benchmarked.

## Validated matrix

| Control | Implemented | Actually validated in Azure |
|---|---:|---:|
| Capacity discovery/status | Yes | Yes |
| Direct pause and final Paused state | Yes | Yes |
| Direct resume and final Active state | Yes | Yes |
| Idempotent lifecycle request | Yes | Yes |
| Automation managed identity/runbook deployment | Yes | Yes |
| Automation identity executes lifecycle operation | Yes | Yes |
| Capacity-scoped custom role assignment | Yes | Yes |
| Human-principal RBAC boundary | Yes | No |
| Policy alias discovery | Yes | Yes |
| Allowed F2 behavior | Yes | Yes |
| Denied F64 creation | Yes | Yes |
| Optional schedules | Yes | No - disabled intentionally |

The ongoing policy posture after the negative test is Audit. The capacity is Paused.
