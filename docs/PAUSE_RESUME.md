# Pause and resume

## Local operation

`scripts/capacity.py` reads the current state before acting. A request for an already-achieved state returns success without another POST. Transitional states are polled rather than overwritten.

The implementation uses the stable `2023-11-01` API at the capacity resource's `/suspend` and `/resume` actions. It handles 401, 403, 404, 409, 429, retryable 5xx responses, `Retry-After`, `Azure-AsyncOperation`, `Location`, timeout, and final-state verification.

## Azure Automation

`automation/Set-FabricCapacityState.ps1` accepts:

- `SubscriptionId`
- `ResourceGroupName`
- `CapacityName`
- `DesiredState` (`Pause` or `Resume`)

The runbook authenticates with the Automation account's system-assigned identity and selects the requested subscription. The identity needs the custom lifecycle role at the capacity. No Run As account, password, certificate, or client secret is used.

Run the deployed path on demand:

```powershell
python scripts/run_runbook.py Resume
python scripts/run_runbook.py Pause
```

## Optional schedules

Schedules are disabled by default. To create them, set an Azure Automation-supported time-zone identifier and explicitly enable schedules:

```dotenv
AUTOMATION_TIME_ZONE=UTC
RESUME_TIME=07:00
PAUSE_TIME=19:00
ENABLE_SCHEDULES=true
```

Rerun `python scripts/deploy.py`. The deployer reconciles one daily resume schedule and one daily pause schedule. Verify daylight-saving behavior for the chosen zone and adjust times for weekends, holidays, or maintenance needs.

## State preservation

For an existing capacity, an authorized validation sequence restores the initial state. For a capacity created by this POC, the required final state is Paused. Always check `python scripts/capacity.py status` after an interrupted demo.
