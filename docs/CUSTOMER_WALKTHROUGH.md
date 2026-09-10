# Customer walkthrough

This is a 10–15 minute demonstration. Use only a dedicated POC scope and confirm the selected capacity is safe to operate.

## Before the session

1. Run `python scripts/preflight.py` and `python -m pytest tests/unit -q`.
2. Confirm policy is Audit unless the session includes an explicitly approved Deny test.
3. Confirm the selected capacity is POC-created or that existing-capacity state change is authorized.
4. Record the initial state and confirm no schedule will fire during the demo.

## Demo

1. Show the Fabric capacity in Azure and explain that it is an ARM resource.
2. Run `python scripts/capacity.py status`.
3. Run `python scripts/capacity.py pause`; show the verified Paused state.
4. Run `python scripts/capacity.py resume`; show the verified Active state.
5. Show the Automation account, system-assigned identity, published runbook, and disabled-by-default schedule configuration.
6. Run `python scripts/run_runbook.py Pause` to exercise the cloud path.
7. Show the capacity-scoped custom role. Call out that the required `write` action is broader than a strict pause/resume permission.
8. Show live policy-alias discovery and the allowed list `F2,F4,F8`.
9. If Deny was explicitly approved, run the validator's disallowed-SKU creation test. Show `RequestDisallowedByPolicy` and confirm no temporary capacity exists.
10. Summarize: RBAC controls **who** can act; Policy controls **what configuration** is accepted.

## Close safely

1. For a POC-created capacity, run `python scripts/capacity.py pause` and verify Paused.
2. For an existing capacity, restore and verify its original state.
3. Restore the policy to Audit unless continued Deny enforcement was explicitly requested.
4. Show `python scripts/cleanup.py` as a dry run; do not delete during a demo unless separately approved.
