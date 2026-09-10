# Security audit

Audit date: 2026-09-09

This repository was independently reviewed after concurrent editing was detected. The published baseline was rebuilt as a single reviewed commit; no earlier editor commit is part of the default branch history.

## Corrected findings

| Finding | Risk | Resolution |
|---|---|---|
| A real email address appeared in commit metadata | Personal/environment data in public Git history | History rebuilt with a generic GitHub no-reply identity; scanner now checks author and committer metadata |
| Scanner suppression comments hid secret-shaped fixtures | A real secret could be hidden by the same bypass | Suppression mechanism removed; fixtures are assembled only at test runtime |
| History scan examined patch additions rather than every blob | Deleted or unchanged historical data could be missed | Scanner now reads every reachable blob plus commit identities |
| ARM client accepted arbitrary absolute LRO URLs | Bearer token could be sent off the configured Resource Manager origin | HTTPS scheme, exact host/port, no user info/fragment, and redirect blocking are enforced before token acquisition |
| Policy Deny test used a fixed capacity name | A collision could update or delete a pre-existing resource | Each test uses a random name, performs a preflight GET, applies per-run ownership tags, and deletes only an exact tag match |
| Existing Automation accounts could be changed implicitly | A name collision could enable identity or overwrite a runbook | Unproven existing accounts are blocked unless `ALLOW_EXISTING_AUTOMATION_MODIFICATION=true` |
| Cleanup attempted role-definition deletion before its assignments | Cleanup could fail and leave inconsistent control-plane artifacts | Exact manifest-recorded capacity assignments are deleted first |
| Python lifecycle result could return before the target resource state was observed | Accepted ARM work could be mistaken for completed state | Every waited operation now polls the capacity until the target state or raises a timeout |

## Verification performed

- Unit tests and explicit read-only Azure integration test
- Ruff lint and formatting checks
- Bandit static analysis with zero medium/high findings
- `pip-audit` with no known vulnerabilities in resolved runtime dependencies
- JSON parsing, PowerShell parser validation, and Bicep compilation
- Custom scanner over publishable files, commit identities, and all reachable Git blobs
- `detect-secrets` as an independent content scan
- Exact comparison of ignored runtime identifiers against tracked content and history
- Deployment and cleanup dry runs
- Live Azure Automation managed-identity Resume and Pause jobs after hardening
- Direct lifecycle validation after hardening, with independent final-state reads

## Residual considerations

- The custom lifecycle role includes `Microsoft.Fabric/capacities/write` because Microsoft documents it as part of the lifecycle prerequisite. This permission is broader than pause/resume.
- Optional schedules were intentionally not enabled or observed firing.
- No separate human test principal was supplied, so human-principal scope comparisons remain unvalidated.
- Dependency and platform behavior can change; CI reruns static, dependency, unit, and repository-history checks on each change.
