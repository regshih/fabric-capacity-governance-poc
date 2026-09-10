# Security

## Reporting a vulnerability

Do not open a public issue containing credentials, Azure identifiers, logs, or deployment output. Use the repository owner's private security-reporting channel when available. Include a minimal reproduction with all environment values replaced by placeholders.

## Supported scope

This is a reference POC, not a managed service. Security fixes are applied to the current default branch. Customers are responsible for reviewing role scope, policy scope, network access, schedules, and operational ownership before production use.

## Secrets and environment data

The implementation uses Azure CLI or `DefaultAzureCredential` locally and managed identity in Azure Automation. It does not need stored credentials. Real values belong only in the ignored `.env` and `results/` locations.

Before publishing a branch, run:

```powershell
python scripts/check_public_repo.py --include-history
python -m bandit -r src scripts -ll -ii
python -m pip_audit -r requirements.txt --progress-spinner off
```

The expected final line is `PUBLIC_REPO_CHECK: PASS`. This check supplements, but does not replace, repository-host secret scanning and human review.

The latest independent review and remediations are recorded in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
