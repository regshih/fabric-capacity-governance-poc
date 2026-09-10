# Public repository security

## Data classification

Tracked files are public examples. Treat the following as local operational data and never commit them:

- `.env` and other populated environment files
- Azure CLI/MSAL caches
- subscription, tenant, principal, role-assignment, resource-group, or resource IDs
- real resource names and user email addresses
- tokens, passwords, certificates, private keys, connection strings, and SAS values
- raw deployment, validation, policy, or Automation job output
- Terraform state or generated parameter files

The `.gitignore` excludes these paths. Runtime results go under `results/`; the directory contains only a tracked `.gitkeep`.

## Ownership and mutation safety

Generic tags can collide and are not sufficient proof of ownership. The deployer creates an ignored manifest with a random deployment ID and exact Azure resource IDs. Destructive cleanup requires both the exact manifest record and matching live ownership tags. Existing-capacity mode is never eligible for capacity deletion.

## Release check

Run from the repository root:

```powershell
python scripts/check_public_repo.py --include-history
```

The scanner examines publishable worktree files, commit author/committer identities, and every reachable historical blob. It flags GUIDs, non-example emails, resource IDs, credential assignments, auth tokens, private-key markers, connection secrets, and common service-token shapes. It has no per-line suppression pragma. It also verifies required public files and ignore rules.

Run `Bandit` for Python security analysis and `pip-audit` for known dependency vulnerabilities as shown in the README. CI runs both checks without Azure credentials.

If Gitleaks or a repository-host secret scanner is available, run it as an independent second control. Any finding must be reviewed before publication. Removing a secret from the latest commit is insufficient if it remains in history; rotate an exposed credential and rewrite affected history using an approved process.

## Safe issue and support workflow

Sanitize diagnostic output with `python scripts/sanitize_results.py` before sharing. Confirm placeholders replaced every environment value. Do not paste `.env`, raw `az` output, Automation job parameters, or manifest contents into public issues.

## CI boundary

Ordinary pull-request CI is offline and receives no Azure credentials. Live integration tests require an explicit environment flag and local authenticated context; they are not part of public CI.
