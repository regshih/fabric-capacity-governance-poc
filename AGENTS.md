# Coding agent instructions

- Read `README.md` first.
- Never commit secrets, Azure tokens, environment values, tenant/subscription/object IDs, email addresses, real resource names, or raw deployment results.
- Use placeholders in tracked files and ignored `.env`/`results/` files at runtime.
- Preserve all safety defaults. Never modify an existing capacity without explicit authorization.
- Never resize an existing capacity to test policy. Never delete it.
- For a POC-created capacity, allow only F2 and leave it paused after testing.
- Use current official Microsoft documentation as the source of truth. Verify Fabric API versions and Azure Policy aliases; do not invent unsupported behavior.
- Keep Audit as the default policy effect. Deny requires explicit opt-in.
- Apply RBAC at the narrowest practical scope and do not call the lifecycle role pause/resume-only because it includes `capacities/write`.
- Run unit tests, lint, and the public-repository check before completing changes.
- Keep live integration tests separate from ordinary CI.
- Update `docs/POC_FINDINGS.md` only from evidence actually collected, and distinguish implemented from validated.
- Keep documentation generic and customer-ready.
