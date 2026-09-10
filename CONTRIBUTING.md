# Contributing

Contributions should keep this repository safe for public customer use.

1. Read `README.md`, `AGENTS.md`, and `docs/SECURITY_PUBLIC_REPO.md`.
2. Create a branch and make a focused change.
3. Never add real Azure identifiers, credentials, populated environment files, or raw runtime results.
4. Preserve safe defaults and verify API versions or policy aliases against current Microsoft documentation.
5. Run `python -m pytest tests/unit -q`, `python -m ruff check .`, and `python scripts/check_public_repo.py`.
6. Update `docs/POC_FINDINGS.md` only when a claim is backed by actual captured testing.

Live tests must be explicitly enabled and must finish by restoring an existing capacity's original state or pausing a POC-created capacity.
