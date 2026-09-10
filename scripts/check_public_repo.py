#!/usr/bin/env python3
"""Pre-publication security scan for this repository.

Checks the working tree, the files git would actually publish, and (where
practical) git history, for values that must not appear in a public repository:
tokens, keys, GUIDs that could be tenant or subscription ids, email addresses,
and environment-specific resource identifiers.

    python scripts/check_public_repo.py
    python scripts/check_public_repo.py --include-history
    python scripts/check_public_repo.py --json

Prints ``PUBLIC_REPO_CHECK: PASS`` only when every check passes.

This complements, and does not replace, a dedicated secret scanner such as
Gitleaks. Run both before publishing.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from _bootstrap import REPO_ROOT, configure_logging  # noqa: E402
from fabgov.sanitize import (  # noqa: E402
    BASIC_AUTH_PATTERN,
    BEARER_PATTERN,
    CONNECTION_SECRET_PATTERN,
    EMAIL_PATTERN,
    GUID_PATTERN,
    JWT_PATTERN,
    SAS_QUERY_PATTERN,
    SERVICE_TOKEN_PATTERN,
)

# Files we never scan for content (binary or generated).
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".whl",
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".exe",
    ".woff",
    ".woff2",
    ".ttf",
}
SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".terraform",
    "results",
}

# Placeholder GUIDs and documentation examples that are safe by construction.
ALLOWED_GUID_CONTEXTS = (
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
)

# Example domains reserved for documentation (RFC 2606) are not real addresses.
ALLOWED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "contoso.com",
    "users.noreply.github.com",
)
ALLOWED_EMAIL_ADDRESSES = ("noreply@github.com",)

# High-signal credential markers.
SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    (
        "client-secret-assignment",
        re.compile(
            r"(?i)\b(client_secret|clientsecret|password|passwd|pwd)\s*[:=]\s*[\"']?[A-Za-z0-9~._\-]{8,}"
        ),
    ),
    (
        "connection-string",
        re.compile(r"(?i)(AccountKey|SharedAccessKey|AccountEndpoint)\s*=\s*[A-Za-z0-9+/=]{16,}"),
    ),
    ("azure-storage-key", re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=")),
    ("connection-secret", CONNECTION_SECRET_PATTERN),
    ("sas-query", SAS_QUERY_PATTERN),
    ("basic-auth", BASIC_AUTH_PATTERN),
    ("service-token", SERVICE_TOKEN_PATTERN),
)

# Assignments in .env.example must stay empty or be a safe literal default.
SAFE_ENV_EXAMPLE_VALUES = {
    "",
    "existing",
    "create",
    "F2",
    "F2,F4,F8",
    "Audit",
    "Deny",
    "Disabled",
    "true",
    "false",
    "07:00",
    "19:00",
    "UTC",
    "User",
    "Group",
    "ServicePrincipal",
}


class Finding:
    def __init__(self, severity, kind, path, line_no, detail):
        self.severity = severity
        self.kind = kind
        self.path = path
        self.line_no = line_no
        self.detail = detail

    def as_dict(self):
        return {
            "severity": self.severity,
            "kind": self.kind,
            "path": self.path,
            "line": self.line_no,
            "detail": self.detail,
        }


def git(args, cwd=None):
    """Run a git command, returning ``(ok, stdout)``."""
    try:
        completed = subprocess.run(
            ["git"] + list(args),
            cwd=str(cwd or REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
        return completed.returncode == 0, completed.stdout
    except (OSError, subprocess.SubprocessError):
        return False, ""


def tracked_files():
    """Tracked and untracked files Git would publish, excluding ignored files."""
    ok, output = git(["ls-files", "--cached", "--others", "--exclude-standard"])
    if ok:
        return [REPO_ROOT / line.strip() for line in output.splitlines() if line.strip()]
    results = []
    for path in REPO_ROOT.rglob("*"):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
            results.append(path)
    return results


def should_scan(path: Path, *, tracked: bool = False) -> bool:
    """Whether to scan a file's content.

    SKIP_DIRS exists to avoid walking build and cache directories. It must NOT
    exempt a file that git is actually tracking: `results/` is normally ignored,
    but a `git add -f` would put a real result file - full of subscription and
    object ids - into the published tree, and skipping it here is exactly where
    that leak would hide. Anything tracked gets scanned regardless of location.
    """
    if path.suffix.lower() in SKIP_SUFFIXES:
        return False
    if tracked:
        return True
    return not any(part in SKIP_DIRS for part in path.parts)


def is_placeholder_guid(value: str) -> bool:
    lowered = value.lower()
    if lowered in ALLOWED_GUID_CONTEXTS:
        return True
    # A GUID of a single repeated character is a placeholder, not a real id.
    stripped = lowered.replace("-", "")
    return len(set(stripped)) <= 2


def is_allowed_email(value: str) -> bool:
    if value.lower() in ALLOWED_EMAIL_ADDRESSES:
        return True
    domain = value.split("@")[-1].lower()
    return any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS)


def scan_line(path_label, line_no, line, findings) -> None:
    """Scan a single line for every category of problem."""
    for kind, pattern in SECRET_PATTERNS:
        if pattern.search(line):
            findings.append(Finding("ERROR", kind, path_label, line_no, "Matched {0}.".format(kind)))

    if JWT_PATTERN.search(line):
        findings.append(Finding("ERROR", "jwt-token", path_label, line_no, "JWT-shaped token."))
    if BEARER_PATTERN.search(line):
        findings.append(Finding("ERROR", "bearer-token", path_label, line_no, "Bearer token."))

    for guid in GUID_PATTERN.findall(line):
        if is_placeholder_guid(guid):
            continue
        findings.append(
            Finding(
                "ERROR",
                "guid",
                path_label,
                line_no,
                "GUID that may be a tenant, subscription, or object id (value withheld).",
            )
        )

    for email in EMAIL_PATTERN.findall(line):
        if is_allowed_email(email):
            continue
        findings.append(
            Finding(
                "ERROR",
                "email",
                path_label,
                line_no,
                "Non-example email address (value withheld).",
            )
        )


def check_env_example(findings) -> None:
    """Every assignment in .env.example must be blank or a safe literal."""
    path = REPO_ROOT / ".env.example"
    if not path.is_file():
        findings.append(Finding("ERROR", "missing-file", ".env.example", 0, "File does not exist."))
        return
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("\"'")
        if value in SAFE_ENV_EXAMPLE_VALUES:
            continue
        findings.append(
            Finding(
                "ERROR",
                "populated-env-example",
                ".env.example",
                line_no,
                "{0} has a non-placeholder value. .env.example must ship empty.".format(key.strip()),
            )
        )


def check_gitignore(findings) -> None:
    """The entries that keep real values out of the repository."""
    path = REPO_ROOT / ".gitignore"
    if not path.is_file():
        findings.append(Finding("ERROR", "missing-file", ".gitignore", 0, "File does not exist."))
        return
    content = path.read_text(encoding="utf-8")
    required = [".env", "results/", "*.tfstate", "*.pem", "*.key", ".azure/"]
    for entry in required:
        token = entry.rstrip("/")
        if token not in content:
            findings.append(
                Finding(
                    "ERROR", "gitignore-gap", ".gitignore", 0, "Missing an ignore rule for {0}".format(entry)
                )
            )


def check_env_not_tracked(findings) -> None:
    """A real .env must never be staged or committed."""
    ok, output = git(["ls-files", "--error-unmatch", ".env"])
    if ok and output.strip():
        findings.append(
            Finding(
                "ERROR", "tracked-env", ".env", 0, ".env is tracked by git. Remove it: git rm --cached .env"
            )
        )
    for candidate in (".env", "config/poc.yaml"):
        path = REPO_ROOT / candidate
        if path.is_file():
            ok, output = git(["check-ignore", candidate])
            if not ok:
                findings.append(
                    Finding(
                        "ERROR",
                        "unignored-secret-file",
                        candidate,
                        0,
                        "Exists but is NOT ignored by .gitignore.",
                    )
                )


def check_required_docs(findings) -> None:
    """Documents a public reference repository is expected to carry."""
    for name in ("README.md", "SECURITY.md", "LICENSE", "AGENTS.md", "docs/LLM_AGENT_PROMPT.md"):
        if not (REPO_ROOT / name).is_file():
            findings.append(Finding("ERROR", "missing-file", name, 0, "Required for publication."))


def scan_history(findings, max_commits: int = 500) -> None:
    """Scan commit identities and every reachable historical blob.

    Only practical on a repository of modest size, which is why it is opt-in.
    """
    ok, output = git(["log", "--all", "--format=%H", "-n", str(max_commits)])
    if not ok or not output.strip():
        findings.append(
            Finding(
                "WARN",
                "history-unavailable",
                "(git history)",
                0,
                "Could not read git history. Scan it manually before publishing.",
            )
        )
        return

    commits = [c.strip() for c in output.splitlines() if c.strip()]
    seen_blobs = set()
    for commit in commits:
        ok, metadata = git(["show", "-s", "--format=%an <%ae>%n%cn <%ce>", commit])
        if not ok:
            findings.append(
                Finding("WARN", "history-unavailable", "(git history)", 0, "Could not read commit metadata.")
            )
            continue
        for line_no, line in enumerate(metadata.splitlines(), start=1):
            scan_line("(commit metadata {0})".format(commit[:12]), line_no, line, findings)

        ok, tree = git(["ls-tree", "-r", commit])
        if not ok:
            findings.append(
                Finding(
                    "WARN", "history-unavailable", "(git history)", 0, "Could not enumerate a commit tree."
                )
            )
            continue
        for entry in tree.splitlines():
            before_path, separator, path = entry.partition("\t")
            fields = before_path.split()
            if not separator or len(fields) < 3 or fields[1] != "blob":
                continue
            blob_id = fields[2]
            if blob_id in seen_blobs or Path(path).suffix.lower() in SKIP_SUFFIXES:
                continue
            seen_blobs.add(blob_id)
            ok, content = git(["cat-file", "blob", blob_id])
            if not ok:
                continue
            label = "(historical blob {0}:{1})".format(commit[:12], path)
            for line_no, line in enumerate(content.splitlines(), start=1):
                scan_line(label, line_no, line, findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_public_repo.py",
        description="Scan this repository for values that must not be published.",
    )
    parser.add_argument("--include-history", action="store_true", help="Also scan committed git history.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    findings = []

    check_gitignore(findings)
    check_env_example(findings)
    check_env_not_tracked(findings)
    check_required_docs(findings)

    scanned = 0
    from_git, _ = git(["ls-files"])
    for path in tracked_files():
        if not path.is_file() or not should_scan(path, tracked=from_git):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        label = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        for line_no, line in enumerate(text.splitlines(), start=1):
            scan_line(label, line_no, line, findings)

    if args.include_history:
        scan_history(findings)

    errors = [f for f in findings if f.severity == "ERROR"]
    warnings = [f for f in findings if f.severity == "WARN"]

    if args.json:
        print(
            json.dumps(
                {
                    "filesScanned": scanned,
                    "errors": len(errors),
                    "warnings": len(warnings),
                    "findings": [f.as_dict() for f in findings],
                    "result": "PASS" if not errors else "FAIL",
                },
                indent=2,
            )
        )
        return 0 if not errors else 1

    print("")
    print("Public repository security scan")
    print("=" * 78)
    print("  Files scanned: {0}".format(scanned))
    print("  History scan:  {0}".format("yes" if args.include_history else "no (use --include-history)"))
    print("")
    if not findings:
        print("  No findings.")
    for finding in findings:
        location = "{0}:{1}".format(finding.path, finding.line_no) if finding.line_no else finding.path
        print("  [{0}] {1}".format(finding.severity, location))
        print("         {0} - {1}".format(finding.kind, finding.detail))
    print("=" * 78)
    print("  {0} error(s), {1} warning(s)".format(len(errors), len(warnings)))
    print("")

    if errors:
        print("PUBLIC_REPO_CHECK: FAIL")
        print("")
        print("Resolve every ERROR before publishing. Also run a dedicated secret")
        print("scanner such as Gitleaks: gitleaks detect --source . --redact")
        print("")
        return 1

    print("PUBLIC_REPO_CHECK: PASS")
    print("")
    if not args.include_history:
        print("Note: git history was not scanned. Re-run with --include-history before")
        print("making the repository public.")
        print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
