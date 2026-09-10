"""Shared bootstrap for the scripts in this directory.

Puts ``src/`` on the import path so the scripts run directly from a clone with
no install step, and configures logging consistently across every entry point.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def configure_logging(verbose: bool = False) -> None:
    """UTC ISO timestamps; logs are demo evidence."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = __import__("time").gmtime
    # Azure Identity is chatty about credential probing at INFO.
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def resolve_env_file(path: str = ".env"):
    """Resolve the .env path, falling back to the repository root.

    Without this, running ``python scripts/preflight.py`` from inside
    ``scripts/`` silently loads no configuration at all and proceeds with
    defaults, which reads as "nothing is configured" rather than as an error.
    An absolute path is always honoured exactly as given.
    """
    candidate = Path(path)
    if candidate.is_absolute() or candidate.is_file():
        return candidate
    # Neither the cwd-relative file nor an absolute path; point at the repo
    # root, which is where the file is documented to live. Returning this path
    # even when absent keeps error messages pointing somewhere useful.
    return REPO_ROOT / path


def find_az_cli() -> str:
    """Locate the Azure CLI executable.

    On Windows ``az`` is a ``.cmd`` shim, which ``subprocess`` will not resolve
    from the bare name without a shell. Resolving the real path lets us keep
    ``shell=False`` (no command injection surface) on every platform.
    """
    import shutil

    for candidate in ("az", "az.cmd", "az.bat", "az.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def run_az(args, timeout: int = 60):
    """Run an Azure CLI command, returning ``(returncode, stdout, stderr)``.

    Returns ``(127, "", ...)`` when the CLI is not installed, so callers can
    degrade gracefully instead of raising.
    """
    import subprocess

    executable = find_az_cli()
    if not executable:
        return 127, "", "Azure CLI not found on PATH."
    try:
        completed = subprocess.run(
            [executable] + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)
    except Exception as exc:  # noqa: BLE001 - a CLI problem must not crash --help
        return 1, "", str(exc)


def resolve_subscription_id(configured: str = "") -> str:
    """Resolve the subscription id from config, else from the Azure CLI context.

    Falling back to the CLI's current subscription keeps ``.env`` free of a
    real subscription id for users who just want to try the POC.
    """
    if configured:
        return configured
    code, stdout, _ = run_az(["account", "show", "--query", "id", "-o", "tsv"], timeout=30)
    return stdout if code == 0 else ""


def fail(message: str, code: int = 1):
    """Print a clear error and exit."""
    print("")
    print("ERROR: {0}".format(message))
    print("")
    raise SystemExit(code)
