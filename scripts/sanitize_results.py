#!/usr/bin/env python3
"""Produce a shareable copy of a result file with identifiers redacted.

``results/`` is gitignored because run output contains subscription ids,
resource group names, and capacity names. This script turns one of those files
into something safe to paste into a document or commit under
``docs/sample-output/``.

    python scripts/sanitize_results.py results/validate-latest.json
    python scripts/sanitize_results.py results/validate-latest.json -o docs/sample-output/validation.json

Review the output before publishing it. Automated redaction is a safety net,
not a substitute for reading what you are about to make public.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import configure_logging, fail, resolve_env_file  # noqa: E402
from fabgov.config import load_config  # noqa: E402
from fabgov.sanitize import find_sensitive_strings, sanitize_document  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sanitize_results.py",
        description="Redact Azure identifiers from a POC result file.",
    )
    parser.add_argument("input", help="Path to the result JSON to sanitize.")
    parser.add_argument("-o", "--output", default="", help="Where to write (default: stdout).")
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--no-env-terms",
        action="store_true",
        help="Do not additionally redact names read from .env.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    source = Path(args.input)
    if not source.is_file():
        fail("Input file not found: {0}".format(source))
        return 1

    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except ValueError as exc:
        fail("Input is not valid JSON: {0}".format(exc))
        return 1

    # Environment-specific names that no regex could infer - the literal
    # resource group and capacity names from the local configuration.
    extra_terms = []
    if not args.no_env_terms:
        try:
            config = load_config(resolve_env_file(args.env_file))
            extra_terms = [
                config.resource_group,
                config.capacity_name,
                config.automation_account_name,
            ]
        except Exception:  # noqa: BLE001 - sanitizing must work without valid config
            extra_terms = []

    sanitized = sanitize_document(document, extra_terms=extra_terms)
    rendered = json.dumps(sanitized, indent=2)

    # Verify our own output before handing it back.
    residual = find_sensitive_strings(rendered)
    if residual:
        print("", file=sys.stderr)
        print("WARNING: possible identifiers remain after sanitization:", file=sys.stderr)
        for finding in residual[:20]:
            print("  {0}: {1}".format(finding["kind"], finding["match"]), file=sys.stderr)
        print("Review the output manually before publishing it.", file=sys.stderr)
        print("", file=sys.stderr)

    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
        print("Sanitized copy written to {0}".format(target))
        print("Review it before committing.")
    else:
        print(rendered)

    return 2 if residual else 0


if __name__ == "__main__":
    sys.exit(main())
