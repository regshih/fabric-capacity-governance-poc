"""Structured result recording for POC runs.

Results are written to ``results/`` which is gitignored, because they contain
subscription ids, resource group names, and capacity names. A sanitized copy
suitable for sharing is produced by ``scripts/sanitize_results.py``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

LOGGER = logging.getLogger("fabgov.results")

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"

# The three statuses used throughout the POC. "NOT VALIDATED" is a first-class
# outcome, not a failure: a test that could not run must never be silently
# upgraded into a passing one.
STATUS_OK = "PASS"
STATUS_FAIL = "FAIL"
STATUS_NOT_VALIDATED = "NOT VALIDATED"
STATUS_SKIPPED = "SKIPPED"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ResultRecorder:
    """Collects step outcomes over a run and writes them as JSON."""

    def __init__(self, run_name: str, results_dir=RESULTS_DIR):
        self.run_name = run_name
        self.results_dir = Path(results_dir)
        self.started_at = utc_now_iso()
        self.steps = []
        self.metadata = {}

    def record(self, name: str, status: str, *, details=None, reason: str = "") -> dict:
        """Record one step outcome.

        ``reason`` is required in spirit for anything not PASS - a bare
        "NOT VALIDATED" with no explanation is useless to the reader of
        POC_FINDINGS.md.
        """
        entry = {
            "step": name,
            "status": status,
            "timestamp": utc_now_iso(),
        }
        if reason:
            entry["reason"] = reason
        if details is not None:
            entry["details"] = details
        self.steps.append(entry)

        log = LOGGER.info if status == STATUS_OK else LOGGER.warning
        log("[%s] %s%s", status, name, " - " + reason if reason else "")
        return entry

    def record_pass(self, name: str, **kwargs) -> dict:
        return self.record(name, STATUS_OK, **kwargs)

    def record_fail(self, name: str, reason: str, **kwargs) -> dict:
        return self.record(name, STATUS_FAIL, reason=reason, **kwargs)

    def record_not_validated(self, name: str, reason: str, **kwargs) -> dict:
        return self.record(name, STATUS_NOT_VALIDATED, reason=reason, **kwargs)

    def record_skipped(self, name: str, reason: str, **kwargs) -> dict:
        return self.record(name, STATUS_SKIPPED, reason=reason, **kwargs)

    # ---- summary ---------------------------------------------------------

    def counts(self) -> dict:
        summary = {}
        for step in self.steps:
            status = step["status"]
            summary[status] = summary.get(status, 0) + 1
        return summary

    @property
    def has_failures(self) -> bool:
        return any(step["status"] == STATUS_FAIL for step in self.steps)

    def document(self) -> dict:
        return {
            "run": self.run_name,
            "startedAt": self.started_at,
            "completedAt": utc_now_iso(),
            "metadata": self.metadata,
            "summary": self.counts(),
            "steps": self.steps,
        }

    def write(self, filename=None) -> Path:
        """Write the result document to ``results/``."""
        self.results_dir.mkdir(parents=True, exist_ok=True)
        name = filename or "{0}-{1}.json".format(
            self.run_name, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        )
        path = self.results_dir / name
        path.write_text(json.dumps(self.document(), indent=2), encoding="utf-8")
        LOGGER.info("Results written to %s", path)
        return path

    def print_summary(self) -> None:
        """Print a human-readable summary table."""
        print("")
        print("=" * 72)
        print("  {0}".format(self.run_name))
        print("=" * 72)
        width = max((len(s["step"]) for s in self.steps), default=10)
        for step in self.steps:
            print("  {0:<{1}}  {2}".format(step["step"], width, step["status"]))
            if step.get("reason"):
                print("  {0:<{1}}  -> {2}".format("", width, step["reason"]))
        print("-" * 72)
        counts = self.counts()
        print("  " + "  ".join("{0}: {1}".format(k, v) for k, v in sorted(counts.items())))
        print("=" * 72)
        print("")
