"""Tests for the pre-publication security scanner.

The scanner is the last automated gate before this repository goes public, so
its blind spots matter more than most code here. These tests pin the two
properties that make a PASS meaningful.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
SCANNER_PATH = SCRIPTS_DIR / "check_public_repo.py"


def _load_scanner():
    """Import check_public_repo.py, which lives in scripts/ rather than a package.

    The scripts share a `_bootstrap` module by sitting on sys.path together, so
    that directory has to be importable before the scanner will load.
    """
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location("check_public_repo", SCANNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = _load_scanner()


class TestShouldScanTrackedFiles:
    """A tracked file is always content-scanned, wherever it lives.

    `results/` is in SKIP_DIRS so the scanner does not walk local run output.
    But if someone runs `git add -f results/...`, that file becomes part of the
    published tree while being full of subscription and object ids. Skipping it
    is precisely where such a leak would hide.
    """

    def test_untracked_results_file_is_skipped(self):
        path = REPO_ROOT / "results" / "validate-latest.json"
        assert scanner.should_scan(path, tracked=False) is False

    def test_tracked_results_file_is_scanned_anyway(self):
        path = REPO_ROOT / "results" / "validate-latest.json"
        assert scanner.should_scan(path, tracked=True) is True

    def test_tracked_flag_defaults_to_false(self):
        """The default must stay conservative for filesystem-walk fallback."""
        path = REPO_ROOT / "results" / "validate-latest.json"
        assert scanner.should_scan(path) is False

    def test_binary_suffix_skipped_even_when_tracked(self):
        """Tracking does not make a PNG worth scanning for text secrets."""
        assert scanner.should_scan(REPO_ROOT / "docs" / "diagram.png", tracked=True) is False

    def test_ordinary_source_file_is_scanned(self):
        assert scanner.should_scan(REPO_ROOT / "src" / "fabgov" / "config.py") is True


class TestScanLineDetection:
    """The scanner must actually catch the categories it claims to."""

    def _findings(self, line):
        found = []
        scanner.scan_line("x.py", 1, line, found)
        return found

    def test_detects_real_looking_guid(self):
        value = "-".join(("3f2504e0", "4f89", "11d3", "9a0c", "0305e82c3301"))
        assert any(f.kind == "guid" for f in self._findings("id = " + value))

    def test_ignores_placeholder_guid(self):
        assert self._findings("id = 00000000-0000-0000-0000-000000000000") == []

    def test_ignores_repeated_char_guid(self):
        assert self._findings("id = 11111111-1111-1111-1111-111111111111") == []

    def test_detects_non_example_email(self):
        address = "someone" + "@" + "realcompany.test"
        assert any(f.kind == "email" for f in self._findings("owner: " + address))

    @pytest.mark.parametrize("domain", ["example.com", "example.org", "contoso.com"])
    def test_ignores_documentation_email_domains(self, domain):
        assert self._findings("owner: someone@" + domain) == []

    def test_allows_exact_github_system_committer(self):
        assert self._findings("committer: noreply@github.com") == []

    def test_does_not_allow_every_github_address(self):
        address = "person" + "@" + "github.com"
        assert any(item.kind == "email" for item in self._findings(address))

    def test_detects_private_key_header(self):
        assert self._findings("-----BEGIN " + "PRIVATE KEY-----") != []

    def test_detects_arm_resource_id_with_real_guid(self):
        value = "-".join(("3f2504e0", "4f89", "11d3", "9a0c", "0305e82c3301"))
        line = "/subscriptions/" + value + "/resourceGroups/rg"
        assert any(f.kind == "guid" for f in self._findings(line))

    def test_ignores_placeholder_resource_id(self):
        line = "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"
        assert self._findings(line) == []


class TestNoScannerBypass:
    def test_allowlist_comment_does_not_suppress_a_finding(self):
        found = []
        value = "-".join(("3f2504e0", "4f89", "11d3", "9a0c", "0305e82c3301"))
        scanner.scan_line("x.py", 1, "guid = " + value + "  # scanner-ignore", found)
        assert any(item.kind == "guid" for item in found)


class TestHistoryScan:
    def test_scans_commit_identity(self, monkeypatch):
        address = "person" + "@" + "realcompany.test"

        def fake_git(args, cwd=None):
            if args[0] == "log":
                return True, "abc123\n"
            if args[0] == "show":
                return True, "Author <{0}>\nCommitter <noreply@users.noreply.github.com>\n".format(address)
            if args[0] == "ls-tree":
                return True, ""
            raise AssertionError(args)

        monkeypatch.setattr(scanner, "git", fake_git)
        findings = []
        scanner.scan_history(findings)
        assert any(item.kind == "email" for item in findings)

    def test_scans_complete_historical_blobs(self, monkeypatch):
        value = "-".join(("3f2504e0", "4f89", "11d3", "9a0c", "0305e82c3301"))

        def fake_git(args, cwd=None):
            if args[0] == "log":
                return True, "abc123\n"
            if args[0] == "show":
                return True, "Agent <noreply@users.noreply.github.com>\n" * 2
            if args[0] == "ls-tree":
                return True, "100644 blob deadbeef\tremoved.txt\n"
            if args[0] == "cat-file":
                return True, "removed id " + value
            raise AssertionError(args)

        monkeypatch.setattr(scanner, "git", fake_git)
        findings = []
        scanner.scan_history(findings)
        assert any(item.kind == "guid" for item in findings)


class TestEnvExampleHygiene:
    """.env.example must never ship a real value."""

    def test_env_example_passes_its_own_check(self):
        findings = []
        scanner.check_env_example(findings)
        assert findings == [], [f.detail for f in findings]

    def test_gitignore_covers_the_essentials(self):
        findings = []
        scanner.check_gitignore(findings)
        assert findings == [], [f.detail for f in findings]
