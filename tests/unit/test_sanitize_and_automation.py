"""Result sanitization and Azure Automation body construction."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from fabgov.automation import (
    build_account_body,
    build_job_schedule_body,
    build_runbook_body,
    build_schedule_body,
    existing_account_change_allowed,
    next_occurrence_utc,
)
from fabgov.results import (
    STATUS_FAIL,
    STATUS_NOT_VALIDATED,
    STATUS_OK,
    ResultRecorder,
)
from fabgov.sanitize import (
    find_sensitive_strings,
    is_sensitive_key,
    sanitize_document,
    sanitize_text,
    sanitize_value,
)

# Construct secret-shaped fixtures at runtime so repository scanners remain
# strict over every source line without needing suppression comments.
REAL_LOOKING_GUID = "-".join(("3f2504e0", "4f89", "11d3", "9a0c", "0305e82c3301"))


class TestSanitizeText:
    def test_redacts_guid(self):
        assert REAL_LOOKING_GUID not in sanitize_text("tenant is " + REAL_LOOKING_GUID)

    def test_redacts_email(self):
        address = "someone" + "@" + "realcompany.example"
        result = sanitize_text("owner is " + address)
        assert address not in result
        assert "<PRINCIPAL_UPN>" in result

    def test_redacts_subscription_segment(self):
        result = sanitize_text("/subscriptions/" + REAL_LOOKING_GUID + "/resourceGroups/my-rg")
        assert REAL_LOOKING_GUID not in result
        assert "my-rg" not in result
        assert "<SUBSCRIPTION_ID>" in result
        assert "<RESOURCE_GROUP>" in result

    def test_redacts_capacity_segment(self):
        result = sanitize_text("/providers/Microsoft.Fabric/capacities/mycapacity")
        assert "mycapacity" not in result
        assert "<CAPACITY_NAME>" in result

    def test_redacts_jwt(self):
        token = ".".join(
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                "abc123" + "def456",
            )
        )
        result = sanitize_text("Authorization: " + token)
        assert token not in result
        assert "<REDACTED_TOKEN>" in result

    def test_redacts_bearer_header(self):
        result = sanitize_text("Bearer " + "abcdefghijklmnopqrstuvwxyz" + "0123456789")
        assert "abcdefghijklmnopqrstuvwxyz" not in result

    @pytest.mark.parametrize(
        "secret",
        [
            "Account" + "Key=QUJDREVGR0hJSktM" + "TU5PUFFSU1RVVldYWVo=",
            "SharedAccess" + "Signature=sv=2024-01-01&" + "si" + "g=supersecretvalue",
            "https://example.invalid/blob?" + "s" + "v=1&" + "s" + "p=r&" + "si" + "g=supersecretvalue",
            "Basic " + "QWxhZGRpbjpvcGVu" + "IHNlc2FtZQ==",
            "ghp_" + "abcdefghijklmnopqr" + "stuvwxyz0123456789",
        ],
    )
    def test_redacts_non_guid_secrets(self, secret):
        assert secret not in sanitize_text(secret)

    def test_redacts_private_key_block(self):
        secret = "-----BEGIN " + "PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
        assert "abc123" not in sanitize_text(secret)

    def test_preserves_resource_id_shape(self):
        """Redaction must keep the id readable so docs still teach the structure."""
        result = sanitize_text(
            "/subscriptions/"
            + REAL_LOOKING_GUID
            + "/resourceGroups/rg1/providers/Microsoft.Fabric/capacities/cap1"
        )
        assert result.startswith("/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/")
        assert "Microsoft.Fabric/capacities" in result

    def test_non_string_passthrough(self):
        assert sanitize_text(None) is None
        assert sanitize_text(123) == 123


class TestIsSensitiveKey:
    @pytest.mark.parametrize(
        "key",
        [
            "subscriptionId",
            "subscription_id",
            "tenantId",
            "objectId",
            "principalId",
            "clientId",
            "accessToken",
            "password",
            "clientSecret",
        ],
    )
    def test_sensitive(self, key):
        assert is_sensitive_key(key) is True

    @pytest.mark.parametrize("key", ["allowedSkus", "state", "sku", "location", "effect"])
    def test_not_sensitive(self, key):
        assert is_sensitive_key(key) is False


class TestSanitizeValue:
    def test_redacts_by_key_regardless_of_content(self):
        result = sanitize_value({"subscriptionId": "plaintext-not-a-guid"}, key="")
        assert result["subscriptionId"] == "<SUBSCRIPTION_ID>"

    def test_recurses_into_nested_structures(self):
        document = {"a": {"b": [{"tenantId": "anything"}]}}
        assert sanitize_document(document)["a"]["b"][0]["tenantId"] == "<TENANT_ID>"

    def test_sensitive_parent_mapping_is_redacted_wholesale(self):
        document = {"clientSecret": {"value": "not-guid-shaped", "metadata": "also-sensitive"}}
        assert sanitize_document(document)["clientSecret"].startswith("<REDACTED")

    def test_bare_resource_names_are_redacted_by_key(self):
        result = sanitize_document({"resourceGroup": "real-rg", "capacityName": "realcap"})
        assert result == {
            "resourceGroup": "<RESOURCE_GROUP>",
            "capacityName": "<CAPACITY_NAME>",
        }

    def test_preserves_non_sensitive_values(self):
        document = {"sku": "F2", "state": "Active", "count": 3, "ok": True}
        assert sanitize_document(document) == document

    def test_preserves_types(self):
        result = sanitize_document({"n": 42, "b": True, "none": None, "list": [1, 2]})
        assert result["n"] == 42 and result["b"] is True
        assert result["none"] is None and result["list"] == [1, 2]


class TestSanitizeDocumentExtraTerms:
    def test_redacts_literal_names(self):
        document = {"note": "capacity mycap1 in group myrg1 is active"}
        result = sanitize_document(document, extra_terms=["mycap1", "myrg1"])
        assert "mycap1" not in result["note"]
        assert "myrg1" not in result["note"]

    def test_ignores_short_terms(self):
        """A 2-character term would corrupt unrelated text."""
        document = {"note": "F2 capacity is ok"}
        result = sanitize_document(document, extra_terms=["F2"])
        assert result["note"] == "F2 capacity is ok"

    def test_case_insensitive(self):
        result = sanitize_document({"n": "MyCap1 here"}, extra_terms=["mycap1"])
        assert "MyCap1" not in result["n"]

    def test_handles_empty_terms(self):
        document = {"note": "unchanged"}
        assert sanitize_document(document, extra_terms=["", None, "  "]) == document


class TestFindSensitiveStrings:
    def test_finds_guid(self):
        findings = find_sensitive_strings("id " + REAL_LOOKING_GUID)
        assert any(f["kind"] == "guid" for f in findings)

    def test_finds_email(self):
        address = "a" + "@" + "b.test"
        findings = find_sensitive_strings("mail me at " + address)
        assert any(f["kind"] == "email" for f in findings)

    def test_truncates_matches(self):
        """The scanner's own output must never become the leak."""
        findings = find_sensitive_strings(REAL_LOOKING_GUID)
        assert REAL_LOOKING_GUID not in findings[0]["match"]
        assert findings[0]["match"].startswith("<redacted")

    def test_clean_text(self):
        assert find_sensitive_strings("nothing to see") == []


class TestNextOccurrence:
    def test_returns_future_instant(self):
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        assert next_occurrence_utc("14:00", now=now) > now

    def test_rolls_to_tomorrow_when_time_has_passed(self):
        now = datetime(2026, 1, 1, 15, 0, tzinfo=timezone.utc)
        result = next_occurrence_utc("07:00", now=now)
        assert result.day == 2 and result.hour == 7

    def test_rolls_forward_when_too_close(self):
        """Automation rejects start times that are imminent."""
        now = datetime(2026, 1, 1, 6, 58, tzinfo=timezone.utc)
        assert next_occurrence_utc("07:00", now=now).day == 2


class TestAutomationBodies:
    def test_account_uses_system_assigned_identity(self):
        body = build_account_body("westus3")
        assert body["identity"]["type"] == "SystemAssigned"


class TestExistingAutomationSafety:
    class Manifest:
        def __init__(self, owns):
            self.owns = owns

        def owns_tagged_resource(self, _body):
            return self.owns

    def test_new_account_is_allowed(self):
        assert existing_account_change_allowed(None, None, explicitly_allowed=False)

    def test_unproven_existing_account_is_blocked_by_default(self):
        assert not existing_account_change_allowed(
            {"id": "account"}, self.Manifest(False), explicitly_allowed=False
        )

    def test_manifest_owned_account_is_allowed(self):
        assert existing_account_change_allowed(
            {"id": "account"}, self.Manifest(True), explicitly_allowed=False
        )

    def test_explicit_override_allows_shared_account(self):
        assert existing_account_change_allowed({"id": "account"}, None, explicitly_allowed=True)


class TestAutomationConfigurationBodies:
    def test_account_disables_local_auth(self):
        """No credential surface: the runbook uses the managed identity only."""
        assert build_account_body("westus3")["properties"]["disableLocalAuth"] is True

    def test_runbook_type_is_powershell(self):
        assert build_runbook_body("westus3")["properties"]["runbookType"] == "PowerShell"

    def test_schedule_requires_time_zone(self):
        with pytest.raises(ValueError, match="time zone"):
            build_schedule_body(description="d", time_of_day="07:00", time_zone="")

    def test_schedule_carries_time_zone(self):
        body = build_schedule_body(
            description="resume", time_of_day="07:00", time_zone="Pacific Standard Time"
        )
        assert body["properties"]["timeZone"] == "Pacific Standard Time"
        assert body["properties"]["frequency"] == "Day"

    def test_job_schedule_lowercases_parameter_names(self):
        body = build_job_schedule_body(
            runbook_name="rb", schedule_name="s", parameters={"DesiredState": "Pause"}
        )
        assert body["properties"]["parameters"] == {"desiredstate": "Pause"}


class TestResultRecorder:
    def test_records_statuses(self):
        recorder = ResultRecorder("test")
        recorder.record_pass("a")
        recorder.record_fail("b", "because")
        recorder.record_not_validated("c", "no permission")
        counts = recorder.counts()
        assert counts[STATUS_OK] == 1
        assert counts[STATUS_FAIL] == 1
        assert counts[STATUS_NOT_VALIDATED] == 1

    def test_has_failures(self):
        recorder = ResultRecorder("test")
        recorder.record_pass("a")
        assert recorder.has_failures is False
        recorder.record_fail("b", "reason")
        assert recorder.has_failures is True

    def test_not_validated_is_not_a_failure(self):
        """A test that could not run must not be reported as a failure or a pass."""
        recorder = ResultRecorder("test")
        recorder.record_not_validated("c", "no permission")
        assert recorder.has_failures is False

    def test_reason_is_recorded(self):
        recorder = ResultRecorder("test")
        recorder.record_not_validated("c", "missing permission X")
        assert recorder.steps[0]["reason"] == "missing permission X"

    def test_writes_document(self, tmp_path):
        recorder = ResultRecorder("test", results_dir=tmp_path)
        recorder.record_pass("a")
        path = recorder.write("out.json")
        assert path.is_file()

        import json

        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["run"] == "test"
        assert len(document["steps"]) == 1
