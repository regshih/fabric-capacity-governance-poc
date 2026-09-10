"""Configuration parsing, validation, and safety-flag behaviour."""

from __future__ import annotations

import pytest

from fabgov.config import (
    Config,
    ConfigError,
    build_capacity_resource_id,
    load_config,
    load_dotenv,
    parse_bool,
    parse_sku_list,
    parse_time_of_day,
    sku_capacity_units,
)


class TestParseBool:
    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "y", "on"])
    def test_truthy(self, value):
        assert parse_bool(value) is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "n", "off", "", None])
    def test_falsey(self, value):
        assert parse_bool(value) is False

    def test_passthrough_bool(self):
        assert parse_bool(True) is True
        assert parse_bool(False) is False

    @pytest.mark.parametrize("value", ["ture", "maybe", "enabled", "2"])
    def test_ambiguous_raises(self, value):
        """A typo must never be silently coerced - especially on a deletion flag."""
        with pytest.raises(ConfigError):
            parse_bool(value, name="ALLOW_POC_RESOURCE_DELETION")

    def test_error_names_the_setting(self):
        with pytest.raises(ConfigError, match="ALLOW_POC_RESOURCE_DELETION"):
            parse_bool("ture", name="ALLOW_POC_RESOURCE_DELETION")


class TestParseSkuList:
    def test_basic(self):
        assert parse_sku_list("F2,F4,F8") == ["F2", "F4", "F8"]

    def test_normalizes_case_and_whitespace(self):
        assert parse_sku_list(" f2 , F4,f8 ") == ["F2", "F4", "F8"]

    def test_deduplicates_preserving_order(self):
        assert parse_sku_list("F4,F2,F4") == ["F4", "F2"]

    def test_accepts_iterable(self):
        assert parse_sku_list(["F2", "f64"]) == ["F2", "F64"]

    @pytest.mark.parametrize("value", ["P1", "F", "Fabric", "2", "F2x"])
    def test_rejects_non_fabric_sku(self, value):
        with pytest.raises(ConfigError):
            parse_sku_list(value)

    def test_rejects_empty(self):
        with pytest.raises(ConfigError):
            parse_sku_list(",, ,")

    def test_rejects_none(self):
        with pytest.raises(ConfigError):
            parse_sku_list(None)


class TestSkuCapacityUnits:
    @pytest.mark.parametrize("sku,units", [("F2", 2), ("F8", 8), ("F64", 64), ("f128", 128)])
    def test_parses(self, sku, units):
        assert sku_capacity_units(sku) == units

    def test_rejects_invalid(self):
        with pytest.raises(ConfigError):
            sku_capacity_units("P1")


class TestParseTimeOfDay:
    @pytest.mark.parametrize(
        "value,expected",
        [("7:00", "07:00"), ("07:00", "07:00"), ("19:30", "19:30"), ("00:00", "00:00"), ("23:59", "23:59")],
    )
    def test_valid(self, value, expected):
        assert parse_time_of_day(value, name="RESUME_TIME") == expected

    @pytest.mark.parametrize("value", ["24:00", "07:60", "7", "0700", "abc", "", None, "-1:00"])
    def test_invalid(self, value):
        with pytest.raises(ConfigError):
            parse_time_of_day(value, name="RESUME_TIME")


class TestBuildCapacityResourceId:
    def test_shape(self):
        result = build_capacity_resource_id("sub-1", "rg-1", "cap1")
        assert result == (
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Fabric/capacities/cap1"
        )

    def test_strips_whitespace(self):
        assert build_capacity_resource_id(" sub ", " rg ", " cap ").endswith("/capacities/cap")

    @pytest.mark.parametrize(
        "args", [("", "rg", "cap"), ("sub", "", "cap"), ("sub", "rg", ""), ("sub", "rg", "   ")]
    )
    def test_rejects_empty_segment(self, args):
        with pytest.raises(ConfigError):
            build_capacity_resource_id(*args)


class TestLoadDotenv:
    def test_parses_pairs_comments_and_quotes(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text(
            "\n".join(
                [
                    "# a comment",
                    "SIMPLE=value",
                    'QUOTED="quoted value"',
                    "SINGLE='single'",
                    "SPACED  =  spaced  ",
                    "",
                    "NOEQUALS",
                ]
            ),
            encoding="utf-8",
        )
        values = load_dotenv(env)
        assert values["SIMPLE"] == "value"
        assert values["QUOTED"] == "quoted value"
        assert values["SINGLE"] == "single"
        assert values["SPACED"] == "spaced"
        assert "NOEQUALS" not in values

    def test_missing_file_is_empty(self, tmp_path):
        assert load_dotenv(tmp_path / "nope.env") == {}

    def test_does_not_mutate_os_environ(self, tmp_path, monkeypatch):
        env = tmp_path / ".env"
        env.write_text("FABGOV_TEST_SENTINEL=leaked", encoding="utf-8")
        load_dotenv(env)
        import os

        assert "FABGOV_TEST_SENTINEL" not in os.environ


def _base_overrides(**extra):
    values = {
        "AZURE_SUBSCRIPTION_ID": "sub-1",
        "RESOURCE_GROUP_NAME": "rg-poc",
        "LOCATION": "westus3",
        "FABRIC_CAPACITY_NAME": "cap1",
    }
    values.update(extra)
    return values


class TestLoadConfigDefaults:
    def test_safety_flags_default_to_safe(self, tmp_path):
        config = load_config(tmp_path / "none.env", _base_overrides(), use_process_env=False)
        assert config.allow_capacity_creation is False
        assert config.allow_existing_capacity_state_change is False
        assert config.allow_poc_resource_deletion is False
        assert config.allow_existing_automation_modification is False
        assert config.enable_schedules is False

    def test_existing_automation_change_requires_explicit_true(self, tmp_path):
        config = load_config(
            tmp_path / "none.env",
            _base_overrides(ALLOW_EXISTING_AUTOMATION_MODIFICATION="true"),
            use_process_env=False,
        )
        assert config.allow_existing_automation_modification is True

    def test_defaults(self, tmp_path):
        config = load_config(tmp_path / "none.env", _base_overrides(), use_process_env=False)
        assert config.capacity_mode == "existing"
        assert config.fabric_sku == "F2"
        assert config.policy_effect == "Audit"
        assert config.allowed_fabric_skus == ["F2", "F4", "F8"]
        assert config.resume_time == "07:00"
        assert config.pause_time == "19:00"

    def test_policy_effect_never_defaults_to_deny(self, tmp_path):
        config = load_config(tmp_path / "none.env", _base_overrides(), use_process_env=False)
        assert config.policy_effect != "Deny"

    def test_overrides_beat_dotenv(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text(
            "\n".join(("CAPACITY_MODE=existing", "FABRIC_SKU=F2", "")),
            encoding="utf-8",
        )
        config = load_config(env, _base_overrides(FABRIC_SKU="F4"), use_process_env=False)
        assert config.fabric_sku == "F4"


class TestLoadConfigValidation:
    def test_rejects_bad_capacity_mode(self, tmp_path):
        with pytest.raises(ConfigError, match="CAPACITY_MODE"):
            load_config(tmp_path / "n.env", _base_overrides(CAPACITY_MODE="destroy"), use_process_env=False)

    def test_rejects_bad_policy_effect(self, tmp_path):
        with pytest.raises(ConfigError, match="POLICY_EFFECT"):
            load_config(tmp_path / "n.env", _base_overrides(POLICY_EFFECT="Delete"), use_process_env=False)

    def test_accepts_lowercase_policy_effect(self, tmp_path):
        config = load_config(tmp_path / "n.env", _base_overrides(POLICY_EFFECT="deny"), use_process_env=False)
        assert config.policy_effect == "Deny"

    def test_schedules_require_time_zone(self, tmp_path):
        with pytest.raises(ConfigError, match="AUTOMATION_TIME_ZONE"):
            load_config(
                tmp_path / "n.env",
                _base_overrides(ENABLE_SCHEDULES="true"),
                use_process_env=False,
            )

    def test_schedules_ok_with_time_zone(self, tmp_path):
        config = load_config(
            tmp_path / "n.env",
            _base_overrides(ENABLE_SCHEDULES="true", AUTOMATION_TIME_ZONE="UTC"),
            use_process_env=False,
        )
        assert config.enable_schedules is True
        assert config.automation_time_zone == "UTC"

    def test_create_mode_requires_admin(self, tmp_path):
        with pytest.raises(ConfigError, match="FABRIC_CAPACITY_ADMIN"):
            load_config(
                tmp_path / "n.env",
                _base_overrides(CAPACITY_MODE="create", ALLOW_CAPACITY_CREATION="true"),
                use_process_env=False,
            )

    def test_create_mode_refuses_large_sku(self, tmp_path):
        """The POC must never create anything bigger than F2 on its own."""
        with pytest.raises(ConfigError, match="Refusing to create"):
            load_config(
                tmp_path / "n.env",
                _base_overrides(
                    CAPACITY_MODE="create",
                    ALLOW_CAPACITY_CREATION="true",
                    FABRIC_CAPACITY_ADMIN="admin@example.com",
                    FABRIC_SKU="F64",
                ),
                use_process_env=False,
            )

    def test_create_mode_unauthorized_skips_validation(self, tmp_path):
        """Without the creation flag, create-mode config loads without demanding admin."""
        config = load_config(
            tmp_path / "n.env",
            _base_overrides(CAPACITY_MODE="create"),
            use_process_env=False,
        )
        assert config.creates_capacity is False


class TestConfigDerived:
    def _config(self, **extra):
        base = dict(
            subscription_id="sub-1",
            tenant_id="",
            resource_group="rg-poc",
            location="westus3",
            capacity_mode="existing",
            capacity_name="cap1",
            capacity_admin="",
            fabric_sku="F2",
            allow_capacity_creation=False,
            allow_existing_capacity_state_change=False,
            allow_poc_resource_deletion=False,
            allow_existing_automation_modification=False,
            enable_automation=True,
            enable_rbac_poc=True,
            enable_policy_poc=True,
            automation_account_name="aa",
            automation_time_zone="UTC",
            resume_time="07:00",
            pause_time="19:00",
            enable_schedules=False,
            allowed_fabric_skus=["F2"],
            policy_effect="Audit",
            test_principal_object_id="",
        )
        base.update(extra)
        return Config(**base)

    def test_scopes(self):
        config = self._config()
        assert config.subscription_scope == "/subscriptions/sub-1"
        assert config.resource_group_scope == "/subscriptions/sub-1/resourceGroups/rg-poc"
        assert config.capacity_resource_id.endswith("/Microsoft.Fabric/capacities/cap1")

    def test_poc_created_capacity_is_always_changeable(self):
        """We own what we created, regardless of the existing-capacity flag."""
        config = self._config(allow_existing_capacity_state_change=False)
        assert config.may_change_state_of(poc_created=True) is True

    def test_existing_capacity_blocked_by_default(self):
        config = self._config(allow_existing_capacity_state_change=False)
        assert config.may_change_state_of(poc_created=False) is False

    def test_existing_capacity_allowed_when_authorized(self):
        config = self._config(allow_existing_capacity_state_change=True)
        assert config.may_change_state_of(poc_created=False) is True

    def test_creates_capacity_requires_both_mode_and_flag(self):
        assert self._config(capacity_mode="create", allow_capacity_creation=False).creates_capacity is False
        assert self._config(capacity_mode="existing", allow_capacity_creation=True).creates_capacity is False
        assert self._config(capacity_mode="create", allow_capacity_creation=True).creates_capacity is True


class TestPrincipalType:
    """A mismatched principalType produces an opaque Azure 400, so validate early."""

    def test_defaults_to_user(self, tmp_path):
        config = load_config(tmp_path / "n.env", _base_overrides(), use_process_env=False)
        assert config.test_principal_type == "User"

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("ServicePrincipal", "ServicePrincipal"),
            ("serviceprincipal", "ServicePrincipal"),
            ("SERVICEPRINCIPAL", "ServicePrincipal"),
            ("Group", "Group"),
            ("group", "Group"),
            ("user", "User"),
        ],
    )
    def test_normalizes_case(self, tmp_path, value, expected):
        config = load_config(
            tmp_path / "n.env",
            _base_overrides(TEST_PRINCIPAL_TYPE=value),
            use_process_env=False,
        )
        assert config.test_principal_type == expected

    def test_blank_falls_back_to_user(self, tmp_path):
        config = load_config(
            tmp_path / "n.env", _base_overrides(TEST_PRINCIPAL_TYPE=""), use_process_env=False
        )
        assert config.test_principal_type == "User"

    @pytest.mark.parametrize("value", ["ManagedIdentity", "SPN", "Application", "Admin"])
    def test_rejects_invalid(self, tmp_path, value):
        with pytest.raises(ConfigError, match="TEST_PRINCIPAL_TYPE"):
            load_config(
                tmp_path / "n.env",
                _base_overrides(TEST_PRINCIPAL_TYPE=value),
                use_process_env=False,
            )
