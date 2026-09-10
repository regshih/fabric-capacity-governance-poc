"""Configuration loading and safety-flag handling.

Configuration comes from a local ``.env`` file (gitignored) and/or process
environment variables. Nothing here ever writes configuration back to disk, and
no default in this module is destructive: every flag that could change or
destroy an Azure resource defaults to the safe value.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Values a user might plausibly type meaning "yes".
_TRUE_VALUES = {"true", "1", "yes", "y", "on"}
_FALSE_VALUES = {"false", "0", "no", "n", "off", ""}

# Fabric F-SKUs follow the pattern F<n>, where n is the capacity unit count.
# We validate the shape rather than hard-coding a list, because Microsoft adds
# SKUs over time; scripts/preflight.py checks the live list from Azure.
_SKU_PATTERN = re.compile(r"^F(\d+)$")

VALID_CAPACITY_MODES = ("existing", "create")
VALID_POLICY_EFFECTS = ("Audit", "Deny", "Disabled")

# Azure role-assignment principal types. A managed identity or app registration
# is a ServicePrincipal; only a human account is a User.
VALID_PRINCIPAL_TYPES = ("User", "Group", "ServicePrincipal")

# Azure Resource Manager API version for Microsoft.Fabric/capacities.
# This is the current STABLE (non-preview) version. Preview versions are
# deliberately not used - see docs/PAUSE_RESUME.md.
FABRIC_API_VERSION = "2023-11-01"

# The largest SKU this POC will ever create on its own.
MAX_SELF_CREATED_SKU_UNITS = 2


class ConfigError(ValueError):
    """Raised when configuration is missing or internally inconsistent."""


def parse_bool(value, *, name: str = "value") -> bool:
    """Parse a permissive boolean, rejecting anything ambiguous.

    We refuse to guess. A typo like ``ALLOW_POC_RESOURCE_DELETION=ture`` must
    raise rather than silently evaluate falsey (which would be safe) or truthy
    (which would not) - either way the operator deserves to be told.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ConfigError("{0}: cannot interpret {1!r} as a boolean. Use true/false.".format(name, value))


def parse_sku_list(value, *, name: str = "ALLOWED_FABRIC_SKUS") -> list:
    """Parse a comma-separated F-SKU list into a normalized, de-duplicated list.

    Normalizes case (``f2`` becomes ``F2``) and preserves the caller's ordering
    so generated policy parameters read the way the operator wrote them.
    """
    if value is None:
        raise ConfigError("{0} is required and was not set.".format(name))
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, Iterable):
        parts = [str(p).strip() for p in value]
    else:
        raise ConfigError("{0}: expected a string or iterable of SKUs.".format(name))

    skus: list = []
    for part in parts:
        if not part:
            continue
        normalized = part.upper()
        if not _SKU_PATTERN.match(normalized):
            raise ConfigError(
                "{0}: {1!r} is not a valid Fabric F-SKU. Expected the form F2, F4, F8, F16, ...".format(
                    name, part
                )
            )
        if normalized not in skus:
            skus.append(normalized)

    if not skus:
        raise ConfigError("{0} resolved to an empty list; at least one SKU is required.".format(name))
    return skus


def sku_capacity_units(sku: str) -> int:
    """Return the numeric capacity-unit count for an F-SKU (``F8`` gives ``8``)."""
    match = _SKU_PATTERN.match(str(sku).upper())
    if not match:
        raise ConfigError("{0!r} is not a valid Fabric F-SKU.".format(sku))
    return int(match.group(1))


def parse_time_of_day(value, *, name: str) -> str:
    """Validate a 24-hour ``HH:MM`` string and return it zero-padded."""
    if not value or not str(value).strip():
        raise ConfigError("{0} is required (24-hour HH:MM).".format(name))
    text = str(value).strip()
    match = re.match(r"^(\d{1,2}):(\d{2})$", text)
    if not match:
        raise ConfigError("{0}: expected 24-hour HH:MM, got {1!r}.".format(name, value))
    hour, minute = int(match.group(1)), int(match.group(2))
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ConfigError("{0}: {1!r} is not a valid time of day.".format(name, value))
    return "{0:02d}:{1:02d}".format(hour, minute)


def load_dotenv(path="_env_default") -> dict:
    """Read a ``.env`` file into a dict without mutating ``os.environ``.

    Deliberately minimal: ``KEY=value`` lines, ``#`` comments, optional
    surrounding quotes. A missing file returns an empty dict - the POC is
    expected to also run from real environment variables.
    """
    if path == "_env_default":
        path = ".env"
    file_path = Path(path)
    if not file_path.is_file():
        return {}

    values: dict = {}
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key:
            values[key] = val
    return values


@dataclass(frozen=True)
class Config:
    """Fully resolved, validated POC configuration."""

    subscription_id: str
    tenant_id: str
    resource_group: str
    location: str

    capacity_mode: str
    capacity_name: str
    capacity_admin: str
    fabric_sku: str

    allow_capacity_creation: bool
    allow_existing_capacity_state_change: bool
    allow_poc_resource_deletion: bool
    allow_existing_automation_modification: bool

    enable_automation: bool
    enable_rbac_poc: bool
    enable_policy_poc: bool

    automation_account_name: str
    automation_time_zone: str
    resume_time: str
    pause_time: str
    enable_schedules: bool

    allowed_fabric_skus: list = field(default_factory=list)
    policy_effect: str = "Audit"

    test_principal_object_id: str = ""
    test_principal_type: str = "User"

    # ---- derived helpers -------------------------------------------------

    @property
    def capacity_resource_id(self) -> str:
        """ARM resource id of the target capacity."""
        return build_capacity_resource_id(self.subscription_id, self.resource_group, self.capacity_name)

    @property
    def resource_group_scope(self) -> str:
        return "/subscriptions/{0}/resourceGroups/{1}".format(self.subscription_id, self.resource_group)

    @property
    def subscription_scope(self) -> str:
        return "/subscriptions/{0}".format(self.subscription_id)

    @property
    def creates_capacity(self) -> bool:
        """True when this run is authorized to create a new POC capacity."""
        return self.capacity_mode == "create" and self.allow_capacity_creation

    def may_change_state_of(self, *, poc_created: bool) -> bool:
        """Whether we are authorized to pause/resume the target capacity.

        A capacity this POC created is ours to drive. One that already existed
        requires explicit opt-in, because pausing a live capacity interrupts
        every workload running on it.
        """
        if poc_created:
            return True
        return self.allow_existing_capacity_state_change


def build_capacity_resource_id(subscription_id: str, resource_group: str, capacity_name: str) -> str:
    """Construct the ARM resource id for a Fabric capacity.

    Kept as a free function so it is unit-testable without a full Config.
    """
    fields = (
        ("subscription id", subscription_id),
        ("resource group", resource_group),
        ("capacity name", capacity_name),
    )
    for label, value in fields:
        if value is None or not str(value).strip():
            raise ConfigError("Cannot build capacity resource id: {0} is empty.".format(label))
    return "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Fabric/capacities/{2}".format(
        str(subscription_id).strip(), str(resource_group).strip(), str(capacity_name).strip()
    )


KNOWN_KEYS = {
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_TENANT_ID",
    "RESOURCE_GROUP_NAME",
    "LOCATION",
    "CAPACITY_MODE",
    "FABRIC_CAPACITY_NAME",
    "FABRIC_CAPACITY_ADMIN",
    "FABRIC_SKU",
    "ALLOW_CAPACITY_CREATION",
    "ALLOW_EXISTING_CAPACITY_STATE_CHANGE",
    "ALLOW_POC_RESOURCE_DELETION",
    "ALLOW_EXISTING_AUTOMATION_MODIFICATION",
    "ENABLE_AUTOMATION",
    "ENABLE_RBAC_POC",
    "ENABLE_POLICY_POC",
    "AUTOMATION_ACCOUNT_NAME",
    "AUTOMATION_TIME_ZONE",
    "RESUME_TIME",
    "PAUSE_TIME",
    "ENABLE_SCHEDULES",
    "ALLOWED_FABRIC_SKUS",
    "POLICY_EFFECT",
    "TEST_PRINCIPAL_OBJECT_ID",
    "TEST_PRINCIPAL_TYPE",
}


def _match_principal_type(value):
    """Resolve a principal type case-insensitively, or return None if invalid."""
    candidate = str(value or "").strip()
    if not candidate:
        return "User"
    for valid in VALID_PRINCIPAL_TYPES:
        if candidate.lower() == valid.lower():
            return valid
    return None


def load_config(env_file="_env_default", overrides=None, *, use_process_env: bool = True) -> Config:
    """Load configuration from ``.env``, process environment, and overrides.

    Precedence (lowest to highest): ``.env`` file, process environment,
    explicit ``overrides``. Validation is strict - we would rather stop with a
    clear message than deploy something the operator did not intend.
    """
    if env_file == "_env_default":
        env_file = ".env"

    values: dict = {}
    values.update(load_dotenv(env_file))
    if use_process_env:
        values.update({k: v for k, v in os.environ.items() if k in KNOWN_KEYS})
    if overrides:
        values.update(overrides)

    def get(key: str, default: str = "") -> str:
        raw = values.get(key, default)
        if raw is None:
            return ""
        text = str(raw).strip()
        return text if text else str(default).strip()

    capacity_mode = get("CAPACITY_MODE", "existing").lower()
    if capacity_mode not in VALID_CAPACITY_MODES:
        raise ConfigError(
            "CAPACITY_MODE must be one of {0}, got {1!r}.".format(VALID_CAPACITY_MODES, capacity_mode)
        )

    policy_effect_raw = get("POLICY_EFFECT", "Audit")
    policy_effect = policy_effect_raw.capitalize()
    if policy_effect not in VALID_POLICY_EFFECTS:
        raise ConfigError(
            "POLICY_EFFECT must be one of {0}, got {1!r}.".format(VALID_POLICY_EFFECTS, policy_effect_raw)
        )

    fabric_sku = get("FABRIC_SKU", "F2").upper()
    if not _SKU_PATTERN.match(fabric_sku):
        raise ConfigError("FABRIC_SKU {0!r} is not a valid F-SKU.".format(fabric_sku))

    enable_schedules = parse_bool(get("ENABLE_SCHEDULES"), name="ENABLE_SCHEDULES")
    time_zone = get("AUTOMATION_TIME_ZONE")
    if enable_schedules and not time_zone:
        raise ConfigError(
            "ENABLE_SCHEDULES=true requires AUTOMATION_TIME_ZONE to be set explicitly. "
            "There is no safe default time zone - see docs/PAUSE_RESUME.md."
        )

    # Azure rejects a role assignment whose declared principalType does not match
    # the principal. A managed identity or app registration is a ServicePrincipal,
    # not a User, and the resulting 400 (UnmatchedPrincipalType) is opaque.
    principal_type_raw = get("TEST_PRINCIPAL_TYPE", "User")
    principal_type = _match_principal_type(principal_type_raw)
    if principal_type is None:
        raise ConfigError(
            "TEST_PRINCIPAL_TYPE must be one of {0}, got {1!r}.".format(
                VALID_PRINCIPAL_TYPES, principal_type_raw
            )
        )

    config = Config(
        subscription_id=get("AZURE_SUBSCRIPTION_ID"),
        tenant_id=get("AZURE_TENANT_ID"),
        resource_group=get("RESOURCE_GROUP_NAME"),
        location=get("LOCATION"),
        capacity_mode=capacity_mode,
        capacity_name=get("FABRIC_CAPACITY_NAME"),
        capacity_admin=get("FABRIC_CAPACITY_ADMIN"),
        fabric_sku=fabric_sku,
        allow_capacity_creation=parse_bool(get("ALLOW_CAPACITY_CREATION"), name="ALLOW_CAPACITY_CREATION"),
        allow_existing_capacity_state_change=parse_bool(
            get("ALLOW_EXISTING_CAPACITY_STATE_CHANGE"),
            name="ALLOW_EXISTING_CAPACITY_STATE_CHANGE",
        ),
        allow_poc_resource_deletion=parse_bool(
            get("ALLOW_POC_RESOURCE_DELETION"), name="ALLOW_POC_RESOURCE_DELETION"
        ),
        allow_existing_automation_modification=parse_bool(
            get("ALLOW_EXISTING_AUTOMATION_MODIFICATION"),
            name="ALLOW_EXISTING_AUTOMATION_MODIFICATION",
        ),
        enable_automation=parse_bool(get("ENABLE_AUTOMATION", "true"), name="ENABLE_AUTOMATION"),
        enable_rbac_poc=parse_bool(get("ENABLE_RBAC_POC", "true"), name="ENABLE_RBAC_POC"),
        enable_policy_poc=parse_bool(get("ENABLE_POLICY_POC", "true"), name="ENABLE_POLICY_POC"),
        automation_account_name=get("AUTOMATION_ACCOUNT_NAME"),
        automation_time_zone=time_zone,
        resume_time=parse_time_of_day(get("RESUME_TIME", "07:00"), name="RESUME_TIME"),
        pause_time=parse_time_of_day(get("PAUSE_TIME", "19:00"), name="PAUSE_TIME"),
        enable_schedules=enable_schedules,
        allowed_fabric_skus=parse_sku_list(get("ALLOWED_FABRIC_SKUS", "F2,F4,F8")),
        policy_effect=policy_effect,
        test_principal_object_id=get("TEST_PRINCIPAL_OBJECT_ID"),
        test_principal_type=principal_type,
    )

    _validate_cross_field(config)
    return config


def _validate_cross_field(config: Config) -> None:
    """Checks that only make sense once every field is known."""
    if config.capacity_mode == "create" and config.allow_capacity_creation:
        if not config.location:
            raise ConfigError("CAPACITY_MODE=create requires LOCATION.")
        if not config.capacity_admin:
            raise ConfigError(
                "CAPACITY_MODE=create requires FABRIC_CAPACITY_ADMIN "
                "(a UPN or object id that will administer the new capacity)."
            )
        if sku_capacity_units(config.fabric_sku) > MAX_SELF_CREATED_SKU_UNITS:
            raise ConfigError(
                "Refusing to create a {0} capacity. This POC creates F2 only; larger SKUs "
                "bill significantly more.".format(config.fabric_sku)
            )
