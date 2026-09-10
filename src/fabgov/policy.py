"""Azure Policy alias discovery and SKU-restriction policy generation.

The central rule of this module: **never assume an alias exists.**

An unverified alias can make policy deployment fail or make evaluation differ
from the operator's intent. Alias discovery is therefore a hard gate here:
``build_sku_policy_rule`` refuses to emit a policy for an unverified alias.
"""

from __future__ import annotations

import logging
import uuid

LOGGER = logging.getLogger("fabgov.policy")

FABRIC_NAMESPACE = "Microsoft.Fabric"
FABRIC_CAPACITY_RESOURCE_TYPE = "capacities"
FABRIC_CAPACITY_TYPE = "Microsoft.Fabric/capacities"

# The alias we expect to find. It is a starting hypothesis to be confirmed
# against the live provider, never a value to hard-code into a policy.
EXPECTED_SKU_ALIAS = "Microsoft.Fabric/capacities/sku.name"

POLICY_DEFINITION_NAME = "fabric-allowed-capacity-skus"
POLICY_DISPLAY_NAME = "Allowed Microsoft Fabric capacity SKUs"
VALID_EFFECTS = ("Audit", "Deny", "Disabled")
NEGATIVE_TEST_PREFIX = "fabgovdeny"


class AliasNotFoundError(RuntimeError):
    """Raised when the Fabric SKU policy alias cannot be verified.

    Deliberately fatal for the policy POC. See docs/SKU_POLICY.md.
    """


def build_negative_test_identity(run_id: str = "") -> tuple:
    """Return a unique capacity name and ownership tags for a Deny test.

    A fixed name could collide with an existing resource and turn a safe create
    attempt into an update. The random identity also lets cleanup prove that a
    resource belongs to this exact validation run before deleting it.
    """
    validation_id = str(run_id or uuid.uuid4().hex).lower().replace("-", "")
    if not validation_id or any(ch not in "0123456789abcdef" for ch in validation_id):
        raise ValueError("run_id must contain hexadecimal characters only.")
    return (
        NEGATIVE_TEST_PREFIX + validation_id[:12],
        {
            "purpose": "fabric-capacity-governance-poc",
            "managed-by": "poc-policy-negative-test",
            "validation-id": validation_id,
        },
    )


def extract_capacity_aliases(provider_body) -> list:
    """Pull the alias list for ``Microsoft.Fabric/capacities`` from a provider document.

    Accepts the raw body of ``GET /providers/Microsoft.Fabric?$expand=resourceTypes/aliases``.
    Returns a list of ``{"name": ..., "defaultPath": ..., "paths": [...]}`` dicts.
    """
    if not isinstance(provider_body, dict):
        return []
    aliases = []
    for resource_type in provider_body.get("resourceTypes") or []:
        if not isinstance(resource_type, dict):
            continue
        if resource_type.get("resourceType") != FABRIC_CAPACITY_RESOURCE_TYPE:
            continue
        for alias in resource_type.get("aliases") or []:
            if not isinstance(alias, dict) or not alias.get("name"):
                continue
            paths = []
            for path in alias.get("paths") or []:
                if isinstance(path, dict) and path.get("path"):
                    paths.append(path["path"])
            aliases.append(
                {
                    "name": alias["name"],
                    "defaultPath": alias.get("defaultPath") or "",
                    "paths": paths,
                }
            )
    return aliases


def find_sku_alias(aliases, expected: str = EXPECTED_SKU_ALIAS):
    """Locate the alias that maps to the capacity's ``sku.name`` property.

    Prefers an exact match on the expected name, then falls back to any alias
    whose default path resolves to ``sku.name``. Returns ``None`` when nothing
    matches - the caller decides whether that is fatal.
    """
    by_name = {}
    for alias in aliases or []:
        name = alias.get("name") if isinstance(alias, dict) else str(alias)
        if name:
            by_name[name] = alias if isinstance(alias, dict) else {"name": name}

    if expected in by_name:
        return by_name[expected]

    for name, alias in by_name.items():
        default_path = str(alias.get("defaultPath") or "")
        if default_path == "sku.name" or name.endswith("/sku.name"):
            LOGGER.warning("Expected alias %s not found; using discovered alias %s instead.", expected, name)
            return alias
    return None


def verify_sku_alias(aliases, expected: str = EXPECTED_SKU_ALIAS) -> dict:
    """Return the verified SKU alias or raise ``AliasNotFoundError``.

    The error message tells the operator exactly what to record in
    POC_FINDINGS.md, because a missing alias is a legitimate, reportable
    outcome of this POC rather than a bug to work around.
    """
    alias = find_sku_alias(aliases, expected)
    if alias is None:
        discovered = sorted(a.get("name", "") if isinstance(a, dict) else str(a) for a in (aliases or []))
        raise AliasNotFoundError(
            "No Azure Policy alias for Fabric capacity SKU could be verified.\n"
            "Expected: {0}\n"
            "Aliases actually exposed by the provider: {1}\n\n"
            "SKU restriction by Azure Policy cannot be implemented without this alias. "
            "Do not fabricate one: an invalid alias can make deployment fail or produce "
            "unintended evaluation. Record this as NOT VERIFIED in "
            "docs/POC_FINDINGS.md.".format(expected, ", ".join(d for d in discovered if d) or "(none)")
        )
    return alias


def build_sku_policy_rule(alias_name: str) -> dict:
    """Build the policy rule that flags capacities whose SKU is not allowed.

    The rule matches a Fabric capacity whose ``sku.name`` is NOT in the allowed
    list, then applies the parameterized effect.
    """
    if not alias_name or not str(alias_name).strip():
        raise AliasNotFoundError(
            "Refusing to build a SKU policy without a verified alias. "
            "Run scripts/discover_policy_aliases.py first."
        )
    return {
        "if": {
            "allOf": [
                {"field": "type", "equals": FABRIC_CAPACITY_TYPE},
                {"not": {"field": alias_name, "in": "[parameters('allowedSkus')]"}},
            ]
        },
        "then": {"effect": "[parameters('effect')]"},
    }


def build_policy_definition(
    alias_name: str,
    *,
    allowed_skus=None,
    default_effect: str = "Audit",
    display_name: str = POLICY_DISPLAY_NAME,
) -> dict:
    """Build a complete custom policy definition for Fabric SKU restriction.

    ``allowedSkus`` and ``effect`` are both parameters, so one definition
    serves every environment: a customer changes the permitted SKU list at
    assignment time without editing or redeploying the definition.
    """
    if default_effect not in VALID_EFFECTS:
        raise ValueError("Policy effect must be one of {0}, got {1!r}.".format(VALID_EFFECTS, default_effect))
    skus = list(allowed_skus or ["F2", "F4", "F8"])

    return {
        "properties": {
            "displayName": display_name,
            "policyType": "Custom",
            "mode": "All",
            "description": (
                "Restricts which Microsoft Fabric capacity F-SKUs may be created or updated. "
                "Capacities whose SKU is not in the allowed list are audited or denied "
                "according to the effect parameter."
            ),
            "metadata": {
                "version": "1.0.0",
                "category": "Fabric",
                # Recorded so a reviewer can tell which alias the policy depends on
                # and re-verify it against their own subscription.
                "verifiedAlias": alias_name,
            },
            "parameters": {
                "allowedSkus": {
                    "type": "Array",
                    "metadata": {
                        "displayName": "Allowed Fabric SKUs",
                        "description": (
                            "The list of Fabric capacity SKU names that are permitted, "
                            "for example F2, F4, F8."
                        ),
                    },
                    "defaultValue": skus,
                },
                "effect": {
                    "type": "String",
                    "metadata": {
                        "displayName": "Effect",
                        "description": (
                            "Audit logs non-compliant capacities. Deny blocks their creation "
                            "or update. Disabled turns the policy off."
                        ),
                    },
                    "allowedValues": list(VALID_EFFECTS),
                    "defaultValue": default_effect,
                },
            },
            "policyRule": build_sku_policy_rule(alias_name),
        }
    }


def build_policy_assignment(
    *,
    policy_definition_id: str,
    display_name: str,
    allowed_skus,
    effect: str,
    description: str = "",
) -> dict:
    """Build a policy assignment body binding the definition to a scope."""
    if effect not in VALID_EFFECTS:
        raise ValueError("Policy effect must be one of {0}, got {1!r}.".format(VALID_EFFECTS, effect))
    return {
        "properties": {
            "displayName": display_name,
            "policyDefinitionId": policy_definition_id,
            "description": description or "Fabric Capacity Governance POC - restrict Fabric capacity SKUs.",
            "parameters": {
                "allowedSkus": {"value": list(allowed_skus)},
                "effect": {"value": effect},
            },
        }
    }


def policy_definition_id(subscription_id: str, definition_name: str = POLICY_DEFINITION_NAME) -> str:
    """ARM id of a subscription-scoped custom policy definition."""
    if not subscription_id:
        raise ValueError("subscription_id is required to build a policy definition id.")
    return "/subscriptions/{0}/providers/Microsoft.Authorization/policyDefinitions/{1}".format(
        subscription_id, definition_name
    )


def definitions_equivalent(existing, desired) -> bool:
    """Whether an existing policy definition already matches what we want.

    Used for idempotency: an unchanged definition is left alone rather than
    rewritten, so re-running deploy.py does not churn resource history.
    """
    if not isinstance(existing, dict) or not isinstance(desired, dict):
        return False
    existing_props = existing.get("properties") or {}
    desired_props = desired.get("properties") or {}
    if existing_props.get("policyRule") != desired_props.get("policyRule"):
        return False
    if existing_props.get("displayName") != desired_props.get("displayName"):
        return False
    existing_params = existing_props.get("parameters") or {}
    desired_params = desired_props.get("parameters") or {}
    return sorted(existing_params.keys()) == sorted(desired_params.keys())
