"""Policy alias handling, policy generation, and RBAC role construction."""

from __future__ import annotations

import pytest

from fabgov.policy import (
    EXPECTED_SKU_ALIAS,
    AliasNotFoundError,
    build_negative_test_identity,
    build_policy_assignment,
    build_policy_definition,
    build_sku_policy_rule,
    definitions_equivalent,
    extract_capacity_aliases,
    find_sku_alias,
    policy_definition_id,
    verify_sku_alias,
)
from fabgov.rbac import (
    LRO_POLLING_ACTIONS,
    PAUSE_RESUME_ACTIONS,
    ROLE_NAME,
    build_role_assignment,
    build_role_definition,
    role_actions,
    scope_behavior_matrix,
)

PROVIDER_BODY = {
    "namespace": "Microsoft.Fabric",
    "resourceTypes": [
        {
            "resourceType": "capacities",
            "aliases": [
                {"name": "Microsoft.Fabric/capacities/sku.name", "defaultPath": "sku.name"},
                {"name": "Microsoft.Fabric/capacities/sku.tier", "defaultPath": "sku.tier"},
                {"name": "Microsoft.Fabric/capacities/state", "defaultPath": "properties.state"},
            ],
        },
        {"resourceType": "operations", "aliases": []},
    ],
}


class TestExtractAliases:
    def test_extracts_capacity_aliases_only(self):
        aliases = extract_capacity_aliases(PROVIDER_BODY)
        assert len(aliases) == 3
        assert {a["name"] for a in aliases} == {
            "Microsoft.Fabric/capacities/sku.name",
            "Microsoft.Fabric/capacities/sku.tier",
            "Microsoft.Fabric/capacities/state",
        }

    def test_handles_missing_resource_types(self):
        assert extract_capacity_aliases({}) == []
        assert extract_capacity_aliases(None) == []
        assert extract_capacity_aliases("nope") == []

    def test_handles_alias_paths(self):
        body = {
            "resourceTypes": [
                {
                    "resourceType": "capacities",
                    "aliases": [
                        {
                            "name": "Microsoft.Fabric/capacities/sku.name",
                            "defaultPath": "sku.name",
                            "paths": [{"path": "sku.name", "apiVersions": ["2023-11-01"]}],
                        }
                    ],
                }
            ]
        }
        assert extract_capacity_aliases(body)[0]["paths"] == ["sku.name"]

    def test_skips_malformed_aliases(self):
        body = {"resourceTypes": [{"resourceType": "capacities", "aliases": [{}, "junk", None]}]}
        assert extract_capacity_aliases(body) == []


class TestFindSkuAlias:
    def test_finds_exact_match(self):
        alias = find_sku_alias(extract_capacity_aliases(PROVIDER_BODY))
        assert alias["name"] == EXPECTED_SKU_ALIAS

    def test_falls_back_to_default_path(self):
        aliases = [{"name": "Microsoft.Fabric/capacities/skuName", "defaultPath": "sku.name"}]
        assert find_sku_alias(aliases)["name"] == "Microsoft.Fabric/capacities/skuName"

    def test_returns_none_when_absent(self):
        aliases = [{"name": "Microsoft.Fabric/capacities/state", "defaultPath": "properties.state"}]
        assert find_sku_alias(aliases) is None

    def test_empty_input(self):
        assert find_sku_alias([]) is None
        assert find_sku_alias(None) is None


class TestVerifySkuAlias:
    def test_returns_alias_when_present(self):
        assert verify_sku_alias(extract_capacity_aliases(PROVIDER_BODY))["name"] == EXPECTED_SKU_ALIAS

    def test_raises_when_absent(self):
        with pytest.raises(AliasNotFoundError):
            verify_sku_alias([{"name": "Microsoft.Fabric/capacities/state"}])

    def test_error_lists_what_was_actually_found(self):
        """The operator needs the real alias list to record an honest finding."""
        with pytest.raises(AliasNotFoundError, match="capacities/state"):
            verify_sku_alias([{"name": "Microsoft.Fabric/capacities/state"}])

    def test_error_warns_against_fabricating(self):
        with pytest.raises(AliasNotFoundError, match="NOT VERIFIED"):
            verify_sku_alias([])


class TestBuildSkuPolicyRule:
    def test_shape(self):
        rule = build_sku_policy_rule(EXPECTED_SKU_ALIAS)
        clauses = rule["if"]["allOf"]
        assert clauses[0] == {"field": "type", "equals": "Microsoft.Fabric/capacities"}
        assert clauses[1]["not"]["field"] == EXPECTED_SKU_ALIAS
        assert clauses[1]["not"]["in"] == "[parameters('allowedSkus')]"
        assert rule["then"]["effect"] == "[parameters('effect')]"

    @pytest.mark.parametrize("alias", ["", None, "   "])
    def test_refuses_empty_alias(self, alias):
        """Never emit a policy without a verified alias."""
        with pytest.raises(AliasNotFoundError):
            build_sku_policy_rule(alias)


class TestBuildPolicyDefinition:
    def test_parameterizes_allowed_skus(self):
        definition = build_policy_definition(EXPECTED_SKU_ALIAS, allowed_skus=["F2", "F4"])
        params = definition["properties"]["parameters"]
        assert params["allowedSkus"]["type"] == "Array"
        assert params["allowedSkus"]["defaultValue"] == ["F2", "F4"]

    def test_effect_defaults_to_audit(self):
        definition = build_policy_definition(EXPECTED_SKU_ALIAS)
        assert definition["properties"]["parameters"]["effect"]["defaultValue"] == "Audit"

    def test_effect_allows_audit_deny_disabled(self):
        definition = build_policy_definition(EXPECTED_SKU_ALIAS)
        allowed = definition["properties"]["parameters"]["effect"]["allowedValues"]
        assert allowed == ["Audit", "Deny", "Disabled"]

    def test_deny_is_possible_but_explicit(self):
        definition = build_policy_definition(EXPECTED_SKU_ALIAS, default_effect="Deny")
        assert definition["properties"]["parameters"]["effect"]["defaultValue"] == "Deny"

    def test_rejects_invalid_effect(self):
        with pytest.raises(ValueError):
            build_policy_definition(EXPECTED_SKU_ALIAS, default_effect="Destroy")

    def test_records_verified_alias_in_metadata(self):
        definition = build_policy_definition(EXPECTED_SKU_ALIAS)
        assert definition["properties"]["metadata"]["verifiedAlias"] == EXPECTED_SKU_ALIAS

    def test_policy_type_is_custom(self):
        assert build_policy_definition(EXPECTED_SKU_ALIAS)["properties"]["policyType"] == "Custom"


class TestPolicyAssignment:
    def test_carries_parameters(self):
        assignment = build_policy_assignment(
            policy_definition_id="/subscriptions/s/providers/Microsoft.Authorization/policyDefinitions/x",
            display_name="Test",
            allowed_skus=["F2"],
            effect="Audit",
        )
        params = assignment["properties"]["parameters"]
        assert params["allowedSkus"]["value"] == ["F2"]
        assert params["effect"]["value"] == "Audit"

    def test_rejects_invalid_effect(self):
        with pytest.raises(ValueError):
            build_policy_assignment(
                policy_definition_id="x", display_name="t", allowed_skus=["F2"], effect="Nope"
            )


class TestPolicyDefinitionId:
    def test_shape(self):
        assert policy_definition_id("sub-1", "my-policy") == (
            "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/my-policy"
        )

    def test_requires_subscription(self):
        with pytest.raises(ValueError):
            policy_definition_id("")


class TestDefinitionsEquivalent:
    def test_identical_definitions_match(self):
        a = build_policy_definition(EXPECTED_SKU_ALIAS)
        b = build_policy_definition(EXPECTED_SKU_ALIAS)
        assert definitions_equivalent(a, b) is True

    def test_different_alias_differs(self):
        a = build_policy_definition(EXPECTED_SKU_ALIAS)
        b = build_policy_definition("Microsoft.Fabric/capacities/sku.tier")
        assert definitions_equivalent(a, b) is False

    def test_non_dict_inputs(self):
        assert definitions_equivalent(None, {}) is False


class TestRoleActions:
    def test_includes_all_four_documented_actions(self):
        actions = role_actions()
        for action in PAUSE_RESUME_ACTIONS:
            assert action in actions

    def test_includes_write_action(self):
        """Microsoft documents write as required; the role must not silently omit it."""
        assert "Microsoft.Fabric/capacities/write" in role_actions()

    def test_excludes_provider_lro_polling_by_default(self):
        for action in LRO_POLLING_ACTIONS:
            assert action not in role_actions()

    def test_lro_polling_requires_explicit_broader_scope_design(self):
        actions = role_actions(include_lro_polling=True)
        for action in LRO_POLLING_ACTIONS:
            assert action in actions

    def test_excludes_delete(self):
        assert "Microsoft.Fabric/capacities/delete" not in role_actions()

    def test_excludes_role_assignment_write(self):
        assert "Microsoft.Authorization/roleAssignments/write" not in role_actions()


class TestBuildRoleDefinition:
    def test_shape(self):
        definition = build_role_definition(subscription_id="sub-1")
        props = definition["properties"]
        assert props["roleName"] == ROLE_NAME
        assert props["type"] == "CustomRole"
        assert props["assignableScopes"] == ["/subscriptions/sub-1"]

    def test_description_discloses_write_implication(self):
        """The role's own description must not overstate least privilege."""
        description = build_role_definition(subscription_id="sub-1")["properties"]["description"]
        assert "SKU" in description
        assert (
            "not restricted to pause/resume" in description.lower() or "not restricted" in description.lower()
        )

    def test_custom_assignable_scopes(self):
        definition = build_role_definition(
            subscription_id="sub-1", assignable_scopes=["/subscriptions/sub-1/resourceGroups/rg"]
        )
        assert definition["properties"]["assignableScopes"] == ["/subscriptions/sub-1/resourceGroups/rg"]

    def test_requires_subscription(self):
        with pytest.raises(ValueError):
            build_role_definition(subscription_id="")

    def test_no_data_actions(self):
        permissions = build_role_definition(subscription_id="s")["properties"]["permissions"][0]
        assert permissions["dataActions"] == []
        assert permissions["notActions"] == []


class TestRoleAssignment:
    def test_shape(self):
        body = build_role_assignment(
            role_definition_id_value="/subscriptions/s/.../roleDefinitions/guid",
            principal_object_id="object-id",
        )
        assert body["properties"]["principalId"] == "object-id"
        assert body["properties"]["principalType"] == "User"

    def test_requires_role_and_principal(self):
        with pytest.raises(ValueError):
            build_role_assignment(role_definition_id_value="", principal_object_id="x")
        with pytest.raises(ValueError):
            build_role_assignment(role_definition_id_value="x", principal_object_id="")


class TestScopeBehaviorMatrix:
    def test_covers_three_scopes(self):
        scopes = [row["scope"] for row in scope_behavior_matrix()]
        assert "Individual Fabric capacity" in scopes
        assert "Resource group" in scopes
        assert "Subscription" in scopes

    def test_capacity_scope_cannot_create_new_capacity(self):
        row = next(r for r in scope_behavior_matrix() if r["scope"] == "Individual Fabric capacity")
        assert row["canCreateNewCapacity"].startswith("No")

    def test_resource_group_scope_can_create(self):
        row = next(r for r in scope_behavior_matrix() if r["scope"] == "Resource group")
        assert row["canCreateNewCapacity"].startswith("Yes")


class TestNegativePolicyIdentity:
    def test_name_and_tags_derive_from_exact_run(self):
        name, tags = build_negative_test_identity("abcdef0123456789")
        assert name == "fabgovdenyabcdef012345"
        assert tags["managed-by"] == "poc-policy-negative-test"
        assert tags["validation-id"] == "abcdef0123456789"

    def test_random_runs_do_not_reuse_a_name(self):
        first, _ = build_negative_test_identity()
        second, _ = build_negative_test_identity()
        assert first != second

    @pytest.mark.parametrize("run_id", ["not-hex", "", "xyz"])
    def test_rejects_invalid_explicit_run_id(self, run_id):
        if run_id == "":
            assert build_negative_test_identity(run_id)[0].startswith("fabgovdeny")
        else:
            with pytest.raises(ValueError):
                build_negative_test_identity(run_id)
