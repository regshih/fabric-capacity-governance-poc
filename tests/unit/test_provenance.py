"""Deployment ownership requires both the ignored manifest and live tags."""

import json

from fabgov.provenance import DEPLOYMENT_TAG, DeploymentManifest


def _resource(manifest, resource_id="/subscriptions/s/resourceGroups/rg/providers/x/y"):
    return {"id": resource_id, "tags": manifest.tags}


def test_manifest_round_trip(tmp_path):
    path = tmp_path / "manifest.json"
    manifest = DeploymentManifest.load_or_create(path)
    manifest.record("/subscriptions/s/resourceGroups/rg/providers/x/y", "test")
    loaded = DeploymentManifest.load(path)
    assert loaded.deployment_id == manifest.deployment_id
    assert loaded.contains("/SUBSCRIPTIONS/S/resourceGroups/RG/providers/X/Y/")


def test_tags_without_manifest_record_are_not_owned(tmp_path):
    manifest = DeploymentManifest.load_or_create(tmp_path / "manifest.json")
    assert manifest.owns_tagged_resource(_resource(manifest)) is False


def test_manifest_record_without_matching_tag_is_not_owned(tmp_path):
    manifest = DeploymentManifest.load_or_create(tmp_path / "manifest.json")
    resource = _resource(manifest)
    manifest.record(resource["id"], "test")
    resource["tags"][DEPLOYMENT_TAG] = "different-run"
    assert manifest.owns_tagged_resource(resource) is False


def test_manifest_and_tags_together_prove_ownership(tmp_path):
    manifest = DeploymentManifest.load_or_create(tmp_path / "manifest.json")
    resource = _resource(manifest)
    manifest.record(resource["id"], "test")
    assert manifest.owns_tagged_resource(resource) is True


def test_manifest_contains_environment_ids_and_must_remain_ignored(tmp_path):
    path = tmp_path / "manifest.json"
    manifest = DeploymentManifest.load_or_create(path)
    manifest.record("/subscriptions/private/resourceGroups/private/providers/x/y", "test")
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["resources"][0]["id"].startswith("/subscriptions/private/")


def test_resource_ids_filter_by_kind_and_scope_prefix(tmp_path):
    manifest = DeploymentManifest.load_or_create(tmp_path / "manifest.json")
    expected = "/subscriptions/s/resourceGroups/rg/providers/cap/one/roleAssignments/a"
    manifest.record(expected, "role-assignment")
    manifest.record(
        "/subscriptions/s/resourceGroups/other/providers/cap/two/roleAssignments/b",
        "role-assignment",
    )
    manifest.record("/subscriptions/s/providers/roles/c", "custom-role-definition")
    assert manifest.resource_ids(
        kind="role-assignment",
        prefix="/SUBSCRIPTIONS/S/resourceGroups/RG/providers/cap/one/",
    ) == [expected]
