"""Local proof of which Azure resources this POC created.

Tags are useful for discovery but are not sufficient authorization to mutate
or delete a resource: another deployment can use the same public tag values.
The ignored deployment manifest records exact resource IDs and a random run
identifier. A resource is owned only when both the manifest and live tags
agree.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from .capacity import POC_PURPOSE_TAG

MANIFEST_VERSION = 1
DEPLOYMENT_TAG = "poc-deployment-id"
MANIFEST_NAME = "deployment-manifest.json"


def default_manifest_path() -> Path:
    return Path(__file__).resolve().parents[2] / "results" / MANIFEST_NAME


def normalize_resource_id(value: str) -> str:
    return str(value or "").strip().rstrip("/").lower()


class DeploymentManifest:
    def __init__(self, path=None, *, deployment_id="", resources=None):
        self.path = Path(path or default_manifest_path())
        self.deployment_id = deployment_id or str(uuid.uuid4())
        self.resources = dict(resources or {})

    @classmethod
    def load(cls, path=None):
        target = Path(path or default_manifest_path())
        if not target.is_file():
            return None
        body = json.loads(target.read_text(encoding="utf-8"))
        if body.get("version") != MANIFEST_VERSION or not body.get("deploymentId"):
            raise ValueError("Deployment manifest is missing a supported version or deploymentId.")
        resources = {}
        for resource in body.get("resources", []):
            resource_id = normalize_resource_id(resource.get("id", ""))
            if resource_id:
                resources[resource_id] = {"id": resource.get("id", ""), "kind": resource.get("kind", "")}
        return cls(target, deployment_id=body["deploymentId"], resources=resources)

    @classmethod
    def load_or_create(cls, path=None, *, persist=True):
        existing = cls.load(path)
        if existing:
            return existing
        manifest = cls(path)
        if persist:
            manifest.save()
        return manifest

    @property
    def tags(self) -> dict:
        return {
            "purpose": POC_PURPOSE_TAG,
            "managed-by": "poc",
            DEPLOYMENT_TAG: self.deployment_id,
        }

    def record(self, resource_id: str, kind: str) -> None:
        normalized = normalize_resource_id(resource_id)
        if not normalized:
            raise ValueError("Cannot record an empty resource id.")
        self.resources[normalized] = {"id": str(resource_id), "kind": str(kind)}
        self.save()

    def contains(self, resource_id: str) -> bool:
        return normalize_resource_id(resource_id) in self.resources

    def resource_ids(self, *, kind: str = "", prefix: str = "") -> list:
        """Return recorded IDs filtered by exact kind and normalized prefix."""
        normalized_prefix = normalize_resource_id(prefix)
        matches = []
        for item in self.resources.values():
            resource_id = str(item.get("id", ""))
            if kind and item.get("kind") != kind:
                continue
            if normalized_prefix and not normalize_resource_id(resource_id).startswith(normalized_prefix):
                continue
            matches.append(resource_id)
        return sorted(matches, key=str.lower)

    def owns_tagged_resource(self, body) -> bool:
        if not isinstance(body, dict) or not self.contains(body.get("id", "")):
            return False
        tags = body.get("tags") or {}
        return (
            tags.get("purpose") == POC_PURPOSE_TAG
            and tags.get("managed-by") == "poc"
            and tags.get(DEPLOYMENT_TAG) == self.deployment_id
        )

    def document(self) -> dict:
        return {
            "version": MANIFEST_VERSION,
            "deploymentId": self.deployment_id,
            "resources": sorted(self.resources.values(), key=lambda item: item["id"].lower()),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.document(), indent=2), encoding="utf-8")
        temporary.replace(self.path)
