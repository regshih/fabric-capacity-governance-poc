"""Redaction of environment-specific identifiers from POC output.

This repository is intended to be published publicly. Runtime results
necessarily contain subscription ids, tenant ids, object ids, resource group
names, and capacity names, so ``results/`` is gitignored outright. This module
provides the second line of defence: turning a real result document into one
that is safe to paste into a document, an issue, or docs/sample-output/.

The redaction is deliberately conservative. It is easier to explain an
over-redacted sample than to un-publish a leaked tenant id.
"""

from __future__ import annotations

import json
import re

# A GUID in any of the forms Azure emits.
GUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Bearer tokens and JWTs. Should never reach a result file, but if a future
# change ever logs one, this catches it before publication.
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}")
BASIC_AUTH_PATTERN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{12,}")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL,
)
CONNECTION_SECRET_PATTERN = re.compile(
    r"(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd)="
    r"([^;\s\"']+)"
)
SAS_QUERY_PATTERN = re.compile(r"(?i)([?&](?:sig|se|sp|sv|sr|skoid|sktid)=)([^&\s\"']+)")
SERVICE_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"vssps_[A-Za-z0-9]{20,})\b"
)

# Structural pieces of an ARM resource id, replaced segment by segment so the
# shape of the id survives redaction and stays readable.
SUBSCRIPTION_SEGMENT = re.compile(r"(?i)/subscriptions/[^/\s\"]+")
RESOURCE_GROUP_SEGMENT = re.compile(r"(?i)/resourceGroups/[^/\s\"]+")
CAPACITY_SEGMENT = re.compile(r"(?i)/capacities/[^/\s\"]+")

PLACEHOLDER_SUBSCRIPTION = "<SUBSCRIPTION_ID>"
PLACEHOLDER_TENANT = "<TENANT_ID>"
PLACEHOLDER_GUID = "<GUID>"
PLACEHOLDER_EMAIL = "<PRINCIPAL_UPN>"
PLACEHOLDER_RESOURCE_GROUP = "<RESOURCE_GROUP>"
PLACEHOLDER_CAPACITY = "<CAPACITY_NAME>"
PLACEHOLDER_TOKEN = "<REDACTED_TOKEN>"

# Keys whose values are always replaced wholesale, regardless of content.
SENSITIVE_KEY_HINTS = (
    "subscriptionid",
    "tenantid",
    "objectid",
    "principalid",
    "clientid",
    "token",
    "secret",
    "password",
    "connectionstring",
    "resourcegroup",
    "capacityname",
    "key",
)

# Keys that merely *contain* a hint word but are safe and useful to keep.
SENSITIVE_KEY_ALLOWLIST = (
    "keycolumns",
    "allowedskus",
    "keyvaultname",
)


def _placeholder_for_key(key: str) -> str:
    lowered = key.lower()
    if "subscription" in lowered:
        return PLACEHOLDER_SUBSCRIPTION
    if "tenant" in lowered:
        return PLACEHOLDER_TENANT
    if "resourcegroup" in lowered.replace("_", "").replace("-", ""):
        return PLACEHOLDER_RESOURCE_GROUP
    if "capacityname" in lowered.replace("_", "").replace("-", ""):
        return PLACEHOLDER_CAPACITY
    if "token" in lowered or "secret" in lowered or "password" in lowered:
        return PLACEHOLDER_TOKEN
    if "principal" in lowered or "object" in lowered or "client" in lowered:
        return "<OBJECT_ID>"
    return PLACEHOLDER_GUID


def is_sensitive_key(key: str) -> bool:
    """Whether a dict key's value should be redacted wholesale."""
    lowered = str(key).lower().replace("_", "").replace("-", "")
    if lowered in SENSITIVE_KEY_ALLOWLIST:
        return False
    return any(hint in lowered for hint in SENSITIVE_KEY_HINTS)


def sanitize_text(text: str) -> str:
    """Redact identifiers from a free-text string.

    Order matters: tokens first (longest, most dangerous), then structured ARM
    segments, then bare GUIDs and emails that survived.
    """
    if not isinstance(text, str) or not text:
        return text

    result = JWT_PATTERN.sub(PLACEHOLDER_TOKEN, text)
    result = BEARER_PATTERN.sub("Bearer " + PLACEHOLDER_TOKEN, result)
    result = BASIC_AUTH_PATTERN.sub("Basic " + PLACEHOLDER_TOKEN, result)
    result = PRIVATE_KEY_PATTERN.sub(PLACEHOLDER_TOKEN, result)
    result = SERVICE_TOKEN_PATTERN.sub(PLACEHOLDER_TOKEN, result)
    result = CONNECTION_SECRET_PATTERN.sub(lambda m: m.group(1) + "=" + PLACEHOLDER_TOKEN, result)
    result = SAS_QUERY_PATTERN.sub(lambda m: m.group(1) + PLACEHOLDER_TOKEN, result)

    result = SUBSCRIPTION_SEGMENT.sub("/subscriptions/" + PLACEHOLDER_SUBSCRIPTION, result)
    result = RESOURCE_GROUP_SEGMENT.sub("/resourceGroups/" + PLACEHOLDER_RESOURCE_GROUP, result)
    result = CAPACITY_SEGMENT.sub("/capacities/" + PLACEHOLDER_CAPACITY, result)

    result = GUID_PATTERN.sub(PLACEHOLDER_GUID, result)
    result = EMAIL_PATTERN.sub(PLACEHOLDER_EMAIL, result)
    return result


def sanitize_value(value, *, key: str = ""):
    """Recursively redact a JSON-like structure."""
    if key and is_sensitive_key(key) and value not in (None, "", [], {}):
        return _placeholder_for_key(key)
    if isinstance(value, dict):
        return {k: sanitize_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item, key=key) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def sanitize_document(document, *, extra_terms=None) -> dict:
    """Sanitize a full result document.

    ``extra_terms`` lets a caller redact environment-specific names that no
    pattern could infer - a resource group or capacity name appearing as a bare
    word rather than inside a resource id. Terms are replaced longest-first so
    that a name which is a substring of another does not corrupt it.
    """
    sanitized = sanitize_value(document)

    terms = sorted(
        {str(t).strip(): None for t in (extra_terms or []) if t and len(str(t).strip()) >= 3},
        key=len,
        reverse=True,
    )
    if not terms:
        return sanitized

    serialized = json.dumps(sanitized)
    for term in terms:
        replacement = _placeholder_for_term(term)
        serialized = re.sub(re.escape(term), replacement, serialized, flags=re.IGNORECASE)
    return json.loads(serialized)


def _placeholder_for_term(term: str) -> str:
    """Choose a readable placeholder for a literal environment term."""
    lowered = term.lower()
    if lowered.startswith("rg-") or "resourcegroup" in lowered:
        return PLACEHOLDER_RESOURCE_GROUP
    return PLACEHOLDER_CAPACITY


def find_sensitive_strings(text: str) -> list:
    """Report identifiers found in text, for the pre-publication scanner.

    Returns a list of ``{"kind": ..., "match": ...}``. Matches are truncated so
    that the scanner's own output never becomes a leak.
    """
    findings = []
    if not isinstance(text, str):
        return findings

    checks = (
        ("jwt", JWT_PATTERN),
        ("bearer-token", BEARER_PATTERN),
        ("basic-auth", BASIC_AUTH_PATTERN),
        ("private-key", PRIVATE_KEY_PATTERN),
        ("connection-secret", CONNECTION_SECRET_PATTERN),
        ("sas-query", SAS_QUERY_PATTERN),
        ("service-token", SERVICE_TOKEN_PATTERN),
        ("guid", GUID_PATTERN),
        ("email", EMAIL_PATTERN),
    )
    for kind, pattern in checks:
        if pattern.search(text):
            findings.append({"kind": kind, "match": "<redacted>"})
    return findings


def _truncate(value: str, keep: int = 8) -> str:
    """Return no part of a sensitive value."""
    return "<redacted:{0}-chars>".format(len(value))
