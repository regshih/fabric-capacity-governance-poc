"""A small Azure Resource Manager REST client.

Why a hand-rolled client rather than an SDK management package: this POC is a
teaching artifact. The ARM calls it makes - suspend, resume, and the long
running operation (LRO) polling that follows them - are the subject matter, so
they are written out plainly instead of hidden behind a generated client.

Authentication is delegated entirely to ``DefaultAzureCredential``. No token is
ever written to disk, logged, or included in a result file.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

LOGGER = logging.getLogger("fabgov.arm")

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"

# HTTP statuses worth retrying: throttling plus transient server-side faults.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Statuses that mean "stop and tell the human something specific".
TERMINAL_CLIENT_STATUS = frozenset({400, 401, 403, 404, 409})

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BACKOFF_SECONDS = 2.0
DEFAULT_LRO_TIMEOUT_SECONDS = 900
DEFAULT_LRO_POLL_SECONDS = 10


class ArmError(RuntimeError):
    """An ARM request failed in a way the caller should not retry.

    Carries the parsed Azure error code so callers (and tests) can branch on
    e.g. ``RequestDisallowedByPolicy`` without string-matching a whole message.
    """

    def __init__(self, message: str, *, status_code=None, error_code=None, body=None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.body = body


class ArmTimeoutError(ArmError):
    """A long running operation did not reach a terminal state in time."""


def parse_error_code(body) -> str:
    """Pull the Azure error code out of an ARM error payload.

    ARM is inconsistent about nesting: sometimes ``{"error": {"code": ...}}``,
    sometimes a bare ``{"code": ...}``, and policy denials nest details a level
    deeper again. Returns an empty string when no code can be found.
    """
    if not isinstance(body, dict):
        return ""
    error = body.get("error") if isinstance(body.get("error"), dict) else body
    if not isinstance(error, dict):
        return ""
    code = error.get("code")
    if isinstance(code, str) and code:
        return code
    details = error.get("details")
    if isinstance(details, list):
        for detail in details:
            if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                return detail["code"]
    return ""


def parse_error_message(body) -> str:
    """Pull a human-readable message out of an ARM error payload."""
    if not isinstance(body, dict):
        return ""
    error = body.get("error") if isinstance(body.get("error"), dict) else body
    if not isinstance(error, dict):
        return ""
    message = error.get("message")
    if isinstance(message, str) and message:
        return message
    details = error.get("details")
    if isinstance(details, list):
        for detail in details:
            if isinstance(detail, dict) and isinstance(detail.get("message"), str):
                return detail["message"]
    return ""


def retry_after_seconds(headers, default: float) -> float:
    """Honour a ``Retry-After`` header when Azure sends one.

    Azure sends integer seconds for ARM throttling. Anything unparseable falls
    back to the caller's default rather than raising - a bad header should not
    fail an otherwise healthy retry.
    """
    if not headers:
        return default
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return default
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if value < 0:
        return default
    # Guard against an absurd server value stalling the POC for hours.
    return min(value, 300.0)


@dataclass
class ArmResponse:
    """A minimal, test-friendly view of an ARM HTTP response."""

    status_code: int
    headers: dict
    body: dict

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_accepted(self) -> bool:
        """202 Accepted - an LRO has started and must be polled."""
        return self.status_code == 202


def describe_status(status_code: int, error_code: str = "", message: str = "") -> str:
    """Turn an HTTP status into an actionable sentence.

    Generic HTTP errors are useless to an operator running a governance POC;
    each of these maps to a specific thing they can go fix.
    """
    hints = {
        400: "Bad request. The request body or API version was rejected by Azure.",
        401: ("Not authenticated. Your token was missing, expired, or invalid. Run `az login` and retry."),
        403: (
            "Authorized identity lacks permission for this operation, or the request was "
            "blocked by Azure Policy. Check the error code: RequestDisallowedByPolicy means "
            "a policy denied it; AuthorizationFailed means the RBAC role is insufficient."
        ),
        404: (
            "Resource not found. Verify the subscription, resource group, and capacity name, "
            "and that Microsoft.Fabric is registered on the subscription."
        ),
        409: (
            "Conflict. The capacity is usually mid-operation (another suspend/resume/scale is "
            "in flight). Wait for the current operation to finish and retry."
        ),
        429: "Throttled by Azure Resource Manager. Retrying after the Retry-After interval.",
    }
    parts = ["HTTP {0}".format(status_code)]
    if error_code:
        parts.append("({0})".format(error_code))
    hint = hints.get(status_code)
    if hint:
        parts.append("- " + hint)
    if message:
        parts.append("Azure said: " + message)
    return " ".join(parts)


class ArmClient:
    """Thin ARM REST wrapper with retry and LRO support.

    ``token_provider`` is any zero-argument callable returning a bearer token
    string. Production callers pass a ``DefaultAzureCredential``-backed
    provider; tests pass a stub, which keeps the whole class unit-testable with
    no Azure contact.
    """

    def __init__(
        self,
        token_provider,
        *,
        session=None,
        endpoint: str = ARM_ENDPOINT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep=time.sleep,
    ):
        self._token_provider = token_provider
        self._session = session or requests.Session()
        self._endpoint = endpoint.rstrip("/")
        self._max_attempts = max(1, int(max_attempts))
        self._backoff_seconds = float(backoff_seconds)
        self._sleep = sleep

    # ---- low level -------------------------------------------------------

    def _headers(self) -> dict:
        return {
            "Authorization": "Bearer {0}".format(self._token_provider()),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _absolute(self, url: str) -> str:
        """Return an HTTPS URL on the configured ARM origin.

        Azure supplies LRO polling URLs in response headers. Sending the ARM
        bearer token to an arbitrary absolute URL would create a credential
        exfiltration path, so absolute URLs must stay on the configured ARM
        host. Redirects are disabled separately for the same reason.
        """
        candidate = (
            url
            if str(url).lower().startswith(("http://", "https://"))
            else (self._endpoint + "/" + str(url).lstrip("/"))
        )
        expected = urlsplit(self._endpoint)
        parsed = urlsplit(candidate)
        try:
            port_matches = (parsed.port or 443) == (expected.port or 443)
        except ValueError:
            port_matches = False
        if (
            parsed.scheme.lower() != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() != (expected.hostname or "").lower()
            or not port_matches
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ArmError("Refusing to send an ARM credential to an untrusted URL.")
        return candidate

    def request(self, method: str, url: str, *, params=None, body=None) -> ArmResponse:
        """Issue one ARM request, retrying transient failures with backoff.

        Retries 429 and 5xx (honouring Retry-After). Everything else either
        succeeds or raises ``ArmError`` with a diagnosable message.
        """
        target = self._absolute(url)
        last_error = None

        for attempt in range(1, self._max_attempts + 1):
            try:
                response = self._session.request(
                    method,
                    target,
                    headers=self._headers(),
                    params=params,
                    data=json.dumps(body) if body is not None else None,
                    timeout=60,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                # Network-level failure: worth retrying, but never silently.
                last_error = exc
                if attempt >= self._max_attempts:
                    raise ArmError(
                        "Network failure calling ARM after {0} attempts: {1}".format(self._max_attempts, exc)
                    ) from exc
                delay = self._backoff_seconds * (2 ** (attempt - 1))
                LOGGER.warning(
                    "ARM %s %s network error (attempt %d/%d), retrying in %.1fs: %s",
                    method,
                    _redact_url(target),
                    attempt,
                    self._max_attempts,
                    delay,
                    exc,
                )
                self._sleep(delay)
                continue

            parsed = _parse_body(response)
            headers = dict(response.headers or {})

            if response.status_code in RETRYABLE_STATUS and attempt < self._max_attempts:
                delay = retry_after_seconds(headers, self._backoff_seconds * (2 ** (attempt - 1)))
                LOGGER.warning(
                    "ARM %s %s returned %d (attempt %d/%d), retrying in %.1fs",
                    method,
                    _redact_url(target),
                    response.status_code,
                    attempt,
                    self._max_attempts,
                    delay,
                )
                self._sleep(delay)
                continue

            if 200 <= response.status_code < 300:
                return ArmResponse(response.status_code, headers, parsed)

            error_code = parse_error_code(parsed)
            message = parse_error_message(parsed)
            raise ArmError(
                describe_status(response.status_code, error_code, message),
                status_code=response.status_code,
                error_code=error_code,
                body=parsed,
            )

        raise ArmError(
            "ARM {0} failed after {1} attempts: {2}".format(method, self._max_attempts, last_error)
        )

    def get(self, url: str, *, params=None) -> ArmResponse:
        return self.request("GET", url, params=params)

    def post(self, url: str, *, params=None, body=None) -> ArmResponse:
        return self.request("POST", url, params=params, body=body)

    def put(self, url: str, *, params=None, body=None) -> ArmResponse:
        return self.request("PUT", url, params=params, body=body)

    def delete(self, url: str, *, params=None) -> ArmResponse:
        return self.request("DELETE", url, params=params)

    def put_text(self, url: str, text: str, *, params=None, content_type: str = "text/plain") -> ArmResponse:
        """PUT a non-JSON body.

        Needed for Azure Automation runbook draft content, which is uploaded as
        raw PowerShell rather than a JSON document.
        """
        target = self._absolute(url)
        headers = self._headers()
        headers["Content-Type"] = content_type

        for attempt in range(1, self._max_attempts + 1):
            response = self._session.put(
                target,
                headers=headers,
                params=params,
                data=text.encode("utf-8"),
                timeout=120,
                allow_redirects=False,
            )
            if response.status_code in RETRYABLE_STATUS and attempt < self._max_attempts:
                delay = retry_after_seconds(
                    dict(response.headers or {}), self._backoff_seconds * (2 ** (attempt - 1))
                )
                LOGGER.warning(
                    "ARM PUT %s returned %d (attempt %d/%d), retrying in %.1fs",
                    _redact_url(target),
                    response.status_code,
                    attempt,
                    self._max_attempts,
                    delay,
                )
                self._sleep(delay)
                continue

            parsed = _parse_body(response)
            if 200 <= response.status_code < 300:
                return ArmResponse(response.status_code, dict(response.headers or {}), parsed)

            error_code = parse_error_code(parsed)
            raise ArmError(
                describe_status(response.status_code, error_code, parse_error_message(parsed)),
                status_code=response.status_code,
                error_code=error_code,
                body=parsed,
            )

        raise ArmError("ARM PUT failed after {0} attempts.".format(self._max_attempts))

    # ---- long running operations ----------------------------------------

    def wait_for_lro(
        self,
        response: ArmResponse,
        *,
        timeout_seconds: int = DEFAULT_LRO_TIMEOUT_SECONDS,
        poll_seconds: int = DEFAULT_LRO_POLL_SECONDS,
    ) -> ArmResponse:
        """Follow an Azure long running operation to a terminal state.

        Suspend and resume return 202 Accepted with an ``Azure-AsyncOperation``
        (preferred) or ``Location`` header. We poll that URL until Azure reports
        Succeeded, Failed, or Canceled - or until the timeout expires, which
        raises rather than reporting a false success.
        """
        poll_url = _lro_poll_url(response.headers)
        # Fabric create/update can return 201 with LRO headers. Follow any
        # server-provided poll URL rather than keying exclusively on 202.
        if not response.is_accepted and not poll_url:
            return response

        if not poll_url:
            # 202 with no pollable header: nothing to follow, so report the
            # accepted response rather than inventing a completion.
            LOGGER.warning("Received 202 with no Azure-AsyncOperation or Location header.")
            return response

        deadline = time.monotonic() + timeout_seconds
        interval = retry_after_seconds(response.headers, poll_seconds)

        while True:
            if time.monotonic() >= deadline:
                raise ArmTimeoutError(
                    "Long running operation did not complete within {0}s. "
                    "It may still be running in Azure - check the capacity state in the "
                    "portal before retrying.".format(timeout_seconds)
                )

            self._sleep(interval)
            polled = self.get(poll_url)
            status = _lro_status(polled)

            if status is None:
                # A Location-header LRO that has finished returns the final
                # resource body with a 200 and no status field.
                if polled.status_code == 200:
                    return polled
                interval = retry_after_seconds(polled.headers, poll_seconds)
                continue

            normalized = status.lower()
            if normalized == "succeeded":
                return polled
            if normalized in ("failed", "canceled", "cancelled"):
                error_code = parse_error_code(polled.body)
                message = parse_error_message(polled.body)
                raise ArmError(
                    "Long running operation finished with status {0}. {1}".format(
                        status, message or "No error message was returned."
                    ),
                    status_code=polled.status_code,
                    error_code=error_code,
                    body=polled.body,
                )

            interval = retry_after_seconds(polled.headers, poll_seconds)


def _lro_poll_url(headers) -> str:
    """Pick the LRO polling URL, preferring Azure-AsyncOperation."""
    if not headers:
        return ""
    lowered = {str(k).lower(): v for k, v in headers.items()}
    return lowered.get("azure-asyncoperation") or lowered.get("location") or ""


def _lro_status(response: ArmResponse):
    """Extract the LRO status from a poll response, if present."""
    body = response.body if isinstance(response.body, dict) else {}
    status = body.get("status")
    if isinstance(status, str) and status:
        return status
    properties = body.get("properties")
    if isinstance(properties, dict):
        provisioning = properties.get("provisioningState")
        if isinstance(provisioning, str) and provisioning:
            return provisioning
    return None


def _parse_body(response) -> dict:
    """Parse a JSON response body, tolerating empty or non-JSON payloads."""
    text = getattr(response, "text", "") or ""
    if not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {"raw": text}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _redact_url(url: str) -> str:
    """Strip query strings from URLs before logging.

    ARM URLs carry subscription ids in the path, which we keep for local
    debugging, but query strings can carry continuation tokens. Result files
    are sanitized separately by ``fabgov.sanitize``.
    """
    return url.split("?", 1)[0]


def default_token_provider(credential=None):
    """Return a callable that yields ARM bearer tokens from Azure Identity.

    The credential is created lazily so that importing this module never
    triggers an authentication attempt - which matters for unit tests and for
    ``--help`` output on a machine that has never run ``az login``.
    """
    holder = {"credential": credential}

    def provider() -> str:
        if holder["credential"] is None:
            from azure.identity import DefaultAzureCredential

            holder["credential"] = DefaultAzureCredential()
        return holder["credential"].get_token(ARM_SCOPE).token

    return provider
