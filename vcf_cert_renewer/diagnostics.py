"""Safe, structured diagnostics for renewal failures.

Diagnostic payloads intentionally contain an allow-listed route template and
typed error summaries. Raw URLs, headers, response bodies and exception text
are never copied into these events.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import requests


ACME_PROBLEM_CATEGORIES = {
    "unauthorized": "ACME_AUTHORIZATION_FAILURE",
    "accountdoesnotexist": "ACME_ACCOUNT_ERROR",
    "ratelimited": "ACME_RATE_LIMIT",
    "badcsr": "CSR_VALIDATION_ERROR",
    "dns": "ACME_PROBLEM",
    "connection": "ACME_PROBLEM",
    "tls": "ACME_PROBLEM",
    "rejectedidentifier": "ACME_PROBLEM",
    "ordernotready": "ACME_PROBLEM",
}
_LEGO_LOCAL_CATEGORIES = frozenset({
    "DNS_PROVIDER_CONFIGURATION", "DNS_UPDATE_FAILURE", "DNS_PROPAGATION_FAILURE",
    "ACME_ACCOUNT_ERROR", "CSR_VALIDATION_ERROR", "NETWORK_TLS_ERROR", "UNKNOWN_ACME_ERROR",
})
LEGO_OPERATIONS = frozenset({"NEW_ORDER", "AUTHORIZATION", "CHALLENGE", "FINALIZE", "ACCOUNT"})


LEGO_STAGES = frozenset({
    "ACCOUNT", "AUTHORIZATION_VALIDATION", "CHALLENGE_VALIDATION",
    "CHALLENGE_ACCEPTANCE", "DNS_PRESENTATION", "DNS_PROPAGATION",
})


class LegoSigningError(ValueError):
    """Carry only validated diagnostic fields, never subprocess output."""

    def __init__(self, exit_status: int, category: str, problem: str | None = None,
                 operation: str | None = None, *, http_context: str | None = None,
                 problem_status: int | None = None, stage: str | None = None) -> None:
        if problem is not None and ACME_PROBLEM_CATEGORIES.get(problem) != category:
            category, problem = "UNKNOWN_ACME_ERROR", None
        if problem is None and category not in _LEGO_LOCAL_CATEGORIES:
            category = "UNKNOWN_ACME_ERROR"
        operation = operation if problem and operation in LEGO_OPERATIONS else None
        self.http_context = (
            "RECOGNIZED_ROUTE" if operation else
            http_context if problem and http_context in {"NO_HTTP_CONTEXT", "UNRECOGNIZED_ROUTE"} else None
        )
        self.problem_status = (
            problem_status if self.http_context in {"RECOGNIZED_ROUTE", "UNRECOGNIZED_ROUTE"}
            and type(problem_status) is int and 400 <= problem_status <= 599 else None
        )
        self.stage = stage if stage in LEGO_STAGES else None
        self.exit_status = int(exit_status)
        self.category = category
        self.problem = problem
        self.operation = operation
        fields = [f"lego signing failed with exit status {self.exit_status}", f"category={category}"]
        if problem:
            fields.append(f"problem={problem}")
        if operation:
            fields.append(f"operation={operation}")
        if self.http_context:
            fields.append(f"httpContext={self.http_context}")
        if self.problem_status is not None:
            fields.append(f"problemStatus={self.problem_status}")
        if self.stage:
            fields.append(f"stage={self.stage}")
        super().__init__("; ".join(fields))

    def safe_fields(self) -> dict[str, Any]:
        fields = {"legoExit": self.exit_status, "category": self.category,
                  "problem": self.problem, "operation": self.operation,
                  "httpContext": self.http_context, "problemStatus": self.problem_status,
                  "stage": self.stage}
        return {key: value for key, value in fields.items() if value is not None}


_ROUTES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/v1/tokens$"), "/v1/tokens"),
    (re.compile(r"^/v1/domains$"), "/v1/domains"),
    (re.compile(r"^/v1/sddc-managers$"), "/v1/sddc-managers"),
    (re.compile(r"^/v1/vcenters$"), "/v1/vcenters"),
    (re.compile(r"^/v1/nsxt-clusters$"), "/v1/nsxt-clusters"),
    (re.compile(r"^/v1/domains/[^/]+/csrs$"), "/v1/domains/{domainId}/csrs"),
    (re.compile(r"^/v1/domains/[^/]+/resource-certificates$"),
     "/v1/domains/{domainId}/resource-certificates"),
    (re.compile(r"^/v1/domains/[^/]+/resource-certificates/validations$"),
     "/v1/domains/{domainId}/resource-certificates/validations"),
    (re.compile(r"^/v1/domains/[^/]+/resource-certificates/validations/[^/]+$"),
     "/v1/domains/{domainId}/resource-certificates/validations/{validationId}"),
    (re.compile(r"^/v1/tasks/[^/]+$"), "/v1/tasks/{taskId}"),
    (re.compile(r"^/api/v1/node/version$"), "/api/v1/node/version"),
    (re.compile(r"^/api/v1/cluster/nodes$"), "/api/v1/cluster/nodes"),
    (re.compile(r"^/api/v1/trust-management/certificate-profiles$"),
     "/api/v1/trust-management/certificate-profiles"),
    (re.compile(r"^/api/v1/trust-management/certificates$"),
     "/api/v1/trust-management/certificates"),
    (re.compile(r"^/api/v1/trust-management/csrs$"),
     "/api/v1/trust-management/csrs"),
    (re.compile(r"^/api/v1/trust-management/csrs/[^/]+$"),
     "/api/v1/trust-management/csrs/{csrId}"),
    (re.compile(r"^/api/v1/trust-management/certificates/[^/]+$"),
     "/api/v1/trust-management/certificates/{certificateId}"),
)


def safe_api_path(path: str) -> str:
    """Return an allow-listed API route template with all query data removed."""
    try:
        path_only = urlsplit(path).path
    except (TypeError, ValueError):
        return "/<unclassified>"
    for pattern, template in _ROUTES:
        if pattern.fullmatch(path_only):
            return template
    return "/<unclassified>"


def safe_identifier(value: object) -> str | None:
    """Allow a short opaque request/task identifier, never arbitrary text."""
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        return None
    return value


def safe_exception_message(exc: BaseException) -> str:
    """Map exceptions to reviewed, non-secret summaries; never echo raw text."""
    if isinstance(exc, LegoSigningError):
        return f"{exc}; tool output suppressed."
    if isinstance(exc, requests.ReadTimeout):
        return "HTTP response was not received before the configured read timeout."
    if isinstance(exc, requests.ConnectTimeout):
        return "HTTP connection was not established before the configured timeout."
    if isinstance(exc, requests.Timeout):
        return "HTTP request timed out."
    if isinstance(exc, requests.HTTPError):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        return (f"HTTP response status {status}." if isinstance(status, int)
                else "HTTP request returned an error response.")
    if isinstance(exc, requests.ConnectionError):
        return "HTTP connection failed."

    # A small allow-list preserves useful, static application diagnostics.
    static_messages = {
        "Could not check lego DNS provider support.",
        "Installed lego does not support the configured DNS_PROVIDER.",
        "NSX MGMT_CLUSTER profile is unavailable or not cluster-scoped",
        "NSX API profile is unavailable or not node-scoped",
        "MGMT_CLUSTER and API unexpectedly share one certificate object",
        "native NSX MGMT_CLUSTER identity contains an IP SAN; public ACME is blocked",
        "MGMT_CLUSTER DNS SANs do not contain the VIP FQDN",
        "NSX CSR import did not return one certificate with a private key",
        "NSX imported certificate lacks id",
        "NSX CSR response lacks id or PEM",
        "SDDC Manager authentication response did not contain accessToken",
        "SDDC Manager response did not contain elements",
        "task response was not an object",
        "CSR task response was not an object",
        "validation response did not contain validationId",
        "replacement task response was not an object",
        "CSR response did not contain a task id",
    }
    message = str(exc)
    if message in static_messages:
        return message
    categorized = re.fullmatch(
        r"lego signing failed with exit status (-?[0-9]{1,3}); category="
        r"(DNS_PROVIDER_CONFIGURATION|DNS_UPDATE_FAILURE|DNS_PROPAGATION_FAILURE|"
        r"ACME_ACCOUNT_ERROR|ACME_RATE_LIMIT|CSR_VALIDATION_ERROR|NETWORK_TLS_ERROR|"
        r"ACME_AUTHORIZATION_FAILURE|UNKNOWN_ACME_ERROR)",
        message,
    )
    if categorized:
        return (f"ACME signer exited with status {categorized.group(1)} "
                f"({categorized.group(2)}); tool output suppressed.")
    match = re.match(r"^lego signing failed with exit status ([0-9]{1,3})\b", message)
    if match:
        return f"ACME signer exited with status {match.group(1)}; tool output suppressed."
    if isinstance(exc, ValueError):
        return "Invalid value or response; message suppressed by diagnostic policy."
    if isinstance(exc, requests.RequestException):
        return "HTTP request failed; details suppressed by diagnostic policy."
    return "Exception details suppressed by diagnostic policy."


def outcome_for(method: str | None, exc: BaseException,
                *, response_received: bool = False) -> str:
    """Classify evidence without claiming a backend result we did not observe."""
    if response_received:
        return "HTTP_RESPONSE_RECEIVED"
    if method and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        if isinstance(exc, requests.ConnectTimeout):
            return "REQUEST_NOT_SENT"
        return "UNKNOWN_SERVER_OUTCOME"
    return "READ_REQUEST_FAILED"


def make_diagnostic(*, component: str, target: str | None, phase: str,
                    operation: str, exc: BaseException,
                    http_method: str | None = None, api_path: str | None = None,
                    timeout_seconds: float | None = None,
                    elapsed_seconds: float | None = None,
                    response_status: int | None = None,
                    task_id: str | None = None,
                    correlation_id: str | None = None,
                    response_received: bool = False) -> dict[str, Any]:
    event: dict[str, Any] = {
        "component": component,
        "phase": phase,
        "operation": operation,
        "errorType": type(exc).__name__,
        "safeMessage": safe_exception_message(exc),
        "outcome": outcome_for(http_method, exc,
                               response_received=response_received),
    }
    if isinstance(exc, LegoSigningError):
        event["acme"] = exc.safe_fields()
    if target:
        event["targetFqdn"] = target
    if http_method:
        event["httpMethod"] = http_method.upper()
    if api_path:
        event["apiPath"] = safe_api_path(api_path)
    if timeout_seconds is not None:
        event["timeoutSeconds"] = timeout_seconds
    if elapsed_seconds is not None:
        event["elapsedSeconds"] = round(max(0.0, elapsed_seconds), 3)
    if response_status is not None:
        event["httpStatus"] = response_status
    if task_id and safe_identifier(task_id):
        event["taskId"] = task_id
    if correlation_id and safe_identifier(correlation_id):
        event["correlationId"] = correlation_id
    return event


def attach_diagnostic(exc: BaseException, event: dict[str, Any]) -> None:
    """Attach structured context to an exception without changing its type."""
    try:
        if isinstance(exc, LegoSigningError):
            event = {**event, "acme": exc.safe_fields()}
        setattr(exc, "renewal_diagnostic", event)
    except (AttributeError, TypeError):
        pass


def diagnostic_for_exception(exc: BaseException, *, component: str,
                             target: str | None, phase: str,
                             operation: str = "RENEWAL_WORKFLOW") -> dict[str, Any]:
    existing = getattr(exc, "renewal_diagnostic", None)
    if isinstance(existing, dict):
        event = dict(existing)
        event.setdefault("component", component)
        event.setdefault("phase", phase)
        event.setdefault("operation", operation)
        if target:
            event.setdefault("targetFqdn", target)
        return event
    return make_diagnostic(component=component, target=target, phase=phase,
                           operation=operation, exc=exc)
