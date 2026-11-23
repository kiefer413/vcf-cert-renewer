"""Official VCF domain-managed certificate API client."""
from __future__ import annotations

import time
import re
from typing import Any
from urllib.parse import urlsplit

import requests

from .client import VcfRequestError, WorkflowFailedError, WorkflowTimeoutError
from .diagnostics import (attach_diagnostic, make_diagnostic, safe_api_path,
                          safe_identifier)

SUCCESS = {"SUCCESSFUL", "SUCCESS", "COMPLETED"}
FAILURE = {"FAILED", "CANCELLED", "CANCELED", "TIMED_OUT",
           "COMPLETED_WITH_WARNING", "SKIPPED"}


class SddcApiClient:
    def __init__(self, base_url: str, username: str, password: str, *, verify_tls: bool = True,
                 timeout_seconds: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self.username = username
        self._password = password
        self._access_token: str | None = None
        self._refresh_metadata: dict[str, Any] = {}
        self._target_fqdn: str | None = None
        self._component = "SDDC_MANAGER"
        self._last_request_context: dict[str, Any] | None = None
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json",
                                     "Content-Type": "application/json"})

    def _redact(self, text: str) -> str:
        for secret in (self._password, self._access_token):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    def set_target(self, fqdn: str, component: str) -> None:
        """Set non-secret context used in subsequent failure diagnostics."""
        self._target_fqdn = fqdn.rstrip(".").lower()
        self._component = component.upper()

    @staticmethod
    def _operation(method: str, path: str) -> str:
        route = urlsplit(path).path
        method = method.upper()
        if route == "/v1/tokens": return "AUTHENTICATE"
        if route == "/v1/domains": return "LIST_DOMAINS"
        if route == "/v1/sddc-managers": return "LIST_SDDC_MANAGERS"
        if route == "/v1/vcenters": return "LIST_VCENTERS"
        if route == "/v1/nsxt-clusters": return "LIST_NSXT_CLUSTERS"
        if re.fullmatch(r"/v1/domains/[^/]+/csrs", route):
            return "CREATE_CSR" if method == "PUT" else "FETCH_CSR"
        if re.fullmatch(r"/v1/tasks/[^/]+", route): return "POLL_TASK"
        if route.endswith("/resource-certificates/validations"):
            return "VALIDATE_CERTIFICATE"
        if "/resource-certificates/validations/" in route:
            return "POLL_CERTIFICATE_VALIDATION"
        if route.endswith("/resource-certificates"):
            return "REPLACE_CERTIFICATE"
        return "SDDC_API_REQUEST"

    @staticmethod
    def _identifier_from_path(path: str, prefix: str) -> str | None:
        route = urlsplit(path).path
        if route.startswith(prefix):
            return safe_identifier(route[len(prefix):].split("/", 1)[0])
        return None

    def _request_context(self, method: str, path: str, *, elapsed: float,
                         response: requests.Response | None = None,
                         response_received: bool = False) -> dict[str, Any]:
        status = getattr(response, "status_code", None) if response else None
        headers = getattr(response, "headers", {}) if response else {}
        correlation = None
        for header in ("X-Request-ID", "X-Correlation-ID", "X-VCF-Request-ID"):
            value = headers.get(header) if hasattr(headers, "get") else None
            correlation = safe_identifier(value)
            if correlation:
                break
        event: dict[str, Any] = {
            "component": self._component,
            "phase": "RENEW",
            "operation": self._operation(method, path),
            "targetFqdn": self._target_fqdn,
            "httpMethod": method.upper(),
            "apiPath": safe_api_path(path),
            "timeoutSeconds": self.timeout_seconds,
            "elapsedSeconds": round(max(0.0, elapsed), 3),
            "httpStatus": status,
            "responseReceived": response_received,
            "taskId": self._identifier_from_path(path, "/v1/tasks/"),
            "correlationId": correlation,
        }
        return {key: value for key, value in event.items() if value is not None}

    def _attach_request_failure(self, exc: BaseException, context: dict[str, Any]) -> None:
        event = dict(context)
        event["errorType"] = type(exc).__name__
        event["safeMessage"] = self._safe_message(exc)
        response_received = bool(event.pop("responseReceived", False))
        operation = event.get("operation")
        mutation_operations = {"CREATE_CSR", "VALIDATE_CERTIFICATE", "REPLACE_CERTIFICATE"}
        if not response_received and operation in mutation_operations:
            event["outcome"] = ("REQUEST_NOT_SENT" if isinstance(exc, requests.ConnectTimeout)
                                else "UNKNOWN_SERVER_OUTCOME")
        elif response_received:
            event["outcome"] = "HTTP_RESPONSE_RECEIVED"
        elif event.get("httpMethod") in {"GET", "HEAD"}:
            event["outcome"] = "READ_REQUEST_FAILED"
        else:
            event["outcome"] = "REQUEST_FAILED"
        attach_diagnostic(exc, event)

    @staticmethod
    def _safe_message(exc: BaseException) -> str:
        from .diagnostics import safe_exception_message
        return safe_exception_message(exc)

    def _remember_response_error(self, exc: BaseException) -> None:
        if self._last_request_context:
            self._attach_request_failure(exc, self._last_request_context)

    def _json(self, response: requests.Response) -> Any:
        try:
            return response.json()
        except Exception as exc:
            self._remember_response_error(exc)
            raise

    def _elements_from_response(self, response: requests.Response) -> list[dict[str, Any]]:
        try:
            return self._elements(self._json(response))
        except Exception as exc:
            self._remember_response_error(exc)
            raise

    def _authenticate(self) -> str:
        if self._access_token:
            return self._access_token
        started = time.monotonic()
        try:
            response = self.session.request(
                "POST", self.base_url + "/v1/tokens", timeout=self.timeout_seconds,
                verify=self.verify_tls,
                json={"username": self.username, "password": self._password})
        except requests.RequestException as exc:
            context = self._request_context("POST", "/v1/tokens",
                                            elapsed=time.monotonic() - started)
            self._attach_request_failure(exc, context)
            raise
        self._last_request_context = self._request_context(
            "POST", "/v1/tokens", elapsed=time.monotonic() - started,
            response=response, response_received=True)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            wrapped = VcfRequestError(
                f"SDDC Manager authentication returned HTTP {response.status_code}",
                response=response)
            self._attach_request_failure(wrapped, self._last_request_context)
            raise wrapped from exc
        try:
            payload = self._json(response)
        except Exception:
            raise
        token = payload.get("accessToken") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise ValueError("SDDC Manager authentication response did not contain accessToken")
        self._access_token = token
        self._refresh_metadata = {
            key: value for key, value in payload.items()
            if key not in {"accessToken", "refreshToken"}
        }
        return token

    def _request(self, method: str, path: str, *, _retried: bool = False,
                 **kwargs: Any) -> requests.Response:
        token = self._authenticate()
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {token}"
        started = time.monotonic()
        try:
            response = self.session.request(method, self.base_url + path,
                                            timeout=self.timeout_seconds,
                                            verify=self.verify_tls, headers=headers, **kwargs)
        except requests.RequestException as exc:
            context = self._request_context(method, path,
                                            elapsed=time.monotonic() - started)
            self._attach_request_failure(exc, context)
            raise
        self._last_request_context = self._request_context(
            method, path, elapsed=time.monotonic() - started,
            response=response, response_received=True)
        if response.status_code == 401 and method.upper() in {"GET", "HEAD"} and not _retried:
            self._access_token = None
            return self._request(method, path, _retried=True, **kwargs)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            wrapped = VcfRequestError(
                f"SDDC Manager API returned HTTP {response.status_code}",
                response=response)
            self._attach_request_failure(wrapped, self._last_request_context)
            raise wrapped from exc
        return response

    @staticmethod
    def _elements(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("elements"), list):
            return [x for x in payload["elements"] if isinstance(x, dict)]
        raise ValueError("SDDC Manager response did not contain elements")

    def resolve_context(self, fqdn: str,
                        resource_type: str = "SDDC_MANAGER") -> tuple[str, dict[str, Any]]:
        resource_type = resource_type.upper()
        self.set_target(fqdn, resource_type)
        endpoints = {"SDDC_MANAGER": "/v1/sddc-managers",
                     "VCENTER": "/v1/vcenters"}
        if resource_type not in {*endpoints, "NSXT_MANAGER"}:
            raise ValueError(f"unsupported domain-managed resource type: {resource_type}")
        domains = self._elements_from_response(self._request("GET", "/v1/domains"))
        management = [d for d in domains if str(d.get("type", "")).upper() == "MANAGEMENT"]
        if len(management) != 1:
            raise ValueError(f"expected one management domain, found {len(management)}")
        domain_id = management[0].get("id")
        if not isinstance(domain_id, str) or not domain_id:
            raise ValueError("management domain has no id")
        if resource_type == "NSXT_MANAGER":
            return domain_id, self._resolve_nsxt_resource(domain_id, fqdn)
        kwargs = ({"params": {"domainId": domain_id}}
                  if resource_type == "VCENTER" else {})
        managers = self._elements_from_response(
            self._request("GET", endpoints[resource_type], **kwargs))
        wanted = fqdn.rstrip(".").lower()
        matches = [m for m in managers if str(m.get("fqdn", "")).rstrip(".").lower() == wanted]
        if len(matches) != 1:
            raise ValueError(
                f"expected one {resource_type} resource for {fqdn}, found {len(matches)}")
        manager = matches[0]
        resource_id = manager.get("id") or manager.get("resourceId")
        if not isinstance(resource_id, str) or not resource_id:
            raise ValueError(f"{resource_type} resource has no id")
        manager_domain = manager.get("domainId")
        nested = manager.get("domain")
        if not manager_domain and isinstance(nested, dict):
            manager_domain = nested.get("id")
        if manager_domain and str(manager_domain) != domain_id:
            raise ValueError(f"{resource_type} resource does not belong to the management domain")
        resource = {"resourceId": resource_id, "fqdn": wanted,
                    "type": resource_type, "name": manager.get("name") or wanted,
                    "sans": manager.get("sans") or [wanted]}
        return domain_id, resource

    def _resolve_nsxt_resource(self, domain_id: str, fqdn: str) -> dict[str, Any]:
        """Resolve an official NSX-T VIP or manager-node certificate resource."""
        clusters = self._elements_from_response(self._request("GET", "/v1/nsxt-clusters"))
        wanted = fqdn.rstrip(".").casefold()
        candidates: list[dict[str, Any]] = []
        for cluster in clusters:
            domains = cluster.get("domains")
            domain_ids = {str(item.get("id")) for item in domains or []
                          if isinstance(item, dict) and item.get("id")}
            if domain_id not in domain_ids:
                continue
            vip = str(cluster.get("vipFqdn") or "").rstrip(".").casefold()
            if vip == wanted:
                candidates.append({"resourceId": cluster.get("id"), "role": "VIP",
                                   "name": cluster.get("vipFqdn")})
            for node in cluster.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                node_fqdn = str(node.get("fqdn") or "").rstrip(".").casefold()
                if node_fqdn == wanted:
                    candidates.append({"resourceId": node.get("id"), "role": "NODE",
                                       "name": node.get("name") or node.get("fqdn")})
        if len(candidates) != 1:
            raise ValueError(
                f"expected one NSXT_MANAGER VIP/node resource for {fqdn}, found {len(candidates)}")
        certificates = self._elements_from_response(self._request(
            "GET", f"/v1/domains/{domain_id}/resource-certificates"))
        metadata = [item for item in certificates
                    if str(item.get("resourceType", "")).upper() == "NSXT_MANAGER"
                    and str(item.get("resourceName") or item.get("issuedTo") or "")
                    .rstrip(".").casefold() == wanted]
        if len(metadata) != 1:
            raise ValueError(
                f"expected one NSXT_MANAGER certificate identity for {fqdn}, found {len(metadata)}")
        resource_id = candidates[0].get("resourceId")
        if not isinstance(resource_id, str) or not resource_id:
            raise ValueError("NSXT_MANAGER resource has no id")
        sans = metadata[0].get("subjectAlternativeName")
        if not isinstance(sans, list) or not sans:
            raise ValueError("NSXT_MANAGER certificate metadata has no SANs")
        normalized_sans = list(dict.fromkeys(str(value).rstrip(".").lower()
                                              for value in sans if str(value).strip()))
        if wanted not in normalized_sans:
            raise ValueError("NSXT_MANAGER certificate SANs do not contain the target FQDN")
        return {"resourceId": resource_id, "fqdn": wanted,
                "type": "NSXT_MANAGER", "name": candidates[0]["name"] or wanted,
                "sans": normalized_sans, "nsxRole": candidates[0]["role"],
                "verificationTargets": [wanted]}

    @staticmethod
    def _task_id(payload: dict[str, Any], response: requests.Response) -> str:
        value = payload.get("id")
        if isinstance(value, str) and value:
            return value
        location = response.headers.get("Location", "").rstrip("/")
        if location:
            return location.rsplit("/", 1)[-1]
        raise ValueError("SDDC Manager response did not contain a task id")

    def wait_task(self, task_id: str, *, poll_interval: float = 2,
                  poll_timeout: float = 900) -> dict[str, Any]:
        deadline = time.monotonic() + poll_timeout
        while True:
            response = self._request("GET", f"/v1/tasks/{task_id}")
            payload = self._json(response)
            if not isinstance(payload, dict):
                raise ValueError("task response was not an object")
            state = str(payload.get("status", "")).upper().replace(" ", "_")
            if state in SUCCESS:
                return payload
            if state in FAILURE:
                exc = WorkflowFailedError("SDDC Manager task reported a terminal failure.")
                if self._last_request_context:
                    context = dict(self._last_request_context)
                    context["taskId"] = task_id
                    self._attach_request_failure(exc, context)
                raise exc
            if time.monotonic() >= deadline:
                exc = WorkflowTimeoutError("SDDC Manager task polling timed out")
                if self._last_request_context:
                    context = dict(self._last_request_context)
                    context["taskId"] = task_id
                    self._attach_request_failure(exc, context)
                    exc.renewal_diagnostic["outcome"] = "TASK_STATE_UNKNOWN"
                raise exc
            time.sleep(poll_interval)

    def generate_csr(self, domain_id: str, resource: dict[str, Any],
                     subject: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        spec = {k: v for k, v in subject.items() if v not in (None, "")}
        spec.setdefault("keySize", 2048)
        spec.setdefault("keyAlgorithm", "RSA")
        response = self._request("PUT", f"/v1/domains/{domain_id}/csrs",
                                 json={"csrGenerationSpec": spec,
                                       "resources": [resource]})
        try:
            payload = self._json(response)
            if not isinstance(payload, dict):
                raise ValueError("CSR task response was not an object")
            return self._task_id(payload, response), payload
        except Exception as exc:
            self._remember_response_error(exc)
            raise

    @staticmethod
    def _csr_matches(record: dict[str, Any], resource: dict[str, Any]) -> bool:
        candidate = record.get("resource")
        if not isinstance(candidate, dict):
            return False
        actual_fqdn = str(candidate.get("fqdn") or "").rstrip(".").casefold()
        expected_fqdn = str(resource.get("fqdn") or "").rstrip(".").casefold()
        if not actual_fqdn or actual_fqdn != expected_fqdn:
            return False
        for name, normalizer in (("resourceId", str),
                                 ("type", lambda value: str(value).upper())):
            actual, expected = candidate.get(name), resource.get(name)
            if actual not in (None, ""):
                if expected in (None, "") or normalizer(actual) != normalizer(expected):
                    return False
        return True

    def fetch_csr(self, domain_id: str, resource: dict[str, Any], *,
                  retry_interval: float = 1, retry_timeout: float = 15) -> str:
        """Fetch the generated CSR, allowing bounded read-after-task propagation."""
        deadline = time.monotonic() + retry_timeout
        while True:
            records = self._elements_from_response(
                self._request("GET", f"/v1/domains/{domain_id}/csrs"))
            matches = [record for record in records
                       if self._csr_matches(record, resource)]
            if len(matches) > 1:
                raise ValueError(
                    f"multiple SDDC Manager CSRs matched {resource.get('fqdn')}")
            if matches:
                csr = matches[0].get("csrEncodedContent")
                if not isinstance(csr, str) or "BEGIN CERTIFICATE REQUEST" not in csr:
                    raise ValueError("SDDC Manager CSR response did not contain PEM")
                return csr if csr.endswith("\n") else csr + "\n"
            if time.monotonic() >= deadline:
                raise ValueError(
                    "SDDC Manager CSR task succeeded but no matching CSR appeared "
                    f"within {retry_timeout:g} seconds for {resource.get('fqdn')}")
            time.sleep(retry_interval)

    @staticmethod
    def certificate_spec(resource: dict[str, Any], chain: str) -> list[dict[str, str]]:
        return [{"resourceId": str(resource["resourceId"]),
                 "resourceFqdn": str(resource["fqdn"]),
                 "certificateChain": chain}]

    @staticmethod
    def _validation_done(payload: dict[str, Any]) -> bool:
        validations = payload.get("validations")
        if not isinstance(validations, list) or not validations:
            raise ValueError("validation response contained no resource validations")
        states = {str(v.get("validationStatus", "")).upper()
                  for v in validations if isinstance(v, dict)}
        if "FAILED" in states:
            raise WorkflowFailedError("SDDC Manager certificate validation failed")
        return bool(payload.get("completed")) and states <= {"SUCCESSFUL"}

    def validate_certificate(self, domain_id: str, resource: dict[str, Any], chain: str,
                             *, poll_interval: float = 2,
                             poll_timeout: float = 300) -> dict[str, Any]:
        response = self._request("PUT", f"/v1/domains/{domain_id}/resource-certificates/validations",
                                 json=self.certificate_spec(resource, chain))
        try:
            payload = self._json(response)
            validation_id = payload.get("validationId") if isinstance(payload, dict) else None
            if not isinstance(validation_id, str) or not validation_id:
                raise ValueError("validation response did not contain validationId")
        except Exception as exc:
            self._remember_response_error(exc)
            raise
        deadline = time.monotonic() + poll_timeout
        while not self._validation_done(payload):
            if time.monotonic() >= deadline:
                exc = WorkflowTimeoutError("SDDC Manager certificate validation polling timed out")
                if self._last_request_context:
                    context = dict(self._last_request_context)
                    self._attach_request_failure(exc, context)
                    exc.renewal_diagnostic["outcome"] = "TASK_STATE_UNKNOWN"
                raise exc
            time.sleep(poll_interval)
            payload = self._json(self._request(
                "GET", f"/v1/domains/{domain_id}/resource-certificates/validations/{validation_id}"))
            if not isinstance(payload, dict):
                raise ValueError("validation status response was not an object")
        return payload

    def replace_certificate(self, domain_id: str, resource: dict[str, Any], chain: str,
                            *, poll_interval: float = 2,
                            poll_timeout: float = 900) -> tuple[str, dict[str, Any]]:
        task_id, payload = self.submit_certificate_replacement(domain_id, resource, chain)
        state = str(payload.get("status", "")).upper().replace(" ", "_")
        return task_id, payload if state in SUCCESS else self.wait_task(
            task_id, poll_interval=poll_interval, poll_timeout=poll_timeout)

    def submit_certificate_replacement(self, domain_id: str, resource: dict[str, Any],
                                       chain: str, *, allow_redirects: bool = True) -> tuple[str, dict[str, Any]]:
        """Submit once and return its identifier before polling."""
        response = self._request("PUT", f"/v1/domains/{domain_id}/resource-certificates",
                                 json=self.certificate_spec(resource, chain), allow_redirects=allow_redirects)
        try:
            if not allow_redirects and not 200 <= response.status_code < 300:
                raise ValueError("replacement response was not a success status")
            payload = self._json(response)
            if not isinstance(payload, dict):
                raise ValueError("replacement task response was not an object")
            task_id = self._task_id(payload, response)
        except Exception as exc:
            self._remember_response_error(exc)
            raise
        return task_id, payload


    def task_inventory_page(self, page: int, size: int) -> Any:
        return self._json(self._request("GET", "/v1/tasks",
                                        params={"pageNumber": page, "pageSize": size}))
