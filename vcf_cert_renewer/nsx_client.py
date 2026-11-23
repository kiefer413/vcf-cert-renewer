"""Official NSX 9.1 trust-management client for the cluster VIP certificate."""
from __future__ import annotations

from ipaddress import ip_address
from collections.abc import Callable
import time
from typing import Any
from urllib.parse import quote

import requests

from .diagnostics import attach_diagnostic, make_diagnostic, safe_api_path, safe_identifier


class NsxApiClient:
    def __init__(self, base_url: str, token_provider: Callable[[], str], *,
                 verify_tls: bool = True, timeout_seconds: float = 30):
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self._token_provider = token_provider
        self._access_token: str | None = None
        self._target_fqdn: str | None = None
        self.session = requests.Session()

    def set_target(self, fqdn: str) -> None:
        self._target_fqdn = fqdn.rstrip(".").lower()

    def _token(self) -> str:
        if self._access_token is None:
            token = self._token_provider()
            if not isinstance(token, str) or not token:
                raise ValueError("VCF Identity Broker returned no NSX bearer token")
            self._access_token = token
        return self._access_token

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {self._token()}"
        started = time.monotonic()
        try:
            response = self.session.request(method, self.base_url + path,
                                            verify=self.verify_tls,
                                            timeout=self.timeout_seconds,
                                            headers=headers, **kwargs)
        except requests.RequestException as exc:
            self._attach_http_diagnostic(exc, method, path,
                                         time.monotonic() - started)
            raise
        try:
            response.raise_for_status()
        except Exception as exc:
            self._attach_http_diagnostic(exc, method, path,
                                         time.monotonic() - started,
                                         response=response)
            raise
        # Never retry automatically: a mutating request may already have been accepted.
        return response

    def _attach_http_diagnostic(self, exc: BaseException, method: str, path: str,
                                elapsed: float,
                                response: requests.Response | None = None) -> None:
        route = safe_api_path(path)
        operation = "NSX_API_REQUEST"
        if route.endswith("/csrs") and method.upper() == "POST":
            operation = "GENERATE_CSR"
        elif "/csrs/{csrId}" in route:
            operation = "IMPORT_CERTIFICATE"
        elif "/certificates/{certificateId}" in route:
            operation = "APPLY_MGMT_CLUSTER_CERTIFICATE"
        elif route.endswith("/certificate-profiles") or route.endswith("/certificates"):
            operation = "DISCOVER_CERTIFICATES"
        elif route.endswith("/cluster/nodes") or route.endswith("/node/version"):
            operation = "DISCOVER_NSX_CLUSTER"
        status = getattr(response, "status_code", None) if response else None
        correlation_id = None
        response_headers = getattr(response, "headers", {}) if response else {}
        for name in ("X-Request-ID", "X-Correlation-ID", "X-NSX-Request-ID"):
            value = response_headers.get(name) if hasattr(response_headers, "get") else None
            correlation_id = safe_identifier(value)
            if correlation_id:
                break
        event = make_diagnostic(
            component="NSX_MANAGER", target=self._target_fqdn, phase="RENEW",
            operation=operation, exc=exc, http_method=method, api_path=path,
            timeout_seconds=self.timeout_seconds, elapsed_seconds=elapsed,
            response_status=status, correlation_id=correlation_id,
            response_received=response is not None)
        attach_diagnostic(exc, event)

    def version(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/node/version").json()

    def nodes(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/cluster/nodes").json().get("results", [])

    def profiles(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/trust-management/certificate-profiles").json().get("results", [])

    def certificates(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/trust-management/certificates", params={"details": "true"}).json().get("results", [])

    @staticmethod
    def _services(certificate: dict[str, Any]) -> set[str]:
        services: set[str] = set()
        for usage in certificate.get("used_by") or []:
            values = usage.get("service_types") or usage.get("services") or []
            if isinstance(values, str):
                values = [values]
            services.update(str(value).upper() for value in values)
            value = usage.get("service_type")
            if value:
                services.add(str(value).upper())
        return services

    def discover(self, vip_fqdn: str) -> dict[str, Any]:
        fqdn = vip_fqdn.rstrip(".").lower()
        profiles = self.profiles()
        mgmt = [p for p in profiles if p.get("service_type") == "MGMT_CLUSTER"]
        api = [p for p in profiles if p.get("service_type") == "API"]
        if len(mgmt) != 1 or mgmt[0].get("cluster_certificate") is not True:
            raise ValueError("NSX MGMT_CLUSTER profile is unavailable or not cluster-scoped")
        if len(api) != 1 or api[0].get("cluster_certificate") is not False:
            raise ValueError("NSX API profile is unavailable or not node-scoped")
        certificates = self.certificates()
        cluster = [c for c in certificates if "MGMT_CLUSTER" in self._services(c)]
        node = [c for c in certificates if "API" in self._services(c)]
        if len(cluster) != 1:
            raise ValueError(f"expected one active MGMT_CLUSTER certificate, found {len(cluster)}")
        if cluster[0] in node:
            raise ValueError("MGMT_CLUSTER and API unexpectedly share one certificate object")
        return {"targetFqdn": fqdn, "serviceType": "MGMT_CLUSTER",
                "profile": mgmt[0], "certificate": cluster[0],
                "apiCertificates": node, "nodes": self.nodes(), "version": self.version()}

    @staticmethod
    def validate_dns_sans(target: str, sans: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in sans:
            name = value.rstrip(".").lower()
            try:
                ip_address(name)
            except ValueError:
                if name and name not in normalized:
                    normalized.append(name)
            else:
                raise ValueError("native NSX MGMT_CLUSTER identity contains an IP SAN; public ACME is blocked")
        if target.rstrip(".").lower() not in normalized:
            raise ValueError("MGMT_CLUSTER DNS SANs do not contain the VIP FQDN")
        return normalized

    def create_csr(self, fqdn: str, sans: list[str], subject: dict[str, str]) -> dict[str, Any]:
        dns = self.validate_dns_sans(fqdn, sans)
        keys = (("CN", fqdn), ("O", subject["organization"]),
                ("OU", subject["organizationUnit"]), ("C", subject["country"]),
                ("ST", subject["state"]), ("L", subject["locality"]))
        payload = {"subject": {"attributes": [{"key": k, "value": v} for k, v in keys]},
                   "key_size": 2048, "algorithm": "RSA", "is_ca": False,
                   "extensions": {"subject_alt_names": {"dns_names": dns}}}
        return self._request("POST", "/api/v1/trust-management/csrs", json=payload).json()

    def import_csr_certificate(self, csr_id: str, pem_chain: str) -> dict[str, Any]:
        result = self._request("POST", f"/api/v1/trust-management/csrs/{quote(csr_id, safe='')}?action=import",
                               json={"pem_encoded": pem_chain}).json()
        items = result.get("results", []) if isinstance(result, dict) else []
        if len(items) != 1 or not items[0].get("has_private_key"):
            raise ValueError("NSX CSR import did not return one certificate with a private key")
        return items[0]

    def apply_mgmt_cluster(self, certificate_id: str, *, allow_redirects: bool = True) -> None:
        response = self._request("POST", f"/api/v1/trust-management/certificates/{quote(certificate_id, safe='')}?action=apply_certificate",
                      params={"service_type": "MGMT_CLUSTER"}, allow_redirects=allow_redirects)
        if not allow_redirects and not 200 <= response.status_code < 300:
            raise ValueError("NSX certificate assignment did not return a success status")
