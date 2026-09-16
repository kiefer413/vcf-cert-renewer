"""HTTP client for the VCF Operations Fleet Management API."""

from __future__ import annotations

import time
from typing import Any

import requests


class WorkflowFailedError(RuntimeError):
    """Raised when asynchronous CSR generation does not complete successfully."""


class WorkflowTimeoutError(TimeoutError):
    """Raised when asynchronous CSR generation exceeds its polling deadline."""


class VcfRequestError(requests.HTTPError):
    """HTTP failure with the VCF API's non-secret diagnostic attached."""


class VcfApiClient:
    def __init__(self, base_url: str, api_token: str, *, verify_tls: bool = True,
                 timeout_seconds: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        response = getattr(self.session, method.lower())(
            f"{self.base_url}{path}", timeout=self.timeout_seconds,
            verify=self.verify_tls, **kwargs)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            detail = response.text.strip()
            if len(detail) > 2000:
                detail = detail[:2000] + "..."
            message = f"{exc}; VCF response: {detail}" if detail else str(exc)
            raise VcfRequestError(message, response=response) from exc
        return response

    def query_certificates(self, *, page_size: int = 500) -> list[dict[str, Any]]:
        response = self._request(
            "POST",
            "/suite-api/api/fleet-management/certificate-management/certificates/query",
            params={"pageSize": page_size}, json={},
        )
        models = response.json().get("vcfCertificateModels")
        if not isinstance(models, list):
            raise ValueError("VCF response did not contain vcfCertificateModels list")
        return models

    @staticmethod
    def _identifier(payload: dict[str, Any], response: requests.Response) -> str:
        for name in ("requestId", "workflowId", "id"):
            value = payload.get(name)
            if isinstance(value, str) and value:
                return value
        for container in ("request", "workflow"):
            nested = payload.get(container)
            if isinstance(nested, dict):
                for name in ("id", "requestId", "workflowId"):
                    value = nested.get(name)
                    if isinstance(value, str) and value:
                        return value
        location = response.headers.get("Location", "").rstrip("/")
        if location:
            return location.rsplit("/", 1)[-1]
        raise ValueError("CSR response did not contain a workflow/request identifier")

    def create_csr(self, certificate: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Start CSR generation for a discovered certificate resource."""
        certificate_id = certificate.get("certificateResourceKey")
        if not isinstance(certificate_id, str) or not certificate_id:
            raise ValueError("discovered certificate has no certificateResourceKey")
        common_name = certificate.get("issuedToCommonName") or certificate.get("applianceFqdn")
        if not isinstance(common_name, str) or not common_name:
            raise ValueError("discovered certificate has no common name")
        subject_alt_names = certificate.get("subjectAlternativeNames") or {}
        if not isinstance(subject_alt_names, dict):
            raise ValueError("discovered certificate has invalid subjectAlternativeNames")
        response = self._request(
            "POST", "/suite-api/api/fleet-management/certificate-management/csrs",
            json={
                "certificateId": certificate_id,
                "generateCsrSpec": {
                    "commonName": common_name,
                    "keySize": "KEY_2048",
                    "keyAlgorithm": "RSA",
                    "organization": "VMware",
                    "orgUnit": "VMware Engineering",
                    "subjectAltNames": {
                        "dns": subject_alt_names.get("dns", []),
                        "ip": subject_alt_names.get("ip", []),
                    },
                },
            },
        )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("CSR response was not a JSON object")
        return self._identifier(payload, response), payload

    @staticmethod
    def _state(payload: dict[str, Any]) -> str:
        for source in (payload, payload.get("request"), payload.get("workflow")):
            if isinstance(source, dict):
                for name in ("status", "state", "executionStatus"):
                    value = source.get(name)
                    if isinstance(value, str) and value:
                        return value.upper()
        return ""

    def wait_for_csr(self, request_id: str, *, poll_interval: float = 2,
                     poll_timeout: float = 300) -> dict[str, Any]:
        """Poll the Fleet Management request endpoint until it is terminal."""
        deadline = time.monotonic() + poll_timeout
        while True:
            payload = self._request(
                "GET", f"/suite-api/api/workflows/requests/{request_id}"
            ).json()
            if not isinstance(payload, dict):
                raise ValueError("Workflow response was not a JSON object")
            state = self._state(payload)
            if state in {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"}:
                return payload
            if state in {"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}:
                raise WorkflowFailedError(f"CSR workflow {request_id} ended with {state}")
            if time.monotonic() >= deadline:
                raise WorkflowTimeoutError(f"CSR workflow {request_id} did not finish in {poll_timeout:g}s")
            time.sleep(poll_interval)

    @staticmethod
    def _csr_from(payload: dict[str, Any]) -> str | None:
        for source in (payload, payload.get("result"), payload.get("response"),
                       payload.get("csr")):
            if isinstance(source, str) and "BEGIN CERTIFICATE REQUEST" in source:
                return source
            if isinstance(source, dict):
                for name in ("csr", "pem", "certificateSigningRequest", "content"):
                    value = source.get(name)
                    if isinstance(value, str) and value:
                        return value
        return None

    @staticmethod
    def _normalize_csr_pem(csr: str) -> str:
        """Convert compact or normally wrapped CSR text to canonical PEM."""
        begin = "-----BEGIN CERTIFICATE REQUEST-----"
        end = "-----END CERTIFICATE REQUEST-----"
        start = csr.find(begin)
        finish = csr.find(end, start + len(begin))
        if start < 0 or finish < 0:
            raise ValueError("CSR fetch response did not contain PEM data")
        body = "".join(csr[start + len(begin):finish].split())
        if not body:
            raise ValueError("CSR PEM body was empty")
        lines = [body[index:index + 64] for index in range(0, len(body), 64)]
        return "\n".join([begin, *lines, end, ""])

    def fetch_csr(self, certificate_id: str, common_name: str) -> str:
        """Fetch generated CSR PEM after its workflow completes."""
        response = self._request(
            "GET", "/suite-api/api/fleet-management/certificate-management/csrs",
            params={"certificateId": certificate_id, "commonName": common_name,
                    "pageSize": 1000},
        )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("CSR fetch response was not a JSON object")
        records = payload.get("certificateSignatureInfo")
        if not isinstance(records, list):
            raise ValueError("CSR fetch response did not contain certificateSignatureInfo")
        matching = [item for item in records if isinstance(item, dict) and
                    item.get("commonName", "").rstrip(".").lower() == common_name.rstrip(".").lower()]
        if len(matching) != 1:
            raise ValueError(f"expected one generated CSR for {common_name}, found {len(matching)}")
        csr = self._csr_from(matching[0])
        if not csr:
            raise ValueError("CSR fetch response did not contain PEM data")
        return self._normalize_csr_pem(csr)
