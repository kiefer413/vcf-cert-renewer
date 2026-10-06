"""HTTP client for the VCF Operations Fleet Management API."""

from __future__ import annotations

import time
from typing import Any, Callable

import requests
from cryptography import x509


class CsrNotFoundError(ValueError):
    """Fleet has no CSR for the requested resource and common name."""


class AmbiguousCsrError(ValueError):
    """Fleet returned multiple possible CSRs for one certificate resource."""


class CsrIdentityError(ValueError):
    """A Fleet CSR does not match the requested endpoint/resource identity."""


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
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        result = []
        page = 0
        while True:
            params = {"pageSize": page_size}
            if page:
                params["page"] = page
            payload = self._request(
                "POST",
                "/suite-api/api/fleet-management/certificate-management/certificates/query",
                params=params, json={},
            ).json()
            models = payload.get("vcfCertificateModels")
            if not isinstance(models, list) or not all(isinstance(item, dict) for item in models):
                raise ValueError("VCF response did not contain vcfCertificateModels list")
            info = payload.get("pageInfo") or {}
            total = info.get("totalCount")
            if page and (not models or info.get("page", page) != page):
                raise ValueError("Fleet inventory pagination did not advance")
            result.extend(models)
            if total is not None:
                if len(result) >= int(total):
                    return result
            elif len(models) < page_size:
                return result
            page += 1
            if page > 10000:
                raise ValueError("Fleet inventory pagination exceeded safety limit")

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

    def create_csr(self, certificate: dict[str, Any], *,
                   on_mutation_attempt: Callable[[], None] | None = None
                   ) -> tuple[str, dict[str, Any]]:
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
        if on_mutation_attempt:
            on_mutation_attempt()
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

    @staticmethod
    def _automation_csr_identity_matches(record: dict[str, Any], certificate_id: str,
                                         expected_fqdn: str, appliance: str,
                                         component: str | None) -> bool:
        """Require observed resource and endpoint identity before reusing VCFA CSR."""
        resource_ids = [record.get(name) for name in
                        ("certificateId", "certificateResourceKey", "resourceId")
                        if record.get(name) not in (None, "")]
        if not resource_ids or any(not isinstance(value, str) or value != certificate_id
                                   for value in resource_ids):
            return False

        appliance_values = [record.get(name) for name in
                            ("appliance", "applianceType", "applianceName")
                            if record.get(name) not in (None, "")]
        if not appliance_values:
            return False
        accepted_appliances = {"VCF_AUTOMATION", "ARIA_AUTOMATION"}
        expected_appliance = appliance.upper()
        for value in appliance_values:
            candidate = str(value).upper()
            if (candidate != expected_appliance and
                    not (candidate in accepted_appliances and
                         expected_appliance in accepted_appliances)):
                return False

        endpoint_values = [record.get(name) for name in
                           ("applianceFqdn", "endpointFqdn")
                           if record.get(name) not in (None, "")]
        if not endpoint_values:
            return False
        wanted = expected_fqdn.rstrip(".").casefold()
        if any(str(value).rstrip(".").casefold() != wanted for value in endpoint_values):
            return False

        if component:
            component_values = [record.get(name) for name in
                                ("vcfComponent", "componentType", "component")
                                if record.get(name) not in (None, "")]
            if any(str(value).casefold() != component.casefold()
                   for value in component_values):
                return False
        return True

    @staticmethod
    def _csr_has_dns_san(csr: str, expected_fqdn: str) -> bool:
        try:
            parsed = x509.load_pem_x509_csr(csr.encode("ascii"))
            names = parsed.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except (x509.ExtensionNotFound, ValueError, UnicodeError):
            return False
        wanted = expected_fqdn.rstrip(".").casefold()
        return wanted in {name.rstrip(".").casefold() for name in names}

    def fetch_csr(self, certificate_id: str, common_name: str, *,
                  expected_fqdn: str | None = None,
                  strict_dns_san: bool = False,
                  appliance: str | None = None,
                  component: str | None = None) -> str:
        """Fetch candidates and validate client-side before selecting a CSR.

        Fleet's certificateId query filter is retained as a hint only; historical
        records may still be returned after certificate replacement.
        """
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
        usable = [item for item in records if isinstance(item, dict)]
        if not usable:
            raise CsrNotFoundError(f"No generated CSR found for certificate resource {certificate_id}")
        matching = [item for item in usable if
                    str(item.get("commonName", "")).rstrip(".").casefold()
                    == common_name.rstrip(".").casefold()]
        if appliance and expected_fqdn:
            # CSR history is not authoritative merely because the server accepted
            # a certificateId filter. Only current resource identity plus the
            # expected appliance/endpoint and SAN can make an entry reusable.
            reusable: list[tuple[dict[str, Any], str]] = []
            for item in matching:
                if not self._automation_csr_identity_matches(
                        item, certificate_id, expected_fqdn, appliance, component):
                    continue
                item_csr = self._csr_from(item)
                if not item_csr:
                    continue
                try:
                    normalized_item_csr = self._normalize_csr_pem(item_csr)
                except ValueError:
                    continue
                if not self._csr_has_dns_san(normalized_item_csr, expected_fqdn):
                    continue
                reusable.append((item, normalized_item_csr))
            if not reusable:
                raise CsrNotFoundError(
                    f"No reusable CSR found for current Automation resource {certificate_id}")
            if len(reusable) > 1:
                raise AmbiguousCsrError(
                    f"Found multiple reusable CSRs for Automation resource {certificate_id}")
            return reusable[0][1]

        if len(matching) > 1:
            raise AmbiguousCsrError(f"Found multiple generated CSRs for certificate resource {certificate_id}")
        if not matching:
            raise CsrIdentityError("Fleet CSR records do not match the requested common name")
        selected = matching[0]
        returned_id = selected.get("certificateId") or selected.get("certificateResourceKey")
        if returned_id and str(returned_id) != certificate_id:
            raise CsrIdentityError("Fleet CSR belongs to a different certificate resource")
        returned_appliance = selected.get("appliance") or selected.get("applianceType")
        if appliance and returned_appliance and str(returned_appliance) != appliance:
            raise CsrIdentityError("Fleet CSR belongs to a different appliance")
        returned_fqdn = selected.get("applianceFqdn")
        if expected_fqdn and returned_fqdn and str(returned_fqdn).rstrip(".").casefold() != expected_fqdn.rstrip(".").casefold():
            raise CsrIdentityError("Fleet CSR belongs to a different endpoint")
        csr = self._csr_from(selected)
        if not csr:
            raise ValueError("CSR fetch response did not contain PEM data")
        normalized = self._normalize_csr_pem(csr)
        if expected_fqdn:
            try:
                parsed = x509.load_pem_x509_csr(normalized.encode("ascii"))
                names = parsed.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            except (ValueError, UnicodeError) as exc:
                raise CsrIdentityError("Fleet returned an invalid CSR") from exc
            wanted = expected_fqdn.rstrip(".").casefold()
            normalized_names = {name.rstrip(".").casefold() for name in names}
            common_names = [attribute.value for attribute in
                            parsed.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
            if strict_dns_san and wanted not in normalized_names:
                raise CsrIdentityError("Fleet CSR DNS SAN does not match the external endpoint")
            if names and wanted not in normalized_names:
                raise CsrIdentityError("Fleet CSR DNS SAN does not match the requested endpoint")
            if not names and common_names and common_names[0].rstrip(".").casefold() != wanted:
                raise CsrIdentityError("Fleet CSR common name does not match the requested endpoint")
            if not names and not common_names:
                raise CsrIdentityError("Fleet CSR has no DNS SAN or common name")
        return normalized
