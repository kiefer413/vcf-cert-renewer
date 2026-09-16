"""Explicit Fleet certificate replacement and post-change TLS verification."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
import ssl
import time
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .certificates import find_leaf_tls_certificate
from .client import VcfApiClient, WorkflowFailedError, WorkflowTimeoutError
from .importer import list_imported_certificates, parse_certificate_chain

_PEM_CHAIN = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
_SUCCESS_STATES = {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"}
_FAILURE_STATES = {"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}


class ImportedCertificateNotFoundError(LookupError):
    pass


class AmbiguousImportedCertificateError(LookupError):
    pass


class TlsVerificationError(RuntimeError):
    pass


def _normalized_thumbprint(value: object) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value).casefold())


def _normalized_dns_names(values: Iterable[str]) -> frozenset[str]:
    return frozenset(value.rstrip(".").casefold() for value in values)


def _normalized_name(value: x509.Name | str) -> tuple[tuple[str, str], ...]:
    """Return an order-independent representation of an X.509 distinguished name."""
    name = value if isinstance(value, x509.Name) else x509.Name.from_rfc4514_string(value)
    return tuple(sorted(
        (attribute.oid.dotted_string, " ".join(attribute.value.split()).casefold())
        for rdn in name.rdns for attribute in rdn))


def _utc_datetime(value: datetime | str) -> datetime:
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        value = datetime.fromisoformat(text)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _cn_from_dn(value: object) -> str | None:
    match = re.search(r"(?:^|,)\s*CN\s*=\s*([^,]+)", str(value), re.I)
    return match.group(1).strip() if match else None


def find_imported_certificate(certificates: Iterable[dict[str, Any]], *,
                              thumbprint: str | None = None,
                              common_name: str | None = None) -> dict[str, Any]:
    """Find exactly one generic certificate-store entry by thumbprint/CN."""
    wanted_thumbprint = _normalized_thumbprint(thumbprint) if thumbprint else None
    wanted_cn = common_name.rstrip(".").lower() if common_name else None
    matches = []
    for certificate in certificates:
        if wanted_thumbprint and _normalized_thumbprint(certificate.get("thumbprint")) != wanted_thumbprint:
            continue
        issued_cn = _cn_from_dn(certificate.get("issuedTo"))
        if wanted_cn and (not issued_cn or issued_cn.rstrip(".").lower() != wanted_cn):
            continue
        matches.append(certificate)
    if not matches:
        raise ImportedCertificateNotFoundError(
            f"No imported certificate found for {thumbprint or common_name or 'the supplied criteria'}")
    if len(matches) != 1:
        raise AmbiguousImportedCertificateError(
            f"Found {len(matches)} imported certificates; specify a thumbprint")
    return matches[0]


def _pem_from_value(value: object) -> bytes | None:
    """Extract a PEM chain from documented store fields or nested JSON."""
    if isinstance(value, dict):
        for key in ("certificateChain", "certificateFullChain", "signedCertificate",
                    "SignedCertificate", "certificate", "pem"):
            found = _pem_from_value(value.get(key))
            if found:
                return found
        for nested in value.values():
            found = _pem_from_value(nested)
            if found:
                return found
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if "BEGIN CERTIFICATE" in text:
        blocks = _PEM_CHAIN.findall(text)
        return ("\n".join(blocks) + "\n").encode("ascii") if blocks else None
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        decoded = b""
    if b"BEGIN CERTIFICATE" in decoded:
        return _pem_from_value(decoded.decode("ascii"))
    try:
        return _pem_from_value(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        return None


def certificate_chain_from_import(imported: dict[str, Any], *,
                                  search_paths: Iterable[Path] = ()) -> bytes:
    """Resolve the imported full chain, falling back to matching local PEM files."""
    for key in ("certificate", "certificateDetails"):
        chain = _pem_from_value(imported.get(key))
        if chain:
            return chain
    wanted = _normalized_thumbprint(imported.get("thumbprint"))
    matches: list[bytes] = []
    for path in search_paths:
        try:
            data = path.read_bytes()
            certificates, _ = parse_certificate_chain(data)
        except (OSError, ValueError):
            continue
        actual = certificates[0].fingerprint(hashes.SHA256()).hex()
        if _normalized_thumbprint(actual) == wanted:
            matches.append(data)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1 and all(item == matches[0] for item in matches[1:]):
        return matches[0]
    if len(matches) > 1:
        raise ValueError("multiple different local PEM chains match the thumbprint")
    raise ValueError(
        "the certificate store did not expose the chain and no matching local PEM file was found")


def replace_certificate(client: VcfApiClient, fqdn: str, *,
                        thumbprint: str | None = None,
                        common_name: str | None = None,
                        search_paths: Iterable[Path] = ()) -> tuple[str, dict[str, Any], bytes]:
    """Start the documented Fleet replace workflow. This function performs the PUT."""
    active = find_leaf_tls_certificate(client.query_certificates(), fqdn)
    certificate_id = active.get("certificateResourceKey")
    if not isinstance(certificate_id, str) or not certificate_id:
        raise ValueError("discovered certificate has no certificateResourceKey")
    imported = find_imported_certificate(
        list_imported_certificates(client), thumbprint=thumbprint,
        common_name=common_name or (None if thumbprint else fqdn))
    chain = certificate_chain_from_import(imported, search_paths=search_paths)
    certificates, info = parse_certificate_chain(chain)
    wanted = fqdn.rstrip(".").lower()
    names = {name.rstrip(".").lower() for name in info.dns_names}
    if info.common_name:
        names.add(info.common_name.rstrip(".").lower())
    if wanted not in names:
        raise ValueError(f"imported certificate does not contain hostname {fqdn}")
    actual = certificates[0].fingerprint(hashes.SHA256()).hex()
    if _normalized_thumbprint(actual) != _normalized_thumbprint(imported.get("thumbprint")):
        raise ValueError("resolved certificate chain does not match imported thumbprint")
    response = client._request(
        "PUT",
        f"/suite-api/api/fleet-management/certificate-management/certificates/{certificate_id}",
        json={"caType": "EXTERNAL_CA", "certificateChain": chain.decode("ascii")})
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("replace response was not a JSON object")
    return client._identifier(payload, response), payload, chain


def poll_workflow(client: VcfApiClient, request_id: str, *,
                  poll_interval: float = 2, poll_timeout: float = 900) -> dict[str, Any]:
    """Poll the documented Workflow Request endpoint to a terminal state."""
    deadline = time.monotonic() + poll_timeout
    while True:
        payload = client._request(
            "GET", f"/suite-api/api/workflows/requests/{request_id}").json()
        if not isinstance(payload, dict):
            raise ValueError("workflow response was not a JSON object")
        state = client._state(payload)
        if state in _SUCCESS_STATES:
            return payload
        if state in _FAILURE_STATES:
            raise WorkflowFailedError(
                f"certificate replacement workflow {request_id} ended with {state}: "
                f"{payload.get('errorCause') or []}")
        if time.monotonic() >= deadline:
            raise WorkflowTimeoutError(
                f"certificate replacement workflow {request_id} did not finish in {poll_timeout:g}s")
        time.sleep(poll_interval)


@dataclass(frozen=True)
class CertificateIdentity:
    common_name: str | None
    dns_names: tuple[str, ...]
    subject: str
    issuer: str
    not_valid_before: str
    not_valid_after: str
    sha256_thumbprint: str


def _validity(certificate: x509.Certificate, field: str) -> datetime:
    aware = getattr(certificate, f"{field}_utc", None)
    if aware is not None:
        return _utc_datetime(aware)
    return _utc_datetime(getattr(certificate, field))


def _identity(certificate: x509.Certificate) -> CertificateIdentity:
    common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    try:
        dns_names = tuple(certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()
    return CertificateIdentity(
        common_names[0].value if common_names else None, dns_names,
        certificate.subject.rfc4514_string(), certificate.issuer.rfc4514_string(),
        _validity(certificate, "not_valid_before").isoformat(),
        _validity(certificate, "not_valid_after").isoformat(),
        certificate.fingerprint(hashes.SHA256()).hex())


def _certificate_differences(actual: x509.Certificate,
                             expected: x509.Certificate) -> list[str]:
    actual_identity = _identity(actual)
    expected_identity = _identity(expected)
    differences = []
    if _normalized_dns_names(actual_identity.dns_names) != _normalized_dns_names(
            expected_identity.dns_names):
        differences.append("dns_names")
    if _normalized_name(actual.subject) != _normalized_name(expected.subject):
        differences.append("subject")
    if _normalized_name(actual.issuer) != _normalized_name(expected.issuer):
        differences.append("issuer")
    for field in ("not_valid_before", "not_valid_after"):
        if _utc_datetime(getattr(actual_identity, field)) != _utc_datetime(
                getattr(expected_identity, field)):
            differences.append(field)
    if _normalized_thumbprint(actual_identity.sha256_thumbprint) != _normalized_thumbprint(
            expected_identity.sha256_thumbprint):
        differences.append("sha256_thumbprint")
    return differences


def _fetch_https_certificate(hostname: str, port: int, timeout: float) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def inspect_https_certificate(hostname: str, *, port: int = 443,
                              timeout: float = 15) -> dict[str, Any]:
    """Read and describe the leaf certificate currently served with SNI."""
    identity = _identity(_fetch_https_certificate(hostname, port, timeout))
    return {
        "hostname": hostname,
        "port": port,
        "commonName": identity.common_name,
        "subject": identity.subject,
        "issuer": identity.issuer,
        "sans": list(identity.dns_names),
        "notBefore": identity.not_valid_before,
        "notAfter": identity.not_valid_after,
        "sha256Thumbprint": identity.sha256_thumbprint,
    }


def verify_https_certificate(hostname: str, expected_chain: bytes, *, port: int = 443,
                             timeout: float = 15, retry_timeout: float = 300,
                             retry_interval: float = 10) -> dict[str, Any]:
    """Fetch the active leaf with SNI and strictly compare it, retrying activation lag."""
    expected_certificates, _ = parse_certificate_chain(expected_chain)
    expected = expected_certificates[0]
    deadline = time.monotonic() + retry_timeout
    while True:
        try:
            certificate = _fetch_https_certificate(hostname, port, timeout)
            differences = _certificate_differences(certificate, expected)
            if not differences:
                result = asdict(_identity(certificate))
                result["verified"] = True
                result["hostname"] = hostname
                return result
            error = TlsVerificationError(
                "active HTTPS certificate differs in: " + ", ".join(differences))
        except (OSError, ssl.SSLError, ValueError) as exc:
            error = TlsVerificationError(f"HTTPS certificate could not be read: {exc}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise error
        time.sleep(min(retry_interval, remaining))
