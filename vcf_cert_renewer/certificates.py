"""Certificate filtering and selection rules."""

from __future__ import annotations

from ipaddress import ip_address
import re
from typing import Any, Iterable


class CertificateNotFoundError(LookupError):
    pass


class AmbiguousCertificateError(LookupError):
    pass


def _hostname_matches(certificate: dict[str, Any], hostname: str) -> bool:
    wanted = hostname.rstrip(".").lower()
    direct_names = {
        str(certificate.get("applianceFqdn", "")).rstrip(".").lower(),
        str(certificate.get("issuedToCommonName", "")).rstrip(".").lower(),
    }
    sans = certificate.get("subjectAlternativeNames") or {}
    dns_names = {
        str(name).rstrip(".").lower()
        for name in sans.get("dns", [])
        if isinstance(name, str)
    }
    return wanted in direct_names or wanted in dns_names


def leaf_tls_certificates_for_hostname(
    certificates: Iterable[dict[str, Any]], hostname: str
) -> list[dict[str, Any]]:
    """Filter leaf TLS records for an appliance hostname."""
    matches = []
    for certificate in certificates:
        metadata = certificate.get("certificateMetadata") or {}
        chain_role = metadata.get("certificateChainRole") if isinstance(metadata, dict) else None
        if (
            certificate.get("category") == "TLS_CERT"
            and chain_role in (None, "LEAF")
            and _hostname_matches(certificate, hostname)
        ):
            matches.append(certificate)
    return matches


def find_leaf_tls_certificate(
    certificates: Iterable[dict[str, Any]], hostname: str
) -> dict[str, Any]:
    """Return exactly one leaf TLS certificate for hostname."""
    matches = leaf_tls_certificates_for_hostname(certificates, hostname)
    if not matches:
        raise CertificateNotFoundError(
            f"No TLS_CERT certificate found for {hostname}"
        )
    if len(matches) > 1:
        keys = [str(item.get("certificateResourceKey", "<missing>")) for item in matches]
        raise AmbiguousCertificateError(
            f"Found {len(matches)} TLS_CERT certificates for {hostname}: "
            + ", ".join(keys)
        )
    return matches[0]


AUTOMATION_APPLIANCES = frozenset({"VCF_AUTOMATION", "ARIA_AUTOMATION"})


def is_automation_external_tls(certificate: dict[str, Any]) -> bool:
    """Match observed Fleet semantics, never hostname conventions."""
    metadata = certificate.get("certificateMetadata") or {}
    return (certificate.get("appliance") in AUTOMATION_APPLIANCES
            and certificate.get("category") == "TLS_CERT"
            and certificate.get("type") == "EXTERNAL_CA"
            and isinstance(metadata, dict)
            and metadata.get("certificateChainRole") == "LEAF"
            and metadata.get("certificatePurpose") == "TLS_CERT")


def find_automation_certificate(certificates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    matches = [item for item in certificates if is_automation_external_tls(item)]
    if not matches:
        raise CertificateNotFoundError("VCF Automation external TLS certificate not discovered")
    if len(matches) != 1:
        raise AmbiguousCertificateError(
            f"VCF Automation: {len(matches)} external TLS certificates found; refusing to guess")
    certificate = matches[0]
    if certificate["certificateMetadata"].get("managementLevel") != "CUSTOMER_MANAGED_FULL_MANAGEMENT":
        raise ValueError("VCF Automation external TLS certificate is not fully Fleet managed")
    fqdn = certificate.get("applianceFqdn")
    key = certificate.get("certificateResourceKey")
    if not isinstance(fqdn, str) or not fqdn or not isinstance(key, str) or not key:
        raise ValueError("VCF Automation inventory lacks endpoint or resource key")
    # Endpoint is used as a DNS/SNI name and as part of local output filenames.
    if len(fqdn) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                 for label in fqdn.rstrip(".").split(".")):
        raise ValueError("VCF Automation inventory has an invalid DNS endpoint")
    try:
        ip_address(fqdn)
    except ValueError:
        return certificate
    raise ValueError("VCF Automation inventory endpoint must be a DNS name")


def resolve_fleet_certificate(certificates: Iterable[dict[str, Any]], fqdn: str, *,
                              expected_certificate: dict[str, Any] | None = None) -> dict[str, Any]:
    """Revalidate Automation identity before every Fleet mutation stage."""
    records = list(certificates)
    automation = ((expected_certificate or {}).get("appliance") in AUTOMATION_APPLIANCES
                  or any(item.get("appliance") in AUTOMATION_APPLIANCES
                         and _hostname_matches(item, fqdn) for item in records))
    if automation:
        selected = find_automation_certificate(records)
        if selected["applianceFqdn"].rstrip(".").lower() != fqdn.rstrip(".").lower():
            raise ValueError("Requested endpoint is not the external VCF Automation TLS endpoint")
    else:
        selected = find_leaf_tls_certificate(records, fqdn)
    if expected_certificate is not None and selected.get("certificateResourceKey") != expected_certificate.get("certificateResourceKey"):
        raise ValueError("Fleet certificate identity changed during renewal; refusing replacement")
    return selected
