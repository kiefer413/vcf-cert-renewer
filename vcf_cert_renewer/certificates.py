"""Certificate filtering and selection rules."""

from __future__ import annotations

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
