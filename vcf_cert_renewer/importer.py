"""Validation and import of CA-signed certificate chains."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certificates import find_leaf_tls_certificate
from .client import VcfApiClient

_PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----\s*", re.DOTALL)


@dataclass(frozen=True)
class CertificateChainInfo:
    common_name: str | None
    dns_names: tuple[str, ...]
    certificate_count: int


def parse_certificate_chain(
    pem_chain: bytes,
) -> tuple[list[x509.Certificate], CertificateChainInfo]:
    """Parse a leaf-first PEM chain and return safe display information."""
    blocks = _PEM_CERTIFICATE.findall(pem_chain)
    if not blocks:
        raise ValueError("certificate file did not contain a PEM certificate")
    certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
    leaf = certificates[0]
    common_names = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    try:
        dns_names = tuple(leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()
    return certificates, CertificateChainInfo(
        common_name, dns_names, len(certificates))


def validate_chain_for_csr(
    pem_chain: bytes, csr_pem: str, fqdn: str,
) -> CertificateChainInfo:
    """Ensure the signed leaf names and public key match the selected VCF CSR."""
    certificates, info = parse_certificate_chain(pem_chain)
    wanted = fqdn.rstrip(".").lower()
    names = {name.rstrip(".").lower() for name in info.dns_names}
    if info.common_name:
        names.add(info.common_name.rstrip(".").lower())
    if wanted not in names:
        raise ValueError(f"leaf certificate does not contain hostname {fqdn}")

    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    leaf_key = certificates[0].public_key().public_bytes(encoding, public_format)
    csr_key = csr.public_key().public_bytes(encoding, public_format)
    if leaf_key != csr_key:
        raise ValueError("leaf certificate public key does not match the VCF CSR")
    return info


def list_imported_certificates(client: VcfApiClient) -> list[dict[str, Any]]:
    """List entries from the documented VCF certificate-store endpoint."""
    payload = client._request("GET", "/suite-api/api/certificate").json()
    if not isinstance(payload, dict) or not isinstance(
        payload.get("certificates"), list
    ):
        raise ValueError(
            "VCF certificate-store response did not contain certificates")
    return payload["certificates"]


def import_certificate_chain(
    client: VcfApiClient, pem_chain: bytes, fqdn: str,
    *, filename: str = "certificate-chain.pem",
) -> dict[str, Any]:
    """Discover, validate against the CSR, and import a complete PEM chain."""
    certificate = find_leaf_tls_certificate(client.query_certificates(), fqdn)
    certificate_id = certificate.get("certificateResourceKey")
    common_name = certificate.get("issuedToCommonName") or fqdn
    if not isinstance(certificate_id, str) or not certificate_id:
        raise ValueError("discovered certificate has no certificateResourceKey")
    if not isinstance(common_name, str) or not common_name:
        raise ValueError("discovered certificate has no common name")
    csr_pem = client.fetch_csr(certificate_id, common_name)
    info = validate_chain_for_csr(pem_chain, csr_pem, fqdn)
    response = client._request(
        "POST", "/suite-api/api/certificate",
        headers={"Content-Type": None},
        files={"certificateFile": (
            filename, pem_chain, "application/x-pem-file")},
    )
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("VCF import response was not a JSON object")
    imported = payload.get("certificates")
    if imported is not None and not isinstance(imported, list):
        raise ValueError("VCF import response contained invalid certificates data")
    first = imported[0] if imported and isinstance(imported[0], dict) else {}
    return {"result": "IMPORTED",
            "importedCertificateId": first.get("id") or first.get("thumbprint"),
            "commonName": info.common_name, "dnsNames": list(info.dns_names),
            "certificateCount": info.certificate_count,
            "workflowStatus": payload.get("state") or payload.get("status")
            or "NOT_APPLICABLE"}
