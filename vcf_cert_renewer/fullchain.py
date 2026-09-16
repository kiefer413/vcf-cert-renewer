"""Build and validate the VCF leaf-first chain."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import requests

from .importer import parse_certificate_chain


def _self_signed(certificate: x509.Certificate) -> bool:
    if certificate.subject != certificate.issuer:
        return False
    try:
        certificate.verify_directly_issued_by(certificate)
        return True
    except (ValueError, TypeError):
        return False


def _verify_child(child: x509.Certificate, issuer: x509.Certificate) -> None:
    if child.issuer != issuer.subject:
        raise ValueError("certificate chain issuer/subject relationship is broken")
    try:
        child.verify_directly_issued_by(issuer)
    except (ValueError, TypeError) as exc:
        raise ValueError("certificate chain signature validation failed") from exc


def _ca_issuer_urls(certificate: x509.Certificate) -> list[str]:
    try:
        aia = certificate.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [str(item.access_location.value) for item in aia
            if item.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(item.access_location, x509.UniformResourceIdentifier)]


def _load_certificate(content: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(content)
    except ValueError:
        return x509.load_der_x509_certificate(content)


def retrieve_issuer(certificate: x509.Certificate, *,
                    fetch: Callable[[str], bytes] | None = None) -> x509.Certificate:
    urls = _ca_issuer_urls(certificate)
    if not urls:
        raise ValueError(
            "chain is missing its root and the final certificate has no CA Issuers AIA")

    def default_fetch(url: str) -> bytes:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        return response.content

    loader = fetch or default_fetch
    errors: list[str] = []
    for url in urls:
        try:
            issuer = _load_certificate(loader(url))
            _verify_child(certificate, issuer)
            return issuer
        except (requests.RequestException, OSError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
    raise ValueError("could not retrieve a valid issuer certificate: " + "; ".join(errors))


def build_vcf_fullchain(leaf_path: Path, issuer_path: Path, output_path: Path, *,
                        fetch: Callable[[str], bytes] | None = None,
                        max_downloads: int = 4) -> Path:
    leaf_certificates, _ = parse_certificate_chain(leaf_path.read_bytes())
    issuer_certificates, _ = parse_certificate_chain(issuer_path.read_bytes())
    certificates: list[x509.Certificate] = []
    seen: set[bytes] = set()
    for certificate in leaf_certificates + issuer_certificates:
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint not in seen:
            seen.add(fingerprint)
            certificates.append(certificate)
    downloads = 0
    while not _self_signed(certificates[-1]):
        if downloads >= max_downloads:
            raise ValueError("chain did not reach a self-signed root")
        issuer = retrieve_issuer(certificates[-1], fetch=fetch)
        fingerprint = issuer.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            raise ValueError("issuer retrieval created a certificate loop")
        seen.add(fingerprint)
        certificates.append(issuer)
        downloads += 1
    for child, issuer in zip(certificates, certificates[1:]):
        _verify_child(child, issuer)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(b"".join(
        certificate.public_bytes(serialization.Encoding.PEM)
        for certificate in certificates))
    parse_certificate_chain(output_path.read_bytes())
    return output_path


def predictable_fullchain_path(output_dir: Path, fqdn: str) -> Path:
    return output_dir / f"{fqdn.rstrip('.').lower()}.vcf-fullchain.pem"
