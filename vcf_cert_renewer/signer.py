"""Non-interactive lego/ACME signing of VCF-generated CSRs."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .config import ConfigurationError, Settings, SECRET_ENV_NAMES, SECRET_FILE_NAMES
from .importer import parse_certificate_chain


def csr_names(csr_path: Path) -> tuple[str, ...]:
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    try:
        names = tuple(csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = ()
    if not names:
        names = tuple(item.value for item in
                      csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
    if not names:
        raise ValueError("CSR contains neither DNS SANs nor a common name")
    return names


def lego_command(settings: Settings, csr_path: Path) -> tuple[list[str], dict[str, str]]:
    """Build argv/environment; argv and error messages never contain secrets."""
    required = {
        "ACME_EMAIL": settings.acme_email,
        "DNSUPDATE_NAMESERVER": settings.dns_nameserver,
        "DNSUPDATE_TSIG_KEY": settings.dns_tsig_key,
        "DNSUPDATE_TSIG_SECRET": settings.dns_tsig_secret,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ConfigurationError("missing signer configuration: " + ", ".join(missing))
    if settings.dns_provider != "rfc2136":
        raise ConfigurationError("DNS_PROVIDER must be rfc2136")
    account_path = settings.output_dir / "acme" / settings.acme_mode
    command = [
        str(settings.lego_path), "run", "--accept-tos", "--email", str(settings.acme_email),
        "--server", settings.acme_server, "--path", str(account_path),
        "--dns", settings.dns_provider,
    ]
    for resolver in settings.public_dns_resolvers:
        command.extend(["--dns.resolvers", resolver])
    command.extend(["--csr", str(csr_path)])
    environment = os.environ.copy()
    for name in SECRET_ENV_NAMES | SECRET_FILE_NAMES:
        environment.pop(name, None)
    # Settings are authoritative: inherited lego EAB credentials must not enable EAB.
    for name in ("LEGO_EAB", "LEGO_EAB_KID", "LEGO_EAB_HMAC",
                 "LEGO_EAB_KID_FILE", "LEGO_EAB_HMAC_FILE",
                 "ACME_EAB_KID", "ACME_EAB_HMAC"):
        environment.pop(name, None)
    if settings.acme_eab_kid and settings.acme_eab_hmac:
        command.insert(2, "--eab")
        environment.update({"LEGO_EAB_KID": settings.acme_eab_kid,
                            "LEGO_EAB_HMAC": settings.acme_eab_hmac})
    environment.update({
        "DNSUPDATE_NAMESERVER": str(settings.dns_nameserver),
        "DNSUPDATE_TSIG_KEY": str(settings.dns_tsig_key),
        "DNSUPDATE_TSIG_ALGORITHM": settings.dns_tsig_algorithm,
        "DNSUPDATE_TSIG_SECRET": str(settings.dns_tsig_secret),
    })
    return command, environment


def _matching_leaf(directory: Path, csr: x509.CertificateSigningRequest) -> Path:
    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    wanted = csr.public_key().public_bytes(encoding, public_format)
    matches: list[Path] = []
    for path in directory.rglob("*.crt"):
        if path.name.endswith(".issuer.crt"):
            continue
        try:
            certificates, _ = parse_certificate_chain(path.read_bytes())
            actual = certificates[0].public_key().public_bytes(encoding, public_format)
        except (OSError, ValueError):
            continue
        if actual == wanted:
            matches.append(path)
    if not matches:
        raise ValueError("lego did not produce a certificate matching the CSR")
    return max(matches, key=lambda item: item.stat().st_mtime_ns)


def sign_csr(settings: Settings, csr_path: Path) -> dict[str, Any]:
    csr_path = csr_path.resolve()
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    names = csr_names(csr_path)
    command, environment = lego_command(settings, csr_path)
    account_path = settings.output_dir / "acme" / settings.acme_mode
    account_path.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            command, env=environment, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        raise ValueError(
            f"lego signing failed with exit status {exc.returncode}; "
            "output was suppressed") from None
    leaf_path = _matching_leaf(account_path, csr)
    issuer_path = leaf_path.with_name(
        leaf_path.name.removesuffix(".crt") + ".issuer.crt")
    if not issuer_path.exists():
        raise ValueError("lego did not produce the issuer certificate")
    certificates, info = parse_certificate_chain(leaf_path.read_bytes())
    leaf = certificates[0]
    not_before = getattr(leaf, "not_valid_before_utc", leaf.not_valid_before)
    not_after = getattr(leaf, "not_valid_after_utc", leaf.not_valid_after)
    return {
        "result": "SIGNED", "fqdn": names[0],
        "leafPath": str(leaf_path), "issuerPath": str(issuer_path),
        "sans": list(info.dns_names), "issuer": leaf.issuer.rfc4514_string(),
        "notBefore": not_before.isoformat(), "notAfter": not_after.isoformat(),
        "sha256Thumbprint": leaf.fingerprint(hashes.SHA256()).hex(),
        "acmeMode": settings.acme_mode, "acmeServer": settings.acme_server,
    }
