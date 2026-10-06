"""Non-interactive lego/ACME signing of VCF-generated CSRs."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any
import re
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .config import ConfigurationError, Settings, SECRET_ENV_NAMES, SECRET_FILE_NAMES
from .importer import parse_certificate_chain



def _is_placeholder(value: str, *, email: bool = False) -> bool:
    """Reject reserved example/test names without restricting private DNS names."""
    text = value.strip().rstrip(".").casefold()
    if email and "@" in text:
        text = text.rsplit("@", 1)[1]
    if not text:
        return False
    if text.endswith((".invalid", ".example", ".test")):
        return True
    labels = text.split(".")
    return "example" in labels


def _validate_signer_configuration(settings: Settings) -> None:
    if settings.acme_email and _is_placeholder(settings.acme_email, email=True):
        raise ConfigurationError("ACME_EMAIL contains an example/placeholder value")
    if settings.dns_nameserver and _is_placeholder(settings.dns_nameserver.split(":", 1)[0]):
        # Bracketed IPv6 is never a placeholder DNS name; leave it to the DNS provider.
        if not settings.dns_nameserver.startswith("["):
            raise ConfigurationError("DNSUPDATE_NAMESERVER contains an example/placeholder value")


def sanitize_diagnostic(output: object, settings: Settings, *, limit: int = 2000) -> str:
    """Bound external tool diagnostics and redact all known application secrets."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    text = str(output)
    text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                  "[PRIVATE KEY REDACTED]", text, flags=re.DOTALL)
    secrets = [
        settings.dns_tsig_secret, settings.acme_eab_hmac, settings.acme_eab_kid,
        settings.api_token, settings.sddc_password, settings.client_secret,
    ]
    for secret in sorted((str(value) for value in secrets if value), key=len, reverse=True):
        for variant in {secret, quote(secret, safe=""), quote(secret, safe="/" )}:
            if variant:
                text = text.replace(variant, "[REDACTED]")
    text = "".join(char if char in "\n\t" or char.isprintable() else " " for char in text)
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if len(text) > limit:
        text = text[:limit - 3].rstrip() + "..."
    return text


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


def validate_signer_configuration(settings: Settings) -> None:
    required = {
        "ACME_EMAIL": settings.acme_email,
        "DNSUPDATE_NAMESERVER": settings.dns_nameserver,
        "DNSUPDATE_TSIG_KEY": settings.dns_tsig_key,
        "DNSUPDATE_TSIG_SECRET": settings.dns_tsig_secret,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ConfigurationError("missing signer configuration: " + ", ".join(missing))
    _validate_signer_configuration(settings)
    if settings.dns_provider != "rfc2136":
        raise ConfigurationError("DNS_PROVIDER must be rfc2136")


def lego_command(settings: Settings, csr_path: Path) -> tuple[list[str], dict[str, str]]:
    """Build argv/environment; argv and error messages never contain secrets."""
    validate_signer_configuration(settings)
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
        stdout = sanitize_diagnostic(exc.stdout, settings)
        stderr = sanitize_diagnostic(exc.stderr, settings)
        details = "; ".join(value for value in
                             (f"stdout: {stdout}" if stdout else "",
                              f"stderr: {stderr}" if stderr else "") if value)
        hint = (" Verify the configured ACME account state and account key; "
                "no account was recreated."
                if "accountdoesnotexist" in (stdout + "\n" + stderr).casefold() else "")
        suffix = f"; {details}" if details else "; lego returned no diagnostic output"
        raise ValueError(
            f"lego signing failed with exit status {exc.returncode}{suffix}.{hint}"
        ) from None
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
