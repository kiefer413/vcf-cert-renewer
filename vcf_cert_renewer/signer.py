"""Non-interactive lego/ACME signing of VCF-generated CSRs."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Any
import re
from urllib.parse import quote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .config import ConfigurationError, Settings, SECRET_ENV_NAMES, SECRET_FILE_NAMES
from .diagnostics import ACME_PROBLEM_CATEGORIES, LegoSigningError
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
    missing = [name for name, value in required.items() if not value or not value.strip()]
    if missing:
        raise ConfigurationError("missing signer configuration: " + ", ".join(missing))
    _validate_signer_configuration(settings)
    if settings.dns_provider not in {"rfc2136", "dnsupdate"}:
        raise ConfigurationError("DNS_PROVIDER must be rfc2136 (legacy lego) or dnsupdate (lego v5)")


def lego_command(settings: Settings, csr_path: Path) -> tuple[list[str], dict[str, str]]:
    """Build argv/environment; argv and error messages never contain secrets."""
    validate_signer_configuration(settings)
    account_path = settings.output_dir / "acme" / settings.acme_mode
    command = [
        str(settings.lego_path), "run", "--accept-tos", "--ari-disable", "--email", str(settings.acme_email),
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


_ACME_HEADER = re.compile(
    r"\bacme: error: (?P<status>[0-9]{1,3}) :: (?:(?P<method>[A-Z]*) :: (?P<url>[^\s]*) :: )?"
    r"urn:ietf:params:acme:error:(?P<problem>[A-Za-z][A-Za-z0-9]*) ::",
    re.IGNORECASE,
)
_LOCAL_ERRORS = (
    ("DNS_PROVIDER_CONFIGURATION", r"""["'](?:dnsupdate|rfc2136)["'] is not yet supported"""),
    ("DNS_UPDATE_FAILURE", r"dnsupdate: failed to (?:insert|remove):|dns update failed:"),
    ("DNS_PROPAGATION_FAILURE", r"propagation: time limit exceeded|timeout waiting for dns propagation|dns propagation timed out"),
    ("ACME_ACCOUNT_ERROR", r"(?:could not|failed to) (?:load|register) (?:the )?account"),
    ("CSR_VALIDATION_ERROR", r"(?:could not|failed to) (?:parse|read|validate) (?:the )?csr|invalid csr signature"),
    ("NETWORK_TLS_ERROR", r"x509: certificate (?:signed by unknown authority|has expired)|tls: handshake failure|tls handshake timeout|dial (?:tcp|udp)[^\n]*: (?:i/o timeout|connect: (?:connection refused|network is unreachable))"),
)


def _acme_operation(method: str | None, url: str | None) -> str | None:
    if method != "POST" or not url or "?" in url or "#" in url or any(
            ord(char) < 33 or ord(char) > 126 for char in url):
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme != "https" or parsed.netloc not in {
            "acme-v02.api.letsencrypt.org", "acme-staging-v02.api.letsencrypt.org"}:
        return None
    for pattern, operation in (
        (r"/acme/new-order", "NEW_ORDER"),
        (r"/acme/(?:new-acct|acct/[0-9]+)", "ACCOUNT"),
        (r"/acme/authz/[0-9]+/[0-9]+", "AUTHORIZATION"),
        (r"/acme/chall/[0-9]+/[0-9]+/[A-Za-z0-9_-]+", "CHALLENGE"),
        (r"/acme/authz-v3/[0-9]+", "AUTHORIZATION"),
        (r"/acme/chall-v3/[0-9]+/[A-Za-z0-9_-]+", "CHALLENGE"),
        (r"/acme/finalize/[0-9]+/[0-9]+", "FINALIZE"),
    ):
        if re.fullmatch(pattern, parsed.path):
            return operation
    return None


_STAGE_WRAPPERS = (
    (r"(?:set up account|registration|resolve account by key|could not complete registration): ", "ACCOUNT"),
    (r"invalid authorization: ", "AUTHORIZATION_VALIDATION"),
    (r"invalid challenge: ", "CHALLENGE_VALIDATION"),
    (r"failed to initiate the challenge: ", "CHALLENGE_ACCEPTANCE"),
    (r"dns01: error presenting token \([A-Za-z0-9.*_-]+\): ", "DNS_PRESENTATION"),
    (r"dns01: time limit exceeded(?=: |$)", "DNS_PROPAGATION"),
)
_GENERIC_WRAPPER = re.compile(
    r"(?:renew certificate|obtain certificate|CSR|could not obtain the certificate): "
    r"|(?:resolver|certificates): one or more domains had a problem: \["
    r"[A-Za-z0-9.*_-]+: "
)
_COLOR_SEQUENCE = re.compile(r"\x1b\[[0-9;]*m")
_FATAL_TEXT = re.compile(
    r"^(?:\S+\s+ERROR\s+Error|time=\S+ level=ERROR msg=Error)\s+error=(.*)$"
)


def _stage_wrappers(line: str) -> set[str]:
    """Inspect only the start of an error chain, never its opaque detail."""
    text = _COLOR_SEQUENCE.sub("", line).strip()
    if text.startswith("{"):
        try:
            event = json.loads(text)
        except ValueError:
            return set()
        if not isinstance(event, dict) or event.get("msg") != "Error" or event.get("level") != "ERROR":
            return set()
        text = event.get("error")
        if not isinstance(text, str):
            return set()
    elif match := _FATAL_TEXT.fullmatch(text):
        text = match[1]
        if text.startswith('"'):
            try:
                text = json.loads(text)
            except ValueError:
                return set()
    if "] [" in text or "\n" in text:
        return set()
    stages = set()
    while text:
        generic = _GENERIC_WRAPPER.match(text)
        if generic:
            text = text[generic.end():]
            continue
        for pattern, stage in _STAGE_WRAPPERS:
            match = re.match(pattern, text)
            if match:
                text = text[match.end():]
                if not text and stage != "DNS_PROPAGATION":
                    return set()
                stages.add(stage)
                break
        else:
            return stages
    return stages


def _classify_lego_failure(error: subprocess.CalledProcessError) -> LegoSigningError:
    evidence = set()
    ambiguous = False
    stages = set()
    for stream in (error.stderr, error.stdout):
        if not isinstance(stream, str):
            continue
        for line in stream.splitlines():
            stages.update(_stage_wrappers(line))
            headers = list(_ACME_HEADER.finditer(line))
            if len(headers) > 1:
                ambiguous = True
                continue
            prefix = line[:headers[0].start()] if headers else line
            for category, pattern in _LOCAL_ERRORS:
                if re.search(pattern, prefix.casefold()):
                    evidence.add((category, None, None, None, None))
            if headers:
                header = headers[0]
                problem = header["problem"].lower()
                category = ACME_PROBLEM_CATEGORIES.get(problem)
                if category is None:
                    ambiguous = True
                else:
                    method, url = header["method"], header["url"]
                    operation = _acme_operation(method, url)
                    context = ("RECOGNIZED_ROUTE" if operation else
                               "UNRECOGNIZED_ROUTE" if method or url else "NO_HTTP_CONTEXT")
                    status = int(header["status"])
                    if not method or not url or not 400 <= status <= 599:
                        status = None
                    evidence.add((category, problem, operation, context, status))
    stage = next(iter(stages)) if len(stages) == 1 else None
    if ambiguous or len(evidence) > 1:
        return LegoSigningError(error.returncode, "UNKNOWN_ACME_ERROR")
    if not evidence:
        return LegoSigningError(error.returncode, "UNKNOWN_ACME_ERROR", stage=stage)
    category, problem, operation, context, status = evidence.pop()
    return LegoSigningError(error.returncode, category, problem, operation,
                            http_context=context, problem_status=status, stage=stage)


def verify_lego_provider(settings: Settings) -> None:
    """Check the binary's provider registry without passing signing credentials."""
    try:
        result = subprocess.run(
            [str(settings.lego_path), "dnshelp", "-c", settings.dns_provider],
            env={"PATH": os.environ.get("PATH", os.defpath)}, check=False, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigurationError("Could not check lego DNS provider support.") from None
    if result.returncode != 0:
        raise ConfigurationError("Installed lego does not support the configured DNS_PROVIDER.")


def sign_csr(settings: Settings, csr_path: Path) -> dict[str, Any]:
    csr_path = csr_path.resolve()
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    names = csr_names(csr_path)
    command, environment = lego_command(settings, csr_path)
    verify_lego_provider(settings)
    account_path = settings.output_dir / "acme" / settings.acme_mode
    account_path.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            command, env=environment, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        raise _classify_lego_failure(exc) from None
    leaf_path = _matching_leaf(account_path, csr)
    issuer_path = leaf_path.with_name(
        leaf_path.name.removesuffix(".crt") + ".issuer.crt")
    if not issuer_path.exists():
        raise ValueError("lego did not produce the issuer certificate")
    return _signed_summary(settings, names[0], leaf_path, issuer_path, "SIGNED")


def _signed_summary(settings, fqdn, leaf_path, issuer_path, result):
    certificates, info = parse_certificate_chain(leaf_path.read_bytes())
    leaf = certificates[0]
    not_before = getattr(leaf, "not_valid_before_utc", None) or leaf.not_valid_before
    not_after = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after
    return {
        "result": result, "fqdn": fqdn,
        "leafPath": str(leaf_path), "issuerPath": str(issuer_path),
        "sans": list(info.dns_names), "issuer": leaf.issuer.rfc4514_string(),
        "notBefore": not_before.isoformat(), "notAfter": not_after.isoformat(),
        "sha256Thumbprint": leaf.fingerprint(hashes.SHA256()).hex(),
        "acmeMode": settings.acme_mode, "acmeServer": settings.acme_server,
    }

def reuse_signed_csr(settings: Settings, target: str, csr_path: Path) -> dict[str, Any]:
    """Use an explicitly requested, trusted local leaf; never fall back to ACME."""
    fqdn = target.rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:[.][a-z0-9-]+)+", fqdn):
        raise ValueError("Existing certificate reuse requires a DNS FQDN")
    directory = settings.output_dir / "acme" / settings.acme_mode / "certificates"
    leaf_path = directory / f"{fqdn}.crt"
    issuer_path = directory / f"{fqdn}.issuer.crt"
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    if not csr.is_signature_valid:
        raise ValueError("Existing certificate reuse requires a valid CSR signature")

    def identities(obj):
        try:
            sans = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            raise ValueError("Existing certificate reuse requires DNS SANs") from None
        if not all(isinstance(name, x509.DNSName) for name in sans):
            raise ValueError("Existing certificate reuse requires DNS-only SANs")
        return {name.value.rstrip(".").lower() for name in sans}

    leaf = parse_certificate_chain(leaf_path.read_bytes())[0][0]
    names = identities(csr)
    if fqdn not in names or names != identities(leaf):
        raise ValueError("Existing certificate DNS SANs do not match the target and CSR")
    encoding = serialization.Encoding.DER
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    if csr.public_key().public_bytes(encoding, fmt) != leaf.public_key().public_bytes(encoding, fmt):
        raise ValueError("Existing certificate public key does not match the CSR")
    now = datetime.now(timezone.utc)
    before = getattr(leaf, "not_valid_before_utc", None) or leaf.not_valid_before.replace(tzinfo=timezone.utc)
    after = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after.replace(tzinfo=timezone.utc)
    if before > now or after <= now + timedelta(days=settings.renew_before_days):
        raise ValueError("Existing certificate is not yet valid, expired, or within the renewal window")
    # OpenSSL verify uses local trust and never downloads AIA certificates.
    parse_certificate_chain(issuer_path.read_bytes())
    try:
        subprocess.run(["openssl", "verify", "-purpose", "sslserver",
                        "-untrusted", str(issuer_path.resolve()), str(leaf_path.resolve())],
                       check=True, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Existing certificate failed local TLS chain verification") from None
    return _signed_summary(settings, fqdn, leaf_path, issuer_path, "REUSED")
