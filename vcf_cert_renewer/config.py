"""Central, layered application configuration with secret-safe errors."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

ACME_DIRECTORIES = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}
DEFAULT_CONFIG_PATH = Path("/etc/vcf-cert-renewer/config.yaml")
DEFAULT_SECRETS_PATH = Path("/etc/vcf-cert-renewer/secrets.env")
SECRET_ENV_NAMES = frozenset({
    "VCF_API_TOKEN", "SDDC_USERNAME", "SDDC_PASSWORD", "VCF_CLIENT_ID",
    "VCF_CLIENT_SECRET", "DNSUPDATE_TSIG_SECRET", "ACME_EAB_KID", "ACME_EAB_HMAC",
})
DEFAULTS: dict[str, Any] = {
    "VCF_TOKEN_ENDPOINT": "https://vcenter.vcf.example.com/acs/t/CUSTOMER/token",
    "VCF_URL": "https://ops.vcf.example.com", "VCF_VERIFY_TLS": True,
    "VCF_TIMEOUT_SECONDS": 30, "NSX_URL": "https://nsxt.vcf.example.com",
    "NSX_VERIFY_TLS": True, "SDDC_URL": "https://sddc.vcf.example.com",
    "CSR_COUNTRY": "US", "CSR_STATE": "California", "CSR_LOCALITY": "Los Angeles",
    "CSR_ORGANIZATION": "Example Organization", "CSR_ORGANIZATION_UNIT": "VCF",
    "ACME_MODE": "staging", "DNS_PROVIDER": "rfc2136",
    "DNSUPDATE_TSIG_ALGORITHM": "hmac-sha256.", "LEGO_PATH": "lego",
    "OUTPUT_DIR": "./out", "RENEW_BEFORE_DAYS": 30,
    "VCF_RENEW_TARGETS": (
        "ops.vcf.example.com,sddc.vcf.example.com,"
        "vcenter.vcf.example.com,nsxt.vcf.example.com"),
    "PUBLIC_DNS_RESOLVERS": "1.1.1.1:53,8.8.8.8:53",
}
YAML_KEYS = {
    "vcf.token_endpoint": "VCF_TOKEN_ENDPOINT", "vcf.url": "VCF_URL",
    "vcf.verify_tls": "VCF_VERIFY_TLS", "vcf.timeout_seconds": "VCF_TIMEOUT_SECONDS",
    "nsx.url": "NSX_URL", "nsx.verify_tls": "NSX_VERIFY_TLS", "sddc.url": "SDDC_URL",
    "csr.country": "CSR_COUNTRY", "csr.state": "CSR_STATE", "csr.locality": "CSR_LOCALITY",
    "csr.organization": "CSR_ORGANIZATION", "csr.organization_unit": "CSR_ORGANIZATION_UNIT",
    "acme.mode": "ACME_MODE", "acme.server": "ACME_SERVER", "acme.email": "ACME_EMAIL",
    "dns.provider": "DNS_PROVIDER", "dns.nameserver": "DNSUPDATE_NAMESERVER",
    "dns.tsig_key": "DNSUPDATE_TSIG_KEY", "dns.tsig_algorithm": "DNSUPDATE_TSIG_ALGORITHM",
    "paths.lego": "LEGO_PATH", "paths.output": "OUTPUT_DIR",
    "renew.threshold_days": "RENEW_BEFORE_DAYS",
    "renew.targets": "VCF_RENEW_TARGETS",
    "renew.public_dns_resolvers": "PUBLIC_DNS_RESOLVERS",
}


class ConfigurationError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _flatten(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, Mapping):
            result.update(_flatten(child, path))
        else:
            result[path] = child
    return result


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(
            f"Unable to load configuration file {path}: {type(exc).__name__}") from None
    if loaded is None:
        return {}
    if not isinstance(loaded, Mapping):
        raise ConfigurationError(f"Configuration file {path} must contain a YAML mapping")
    flattened = _flatten(loaded)
    unknown = sorted(set(flattened) - set(YAML_KEYS))
    if unknown:
        raise ConfigurationError(f"Unknown setting(s) in {path}: {', '.join(unknown)}")
    return {YAML_KEYS[key]: value for key, value in flattened.items()}


def _read_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(
            f"Unable to load secrets file {path}: {type(exc).__name__}") from None
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise ConfigurationError(f"Malformed secrets file {path} at line {number}")
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name not in SECRET_ENV_NAMES:
            raise ConfigurationError(
                f"Unsupported secret name in {path} at line {number}: {name}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        result[name] = value
    return result


def _bool(name: str, raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    token_url: str
    base_url: str
    verify_tls: bool
    timeout_seconds: float
    api_token: str | None
    nsx_url: str = "https://nsxt.vcf.example.com"
    nsx_verify_tls: bool = True
    sddc_url: str = "https://sddc.vcf.example.com"
    sddc_username: str | None = None
    sddc_password: str | None = None
    csr_country: str = "DK"
    csr_state: str = "Hovedstaden"
    csr_locality: str = "Copenhagen"
    csr_organization: str = "Example Organization"
    csr_organization_unit: str = "VCF"
    client_id: str | None = None
    client_secret: str | None = None
    acme_mode: str = "staging"
    acme_server: str = ACME_DIRECTORIES["staging"]
    acme_email: str | None = None
    acme_eab_kid: str | None = field(default=None, repr=False, kw_only=True)
    acme_eab_hmac: str | None = field(default=None, repr=False, kw_only=True)
    dns_provider: str = "rfc2136"
    dns_nameserver: str | None = None
    dns_tsig_key: str | None = None
    dns_tsig_algorithm: str = "hmac-sha256."
    dns_tsig_secret: str | None = None
    lego_path: Path = Path("lego")
    output_dir: Path = Path("out")
    renew_before_days: int = 30
    public_dns_resolvers: tuple[str, ...] = ("1.1.1.1:53", "8.8.8.8:53")
    renewal_targets: tuple[str, ...] = (
        "ops.vcf.example.com", "sddc.vcf.example.com",
        "vcenter.vcf.example.com", "nsxt.vcf.example.com")

    def __post_init__(self) -> None:
        if bool(self.acme_eab_kid) != bool(self.acme_eab_hmac):
            raise ConfigurationError(
                "ACME_EAB_KID and ACME_EAB_HMAC must both be set or both be empty")

    @classmethod
    def load(cls, *, config_path: Path | None = None,
             secrets_path: Path | None = None,
             overrides: Mapping[str, Any] | None = None,
             environ: Mapping[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        selected_config = config_path or Path(
            env.get("VCF_CONFIG_FILE", DEFAULT_CONFIG_PATH))
        selected_secrets = secrets_path or Path(
            env.get("VCF_SECRETS_FILE", DEFAULT_SECRETS_PATH))
        values = dict(DEFAULTS)
        values.update(_read_yaml(selected_config))
        values.update(_read_secrets(selected_secrets))
        if "VCF_TOKEN_URL" in env and "VCF_TOKEN_ENDPOINT" not in env:
            env["VCF_TOKEN_ENDPOINT"] = env["VCF_TOKEN_URL"]
        if "VCF_BASE_URL" in env and "VCF_URL" not in env:
            env["VCF_URL"] = env["VCF_BASE_URL"]
        if "DNSUPDATE_TSIG_KEY_NAME" in env and "DNSUPDATE_TSIG_KEY" not in env:
            env["DNSUPDATE_TSIG_KEY"] = env["DNSUPDATE_TSIG_KEY_NAME"]
        supported = (set(DEFAULTS) | set(SECRET_ENV_NAMES) |
                     {"ACME_SERVER", "ACME_EMAIL", "DNSUPDATE_NAMESERVER",
                      "DNSUPDATE_TSIG_KEY"})
        values.update({key: value for key, value in env.items()
                       if key in supported})
        values.update({key: value for key, value in (overrides or {}).items()
                       if value is not None})
        try:
            timeout = float(values["VCF_TIMEOUT_SECONDS"])
            renew_before = int(values["RENEW_BEFORE_DAYS"])
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "Timeout must be numeric and renewal threshold must be an integer") from exc
        if timeout <= 0 or renew_before < 0:
            raise ConfigurationError(
                "Timeout must be positive and renewal threshold zero or greater")
        mode = str(values["ACME_MODE"]).strip().lower()
        explicit_server = str(values.get("ACME_SERVER", "")).strip()
        if mode not in ACME_DIRECTORIES and not explicit_server:
            raise ConfigurationError(
                "ACME_MODE must be staging or production unless ACME_SERVER is set")
        server = explicit_server or ACME_DIRECTORIES[mode]
        if explicit_server == ACME_DIRECTORIES["staging"]:
            mode = "staging"
        elif explicit_server == ACME_DIRECTORIES["production"]:
            mode = "production"
        elif explicit_server:
            mode = "custom"
        resolver_source = values["PUBLIC_DNS_RESOLVERS"]
        resolver_values = (resolver_source if isinstance(resolver_source, list)
                           else str(resolver_source).split(","))
        resolvers = tuple(str(item).strip() for item in resolver_values
                          if str(item).strip())
        target_source = values["VCF_RENEW_TARGETS"]
        target_values = (target_source if isinstance(target_source, list)
                         else str(target_source).split(","))
        renewal_targets = tuple(str(item).strip().rstrip(".").lower()
                                for item in target_values if str(item).strip())
        if len(renewal_targets) != 4 or len(set(renewal_targets)) != 4:
            raise ConfigurationError(
                "VCF_RENEW_TARGETS must contain exactly four unique FQDNs")

        def value(name: str) -> Any:
            return values.get(name) or None

        return cls(
            token_url=str(values["VCF_TOKEN_ENDPOINT"]).rstrip("/"),
            base_url=str(values["VCF_URL"]).rstrip("/"),
            verify_tls=_bool("VCF_VERIFY_TLS", values["VCF_VERIFY_TLS"]),
            timeout_seconds=timeout, api_token=value("VCF_API_TOKEN"),
            nsx_url=str(values["NSX_URL"]).rstrip("/"),
            nsx_verify_tls=_bool("NSX_VERIFY_TLS", values["NSX_VERIFY_TLS"]),
            sddc_url=str(values["SDDC_URL"]).rstrip("/"),
            sddc_username=value("SDDC_USERNAME"),
            sddc_password=value("SDDC_PASSWORD"),
            csr_country=str(values["CSR_COUNTRY"]),
            csr_state=str(values["CSR_STATE"]),
            csr_locality=str(values["CSR_LOCALITY"]),
            csr_organization=str(values["CSR_ORGANIZATION"]),
            csr_organization_unit=str(values["CSR_ORGANIZATION_UNIT"]),
            client_id=value("VCF_CLIENT_ID"),
            client_secret=value("VCF_CLIENT_SECRET"),
            acme_mode=mode, acme_server=server,
            acme_email=value("ACME_EMAIL"),
            acme_eab_kid=str(values.get("ACME_EAB_KID") or "").strip() or None,
            acme_eab_hmac=str(values.get("ACME_EAB_HMAC") or "").strip() or None,
            dns_provider=str(values["DNS_PROVIDER"]).strip().lower(),
            dns_nameserver=value("DNSUPDATE_NAMESERVER"),
            dns_tsig_key=value("DNSUPDATE_TSIG_KEY"),
            dns_tsig_algorithm=str(values["DNSUPDATE_TSIG_ALGORITHM"]),
            dns_tsig_secret=value("DNSUPDATE_TSIG_SECRET"),
            lego_path=Path(str(values["LEGO_PATH"])),
            output_dir=Path(str(values["OUTPUT_DIR"])),
            renew_before_days=renew_before, public_dns_resolvers=resolvers,
            renewal_targets=renewal_targets)

    @classmethod
    def from_env(cls) -> "Settings":
        """Backwards-compatible entry point for existing environment users."""
        return cls.load()

    def require_api_token(self) -> str:
        if not self.api_token:
            raise ConfigurationError("VCF_API_TOKEN is not set")
        return self.api_token

    def require_sddc_credentials(self) -> tuple[str, str]:
        missing = [name for name, candidate in (
            ("SDDC_USERNAME", self.sddc_username),
            ("SDDC_PASSWORD", self.sddc_password)) if not candidate]
        if missing:
            raise ConfigurationError(
                f"Missing SDDC Manager credentials: {', '.join(missing)}")
        return self.sddc_username, self.sddc_password

    def require_oauth_credentials(self) -> tuple[str, str]:
        """Legacy compatibility helper; supported v1 flows do not call it."""
        if not self.client_id or not self.client_secret:
            raise ConfigurationError(
                "VCF_CLIENT_ID and VCF_CLIENT_SECRET must both be set")
        return self.client_id, self.client_secret
