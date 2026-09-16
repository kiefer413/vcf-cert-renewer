"""Read-only renewal planning."""
from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
import ipaddress
import re

import requests

from .certificates import find_leaf_tls_certificate
from .config import Settings
from .importer import list_imported_certificates
from .replacer import inspect_https_certificate
from .sddc_client import SddcApiClient


def _first(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value not in (None, "", [], {}):
            return value
    return None


def _matching_imports(records: list[dict[str, Any]], fqdn: str) -> list[dict[str, Any]]:
    wanted = fqdn.rstrip(".").casefold()
    matches = []
    for record in records:
        issued_to = str(_first(record, "issuedTo", "commonName", "issuedToCommonName") or "")
        dns = record.get("subjectAlternativeNames") or record.get("dnsNames") or []
        if isinstance(dns, dict):
            dns = dns.get("dns", [])
        names = [str(value).rstrip(".").casefold() for value in dns]
        if wanted in issued_to.casefold() or wanted in names:
            matches.append({
                "id": _first(record, "id", "thumbprint"),
                "thumbprint": record.get("thumbprint"),
                "issuedTo": _first(record, "issuedTo", "commonName"),
                "notAfter": _first(record, "notAfter", "validTo", "expiryDate"),
            })
    return matches


def _normalized_text(value: object) -> str:
    return " ".join(str(value).split()).casefold()


def _normalized_thumbprint(value: object) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value).casefold())


def _normalized_time(value: object) -> str:
    text = str(value).strip()
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        timestamp = float(text)
        if abs(timestamp) >= 100_000_000_000:
            timestamp /= 1000
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def compare_inventory_to_live(inventory: dict[str, Any],
                              live: dict[str, Any]) -> dict[str, Any]:
    """Classify agreement without treating absent Fleet metadata as conflict."""
    details: dict[str, str] = {}
    fields = (
        ("commonName", _normalized_text),
        ("sans", lambda value: {str(v).rstrip(".").casefold() for v in value}),
        ("issuer", _normalized_text),
        ("notBefore", _normalized_time),
        ("notAfter", _normalized_time),
        ("sha256Thumbprint", _normalized_thumbprint),
    )
    for name, normalizer in fields:
        left, right = inventory.get(name), live.get(name)
        if left in (None, "", []) or right in (None, "", []):
            details[name] = "UNKNOWN"
            continue
        try:
            equal = normalizer(left) == normalizer(right)
        except (TypeError, ValueError):
            equal = _normalized_text(left) == _normalized_text(right)
        details[name] = "MATCH" if equal else "MISMATCH"
    states = set(details.values())
    if "MISMATCH" in states:
        status = "MISMATCH"
    elif states == {"UNKNOWN"}:
        status = "UNKNOWN"
    elif "UNKNOWN" in states:
        status = "STALE_OR_INCOMPLETE_INVENTORY"
    else:
        status = "MATCH"
    return {"status": status, "fields": details}


def inventory_matches_live(inventory: dict[str, Any], live: dict[str, Any]) -> bool:
    """Backward-compatible boolean: false only for a proven field conflict."""
    return compare_inventory_to_live(inventory, live)["status"] != "MISMATCH"


def assemble_plan(fqdn: str, active: dict[str, Any], settings: Settings, *,
                  csr_exists: bool | None,
                  imported_certificates: list[dict[str, Any]],
                  live_certificate: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = active.get("certificateMetadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    level = _first(active, "managementLevel", "certificateManagementLevel", "managementType")
    level = level or _first(metadata, "managementLevel", "certificateManagementLevel", "managementType")
    customer_managed = _first(active, "customerManaged", "isCustomerManaged")
    if customer_managed is None:
        customer_managed = _first(metadata, "customerManaged", "isCustomerManaged")
    if customer_managed is None and level is not None:
        customer_managed = any(word in str(level).upper() for word in ("CUSTOMER", "EXTERNAL"))
    sans = active.get("subjectAlternativeNames")
    sans = sans.get("dns", []) if isinstance(sans, dict) else []
    inventory = {
        "certificateResourceKey": active.get("certificateResourceKey"),
        "commonName": _first(active, "issuedToCommonName", "applianceFqdn"),
        "issuer": _first(active, "issuer", "issuedBy", "issuerName") or _first(metadata, "issuer", "issuedBy"),
        "notBefore": _first(active, "notBefore", "validFrom"),
        "notAfter": _first(active, "notAfter", "validTo", "expiryDate"),
        "daysToExpire": active.get("daysToExpire"),
        "sans": [str(value) for value in sans],
        "sha256Thumbprint": _first(active, "sha256Thumbprint", "thumbprint"),
        "managementLevel": level,
        "customerManaged": customer_managed,
        "status": active.get("status"),
    }
    result = {
        "targetFqdn": fqdn.rstrip(".").lower(),
        "activeLeafTlsCertificate": inventory,
        "existingState": {
            "matchingCsrExists": csr_exists,
            "matchingImportedCertificates": _matching_imports(imported_certificates, fqdn),
        },
        "acme": {"mode": settings.acme_mode, "server": settings.acme_server},
        "expectedActions": ["Generate CSR", "Sign CSR", "Import", "Replace", "Verify"],
        "futureCertificate": {
            "status": "PLANNED_NOT_ISSUED",
            "note": "A future certificate is not represented as existing state.",
        },
        "notice": "No changes have been made.",
    }
    if live_certificate is not None:
        comparison = compare_inventory_to_live(inventory, live_certificate)
        status = comparison["status"]
        result["liveHttpsCertificate"] = live_certificate
        result["inventoryMatchesLive"] = (False if status == "MISMATCH" else
                                          True if status != "UNKNOWN" else None)
        result["inventoryComparisonStatus"] = status
        result["inventoryComparisonDetails"] = comparison["fields"]
        if status == "MISMATCH":
            result["warnings"] = [
                "Fleet certificate inventory conflicts with the live HTTPS certificate on one or more available fields."
            ]
        elif status == "STALE_OR_INCOMPLETE_INVENTORY":
            result["warnings"] = [
                "Fleet certificate inventory agrees on available fields but is incomplete or may be stale."
            ]
        elif status == "UNKNOWN":
            result["warnings"] = [
                "Fleet certificate inventory lacks enough comparable fields to confirm the live HTTPS certificate."
            ]
    return result


def build_plan(client: Any, settings: Settings, fqdn: str, *, page_size: int = 500) -> dict[str, Any]:
    """Inspect state using certificate query and GET operations only."""
    active = find_leaf_tls_certificate(client.query_certificates(page_size=page_size), fqdn)
    try:
        imported = list_imported_certificates(client)
    except (requests.RequestException, ValueError, OSError):
        imported = []
    certificate_id = active.get("certificateResourceKey")
    common_name = active.get("issuedToCommonName") or fqdn
    csr_exists: bool | None = None
    if isinstance(certificate_id, str) and certificate_id:
        try:
            client.fetch_csr(certificate_id, str(common_name))
            csr_exists = True
        except (requests.RequestException, ValueError, OSError):
            csr_exists = False
    live = inspect_https_certificate(
        fqdn, timeout=min(float(settings.timeout_seconds), 15.0))
    return assemble_plan(fqdn, active, settings, csr_exists=csr_exists,
                         imported_certificates=imported, live_certificate=live)


def build_domain_plan(client: SddcApiClient, settings: Settings, fqdn: str,
                      resource_type: str) -> dict[str, Any]:
    """Resolve a domain-managed resource with GETs and inspect HTTPS; never mutate."""
    domain_id, resource = client.resolve_context(fqdn, resource_type)
    live = inspect_https_certificate(fqdn, timeout=min(float(settings.timeout_seconds), 15.0))
    component = {"SDDC_MANAGER": "sddc", "VCENTER": "vcenter",
                 "NSXT_MANAGER": "nsx"}.get(resource_type, resource_type.lower())
    ip_sans = []
    for value in resource.get("sans", []):
        try:
            ip_sans.append(ipaddress.ip_address(value))
        except ValueError:
            pass
    blocked = [str(value) for value in ip_sans
               if value.is_private or value.is_reserved or not value.is_global]
    result = {
        "targetFqdn": fqdn.rstrip(".").lower(),
        "component": component,
        "domainId": domain_id, "resource": resource,
        "liveHttpsCertificate": live,
        "acme": {"mode": settings.acme_mode, "server": settings.acme_server},
        "expectedActions": ["Resolve domain resource", "Generate domain CSR",
                            "Poll CSR task", "Fetch matching CSR", "Sign CSR",
                            "Validate chain", "Replace resource certificate",
                            "Poll replacement task", "Verify HTTPS"],
        "notice": "No changes have been made.",
    }
    if blocked:
        result.update({
            "renewalCapability": "PLAN_ONLY",
            "unsupportedSans": blocked,
            "unsupportedReason": (
                "The official NSX certificate identity contains reserved/private IP SANs. "
                "A publicly trusted ACME CA cannot issue that complete identity; reducing "
                "the SAN set is forbidden, so renewal fails closed before CSR generation."),
        })
    return result


def build_sddc_plan(client: SddcApiClient, settings: Settings, fqdn: str) -> dict[str, Any]:
    return build_domain_plan(client, settings, fqdn, "SDDC_MANAGER")
