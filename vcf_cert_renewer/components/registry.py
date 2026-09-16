"""Ordered adapter selection and multi-component inventory services."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from typing import Any, Callable, Iterable

from ..replacer import inspect_https_certificate
from .base import ComponentAdapter
from .classified import (EsxiAdapter, GenericFleetAdapter, IdentityAdapter,
                         NsxAdapter, NsxNodeAdapter, OperationsNetworksAdapter, RuntimeAdapter,
                         SddcAdapter, SupervisorAdapter, VcenterAdapter)
from .operations import OperationsAdapter

ADAPTERS: tuple[type[ComponentAdapter], ...] = (
    OperationsAdapter, IdentityAdapter, OperationsNetworksAdapter,
    SupervisorAdapter, VcenterAdapter, NsxAdapter, NsxNodeAdapter, SddcAdapter,
    RuntimeAdapter, EsxiAdapter, GenericFleetAdapter,
)


def adapter_for(certificate: dict[str, Any]) -> ComponentAdapter:
    for adapter_type in ADAPTERS:
        if adapter_type.matches(certificate):
            return adapter_type()
    raise AssertionError("generic adapter must match")


def _leaf_tls(certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in certificates:
        metadata = item.get("certificateMetadata") or {}
        role = metadata.get("certificateChainRole") if isinstance(metadata, dict) else None
        if item.get("category") == "TLS_CERT" and role in (None, "LEAF"):
            result.append(item)
    return result


def _live(adapter: ComponentAdapter, item: dict[str, Any], verifier: Callable[..., dict[str, Any]],
          timeout: float) -> dict[str, Any]:
    fqdn = str(item.get("applianceFqdn") or item.get("issuedToCommonName") or "")
    try:
        ip_address(fqdn)
        return {"reachable": False, "reason": "IP-only inventory record; DNS/SNI verification skipped."}
    except ValueError:
        pass
    if not fqdn:
        return {"reachable": False, "reason": "No target hostname in Fleet record."}
    return adapter.verify_endpoint(fqdn, verifier, timeout=timeout)


def discover_inventory(client: Any, *, page_size: int = 500, timeout: float = 5.0,
                       verifier: Callable[..., dict[str, Any]] = inspect_https_certificate
                       ) -> list[dict[str, Any]]:
    """Normalize every Fleet leaf; certificate query and HTTPS handshakes only."""
    records = _leaf_tls(client.query_certificates(page_size=page_size))
    adapters = [adapter_for(item) for item in records]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(records)))) as pool:
        futures = [pool.submit(_live, adapter, item, verifier, timeout)
                   for adapter, item in zip(adapters, records)]
        live = [future.result() for future in futures]
    normalized = [adapter.normalize(item, status).as_dict()
                  for adapter, item, status in zip(adapters, records, live)]
    return sorted(normalized, key=lambda item: (item["componentType"], item["targetFqdn"]))


def plan_inventory(client: Any, *, page_size: int = 500, timeout: float = 5.0,
                   verifier: Callable[..., dict[str, Any]] = inspect_https_certificate
                   ) -> dict[str, Any]:
    targets = discover_inventory(client, page_size=page_size, timeout=timeout,
                                 verifier=verifier)
    return {"mode": "READ_ONLY", "targetCount": len(targets), "targets": targets,
            "mutatingCallsMade": False, "notice": "No changes have been made."}
