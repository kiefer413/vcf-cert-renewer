"""Read-only component adapters; mutation stays disabled until officially verified."""
from __future__ import annotations
from typing import Any

from .base import Capability, ComponentAdapter


def _fqdn(item: dict[str, Any]) -> str:
    return str(item.get("applianceFqdn") or "").lower()


def _text(item: dict[str, Any]) -> str:
    metadata = item.get("certificateMetadata") or {}
    return " ".join(str(item.get(name) or "") for name in
                    ("applianceFqdn", "issuedToCommonName", "vcfEndpoint")
                    ) + " " + str(metadata.get("certificateChainGroupId") or "")


class SddcAdapter(ComponentAdapter):
    name, component_type = "sddc", "SDDC_MANAGER"
    capability, management_path = Capability.FULL_RENEW, "DOMAIN_MANAGED"
    supports_generate_csr = True
    supports_import = True
    supports_replace = True
    reason = "Official domain-scoped SDDC Manager CSR/validation/replacement APIs."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return _fqdn(item).startswith("sddc.")


class VcenterAdapter(ComponentAdapter):
    name, component_type = "vcenter", "VCENTER"
    capability, management_path = Capability.FULL_RENEW, "DOMAIN_MANAGED"
    supports_generate_csr = True
    supports_import = True
    supports_replace = True
    reason = "Official domain-scoped vCenter CSR/validation/replacement APIs."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return "vcenter" in _fqdn(item) or "VCENTER" in _text(item).upper()


class NsxAdapter(ComponentAdapter):
    name, component_type = "nsx", "NSXT_MANAGER"
    capability, management_path = Capability.FULL_RENEW, "NSX_NATIVE_MGMT_CLUSTER"
    supports_generate_csr = True
    supports_import = True
    supports_replace = True
    reason = "Production-validated native NSX MGMT_CLUSTER CSR/import/apply API."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        fqdn = _fqdn(item)
        return fqdn.startswith("nsxt.")


class NsxNodeAdapter(ComponentAdapter):
    name, component_type = "nsx_node", "NSXT_MANAGER_API"
    capability, management_path = Capability.PLAN_ONLY, "NSX_NATIVE_API"
    reason = "NSX node/API certificates are intentionally outside the MGMT_CLUSTER VIP adapter."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        text = _text(item).lower()
        return "nsxt" in text or "nsx" in text


class IdentityAdapter(ComponentAdapter):
    name, component_type = "identity", "IDENTITY_BROKER_ACS"
    capability, management_path = Capability.PLAN_ONLY, "RUNTIME_MANAGED"
    reason = "Identity/ACS endpoint is discoverable; no verified mutation API is configured."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        text = _text(item).lower()
        return any(value in text for value in ("idbroker", "identity", "vidb", "acs"))


class OperationsNetworksAdapter(ComponentAdapter):
    name, component_type = "operations_networks", "OPERATIONS_FOR_NETWORKS"
    capability, management_path = Capability.DISCOVER_ONLY, "FLEET_DISCOVERED"
    reason = "Operations for Networks record found; endpoint is not a verified DNS TLS mutation target."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return "OPS_NETWORKS" in _text(item).upper()


class SupervisorAdapter(ComponentAdapter):
    name, component_type = "supervisor", "SUPERVISOR"
    capability, management_path = Capability.PLAN_ONLY, "DOMAIN_MANAGED"
    reason = "Supervisor endpoint is discoverable; certificate mutation is not enabled."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return "supervisor" in _text(item).lower()


class RuntimeAdapter(ComponentAdapter):
    name, component_type = "runtime", "RUNTIME_AUTOMATION"
    capability, management_path = Capability.PLAN_ONLY, "RUNTIME_MANAGED"
    reason = "Runtime/automation endpoint is discoverable; component-specific writes are disabled."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        text = _text(item).lower()
        return any(value in text for value in
                   ("runtime", "automation", "flmc", "instance", "loginsight"))


class EsxiAdapter(ComponentAdapter):
    name, component_type = "esxi", "ESXI"
    capability, management_path = Capability.UNSUPPORTED, "DOMAIN_MANAGED"
    reason = "ESXi leaf is inventoried but outside this phase's requested mutation coverage."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return _fqdn(item).startswith("esx")


class GenericFleetAdapter(ComponentAdapter):
    name, component_type = "generic_fleet", "OTHER_FLEET_TLS"
    capability, management_path = Capability.DISCOVER_ONLY, "FLEET_DISCOVERED"
    reason = "Fleet TLS leaf discovered but component type could not be safely classified."
    @classmethod
    def matches(cls, item: dict[str, Any]) -> bool:
        return True
