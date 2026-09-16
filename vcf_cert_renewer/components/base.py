"""Common adapter contract and normalized target model."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable


class Capability(str, Enum):
    DISCOVER_ONLY = "DISCOVER_ONLY"
    PLAN_ONLY = "PLAN_ONLY"
    FULL_RENEW = "FULL_RENEW"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class InventoryTarget:
    target_fqdn: str
    component_type: str
    appliance: str
    domain_id: str | None
    vcf_endpoint: str | None
    category: str
    certificate_resource_key: str | None
    management_level: str | None
    management_path: str
    adapter_name: str
    renewal_capability: str
    supports_generate_csr: bool
    supports_import: bool
    supports_replace: bool
    supported_reason: str
    live_https_status: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {"targetFqdn": data["target_fqdn"],
                "componentType": data["component_type"],
                "appliance": data["appliance"],
                "domainId": data["domain_id"],
                "vcfEndpoint": data["vcf_endpoint"],
                "category": data["category"],
                "certificateResourceKey": data["certificate_resource_key"],
                "managementLevel": data["management_level"],
                "managementPath": data["management_path"],
                "liveHttpsStatus": data["live_https_status"],
                "renewalCapability": data["renewal_capability"],
                "adapterName": data["adapter_name"],
                "supportsGenerateCsr": data["supports_generate_csr"],
                "supportsImport": data["supports_import"],
                "supportsReplace": data["supports_replace"],
                "supportedReason": data["supported_reason"]}


class ComponentAdapter:
    """Base adapter. Mutation methods refuse unless a subclass implements them."""

    name = "generic"
    component_type = "UNKNOWN"
    capability = Capability.UNSUPPORTED
    supports_generate_csr = False
    supports_import = False
    supports_replace = False
    management_path = "UNKNOWN"
    reason = "No verified certificate lifecycle API is available for this target."

    @classmethod
    def matches(cls, certificate: dict[str, Any]) -> bool:
        return False

    def discover_targets(self, certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        return [item for item in certificates if self.matches(item)]

    def generate_csr(self, client: Any, certificate: dict[str, Any]) -> Any:
        raise NotImplementedError(f"{self.name} does not support CSR generation")

    def import_certificate(self, client: Any, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError(f"{self.name} does not support certificate import")

    def replace_certificate(self, client: Any, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError(f"{self.name} does not support certificate replacement")

    def verify_endpoint(self, fqdn: str, verifier: Any, *, timeout: float) -> dict[str, Any]:
        try:
            result = verifier(fqdn, timeout=timeout)
            return {"reachable": True, "certificate": result}
        except (OSError, ValueError) as exc:
            return {"reachable": False, "reason": str(exc)}

    def normalize(self, certificate: dict[str, Any], live: dict[str, Any]) -> InventoryTarget:
        metadata = certificate.get("certificateMetadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        fqdn = str(certificate.get("applianceFqdn") or
                   certificate.get("issuedToCommonName") or "").rstrip(".").lower()
        management = (certificate.get("managementLevel") or
                      certificate.get("certificateManagementLevel") or
                      metadata.get("managementLevel"))
        return InventoryTarget(
            target_fqdn=fqdn, component_type=self.component_type,
            appliance=str(certificate.get("applianceFqdn") or fqdn),
            domain_id=str(certificate.get("domainId")) if certificate.get("domainId") else None,
            vcf_endpoint=str(certificate.get("vcfEndpoint")) if certificate.get("vcfEndpoint") else None,
            category=str(certificate.get("category") or ""),
            certificate_resource_key=(str(certificate.get("certificateResourceKey"))
                                      if certificate.get("certificateResourceKey") else None),
            management_level=str(management) if management else None,
            management_path=self.management_path, adapter_name=self.name,
            renewal_capability=self.capability.value,
            supports_generate_csr=self.supports_generate_csr,
            supports_import=self.supports_import,
            supports_replace=self.supports_replace,
            supported_reason=self.reason, live_https_status=live)
