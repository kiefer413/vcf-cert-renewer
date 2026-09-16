"""VCF Operations adapter using the proven Fleet lifecycle."""
from __future__ import annotations
from typing import Any

from .base import Capability, ComponentAdapter


class OperationsAdapter(ComponentAdapter):
    name = "operations"
    component_type = "VCF_OPERATIONS"
    capability = Capability.FULL_RENEW
    supports_generate_csr = True
    supports_import = True
    supports_replace = True
    management_path = "FLEET_MANAGED"
    reason = "Proven Fleet CSR/import/replace workflow with live HTTPS verification."

    @classmethod
    def matches(cls, certificate: dict[str, Any]) -> bool:
        endpoint = str(certificate.get("vcfEndpoint") or "").upper()
        fqdn = str(certificate.get("applianceFqdn") or "").lower()
        return endpoint == "INTEGRATED_OPS_LCM" or fqdn.startswith("ops.")

    def generate_csr(self, client: Any, certificate: dict[str, Any]) -> Any:
        return client.create_csr(certificate)

    def import_certificate(self, client: Any, *args: Any, **kwargs: Any) -> Any:
        from ..importer import import_certificate_chain
        return import_certificate_chain(client, *args, **kwargs)

    def replace_certificate(self, client: Any, *args: Any, **kwargs: Any) -> Any:
        from ..replacer import replace_certificate
        return replace_certificate(client, *args, **kwargs)
