"""External Automation TLS support through the shared Fleet lifecycle."""
from typing import Any

from .base import Capability, ComponentAdapter
from .operations import OperationsAdapter
from ..certificates import AUTOMATION_APPLIANCES, is_automation_external_tls


class AutomationAdapter(OperationsAdapter):
    name = "automation"
    component_type = "VCF_AUTOMATION"
    reason = "External CA TLS only; Fleet CSR/import/replace with live HTTPS verification."

    @classmethod
    def matches(cls, certificate: dict[str, Any]) -> bool:
        return (is_automation_external_tls(certificate)
                and certificate["certificateMetadata"].get("managementLevel")
                == "CUSTOMER_MANAGED_FULL_MANAGEMENT")


class InternalAutomationAdapter(ComponentAdapter):
    name = "automation_internal"
    component_type = "VCF_AUTOMATION"
    capability = Capability.DISCOVER_ONLY
    management_path = "RUNTIME_MANAGED"
    reason = "Internal or ineligible Automation certificate; replacement is out of scope."

    @classmethod
    def matches(cls, certificate: dict[str, Any]) -> bool:
        return certificate.get("appliance") in AUTOMATION_APPLIANCES
