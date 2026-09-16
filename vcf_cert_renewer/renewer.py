"""Safe one-command certificate renewal orchestration."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Callable

from .certificates import find_leaf_tls_certificate
from .client import VcfApiClient
from .config import Settings
from .fullchain import build_vcf_fullchain, predictable_fullchain_path
from .importer import import_certificate_chain
from .replacer import (inspect_https_certificate, poll_workflow,
                       replace_certificate, TlsVerificationError, verify_https_certificate)
from .sddc_client import SddcApiClient
from .signer import sign_csr

SUCCESS_STATES = {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"}
OPERATIONS_ACTIONS = [
    "Find Fleet TLS leaf", "Generate VCF CSR", "Fetch CSR", "Sign CSR via ACME",
    "Build and validate VCF fullchain", "Import certificate",
    "Replace certificate", "Poll workflow", "Verify live HTTPS",
]
DOMAIN_ACTIONS = [
    "Resolve domain resource", "Generate domain CSR", "Poll CSR task",
    "Fetch matching CSR", "Sign CSR via ACME", "Build and validate fullchain",
    "Validate resource certificate", "Replace resource certificate",
    "Poll replacement task", "Verify live HTTPS",
]
NSX_ACTIONS = ["Discover native MGMT_CLUSTER profile and assignment", "Generate NSX CSR",
               "Sign CSR via ACME", "Import signed chain into the NSX CSR",
               "Apply certificate only to MGMT_CLUSTER", "Verify assignment and live HTTPS"]


def _as_utc(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None
            else parsed.astimezone(timezone.utc))


def renewal_plan(settings: Settings, fqdn: str, *, force: bool = False,
                 now: datetime | None = None,
                 inspect: Callable[..., dict[str, Any]] = inspect_https_certificate
                 ) -> dict[str, Any]:
    live = inspect(fqdn, timeout=min(float(settings.timeout_seconds), 15.0))
    remaining = _as_utc(str(live["notAfter"])) - (now or datetime.now(timezone.utc))
    days = remaining.total_seconds() / 86400
    needed = force or days <= settings.renew_before_days
    from .components import adapter_for
    adapter = adapter_for({"applianceFqdn": fqdn})
    actions = (NSX_ACTIONS if adapter.management_path == "NSX_NATIVE_MGMT_CLUSTER" else
               DOMAIN_ACTIONS if adapter.management_path == "DOMAIN_MANAGED" else OPERATIONS_ACTIONS)
    return {
        "result": "RENEWAL_REQUIRED" if needed else "NO_RENEWAL_NEEDED",
        "targetFqdn": fqdn.rstrip(".").lower(),
        "liveHttpsCertificate": live, "daysRemaining": round(days, 2),
        "renewBeforeDays": settings.renew_before_days, "force": force,
        "acme": {"mode": settings.acme_mode, "server": settings.acme_server},
        "sans": live.get("sans", []), "plannedActions": actions,
        "notice": "No changes have been made.",
    }


def execute_domain_renewal(client: SddcApiClient, settings: Settings, fqdn: str, *,
                         resource_type: str,
                         poll_interval: float = 2,
                         poll_timeout: float = 900) -> dict[str, Any]:
    domain_id, resource = client.resolve_context(fqdn, resource_type)
    subject = {"country": settings.csr_country, "state": settings.csr_state,
               "locality": settings.csr_locality,
               "organization": settings.csr_organization,
               "organizationUnit": settings.csr_organization_unit,
               "keySize": 2048, "keyAlgorithm": "RSA"}
    request_id, _ = client.generate_csr(domain_id, resource, subject)
    client.wait_task(request_id, poll_interval=poll_interval,
                     poll_timeout=poll_timeout)
    csr = client.fetch_csr(domain_id, resource)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
    csr_path.write_text(csr, encoding="ascii")
    signed = sign_csr(settings, csr_path)
    fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
    build_vcf_fullchain(Path(str(signed["leafPath"])),
                        Path(str(signed["issuerPath"])), fullchain_path)
    chain = fullchain_path.read_text(encoding="ascii")
    validation = client.validate_certificate(domain_id, resource, chain,
                                             poll_interval=poll_interval,
                                             poll_timeout=poll_timeout)
    task_id, task = client.replace_certificate(domain_id, resource, chain,
                                               poll_interval=poll_interval,
                                               poll_timeout=poll_timeout)
    verification = verify_https_certificate(fqdn, chain.encode("ascii"))
    return {"result": "RENEWED", "targetFqdn": fqdn.rstrip(".").lower(),
            "domainId": domain_id, "resource": resource,
            "csrPath": str(csr_path), "fullchainPath": str(fullchain_path),
            "certificate": signed, "validationId": validation.get("validationId"),
            "taskId": task_id, "taskStatus": task.get("status"),
            "liveHttpsCertificate": verification}


def execute_sddc_renewal(client: SddcApiClient, settings: Settings, fqdn: str, *,
                         poll_interval: float = 2,
                         poll_timeout: float = 900) -> dict[str, Any]:
    """Compatibility wrapper for the production-validated SDDC path."""
    return execute_domain_renewal(
        client, settings, fqdn, resource_type="SDDC_MANAGER",
        poll_interval=poll_interval, poll_timeout=poll_timeout)


def _verify_nsx_mgmt_cluster(client: Any, fqdn: str, certificate_id: str,
                             expected_chain: bytes, *, poll_interval: float,
                             poll_timeout: float) -> dict[str, Any]:
    """Poll metadata and VIP HTTPS; the exact live leaf is final authority."""
    deadline = time.monotonic() + poll_timeout
    assignment: dict[str, Any] = {}
    last_error: TlsVerificationError | None = None
    while True:
        try:
            active = client.discover(fqdn).get("certificate") or {}
            active_id = active.get("id")
            assignment = {
                "status": "MATCHED" if active_id == certificate_id else "INCONCLUSIVE",
                "expectedCertificateId": certificate_id,
                "observedCertificateId": active_id,
                "usedBy": active.get("used_by") or [],
            }
        except (OSError, ValueError) as exc:
            assignment = {"status": "UNAVAILABLE", "diagnostic": str(exc)}
        try:
            live = verify_https_certificate(
                fqdn, expected_chain, retry_timeout=0,
                retry_interval=poll_interval)
            result = {"status": "SUCCEEDED", "authoritativeSource": "LIVE_HTTPS",
                      "assignmentMetadata": assignment,
                      "liveHttpsCertificate": live}
            if assignment.get("status") != "MATCHED":
                result["warning"] = (
                    "NSX assignment metadata was inconclusive, but live HTTPS "
                    "presented the exact expected certificate.")
            return result
        except TlsVerificationError as exc:
            last_error = exc
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = assignment.get("observedCertificateId") or assignment.get("status")
            raise TlsVerificationError(
                f"NSX VIP did not present the expected certificate within {poll_timeout:g}s; "
                f"assignment metadata: {detail}; last HTTPS result: {last_error}")
        time.sleep(min(poll_interval, remaining))


def execute_nsx_renewal(client: Any, settings: Settings, fqdn: str, *,
                        poll_interval: float = 10,
                        poll_timeout: float = 300) -> dict[str, Any]:
    client.discover(fqdn)
    sans = client.validate_dns_sans(fqdn, [fqdn])
    subject = {"country": settings.csr_country, "state": settings.csr_state,
               "locality": settings.csr_locality, "organization": settings.csr_organization,
               "organizationUnit": settings.csr_organization_unit}
    csr = client.create_csr(fqdn, sans, subject)
    csr_id, pem = csr.get("id"), csr.get("pem_encoded")
    if not isinstance(csr_id, str) or not isinstance(pem, str):
        raise ValueError("NSX CSR response lacks id or PEM")
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
    csr_path.write_text(pem, encoding="ascii")
    signed = sign_csr(settings, csr_path)
    fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
    build_vcf_fullchain(Path(str(signed["leafPath"])), Path(str(signed["issuerPath"])), fullchain_path)
    imported = client.import_csr_certificate(csr_id, fullchain_path.read_text(encoding="ascii"))
    certificate_id = imported.get("id")
    if not isinstance(certificate_id, str):
        raise ValueError("NSX imported certificate lacks id")
    client.apply_mgmt_cluster(certificate_id)
    verification = _verify_nsx_mgmt_cluster(
        client, fqdn, certificate_id, fullchain_path.read_bytes(),
        poll_interval=poll_interval, poll_timeout=poll_timeout)
    live_thumbprint = str(verification["liveHttpsCertificate"]["sha256_thumbprint"])
    return {"result": "RENEWED", "targetFqdn": fqdn.rstrip(".").lower(),
            "serviceType": "MGMT_CLUSTER", "certificateId": certificate_id,
            "csrPath": str(csr_path), "fullchainPath": str(fullchain_path),
            "certificate": signed,

            "expectedThumbprint": str(signed["sha256Thumbprint"]),
            "liveThumbprint": live_thumbprint, "verification": verification,
            "liveHttpsCertificate": verification["liveHttpsCertificate"],
            "apiCertificatesTouched": False}


def execute_renewal(client: VcfApiClient, settings: Settings, fqdn: str, *,
                    poll_interval: float = 2, poll_timeout: float = 900) -> dict[str, Any]:
    active = find_leaf_tls_certificate(client.query_certificates(), fqdn)
    certificate_id = active.get("certificateResourceKey")
    common_name = active.get("issuedToCommonName") or fqdn
    if not isinstance(certificate_id, str) or not certificate_id:
        raise ValueError("discovered certificate has no certificateResourceKey")
    request_id, initial = client.create_csr(active)
    if client._state(initial) not in SUCCESS_STATES:
        client.wait_for_csr(request_id, poll_interval=poll_interval,
                            poll_timeout=poll_timeout)
    csr = client.fetch_csr(certificate_id, str(common_name))
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
    csr_path.write_text(csr, encoding="ascii")
    signed = sign_csr(settings, csr_path)
    fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
    build_vcf_fullchain(Path(str(signed["leafPath"])),
                        Path(str(signed["issuerPath"])), fullchain_path)
    imported = import_certificate_chain(
        client, fullchain_path.read_bytes(), fqdn, filename=fullchain_path.name)
    replace_request, replace_initial, chain = replace_certificate(
        client, fqdn, thumbprint=str(signed["sha256Thumbprint"]),
        search_paths=[fullchain_path])
    workflow = replace_initial
    if client._state(replace_initial) not in SUCCESS_STATES:
        workflow = poll_workflow(client, replace_request,
                                 poll_interval=poll_interval,
                                 poll_timeout=poll_timeout)
    verification = verify_https_certificate(fqdn, chain)
    return {
        "result": "RENEWED", "targetFqdn": fqdn.rstrip(".").lower(),
        "csrPath": str(csr_path), "fullchainPath": str(fullchain_path),
        "certificate": signed, "import": imported,
        "replaceRequestId": replace_request,
        "workflowState": client._state(workflow),
        "liveHttpsCertificate": verification,
    }
