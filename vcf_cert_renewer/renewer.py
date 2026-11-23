"""Safe one-command certificate renewal orchestration."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Callable

from .certificates import is_automation_external_tls, resolve_fleet_certificate
from .client import (CsrNotFoundError, VcfApiClient, WorkflowFailedError)
from .config import Settings
from .diagnostics import attach_diagnostic, safe_exception_message
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
                         poll_timeout: float = 900,
                         operation=None) -> dict[str, Any]:
    def stage(name: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            existing = getattr(exc, "renewal_diagnostic", None)
            event = dict(existing) if isinstance(existing, dict) else {}
            event.update({
                "component": resource_type.upper(), "targetFqdn": fqdn.rstrip(".").lower(),
                "phase": "RENEW", "stage": name, "errorType": type(exc).__name__,
                "safeMessage": safe_exception_message(exc),
            })
            event.setdefault("operation", name)
            attach_diagnostic(exc, event)
            raise

    domain_id, resource = stage("RESOURCE_DISCOVERY", client.resolve_context, fqdn, resource_type)
    subject = {"country": settings.csr_country, "state": settings.csr_state,
               "locality": settings.csr_locality,
               "organization": settings.csr_organization,
               "organizationUnit": settings.csr_organization_unit,
               "keySize": 2048, "keyAlgorithm": "RSA"}
    request_id, _ = stage("CSR_GENERATION", client.generate_csr, domain_id, resource, subject)
    stage("CSR_TASK_POLLING", client.wait_task, request_id,
          poll_interval=poll_interval, poll_timeout=poll_timeout)
    csr = stage("CSR_RETRIEVAL", client.fetch_csr, domain_id, resource)
    stage("CSR_WRITE", settings.output_dir.mkdir, parents=True, exist_ok=True)
    csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
    stage("CSR_WRITE", csr_path.write_text, csr, encoding="ascii")
    if operation is not None:
        stage("CSR_IDENTITY", operation.validate_csr, csr_path)
    signed = stage("ACME_SIGNING", sign_csr, settings, csr_path)

    def construct_chain() -> tuple[Path, str]:
        fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
        build_vcf_fullchain(Path(str(signed["leafPath"])),
                            Path(str(signed["issuerPath"])), fullchain_path)
        return fullchain_path, fullchain_path.read_text(encoding="ascii")

    fullchain_path, chain = stage("CERTIFICATE_CHAIN_CONSTRUCTION", construct_chain)
    if operation is not None:
        chain = stage("ISSUED_CERTIFICATE", operation.validate_issued, settings, csr_path, fullchain_path)
    validation = stage("CERTIFICATE_VALIDATION", client.validate_certificate,
                       domain_id, resource, chain, poll_interval=poll_interval,
                       poll_timeout=poll_timeout)
    replace_resource = client.replace_certificate if operation is None else operation.replace_vcenter
    task_id, task = stage("CERTIFICATE_REPLACEMENT", replace_resource,
                          domain_id, resource, chain, poll_interval=poll_interval,
                          poll_timeout=poll_timeout)
    verification = stage("POST_INSTALLATION_VERIFICATION", verify_https_certificate,
                         fqdn, chain.encode("ascii"))
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
                        poll_timeout: float = 300,
                        operation=None) -> dict[str, Any]:
    target = fqdn.rstrip(".").lower()
    if hasattr(client, "set_target"):
        client.set_target(target)

    def stage(operation: str, function: Callable[..., Any], *args: Any,
              **kwargs: Any) -> Any:
        started = time.monotonic()
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            current = getattr(exc, "renewal_diagnostic", None)
            event = dict(current) if isinstance(current, dict) else {}
            event.update({"component": "NSX_MANAGER", "targetFqdn": target,
                          "phase": "RENEW", "operation": operation,
                          "errorType": type(exc).__name__,
                          "safeMessage": safe_exception_message(exc)})
            elapsed = round(max(0.0, time.monotonic() - started), 3)
            if "httpMethod" in event:
                event["stageElapsedSeconds"] = elapsed
            else:
                event["elapsedSeconds"] = elapsed
            attach_diagnostic(exc, event)
            raise

    stage("DISCOVER_MGMT_CLUSTER", client.discover, fqdn)
    sans = stage("VALIDATE_VIP_DNS_IDENTITY", client.validate_dns_sans, fqdn, [fqdn])
    subject = {"country": settings.csr_country, "state": settings.csr_state,
               "locality": settings.csr_locality, "organization": settings.csr_organization,
               "organizationUnit": settings.csr_organization_unit}
    csr = stage("GENERATE_CSR", client.create_csr, fqdn, sans, subject)

    def unpack_csr() -> tuple[str, str]:
        csr_id_value, pem_value = csr.get("id"), csr.get("pem_encoded")
        if not isinstance(csr_id_value, str) or not isinstance(pem_value, str):
            raise ValueError("NSX CSR response lacks id or PEM")
        return csr_id_value, pem_value

    csr_id, pem = stage("GENERATE_CSR", unpack_csr)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
    csr_path.write_text(pem, encoding="ascii")
    if operation is not None:
        stage("CSR_IDENTITY", operation.validate_csr, csr_path)
    signed = stage("ACME_SIGNING", sign_csr, settings, csr_path)
    fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
    stage("CERTIFICATE_CHAIN_CONSTRUCTION", build_vcf_fullchain,
          Path(str(signed["leafPath"])), Path(str(signed["issuerPath"])), fullchain_path)
    chain = (fullchain_path.read_text(encoding="ascii") if operation is None else
             stage("ISSUED_CERTIFICATE", operation.validate_issued, settings, csr_path, fullchain_path))
    imported = stage("CERTIFICATE_IMPORT", client.import_csr_certificate, csr_id, chain)

    def unpack_import() -> str:
        certificate_id_value = imported.get("id")
        if not isinstance(certificate_id_value, str):
            raise ValueError("NSX imported certificate lacks id")
        return certificate_id_value

    certificate_id = stage("CERTIFICATE_IMPORT", unpack_import)
    apply_cluster = client.apply_mgmt_cluster if operation is None else operation.apply_nsx
    stage("APPLY_MGMT_CLUSTER_CERTIFICATE", apply_cluster, certificate_id)
    verification = stage(
        "POST_INSTALLATION_VERIFICATION", _verify_nsx_mgmt_cluster,
        client, fqdn, certificate_id, chain.encode("ascii"),
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


class RenewalExecutionError(RuntimeError):
    """A failed Fleet renewal with truthful completed-mutation state."""

    def __init__(self, phase: str, completed_mutations: list[str],
                 replacement_requested: bool, replacement_completed: bool,
                 mutation_outcome_unknown: bool, cause: Exception) -> None:
        self.phase = phase
        self.completed_mutations = tuple(completed_mutations)
        self.replacement_requested = replacement_requested
        self.replacement_completed = replacement_completed
        self.mutation_outcome_unknown = mutation_outcome_unknown
        self.cause = cause
        super().__init__(f"Renewal failed during {phase}")


def execute_renewal(client: VcfApiClient, settings: Settings, fqdn: str, *,
                    poll_interval: float = 2, poll_timeout: float = 900,
                    certificate: dict[str, Any] | None = None, operation=None) -> dict[str, Any]:
    """Run the Fleet flow, safely reuse a matching Automation CSR and track mutations."""
    phase = "Fleet certificate discovery"
    completed_mutations: list[str] = []
    replacement_requested = False
    replacement_completed = False
    mutation_outcome_unknown = False

    def mark_mutation_attempted() -> None:
        nonlocal mutation_outcome_unknown
        mutation_outcome_unknown = True

    try:
        active = resolve_fleet_certificate(client.query_certificates(), fqdn,
                                           expected_certificate=certificate)
        selected = {"expected_certificate": active}
        certificate_id = active.get("certificateResourceKey")
        common_name = active.get("issuedToCommonName") or fqdn
        if not isinstance(certificate_id, str) or not certificate_id:
            raise ValueError("discovered certificate has no certificateResourceKey")

        automation = is_automation_external_tls(active)
        appliance = str(active.get("appliance") or "")
        csr = None
        reused_csr = False
        if automation:
            phase = "matching Fleet CSR lookup"
            try:
                csr = client.fetch_csr(certificate_id, str(common_name),
                                       expected_fqdn=fqdn, strict_dns_san=True,
                                       appliance=appliance,
                                       component=str(active.get("vcfComponent") or "") or None)
                reused_csr = True
            except CsrNotFoundError:
                pass

        if csr is None:
            phase = "Fleet CSR generation"
            request_id, initial = client.create_csr(
                active, on_mutation_attempt=mark_mutation_attempted)
            mutation_outcome_unknown = False
            completed_mutations.append("Fleet CSR generation requested")
            if client._state(initial) in {"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}:
                raise WorkflowFailedError("Fleet CSR generation failed")
            if client._state(initial) not in SUCCESS_STATES:
                client.wait_for_csr(request_id, poll_interval=poll_interval,
                                    poll_timeout=poll_timeout)
            completed_mutations[-1] = "Fleet CSR generated"
            phase = "Fleet CSR fetch and identity validation"
            csr = client.fetch_csr(certificate_id, str(common_name),
                                   expected_fqdn=fqdn if automation else None,
                                   strict_dns_san=automation,
                                   appliance=appliance if automation else None,
                                   component=(str(active.get("vcfComponent") or "") or None)
                                   if automation else None)

        settings.output_dir.mkdir(parents=True, exist_ok=True)
        csr_path = settings.output_dir / f"{fqdn.rstrip('.').lower()}.csr.pem"
        csr_path.write_text(csr, encoding="ascii")
        if operation is not None:
            phase = "CSR identity validation"
            operation.validate_csr(csr_path)
        phase = "ACME signing"
        signed = sign_csr(settings, csr_path)
        phase = "certificate chain construction"
        fullchain_path = predictable_fullchain_path(settings.output_dir, fqdn)
        build_vcf_fullchain(Path(str(signed["leafPath"])),
                            Path(str(signed["issuerPath"])), fullchain_path)
        replacement_chain = None
        if operation is not None:
            phase = "issued certificate validation"
            replacement_chain = operation.validate_issued(settings, csr_path, fullchain_path).encode("ascii")
        phase = "Fleet certificate import"
        imported = import_certificate_chain(
            client, fullchain_path.read_bytes(), fqdn,
            filename=fullchain_path.name, validated_csr=csr,
            on_mutation_attempt=mark_mutation_attempted, **selected)
        mutation_outcome_unknown = False
        completed_mutations.append("Signed certificate imported into Fleet")
        phase = "Fleet certificate replacement request"
        def start_replacement():
            if operation is not None:
                operation.start_fleet()
            mark_mutation_attempted()

        replace_request, replace_initial, chain = replace_certificate(
            client, fqdn, thumbprint=str(signed["sha256Thumbprint"]),
            search_paths=[fullchain_path], on_mutation_attempt=start_replacement,
            **({"allow_redirects": False, "expected_chain": replacement_chain}
               if operation is not None else {}),
            **selected)
        mutation_outcome_unknown = False
        replacement_requested = True
        completed_mutations.append("Fleet certificate replacement requested")
        workflow = replace_initial
        if operation is not None:
            phase = "Fleet replacement workflow"
            workflow = operation.track_fleet(replace_request, replace_initial,
                                             poll_interval=poll_interval, poll_timeout=poll_timeout)
        elif client._state(replace_initial) in {"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}:
            raise WorkflowFailedError("Fleet certificate replacement failed")
        if operation is None and client._state(replace_initial) not in SUCCESS_STATES:
            phase = "Fleet replacement workflow"
            workflow = poll_workflow(client, replace_request,
                                     poll_interval=poll_interval,
                                     poll_timeout=poll_timeout)
        replacement_completed = True
        completed_mutations.append("Fleet certificate replacement workflow completed")
        phase = "live HTTPS verification"
        verification = verify_https_certificate(fqdn, chain)
        return {
            "result": "RENEWED", "targetFqdn": fqdn.rstrip(".").lower(),
            "csrPath": str(csr_path), "fullchainPath": str(fullchain_path),
            "certificate": signed, "import": imported,
            "replaceRequestId": replace_request,
            "workflowState": client._state(workflow),
            "liveHttpsCertificate": verification,
            "reusedExistingCsr": reused_csr,
            "completedMutations": completed_mutations,
            "certificateReplacementPerformed": True,
        }
    except RenewalExecutionError:
        raise
    except Exception as exc:
        raise RenewalExecutionError(phase, completed_mutations,
                                    replacement_requested, replacement_completed,
                                    mutation_outcome_unknown, exc) from None
