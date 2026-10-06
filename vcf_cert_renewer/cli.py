"""Consistent command-line interface for VCF certificate lifecycle operations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from . import __version__

from .auth import exchange_token
from .certificates import (AmbiguousCertificateError, CertificateNotFoundError,
                           find_leaf_tls_certificate, leaf_tls_certificates_for_hostname,
                           find_automation_certificate, resolve_fleet_certificate,
                           is_automation_external_tls)
from .client import VcfApiClient, WorkflowFailedError, WorkflowTimeoutError
from .components import adapter_for, discover_inventory, plan_inventory
from .config import ConfigurationError, Settings
from .fullchain import build_vcf_fullchain, predictable_fullchain_path
from .renewer import (OPERATIONS_ACTIONS, RenewalExecutionError,
                      execute_domain_renewal, execute_nsx_renewal, execute_renewal, renewal_plan)
from .signer import sanitize_diagnostic, validate_signer_configuration
from .nsx_client import NsxApiClient
from .sddc_client import SddcApiClient
from .signer import sign_csr
from .importer import import_certificate_chain
from .plan import build_domain_plan, build_plan
from .replacer import (AmbiguousImportedCertificateError,
                       ImportedCertificateNotFoundError, TlsVerificationError,
                       poll_workflow, replace_certificate,
                       verify_https_certificate)

BATCH_TARGETS = (
    "ops.vcf.example.com",
    "sddc.vcf.example.com",
    "vcenter.vcf.example.com",
    "nsxt.vcf.example.com",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vcf-cert-renewer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, help="non-secret YAML configuration file")
    parser.add_argument("--secrets-file", type=Path,
                        help="root-readable secrets environment file")
    parser.add_argument("--renew-before-days", type=int,
                        help="override renewal threshold")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("token", help="exchange OAuth credentials for a token")
    listing = sub.add_parser("cert-list", help="query certificates (legacy)")
    listing.add_argument("--hostname")
    listing.add_argument("--page-size", type=int, default=500)
    finding = sub.add_parser("cert-find", help="find one TLS leaf (legacy)")
    finding.add_argument("hostname")
    finding.add_argument("--page-size", type=int, default=500)
    discover = sub.add_parser("discover", help="read-only certificate discovery")
    discover.add_argument("hostname", nargs="?")
    discover.add_argument("--all", action="store_true", dest="all_targets")
    discover.add_argument("--page-size", type=int, default=500)
    live = sub.add_parser("live-test", help="OAuth and discovery compatibility command")
    live.add_argument("hostname", nargs="?", default="ops.vcf.example.com")
    live.add_argument("--page-size", type=int, default=500)
    for name in ("generate-csr", "csr"):
        generate = sub.add_parser(name, help="generate and save a CSR")
        generate.add_argument("hostname")
        generate.add_argument("--output", type=Path)
        generate.add_argument("--page-size", type=int, default=500)
        generate.add_argument("--poll-interval", type=float, default=2)
        generate.add_argument("--poll-timeout", type=float, default=300)
    importing = sub.add_parser("import-certificate", help="validate/import PEM (legacy)")
    importing.add_argument("--certificate", required=True, type=Path)
    importing.add_argument("--fqdn", required=True)
    importing_alias = sub.add_parser("import", help="validate and import a signed PEM chain")
    importing_alias.add_argument("fqdn")
    importing_alias.add_argument("certificate", type=Path)
    for name in ("replace-certificate", "replace"):
        replacing = sub.add_parser(name, help="explicitly replace a Fleet certificate")
        if name == "replace":
            replacing.add_argument("fqdn")
        else:
            replacing.add_argument("--fqdn", required=True)
        selector = replacing.add_mutually_exclusive_group(required=True)
        selector.add_argument("--thumbprint")
        selector.add_argument("--common-name")
        replacing.add_argument("--poll-interval", type=float, default=2)
        replacing.add_argument("--poll-timeout", type=float, default=900)
    planning = sub.add_parser("plan", help="read-only renewal plan; makes no changes")
    planning.add_argument("fqdn", nargs="?")
    planning.add_argument("--all", action="store_true", dest="all_targets")
    planning.add_argument("--page-size", type=int, default=500)
    verify = sub.add_parser("verify", help="compare live TLS with an expected PEM chain")
    verify.add_argument("fqdn")
    verify.add_argument("certificate", type=Path)
    sign = sub.add_parser("sign", help="sign an existing VCF-generated CSR with ACME")
    sign.add_argument("target")
    sign.add_argument("--csr", type=Path)
    sign.add_argument("--build-fullchain", action="store_true")
    renew = sub.add_parser("renew", help="safely orchestrate the renewal lifecycle")
    renew.add_argument("fqdn", nargs="?")
    renew.add_argument("--all", action="store_true", dest="all_targets",
                       help="renew existing supported targets and discovered external VCF Automation TLS")
    renew.add_argument("--force", action="store_true",
                       help="renew regardless of expiry threshold")
    gate = renew.add_mutually_exclusive_group()
    gate.add_argument("--yes", action="store_true", help="allow production mutation")
    gate.add_argument("--apply", action="store_true", help="allow production mutation")
    renew.add_argument("--poll-interval", type=float, default=2)
    renew.add_argument("--poll-timeout", type=float, default=900)
    return parser


def _execute_supported_renewal(settings: Settings, fqdn: str, *,
                               poll_interval: float, poll_timeout: float,
                               certificate: dict[str, object] | None = None) -> dict[str, object]:
    """Validate route credentials and signer inputs before mutation."""
    adapter = adapter_for(certificate or {"applianceFqdn": fqdn})
    if adapter.capability.value != "FULL_RENEW":
        raise ValueError(f"{fqdn} is not a FULL_RENEW target: {adapter.reason}")
    if adapter.management_path == "NSX_NATIVE_MGMT_CLUSTER":
        settings.require_api_token()
        validate_signer_configuration(settings)
        return execute_nsx_renewal(
            _nsx_client(settings), settings, fqdn,
            poll_interval=poll_interval, poll_timeout=poll_timeout)
    if adapter.management_path == "DOMAIN_MANAGED":
        domain_client = _sddc_client(settings)
        validate_signer_configuration(settings)
        return execute_domain_renewal(
            domain_client, settings, fqdn,
            resource_type=adapter.component_type,
            poll_interval=poll_interval, poll_timeout=poll_timeout)
    if adapter.management_path == "FLEET_MANAGED" and adapter.name in {"operations", "automation"}:
        validate_signer_configuration(settings)
        selected = {"certificate": certificate} if certificate is not None else {}
        return execute_renewal(
            _client(settings, exchange_token(settings)), settings, fqdn,
            poll_interval=poll_interval, poll_timeout=poll_timeout, **selected)
    raise ValueError(f"No validated renewal route for {fqdn}")


def _discover_automation(settings: Settings) -> dict[str, object]:
    client = _client(settings, exchange_token(settings))
    return find_automation_certificate(client.query_certificates())


def _automation_labels(certificate: dict[str, object]) -> dict[str, object]:
    return {"componentType": "VCF_AUTOMATION", "componentDisplayName": "VCF Automation",
            "category": "TLS_CERT", "categoryDisplayName": "TLS Certificate",
            "certificateType": "EXTERNAL_CA", "certificateTypeDisplayName": "External CA",
            "certificateResourceKey": certificate["certificateResourceKey"],
            "plannedActions": OPERATIONS_ACTIONS}


def _require_supported_fleet_target(certificates: list[dict[str, object]], fqdn: str,
                                   action: str) -> dict[str, object]:
    """Refuse explicit Fleet mutations outside a FULL_RENEW Fleet adapter."""
    certificate = resolve_fleet_certificate(certificates, fqdn)
    adapter = adapter_for(certificate)
    support_flag = {
        "generate-csr": "supports_generate_csr",
        "import": "supports_import",
        "replace": "supports_replace",
    }[action]
    if (adapter.capability.value != "FULL_RENEW"
            or adapter.management_path != "FLEET_MANAGED"
            or not getattr(adapter, support_flag, False)):
        raise ValueError(
            f"{fqdn} is not a supported Fleet-managed FULL_RENEW target for {action}: "
            f"{adapter.reason}")
    return certificate


def _batch_renew(settings: Settings, args: argparse.Namespace) -> int:
    """Preserve legacy planning gates and add independently discovered Automation."""
    plans: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    for fqdn in settings.renewal_targets:
        try:
            plans.append(renewal_plan(settings, fqdn, force=args.force))
        except Exception as exc:  # Planning must fail closed before any mutation.
            results.append({"targetFqdn": fqdn, "status": "FAILED",
                            "phase": "PLAN", "errorType": type(exc).__name__})
    if results:
        print(json.dumps({"result": "FAILED", "mode": "BATCH", "plans": plans,
                          "summary": results, "mutatingCallsMade": False},
                         indent=2, sort_keys=True))
        return 1

    automation = None
    discovery = {"componentType": "VCF_AUTOMATION", "status": "NOT_DISCOVERED"}
    try:
        automation = _discover_automation(settings)
        automation_fqdn = str(automation["applianceFqdn"]).rstrip(".").lower()
        automation_plan = renewal_plan(settings, automation_fqdn, force=args.force)
        automation_plan.update(_automation_labels(automation))
        # Metadata takes precedence even if the endpoint resembles a legacy hostname.
        plans = [plan for plan in plans if plan["targetFqdn"] != automation_fqdn]
        plans.append(automation_plan)
        discovery["status"] = "DISCOVERED"
    except CertificateNotFoundError:
        pass
    except Exception as exc:
        discovery["status"] = "FAILED"
        results.append({"componentType": "VCF_AUTOMATION", "status": "FAILED",
                        "phase": "DISCOVERY_OR_PLAN", "errorType": type(exc).__name__,
                        "reason": "Ambiguous external TLS inventory; refusing to guess"
                        if isinstance(exc, AmbiguousCertificateError) else
                        "VCF Automation discovery or live HTTPS planning failed"})

    due = [plan for plan in plans if plan["result"] == "RENEWAL_REQUIRED"]
    approved = args.yes or args.apply
    if due and settings.acme_mode == "production" and not approved:
        print(json.dumps({"result": "PLAN_ONLY", "mode": "BATCH", "plans": plans,
                          "discovery": discovery, "errors": results,
                          "summary": [{"targetFqdn": str(plan["targetFqdn"]),
                                       "status": "PENDING_APPROVAL"} for plan in due],
                          "mutatingCallsMade": False,
                          "notice": "Production mutation requires --yes or --apply."},
                         indent=2, sort_keys=True))
        return 0

    if due:
        try:
            validate_signer_configuration(settings)
        except ConfigurationError as exc:
            print(json.dumps({"result": "FAILED", "mode": "BATCH", "plans": plans,
                              "discovery": discovery, "summary": [{
                                  "status": "FAILED", "phase": "SIGNER_CONFIGURATION",
                                  "errorType": type(exc).__name__, "error": str(exc),
                                  "mutatingChangesMade": False, "mutationAttempted": False}],
                              "mutatingCallsMade": False,
                              "notice": "No changes have been made."},
                             indent=2, sort_keys=True))
            return 1
        # Keep final batch output free of stale preflight-only notices.
        for item in plans:
            item.pop("notice", None)
    for plan in plans:
        fqdn = str(plan["targetFqdn"])
        if plan["result"] == "NO_RENEWAL_NEEDED":
            results.append({"targetFqdn": fqdn, "status": "SKIPPED",
                            "reason": "NO_RENEWAL_NEEDED"})
            continue
        try:
            selected = ({"certificate": automation}
                        if plan.get("componentType") == "VCF_AUTOMATION" else {})
            renewal = _execute_supported_renewal(
                settings, fqdn, poll_interval=args.poll_interval,
                poll_timeout=args.poll_timeout, **selected)
            results.append({"targetFqdn": fqdn, "status": "RENEWED",
                            "result": renewal})
        except RenewalExecutionError as exc:
            results.append({"targetFqdn": fqdn, "status": "FAILED",
                            "phase": exc.phase, "errorType": type(exc.cause).__name__,
                            "error": sanitize_diagnostic(exc.cause, settings),
                            "changesAlreadyMade": list(exc.completed_mutations),
                            "mutatingChangesMade": bool(exc.completed_mutations),
                            "mutationAttempted": bool(exc.completed_mutations) or exc.mutation_outcome_unknown,
                            "certificateReplacementRequested": exc.replacement_requested,
                            "certificateReplacementPerformed": exc.replacement_completed,
                            "mutationOutcomeUnknown": exc.mutation_outcome_unknown})
        except Exception as exc:  # Keep processing independent validated targets.
            results.append({"targetFqdn": fqdn, "status": "FAILED",
                            "phase": "RENEW", "errorType": type(exc).__name__})
    failed = any(item["status"] == "FAILED" for item in results)
    print(json.dumps({"result": "FAILED" if failed else "SUCCESS", "mode": "BATCH",
                      "plans": plans, "summary": results, "discovery": discovery,
                      "counts": {state: sum(item["status"] == state for item in results)
                                 for state in ("RENEWED", "SKIPPED", "FAILED")}},
                     indent=2, sort_keys=True))
    return 1 if failed else 0


def _client(settings: Settings, token: str | None = None) -> VcfApiClient:
    return VcfApiClient(settings.base_url, token or settings.require_api_token(),
                        verify_tls=settings.verify_tls,
                        timeout_seconds=settings.timeout_seconds)


def _sddc_client(settings: Settings) -> SddcApiClient:
    username, password = settings.require_sddc_credentials()
    return SddcApiClient(settings.sddc_url, username, password,
                         verify_tls=settings.verify_tls,
                         timeout_seconds=settings.timeout_seconds)


def _nsx_client(settings: Settings) -> NsxApiClient:
    return NsxApiClient(settings.nsx_url, lambda: exchange_token(settings),
                        verify_tls=settings.nsx_verify_tls,
                        timeout_seconds=settings.timeout_seconds)


def _safe_summary(certificate: dict[str, object]) -> dict[str, object]:
    sans = certificate.get("subjectAlternativeNames") or {}
    metadata = certificate.get("certificateMetadata") or {}
    return {"certificateResourceKey": certificate.get("certificateResourceKey"),
            "issuedToCommonName": certificate.get("issuedToCommonName"),
            "applianceFqdn": certificate.get("applianceFqdn"),
            "category": certificate.get("category"),
            "chainRole": metadata.get("certificateChainRole") if isinstance(metadata, dict) else None,
            "status": certificate.get("status"), "daysToExpire": certificate.get("daysToExpire"),
            "dnsNames": sans.get("dns", []) if isinstance(sans, dict) else []}


def _write_csr(output: Path, hostname: str, csr: str) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"{hostname.rstrip('.').lower()}.csr.pem"
    destination.write_text(csr, encoding="ascii")
    return destination


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = Settings.load(
            config_path=args.config, secrets_path=args.secrets_file,
            overrides={"RENEW_BEFORE_DAYS": args.renew_before_days})
        if not settings.verify_tls:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning,
                                    module=r"urllib3(\..*)?")
            print("WARNING: TLS certificate verification is disabled for VCF API connections.",
                  file=sys.stderr)
        if args.command == "token":
            print(exchange_token(settings)); return 0
        if args.command == "sign":
            target = Path(args.target)
            csr_path = args.csr or (target if target.is_file() else
                                     settings.output_dir /
                                     f"{args.target.rstrip('.').lower()}.csr.pem")
            signed = sign_csr(settings, csr_path)
            if args.build_fullchain:
                output = predictable_fullchain_path(
                    settings.output_dir, str(signed["fqdn"]))
                build_vcf_fullchain(Path(str(signed["leafPath"])),
                                    Path(str(signed["issuerPath"])), output)
                signed["vcfFullchainPath"] = str(output)
            print(json.dumps(signed, indent=2, sort_keys=True))
            return 0
        if args.command == "renew":
            if args.all_targets:
                if args.fqdn:
                    print("error: renew accepts either <fqdn> or --all", file=sys.stderr)
                    return 2
                return _batch_renew(settings, args)
            if not args.fqdn:
                print("error: renew requires <fqdn> or --all", file=sys.stderr)
                return 2
            selected_certificate = None
            initial_adapter = adapter_for({"applianceFqdn": args.fqdn})
            if initial_adapter.capability.value != "FULL_RENEW":
                candidate = _discover_automation(settings)
                if str(candidate["applianceFqdn"]).rstrip(".").lower() == args.fqdn.rstrip(".").lower():
                    selected_certificate = candidate
            plan = renewal_plan(settings, args.fqdn, force=args.force)
            if selected_certificate is not None:
                plan.update(_automation_labels(selected_certificate))
            if plan["result"] == "NO_RENEWAL_NEEDED":
                print(json.dumps(plan, indent=2, sort_keys=True))
                return 0
            approved = args.yes or args.apply
            if settings.acme_mode == "production" and not approved:
                print(json.dumps(plan, indent=2, sort_keys=True))
                print(json.dumps({
                    "result": "PLAN_ONLY",
                    "reason": "Production mutation requires --yes or --apply.",
                    "notice": "No changes have been made.",
                }, indent=2, sort_keys=True))
                return 0
            plan["notice"] = "Preflight complete; renewal has not started."
            print(json.dumps(plan, indent=2, sort_keys=True))
            adapter = adapter_for(selected_certificate or {"applianceFqdn": args.fqdn})
            if adapter.capability.value != "FULL_RENEW":
                print(json.dumps({
                    "result": "UNSUPPORTED",
                    "targetFqdn": args.fqdn.rstrip(".").lower(),
                    "reason": adapter.reason,
                    "notice": "No changes have been made.",
                }, indent=2, sort_keys=True))
                return 2
            try:
                result = _execute_supported_renewal(
                    settings, args.fqdn, poll_interval=args.poll_interval,
                    poll_timeout=args.poll_timeout,
                    **({"certificate": selected_certificate} if selected_certificate is not None else {}))
            except ConfigurationError as exc:
                if str(exc).startswith(("Missing SDDC Manager credentials:",
                                        "VCF_API_TOKEN is not set")):
                    raise
                print(json.dumps({"result": "FAILED", "targetFqdn": args.fqdn.rstrip(".").lower(),
                                  "phase": "SIGNER_CONFIGURATION",
                                  "errorType": type(exc).__name__, "error": str(exc),
                                  "mutatingChangesMade": False, "mutationAttempted": False,
                                  "notice": "No changes have been made."},
                                 indent=2, sort_keys=True))
                return 1
            except RenewalExecutionError as exc:
                failure = {"result": "FAILED", "targetFqdn": args.fqdn.rstrip(".").lower(),
                           "phase": exc.phase, "errorType": type(exc.cause).__name__,
                           "error": sanitize_diagnostic(exc.cause, settings),
                           "changesAlreadyMade": list(exc.completed_mutations),
                           "mutatingChangesMade": bool(exc.completed_mutations),
                           "mutationAttempted": bool(exc.completed_mutations) or exc.mutation_outcome_unknown,
                           "certificateReplacementRequested": exc.replacement_requested,
                           "certificateReplacementPerformed": exc.replacement_completed,
                           "mutationOutcomeUnknown": exc.mutation_outcome_unknown}
                if exc.mutation_outcome_unknown:
                    failure["notice"] = ("A Fleet mutation request may have been accepted; "
                                          "inspect its workflow before retrying. No rollback was performed.")
                elif exc.completed_mutations:
                    failure["notice"] = "No rollback was performed; see changesAlreadyMade."
                else:
                    failure["notice"] = "No changes have been made."
                print(json.dumps(failure, indent=2, sort_keys=True))
                return 1
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "verify":
            print(json.dumps(verify_https_certificate(
                args.fqdn, args.certificate.read_bytes()), indent=2, sort_keys=True))
            return 0
        oauth_commands = {"live-test", "generate-csr", "csr", "import-certificate",
                          "import", "replace-certificate", "replace", "plan", "discover"}
        domain_adapter = (adapter_for({"applianceFqdn": args.fqdn})
                          if args.command == "plan" and not args.all_targets and args.fqdn
                          else None)
        if (domain_adapter and domain_adapter.management_path == "NSX_NATIVE_MGMT_CLUSTER"):
            discovery = _nsx_client(settings).discover(args.fqdn)
            live = renewal_plan(settings, args.fqdn)
            live.update({"component": "nsx", "renewalCapability": "FULL_RENEW",
                         "validationStatus": "PRODUCTION_VALIDATED",
                         "nativeDiscovery": discovery, "mutatingCallsMade": False})
            print(json.dumps(live, indent=2, sort_keys=True)); return 0
        if (domain_adapter and domain_adapter.management_path == "DOMAIN_MANAGED" and
                domain_adapter.component_type in {"SDDC_MANAGER", "VCENTER", "NSXT_MANAGER"}):
            print(json.dumps(build_domain_plan(
                _sddc_client(settings), settings, args.fqdn,
                domain_adapter.component_type),
                             indent=2, sort_keys=True))
            return 0
        client = (_client(settings, exchange_token(settings))
                  if args.command in oauth_commands else _client(settings))
        if args.command == "plan":
            if args.all_targets:
                print(json.dumps(plan_inventory(client, page_size=args.page_size),
                                 indent=2, sort_keys=True))
                return 0
            if not args.fqdn:
                print("error: plan requires <fqdn> or --all", file=sys.stderr)
                return 2
            print(json.dumps(build_plan(client, settings, args.fqdn,
                                        page_size=args.page_size), indent=2, sort_keys=True))
            return 0
        if args.command in {"replace-certificate", "replace"}:
            certificate = _require_supported_fleet_target(
                client.query_certificates(), args.fqdn, "replace")
            search_paths = settings.output_dir.glob("**/*.pem") if settings.output_dir.exists() else ()
            request_id, initial, chain = replace_certificate(
                client, args.fqdn, thumbprint=args.thumbprint,
                common_name=args.common_name, search_paths=search_paths,
                expected_certificate=certificate)
            state = client._state(initial)
            workflow = initial if state in {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"} else poll_workflow(
                client, request_id, poll_interval=args.poll_interval,
                poll_timeout=args.poll_timeout)
            verification = verify_https_certificate(args.fqdn, chain)
            print(json.dumps({"requestId": request_id, "workflowState": client._state(workflow),
                              "httpsCertificate": verification}, indent=2, sort_keys=True))
            return 0
        if args.command in {"import-certificate", "import"}:
            certificate = _require_supported_fleet_target(
                client.query_certificates(), args.fqdn, "import")
            result = import_certificate_chain(
                client, args.certificate.read_bytes(), args.fqdn,
                filename=args.certificate.name, expected_certificate=certificate)
            print(json.dumps(result, indent=2, sort_keys=True)); return 0
        if args.command == "discover" and args.all_targets:
            print(json.dumps(discover_inventory(client, page_size=args.page_size),
                             indent=2, sort_keys=True))
            return 0
        certificates = client.query_certificates(page_size=args.page_size)
        if args.command in {"generate-csr", "csr"}:
            certificate = _require_supported_fleet_target(
                certificates, args.hostname, "generate-csr")
            # Re-read and pin identity immediately before the CSR mutation.
            certificate = resolve_fleet_certificate(
                client.query_certificates(page_size=args.page_size), args.hostname,
                expected_certificate=certificate)
            request_id, initial = client.create_csr(certificate)
            state = client._state(initial)
            if state not in {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"}:
                client.wait_for_csr(request_id, poll_interval=args.poll_interval,
                                    poll_timeout=args.poll_timeout)
            key = str(certificate["certificateResourceKey"])
            common_name = str(certificate.get("issuedToCommonName") or args.hostname)
            output = args.output or (Path(".") if args.command == "generate-csr" else settings.output_dir)
            automation = is_automation_external_tls(certificate)
            if automation:
                csr = client.fetch_csr(
                    key, common_name, expected_fqdn=args.hostname,
                    strict_dns_san=True,
                    appliance=str(certificate.get("appliance") or ""),
                    component=str(certificate.get("vcfComponent") or "") or None)
            else:
                csr = client.fetch_csr(key, common_name)
            print(_write_csr(output, args.hostname, csr)); return 0
        if args.command == "live-test":
            print(json.dumps(_safe_summary(find_leaf_tls_certificate(certificates, args.hostname)),
                             indent=2, sort_keys=True)); return 0
        hostname = getattr(args, "hostname", None)
        if args.command in {"cert-list", "discover"}:
            if hostname:
                certificates = leaf_tls_certificates_for_hostname(certificates, hostname)
            print(json.dumps(certificates, indent=2, sort_keys=True)); return 0
        print(json.dumps(find_leaf_tls_certificate(certificates, args.hostname), indent=2, sort_keys=True)); return 0
    except (ConfigurationError, CertificateNotFoundError, AmbiguousCertificateError,
            ImportedCertificateNotFoundError, AmbiguousImportedCertificateError,
            TlsVerificationError, WorkflowFailedError, WorkflowTimeoutError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    except (requests.RequestException, OSError, ValueError) as exc:
        print(f"error: operation failed: {exc}", file=sys.stderr); return 1
