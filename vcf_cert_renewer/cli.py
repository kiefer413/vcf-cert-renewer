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
                           find_leaf_tls_certificate, leaf_tls_certificates_for_hostname)
from .client import VcfApiClient, WorkflowFailedError, WorkflowTimeoutError
from .components import adapter_for, discover_inventory, plan_inventory
from .config import ConfigurationError, Settings
from .fullchain import build_vcf_fullchain, predictable_fullchain_path
from .renewer import execute_domain_renewal, execute_nsx_renewal, execute_renewal, renewal_plan
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
                       help="renew only the four production-validated v1 targets")
    renew.add_argument("--force", action="store_true",
                       help="renew regardless of expiry threshold")
    gate = renew.add_mutually_exclusive_group()
    gate.add_argument("--yes", action="store_true", help="allow production mutation")
    gate.add_argument("--apply", action="store_true", help="allow production mutation")
    renew.add_argument("--poll-interval", type=float, default=2)
    renew.add_argument("--poll-timeout", type=float, default=900)
    return parser


def _execute_supported_renewal(settings: Settings, fqdn: str, *,
                               poll_interval: float, poll_timeout: float) -> dict[str, object]:
    """Route one approved target through exactly its validated API family."""
    adapter = adapter_for({"applianceFqdn": fqdn})
    if adapter.capability.value != "FULL_RENEW":
        raise ValueError(f"{fqdn} is not a FULL_RENEW target: {adapter.reason}")
    if adapter.management_path == "NSX_NATIVE_MGMT_CLUSTER":
        return execute_nsx_renewal(
            _nsx_client(settings), settings, fqdn,
            poll_interval=poll_interval, poll_timeout=poll_timeout)
    if adapter.management_path == "DOMAIN_MANAGED":
        return execute_domain_renewal(
            _sddc_client(settings), settings, fqdn,
            resource_type=adapter.component_type,
            poll_interval=poll_interval, poll_timeout=poll_timeout)
    if adapter.management_path == "FLEET_MANAGED" and adapter.name == "operations":
        return execute_renewal(
            _client(settings, exchange_token(settings)), settings, fqdn,
            poll_interval=poll_interval, poll_timeout=poll_timeout)
    raise ValueError(f"No validated renewal route for {fqdn}")


def _batch_renew(settings: Settings, args: argparse.Namespace) -> int:
    """Plan every v1 target before mutation, then continue across target failures."""
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

    due = [plan for plan in plans if plan["result"] == "RENEWAL_REQUIRED"]
    approved = args.yes or args.apply
    if due and settings.acme_mode == "production" and not approved:
        print(json.dumps({"result": "PLAN_ONLY", "mode": "BATCH", "plans": plans,
                          "summary": [{"targetFqdn": str(plan["targetFqdn"]),
                                       "status": "PENDING_APPROVAL"} for plan in due],
                          "mutatingCallsMade": False,
                          "notice": "Production mutation requires --yes or --apply."},
                         indent=2, sort_keys=True))
        return 0

    for plan in plans:
        fqdn = str(plan["targetFqdn"])
        if plan["result"] == "NO_RENEWAL_NEEDED":
            results.append({"targetFqdn": fqdn, "status": "SKIPPED",
                            "reason": "NO_RENEWAL_NEEDED"})
            continue
        try:
            renewal = _execute_supported_renewal(
                settings, fqdn, poll_interval=args.poll_interval,
                poll_timeout=args.poll_timeout)
            results.append({"targetFqdn": fqdn, "status": "RENEWED",
                            "result": renewal})
        except Exception as exc:  # Keep processing independent validated targets.
            results.append({"targetFqdn": fqdn, "status": "FAILED",
                            "phase": "RENEW", "errorType": type(exc).__name__})
    failed = any(item["status"] == "FAILED" for item in results)
    print(json.dumps({"result": "FAILED" if failed else "SUCCESS", "mode": "BATCH",
                      "plans": plans, "summary": results,
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
            plan = renewal_plan(settings, args.fqdn, force=args.force)
            print(json.dumps(plan, indent=2, sort_keys=True))
            if plan["result"] == "NO_RENEWAL_NEEDED":
                return 0
            approved = args.yes or args.apply
            if settings.acme_mode == "production" and not approved:
                print(json.dumps({
                    "result": "PLAN_ONLY",
                    "reason": "Production mutation requires --yes or --apply.",
                    "notice": "No changes have been made.",
                }, indent=2, sort_keys=True))
                return 0
            adapter = adapter_for({"applianceFqdn": args.fqdn})
            if adapter.capability.value != "FULL_RENEW":
                print(json.dumps({
                    "result": "UNSUPPORTED",
                    "targetFqdn": args.fqdn.rstrip(".").lower(),
                    "reason": adapter.reason,
                    "notice": "No changes have been made.",
                }, indent=2, sort_keys=True))
                return 2
            result = _execute_supported_renewal(
                settings, args.fqdn, poll_interval=args.poll_interval,
                poll_timeout=args.poll_timeout)
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
            search_paths = settings.output_dir.glob("**/*.pem") if settings.output_dir.exists() else ()
            request_id, initial, chain = replace_certificate(
                client, args.fqdn, thumbprint=args.thumbprint,
                common_name=args.common_name, search_paths=search_paths)
            state = client._state(initial)
            workflow = initial if state in {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"} else poll_workflow(
                client, request_id, poll_interval=args.poll_interval,
                poll_timeout=args.poll_timeout)
            verification = verify_https_certificate(args.fqdn, chain)
            print(json.dumps({"requestId": request_id, "workflowState": client._state(workflow),
                              "httpsCertificate": verification}, indent=2, sort_keys=True))
            return 0
        if args.command in {"import-certificate", "import"}:
            result = import_certificate_chain(client, args.certificate.read_bytes(),
                                              args.fqdn, filename=args.certificate.name)
            print(json.dumps(result, indent=2, sort_keys=True)); return 0
        if args.command == "discover" and args.all_targets:
            print(json.dumps(discover_inventory(client, page_size=args.page_size),
                             indent=2, sort_keys=True))
            return 0
        certificates = client.query_certificates(page_size=args.page_size)
        if args.command in {"generate-csr", "csr"}:
            certificate = find_leaf_tls_certificate(certificates, args.hostname)
            request_id, initial = client.create_csr(certificate)
            state = client._state(initial)
            if state not in {"COMPLETED", "COMPLETE", "SUCCEEDED", "SUCCESS", "FINISHED"}:
                client.wait_for_csr(request_id, poll_interval=args.poll_interval,
                                    poll_timeout=args.poll_timeout)
            key = str(certificate["certificateResourceKey"])
            common_name = str(certificate.get("issuedToCommonName") or args.hostname)
            output = args.output or (Path(".") if args.command == "generate-csr" else settings.output_dir)
            print(_write_csr(output, args.hostname, client.fetch_csr(key, common_name))); return 0
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
