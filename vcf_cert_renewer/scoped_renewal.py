"""Production renewal policy and durable replacement checkpoints for approved targets."""
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import re
from urllib.parse import urlsplit
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .auth import exchange_token
from .client import VcfApiClient, WorkflowFailedError
from .certificates import find_automation_certificate, resolve_fleet_certificate
from .components import adapter_for
from .replacer import poll_workflow
from .nsx_client import NsxApiClient
from .renewer import execute_domain_renewal, execute_nsx_renewal, execute_renewal, SUCCESS_STATES
from .sddc_client import SddcApiClient
from .sddc_install import (_bundle, _load, _locked_state, _payload, _reconcile,
                           _trusted_live_certificate, _write, InstallError)
from .signer import reuse_signed_csr, validate_signer_configuration
from .task_guard import check_tasks

TARGETS = {"vcenter.vcf.example.com": "VCENTER", "nsxt.vcf.example.com": "NSX"}
ROLES = {"SDDC_MANAGER", "VCENTER", "NSX", "OPERATIONS", "AUTOMATION"}
FLEET = {"OPERATIONS", "AUTOMATION"}
DOMAIN = {"SDDC_MANAGER", "VCENTER"}
INCOMPLETE = {"SUBMITTING", "TASK_PENDING", "VERIFY_PENDING", "TASK_FAILED"}


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _dns_sans(cert):
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if any(not isinstance(name, x509.DNSName) for name in sans):
        raise InstallError("NON_DNS_SAN")
    return sans.get_values_for_type(x509.DNSName)


def _live(target):
    return x509.load_der_x509_certificate(_trusted_live_certificate(target, 443))


def _validate_state(state, target, kind):
    if (not isinstance(state, dict) or state.get("version") != 1 or state.get("target") != target
            or state.get("state") not in INCOMPLETE | {"INSTALLED"}
            or state.get("recovery") != "UNVERIFIED_ACKNOWLEDGED"
            or not re.fullmatch(r"[0-9a-f]{64}", state["expected"])
            or not re.fullmatch(r"[0-9a-f]{64}", state["previous"])):
        raise ValueError
    if kind in DOMAIN | FLEET:
        if state["state"] != "SUBMITTING":
            _task_id(state["task_id"])
        elif "task_id" in state:
            raise ValueError
    else:
        UUID(state["certificate_id"])
        if state["state"] in {"TASK_PENDING", "TASK_FAILED"}:
            raise ValueError


def _task_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value):
        raise ValueError("Invalid operation identifier")
    return value


def _fleet_identity(client, kind, target):
    records = client.query_certificates()
    record = (find_automation_certificate(records) if kind == "AUTOMATION"
              else resolve_fleet_certificate(records, target))
    if (str(record.get("applianceFqdn", "")).rstrip(".").lower() != target
            or adapter_for(record).name != kind.lower()):
        raise InstallError("FLEET_TARGET_IDENTITY_UNVERIFIED")
    return record


class Replacement:
    def __init__(self, fd, target, live, client, state, kind=None, on_issued=None):
        self.fd = fd
        self.target = target
        self.kind = kind or TARGETS[target]
        self.names = None
        self.on_issued = on_issued
        self.previous = _fingerprint(live)
        self.client = client
        self.state = state
        self.expected = None

    def validate_csr(self, path):
        csr = x509.load_pem_x509_csr(path.read_bytes())
        if not csr.is_signature_valid or set(_dns_sans(csr)) != (self.names or {self.target}):
            raise InstallError("CSR_IDENTITY_MISMATCH")

    def validate_issued(self, settings, csr_path, fullchain_path):
        reuse_signed_csr(settings, self.target, csr_path)
        leaf, chain = _payload(_bundle(fullchain_path), [], require_root=True)
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        if leaf.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo):
            raise InstallError("ISSUED_PUBLIC_KEY_MISMATCH")
        if set(_dns_sans(leaf)) != (self.names or {self.target}):
            raise InstallError("ISSUED_IDENTITY_MISMATCH")
        self.expected = _fingerprint(leaf)
        if self.on_issued is not None:
            expiration = (getattr(leaf, "not_valid_after_utc", None)
                          or leaf.not_valid_after.replace(tzinfo=timezone.utc))
            self.on_issued(self.expected, expiration.isoformat())
        return chain

    def _update(self, **fields):
        state = dict(self.state, **fields)
        _validate_state(state, self.target, self.kind)
        _write(self.fd, state)
        self.state = state

    def _start(self, **fields):
        live = _fingerprint(_live(self.target))
        if live != self.previous or live == self.expected or self.expected is None:
            raise InstallError("REPLACEMENT_PREFLIGHT_CHANGED")
        self.state = {}
        self._update(state="SUBMITTING", target=self.target, version=1,
                     recovery="UNVERIFIED_ACKNOWLEDGED", expected=self.expected,
                     previous=self.previous, **fields)

    def replace_vcenter(self, domain, resource, chain, *, poll_interval, poll_timeout):
        check_tasks(self.client.task_inventory_page)
        self._start()
        task_id, _ = self.client.submit_certificate_replacement(
            domain, resource, chain, allow_redirects=False)
        self._update(state="TASK_PENDING", task_id=str(UUID(task_id)))
        task = self._wait_vcenter(poll_interval, poll_timeout)
        return task_id, task

    def _wait_vcenter(self, interval, timeout):
        try:
            task = self.client.wait_task(self.state["task_id"],
                                         poll_interval=interval, poll_timeout=timeout)
        except WorkflowFailedError:
            self._update(state="TASK_FAILED")
            raise
        self._update(state="VERIFY_PENDING")
        return task

    def start_fleet(self):
        self._start()

    def track_fleet(self, request_id, initial, *, poll_interval, poll_timeout):
        self._update(state="TASK_PENDING", task_id=_task_id(request_id))
        status = self.client._state(initial)
        if status in {"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}:
            self._update(state="TASK_FAILED")
            raise WorkflowFailedError("Fleet replacement failed")
        if status in SUCCESS_STATES:
            self._update(state="VERIFY_PENDING")
            return initial
        return self._wait_fleet(poll_interval, poll_timeout)

    def _wait_fleet(self, interval, timeout):
        try:
            task = poll_workflow(self.client, self.state["task_id"],
                                 poll_interval=interval, poll_timeout=timeout)
        except WorkflowFailedError:
            self._update(state="TASK_FAILED")
            raise
        self._update(state="VERIFY_PENDING")
        return task

    def apply_nsx(self, certificate_id):
        self._start(certificate_id=str(UUID(certificate_id)))
        self.client.apply_mgmt_cluster(certificate_id, allow_redirects=False)
        self._update(state="VERIFY_PENDING")

    def reconcile(self, poll_interval, poll_timeout):
        state = self.state["state"]
        if state == "TASK_FAILED":
            raise InstallError("PREVIOUS_REPLACEMENT_FAILED")
        if self.kind in DOMAIN | FLEET:
            if state == "SUBMITTING":
                raise InstallError("REPLACEMENT_OUTCOME_UNKNOWN_NO_TASK_ID")
            if state == "TASK_PENDING":
                wait = self._wait_vcenter if self.kind in DOMAIN else self._wait_fleet
                wait(poll_interval, poll_timeout)
            if self.kind in DOMAIN:
                self.client.resolve_context(self.target, self.kind)
            else:
                _fleet_identity(self.client, self.kind, self.target)
        else:
            active = self.client.discover(self.target)["certificate"]
            if active["id"] != self.state["certificate_id"]:
                raise InstallError("NSX_ASSIGNMENT_UNVERIFIED")
        if _fingerprint(_live(self.target)) != self.state["expected"]:
            raise InstallError("LIVE_CERTIFICATE_UNVERIFIED")
        self._update(state="INSTALLED")
        return {"result": "INSTALLED", "fingerprint": self.state["expected"],
                **{k: self.state[k] for k in ("task_id", "certificate_id") if k in self.state}}


def renew_scoped(settings, target, *, poll_interval, poll_timeout, kind=None, on_issued=None):
    kind = kind or TARGETS.get(target)
    if kind not in ROLES or settings.acme_mode != "production":
        raise InstallError("TARGET_OR_ACME_MODE_NOT_APPROVED")
    settings = replace(settings, verify_tls=True, nsx_verify_tls=True)
    with ExitStack() as stack:
        if kind == "SDDC_MANAGER":
            legacy_fd = stack.enter_context(_locked_state(settings.output_dir))
            legacy = _load(legacy_fd)
            if legacy and legacy.get("target") != target:
                raise InstallError("LEGACY_SDDC_OPERATION_UNRESOLVED")
            if legacy and legacy["state"] in {"TASK_PENDING", "VERIFY_PENDING"}:
                url = urlsplit(settings.sddc_url)
                if url.scheme != "https" or url.hostname != target:
                    raise InstallError("SDDC_TARGET_IDENTITY_UNVERIFIED")
                client = SddcApiClient(settings.sddc_url, *settings.require_sddc_credentials(),
                                       verify_tls=True, timeout_seconds=settings.timeout_seconds)
                return _reconcile(legacy_fd, legacy, client, target, url.port or 443)
            if legacy and legacy["state"] not in {"INSTALLED", "PREPARED"}:
                raise InstallError("LEGACY_SDDC_OPERATION_UNRESOLVED")
        fd = stack.enter_context(_locked_state(settings.output_dir, ".renew-" + kind.lower()))
        state = _load(fd, lambda data: _validate_state(data, target, kind))
        live = _live(target)
        fingerprint = _fingerprint(live)
        expiration = getattr(live, "not_valid_after_utc", None) or live.not_valid_after.replace(tzinfo=timezone.utc)
        if target not in set(_dns_sans(live)):
            raise InstallError("CURRENT_TLS_IDENTITY_MISMATCH")
        if not state or state["state"] == "INSTALLED":
            days = (expiration - datetime.now(timezone.utc)).total_seconds() / 86400
            if days > settings.renew_before_days:
                return {"result": "SKIPPED", "reason": "OUTSIDE_RENEWAL_WINDOW", "daysRemaining": round(days, 2),
                        "fingerprint": fingerprint, "expires": expiration.isoformat()}
        if kind in DOMAIN:
            if kind == "SDDC_MANAGER" and (urlsplit(settings.sddc_url).hostname != target
                                          or urlsplit(settings.sddc_url).scheme != "https"):
                raise InstallError("SDDC_TARGET_IDENTITY_UNVERIFIED")
            client = SddcApiClient(settings.sddc_url, *settings.require_sddc_credentials(),
                                   verify_tls=True, timeout_seconds=settings.timeout_seconds)
        elif kind in FLEET:
            if any(urlsplit(url).scheme != "https" for url in (settings.base_url, settings.token_url)):
                raise InstallError("FLEET_HTTPS_REQUIRED")
            client = VcfApiClient(settings.base_url, exchange_token(settings), verify_tls=True,
                                  timeout_seconds=settings.timeout_seconds)
        else:
            if (urlsplit(settings.nsx_url).hostname != target or urlsplit(settings.nsx_url).scheme != "https"
                    or urlsplit(settings.token_url).scheme != "https"):
                raise InstallError("NSX_VIP_NOT_CONFIGURED")
            client = NsxApiClient(settings.nsx_url, lambda: exchange_token(settings),
                                  verify_tls=True, timeout_seconds=settings.timeout_seconds)
        operation = Replacement(fd, target, live, client, state, kind, on_issued)
        if state and state["state"] in INCOMPLETE:
            return operation.reconcile(poll_interval, poll_timeout)
        operation.names = set(_dns_sans(live))
        validate_signer_configuration(settings)
        if kind in DOMAIN:
            check_tasks(client.task_inventory_page)
            execute_domain_renewal(client, settings, target, resource_type=kind,
                                   poll_interval=poll_interval, poll_timeout=poll_timeout,
                                   operation=operation)
        elif kind in FLEET:
            active = _fleet_identity(client, kind, target)
            inventory_sans = active.get("subjectAlternativeNames") or {}
            if inventory_sans.get("ip") or set(inventory_sans.get("dns") or ()) != operation.names:
                raise InstallError("FLEET_SAN_INVENTORY_MISMATCH")
            execute_renewal(client, settings, target, certificate=active, operation=operation,
                            poll_interval=poll_interval, poll_timeout=poll_timeout)
        else:
            active = client.discover(target)["certificate"]
            assigned = x509.load_pem_x509_certificate(active["pem_encoded"].encode())
            if _fingerprint(assigned) != _fingerprint(live) or _dns_sans(assigned) != [target]:
                raise InstallError("NSX_ASSIGNMENT_IDENTITY_MISMATCH")
            execute_nsx_renewal(client, settings, target, poll_interval=poll_interval,
                                poll_timeout=poll_timeout, operation=operation)
        return operation.reconcile(poll_interval, poll_timeout)
