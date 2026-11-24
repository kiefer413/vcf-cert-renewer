"""Local structured events, optional best-effort syslog, and atomic scheduler health."""
from datetime import datetime, timezone
import json
import logging
from logging.handlers import WatchedFileHandler
import os
from pathlib import Path
from queue import Full, Queue
import re
import signal
import socket
import ssl
import stat
import subprocess
from threading import Event, Thread
from uuid import uuid4

from . import __version__, updates
from .config import ConfigurationError
from .renewer import RenewalExecutionError
from .scoped_renewal import ROLES, renew_scoped
from .sddc_install import InstallError, _load, _locked_state, _write
from .task_guard import Stop

CATALOG = {
    "VCF-1000": "INFO", "VCF-1010": "INFO", "VCF-1100": "INFO", "VCF-1110": "INFO", "VCF-1200": "INFO",
    "VCF-2000": "WARNING", "VCF-2100": "WARNING", "VCF-2200": "WARNING",
    "VCF-3000": "ERROR", "VCF-3100": "ERROR", "VCF-3200": "ERROR",
    "VCF-3300": "ERROR", "VCF-4000": "CRITICAL", "VCF-4100": "CRITICAL",
    "VCF-5000": "INFO", "VCF-6000": "INFO", "VCF-6010": "INFO",
    "VCF-6020": "WARNING", "VCF-6030": "INFO",
}
SEVERITY = {"INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}
HOST = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                  r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
IDENTIFIER = re.compile(r"[a-zA-Z0-9_-]{1,128}")

STAGES = {
    "ACME_SIGNING", "ACME signing", "RESOURCE_DISCOVERY", "CSR_GENERATION",
    "CSR_TASK_POLLING", "CSR_RETRIEVAL", "CSR_WRITE", "CSR_IDENTITY",
    "ISSUED_CERTIFICATE", "CERTIFICATE_CHAIN_CONSTRUCTION", "CERTIFICATE_VALIDATION",
    "CERTIFICATE_REPLACEMENT", "POST_INSTALLATION_VERIFICATION",
    "DISCOVER_MGMT_CLUSTER", "VALIDATE_VIP_DNS_IDENTITY", "GENERATE_CSR",
    "CERTIFICATE_IMPORT", "APPLY_MGMT_CLUSTER_CERTIFICATE",
    "Fleet certificate discovery", "matching Fleet CSR lookup", "Fleet CSR generation",
    "Fleet CSR fetch and identity validation", "CSR identity validation",
    "issued certificate validation", "certificate chain construction",
    "Fleet certificate import", "Fleet certificate replacement request",
    "Fleet replacement workflow", "live HTTPS verification",
}


def now():
    return datetime.now(timezone.utc).isoformat()


def policy(environ):
    targets = {}
    for item in environ.get("VCF_RENEW_TARGETS", "").split(","):
        if not item.strip():
            continue
        role, sep, name = item.strip().partition("=")
        if not sep or role not in ROLES or role in targets or not HOST.fullmatch(name) or name in targets.values():
            raise ConfigurationError("Invalid VCF_RENEW_TARGETS policy")
        targets[role] = name
    allowed = set(environ.get("VCF_ACCEPT_UNVERIFIED_RECOVERY", "").split(",")) - {""}
    if not targets or not allowed <= targets.keys():
        raise ConfigurationError("Missing targets or invalid recovery policy")
    return targets, allowed


def _parse_int(environ, name, default, lower, upper):
    try:
        value = int(environ.get(name, default))
    except ValueError:
        raise ConfigurationError("Invalid monitoring numeric setting") from None
    if not lower <= value <= upper:
        raise ConfigurationError("Monitoring numeric setting out of range")
    return value


class Syslog:
    def __init__(self, env):
        self.host = env.get("VCF_SYSLOG_HOST")
        self.port = _parse_int(env, "VCF_SYSLOG_PORT", 6514, 1, 65535)
        self.facility = _parse_int(env, "VCF_SYSLOG_FACILITY", 16, 0, 23)
        self.app = env.get("VCF_SYSLOG_APP", "vcf-cert-renewer")
        mode = env.get("VCF_SYSLOG_TRANSPORT", "tls")
        if mode not in {"tls", "tcp"} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", self.app):
            raise ConfigurationError("Invalid syslog settings")
        self.context = ssl.create_default_context(cafile=env.get("VCF_SYSLOG_CA_FILE")) if mode == "tls" else None
        self.queue = Queue(maxsize=128)
        self.worker = Thread(target=self._send, daemon=True)
        self.worker.start()

    def put(self, event, line):
        priority = 8 * self.facility + SEVERITY[event["severity"]]
        payload = (f'<{priority}>1 {event["timestamp"]} - {self.app} '
                   f'- {event["event_id"]} - {line}').encode()
        try:
            self.queue.put_nowait(str(len(payload)).encode() + b" " + payload)
        except Full:
            pass

    def _send(self):
        while True:
            data = self.queue.get()
            if data is None:
                return
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5) as raw:
                    if self.context is None:
                        raw.sendall(data)
                    else:
                        with self.context.wrap_socket(raw, server_hostname=self.host) as stream:
                            stream.sendall(data)
            except OSError:
                continue

    def close(self):
        try:
            self.queue.put_nowait(None)
        except Full:
            pass
        self.worker.join(timeout=0.75)


class Events:
    """Emit only fields produced by this module, never raw exceptions or responses."""
    def __init__(self, env, *, stream=None):
        self.handler = None
        self.stream = stream
        filename = env.get("VCF_LOG_FILE")
        if filename:
            path = Path(filename)
            folder = path.parent.stat()
            if folder.st_uid != os.geteuid() or stat.S_IMODE(folder.st_mode) & 0o077:
                raise ConfigurationError("Unsafe log directory ownership or permissions")
            if path.is_symlink() or (path.exists() and
                                   (path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077)):
                raise ConfigurationError("Unsafe log file ownership or permissions")
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ConfigurationError("Unsafe log file type")
            finally:
                os.close(fd)
            self.handler = WatchedFileHandler(path, encoding="utf-8")
        self.syslog = Syslog(env) if env.get("VCF_SYSLOG_HOST") else None

    def emit(self, event_id, **details):
        event = dict(details, timestamp=now(), event_id=event_id, severity=CATALOG[event_id],
                     application_version=__version__)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        if self.handler is None:
            print(line, file=self.stream, flush=True)
        else:
            self.handler.handle(logging.LogRecord("vcf-cert-renewer", logging.INFO, "", 0, line, (), None))
        if self.syslog is not None:
            self.syslog.put(event, line)

    def close(self):
        if self.handler is not None:
            self.handler.close()
        if self.syslog is not None:
            self.syslog.close()


def _health(data):
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("targets"), dict):
        raise ValueError("Invalid scheduler state")


def read_state(output):
    directory = output / ".scheduler"
    try:
        fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    try:
        attrs = os.fstat(fd)
        if attrs.st_uid != os.geteuid() or stat.S_IMODE(attrs.st_mode) != 0o700:
            raise InstallError("UNSAFE_SCHEDULER_STATE")
        return _load(fd, _health, max_bytes=65536)
    finally:
        os.close(fd)


def _failure(exc):
    stage = getattr(exc, "phase", None)
    root = exc.cause if isinstance(exc, RenewalExecutionError) else exc
    diagnostic = getattr(root, "renewal_diagnostic", None) or {}
    stage = stage or diagnostic.get("stage") or diagnostic.get("operation")
    code = type(root).__name__
    if isinstance(root, (InstallError, Stop)):
        candidate = str(root) if isinstance(root, InstallError) else root.reason
        if candidate in {"ACTIVE_TASK", "CSR_IDENTITY_MISMATCH", "ISSUED_PUBLIC_KEY_MISMATCH",
                         "ISSUED_IDENTITY_MISMATCH", "FLEET_SAN_INVENTORY_MISMATCH",
                         "FLEET_TARGET_IDENTITY_UNVERIFIED", "NSX_ASSIGNMENT_UNVERIFIED",
                         "REPLACEMENT_OUTCOME_UNKNOWN_NO_TASK_ID", "PREVIOUS_REPLACEMENT_FAILED",
                         "LIVE_CERTIFICATE_UNVERIFIED", "LEGACY_SDDC_OPERATION_UNRESOLVED",
                         "REPLACEMENT_PREFLIGHT_CHANGED", "INSTALL_COMMAND_ACTIVE"}:
            code = candidate
    response = getattr(root, "response", None)
    status = getattr(response, "status_code", None)
    if stage in {"ACME_SIGNING", "ACME signing"}:
        event = "VCF-3000"
    elif status in {401, 403} or stage == "RESOURCE_DISCOVERY":
        event = "VCF-3200"
    elif "UNRESOLVED" in code or "UNKNOWN" in code or "UNVERIFIED" in code or code == "ACTIVE_TASK":
        event = "VCF-2100"
    else:
        event = "VCF-3100"
    detail = {"error_code": code}
    if isinstance(stage, str) and stage in STAGES:
        detail["stage"] = stage
    if isinstance(status, int) and 100 <= status < 600:
        detail["http_status"] = status
    return event, detail


def _certificate_observation(settings, kind, target):
    from .scoped_renewal import _live, _fingerprint
    cert = _live(target)
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    fields = {"fingerprint": _fingerprint(cert), "expires": expires.isoformat()}
    # Files in this directory use the per-target operation schema and private owner/mode.
    from .scoped_renewal import _validate_state, INCOMPLETE
    try:
        with _locked_state(settings.output_dir, ".renew-" + kind.lower()) as fd:
            operation = _load(fd, lambda data: _validate_state(data, target, kind))
        if operation and operation["state"] in INCOMPLETE:
            fields["pending_operation"] = operation["state"]
            if operation.get("task_id"):
                fields["task_id"] = operation["task_id"]
    except (OSError, InstallError):
        fields["pending_operation"] = "STATE_UNAVAILABLE"
    return fields


def scheduled(settings, events, environ, stop=None):
    targets, allowed = policy(environ)
    operation_id = uuid4().hex
    with _locked_state(settings.output_dir, ".scheduler") as fd:
        previous = _load(fd, _health, max_bytes=65536)
        records = {k: v for k, v in previous.get("targets", {}).items()
                   if k in targets and v.get("target") == targets[k]}
        state = dict(previous, version=1, application_version=__version__, last_start=now(),
                     running=True, operation_id=operation_id, targets=records)
        _write(fd, state)
        failures = 0
        for kind, target in targets.items():
            if stop is not None and stop.is_set():
                failures += 1
                break
            prior = records.get(kind, {})
            record = dict(prior, target=target, last_check=now())
            record.setdefault("status", "CHECKING")
            for key in ("pending_operation", "task_id", "fingerprint", "expires"):
                record.pop(key, None)
            fields = {"target_type": kind, "target_fqdn": target, "operation_id": operation_id}
            def record_issuance(fingerprint, expires):
                record.update(last_validated_issuance=now(), issued_fingerprint=fingerprint)
                records[kind] = record
                _write(fd, state)
                events.emit("VCF-1110", **fields, outcome="ISSUED",
                            fingerprint=fingerprint, expires=expires)

            try:
                observation = _certificate_observation(settings, kind, target)
                if kind not in allowed:
                    result = {"result": "DISABLED"}
                    record.update(observation)
                else:
                    if not observation.get("pending_operation"):
                        expires = datetime.fromisoformat(observation["expires"])
                        if (expires - datetime.now(timezone.utc)).total_seconds() <= settings.renew_before_days * 86400:
                            record["last_attempt"] = now()
                            records[kind] = record
                            _write(fd, state)
                    result = renew_scoped(settings, target, kind=kind, poll_interval=5, poll_timeout=900,
                                          on_issued=record_issuance)
                    record.update(_certificate_observation(settings, kind, target))
                outcome = result["result"]
                record.update(status=outcome, consecutive_failures=0)
                record.pop("last_failure", None)
                if outcome == "DISABLED" and prior.get("status") != "DISABLED":
                    events.emit("VCF-2200", **fields, error_code="RECOVERY_POLICY_DISABLED")
                if outcome == "INSTALLED":
                    record["last_successful_renewal"] = now()
                    for key in ("task_id", "certificate_id"):
                        if result.get(key):
                            fields[key] = result[key]
                    events.emit("VCF-1200", **fields, fingerprint=record["fingerprint"])
                    events.emit("VCF-1100", **fields, outcome=outcome, expires=record["expires"])
                if prior.get("consecutive_failures"):
                    events.emit("VCF-5000", **fields, outcome=outcome)
            except Exception as exc:
                failures += 1
                event, detail = _failure(exc)
                try:
                    record.update(_certificate_observation(settings, kind, target))
                except Exception:
                    for key in ("expires", "fingerprint", "pending_operation", "task_id"):
                        if key in prior:
                            record[key] = prior[key]
                if record.get("pending_operation"):
                    event = "VCF-2100" if record["pending_operation"] != "TASK_FAILED" else "VCF-3100"
                record.update(status="UNRESOLVED" if event == "VCF-2100" else "FAILED",
                              last_failure=detail, consecutive_failures=prior.get("consecutive_failures", 0) + 1)
                count = record["consecutive_failures"]
                if count in {1, 3} or prior.get("last_failure") != detail:
                    events.emit(event, **fields, **detail, consecutive_failures=count,
                                **({"task_id": record["task_id"]} if record.get("task_id") else {}))
            if record.get("expires"):
                remaining = (datetime.fromisoformat(record["expires"]) - datetime.now(timezone.utc)).total_seconds() / 86400
                record["days_remaining"] = round(remaining, 2)
                band = next((day for day in (1, 3, 7, 14, 30) if remaining <= day), None)
                record["expiration_band"] = band
                if band is not None and band != prior.get("expiration_band"):
                    events.emit("VCF-4000" if band <= 3 else "VCF-2000", **fields,
                                threshold_days=band, expires=record["expires"])
            if record["status"] != prior.get("status"):
                record["last_transition"] = now()
            records[kind] = record
            _write(fd, state)
            if record["status"] == "SKIPPED":
                events.emit("VCF-1010", **fields, outcome="SKIPPED",
                            error_code="OUTSIDE_RENEWAL_WINDOW", expires=record["expires"],
                            fingerprint=record["fingerprint"])
        state.update(running=False, last_completion=now(), failures=failures)
        if not failures:
            state["last_successful_check"] = state["last_completion"]
        _write(fd, state)
        events.emit("VCF-1000", operation_id=operation_id,
                    outcome="FAILED" if failures else "COMPLETE", failures=failures)
        return int(bool(failures))


def _age(timestamp):
    if not timestamp:
        return float("inf")
    return (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()


def status(settings, environ, timer=False):
    state = read_state(settings.output_dir)
    threshold = _parse_int(environ, "VCF_HEARTBEAT_MAX_SECONDS", 93600, 60, 604800)
    issues = []
    if not state.get("last_completion") and state.get("running") and _age(state.get("last_start")) <= 3600:
        issues.append("SCHEDULER_STARTING")
    elif _age(state.get("last_completion")) > threshold:
        issues.append("SCHEDULER_HEARTBEAT_STALE")
    if state.get("running") and _age(state.get("last_start")) > 3600:
        issues.append("SCHEDULER_INCOMPLETE")
    if timer:
        for action, expected in (("is-enabled", "enabled"), ("is-active", "active")):
            check = subprocess.run(["systemctl", action, "vcf-cert-renewer.timer"],
                                   capture_output=True, text=True, timeout=5)
            if check.stdout.strip() != expected:
                issues.append("TIMER_NOT_" + expected.upper())
        result = subprocess.run(["systemctl", "show", "-p", "Result", "--value",
                                 "vcf-cert-renewer.service"], capture_output=True, text=True, timeout=5)
        if result.returncode or result.stdout.strip() not in {"success", ""}:
            issues.append("SCHEDULER_SERVICE_FAILED")
    targets = state.get("targets", {})
    for kind, record in targets.items():
        expires = record.get("expires")
        if expires:
            days = -_age(expires) / 86400
            record["days_remaining"] = round(days, 2)
            record["certificate_due"] = days <= settings.renew_before_days
            if days <= 3:
                issues.append(kind + "_CERTIFICATE_EXPIRATION_IMMINENT")
        if record.get("pending_operation"):
            issues.append(kind + "_UNRESOLVED")
        elif record.get("status") in {"FAILED", "UNRESOLVED"}:
            issues.append(kind + "_" + record["status"])
    if state.get("failures") and not any("FAILED" in item or "UNRESOLVED" in item for item in issues):
        issues.append("SCHEDULER_FAILED")
    return {**state, "healthy": not issues, "issues": issues,
            "software_update": updates.status(settings.output_dir, environ)}


def _watchdog_state(data):
    if not isinstance(data, dict) or not isinstance(data.get("issues"), list):
        raise ValueError("Invalid watchdog state")


def watchdog(settings, events, environ, *, timer=False):
    health = status(settings, environ, timer=timer)
    with _locked_state(settings.output_dir, ".watchdog") as fd:
        previous = _load(fd, _watchdog_state)
        issues = health["issues"]
        for issue in sorted(set(issues) - set(previous.get("issues", []))):
            event = ("VCF-4100" if issue.startswith(("SCHEDULER_", "TIMER_"))
                     else "VCF-4000" if issue.endswith("IMMINENT")
                     else "VCF-2100" if issue.endswith("UNRESOLVED") else "VCF-3300")
            events.emit(event, error_code=issue)
        for issue in sorted(set(previous.get("issues", [])) - set(issues)):
            events.emit("VCF-5000", recovered_condition=issue)
        _write(fd, {"issues": issues})
    return int(bool(health["issues"]))


def run_loop(settings, events, environ):
    period = _parse_int(environ, "VCF_CHECK_INTERVAL_SECONDS", 86400, 60, 604800)
    stopped = Event()

    def stop(*_):
        stopped.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    while not stopped.is_set():
        try:
            scheduled(settings, events, environ, stopped)
            if not stopped.is_set():
                updates.advisory(settings.output_dir, events, environ)
        except Exception as exc:
            events.emit("VCF-3300", error_code=type(exc).__name__)
        stopped.wait(period)
    return 0
