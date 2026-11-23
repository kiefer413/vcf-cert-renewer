"""Guarded installation of existing SDDC certificate artifacts."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import requests

from .client import WorkflowFailedError
from .fullchain import _self_signed, _verify_child
from .sddc_client import SddcApiClient
from .signer import reuse_signed_csr
from .task_guard import Stop, check_tasks

METHOD = "PUT /v1/domains/{id}/resource-certificates"
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")
ENCODING = serialization.Encoding
BLOCKING = {"SUBMITTING", "TASK_PENDING", "TASK_FAILED", "VERIFY_PENDING"}


class InstallError(Exception):
    """Only fixed messages and validated identifiers may cross the CLI boundary."""


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _bundle(path):
    data = path.read_bytes()
    blocks = PEM.findall(data)
    if not blocks or PEM.sub(b"", data).strip():
        raise ValueError("invalid PEM")
    certs = [x509.load_pem_x509_certificate(block) for block in blocks]
    if len({_fingerprint(cert) for cert in certs}) != len(certs):
        raise ValueError("duplicate certificate in bundle")
    return certs


def _payload(leaf_bundle, issuer_bundle, *, require_root=False):
    leaf = leaf_bundle[0]
    pool = {_fingerprint(cert): cert for cert in (*leaf_bundle[1:], *issuer_bundle)}
    if _fingerprint(leaf) in pool or _self_signed(leaf):
        raise ValueError("invalid leaf")
    path = [leaf]
    while pool:
        issuers = []
        for cert in pool.values():
            try:
                _verify_child(path[-1], cert)
            except ValueError:
                continue
            issuers.append(cert)
        if len(issuers) != 1:
            raise ValueError("ambiguous or disconnected issuer chain")
        issuer = issuers[0]
        del pool[_fingerprint(issuer)]
        if _self_signed(issuer):
            if pool:
                raise ValueError("unused certificates")
            if require_root:
                path.append(issuer)
            break
        path.append(issuer)
    if require_root and not _self_signed(path[-1]):
        raise ValueError("missing self-signed root")
    if len(path) < 2:
        raise ValueError("missing intermediate")
    leaf_pem, *intermediates = [cert.public_bytes(ENCODING.PEM) for cert in path]
    chain = b"".join(intermediates)
    with tempfile.TemporaryDirectory(prefix="sddc-chain-") as directory:
        leaf_file, chain_file = (Path(directory) / name for name in ("leaf.pem", "issuers.pem"))
        leaf_file.write_bytes(leaf_pem)
        chain_file.write_bytes(chain)
        subprocess.run(["openssl", "verify", "-purpose", "sslserver",
                        "-untrusted", str(chain_file), str(leaf_file)],
                       check=True, capture_output=True, timeout=10)
    return leaf, (leaf_pem + chain).decode("ascii")


def _artifacts(settings, target):
    csr_path = settings.output_dir / f"{target}.csr.pem"
    directory = settings.output_dir / "acme" / "production" / "certificates"
    try:
        # Feed B12 and the payload builder the same protected local snapshot.
        with tempfile.TemporaryDirectory(prefix="sddc-artifacts-") as snapshot:
            root = Path(snapshot)
            snapshot_dir = root / "acme" / "production" / "certificates"
            snapshot_dir.mkdir(parents=True)
            leaf_path = snapshot_dir / f"{target}.crt"
            issuer_path = snapshot_dir / f"{target}.issuer.crt"
            for copy in (leaf_path, issuer_path):
                copy.write_bytes((directory / copy.name).read_bytes())
            snapshot_csr = root / csr_path.name
            snapshot_csr.write_bytes(csr_path.read_bytes())
            csr = x509.load_pem_x509_csr(snapshot_csr.read_bytes())
            leaf_bundle, issuer_bundle = _bundle(leaf_path), _bundle(issuer_path)
            reuse_signed_csr(replace(settings, output_dir=root), target, snapshot_csr)
            leaf, chain = _payload(leaf_bundle, issuer_bundle)
    except FileNotFoundError:
        raise InstallError("MISSING_CERTIFICATE_ARTIFACT") from None
    except (OSError, ValueError, subprocess.SubprocessError):
        raise InstallError("CERTIFICATE_ARTIFACT_VALIDATION_FAILED") from None
    return {"certificate": _fingerprint(leaf),
            "csr": sha256(csr.public_bytes(ENCODING.DER)).hexdigest(),
            "chain": sha256(chain.encode("ascii")).hexdigest()}, chain


def _trusted_live_certificate(target, port):
    with socket.create_connection((target, port), timeout=10) as conn:
        with ssl.create_default_context().wrap_socket(conn, server_hostname=target) as tls:
            return tls.getpeercert(binary_form=True)


def _live_fingerprint(target, port):
    return sha256(_trusted_live_certificate(target, port)).hexdigest()


def _rollback_readiness():
    # The supported recovery instructions require the old matching private key.
    # No verified mechanism for recovering that appliance-held key is available.
    return "ROLLBACK_NOT_VERIFIED"


def _check_private(fd, expected_mode, kind):
    attrs = os.fstat(fd)
    if attrs.st_uid != os.geteuid() or stat.S_IMODE(attrs.st_mode) != expected_mode or not kind(attrs.st_mode):
        raise InstallError("UNSAFE_OPERATION_STATE_PERMISSIONS")


@contextmanager
def _locked_state(output, directory_name=".sddc-install"):
    directory = output / directory_name
    directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _check_private(fd, 0o700, stat.S_ISDIR)
        lock = os.open("lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=fd)
        try:
            _check_private(lock, 0o600, stat.S_ISREG)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallError("INSTALL_COMMAND_ACTIVE") from None
            yield fd
        finally:
            os.close(lock)
    finally:
        os.close(fd)


def _load(fd, validate=None, *, max_bytes=8192):
    try:
        state = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return {}
    with os.fdopen(state, "r") as handle:
        _check_private(handle.fileno(), 0o600, stat.S_ISREG)
        try:
            raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError
            data = json.loads(raw)
            (validate or _validate_state)(data)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise InstallError("INVALID_OPERATION_STATE") from None
    return data


def _validate_state(data):
    if (not isinstance(data, dict) or type(data.get("version")) is not int
            or data["version"] != 1 or data["method"] != METHOD
            or data["state"] not in BLOCKING | {"PREPARED", "INSTALLED"}
            or data["rollback"] not in {"VERIFIED", "ROLLBACK_NOT_VERIFIED"}
            or type(data["tasks_checked"]) is not int or data["tasks_checked"] < 0
            or datetime.fromisoformat(data["prepared_at"]).utcoffset() is None
            or not re.fullmatch(r"[a-z0-9-]+(?:[.][a-z0-9-]+)+", data["target"])):
        raise ValueError
    for field in ("certificate", "csr", "chain", "live_certificate"):
        if not re.fullmatch(r"[0-9a-f]{64}", data[field]):
            raise ValueError
    for field in ("domain_id", "resource_id"):
        UUID(data[field])
    if data["state"] in {"PREPARED", "SUBMITTING"}:
        if "task_id" in data:
            raise ValueError
    else:
        UUID(data["task_id"])
    acknowledged = data.get("unverified_rollback_acknowledged", False)
    if type(acknowledged) is not bool:
        raise ValueError
    if acknowledged and (data["state"] == "PREPARED" or data["rollback"] != "ROLLBACK_NOT_VERIFIED"):
        raise ValueError
    if data["state"] != "PREPARED" and data["rollback"] != "VERIFIED" and not acknowledged:
        raise ValueError


def _write(fd, data):
    # Use a directory-relative name so the lock and manifest stay in the same directory.
    name = ".state-" + os.urandom(12).hex()
    state = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
    try:
        with os.fdopen(state, "w") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, "state.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def _reconcile(fd, state, client, target, port):
    status = state.get("state")
    if status == "SUBMITTING":
        raise InstallError("REPLACEMENT_OUTCOME_UNKNOWN_NO_TASK_ID")
    if status in {"TASK_FAILED", "INSTALLED"}:
        return {"result": status, "task_id": str(UUID(state["task_id"]))}
    if status not in {"TASK_PENDING", "VERIFY_PENDING"}:
        raise InstallError("NO_REPLACEMENT_TASK")
    task_id = str(UUID(state["task_id"]))
    if status == "TASK_PENDING":
        for attempt in range(3):
            try:
                client.wait_task(task_id, poll_timeout=120)
                break
            except (requests.ConnectionError, requests.Timeout):
                if attempt == 2:
                    raise InstallError("TASK_POLL_DISCONNECTED " + task_id) from None
                time.sleep(2)
            except WorkflowFailedError:
                _write(fd, dict(state, state="TASK_FAILED"))
                raise InstallError("TASK_FAILED " + task_id) from None
            except Exception:
                raise InstallError("TASK_STATUS_UNVERIFIED " + task_id) from None
        state = dict(state, state="VERIFY_PENDING")
        _write(fd, state)
    try:
        matches = _live_fingerprint(target, port) == state["certificate"]
        domain, resource = client.resolve_context(target, "SDDC_MANAGER")
        healthy = (str(UUID(domain)) == state["domain_id"]
                   and str(UUID(resource["resourceId"])) == state["resource_id"])
    except Exception:
        raise InstallError("POST_INSTALL_HEALTH_UNVERIFIED " + task_id) from None
    if not matches or not healthy:
        reason = "POST_INSTALL_FINGERPRINT_MISMATCH" if not matches else "POST_INSTALL_IDENTITY_MISMATCH"
        raise InstallError(reason + " " + task_id)
    _write(fd, dict(state, state="INSTALLED"))
    return {"result": "INSTALLED", "task_id": task_id}


def install_existing(settings, target, mode, *, accept_unverified_rollback=False):
    url = urlsplit(settings.sddc_url)
    target = target.rstrip(".").lower()
    if (not re.fullmatch(r"[a-z0-9-]+(?:[.][a-z0-9-]+)+", target)
            or target != url.hostname or url.scheme != "https" or url.username is not None
            or url.path not in ("", "/") or url.query or url.fragment):
        raise InstallError("TARGET_IS_NOT_CONFIGURED_SDDC_MANAGER")
    if os.geteuid() != 0:
        raise InstallError("ROOT_REQUIRED")
    if settings.acme_mode != "production":
        raise InstallError("PRODUCTION_CERTIFICATE_ARTIFACTS_REQUIRED")
    port = url.port or 443
    with _locked_state(settings.output_dir) as fd:
        if mode == "apply" and os.path.lexists(settings.output_dir / ".renew-sddc_manager"):
            from .scoped_renewal import INCOMPLETE, _validate_state as validate_scoped
            with _locked_state(settings.output_dir, ".renew-sddc_manager") as scoped_fd:
                operation = _load(scoped_fd, lambda data: validate_scoped(data, target, "SDDC_MANAGER"))
            if operation and operation["state"] in INCOMPLETE:
                raise InstallError("SCOPED_SDDC_OPERATION_UNRESOLVED")
        previous = _load(fd)
        if previous and previous.get("target") != target:
            raise InstallError("OPERATION_STATE_TARGET_MISMATCH")
        if mode == "status":
            if not previous:
                return {"result": "NOT_PREPARED", "target": target}
            if previous["state"] == "PREPARED":
                readiness = _rollback_readiness()
                rollback = (previous["rollback"] if readiness == "VERIFIED" else readiness)
                age = datetime.now(timezone.utc) - datetime.fromisoformat(previous["prepared_at"])
                return {"result": "PREPARED", "target": target, "rollback": rollback,
                        "task_id": None, "apply_permitted": (
                            rollback == "VERIFIED" and timedelta(0) <= age <= timedelta(minutes=10))}
        client = SddcApiClient(settings.sddc_url, *settings.require_sddc_credentials(), verify_tls=True)
        if mode == "status" or previous.get("state") in BLOCKING:
            return _reconcile(fd, previous, client, target, port)
        artifacts, chain = _artifacts(settings, target)
        domain, resource = client.resolve_context(target, "SDDC_MANAGER")
        if resource["type"] != "SDDC_MANAGER" or resource["fqdn"] != target:
            raise InstallError("SDDC_INVENTORY_IDENTITY_MISMATCH")
        live = _live_fingerprint(target, port)
        if live == artifacts["certificate"]:
            return {"result": "ALREADY_INSTALLED", "certificate": live}
        try:
            appliance_csr = x509.load_pem_x509_csr(client.fetch_csr(domain, resource).encode("ascii"))
            csr_matches = (appliance_csr.is_signature_valid and
                           sha256(appliance_csr.public_bytes(ENCODING.DER)).hexdigest() == artifacts["csr"])
        except Exception:
            raise InstallError("APPLIANCE_CSR_UNVERIFIED") from None
        if not csr_matches:
            raise InstallError("APPLIANCE_CSR_MISMATCH")
        try:
            count = check_tasks(client.task_inventory_page)
        except Stop as exc:
            raise InstallError(str(exc)) from None
        manifest = dict(artifacts, version=1, state="PREPARED", target=target,
                        domain_id=str(UUID(domain)), resource_id=str(UUID(resource["resourceId"])),
                        live_certificate=live, method=METHOD, rollback=_rollback_readiness())
        now = datetime.now(timezone.utc)
        if mode == "prepare":
            _write(fd, dict(manifest, prepared_at=now.isoformat(), tasks_checked=count))
            return {"result": manifest["rollback"], "manifest": str(settings.output_dir / ".sddc-install/state.json")}
        if previous.get("state") != "PREPARED":
            raise InstallError("PREPARATION_REQUIRED")
        if any(previous.get(key) != value for key, value in manifest.items() if key != "rollback"):
            raise InstallError("PREPARATION_MISMATCH")
        age = now - datetime.fromisoformat(previous["prepared_at"])
        if not timedelta(0) <= age <= timedelta(minutes=10):
            raise InstallError("PREPARATION_STALE")
        rollback = manifest["rollback"]
        if previous["rollback"] != rollback:
            raise InstallError("PREPARATION_MISMATCH")
        acknowledged = rollback == "ROLLBACK_NOT_VERIFIED" and accept_unverified_rollback is True
        if rollback != "VERIFIED" and not acknowledged:
            raise InstallError("ROLLBACK_NOT_VERIFIED")
        state = dict(previous, state="SUBMITTING")
        if acknowledged:
            state["unverified_rollback_acknowledged"] = True
        _write(fd, state)
        try:
            task, _ = client.submit_certificate_replacement(domain, resource, chain,
                                                             allow_redirects=False)
            task_id = str(UUID(task))
            state = dict(state, state="TASK_PENDING", task_id=task_id)
            _write(fd, state)
        except Exception:
            raise InstallError("REPLACEMENT_OUTCOME_UNKNOWN_CHECK_STATE") from None
        return _reconcile(fd, state, client, target, port)
