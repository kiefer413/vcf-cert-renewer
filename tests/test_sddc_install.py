"""Offline integration tests. VMware and live TLS are replaced with local mocks."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from unittest.mock import Mock

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from test_reuse_signed_csr import artifacts, TARGET
from vcf_cert_renewer import sddc_install as install
from vcf_cert_renewer.cli import _parser, main
from vcf_cert_renewer.client import WorkflowFailedError

DOMAIN = "10000000-0000-4000-8000-000000000001"
RESOURCE = "10000000-0000-4000-8000-000000000002"
TASK = "10000000-0000-4000-8000-000000000003"
OLD, NEW = "1" * 64, "2" * 64


@pytest.fixture
def workflow(artifacts, monkeypatch):
    settings, csr, *_ = artifacts
    settings = replace(settings, sddc_url=f"https://{TARGET}", sddc_username="fixture",
                       sddc_password="fixture", acme_mode="production")
    client = Mock()
    client.resolve_context.return_value = (DOMAIN, {
        "resourceId": RESOURCE, "type": "SDDC_MANAGER", "fqdn": TARGET})
    client.fetch_csr.return_value = csr.read_text()
    digest = sha256(x509.load_pem_x509_csr(csr.read_bytes()).public_bytes(
        serialization.Encoding.DER)).hexdigest()
    client.task_inventory_page.return_value = {
        "elements": [], "pageMetadata": {
            "pageNumber": 1, "pageSize": 100, "totalPages": 0, "totalElements": 0}}
    client.submit_certificate_replacement.return_value = (TASK, {})
    client.wait_task.return_value = {"status": "SUCCESSFUL"}
    api = Mock(return_value=client)
    monkeypatch.setattr(install, "SddcApiClient", api)
    monkeypatch.setattr(install.os, "geteuid", lambda: 0)
    actual_uid = os.stat(settings.output_dir).st_uid
    check_private = install._check_private

    def check_permissions(fd, mode, kind):
        with monkeypatch.context() as patch:
            patch.setattr(install.os, "geteuid", lambda: actual_uid)
            check_private(fd, mode, kind)

    monkeypatch.setattr(install, "_check_private", check_permissions)
    monkeypatch.setattr(install, "_artifacts", Mock(return_value=(
        {"certificate": NEW, "csr": digest, "chain": "3" * 64}, "fixture-chain")))
    live = Mock(return_value=OLD)
    monkeypatch.setattr(install, "_live_fingerprint", live)
    monkeypatch.setattr("vcf_cert_renewer.cli.Settings.load", Mock(return_value=settings))
    path = settings.output_dir / ".sddc-install" / "state.json"

    def run(mode, **kwargs):
        return install.install_existing(settings, TARGET, mode, **kwargs)

    return run, client, live, path


def test_prepare_and_real_rollback_gate(workflow):
    run, client, _, path = workflow
    assert run("prepare")["result"] == "ROLLBACK_NOT_VERIFIED"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(path.read_text())["live_certificate"] == OLD
    with pytest.raises(install.InstallError, match="ROLLBACK_NOT_VERIFIED"):
        run("apply")
    client.submit_certificate_replacement.assert_not_called()
    client.generate_csr.assert_not_called()
    client.validate_certificate.assert_not_called()


@pytest.mark.parametrize("case,reason", [
    ("stale", "PREPARATION_STALE"), ("changed", "PREPARATION_MISMATCH"),
    ("active", "ACTIVE_TASK"), ("csr", "APPLIANCE_CSR_UNVERIFIED"),
    ("type", "SDDC_INVENTORY_IDENTITY_MISMATCH"),
])
def test_preflight_refusals(workflow, case, reason):
    run, client, live, path = workflow
    run("prepare")
    if case == "stale":
        payload = json.loads(path.read_text())
        payload["prepared_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        path.write_text(json.dumps(payload))
    if case == "changed":
        live.return_value = "4" * 64
    if case == "active":
        response = client.task_inventory_page.return_value
        response["elements"] = [{"id": TASK, "status": "In Progress"}]
        response["pageMetadata"].update(totalPages=1, totalElements=1)
    if case == "csr":
        client.fetch_csr.return_value = "bad pem"
    if case == "type":
        client.resolve_context.return_value[1]["type"] = "VCENTER"
    with pytest.raises(install.InstallError, match=reason):
        run("apply", accept_unverified_rollback=True)
    client.submit_certificate_replacement.assert_not_called()


@pytest.mark.parametrize("case,reason", [
    ("success", None), ("lost-submit", "REPLACEMENT_OUTCOME_UNKNOWN"),
    ("failed", "TASK_FAILED"), ("fingerprint", "POST_INSTALL_FINGERPRINT_MISMATCH"),
    ("unhealthy", "POST_INSTALL_HEALTH_UNVERIFIED"), ("poll-disconnect", None),
    ("poll-unknown", "TASK_STATUS_UNVERIFIED"),
])
def test_replacement_and_reconciliation(workflow, monkeypatch, case, reason):
    run, client, live, path = workflow
    monkeypatch.setattr(install, "_rollback_readiness", lambda: "VERIFIED")
    monkeypatch.setattr(install.time, "sleep", lambda _: None)
    run("prepare")
    live.side_effect = [OLD, OLD if case == "fingerprint" else NEW]
    if case == "lost-submit":
        client.submit_certificate_replacement.side_effect = requests.Timeout
    if case == "failed":
        client.wait_task.side_effect = WorkflowFailedError("SECRET")
    if case == "poll-unknown":
        client.wait_task.side_effect = ValueError("SECRET")
    if case == "poll-disconnect":
        client.wait_task.side_effect = [requests.ConnectionError(), {}]
    if case == "unhealthy":
        client.resolve_context.side_effect = [client.resolve_context.return_value, requests.Timeout()]
    if reason:
        with pytest.raises(install.InstallError, match=reason) as error:
            run("apply")
        assert "SECRET" not in str(error.value)
    else:
        assert run("apply") == {"result": "INSTALLED", "task_id": TASK}
    client.submit_certificate_replacement.assert_called_once_with(
        DOMAIN, client.resolve_context.return_value[1], "fixture-chain", allow_redirects=False)
    if case == "lost-submit":
        with pytest.raises(install.InstallError, match="OUTCOME_UNKNOWN_NO_TASK_ID"):
            run("apply")
    if case == "success":
        live.side_effect = None
        live.return_value = NEW
        assert run("apply")["result"] == "ALREADY_INSTALLED"
        assert run("status")["task_id"] == TASK
    if case == "poll-unknown":
        client.wait_task.side_effect = None
        live.side_effect = None
        live.return_value = NEW
        assert run("status")["result"] == "INSTALLED"
    assert client.submit_certificate_replacement.call_count == 1
    client.generate_csr.assert_not_called()


def test_cli(monkeypatch, capsys):
    monkeypatch.setattr("vcf_cert_renewer.cli.Settings.load", Mock())
    call = Mock(return_value={"result": "ALREADY_INSTALLED"})
    monkeypatch.setattr("vcf_cert_renewer.cli.install_existing", call)
    assert main(["install", TARGET, "--existing", "--apply", "--yes"]) == 0
    assert "ALREADY_INSTALLED" in capsys.readouterr().out
    assert main(["install", TARGET, "--existing", "--apply"]) == 2
    assert call.call_count == 1
    with pytest.raises(SystemExit):
        _parser().parse_args(["install", "--existing", "--prepare"])


def test_wrong_configured_host_is_rejected_before_api(artifacts):
    settings, *_ = artifacts
    with pytest.raises(install.InstallError, match="TARGET_IS_NOT_CONFIGURED_SDDC_MANAGER"):
        install.install_existing(settings, "wrong.example", "prepare")


@pytest.mark.parametrize("problem", ["missing", "invalid-csr", "wrong-san", "wrong-key",
                                     "expired", "near-expiry", "key-block", "duplicate", "chain"])
def test_real_artifact_validation_rejects_invalid_input(artifacts, problem):
    settings, csr, _, _, certificate, key, root = artifacts
    settings = replace(settings, acme_mode="production")
    directory = settings.output_dir / "acme/production/certificates"
    directory.mkdir(parents=True, exist_ok=True)
    local_csr = settings.output_dir / f"{TARGET}.csr.pem"
    local_csr.write_bytes(b"invalid" if problem == "invalid-csr" else csr.read_bytes())
    leaf = certificate("wrong.example" if problem == "wrong-san" else TARGET,
                       root.public_key() if problem == "wrong-key" else key.public_key(),
                       {"expired": -1, "near-expiry": 1}.get(problem, 90))
    if problem != "missing":
        (directory / f"{TARGET}.crt").write_bytes(leaf * (2 if problem == "duplicate" else 1))
    issuer = certificate("", root.public_key(), 90, True)
    (directory / f"{TARGET}.issuer.crt").write_bytes(
        b"bad chain" if problem == "chain" else issuer +
        ((b"-----BEGIN " b"PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----") if problem == "key-block" else b""))
    with pytest.raises(install.InstallError, match="MISSING_CERTIFICATE_ARTIFACT" if problem == "missing"
                       else "CERTIFICATE_ARTIFACT_VALIDATION_FAILED"):
        install._artifacts(settings, TARGET)


def test_real_payload_orders_intermediate_and_excludes_root(artifacts, monkeypatch):
    settings, csr, _, _, certificate, key, root = artifacts
    settings = replace(settings, acme_mode="production")
    directory = settings.output_dir / "acme/production/certificates"
    directory.mkdir(parents=True, exist_ok=True)
    (settings.output_dir / f"{TARGET}.csr.pem").write_bytes(csr.read_bytes())
    root_pem = certificate("", root.public_key(), 90, True)
    root_cert = x509.load_pem_x509_certificate(root_pem)
    trust = settings.output_dir / "fixture-root.pem"
    trust.write_bytes(root_pem)
    openssl_run = install.subprocess.run

    def verify_with_fixture_ca(command, **kwargs):
        assert command[:2] == ["openssl", "verify"]
        return openssl_run(command[:2] + ["-CAfile", str(trust)] + command[2:], **kwargs)

    monkeypatch.setattr(install.subprocess, "run", verify_with_fixture_ca)

    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Fixture Intermediate")])
    leaf_name = x509.load_pem_x509_csr(csr.read_bytes()).subject
    now = datetime.now(timezone.utc)

    def build(subject, issuer, public_key, is_ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=85))
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True))

    encode = serialization.Encoding.PEM
    intermediate = build(issuer_name, root_cert.subject, issuer_key.public_key(), True).sign(
        root, hashes.SHA256()).public_bytes(encode)
    leaf = (build(leaf_name, issuer_name, key.public_key(), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(TARGET)]), False)
            .sign(issuer_key, hashes.SHA256()).public_bytes(encode))
    (directory / f"{TARGET}.crt").write_bytes(leaf + intermediate)
    (directory / f"{TARGET}.issuer.crt").write_bytes(root_pem + intermediate)
    manifest, chain = install._artifacts(settings, TARGET)
    assert chain.encode("ascii") == leaf + intermediate
    assert manifest["chain"] == sha256(leaf + intermediate).hexdigest()


def _cli(mode, *options):
    return main(["install", TARGET, "--existing", f"--{mode}", *options])


def test_cli_prepare_status_and_blocked_apply(workflow, capsys, monkeypatch):
    _, client, _, path = workflow
    execute = Mock(side_effect=AssertionError("unexpected external process"))
    monkeypatch.setattr(install.subprocess, "run", execute)
    assert _cli("prepare") == 1
    assert json.loads(capsys.readouterr().out)["result"] == "ROLLBACK_NOT_VERIFIED"
    manifest = path.read_bytes()
    client.reset_mock()
    assert _cli("status") == 0
    assert json.loads(capsys.readouterr().out) == {
        "result": "PREPARED", "target": TARGET, "rollback": "ROLLBACK_NOT_VERIFIED",
        "task_id": None, "apply_permitted": False,
    }
    assert client.mock_calls == []
    assert _cli("apply", "--yes") == 1
    assert capsys.readouterr().err.strip() == "ROLLBACK_NOT_VERIFIED"
    client.submit_certificate_replacement.assert_not_called()
    client.generate_csr.assert_not_called()
    execute.assert_not_called()
    assert path.read_bytes() == manifest


def test_cli_missing_manifest(workflow, capsys):
    _, client, _, path = workflow
    assert _cli("status") == 0
    assert json.loads(capsys.readouterr().out)["result"] == "NOT_PREPARED"
    assert not path.exists()
    assert client.mock_calls == []


@pytest.mark.parametrize("case", ["bad-json", "invalid-state", "missing-field", "unexpected-target",
                                 "prepared-with-task", "pending-without-task"])
def test_cli_invalid_manifest(workflow, capsys, case):
    run, client, _, path = workflow
    run("prepare")
    state = json.loads(path.read_text())
    if case == "invalid-state":
        state["state"] = "UNKNOWN"
    elif case == "missing-field":
        del state["csr"]
    elif case == "unexpected-target":
        state["target"] = "other.example"
    elif case == "prepared-with-task":
        state["task_id"] = TASK
    elif case == "pending-without-task":
        state.update(state="TASK_PENDING", rollback="VERIFIED")
    path.write_text("{" if case == "bad-json" else json.dumps(state))
    before = path.read_bytes()
    client.reset_mock()
    assert _cli("status") == 1
    expected = "OPERATION_STATE_TARGET_MISMATCH" if case == "unexpected-target" else "INVALID_OPERATION_STATE"
    assert capsys.readouterr().err.strip() == expected
    assert path.read_bytes() == before
    assert client.mock_calls == []


@pytest.mark.parametrize("case,expected", [
    ("active", "TASK_STATUS_UNVERIFIED"), ("inaccessible", "TASK_STATUS_UNVERIFIED"),
    ("mismatch", "POST_INSTALL_FINGERPRINT_MISMATCH"), ("success", "INSTALLED"),
    ("failure", "TASK_FAILED"), ("ambiguous", "REPLACEMENT_OUTCOME_UNKNOWN_NO_TASK_ID"),
])
def test_cli_status_reconciliation(workflow, monkeypatch, capsys, case, expected):
    run, client, live, path = workflow
    monkeypatch.setattr(install, "_rollback_readiness", lambda: "VERIFIED")
    run("prepare")
    if case == "ambiguous":
        client.submit_certificate_replacement.side_effect = requests.Timeout()
        assert _cli("apply", "--yes") == 1
        capsys.readouterr()
        before = path.read_bytes()
        assert _cli("status") == 1
        assert capsys.readouterr().err.strip() == expected
        assert _cli("apply", "--yes") == 1
        assert path.read_bytes() == before
        client.submit_certificate_replacement.assert_called_once()
        return
    state = dict(json.loads(path.read_text()), state="TASK_PENDING", task_id=TASK)
    path.write_text(json.dumps(state))
    if case == "active":
        from vcf_cert_renewer.client import WorkflowTimeoutError
        client.wait_task.side_effect = WorkflowTimeoutError("polling timed out")
    elif case == "inaccessible":
        client.wait_task.side_effect = requests.HTTPError("unavailable")
    elif case == "failure":
        client.wait_task.side_effect = WorkflowFailedError("failed")
    elif case == "success":
        live.return_value = NEW
    status = _cli("status")
    output = capsys.readouterr()
    if case == "success":
        assert status == 0
        assert json.loads(output.out)["result"] == expected
    else:
        assert status == 1
        assert output.err.strip() == f"{expected} {TASK}"
    assert json.loads(path.read_text())["task_id"] == TASK
    client.submit_certificate_replacement.assert_not_called()
    if case == "failure":
        assert _cli("status") == 0
        assert json.loads(capsys.readouterr().out)["result"] == "TASK_FAILED"


@pytest.mark.parametrize("lost", [False, True])
def test_acknowledgement_records_limitation_before_request(workflow, capsys, lost):
    run, client, live, path = workflow
    run("prepare")
    assert _cli("status", "--accept-unverified-rollback") == 2
    capsys.readouterr()
    live.side_effect = [OLD, NEW]

    def submit(*args, **kwargs):
        state = json.loads(path.read_bytes())
        assert state["state"] == "SUBMITTING"
        assert state["rollback"] == "ROLLBACK_NOT_VERIFIED"
        assert state["unverified_rollback_acknowledged"] is True
        if lost:
            raise requests.Timeout()
        return TASK, {}

    client.submit_certificate_replacement.side_effect = submit
    assert _cli("apply", "--yes", "--accept-unverified-rollback") == int(lost)
    capsys.readouterr()
    state = path.read_bytes()
    if lost:
        assert _cli("status") == 1
        assert _cli("apply", "--yes", "--accept-unverified-rollback") == 1
        assert path.read_bytes() == state
    else:
        assert _cli("status") == 0
        assert json.loads(path.read_bytes())["state"] == "INSTALLED"
    client.submit_certificate_replacement.assert_called_once()
    client.generate_csr.assert_not_called()


@pytest.mark.parametrize("error", ["invalid certificate", "wrong CSR key", "wrong SAN", "bad chain"])
def test_acknowledgement_keeps_artifact_validation(workflow, monkeypatch, error):
    run, client, _, path = workflow
    run("prepare")
    before = path.read_bytes()
    monkeypatch.setattr(install, "_artifacts", Mock(side_effect=install.InstallError(error)))
    with pytest.raises(install.InstallError, match=error):
        run("apply", accept_unverified_rollback=True)
    assert path.read_bytes() == before
    client.submit_certificate_replacement.assert_not_called()
