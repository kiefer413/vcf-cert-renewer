from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
import requests
from vcf_cert_renewer import scoped_renewal as scoped
from vcf_cert_renewer.cli import main
from vcf_cert_renewer.sddc_install import InstallError

VC, NSX = scoped.TARGETS
FP, NEW = "a" * 64, "b" * 64


@pytest.fixture
def operation(monkeypatch):
    c = Mock()
    live = object()
    monkeypatch.setattr(scoped, "_fingerprint", lambda cert: FP if cert is live else NEW)
    monkeypatch.setattr(scoped, "_live", lambda _: live)
    journal = Mock()
    monkeypatch.setattr(scoped, "_write", journal)
    monkeypatch.setattr(scoped, "check_tasks", Mock())
    op = scoped.Replacement(99, VC, live, c, {})
    op.expected = NEW
    return op, c, journal


def test_vcenter_recovers_task_without_second_submission(operation, monkeypatch):
    op, c, journal = operation
    task_id = str(uuid4())
    c.submit_certificate_replacement.return_value = (task_id, {})
    c.wait_task.side_effect = requests.Timeout()
    with pytest.raises(requests.Timeout):
        op.replace_vcenter("domain", {}, "chain", poll_interval=1, poll_timeout=2)
    assert [call.args[1]["state"] for call in journal.call_args_list] == ["SUBMITTING", "TASK_PENDING"]
    with patch.object(scoped, "_live", return_value=object()):
        c.wait_task.side_effect = None
        assert op.reconcile(1, 2)["fingerprint"] == NEW
    c.submit_certificate_replacement.assert_called_once()
    assert op.state["state"] == "INSTALLED"


def test_vcenter_missing_task_id_stays_blocked(operation):
    op, c, _ = operation
    c.submit_certificate_replacement.side_effect = requests.Timeout()
    with pytest.raises(requests.Timeout):
        op.replace_vcenter("domain", {}, "chain", poll_interval=1, poll_timeout=2)
    with pytest.raises(InstallError, match="OUTCOME_UNKNOWN"):
        op.reconcile(1, 2)
    assert op.state["state"] == "SUBMITTING"
    c.submit_certificate_replacement.assert_called_once()


def test_nsx_reconciles_assignment_and_vip_after_disconnect(operation):
    op, c, _ = operation
    op.target = NSX
    op.kind = "NSX"
    cert_id = str(uuid4())
    c.apply_mgmt_cluster.side_effect = requests.Timeout()
    with pytest.raises(requests.Timeout):
        op.apply_nsx(cert_id)
    c.discover.return_value = {"certificate": {"id": str(uuid4())}}
    with pytest.raises(InstallError, match="NSX_ASSIGNMENT_UNVERIFIED"):
        op.reconcile(1, 2)
    c.discover.return_value = {"certificate": {"id": cert_id}}
    with pytest.raises(InstallError, match="LIVE_CERTIFICATE_UNVERIFIED"):
        op.reconcile(1, 2)
    with patch.object(scoped, "_live", return_value=object()):
        assert op.reconcile(1, 2)["certificate_id"] == cert_id
    c.apply_mgmt_cluster.assert_called_once_with(cert_id, allow_redirects=False)


def test_scope_and_target_isolation(monkeypatch, capsys):
    monkeypatch.setattr("vcf_cert_renewer.cli.Settings.load", Mock())
    run = Mock(side_effect=[InstallError("PREVIOUS_REPLACEMENT_FAILED"),
                            {"result": "SKIPPED", "reason": "OUTSIDE_RENEWAL_WINDOW"}])
    monkeypatch.setattr("vcf_cert_renewer.cli.renew_scoped", run)
    assert main(["renew-scoped", "--target", VC, "--target", NSX,
                 "--accept-unverified-rollback"]) == 1
    assert [c.args[1] for c in run.call_args_list] == [VC, NSX]
    output = capsys.readouterr().out
    assert "PREVIOUS_REPLACEMENT_FAILED" in output and "OUTSIDE_RENEWAL_WINDOW" in output
    with pytest.raises(SystemExit):
        main(["renew-scoped", "--target", "sddc.vcf.example.com", "--accept-unverified-rollback"])
    with pytest.raises(SystemExit):
        main(["renew-scoped", "--target", VC])


def test_outside_window_does_not_construct_clients(monkeypatch, tmp_path):
    from vcf_cert_renewer.config import Settings
    from contextlib import nullcontext
    monkeypatch.setattr(scoped, "_fingerprint", lambda _: FP)
    monkeypatch.setattr(scoped, "_dns_sans", lambda _: [VC])
    monkeypatch.setattr(scoped, "_locked_state", lambda *_: nullcontext(99))
    monkeypatch.setattr(scoped, "_load", lambda *args: {})
    monkeypatch.setattr(scoped, "_live", lambda _: SimpleNamespace(
        not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=80)))
    s = Settings("token", "url", True, 30, None, output_dir=tmp_path,
                 acme_mode="production")
    with patch.object(scoped, "SddcApiClient") as client:
        assert scoped.renew_scoped(s, VC, poll_interval=1, poll_timeout=2)["result"] == "SKIPPED"
        client.assert_not_called()


@pytest.mark.parametrize("role", ["OPERATIONS", "AUTOMATION"])
def test_fleet_pending_task_reconciles_without_replacement(operation, role, monkeypatch):
    op, client, _ = operation
    op.kind = role
    op.start_fleet()
    assert op.state["state"] == "SUBMITTING"
    client._state.return_value = "IN_PROGRESS"
    wait = Mock(side_effect=[requests.Timeout(), {"status": "COMPLETED"}])
    monkeypatch.setattr(scoped, "poll_workflow", wait)
    monkeypatch.setattr(scoped, "_fleet_identity", Mock())
    with pytest.raises(requests.Timeout):
        op.track_fleet("workflow_123", {}, poll_interval=1, poll_timeout=2)
    assert op.state["state"] == "TASK_PENDING"
    with patch.object(scoped, "_live", return_value=object()):
        assert op.reconcile(1, 2)["task_id"] == "workflow_123"
    assert wait.call_count == 2
    client._request.assert_not_called()
    assert op.state["state"] == "INSTALLED"


def test_fleet_import_identity_requires_exact_record(monkeypatch):
    client = Mock()
    monkeypatch.setattr(scoped, "resolve_fleet_certificate", lambda *args: {
        "applianceFqdn": "unrelated.example.com"})
    with pytest.raises(InstallError, match="FLEET_TARGET_IDENTITY_UNVERIFIED"):
        scoped._fleet_identity(client, "OPERATIONS", "ops.example.com")
