from datetime import datetime, timedelta, timezone
from queue import Queue
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock
import json
import socket
import ssl
import subprocess

import pytest

from vcf_cert_renewer import monitoring as m
from vcf_cert_renewer.config import ConfigurationError
from vcf_cert_renewer.sddc_install import InstallError

_REAL_CONNECT = socket.socket.connect


@pytest.fixture
def loopback_only(monkeypatch):
    def connect(sock, address):
        assert address[0] in {"127.0.0.1", "::1"}
        return _REAL_CONNECT(sock, address)
    monkeypatch.setattr(socket.socket, "connect", connect)


def iso(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def test_scheduler_isolation_redaction_and_recovery(tmp_path, monkeypatch, capsys):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    env = {"VCF_RENEW_TARGETS": "OPERATIONS=ops.example.com,AUTOMATION=automation.example.com",
           "VCF_ACCEPT_UNVERIFIED_RECOVERY": "OPERATIONS,AUTOMATION"}
    monkeypatch.setattr(m, "_certificate_observation",
                        lambda *args: {"expires": iso(14), "fingerprint": "b" * 64})
    run = Mock(side_effect=[InstallError("DO_NOT_LOG_THIS_SECRET"), {"result": "SKIPPED"},
                            {"result": "SKIPPED"}, {"result": "SKIPPED"}])
    monkeypatch.setattr(m, "renew_scoped", run)
    events = m.Events({})
    assert m.scheduled(settings, events, env) == 1
    state = m.status(settings, env)
    assert state["targets"]["OPERATIONS"]["status"] == "FAILED"
    assert state["targets"]["AUTOMATION"]["status"] == "SKIPPED"
    assert m.scheduled(settings, events, env) == 0
    output = capsys.readouterr().out
    assert "DO_NOT_LOG_THIS_SECRET" not in output
    assert {"VCF-3100", "VCF-5000", "VCF-1000", "VCF-2000"} <= {
        json.loads(line)["event_id"] for line in output.splitlines()}
    assert m.status(settings, env)["healthy"]


def test_watchdog_stale_disabled_and_recovery(tmp_path, monkeypatch, capsys):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    timer = Mock(side_effect=[SimpleNamespace(stdout="disabled", returncode=1),
                             SimpleNamespace(stdout="inactive", returncode=3),
                             SimpleNamespace(stdout="success", returncode=0)])
    monkeypatch.setattr(m.subprocess, "run", timer)
    events = m.Events({})
    assert m.watchdog(settings, events, {}, timer=True) == 1
    codes = [json.loads(line)["error_code"] for line in capsys.readouterr().out.splitlines()]
    assert codes == ["SCHEDULER_HEARTBEAT_STALE", "TIMER_NOT_ACTIVE", "TIMER_NOT_ENABLED"]
    monkeypatch.setattr(m, "read_state", lambda output: {"last_completion": iso(0), "targets": {}})
    timer.side_effect = [SimpleNamespace(stdout=word, returncode=0) for word in ("enabled", "active", "success")]
    assert m.watchdog(settings, events, {}, timer=True) == 0
    assert {json.loads(line)["event_id"] for line in capsys.readouterr().out.splitlines()} == {"VCF-5000"}


def test_rotation_reopens_watched_log(tmp_path):
    tmp_path.chmod(0o700)
    log = tmp_path / "renewer.log"
    old = tmp_path / "renewer.log.1"
    events = m.Events({"VCF_LOG_FILE": str(log)})
    events.emit("VCF-1000", outcome="first")
    log.rename(old)
    log.touch(mode=0o600)
    events.emit("VCF-5000", outcome="recovered")
    events.close()
    assert json.loads(old.read_text())["outcome"] == "first"
    assert json.loads(log.read_text())["outcome"] == "recovered"
    assert log.stat().st_mode & 0o777 == 0o600


def test_missing_or_duplicate_target_policy_rejected():
    with pytest.raises(ConfigurationError):
        m.policy({})
    with pytest.raises(ConfigurationError):
        m.policy({"VCF_RENEW_TARGETS": "VCENTER=sddc.example.com,SDDC_MANAGER=sddc.example.com"})


def test_syslog_tcp_receives_framed_events_and_outage_is_safe(loopback_only):
    receiver = socket.socket()
    with receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.listen(1)
        receiver.settimeout(3)
        port = receiver.getsockname()[1]
        forward = m.Syslog({"VCF_SYSLOG_HOST": "127.0.0.1", "VCF_SYSLOG_PORT": str(port),
                            "VCF_SYSLOG_TRANSPORT": "tcp"})
        forward.put({"severity": "INFO", "timestamp": iso(0), "event_id": "VCF-1000"}, "{}")
        conn, _ = receiver.accept()
        with conn:
            size, record = conn.recv(4096).split(b" ", 1)
        assert len(record) == int(size)
        assert record.startswith(b"<134>1 ") and record.endswith(b"VCF-1000 - {}")
        forward.close()
    forward = m.Syslog({"VCF_SYSLOG_HOST": "127.0.0.1", "VCF_SYSLOG_PORT": str(port),
                        "VCF_SYSLOG_TRANSPORT": "tcp"})
    for _ in range(500):
        forward.put({"severity": "ERROR", "timestamp": iso(0), "event_id": "VCF-3000"}, "{}")
    forward.close()


@pytest.mark.parametrize("trusted", [True, False])
def test_syslog_tls_validates_peer(tmp_path, trusted, loopback_only):
    key, cert = (tmp_path / n for n in ("fixture.key", "fixture.crt"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert), "-days", "2"],
                   check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    results = Queue()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        env = {"VCF_SYSLOG_HOST": "localhost", "VCF_SYSLOG_PORT": str(listener.getsockname()[1])}
        if trusted:
            env["VCF_SYSLOG_CA_FILE"] = str(cert)
        def receive():
            try:
                conn, _ = listener.accept()
                with conn, server.wrap_socket(conn, server_side=True) as tls:
                    results.put(tls.recv(4096))
            except ssl.SSLError:
                results.put(b"")
        thread = Thread(target=receive)
        thread.start()
        forward = m.Syslog(env)
        forward.put({"severity": "INFO", "timestamp": iso(0), "event_id": "VCF-1000"}, "{}")
        payload = results.get(timeout=4)
        forward.close()
        thread.join(timeout=3)
        assert (b"VCF-1000" in payload) == trusted


def test_validated_issuance_and_failed_installation_are_separate(tmp_path, monkeypatch, capsys):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    env = {"VCF_RENEW_TARGETS": "VCENTER=vcenter.example.com",
           "VCF_ACCEPT_UNVERIFIED_RECOVERY": "VCENTER"}
    monkeypatch.setattr(m, "_certificate_observation",
                        lambda *args: {"expires": iso(14), "fingerprint": "b" * 64})

    def issued_then_failed(*args, on_issued, **kwargs):
        on_issued("c" * 64, iso(90))
        raise InstallError("LIVE_CERTIFICATE_UNVERIFIED")

    monkeypatch.setattr(m, "renew_scoped", issued_then_failed)
    assert m.scheduled(settings, m.Events({}), env) == 1
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    ids = [e["event_id"] for e in events]
    assert "VCF-1110" in ids and "VCF-1100" not in ids
    state = m.read_state(tmp_path)["targets"]["VCENTER"]
    assert state["issued_fingerprint"] == "c" * 64
    assert state["fingerprint"] == "b" * 64 and "last_successful_renewal" not in state


def test_first_running_scheduler_is_not_yet_healthy(tmp_path, monkeypatch):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    monkeypatch.setattr(m, "read_state", lambda _: {"last_start": iso(0), "running": True})
    assert m.status(settings, {})["issues"] == ["SCHEDULER_STARTING"]
    assert not m.status(settings, {})["healthy"]
