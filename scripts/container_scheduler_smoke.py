"""Run the real scheduler and Docker healthcheck against an isolated fixture."""
import json
import subprocess
import sys
import time
from uuid import uuid4

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "vcf-cert-renewer:1.5.0"
TARGET = "nsx.example.com"
CERT_ID = "43b7b14d-f816-48dc-a558-11504f851eae"
FIXTURE = r"""
import json
import os
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from vcf_cert_renewer import cli, scoped_renewal as scoped
from vcf_cert_renewer.sddc_install import _locked_state, _write

os.umask(0o077)
root = Path("/data")
assert os.getuid() == os.getgid() == 10001
target = "nsx.example.com"
fp = "a" * 64
cert_id = "43b7b14d-f816-48dc-a558-11504f851eae"
mode = os.environ["VCF_SMOKE_MODE"]
paths = ("acme/production/accounts/fixture.key", "acme/production/certificates/fixture.crt",
         "metadata/renewal.json")
if mode == "fresh":
    for name in paths:
        assert not (root / name).exists(), name
    assert not (root / ".scheduler/state.json").exists()
    for name in paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-only")
    with _locked_state(root, ".renew-nsx") as fd:
        _write(fd, {"version": 1, "target": target, "state": "SUBMITTING",
                    "recovery": "UNVERIFIED_ACKNOWLEDGED", "expected": fp,
                    "previous": "b" * 64, "certificate_id": cert_id})
else:
    for name in paths:
        path = root / name
        assert path.read_text() == "synthetic-only" and path.stat().st_mode & 0o777 == 0o600
    state = json.loads((root / ".renew-nsx/state.json").read_text())
    assert state["certificate_id"] == cert_id and state["state"] == "SUBMITTING"
    assert (root / ".scheduler/state.json").is_file()

def discovery(name):
    assert name == target
    return {"certificate": {"id": cert_id if mode == "resume" else "old-assignment"}}

# Provide only the read API needed for reconciliation. Any replacement or CSR
# call fails because the fixture has no such method.
client = SimpleNamespace(discover=discovery)
live = SimpleNamespace(not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=90))
def reject_mutation(*args, **kwargs):
    raise AssertionError("Unexpected mutation or issuance attempt")
with patch.object(scoped, "_live", return_value=live), \
     patch.object(scoped, "_fingerprint", return_value=fp), \
     patch.object(scoped, "_dns_sans", return_value=[target]), \
     patch.object(scoped, "NsxApiClient", return_value=client), \
     patch.object(scoped, "execute_nsx_renewal", side_effect=reject_mutation):
    raise SystemExit(cli.main(["scheduler"]))
"""


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def check_health(name, wanted):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        status = docker("inspect", "-f", "{{.State.Health.Status}}", name)
        if status == wanted and '"event_id":"VCF-1000"' in docker("logs", name):
            return
        if docker("inspect", "-f", "{{.State.Status}}", name) != "running":
            raise AssertionError(docker("logs", name))
        time.sleep(0.5)
    health = docker("inspect", "-f", "{{json .State.Health}}", name)
    raise AssertionError(f"Expected {wanted} health status; engine reported {health}")


def start(name, volume, mode):
    docker("run", "-d", "--name", name, "--network", "none", "--read-only",
           "--restart", "unless-stopped", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--health-interval", "1s",
           "--health-retries", "2", "--health-start-period", "1s",
           "--mount", f"type=volume,src={volume},dst=/data",
           "-e", f"VCF_SMOKE_MODE={mode}", "-e", f"VCF_RENEW_TARGETS=NSX={TARGET}",
           "-e", "VCF_CHECK_INTERVAL_SECONDS=60",
           "-e", "VCF_ACCEPT_UNVERIFIED_RECOVERY=NSX", "-e", "ACME_MODE=production",
           "-e", f"NSX_URL=https://{TARGET}", "--entrypoint", "python", IMAGE, "-c", FIXTURE)


def events(name):
    records = [json.loads(line) for line in docker("logs", name).splitlines() if line.startswith("{")]
    assert any(r["event_id"] == "VCF-1000" and r["application_version"] == "1.5.0" for r in records)
    return records


def stop(name):
    docker("stop", "--time", "10", name)
    assert docker("inspect", "-f", "{{.State.ExitCode}}", name) == "0"
    docker("rm", name)


def main():
    suffix = uuid4().hex
    volume = "vcf-b17-data-" + suffix
    names = ("vcf-b17-fresh-" + suffix, "vcf-b17-resume-" + suffix)
    docker("volume", "create", volume)
    try:
        start(names[0], volume, "fresh")
        check_health(names[0], "unhealthy")
        assert any(r["event_id"] == "VCF-2100" for r in events(names[0]))
        stop(names[0])
        start(names[1], volume, "resume")
        check_health(names[1], "healthy")
        assert any(r["event_id"] == "VCF-1200" and r["certificate_id"] == CERT_ID
                   for r in events(names[1]))
        state = json.loads(docker("exec", names[1], "cat", "/data/.renew-nsx/state.json"))
        assert state["state"] == "INSTALLED" and state["certificate_id"] == CERT_ID
        assert docker("inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", names[1]) == "unless-stopped"
        # Verify the first complete run is followed by another at the configured interval.
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            completed = [r for r in events(names[1]) if r["event_id"] == "VCF-1000"]
            if len(completed) >= 2:
                from datetime import datetime
                elapsed = (datetime.fromisoformat(completed[1]["timestamp"]) -
                           datetime.fromisoformat(completed[0]["timestamp"])).total_seconds()
                assert 59 <= elapsed <= 75
                break
            time.sleep(2)
        else:
            raise AssertionError("Second scheduled check did not run")
        lock_check = """
from pathlib import Path
import json
import subprocess
from vcf_cert_renewer.sddc_install import _locked_state
with _locked_state(Path('/data'), '.scheduler'):
    completed = subprocess.run(['python', '-m', 'vcf_cert_renewer', 'scheduled'],
                               capture_output=True, text=True)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)['event_id'] == 'VCF-3300'
"""
        docker("exec", names[1], "python", "-c", lock_check)
        # Age only the synthetic heartbeat. No production data or network is mounted.
        stale = """
from pathlib import Path
import json
from vcf_cert_renewer.sddc_install import _locked_state, _write
with _locked_state(Path('/data'), '.scheduler') as fd:
    state = json.loads(Path('/data/.scheduler/state.json').read_text())
    state['last_completion'] = '2000-01-01T00:00:00+00:00'
    _write(fd, state)
"""
        docker("exec", names[1], "python", "-c", stale)
        check_health(names[1], "unhealthy")
        stop(names[1])
        print("Isolated scheduler, Docker health, signal handling and volume recreation passed")
    finally:
        for name in names:
            subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)
        docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
