"""Offline integration checks for the shipped configuration and batch contract."""
from pathlib import Path
import yaml
import pytest

from vcf_cert_renewer import __version__
from vcf_cert_renewer.config import DEFAULTS, SECRET_ENV_NAMES, SECRET_FILE_NAMES, Settings

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/kubernetes"


@pytest.mark.skipif("VCF_RENEW_TARGETS" not in DEFAULTS,
                    reason="Manifests target the public GHCR image, not site-specific internal defaults")
def test_manifests_and_configuration_resolve_with_mounted_credentials(tmp_path):
    docs = {p.name: yaml.safe_load(p.read_text()) for p in DEPLOY.glob("*.yaml")}
    config = docs["configmap.example.yaml"]["data"]
    supported = set(DEFAULTS) | SECRET_ENV_NAMES | SECRET_FILE_NAMES | {
        "ACME_SERVER", "ACME_EMAIL", "DNSUPDATE_NAMESERVER", "DNSUPDATE_TSIG_KEY"}
    assert set(config) <= supported
    assert all(isinstance(value, str) for value in config.values())
    assert not ({"VCF_API_TOKEN", "SDDC_PASSWORD", "DNSUPDATE_TSIG_SECRET",
                 "ACME_EAB_HMAC"} & config.keys())
    env = dict(config)
    for name in SECRET_FILE_NAMES & config.keys():
        assert config[name].startswith("/run/secrets/")
        path = tmp_path / Path(config[name]).name
        path.write_text("dummy-mounted-value\n")
        env[name] = str(path)
    settings = Settings.load(environ=env, config_path=tmp_path / "absent.yaml",
                             secrets_path=tmp_path / "absent.env")
    assert settings.api_token == "dummy-mounted-value"
    assert settings.sddc_password == "dummy-mounted-value"
    assert settings.dns_tsig_secret == "dummy-mounted-value"
    assert len(settings.renewal_targets) == 4
    assert settings.output_dir == Path("/data")
    assert settings.verify_tls and settings.nsx_verify_tls
    assert "dummy-mounted-value" not in repr(settings)
    cron = docs["cronjob.yaml"]
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"].endswith(":" + __version__)
    assert container["envFrom"][0]["configMapRef"]["name"] == docs["configmap.example.yaml"]["metadata"]["name"]
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == docs["pvc.yaml"]["metadata"]["name"]
    assert all(d["metadata"]["namespace"] == docs["namespace.yaml"]["metadata"]["name"]
               for d in docs.values() if d["kind"] != "Namespace")
    assert not any(d["kind"] in {"Secret", "Role", "RoleBinding", "ClusterRole"}
                   for d in docs.values())


def test_cronjob_does_not_auto_start_retry_or_expand_mutation_scope():
    cron = yaml.safe_load((DEPLOY / "cronjob.yaml").read_text())["spec"]
    assert cron["suspend"] is True
    assert cron["concurrencyPolicy"] == "Forbid"
    job = cron["jobTemplate"]["spec"]
    assert job["backoffLimit"] == 0
    pod = job["template"]["spec"]
    assert pod["restartPolicy"] == "Never"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    container = pod["containers"][0]
    assert container["args"] == ["renew", "--all", "--yes"]
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]}}
    assert not pod.get("hostNetwork", False)
    assert not any("hostPath" in v for v in pod["volumes"])
    mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
    assert mounts["/run/secrets"]["readOnly"] is True
    assert {"/data", "/tmp"} <= mounts.keys()
