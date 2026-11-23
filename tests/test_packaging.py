import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from vcf_cert_renewer import __version__
from vcf_cert_renewer.cli import BATCH_TARGETS, main


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_package_cli_and_container_metadata_versions_match(self):
        self.assertEqual(__version__, "1.5.0")
        output = StringIO()
        with patch("sys.stdout", output):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "vcf-cert-renewer 1.5.0")
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn('org.opencontainers.image.version="1.5.0"', dockerfile)

    def test_batch_scope_is_exactly_v1_targets(self):
        self.assertEqual(BATCH_TARGETS, (
            "ops.vcf.example.com", "sddc.vcf.example.com",
            "vcenter.vcf.example.com", "nsxt.vcf.example.com"))

    def test_systemd_service_is_safe(self):
        service = (ROOT / "packaging/systemd/vcf-cert-renewer.service").read_text()
        self.assertIn("ExecStart=/usr/bin/python3 -m vcf_cert_renewer scheduled", service)
        self.assertNotIn(".venv", service)
        self.assertIn("scheduled", service)
        self.assertNotIn("--force", service)
        self.assertIn("EnvironmentFile=/etc/vcf-cert-renewer/vcf-cert-renewer.env", service)
        for credential in ("replace-me", "password=", "token="):
            self.assertNotIn(credential, service.lower())

    def test_production_env_example_is_placeholder_only(self):
        example = (ROOT / "examples/vcf-cert-renewer.env.example").read_text()
        self.assertNotIn("VCF_CLIENT_ID", example)
        self.assertNotIn("VCF_CLIENT_SECRET", example)
        for secret in ("VCF_API_TOKEN", "SDDC_PASSWORD", "DNSUPDATE_TSIG_SECRET"):
            self.assertIn(f"{secret}=", example)
        self.assertIn("yourdomain.tld", example)

    def test_timer_is_daily_persistent_and_randomized(self):
        timer = (ROOT / "packaging/systemd/vcf-cert-renewer.timer").read_text()
        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=1h", timer)
