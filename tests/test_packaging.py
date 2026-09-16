import unittest
from pathlib import Path

from vcf_cert_renewer.cli import BATCH_TARGETS


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_batch_scope_is_exactly_v1_targets(self):
        self.assertEqual(BATCH_TARGETS, (
            "ops.vcf.example.com", "sddc.vcf.example.com",
            "vcenter.vcf.example.com", "nsxt.vcf.example.com"))

    def test_systemd_service_is_safe(self):
        service = (ROOT / "packaging/systemd/vcf-cert-renewer.service").read_text()
        self.assertIn("ExecStart=/usr/bin/python3 -m vcf_cert_renewer renew --all --yes", service)
        self.assertNotIn(".venv", service)
        self.assertIn("renew --all --yes", service)
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
        self.assertNotIn("example.invalid", example)

    def test_timer_is_daily_persistent_and_randomized(self):
        timer = (ROOT / "packaging/systemd/vcf-cert-renewer.timer").read_text()
        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=1h", timer)
