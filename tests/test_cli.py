import io
import json
import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import main


class LiveTestCommandTests(unittest.TestCase):
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="access-secret")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "api-secret"}, clear=True)
    def test_prints_safe_summary(self, exchange, client_class):
        client_class.return_value.query_certificates.return_value = [{
            "certificateResourceKey": "dynamic-id",
            "issuedToCommonName": "operations.example.com",
            "applianceFqdn": "operations.example.com",
            "category": "TLS_CERT",
            "status": "NORMAL",
            "daysToExpire": 42,
            "subjectAlternativeNames": {"dns": ["operations.example.com"], "ip": []},
            "certificateMetadata": {"certificateChainRole": "LEAF"},
            "unexpectedSensitiveField": "must-not-print",
        }]

        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["live-test", "operations.example.com"]), 0)

        rendered = output.getvalue()
        summary = json.loads(rendered)
        self.assertEqual(summary["certificateResourceKey"], "dynamic-id")
        self.assertNotIn("api-secret", rendered)
        self.assertNotIn("access-secret", rendered)
        self.assertNotIn("must-not-print", rendered)
        exchange.assert_called_once()
        client_class.return_value.query_certificates.assert_called_once_with(
            page_size=500
        )

    @patch("vcf_cert_renewer.cli.execute_domain_renewal", return_value={"result": "RENEWED"})
    @patch("vcf_cert_renewer.cli.renewal_plan", return_value={"result": "RENEWAL_REQUIRED"})
    @patch("vcf_cert_renewer.cli.exchange_token")
    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example", "SDDC_PASSWORD": "pw",
                               "ACME_MODE": "production", "VCF_VERIFY_TLS": "true",
                               "ACME_EMAIL": "unit@localhost",
                               "DNSUPDATE_NAMESERVER": "192.0.2.53:53",
                               "DNSUPDATE_TSIG_KEY": "renewal",
                               "DNSUPDATE_TSIG_SECRET": "fixture"}, clear=True)
    def test_sddc_renewal_uses_own_auth_family(self, exchange, plan, execute):
        self.assertEqual(main(["renew", "sddc.example.com", "--force", "--yes"]), 0)
        exchange.assert_not_called()
        execute.assert_called_once()

    @patch("vcf_cert_renewer.cli.execute_domain_renewal", return_value={"result": "RENEWED"})
    @patch("vcf_cert_renewer.cli.renewal_plan", return_value={"result": "RENEWAL_REQUIRED"})
    @patch("vcf_cert_renewer.cli.exchange_token")
    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example", "SDDC_PASSWORD": "pw",
                               "ACME_MODE": "production", "VCF_VERIFY_TLS": "true",
                               "ACME_EMAIL": "unit@localhost",
                               "DNSUPDATE_NAMESERVER": "192.0.2.53:53",
                               "DNSUPDATE_TSIG_KEY": "renewal",
                               "DNSUPDATE_TSIG_SECRET": "fixture"}, clear=True)
    def test_vcenter_renewal_uses_domain_engine(self, exchange, plan, execute):
        self.assertEqual(main(["renew", "vcenter.example.com", "--force", "--yes"]), 0)
        exchange.assert_not_called()
        self.assertEqual(execute.call_args.kwargs["resource_type"], "VCENTER")

    @patch("vcf_cert_renewer.cli.renewal_plan", return_value={"result": "RENEWAL_REQUIRED"})
    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example", "ACME_MODE": "production",
                               "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_sddc_missing_credentials_error(self, plan):
        errors = io.StringIO()
        with patch("sys.stderr", errors):
            self.assertEqual(main(["renew", "sddc.example.com", "--force", "--yes"]), 2)
        self.assertIn("SDDC_PASSWORD", errors.getvalue())
        self.assertNotIn("svc@example", errors.getvalue())

    @patch("vcf_cert_renewer.cli.build_domain_plan", return_value={"notice": "No changes have been made."})
    @patch("vcf_cert_renewer.cli.exchange_token")
    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example", "SDDC_PASSWORD": "pw",
                               "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_sddc_plan_uses_sddc_auth_without_operations_exchange(self, exchange, build):
        self.assertEqual(main(["plan", "sddc.example.com"]), 0)
        exchange.assert_not_called()
        build.assert_called_once()


if __name__ == "__main__":
    unittest.main()
