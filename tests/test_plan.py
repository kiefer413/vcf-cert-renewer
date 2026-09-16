import io
import json
import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import main
from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.plan import (assemble_plan, build_plan,
                                   compare_inventory_to_live,
                                   inventory_matches_live)


ACTIVE = {
    "certificateResourceKey": "dynamic-key", "category": "TLS_CERT",
    "applianceFqdn": "ops.vcf.example.com",
    "issuedToCommonName": "ops.vcf.example.com", "issuedBy": "Lab Issuer",
    "notBefore": "2026-01-01T00:00:00Z", "notAfter": "2026-10-01T00:00:00Z",
    "daysToExpire": 17, "subjectAlternativeNames": {"dns": ["ops.vcf.example.com"]},
    "certificateMetadata": {"certificateChainRole": "LEAF", "managementLevel": "CUSTOMER_MANAGED"},
}


class PlanTests(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_assembles_required_safe_output(self):
        result = assemble_plan("OPS.vcf.example.com", ACTIVE, Settings.from_env(),
                               csr_exists=True, imported_certificates=[])
        self.assertEqual(result["targetFqdn"], "ops.vcf.example.com")
        self.assertEqual(result["activeLeafTlsCertificate"]["issuer"], "Lab Issuer")
        self.assertTrue(result["activeLeafTlsCertificate"]["customerManaged"])
        self.assertEqual(result["expectedActions"],
                         ["Generate CSR", "Sign CSR", "Import", "Replace", "Verify"])
        self.assertEqual(result["notice"], "No changes have been made.")

    @patch.dict("os.environ", {}, clear=True)
    @patch("vcf_cert_renewer.plan.inspect_https_certificate", return_value={
        "commonName": "ops.vcf.example.com", "subject": "CN=ops.vcf.example.com",
        "issuer": "Lab Issuer", "sans": ["ops.vcf.example.com"],
        "notBefore": "2026-01-01T00:00:00+00:00",
        "notAfter": "2026-10-01T00:00:00+00:00",
        "sha256Thumbprint": "aabb"})
    @patch("vcf_cert_renewer.plan.list_imported_certificates", return_value=[])
    def test_build_plan_calls_only_read_helpers(self, imported, inspect):
        client = Mock()
        client.query_certificates.return_value = [ACTIVE]
        client.fetch_csr.return_value = "CSR"
        result = build_plan(client, Settings.from_env(), "ops.vcf.example.com")
        client.query_certificates.assert_called_once_with(page_size=500)
        client.fetch_csr.assert_called_once_with("dynamic-key", "ops.vcf.example.com")
        self.assertFalse(client.create_csr.called)
        self.assertFalse(client.session.post.called)
        self.assertFalse(client.session.put.called)
        self.assertTrue(result["existingState"]["matchingCsrExists"])
        self.assertEqual(result["liveHttpsCertificate"]["sha256Thumbprint"], "aabb")
        self.assertTrue(result["inventoryMatchesLive"])
        self.assertEqual(result["inventoryComparisonStatus"],
                         "STALE_OR_INCOMPLETE_INVENTORY")
        inspect.assert_called_once_with("ops.vcf.example.com", timeout=15.0)

    def test_inventory_match_and_mismatch_detection(self):
        inventory = {"issuer": "CN=Issuer", "sans": ["OPS.EXAMPLE"],
                     "notAfter": "2026-10-01T00:00:00Z",
                     "sha256Thumbprint": "AA:BB"}
        live = {"issuer": "cn=issuer", "sans": ["ops.example."],
                "notAfter": "2026-10-01T00:00:00+00:00",
                "sha256Thumbprint": "aabb"}
        self.assertTrue(inventory_matches_live(inventory, live))
        self.assertFalse(inventory_matches_live(
            inventory, {**live, "issuer": "CN=Different Issuer"}))

    def test_missing_fleet_metadata_is_incomplete_not_mismatch(self):
        inventory = {"commonName": "ops.example", "issuer": "CN=Issuer",
                     "sans": ["ops.example"],
                     "notAfter": "2026-10-01T00:00:00Z"}
        live = {**inventory, "notAfter": "2026-10-01T00:00:00+00:00",
                "notBefore": "2026-01-01T00:00:00Z",
                "sha256Thumbprint": "aabb"}
        comparison = compare_inventory_to_live(inventory, live)
        self.assertEqual(comparison["status"], "STALE_OR_INCOMPLETE_INVENTORY")
        self.assertEqual(comparison["fields"]["sha256Thumbprint"], "UNKNOWN")
        self.assertEqual(comparison["fields"]["notBefore"], "UNKNOWN")
        self.assertTrue(inventory_matches_live(inventory, live))

    def test_epoch_millisecond_expiry_matches_iso_live_expiry(self):
        comparison = compare_inventory_to_live(
            {"notAfter": 1797148441000},
            {"notAfter": "2026-12-13T07:54:01+00:00"})
        self.assertEqual(comparison["fields"]["notAfter"], "MATCH")
        self.assertEqual(comparison["status"], "STALE_OR_INCOMPLETE_INVENTORY")

    def test_different_san_or_thumbprint_is_mismatch(self):
        live = {"sans": ["ops.example"], "sha256Thumbprint": "aabb"}
        for inventory in ({"sans": ["other.example"]},
                          {"sha256Thumbprint": "ccdd"}):
            self.assertEqual(compare_inventory_to_live(inventory, live)["status"],
                             "MISMATCH")

    @patch.dict("os.environ", {}, clear=True)
    def test_mismatch_is_structured_and_nonfatal(self):
        live = {"commonName": "ops.vcf.example.com", "subject": "CN=ops.vcf.example.com",
                "issuer": "CN=Lets Encrypt Staging", "sans": ["ops.vcf.example.com"],
                "notBefore": "2026-09-01T00:00:00+00:00",
                "notAfter": "2026-12-01T00:00:00+00:00",
                "sha256Thumbprint": "deadbeef"}
        result = assemble_plan("ops.vcf.example.com", ACTIVE, Settings.from_env(),
                               csr_exists=False, imported_certificates=[],
                               live_certificate=live)
        self.assertFalse(result["inventoryMatchesLive"])
        self.assertEqual(result["inventoryComparisonStatus"], "MISMATCH")
        self.assertIn("conflicts", result["warnings"][0])

    @patch.dict("os.environ", {"RENEW_BEFORE_DAYS": "30"}, clear=True)
    def test_live_https_still_drives_renewal_decision(self):
        from datetime import datetime, timezone
        from vcf_cert_renewer.renewer import renewal_plan
        result = renewal_plan(Settings.from_env(), "ops.example",
                              now=datetime(2026, 9, 14, tzinfo=timezone.utc),
                              inspect=lambda *args, **kwargs: {
                                  "notAfter": "2026-09-24T00:00:00+00:00",
                                  "sans": ["ops.example"]})
        self.assertEqual(result["result"], "RENEWAL_REQUIRED")
        self.assertEqual(result["daysRemaining"], 10.0)

    @patch("vcf_cert_renewer.cli.build_plan")
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token"}, clear=True)
    def test_plan_cli_does_not_dispatch_mutations(self, exchange, client_class, build):
        build.return_value = {"notice": "No changes have been made."}
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["plan", "ops.vcf.example.com"]), 0)
        self.assertEqual(json.loads(output.getvalue())["notice"], "No changes have been made.")
        self.assertFalse(client_class.return_value.create_csr.called)
        self.assertFalse(client_class.return_value.session.put.called)

    @patch("vcf_cert_renewer.cli.build_plan", return_value={"notice": "No changes have been made."})
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token", "VCF_VERIFY_TLS": "false"}, clear=True)
    def test_insecure_tls_emits_one_controlled_warning(self, exchange, client_class, build):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            self.assertEqual(main(["plan", "ops.vcf.example.com"]), 0)
        message = "WARNING: TLS certificate verification is disabled for VCF API connections."
        self.assertEqual(stderr.getvalue().count(message), 1)
        self.assertNotIn("InsecureRequestWarning", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
