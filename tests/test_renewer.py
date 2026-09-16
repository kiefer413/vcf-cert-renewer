import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import BATCH_TARGETS, main
from vcf_cert_renewer.config import ACME_DIRECTORIES, Settings
from vcf_cert_renewer.renewer import execute_renewal, renewal_plan


LIVE = {
    "notAfter": "2027-01-01T00:00:00+00:00",
    "sans": ["ops.example"], "issuer": "CN=Issuer",
}


class RenewalTests(unittest.TestCase):
    def settings(self, output=Path("out")):
        return Settings(
            "token", "url", True, 30, "api", acme_mode="production",
            acme_server=ACME_DIRECTORIES["production"], output_dir=output)

    def test_noop_above_threshold(self):
        plan = renewal_plan(
            self.settings(), "ops.example",
            now=datetime(2026, 9, 1, tzinfo=timezone.utc),
            inspect=lambda *args, **kwargs: LIVE)
        self.assertEqual(plan["result"], "NO_RENEWAL_NEEDED")
        self.assertEqual(plan["notice"], "No changes have been made.")

    def test_v1_batch_scope_is_exact_and_excludes_nsx_node(self):
        self.assertEqual(BATCH_TARGETS, (
            "ops.vcf.example.com", "sddc.vcf.example.com",
            "vcenter.vcf.example.com", "nsxt.vcf.example.com"))
        self.assertNotIn("nsxt01.vcf.example.com", BATCH_TARGETS)

    def test_batch_uses_configured_four_targets(self):
        settings = self.settings()
        self.assertEqual(len(settings.renewal_targets), 4)

    def test_systemd_sample_never_forces_and_does_not_embed_secrets(self):
        service = Path("packaging/systemd/vcf-cert-renewer.service").read_text()
        self.assertIn("renew --all --yes", service)
        self.assertNotIn("--force", service)
        self.assertIn("EnvironmentFile=", service)
        self.assertNotIn("VCF_API_TOKEN=", service)
        self.assertNotIn("DNSUPDATE_TSIG_SECRET=", service)

    @patch("vcf_cert_renewer.cli.execute_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {"VCF_VERIFY_TLS": "true", "ACME_MODE": "production"}, clear=True)
    def test_production_safety_gate(self, plan, execute):
        plan.return_value = {"result": "RENEWAL_REQUIRED"}
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["renew", "ops.example"]), 0)
        execute.assert_not_called()
        self.assertIn("PLAN_ONLY", output.getvalue())

    @patch("vcf_cert_renewer.cli.exchange_token", return_value="token")
    @patch("vcf_cert_renewer.cli.execute_renewal", return_value={"result": "RENEWED"})
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {
        "VCF_VERIFY_TLS": "true", "VCF_API_TOKEN": "api",
        "ACME_MODE": "production"}, clear=True)
    def test_force_still_requires_yes_and_yes_executes(self, plan, execute, token):
        plan.return_value = {"result": "RENEWAL_REQUIRED"}
        self.assertEqual(main(["renew", "ops.example", "--force", "--yes"]), 0)
        execute.assert_called_once()

    @patch("vcf_cert_renewer.cli._execute_supported_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {"ACME_MODE": "production", "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_batch_noop_is_success_and_skips_all(self, plan, execute):
        plan.side_effect = lambda settings, fqdn, force=False: {
            "result": "NO_RENEWAL_NEEDED", "targetFqdn": fqdn, "force": force}
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["renew", "--all", "--yes"]), 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["counts"], {"FAILED": 0, "RENEWED": 0, "SKIPPED": 4})
        execute.assert_not_called()

    @patch("vcf_cert_renewer.cli._execute_supported_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {"ACME_MODE": "production", "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_batch_plans_all_before_approval_and_force_is_explicit(self, plan, execute):
        plan.side_effect = lambda settings, fqdn, force=False: {
            "result": "RENEWAL_REQUIRED", "targetFqdn": fqdn, "force": force}
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["renew", "--all", "--force"]), 0)
        self.assertEqual(plan.call_count, 4)
        self.assertTrue(all(call.kwargs["force"] for call in plan.call_args_list))
        self.assertEqual(json.loads(output.getvalue())["result"], "PLAN_ONLY")
        execute.assert_not_called()

    @patch("vcf_cert_renewer.cli._execute_supported_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {"ACME_MODE": "production", "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_batch_partial_failure_has_summary_and_nonzero_exit(self, plan, execute):
        plan.side_effect = lambda settings, fqdn, force=False: {
            "result": "RENEWAL_REQUIRED", "targetFqdn": fqdn}
        execute.side_effect = [RuntimeError("secret must not render"),
                               {"result": "RENEWED"}, {"result": "RENEWED"},
                               {"result": "RENEWED"}]
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["renew", "--all", "--yes"]), 1)
        rendered = output.getvalue()
        summary = json.loads(rendered)
        self.assertEqual(summary["counts"], {"FAILED": 1, "RENEWED": 3, "SKIPPED": 0})
        self.assertNotIn("secret must not render", rendered)

    @patch("vcf_cert_renewer.cli._execute_supported_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan")
    @patch.dict("os.environ", {"ACME_MODE": "production", "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_batch_plan_failure_causes_zero_mutations(self, plan, execute):
        plan.side_effect = RuntimeError("unavailable")
        with patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["renew", "--all", "--yes"]), 1)
        self.assertEqual(plan.call_count, 4)
        execute.assert_not_called()

    @patch("vcf_cert_renewer.renewer.find_leaf_tls_certificate")
    def test_first_step_failure_stops_all_later_actions(self, find):
        client = Mock()
        client.query_certificates.side_effect = RuntimeError("stop")
        with self.assertRaisesRegex(RuntimeError, "stop"):
            execute_renewal(client, self.settings(), "ops.example")
        find.assert_not_called()
        client.create_csr.assert_not_called()

    @patch("vcf_cert_renewer.renewer.verify_https_certificate")
    @patch("vcf_cert_renewer.renewer.replace_certificate")
    @patch("vcf_cert_renewer.renewer.import_certificate_chain")
    @patch("vcf_cert_renewer.renewer.build_vcf_fullchain")
    @patch("vcf_cert_renewer.renewer.sign_csr")
    @patch("vcf_cert_renewer.renewer.find_leaf_tls_certificate")
    def test_successful_orchestration(self, find, sign, build, imported, replace, verify):
        with tempfile.TemporaryDirectory() as directory:
            settings = self.settings(Path(directory))
            client = Mock()
            active = {"certificateResourceKey": "key", "issuedToCommonName": "ops.example"}
            find.return_value = active
            client.query_certificates.return_value = [active]
            client.create_csr.return_value = ("csr-request", {"status": "COMPLETED"})
            client._state.side_effect = lambda value: value["status"]
            client.fetch_csr.return_value = "CSR"
            leaf, issuer = Path(directory) / "leaf.crt", Path(directory) / "issuer.crt"
            sign.return_value = {
                "leafPath": str(leaf), "issuerPath": str(issuer),
                "sha256Thumbprint": "abc"}
            fullchain = Path(directory) / "ops.example.vcf-fullchain.pem"
            fullchain.write_bytes(b"chain")
            imported.return_value = {"result": "IMPORTED"}
            replace.return_value = (
                "replace-request", {"status": "COMPLETED"}, b"chain")
            verify.return_value = {"verified": True}
            result = execute_renewal(client, settings, "ops.example")
            self.assertEqual(result["result"], "RENEWED")
            self.assertTrue((Path(directory) / "ops.example.csr.pem").exists())
            verify.assert_called_once_with("ops.example", b"chain")


if __name__ == "__main__":
    unittest.main()
