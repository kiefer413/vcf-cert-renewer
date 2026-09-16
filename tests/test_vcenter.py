import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vcf_cert_renewer.client import WorkflowFailedError
from vcf_cert_renewer.config import ACME_DIRECTORIES, Settings
from vcf_cert_renewer.renewer import execute_domain_renewal, renewal_plan
from vcf_cert_renewer.sddc_client import SddcApiClient


def response(payload):
    result = Mock()
    result.json.return_value = payload
    result.headers = {}
    result.raise_for_status.return_value = None
    result.status_code = 200
    result.text = ""
    return result


class VcenterDomainApiTests(unittest.TestCase):
    def client(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "secret")
        client._access_token = "token"
        return client

    def test_dynamic_management_vcenter_resolution_and_exact_type(self):
        client = self.client()
        client._request = Mock(side_effect=[
            response({"elements": [{"id": "domain-1", "type": "MANAGEMENT"}]}),
            response({"elements": [
                {"id": "other", "fqdn": "other.example", "domain": {"id": "domain-1"}},
                {"id": "vc-1", "fqdn": "VCENTER.EXAMPLE.", "domain": {"id": "domain-1"}},
            ]}),
        ])
        domain, resource = client.resolve_context("vcenter.example", "VCENTER")
        self.assertEqual(domain, "domain-1")
        self.assertEqual(resource, {"resourceId": "vc-1", "fqdn": "vcenter.example",
                                    "type": "VCENTER", "name": "vcenter.example",
                                    "sans": ["vcenter.example"]})
        self.assertEqual(client._request.call_args_list[1].args, ("GET", "/v1/vcenters"))
        self.assertEqual(client._request.call_args_list[1].kwargs,
                         {"params": {"domainId": "domain-1"}})

    def test_ambiguous_vcenter_fails_closed(self):
        client = self.client()
        duplicate = {"id": "vc", "fqdn": "vcenter.example", "domain": {"id": "domain"}}
        client._request = Mock(side_effect=[
            response({"elements": [{"id": "domain", "type": "MANAGEMENT"}]}),
            response({"elements": [duplicate, {**duplicate, "id": "vc-2"}]})])
        with self.assertRaisesRegex(ValueError, "found 2"):
            client.resolve_context("vcenter.example", "VCENTER")

    def test_exact_csr_validation_replace_payloads_and_matching(self):
        client = self.client()
        resource = {"resourceId": "vc-1", "fqdn": "vcenter.example",
                    "type": "VCENTER", "sans": ["vcenter.example"]}
        client._request = Mock(side_effect=[
            response({"id": "csr-task", "status": "IN_PROGRESS"}),
            response({"elements": [{"csrEncodedContent":
                      "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
                      "resource": {"resourceId": "vc-1", "fqdn": "vcenter.example",
                                   "type": "VCENTER"}}]}),
            response({"validationId": "validation", "completed": True,
                      "validations": [{"validationStatus": "SUCCESSFUL"}]}),
            response({"id": "replace-task", "status": "SUCCESSFUL"}),
        ])
        client.generate_csr("domain", resource, {"organization": "Org"})
        self.assertEqual(client._request.call_args_list[0].kwargs["json"]["resources"], [resource])
        self.assertIn("BEGIN CERTIFICATE REQUEST", client.fetch_csr("domain", resource))
        client.validate_certificate("domain", resource, "CHAIN")
        client.replace_certificate("domain", resource, "CHAIN")
        expected = [{"resourceId": "vc-1", "resourceFqdn": "vcenter.example",
                     "certificateChain": "CHAIN"}]
        self.assertEqual(client._request.call_args_list[2].kwargs["json"], expected)
        self.assertEqual(client._request.call_args_list[3].kwargs["json"], expected)

    def test_task_failure_prevents_duplicate_csr_and_later_mutation(self):
        settings = Settings("token", "url", True, 30, "api")
        client = Mock()
        client.resolve_context.return_value = ("domain", {
            "resourceId": "vc", "fqdn": "vcenter.example", "type": "VCENTER",
            "sans": ["vcenter.example"]})
        client.generate_csr.return_value = ("task", {"status": "IN_PROGRESS"})
        client.wait_task.side_effect = WorkflowFailedError("failed")
        with patch("vcf_cert_renewer.renewer.sign_csr") as sign:
            with self.assertRaises(WorkflowFailedError):
                execute_domain_renewal(client, settings, "vcenter.example",
                                       resource_type="VCENTER")
        client.generate_csr.assert_called_once()
        client.fetch_csr.assert_not_called()
        client.validate_certificate.assert_not_called()
        client.replace_certificate.assert_not_called()
        sign.assert_not_called()

    def test_shared_flow_finishes_with_https_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings("token", "url", True, 30, "api",
                                output_dir=Path(directory), acme_mode="production",
                                acme_server=ACME_DIRECTORIES["production"])
            client = Mock()
            resource = {"resourceId": "vc", "fqdn": "vcenter.example",
                        "type": "VCENTER", "sans": ["vcenter.example"]}
            client.resolve_context.return_value = ("domain", resource)
            client.generate_csr.return_value = ("csr-task", {})
            client.fetch_csr.return_value = "CSR"
            client.validate_certificate.return_value = {"validationId": "validation"}
            client.replace_certificate.return_value = ("replace-task", {"status": "SUCCESSFUL"})
            fullchain = Path(directory) / "vcenter.example.vcf-fullchain.pem"
            fullchain.write_text("CHAIN")
            with patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": str(Path(directory) / "leaf"),
                    "issuerPath": str(Path(directory) / "issuer")}), \
                 patch("vcf_cert_renewer.renewer.build_vcf_fullchain"), \
                 patch("vcf_cert_renewer.renewer.verify_https_certificate",
                       return_value={"verified": True}) as verify:
                result = execute_domain_renewal(client, settings, "vcenter.example",
                                                resource_type="VCENTER")
            self.assertEqual(result["resource"]["type"], "VCENTER")
            verify.assert_called_once_with("vcenter.example", b"CHAIN")

    @patch.dict("os.environ", {}, clear=True)
    def test_threshold_noop_and_domain_planned_actions(self):
        result = renewal_plan(
            Settings.from_env(), "vcenter.example",
            inspect=lambda *args, **kwargs: {
                "notAfter": "2099-01-01T00:00:00+00:00", "sans": ["vcenter.example"]})
        self.assertEqual(result["result"], "NO_RENEWAL_NEEDED")
        self.assertEqual(result["plannedActions"][0], "Resolve domain resource")
        self.assertNotIn("Find Fleet TLS leaf", result["plannedActions"])


if __name__ == "__main__":
    unittest.main()
