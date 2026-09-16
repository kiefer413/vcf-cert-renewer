import io
import json
import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import main
from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.plan import build_domain_plan
from vcf_cert_renewer.sddc_client import SddcApiClient


def response(payload):
    result = Mock()
    result.json.return_value = payload
    result.headers = {}
    result.raise_for_status.return_value = None
    result.status_code = 200
    result.text = ""
    return result


class NsxOfficialDiscoveryTests(unittest.TestCase):
    def client(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "secret")
        client._access_token = "token"
        return client

    def payloads(self):
        domains = response({"elements": [{"id": "domain", "type": "MANAGEMENT"}]})
        clusters = response({"elements": [{
            "id": "cluster", "vipFqdn": "nsxt.example",
            "domains": [{"id": "domain"}],
            "nodes": [{"id": "node", "fqdn": "nsxt01.example", "name": "nsxt01"}],
        }]})
        certificates = response({"elements": [
            {"resourceType": "NSXT_MANAGER", "resourceName": "nsxt.example",
             "subjectAlternativeName": ["nsxt.example", "192.0.2.30"]},
            {"resourceType": "NSXT_MANAGER", "resourceName": "nsxt01.example",
             "subjectAlternativeName": ["nsxt01.example", "192.0.2.31"]},
        ]})
        return domains, clusters, certificates

    def test_vip_and_node_are_distinct_exact_nsxt_manager_resources(self):
        client = self.client()
        client._request = Mock(side_effect=self.payloads())
        domain, vip = client.resolve_context("NSXT.EXAMPLE.", "NSXT_MANAGER")
        self.assertEqual((domain, vip["resourceId"], vip["nsxRole"]),
                         ("domain", "cluster", "VIP"))
        self.assertEqual(vip["sans"], ["nsxt.example", "192.0.2.30"])
        self.assertEqual(vip["type"], "NSXT_MANAGER")

        client._request = Mock(side_effect=self.payloads())
        _, node = client.resolve_context("nsxt01.example", "NSXT_MANAGER")
        self.assertEqual((node["resourceId"], node["nsxRole"]), ("node", "NODE"))
        self.assertEqual(node["verificationTargets"], ["nsxt01.example"])

    def test_ambiguous_or_missing_certificate_identity_fails_closed(self):
        client = self.client()
        domains, clusters, _ = self.payloads()
        client._request = Mock(side_effect=[domains, clusters, response({"elements": []})])
        with self.assertRaisesRegex(ValueError, "certificate identity.*found 0"):
            client.resolve_context("nsxt.example", "NSXT_MANAGER")

    @patch("vcf_cert_renewer.plan.inspect_https_certificate",
           return_value={"notAfter": "2028-01-01T00:00:00Z", "sans": ["nsxt.example"]})
    def test_private_ip_san_is_reported_and_plan_is_read_only(self, inspect):
        client = self.client()
        client._request = Mock(side_effect=self.payloads())
        result = build_domain_plan(client, Settings("token", "url", True, 30, "api"),
                                   "nsxt.example", "NSXT_MANAGER")
        self.assertEqual(result["renewalCapability"], "PLAN_ONLY")
        self.assertEqual(result["unsupportedSans"], ["192.0.2.30"])
        self.assertTrue(all(call.args[0] == "GET" for call in client._request.call_args_list))
        self.assertEqual(client._request.call_count, 3)

    @patch("vcf_cert_renewer.cli.execute_domain_renewal")
    @patch("vcf_cert_renewer.cli.execute_renewal")
    @patch("vcf_cert_renewer.cli.renewal_plan", return_value={"result": "RENEWAL_REQUIRED"})
    @patch.dict("os.environ", {"ACME_MODE": "production", "VCF_VERIFY_TLS": "true"}, clear=True)
    def test_approved_nsx_renew_requires_separate_native_auth_without_mutation(self, plan, operations, domain):
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["renew", "nsxt.example", "--force", "--yes"]), 2)
        self.assertIn('"result": "RENEWAL_REQUIRED"', output.getvalue())
        domain.assert_not_called()
        operations.assert_not_called()


if __name__ == "__main__":
    unittest.main()
