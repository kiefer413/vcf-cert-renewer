import io
import json
import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import main
from vcf_cert_renewer.components import adapter_for, discover_inventory, plan_inventory


def cert(host, endpoint="sddc.example", cn=None, group="default"):
    return {"certificateResourceKey": "dynamic-key", "category": "TLS_CERT",
            "applianceFqdn": host, "issuedToCommonName": cn or host,
            "vcfEndpoint": endpoint, "domainId": "dynamic-domain",
            "certificateMetadata": {"certificateChainRole": "LEAF",
                                    "certificateChainGroupId": group,
                                    "managementLevel": "CUSTOMER_MANAGED_FULL_MANAGEMENT"}}


class AdapterTests(unittest.TestCase):
    def test_adapter_selection(self):
        cases = [
            (cert("ops.example", "INTEGRATED_OPS_LCM"), "operations", "FULL_RENEW"),
            (cert("sddc.example"), "sddc", "FULL_RENEW"),
            (cert("vcenter.example"), "vcenter", "FULL_RENEW"),
            (cert("nsxt.example"), "nsx", "FULL_RENEW"),
            (cert("nsxt01.example"), "nsx_node", "PLAN_ONLY"),
            (cert("idbroker.example", "runtime.example"), "identity", "PLAN_ONLY"),
            (cert("runtime.example", "runtime.example"), "runtime", "PLAN_ONLY"),
            (cert("192.0.2.2", "192.0.2.3", "OPS_NETWORKS-COLLECTOR"),
             "operations_networks", "DISCOVER_ONLY"),
            (cert("supervisor.example"), "supervisor", "PLAN_ONLY"),
        ]
        for record, name, capability in cases:
            with self.subTest(name=name):
                adapter = adapter_for(record)
                self.assertEqual(adapter.name, name)
                self.assertEqual(adapter.capability.value, capability)

    def test_normalized_inventory_and_live_status(self):
        client = Mock()
        client.query_certificates.return_value = [cert("vcenter.example")]
        verifier = Mock(return_value={"notAfter": "2030-01-01T00:00:00+00:00"})
        result = discover_inventory(client, verifier=verifier)
        self.assertEqual(result[0]["targetFqdn"], "vcenter.example")
        self.assertEqual(result[0]["domainId"], "dynamic-domain")
        self.assertEqual(result[0]["adapterName"], "vcenter")
        self.assertTrue(result[0]["liveHttpsStatus"]["reachable"])
        self.assertTrue(result[0]["supportsReplace"])
        client.query_certificates.assert_called_once_with(page_size=500)

    def test_non_leaf_is_excluded(self):
        client = Mock()
        root = cert("root.example")
        root["certificateMetadata"]["certificateChainRole"] = "ROOT"
        client.query_certificates.return_value = [root]
        self.assertEqual(discover_inventory(client), [])

    def test_unsupported_methods_refuse(self):
        adapter = adapter_for(cert("vcenter.example"))
        with self.assertRaises(NotImplementedError):
            adapter.generate_csr(Mock(), {})
        with self.assertRaises(NotImplementedError):
            adapter.import_certificate(Mock(), b"pem", "vcenter.example")
        with self.assertRaises(NotImplementedError):
            adapter.replace_certificate(Mock(), "vcenter.example")

    def test_plan_all_uses_read_only_query_and_verifier(self):
        client = Mock()
        client.query_certificates.return_value = [cert("sddc.example")]
        result = plan_inventory(client, verifier=Mock(return_value={"notAfter": "2030"}))
        self.assertEqual(result["mode"], "READ_ONLY")
        self.assertFalse(result["mutatingCallsMade"])
        self.assertEqual(result["targetCount"], 1)
        self.assertFalse(client.create_csr.called)
        self.assertFalse(client.session.post.called)
        self.assertFalse(client.session.put.called)


class MultiCliTests(unittest.TestCase):
    @patch("vcf_cert_renewer.cli.discover_inventory")
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token"}, clear=True)
    def test_discover_all(self, exchange, client_class, discover):
        discover.return_value = [{"adapterName": "operations"}]
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["discover", "--all"]), 0)
        self.assertEqual(json.loads(output.getvalue())[0]["adapterName"], "operations")
        discover.assert_called_once_with(client_class.return_value, page_size=500)
        self.assertFalse(client_class.return_value.create_csr.called)

    @patch("vcf_cert_renewer.cli.plan_inventory")
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token"}, clear=True)
    def test_plan_all(self, exchange, client_class, planning):
        planning.return_value = {"targetCount": 1, "notice": "No changes have been made."}
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(main(["plan", "--all"]), 0)
        self.assertEqual(json.loads(output.getvalue())["targetCount"], 1)
        planning.assert_called_once_with(client_class.return_value, page_size=500)
        self.assertFalse(client_class.return_value.session.put.called)

    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token"}, clear=True)
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    def test_plan_requires_target_or_all(self, exchange):
        with patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["plan"]), 2)


if __name__ == "__main__":
    unittest.main()
