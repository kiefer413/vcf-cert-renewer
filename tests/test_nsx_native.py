import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.nsx_client import NsxApiClient
from vcf_cert_renewer.renewer import _verify_nsx_mgmt_cluster, execute_nsx_renewal
from vcf_cert_renewer.replacer import TlsVerificationError


def response(payload=None):
    value = Mock(); value.json.return_value = payload or {}; value.raise_for_status.return_value = None
    return value


class NsxNativeClientTests(unittest.TestCase):
    def client(self):
        return NsxApiClient("https://nsxt.example", lambda: "bearer-secret")

    def test_bearer_token_is_lazy_cached_and_basic_auth_is_never_used(self):
        provider = Mock(return_value="bearer-secret")
        client = NsxApiClient("https://nsxt.example", provider)
        client.session.request = Mock(return_value=response({"product_version": "9.1.1"}))
        client.version(); client.version()
        provider.assert_called_once_with()
        self.assertIsNone(client.session.auth)
        for call in client.session.request.call_args_list:
            self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer bearer-secret")

    def test_unauthorized_is_not_retried_and_secret_is_not_in_error(self):
        for status in ("401 Unauthorized", "403 Forbidden"):
            with self.subTest(status=status):
                provider = Mock(return_value="bearer-secret")
                client = NsxApiClient("https://nsxt.example", provider)
                denied = response(); denied.raise_for_status.side_effect = RuntimeError(status)
                client.session.request = Mock(return_value=denied)
                with self.assertRaisesRegex(RuntimeError, status) as caught:
                    client.version()
                client.session.request.assert_called_once()
                provider.assert_called_once_with()
                self.assertNotIn("bearer-secret", str(caught.exception))

    def test_discovery_distinguishes_cluster_and_node_api(self):
        client = self.client()
        client.profiles = Mock(return_value=[
            {"service_type": "MGMT_CLUSTER", "cluster_certificate": True},
            {"service_type": "API", "cluster_certificate": False}])
        vip = {"id": "vip-cert", "used_by": [{"service_types": ["MGMT_CLUSTER"]}]}
        node = {"id": "node-cert", "used_by": [{"node_id": "node-1", "service_types": ["API"]}]}
        client.certificates = Mock(return_value=[vip, node])
        client.nodes = Mock(return_value=[{"id": "node-1", "fqdn": "nsxt01.example"}])
        client.version = Mock(return_value={"product_version": "9.1.1.0"})
        found = client.discover("nsxt.example")
        self.assertEqual(found["certificate"]["id"], "vip-cert")
        self.assertEqual(found["apiCertificates"][0]["id"], "node-cert")

    def test_csr_and_apply_use_exact_official_contract(self):
        client = self.client(); client._request = Mock(side_effect=[response({"id": "csr"}), response()])
        client.create_csr("nsxt.example", ["nsxt.example"], {
            "organization": "O", "organizationUnit": "OU", "country": "DK",
            "state": "S", "locality": "L"})
        call = client._request.call_args_list[0]
        self.assertEqual(call.args[:2], ("POST", "/api/v1/trust-management/csrs"))
        self.assertEqual(call.kwargs["json"]["extensions"]["subject_alt_names"]["dns_names"], ["nsxt.example"])
        client.apply_mgmt_cluster("cert id")
        call = client._request.call_args_list[1]
        self.assertEqual(call.args[1], "/api/v1/trust-management/certificates/cert%20id?action=apply_certificate")
        self.assertEqual(call.kwargs["params"], {"service_type": "MGMT_CLUSTER"})
        self.assertNotIn("node_id", call.kwargs["params"])
        self.assertNotEqual(call.kwargs["params"].get("service_type"), "API")
        self.assertNotIn("node-cert", call.args[1])

    def test_ip_sans_fail_closed_and_sans_are_preserved(self):
        self.assertEqual(NsxApiClient.validate_dns_sans("nsxt.example", ["nsxt.example", "alias.example"]),
                         ["nsxt.example", "alias.example"])
        with self.assertRaisesRegex(ValueError, "IP SAN"):
            NsxApiClient.validate_dns_sans("nsxt.example", ["nsxt.example", "192.0.2.30"])

    @patch("vcf_cert_renewer.renewer.verify_https_certificate", return_value={"sha256_thumbprint": "x", "verified": True})
    @patch("vcf_cert_renewer.renewer.build_vcf_fullchain")
    @patch("vcf_cert_renewer.renewer.sign_csr")
    def test_flow_applies_only_mgmt_cluster(self, sign, build, verify):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); (out / "nsxt.example.vcf-fullchain.pem").write_text("CHAIN")
            sign.return_value = {"leafPath": out/"leaf", "issuerPath": out/"issuer", "sha256Thumbprint": "x"}
            client = Mock(); client.validate_dns_sans.return_value = ["nsxt.example"]
            client.create_csr.return_value = {"id": "csr", "pem_encoded": "CSR"}
            client.import_csr_certificate.return_value = {"id": "new", "has_private_key": True}
            client.discover.side_effect = [{"certificate": {"id": "old"}}, {"certificate": {"id": "new"}}]
            settings = Settings("token", "url", True, 30, "api", output_dir=out)
            result = execute_nsx_renewal(client, settings, "nsxt.example")
            client.apply_mgmt_cluster.assert_called_once_with("new")
            self.assertFalse(result["apiCertificatesTouched"])
            self.assertEqual(client.import_csr_certificate.call_count, 1)
            self.assertEqual(verify.call_args.args[0], "nsxt.example")
            self.assertEqual(result["verification"]["status"], "SUCCEEDED")


    @patch("vcf_cert_renewer.renewer.time.sleep")
    @patch("vcf_cert_renewer.renewer.verify_https_certificate")
    def test_stale_metadata_then_https_match_succeeds(self, verify, sleep):
        client = Mock()
        client.discover.return_value = {"certificate": {"id": "old", "used_by": []}}
        verify.side_effect = [TlsVerificationError("old"),
                              {"sha256_thumbprint": "expected", "verified": True}]
        result = _verify_nsx_mgmt_cluster(
            client, "nsxt.example", "new", b"CHAIN",
            poll_interval=0.01, poll_timeout=1)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertIn("warning", result)
        client.apply_mgmt_cluster.assert_not_called()

    @patch("vcf_cert_renewer.renewer.time.sleep")
    @patch("vcf_cert_renewer.renewer.verify_https_certificate")
    def test_metadata_eventually_matches(self, verify, sleep):
        client = Mock()
        client.discover.side_effect = [
            {"certificate": {"id": "old"}}, {"certificate": {"id": "new"}}]
        verify.side_effect = [TlsVerificationError("old"),
                              {"sha256_thumbprint": "expected", "verified": True}]
        result = _verify_nsx_mgmt_cluster(
            client, "nsxt.example", "new", b"CHAIN",
            poll_interval=0.01, poll_timeout=1)
        self.assertEqual(result["assignmentMetadata"]["status"], "MATCHED")
        self.assertNotIn("warning", result)

    @patch("vcf_cert_renewer.renewer.verify_https_certificate",
           return_value={"sha256_thumbprint": "expected", "verified": True})
    def test_inconclusive_metadata_https_match_is_nonfatal(self, verify):
        client = Mock()
        client.discover.return_value = {"certificate": {"id": "other", "used_by": []}}
        result = _verify_nsx_mgmt_cluster(
            client, "nsxt.example", "new", b"CHAIN",
            poll_interval=0.01, poll_timeout=1)
        self.assertEqual(result["authoritativeSource"], "LIVE_HTTPS")
        self.assertIn("warning", result)

    @patch("vcf_cert_renewer.renewer.verify_https_certificate",
           side_effect=TlsVerificationError("wrong thumbprint"))
    def test_https_timeout_fails_closed_without_apply(self, verify):
        client = Mock()

        client.discover.return_value = {"certificate": {"id": "other"}}
        with self.assertRaisesRegex(TlsVerificationError, "did not present"):
            _verify_nsx_mgmt_cluster(
                client, "nsxt.example", "new", b"CHAIN",
                poll_interval=1, poll_timeout=0)
        client.apply_mgmt_cluster.assert_not_called()

    def test_apply_http_failure_fails_before_verification(self):
        client = self.client()
        failed = response()
        failed.raise_for_status.side_effect = RuntimeError("500 apply failed")
        client.session.request = Mock(return_value=failed)
        with self.assertRaisesRegex(RuntimeError, "500 apply failed"):
            client.apply_mgmt_cluster("new")
        client.session.request.assert_called_once()

if __name__ == "__main__":
    unittest.main()
