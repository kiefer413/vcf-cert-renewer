import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vcf_cert_renewer.cli import main
from vcf_cert_renewer.client import VcfApiClient, WorkflowFailedError


class CsrClientTests(unittest.TestCase):
    def setUp(self):
        self.client = VcfApiClient("https://ops.example", "bearer", verify_tls=False)
        self.client.session.post = Mock()
        self.client.session.get = Mock()

    def test_create_uses_discovered_key(self):
        response = Mock(headers={"Location": "/requests/request-1"})
        response.json.return_value = {"status": "IN_PROGRESS"}
        self.client.session.post.return_value = response
        certificate = {
            "certificateResourceKey": "dynamic-key",
            "issuedToCommonName": "ops.example",
            "subjectAlternativeNames": {"dns": ["ops.example"], "ip": ["192.0.2.1"]},
        }
        request_id, _ = self.client.create_csr(certificate)
        self.assertEqual(request_id, "request-1")
        self.client.session.post.assert_called_once_with(
            "https://ops.example/suite-api/api/fleet-management/certificate-management/csrs",
            timeout=30, verify=False, json={
                "certificateId": "dynamic-key",
                "generateCsrSpec": {
                    "commonName": "ops.example", "keySize": "KEY_2048",
                    "keyAlgorithm": "RSA", "organization": "VMware",
                    "orgUnit": "VMware Engineering",
                    "subjectAltNames": {"dns": ["ops.example"], "ip": ["192.0.2.1"]},
                }})

    @patch("vcf_cert_renewer.client.time.sleep")
    def test_polls_to_completion(self, sleep):
        running, done = Mock(), Mock()
        running.json.return_value = {"status": "IN_PROGRESS"}
        done.json.return_value = {"status": "COMPLETED", "result": {"csr": "PEM"}}
        self.client.session.get.side_effect = [running, done]
        result = self.client.wait_for_csr("request-1", poll_interval=0, poll_timeout=10)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.client.session.get.call_count, 2)

    def test_failed_workflow_raises(self):
        response = Mock(); response.json.return_value = {"status": "FAILED"}
        self.client.session.get.return_value = response
        with self.assertRaises(WorkflowFailedError):
            self.client.wait_for_csr("request-1", poll_interval=0)

    def test_fetches_csr_from_endpoint(self):
        response = Mock(); response.json.return_value = {"certificateSignatureInfo": [{
            "commonName": "ops.example",
            "csr": "-----BEGIN CERTIFICATE REQUEST----- " + "a" * 70 +
                   " -----END CERTIFICATE REQUEST-----"}]}
        self.client.session.get.return_value = response
        csr = self.client.fetch_csr("dynamic-key", "ops.example")
        self.assertEqual(csr.splitlines()[0], "-----BEGIN CERTIFICATE REQUEST-----")
        self.assertEqual(len(csr.splitlines()[1]), 64)
        self.assertEqual(len(csr.splitlines()[2]), 6)
        self.assertEqual(csr.splitlines()[3], "-----END CERTIFICATE REQUEST-----")


class GenerateCsrCommandTests(unittest.TestCase):
    @patch("vcf_cert_renewer.cli.VcfApiClient")
    @patch("vcf_cert_renewer.cli.exchange_token", return_value="short-token")
    @patch.dict("os.environ", {"VCF_API_TOKEN": "long-token"}, clear=True)
    def test_discovers_generates_and_writes_pem(self, exchange, client_class):
        client = client_class.return_value
        client.query_certificates.return_value = [{
            "certificateResourceKey": "dynamic-key", "category": "TLS_CERT",
            "applianceFqdn": "ops.vcf.example.com",
            "certificateMetadata": {"certificateChainRole": "LEAF"}}]
        client.create_csr.return_value = ("request-1", {"status": "IN_PROGRESS"})
        client._state.return_value = "IN_PROGRESS"
        client.wait_for_csr.return_value = {"status": "COMPLETED"}
        client.fetch_csr.return_value = "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n"
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["generate-csr", "ops.vcf.example.com", "--output", directory]), 0)
            output = Path(directory) / "ops.vcf.example.com.csr.pem"
            self.assertIn("BEGIN CERTIFICATE REQUEST", output.read_text())
        client.create_csr.assert_called_once_with(client.query_certificates.return_value[0])
        client.wait_for_csr.assert_called_once()
        client.fetch_csr.assert_called_once_with("dynamic-key", "ops.vcf.example.com")


if __name__ == "__main__":
    unittest.main()
