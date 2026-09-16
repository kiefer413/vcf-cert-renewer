import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.client import VcfApiClient
from vcf_cert_renewer.importer import (
    CertificateChainInfo, import_certificate_chain, list_imported_certificates)


class ImportCertificateTests(unittest.TestCase):
    def setUp(self):
        self.client = VcfApiClient(
            "https://ops.example", "bearer-secret", verify_tls=False)

    @patch("vcf_cert_renewer.importer.validate_chain_for_csr")
    def test_discovers_validates_and_posts_multipart(self, validate):
        self.client.query_certificates = Mock(return_value=[{
            "certificateResourceKey": "dynamic-key", "category": "TLS_CERT",
            "applianceFqdn": "ops.example", "issuedToCommonName": "ops.example",
            "certificateMetadata": {"certificateChainRole": "LEAF"}}])
        self.client.fetch_csr = Mock(return_value="CSR PEM")
        response = Mock()
        response.json.return_value = {
            "certificates": [{"thumbprint": "abc123"}]}
        self.client.session.post = Mock(return_value=response)
        validate.return_value = CertificateChainInfo(
            "ops.example", ("ops.example", "alias.example"), 3)

        result = import_certificate_chain(
            self.client, b"PEM CHAIN", "ops.example", filename="chain.pem")

        self.client.fetch_csr.assert_called_once_with(
            "dynamic-key", "ops.example")
        self.client.session.post.assert_called_once_with(
            "https://ops.example/suite-api/api/certificate",
            headers={"Content-Type": None},
            files={"certificateFile": (
                "chain.pem", b"PEM CHAIN", "application/x-pem-file")},
            timeout=30, verify=False)
        self.assertEqual(
            self.client.session.headers["Authorization"], "Bearer bearer-secret")
        self.assertEqual(result["importedCertificateId"], "abc123")
        self.assertEqual(result["workflowStatus"], "NOT_APPLICABLE")

    @patch("vcf_cert_renewer.importer.validate_chain_for_csr")
    def test_reports_server_workflow_status_when_present(self, validate):
        self.client.query_certificates = Mock(return_value=[{
            "certificateResourceKey": "dynamic-key", "category": "TLS_CERT",
            "applianceFqdn": "ops.example",
            "certificateMetadata": {"certificateChainRole": "LEAF"}}])
        self.client.fetch_csr = Mock(return_value="CSR PEM")
        response = Mock()
        response.json.return_value = {
            "state": "COMPLETED", "certificates": []}
        self.client.session.post = Mock(return_value=response)
        validate.return_value = CertificateChainInfo("ops.example", (), 1)
        result = import_certificate_chain(
            self.client, b"PEM", "ops.example")
        self.assertEqual(result["workflowStatus"], "COMPLETED")

    def test_lists_imported_certificates(self):
        response = Mock()
        response.json.return_value = {
            "certificates": [{"thumbprint": "one"}]}
        self.client.session.get = Mock(return_value=response)
        self.assertEqual(
            list_imported_certificates(self.client), [{"thumbprint": "one"}])
        self.client.session.get.assert_called_once_with(
            "https://ops.example/suite-api/api/certificate",
            timeout=30, verify=False)


if __name__ == "__main__":
    unittest.main()
