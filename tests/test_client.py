import unittest
from unittest.mock import Mock

from vcf_cert_renewer.client import VcfApiClient


class QueryCertificatesTests(unittest.TestCase):
    def test_posts_expected_query(self):
        client = VcfApiClient("https://ops.example", "bearer", verify_tls=False)
        response = Mock()
        response.json.return_value = {"vcfCertificateModels": [{"id": "one"}]}
        client.session.post = Mock(return_value=response)

        self.assertEqual(client.query_certificates(), [{"id": "one"}])
        client.session.post.assert_called_once_with(
            "https://ops.example/suite-api/api/fleet-management/"
            "certificate-management/certificates/query",
            params={"pageSize": 500},
            json={},
            timeout=30,
            verify=False,
        )


if __name__ == "__main__":
    unittest.main()
