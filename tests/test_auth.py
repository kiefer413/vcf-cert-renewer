import unittest
from unittest.mock import Mock, patch

from vcf_cert_renewer.auth import TokenExchangeError, exchange_token
from vcf_cert_renewer.config import Settings


class ExchangeTokenTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            token_url="https://identity.example/token",
            base_url="https://ops.example",
            verify_tls=False,
            timeout_seconds=12,
            api_token="secret-api-token",
            client_id=None,
            client_secret=None,
        )

    @patch("vcf_cert_renewer.auth.requests.post")
    def test_uses_vcf_api_token_grant(self, post):
        response = Mock()
        response.json.return_value = {"access_token": "short-lived-token"}
        post.return_value = response

        self.assertEqual(exchange_token(self.settings), "short-lived-token")
        post.assert_called_once_with(
            "https://identity.example/token",
            data={
                "grant_type": "urn:custom:vcf:params:oauth:grant-type:api-token",
                "api_token": "secret-api-token",
            },
            headers={"Accept": "application/json"},
            timeout=12,
            verify=False,
        )
        response.raise_for_status.assert_called_once_with()

    @patch("vcf_cert_renewer.auth.requests.post")
    def test_rejects_response_without_access_token(self, post):
        post.return_value.json.return_value = {}
        with self.assertRaises(TokenExchangeError):
            exchange_token(self.settings)


if __name__ == "__main__":
    unittest.main()
