import unittest

from vcf_cert_renewer.certificates import (
    AmbiguousCertificateError,
    CertificateNotFoundError,
    find_leaf_tls_certificate,
)


class FindLeafTlsCertificateTests(unittest.TestCase):
    def setUp(self):
        self.root = {
            "certificateResourceKey": "root-id",
            "category": "ROOT_CERT",
            "applianceFqdn": "operations.example.com",
            "certificateMetadata": {"certificateChainRole": "ROOT"},
        }
        self.leaf = {
            "certificateResourceKey": "dynamic-leaf-id",
            "category": "TLS_CERT",
            "applianceFqdn": "operations.example.com",
            "issuedToCommonName": "operations.example.com",
            "subjectAlternativeNames": {
                "dns": ["operations.example.com", "opc.example.com"],
                "ip": [],
            },
            "certificateMetadata": {"certificateChainRole": "LEAF"},
        }

    def test_ignores_non_leaf_tls_record(self):
        non_leaf = dict(self.leaf)
        non_leaf["certificateMetadata"] = {"certificateChainRole": "INTERMEDIATE"}
        self.assertEqual(
            find_leaf_tls_certificate([non_leaf, self.leaf], "operations.example.com"),
            self.leaf,
        )

    def test_ignores_root_and_returns_leaf(self):
        self.assertIs(
            find_leaf_tls_certificate([self.root, self.leaf], "operations.example.com"),
            self.leaf,
        )

    def test_matches_san_case_insensitively(self):
        result = find_leaf_tls_certificate([self.leaf], "OPC.EXAMPLE.COM")
        self.assertIs(result, self.leaf)

    def test_raises_when_missing(self):
        with self.assertRaises(CertificateNotFoundError):
            find_leaf_tls_certificate([self.root], "operations.example.com")

    def test_raises_when_ambiguous(self):
        with self.assertRaises(AmbiguousCertificateError):
            find_leaf_tls_certificate([self.leaf, dict(self.leaf)], "operations.example.com")


if __name__ == "__main__":
    unittest.main()
