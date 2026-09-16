import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vcf_cert_renewer.client import VcfApiClient, WorkflowFailedError
from vcf_cert_renewer.replacer import (
    TlsVerificationError, certificate_chain_from_import,
    find_imported_certificate, poll_workflow, replace_certificate,
    verify_https_certificate, _certificate_differences, _normalized_dns_names,
    _normalized_name, _normalized_thumbprint, _utc_datetime)


def certificate_pem(name="ops.example"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), cert


class ReplacerTests(unittest.TestCase):
    def setUp(self):
        self.client = VcfApiClient("https://ops.example", "secret", verify_tls=False)

    def test_find_imported_by_thumbprint_and_cn(self):
        records = [{"thumbprint": "AA:BB", "issuedTo": "CN=ops.example, O=Lab"}]
        self.assertIs(find_imported_certificate(records, thumbprint="aabb"), records[0])
        self.assertIs(find_imported_certificate(records, common_name="OPS.EXAMPLE"), records[0])

    def test_chain_falls_back_to_matching_local_file(self):
        pem, cert = certificate_pem()
        imported = {"thumbprint": cert.fingerprint(hashes.SHA256()).hex()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.pem"
            path.write_bytes(pem)
            self.assertEqual(certificate_chain_from_import(imported, search_paths=[path]), pem)

    def test_replace_uses_dynamic_id_and_official_payload(self):
        pem, cert = certificate_pem()
        thumbprint = cert.fingerprint(hashes.SHA256()).hex()
        self.client.query_certificates = Mock(return_value=[{
            "certificateResourceKey": "dynamic-id", "category": "TLS_CERT",
            "applianceFqdn": "ops.example",
            "certificateMetadata": {"certificateChainRole": "LEAF"}}])
        response = Mock(headers={})
        response.json.return_value = {"requestId": "workflow-1", "state": "CREATED"}
        self.client.session.get = Mock(return_value=Mock(json=Mock(return_value={
            "certificates": [{"thumbprint": thumbprint, "issuedTo": "CN=ops.example",
                              "certificate": pem.decode()}]})))
        self.client.session.put = Mock(return_value=response)
        request_id, payload, chain = replace_certificate(
            self.client, "ops.example", thumbprint=thumbprint)
        self.assertEqual(request_id, "workflow-1")
        self.assertEqual(chain, pem)
        call = self.client.session.put.call_args
        self.assertTrue(call.args[0].endswith("/certificates/dynamic-id"))
        self.assertEqual(call.kwargs["json"], {
            "caType": "EXTERNAL_CA", "certificateChain": pem.decode()})

    @patch("vcf_cert_renewer.replacer.time.sleep")
    def test_poll_workflow_through_documented_states(self, sleep):
        responses = []
        for state in ("CREATED", "IN_PROGRESS", "COMPLETED"):
            response = Mock()
            response.json.return_value = {"state": state}
            responses.append(response)
        self.client.session.get = Mock(side_effect=responses)
        result = poll_workflow(self.client, "workflow-1", poll_interval=0)
        self.assertEqual(result["state"], "COMPLETED")

    def test_poll_workflow_raises_on_failed(self):
        response = Mock()
        response.json.return_value = {"state": "FAILED", "errorCause": [{"message": "no"}]}
        self.client.session.get = Mock(return_value=response)
        with self.assertRaises(WorkflowFailedError):
            poll_workflow(self.client, "workflow-1", poll_interval=0)

    def test_thumbprint_normalization_ignores_case_and_separators(self):
        plain = "ab" * 32
        coloned = ":".join(["AB"] * 32)
        self.assertEqual(_normalized_thumbprint(plain), _normalized_thumbprint(coloned))

    def test_san_normalization_uses_case_insensitive_set(self):
        self.assertEqual(
            _normalized_dns_names(["OPS.Example", "opc.example", "ops.example."]),
            _normalized_dns_names(["OPC.EXAMPLE", "ops.example"]))

    def test_distinguished_name_normalization_ignores_order_and_spacing(self):
        self.assertEqual(
            _normalized_name("CN=OPS.Example,O=Example Corp,C=DK"),
            _normalized_name("C=DK,O=Example  Corp,CN=ops.example"))

    def test_date_normalization_converts_semantic_instant_to_utc(self):
        self.assertEqual(_utc_datetime("2026-09-14T08:00:00+02:00"),
                         _utc_datetime("2026-09-14T06:00:00Z"))
        self.assertEqual(_utc_datetime("2026-09-14T06:00:00"),
                         _utc_datetime("2026-09-14T06:00:00+00:00"))

    def test_subject_and_issuer_comparison_uses_parsed_names(self):
        _, cert = certificate_pem()
        self.assertEqual(_certificate_differences(cert, cert), [])

    def test_tls_verification_compares_active_leaf(self):
        pem, cert = certificate_pem()
        der = cert.public_bytes(serialization.Encoding.DER)
        raw = Mock()
        raw.__enter__ = Mock(return_value=raw)
        raw.__exit__ = Mock(return_value=False)
        tls = Mock()
        tls.__enter__ = Mock(return_value=tls)
        tls.__exit__ = Mock(return_value=False)
        tls.getpeercert.return_value = der
        context = Mock()
        context.wrap_socket.return_value = tls
        with patch("vcf_cert_renewer.replacer.socket.create_connection", return_value=raw), \
             patch("vcf_cert_renewer.replacer.ssl.create_default_context", return_value=context):
            result = verify_https_certificate("ops.example", pem)
        self.assertTrue(result["verified"])
        context.wrap_socket.assert_called_once_with(raw, server_hostname="ops.example")

    def test_tls_verification_rejects_other_certificate(self):
        expected, _ = certificate_pem()
        _, actual = certificate_pem("other.example")
        der = actual.public_bytes(serialization.Encoding.DER)
        raw = Mock(__enter__=Mock(return_value=Mock()), __exit__=Mock(return_value=False))
        raw.__enter__.return_value = raw
        tls = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        tls.__enter__.return_value = tls
        tls.getpeercert.return_value = der
        context = Mock()
        context.wrap_socket.return_value = tls
        with patch("vcf_cert_renewer.replacer.socket.create_connection", return_value=raw), \
             patch("vcf_cert_renewer.replacer.ssl.create_default_context", return_value=context), \
             self.assertRaises(TlsVerificationError):
            verify_https_certificate("ops.example", expected, retry_timeout=0)

    @patch("vcf_cert_renewer.replacer.time.sleep")
    @patch("vcf_cert_renewer.replacer.time.monotonic", side_effect=[0, 1, 2])
    @patch("vcf_cert_renewer.replacer._fetch_https_certificate")
    def test_tls_verification_retries_until_expected_certificate_is_active(
            self, fetch, monotonic, sleep):
        expected_pem, expected = certificate_pem()
        _, old = certificate_pem("old.example")
        fetch.side_effect = [old, expected]
        result = verify_https_certificate(
            "ops.example", expected_pem, retry_timeout=300, retry_interval=10)
        self.assertTrue(result["verified"])
        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once_with(10)


if __name__ == "__main__":
    unittest.main()
