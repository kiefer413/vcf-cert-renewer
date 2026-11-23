import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.certificates import CertificateNotFoundError
from vcf_cert_renewer.cli import BATCH_TARGETS, _batch_renew
from vcf_cert_renewer.diagnostics import diagnostic_for_exception
from vcf_cert_renewer.nsx_client import NsxApiClient
from vcf_cert_renewer.renewer import execute_nsx_renewal
from vcf_cert_renewer.sddc_client import SddcApiClient


def response(payload=None, status=200, headers=None):
    result = Mock()
    result.json.return_value = payload or {}
    result.headers = headers or {}
    result.status_code = status
    result.text = "credential=must-not-appear"
    result.raise_for_status.return_value = None
    return result


class SddcDiagnosticTests(unittest.TestCase):
    def client(self, component="SDDC_MANAGER", target="sddc.vcf.example"):
        client = SddcApiClient("https://sddc.internal", "service-user",
                               "password-secret", timeout_seconds=30)
        client._access_token = "bearer-secret"
        client.set_target(target, component)
        return client

    def test_get_timeout_identifies_component_operation_and_sanitized_route(self):
        client = self.client("VCENTER", "vcenter.vcf.example")
        client.session.request = Mock(side_effect=requests.ReadTimeout(
            "Bearer bearer-secret https://sddc.internal/v1/vcenters?api_token=api-secret"))
        with self.assertRaises(requests.ReadTimeout) as caught:
            client._request("GET", "/v1/vcenters?domainId=private-id&password=password-secret")

        event = caught.exception.renewal_diagnostic
        self.assertEqual(event["component"], "VCENTER")
        self.assertEqual(event["operation"], "LIST_VCENTERS")
        self.assertEqual(event["httpMethod"], "GET")
        self.assertEqual(event["apiPath"], "/v1/vcenters")
        self.assertEqual(event["errorType"], "ReadTimeout")
        self.assertEqual(event["timeoutSeconds"], 30)
        self.assertEqual(event["outcome"], "READ_REQUEST_FAILED")
        rendered = json.dumps(event)
        for secret in ("bearer-secret", "password-secret", "api-secret", "private-id"):
            self.assertNotIn(secret, rendered)
        client.session.request.assert_called_once()

    def test_mutating_put_timeout_is_unknown_and_never_retried(self):
        client = self.client()
        accepted_then_response_lost = []

        def accept_then_drop(*args, **kwargs):
            accepted_then_response_lost.append(kwargs["json"])
            raise requests.ReadTimeout("Authorization: Bearer bearer-secret")

        client.session.request = Mock(side_effect=accept_then_drop)
        resource = {"resourceId": "private-domain-id", "fqdn": "sddc.vcf.example"}
        with self.assertRaises(requests.ReadTimeout) as caught:
            client.generate_csr("private-domain-id", resource, {"organization": "Org"})

        event = caught.exception.renewal_diagnostic
        self.assertEqual(event["operation"], "CREATE_CSR")
        self.assertEqual(event["httpMethod"], "PUT")
        self.assertEqual(event["apiPath"], "/v1/domains/{domainId}/csrs")
        self.assertEqual(event["outcome"], "UNKNOWN_SERVER_OUTCOME")
        self.assertNotIn("taskId", event)
        self.assertEqual(len(accepted_then_response_lost), 1)
        client.session.request.assert_called_once()
        self.assertNotIn("private-domain-id", json.dumps(event))
        self.assertNotIn("bearer-secret", json.dumps(event))

    def test_delayed_successful_response_records_elapsed_time_without_output_change(self):
        client = self.client()
        client.session.request = Mock(return_value=response({"elements": []}))
        with patch("vcf_cert_renewer.sddc_client.time.monotonic",
                   side_effect=[100.0, 100.125]):
            result = client._request("GET", "/v1/domains")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(client._last_request_context["elapsedSeconds"], 0.125)

    def test_response_status_and_body_are_not_disclosed(self):
        client = self.client()
        failed = response(status=503)
        failed.raise_for_status.side_effect = requests.HTTPError("503 credential=secret")
        client.session.request = Mock(return_value=failed)
        with self.assertRaises(Exception) as caught:
            client._request("PUT", "/v1/domains/domain-id/resource-certificates")
        event = caught.exception.renewal_diagnostic
        self.assertEqual(event["httpStatus"], 503)
        self.assertEqual(event["outcome"], "HTTP_RESPONSE_RECEIVED")
        self.assertNotIn("credential=must-not-appear", json.dumps(event))
        self.assertNotIn("credential=secret", json.dumps(event))

    def test_task_id_is_reported_only_when_observed_in_poll_route(self):
        client = self.client()
        client.session.request = Mock(side_effect=requests.ReadTimeout("lost"))
        with self.assertRaises(requests.ReadTimeout) as caught:
            client._request("GET", "/v1/tasks/task-456")
        event = caught.exception.renewal_diagnostic
        self.assertEqual(event["taskId"], "task-456")
        self.assertEqual(event["apiPath"], "/v1/tasks/{taskId}")

        client.session.request = Mock(side_effect=requests.ReadTimeout("lost"))
        with self.assertRaises(requests.ReadTimeout) as caught:
            client._request("GET", "/v1/domains")
        self.assertNotIn("taskId", caught.exception.renewal_diagnostic)


class BatchDiagnosticTests(unittest.TestCase):
    def test_failure_diagnostic_is_retained_while_batch_continues(self):
        settings = Settings("https://token.invalid", "https://vcf.invalid",
                            True, 30, "api-token-secret")
        plans = lambda _settings, target, force: {
            "targetFqdn": target, "result": "RENEWAL_REQUIRED"}
        outcomes = [
            {"result": "RENEWED"},
            requests.ReadTimeout("Authorization: Bearer api-token-secret"),
            {"result": "RENEWED"},
            {"result": "RENEWED"},
        ]

        def execute(*args, **kwargs):
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        output = io.StringIO()
        with (patch("vcf_cert_renewer.cli.renewal_plan", side_effect=plans),
              patch("vcf_cert_renewer.cli._discover_automation",
                    side_effect=CertificateNotFoundError()),
              patch("vcf_cert_renewer.cli._execute_supported_renewal",
                    side_effect=execute),
              patch("vcf_cert_renewer.cli.validate_signer_configuration"),
              patch("sys.stdout", output)):
            code = _batch_renew(settings, Namespace(
                force=True, yes=True, apply=False,
                poll_interval=2, poll_timeout=10))

        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result["summary"][0]["status"], "RENEWED")
        failure = result["summary"][1]
        self.assertEqual(failure["targetFqdn"], BATCH_TARGETS[1])
        self.assertEqual(failure["diagnostic"]["component"], "SDDC_MANAGER")
        self.assertEqual(failure["diagnostic"]["errorType"], "ReadTimeout")
        self.assertNotIn("api-token-secret", output.getvalue())
        self.assertEqual([item["status"] for item in result["summary"]],
                         ["RENEWED", "FAILED", "RENEWED", "RENEWED"])


class NsxDiagnosticTests(unittest.TestCase):
    def base_flow(self, output):
        client = Mock()
        client.validate_dns_sans.return_value = ["nsxt.vcf.example"]
        client.create_csr.return_value = {"id": "csr-id", "pem_encoded": "CSR"}
        client.import_csr_certificate.return_value = {"id": "cert-id", "has_private_key": True}
        client.discover.side_effect = [
            {"certificate": {"id": "vip-old", "details": [{"subject_alt_names": {
                "dns_names": ["nsxt.vcf.example"], "ip_addresses": []}}]},
             "apiCertificates": [{"id": "node-api", "details": [{"subject_alt_names": {
                 "dns_names": ["nsxt01.vcf.example"], "ip_addresses": ["10.0.0.31"]}}]}]},
            {"certificate": {"id": "cert-id"}},
        ]
        settings = Settings("token", "url", True, 30, "api", output_dir=output)
        (output / "nsxt.vcf.example.vcf-fullchain.pem").write_text("CHAIN")
        return client, settings

    def run_failure(self, operation):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            client, settings = self.base_flow(output)
            patches = []
            if operation == "GENERATE_CSR":
                client.create_csr.side_effect = ValueError("generation detail with secret")
            elif operation == "ACME_SIGNING":
                patches.append(patch("vcf_cert_renewer.renewer.sign_csr",
                                     side_effect=ValueError(
                                         "lego signing failed with exit status 7; "
                                         "stderr: TSIG_SECRET=private-secret")))
            elif operation == "CERTIFICATE_CHAIN_CONSTRUCTION":
                patches.append(patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": output / "leaf", "issuerPath": output / "issuer"}))
                patches.append(patch("vcf_cert_renewer.renewer.build_vcf_fullchain",
                                     side_effect=ValueError("chain body private-secret")))
            elif operation == "CERTIFICATE_IMPORT":
                patches.append(patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": output / "leaf", "issuerPath": output / "issuer"}))
                patches.append(patch("vcf_cert_renewer.renewer.build_vcf_fullchain"))
                client.import_csr_certificate.side_effect = ValueError("token=private-secret")
            elif operation == "APPLY_MGMT_CLUSTER_CERTIFICATE":
                patches.append(patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": output / "leaf", "issuerPath": output / "issuer"}))
                patches.append(patch("vcf_cert_renewer.renewer.build_vcf_fullchain"))
                client.apply_mgmt_cluster.side_effect = requests.ReadTimeout(
                    "Authorization: Bearer private-secret")
            elif operation == "POST_INSTALLATION_VERIFICATION":
                patches.append(patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": output / "leaf", "issuerPath": output / "issuer"}))
                patches.append(patch("vcf_cert_renewer.renewer.build_vcf_fullchain"))
                patches.append(patch("vcf_cert_renewer.renewer._verify_nsx_mgmt_cluster",
                                     side_effect=ValueError("private-secret")))
            for item in patches:
                item.start()
            try:
                execute_nsx_renewal(client, settings, "nsxt.vcf.example")
            except Exception as exc:
                event = diagnostic_for_exception(
                    exc, component="NSX_MANAGER", target="nsxt.vcf.example",
                    phase="RENEW")
                return exc, event, client
            finally:
                for item in reversed(patches):
                    item.stop()
        self.fail(f"expected {operation} to fail")

    def test_dns_only_vip_identity_and_node_api_ip_san_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            client, settings = self.base_flow(output)
            with patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": output / "leaf", "issuerPath": output / "issuer",
                    "sha256Thumbprint": "fingerprint"}), \
                 patch("vcf_cert_renewer.renewer.build_vcf_fullchain"), \
                 patch("vcf_cert_renewer.renewer._verify_nsx_mgmt_cluster",
                       return_value={"liveHttpsCertificate": {"sha256_thumbprint": "x"}}):
                execute_nsx_renewal(client, settings, "nsxt.vcf.example")
            client.validate_dns_sans.assert_called_once_with(
                "nsxt.vcf.example", ["nsxt.vcf.example"])
            client.create_csr.assert_called_once_with(
                "nsxt.vcf.example", ["nsxt.vcf.example"], unittest.mock.ANY)

    def test_nsx_stage_failures_are_identified_and_secret_safe(self):
        for operation in ("GENERATE_CSR", "ACME_SIGNING", "CERTIFICATE_CHAIN_CONSTRUCTION",
                          "CERTIFICATE_IMPORT", "APPLY_MGMT_CLUSTER_CERTIFICATE",
                          "POST_INSTALLATION_VERIFICATION"):
            with self.subTest(operation=operation):
                exc, event, client = self.run_failure(operation)
                self.assertEqual(event["operation"], operation)
                self.assertEqual(event["component"], "NSX_MANAGER")
                self.assertEqual(event["targetFqdn"], "nsxt.vcf.example")
                rendered = json.dumps(event)
                self.assertNotIn("private-secret", rendered)
                self.assertNotIn("token=", rendered)
                self.assertNotIn("Authorization", rendered)

    def test_nsx_mutating_http_timeout_has_ambiguous_outcome(self):
        client = NsxApiClient("https://nsxt.internal", lambda: "bearer-secret")
        client.set_target("nsxt.vcf.example")
        client.session.request = Mock(side_effect=requests.ReadTimeout("lost response"))
        with self.assertRaises(requests.ReadTimeout) as caught:
            client.apply_mgmt_cluster("certificate-secret-id")
        event = caught.exception.renewal_diagnostic
        self.assertEqual(event["operation"], "APPLY_MGMT_CLUSTER_CERTIFICATE")
        self.assertEqual(event["apiPath"],
                         "/api/v1/trust-management/certificates/{certificateId}")
        self.assertEqual(event["outcome"], "UNKNOWN_SERVER_OUTCOME")
        self.assertNotIn("bearer-secret", json.dumps(event))
        self.assertNotIn("certificate-secret-id", json.dumps(event))
        client.session.request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
