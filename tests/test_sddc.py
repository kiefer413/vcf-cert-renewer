import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from vcf_cert_renewer.config import ACME_DIRECTORIES, Settings
from vcf_cert_renewer.renewer import execute_sddc_renewal
from vcf_cert_renewer.sddc_client import SddcApiClient
from vcf_cert_renewer.client import WorkflowFailedError


def response(payload, location=None):
    result = Mock()
    result.json.return_value = payload
    result.headers = {"Location": location} if location else {}
    result.raise_for_status.return_value = None
    result.status_code = 200
    result.text = ""
    return result


class SddcClientTests(unittest.TestCase):
    def client(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
        client._access_token = "access-secret"
        return client

    def test_username_password_exchange_and_token_cached(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
        auth = response({"accessToken": "jwt-secret", "refreshToken": "refresh-secret",
                         "expiresIn": 3600})
        domains = response({"elements": []})
        client.session.request = Mock(side_effect=[auth, domains, domains])
        client._request("GET", "/v1/domains")
        client._request("GET", "/v1/domains")
        self.assertEqual(client.session.request.call_count, 3)
        first = client.session.request.call_args_list[0]
        self.assertEqual(first.args, ("POST", "https://sddc.example/v1/tokens"))
        self.assertEqual(first.kwargs["json"], {"username": "svc@example",
                                                "password": "password-secret"})
        for request_call in client.session.request.call_args_list[1:]:
            self.assertEqual(request_call.kwargs["headers"]["Authorization"],
                             "Bearer jwt-secret")
            self.assertNotIn("password-secret", str(request_call.kwargs["headers"]))

    def test_missing_access_token_fails_closed(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
        client.session.request = Mock(return_value=response({"refreshToken": "refresh"}))
        with self.assertRaisesRegex(ValueError, "did not contain accessToken"):
            client._request("GET", "/v1/domains")
        self.assertEqual(client.session.request.call_count, 1)

    def test_get_401_reauthenticates_once_but_put_fails_closed(self):
        client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
        unauthorized = response({})
        unauthorized.status_code = 401
        unauthorized.text = "expired"
        unauthorized.raise_for_status.side_effect = __import__("requests").HTTPError("401")
        client.session.request = Mock(side_effect=[
            response({"accessToken": "jwt-1"}), unauthorized,
            response({"accessToken": "jwt-2"}), response({"elements": []}),
        ])
        self.assertEqual(client._request("GET", "/v1/domains").status_code, 200)
        self.assertEqual(client.session.request.call_count, 4)

        client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
        client.session.request = Mock(side_effect=[response({"accessToken": "jwt"}), unauthorized])
        with self.assertRaises(Exception):
            client._request("PUT", "/v1/domains/domain/csrs", json={})
        self.assertEqual(client.session.request.call_count, 2)

    def test_secrets_are_redacted_from_api_errors(self):
        client = self.client()
        failed = response({})
        failed.status_code = 500
        failed.text = "password-secret access-secret"
        failed.raise_for_status.side_effect = __import__("requests").HTTPError("500")
        client.session.request = Mock(return_value=failed)
        with self.assertRaises(Exception) as caught:
            client._request("GET", "/v1/domains")
        self.assertNotIn("password-secret", str(caught.exception))
        self.assertNotIn("access-secret", str(caught.exception))

    def test_resolves_management_domain_and_sddc_resource(self):
        client = self.client()
        client._request = Mock(side_effect=[
            response({"elements": [{"id": "domain-1", "type": "MANAGEMENT"}]}),
            response({"elements": [{"id": "manager-1", "fqdn": "sddc.example",
                                      "domain": {"id": "domain-1"}}]}),
        ])
        domain, resource = client.resolve_context("sddc.example")
        self.assertEqual(domain, "domain-1")
        self.assertEqual(resource["resourceId"], "manager-1")
        self.assertEqual(resource["type"], "SDDC_MANAGER")

    def test_csr_payload_and_fetch_matches_available_resource_metadata(self):
        client = self.client()
        client._request = Mock(return_value=response(
            {"id": "task-1", "status": "IN_PROGRESS"}))
        resource = {"resourceId": "manager-1", "fqdn": "sddc.example",
                    "type": "SDDC_MANAGER", "sans": ["sddc.example"]}
        task, _ = client.generate_csr("domain-1", resource, {"organization": "Org"})
        self.assertEqual(task, "task-1")
        payload = client._request.call_args.kwargs["json"]
        self.assertEqual(payload["resources"], [resource])
        self.assertEqual(payload["csrGenerationSpec"]["keyAlgorithm"], "RSA")
        client._request.return_value = response({"elements": [{
            "csrEncodedContent": "-----BEGIN CERTIFICATE REQUEST-----\nWRONG\n-----END CERTIFICATE REQUEST-----",
            "resource": {"resourceId": "other", "fqdn": "sddc.example",
                         "type": "SDDC_MANAGER"}}, {
            "csrEncodedContent": "-----BEGIN CERTIFICATE REQUEST-----\nABC\n-----END CERTIFICATE REQUEST-----",
            "resource": {"fqdn": "SDDC.EXAMPLE."}}]})
        self.assertIn("BEGIN CERTIFICATE REQUEST", client.fetch_csr("domain-1", resource))

    @patch("vcf_cert_renewer.sddc_client.time.sleep")
    def test_empty_csr_after_success_is_retried_read_only(self, sleep):
        client = self.client()
        client._request = Mock(side_effect=[
            response({"elements": []}),
            response({"elements": [{
                "csrEncodedContent": "-----BEGIN CERTIFICATE REQUEST-----\nABC\n-----END CERTIFICATE REQUEST-----",
                "resource": {"resourceId": "manager-1", "fqdn": "sddc.example",
                             "type": "SDDC_MANAGER"}}]}),
        ])
        resource = {"resourceId": "manager-1", "fqdn": "sddc.example",
                    "type": "SDDC_MANAGER"}
        self.assertIn("BEGIN CERTIFICATE REQUEST", client.fetch_csr(
            "domain-1", resource, retry_interval=0, retry_timeout=1))
        self.assertEqual(client._request.call_count, 2)
        self.assertTrue(all(item.args[0] == "GET" for item in client._request.call_args_list))
        sleep.assert_called_once_with(0)

    def test_permanent_csr_absence_fails_clearly(self):
        client = self.client()
        client._request = Mock(return_value=response({"elements": []}))
        with self.assertRaisesRegex(ValueError, "task succeeded.*no matching CSR"):
            client.fetch_csr("domain-1", {
                "resourceId": "manager-1", "fqdn": "sddc.example",
                "type": "SDDC_MANAGER"}, retry_interval=0, retry_timeout=0)
        self.assertEqual(client._request.call_count, 1)

    def test_validation_and_replace_payloads(self):
        client = self.client()
        resource = {"resourceId": "manager-1", "fqdn": "sddc.example"}
        client._request = Mock(side_effect=[
            response({"validationId": "validation-1", "completed": True,
                      "validations": [{"validationStatus": "SUCCESSFUL"}]}),
            response({"id": "task-1", "status": "SUCCESSFUL"}),
        ])
        client.validate_certificate("domain-1", resource, "CHAIN", poll_interval=0)
        task, result = client.replace_certificate("domain-1", resource, "CHAIN")
        expected = [{"resourceId": "manager-1", "resourceFqdn": "sddc.example",
                     "certificateChain": "CHAIN"}]
        self.assertEqual(client._request.call_args_list[0].kwargs["json"], expected)
        self.assertEqual(client._request.call_args_list[1].kwargs["json"], expected)
        self.assertEqual((task, result["status"]), ("task-1", "SUCCESSFUL"))

    def test_validation_failure_stops(self):
        client = self.client()
        client._request = Mock(return_value=response(
            {"validationId": "bad", "completed": True,
             "validations": [{"validationStatus": "FAILED"}]}))
        with self.assertRaises(WorkflowFailedError):
            client.validate_certificate("domain", {"resourceId": "id", "fqdn": "sddc"},
                                        "CHAIN", poll_interval=0)

    def test_task_polling(self):
        client = self.client()
        client._request = Mock(side_effect=[response({"status": "IN_PROGRESS"}),
                                             response({"status": "SUCCESSFUL"})])
        self.assertEqual(client.wait_task("task", poll_interval=0)["status"], "SUCCESSFUL")
        self.assertEqual(client._request.call_args_list[-1].args,
                         ("GET", "/v1/tasks/task"))


class SddcOrchestrationTests(unittest.TestCase):
    def test_authenticated_token_domain_csr_validation_replace_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings("ops-token", "ops-url", True, 30, "ops-api",
                                output_dir=Path(directory), acme_mode="production",
                                acme_server=ACME_DIRECTORIES["production"])
            client = SddcApiClient("https://sddc.example", "svc@example", "password-secret")
            client.session.request = Mock(side_effect=[
                response({"accessToken": "jwt-secret", "refreshToken": "refresh-secret"}),
                response({"elements": [{"id": "domain", "type": "MANAGEMENT"}]}),
                response({"elements": [{"id": "manager", "fqdn": "sddc.example",
                                         "domainId": "domain"}]}),
                response({"id": "csr-task", "status": "IN_PROGRESS"}),
                response({"id": "csr-task", "status": "IN_PROGRESS"}),
                response({"id": "csr-task", "status": "SUCCESSFUL"}),
                response({"elements": [{
                    "csrEncodedContent": "-----BEGIN CERTIFICATE REQUEST-----\nABC\n-----END CERTIFICATE REQUEST-----",
                    "resource": {"resourceId": "manager", "fqdn": "sddc.example",
                                 "type": "SDDC_MANAGER"}}]}),
                response({"validationId": "validation", "completed": True,
                          "validations": [{"validationStatus": "SUCCESSFUL"}]}),
                response({"id": "replace-task", "status": "SUCCESSFUL"}),
            ])
            fullchain = Path(directory) / "sddc.example.vcf-fullchain.pem"
            fullchain.write_text("CHAIN")
            with patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": str(Path(directory) / "leaf"),
                    "issuerPath": str(Path(directory) / "issuer")}), \
                 patch("vcf_cert_renewer.renewer.build_vcf_fullchain"), \
                 patch("vcf_cert_renewer.renewer.verify_https_certificate",
                       return_value={"verified": True}):
                result = execute_sddc_renewal(client, settings, "sddc.example",
                                              poll_interval=0)
            self.assertEqual(result["result"], "RENEWED")
            calls = client.session.request.call_args_list
            self.assertEqual([(item.args[0], item.args[1].removeprefix("https://sddc.example"))
                              for item in calls], [
                ("POST", "/v1/tokens"), ("GET", "/v1/domains"),
                ("GET", "/v1/sddc-managers"), ("PUT", "/v1/domains/domain/csrs"),
                ("GET", "/v1/tasks/csr-task"), ("GET", "/v1/tasks/csr-task"),
                ("GET", "/v1/domains/domain/csrs"),
                ("PUT", "/v1/domains/domain/resource-certificates/validations"),
                ("PUT", "/v1/domains/domain/resource-certificates")])
            for request_call in calls[1:]:
                self.assertEqual(request_call.kwargs["headers"]["Authorization"],
                                 "Bearer jwt-secret")

    def test_full_flow_reuses_signer_builder_and_https_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings("token", "url", True, 30, "api",
                                output_dir=Path(directory),
                                acme_mode="production",
                                acme_server=ACME_DIRECTORIES["production"])
            client = Mock()
            resource = {"resourceId": "manager", "fqdn": "sddc.example",
                        "type": "SDDC_MANAGER", "sans": ["sddc.example"]}
            client.resolve_context.return_value = ("domain", resource)
            client.generate_csr.return_value = ("csr-task", {"status": "SUCCESSFUL"})
            client.wait_task.return_value = {"status": "SUCCESSFUL"}
            client.fetch_csr.return_value = "CSR"
            client.validate_certificate.return_value = {"validationId": "validation"}
            client.replace_certificate.return_value = ("replace-task", {"status": "SUCCESSFUL"})
            leaf, issuer = Path(directory) / "leaf", Path(directory) / "issuer"
            fullchain = Path(directory) / "sddc.example.vcf-fullchain.pem"
            fullchain.write_text("CHAIN")
            with patch("vcf_cert_renewer.renewer.sign_csr", return_value={
                    "leafPath": str(leaf), "issuerPath": str(issuer)}), \
                 patch("vcf_cert_renewer.renewer.build_vcf_fullchain"), \
                 patch("vcf_cert_renewer.renewer.verify_https_certificate",
                       return_value={"verified": True}) as verify:
                result = execute_sddc_renewal(client, settings, "sddc.example")
            self.assertEqual(result["result"], "RENEWED")
            client.wait_task.assert_called_once_with(
                "csr-task", poll_interval=2, poll_timeout=900)
            client.generate_csr.assert_called_once()
            client.validate_certificate.assert_called_once()
            client.replace_certificate.assert_called_once()
            verify.assert_called_once_with("sddc.example", b"CHAIN")

    def test_csr_task_failure_stops_before_signing_validation_and_replace(self):
        settings = Settings("token", "url", True, 30, "api")
        client = Mock()
        client.resolve_context.return_value = ("domain", {
            "resourceId": "manager", "fqdn": "sddc.example",
            "type": "SDDC_MANAGER", "sans": ["sddc.example"]})
        client.generate_csr.return_value = ("csr-task", {"status": "IN_PROGRESS"})
        client.wait_task.side_effect = WorkflowFailedError("failed")
        with patch("vcf_cert_renewer.renewer.sign_csr") as sign:
            with self.assertRaises(WorkflowFailedError):
                execute_sddc_renewal(client, settings, "sddc.example")
        client.generate_csr.assert_called_once()
        client.fetch_csr.assert_not_called()
        sign.assert_not_called()
        client.validate_certificate.assert_not_called()
        client.replace_certificate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
