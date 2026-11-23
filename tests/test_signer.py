import os
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vcf_cert_renewer.config import ACME_DIRECTORIES, Settings
from vcf_cert_renewer.signer import lego_command


class SignerTests(unittest.TestCase):
    def settings(self, mode="staging"):
        return Settings(
            "token", "url", True, 30, "api", acme_mode=mode,
            acme_server=ACME_DIRECTORIES[mode], acme_email="unit@localhost",
            dns_nameserver="192.0.2.53:53", dns_tsig_key="key",
            dns_tsig_secret="top-secret", lego_path=Path("/usr/bin/lego"),
            output_dir=Path("/var/lib/vcf"))

    def test_command_is_noninteractive_and_uses_stable_account_path(self):
        command, environment = lego_command(self.settings(), Path("/tmp/request.pem"))
        self.assertIn("--accept-tos", command)
        self.assertEqual(command.count("--ari-disable"), 1)
        self.assertIn("/var/lib/vcf/acme/staging", command)
        self.assertEqual(command[:2], ["/usr/bin/lego", "run"])
        self.assertEqual(command[-2:], ["--csr", "/tmp/request.pem"])
        self.assertEqual(command.count("--dns.resolvers"), 2)
        self.assertEqual(environment["DNSUPDATE_TSIG_SECRET"], "top-secret")
        self.assertNotIn("top-secret", " ".join(command))

    def test_provider_selection_preserves_tsig_environment(self):
        for provider in ("rfc2136", "dnsupdate"):
            with self.subTest(provider=provider):
                command, env = lego_command(
                    replace(self.settings(), dns_provider=provider), Path("target.csr"))
                self.assertEqual(command[command.index("--dns") + 1], provider)
                self.assertEqual(env["DNSUPDATE_TSIG_SECRET"], "top-secret")
                self.assertNotIn("top-secret", command)
        with self.assertRaisesRegex(ValueError, "DNS_PROVIDER"):
            lego_command(replace(self.settings(), dns_provider="unsupported"), Path("target.csr"))
        with self.assertRaisesRegex(ValueError, "DNSUPDATE_TSIG_KEY"):
            lego_command(replace(self.settings(), dns_tsig_key="   "), Path("target.csr"))

    def test_provider_probe_fails_closed_and_uses_no_credentials(self):
        from subprocess import CompletedProcess, TimeoutExpired
        from vcf_cert_renewer.signer import verify_lego_provider

        settings = replace(self.settings(), dns_provider="dnsupdate")
        with patch.dict(os.environ, {"PATH": "/usr/local/bin:/usr/bin", "SECRET": "fixture"}), patch(
                "vcf_cert_renewer.signer.subprocess.run") as run:
            run.return_value = CompletedProcess([], 0)
            verify_lego_provider(settings)
            self.assertEqual(run.call_args.args[0], ["/usr/bin/lego", "dnshelp", "-c", "dnsupdate"])
            self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/local/bin:/usr/bin"})
            self.assertEqual(run.call_args.kwargs["timeout"], 10)
            run.return_value = CompletedProcess([], 1, stderr=b"secret")
            with self.assertRaisesRegex(ValueError, "^Installed lego does not support"):
                verify_lego_provider(settings)
            run.side_effect = TimeoutExpired([], 10)
            with self.assertRaisesRegex(ValueError, "^Could not check"):
                verify_lego_provider(settings)

    def test_staging_and_production_servers_are_forwarded(self):
        staging, _ = lego_command(self.settings("staging"), Path("a.csr"))
        production, _ = lego_command(self.settings("production"), Path("a.csr"))
        self.assertIn(ACME_DIRECTORIES["staging"], staging)
        self.assertIn(ACME_DIRECTORIES["production"], production)

    def test_missing_secret_names_variable_without_disclosing_values(self):
        settings = self.settings()
        settings = Settings(**{**settings.__dict__, "dns_tsig_secret": None})
        with self.assertRaisesRegex(ValueError, "DNSUPDATE_TSIG_SECRET"):
            lego_command(settings, Path("a.csr"))

    def test_signer_accepts_valid_email_and_private_nameserver(self):
        settings = self.settings()
        settings = Settings(**{**settings.__dict__,
                              "acme_email": "unit@localhost",
                              "dns_nameserver": "dns01.home.arpa:53"})
        command, _ = lego_command(settings, Path("target.csr"))
        self.assertIn("--email", command)

    def test_signer_rejects_example_email(self):
        for email in ("admin@example.invalid", "admin@example.com", "admin@lab.test"):
            settings = Settings(**{**self.settings().__dict__, "acme_email": email})
            with self.subTest(email=email), self.assertRaisesRegex(
                    ValueError, "ACME_EMAIL contains an example/placeholder"):
                lego_command(settings, Path("target.csr"))

    def test_signer_rejects_example_nameserver_but_accepts_private_ip(self):
        for nameserver in ("ns1.example.invalid:53", "resolver.lab.test", "dns.example.org"):
            settings = Settings(**{**self.settings().__dict__, "dns_nameserver": nameserver})
            with self.subTest(nameserver=nameserver), self.assertRaisesRegex(
                    ValueError, "DNSUPDATE_NAMESERVER contains an example/placeholder"):
                lego_command(settings, Path("target.csr"))
        settings = Settings(**{**self.settings().__dict__, "dns_nameserver": "192.0.2.53:53:53"})
        lego_command(settings, Path("target.csr"))

    def test_lego_failure_suppresses_output_and_preserves_category(self):
        import subprocess
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from vcf_cert_renewer.signer import sign_csr

        settings = self.settings()
        settings = Settings(**{**settings.__dict__, "acme_email": "unit@localhost",
                               "dns_tsig_secret": "tsig-sensitive",
                               "acme_eab_kid": "kid-sensitive",
                               "acme_eab_hmac": "hmac-sensitive"})
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "vcfa.example.test")]))
            .sign(private, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.csr"
            path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
            settings = Settings(**{**settings.__dict__, "output_dir": Path(directory) / "output"})
            error = subprocess.CalledProcessError(
                7, ["lego"], output="acme: error: 400 :: urn:ietf:params:acme:error:accountDoesNotExist :: tsig-sensitive",
                stderr="DNS failure: hmac-sensitive\nNS1 resolution failed")
            from vcf_cert_renewer.diagnostics import safe_exception_message
            for failure, category in (
                (error, "ACME_ACCOUNT_ERROR"),
                (subprocess.CalledProcessError(7, ["lego"], stderr=
                    '"rfc2136" is not yet supported; unknown credential=secret-value'),
                 "DNS_PROVIDER_CONFIGURATION"),
                (subprocess.CalledProcessError(7, ["lego"], stderr=
                    "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: secret-value"), "ACME_RATE_LIMIT"),
                *(
                    (subprocess.CalledProcessError(7, ["lego"], stderr=message + " secret-value"), category)
                    for message, category in (
                        ("authorization failed: dnsupdate: failed to insert: DNS update failed: REFUSED",
                         "DNS_UPDATE_FAILURE"),
                        ("authorization failed: propagation: time limit exceeded", "DNS_PROPAGATION_FAILURE"),
                        ("acme: error: 403 :: urn:ietf:params:acme:error:unauthorized ::", "ACME_AUTHORIZATION_FAILURE"),
                        ("acme: error: 400 :: urn:ietf:params:acme:error:badCSR ::", "CSR_VALIDATION_ERROR"),
                        ("Post: tls: failed to verify certificate: x509: certificate signed by unknown authority",
                         "NETWORK_TLS_ERROR"),
                    )
                ),
                (subprocess.CalledProcessError(7, ["lego"], stderr=
                    "unrecognized output secret-value"), "UNKNOWN_ACME_ERROR"),
            ):
                with self.subTest(category=category), patch(
                        "vcf_cert_renewer.signer.verify_lego_provider"), patch(
                        "vcf_cert_renewer.signer.subprocess.run", side_effect=failure):
                    with self.assertRaisesRegex(ValueError, "exit status 7") as caught:
                        sign_csr(settings, path)
                self.assertEqual(caught.exception.category, category)
                self.assertEqual(caught.exception.exit_status, 7)
                for secret in ("secret-value", "tsig-sensitive", "hmac-sensitive"):
                    self.assertNotIn(secret, str(caught.exception))
                    self.assertNotIn(secret, safe_exception_message(caught.exception))

    def test_acme_evidence_is_structural_and_conflicts_fail_closed(self):
        from subprocess import CalledProcessError
        from vcf_cert_renewer.signer import _classify_lego_failure
        from vcf_cert_renewer.diagnostics import safe_exception_message

        def problem(path, code="unauthorized", host="acme-v02.api.letsencrypt.org"):
            return (f"CSR: could not obtain certificate: acme: error: 403 :: POST :: "
                    f"https://{host}{path} :: urn:ietf:params:acme:error:{code} :: "
                    "credential=fixture-password account=https://ca.invalid/acct/fixture-account "
                    "challenge=fixture-challenge")

        for path, operation in (
            ("/acme/new-order", "NEW_ORDER"),
            ("/acme/authz-v3/123", "AUTHORIZATION"),
            ("/acme/chall-v3/123/fixture-challenge", "CHALLENGE"),
            ("/acme/finalize/123/456", "FINALIZE"),
            ("/acme/order/123/456", None),
        ):
            with self.subTest(operation=operation):
                e = _classify_lego_failure(CalledProcessError(1, ["lego"], stderr=problem(path)))
                self.assertEqual((e.category, e.problem, e.operation),
                                 ("ACME_AUTHORIZATION_FAILURE", "unauthorized", operation))
                self.assertEqual(e.exit_status, 1)
                for candidate in (str(e), safe_exception_message(e)):
                    for secret in ("fixture-password", "fixture-account", "fixture-challenge", "https://"):
                        self.assertNotIn(secret, candidate)

        custom = _classify_lego_failure(CalledProcessError(
            1, ["lego"], stderr=problem("/acme/new-order", host="other.invalid")))
        self.assertEqual((custom.problem, custom.operation), ("unauthorized", None))
        for stream in (
            "authorization failed",
            "quoted detail urn:ietf:params:acme:error:unauthorized",
            problem("/acme/new-order", code="unknownCode"),
            problem("/acme/new-order") + "\nDNS update failed: REFUSED",
            problem("/acme/new-order") + "\n" + problem("/acme/authz-v3/123"),
            problem("/acme/new-order") + "\n" + problem("/acme/new-order", code="badCSR"),
            "DNS update failed: REFUSED\npropagation: time limit exceeded",
        ):
            with self.subTest(stream=stream):
                e = _classify_lego_failure(CalledProcessError(1, ["lego"], stderr=stream))
                self.assertEqual((e.category, e.problem, e.operation),
                                 ("UNKNOWN_ACME_ERROR", None, None))


if __name__ == "__main__":
    unittest.main()
