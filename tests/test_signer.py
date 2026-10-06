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
        self.assertIn("/var/lib/vcf/acme/staging", command)
        self.assertEqual(command[:2], ["/usr/bin/lego", "run"])
        self.assertEqual(command[-2:], ["--csr", "/tmp/request.pem"])
        self.assertEqual(command.count("--dns.resolvers"), 2)
        self.assertEqual(environment["DNSUPDATE_TSIG_SECRET"], "top-secret")
        self.assertNotIn("top-secret", " ".join(command))

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

    def test_lego_failure_surfaces_sanitized_details_and_account_hint(self):
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
                7, ["lego"], output="accountDoesNotExist :: tsig-sensitive",
                stderr="DNS failure: hmac-sensitive\nNS1 resolution failed")
            with patch("vcf_cert_renewer.signer.subprocess.run", side_effect=error):
                with self.assertRaisesRegex(ValueError, "exit status 7") as caught:
                    sign_csr(settings, path)
        message = str(caught.exception)
        self.assertIn("accountDoesNotExist", message)
        self.assertIn("DNS failure", message)
        self.assertIn("Verify the configured ACME account state", message)
        self.assertNotIn("tsig-sensitive", message)
        for secret in ("hmac-sensitive", "kid-sensitive", "token-sensitive",
                       "password-sensitive", "client-sensitive", "private-material"):
            self.assertNotIn(secret, message)
        self.assertIn("[REDACTED]", message)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", message)

if __name__ == "__main__":
    unittest.main()
