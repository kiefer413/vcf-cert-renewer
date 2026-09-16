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
            acme_server=ACME_DIRECTORIES[mode], acme_email="admin@example.com",
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


if __name__ == "__main__":
    unittest.main()
