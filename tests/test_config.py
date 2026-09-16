import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from vcf_cert_renewer.config import ACME_DIRECTORIES, ConfigurationError, Settings


class SettingsTests(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_safe_defaults_use_staging(self):
        settings = Settings.from_env()
        self.assertEqual(settings.acme_mode, "staging")
        self.assertEqual(settings.acme_server, ACME_DIRECTORIES["staging"])
        self.assertEqual(str(settings.output_dir), "out")

    @patch.dict("os.environ", {
        "VCF_URL": "https://ops.example/",
        "VCF_TOKEN_ENDPOINT": "https://id.example/token/",
        "VCF_VERIFY_TLS": "true", "ACME_MODE": "production",
        "OUTPUT_DIR": "/var/tmp/certs", "DNSUPDATE_TSIG_SECRET": "secret",
    }, clear=True)
    def test_parses_canonical_names(self):
        settings = Settings.from_env()
        self.assertEqual(settings.base_url, "https://ops.example")
        self.assertEqual(settings.token_url, "https://id.example/token")
        self.assertTrue(settings.verify_tls)
        self.assertEqual(settings.acme_server, ACME_DIRECTORIES["production"])
        self.assertEqual(settings.dns_tsig_secret, "secret")

    @patch.dict("os.environ", {"ACME_MODE": "danger"}, clear=True)
    def test_rejects_unknown_mode(self):
        with self.assertRaises(ConfigurationError):
            Settings.from_env()

    def test_parses_exact_four_public_targets(self):
        settings = Settings.load(
            config_path=Path("/missing"), secrets_path=Path("/missing"),
            environ={"VCF_RENEW_TARGETS": "ops.example,sddc.example,vc.example,nsx.example"})
        self.assertEqual(settings.renewal_targets,
                         ("ops.example", "sddc.example", "vc.example", "nsx.example"))

    def test_rejects_incomplete_public_targets(self):
        with self.assertRaisesRegex(ConfigurationError, "exactly four"):
            Settings.load(
                config_path=Path("/missing"), secrets_path=Path("/missing"),
                environ={"VCF_RENEW_TARGETS": "ops.example,sddc.example"})

    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example", "SDDC_PASSWORD": "pw"}, clear=True)
    def test_sddc_credentials(self):
        self.assertEqual(Settings.from_env().require_sddc_credentials(), ("svc@example", "pw"))

    @patch.dict("os.environ", {"SDDC_USERNAME": "svc@example"}, clear=True)
    def test_missing_sddc_credentials_names_only(self):
        with self.assertRaisesRegex(ConfigurationError, "SDDC_PASSWORD") as caught:
            Settings.from_env().require_sddc_credentials()
        self.assertNotIn("svc@example", str(caught.exception))

    def test_precedence_override_env_secrets_yaml_defaults(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            secrets = root / "secrets.env"
            config.write_text(
                "renew:\n  threshold_days: 10\nvcf:\n  url: https://yaml.example\n",
                encoding="utf-8")
            secrets.write_text("VCF_API_TOKEN=file-token\n", encoding="utf-8")
            settings = Settings.load(
                config_path=config, secrets_path=secrets,
                environ={"VCF_URL": "https://env.example",
                         "VCF_API_TOKEN": "env-token",
                         "RENEW_BEFORE_DAYS": "20"},
                overrides={"RENEW_BEFORE_DAYS": 25})
            self.assertEqual(settings.base_url, "https://env.example")
            self.assertEqual(settings.api_token, "env-token")
            self.assertEqual(settings.renew_before_days, 25)
            self.assertEqual(settings.dns_provider, "rfc2136")

    def test_secrets_file_overrides_yaml_layer(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets.env"
            secrets.write_text("VCF_API_TOKEN=file-token\n", encoding="utf-8")
            settings = Settings.load(
                config_path=root / "missing.yaml", secrets_path=secrets,
                environ={})
            self.assertEqual(settings.api_token, "file-token")

    def test_malformed_yaml_fails_clearly(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text("vcf: [broken", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "Unable to load"):
                Settings.load(config_path=config,
                              secrets_path=Path(directory) / "missing", environ={})

    def test_missing_optional_files_are_allowed(self):
        settings = Settings.load(
            config_path=Path("/definitely/missing/config"),
            secrets_path=Path("/definitely/missing/secrets"), environ={})
        self.assertEqual(settings.renew_before_days, 30)

    def test_secret_values_never_appear_in_errors(self):
        secret = "never-print-this-secret"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text(f"NOT_ALLOWED={secret}\n", encoding="utf-8")
            with self.assertRaises(ConfigurationError) as caught:
                Settings.load(secrets_path=path, environ={})
            self.assertNotIn(secret, str(caught.exception))

    def test_environment_backwards_compatibility(self):
        settings = Settings.load(
            config_path=Path("/missing"), secrets_path=Path("/missing"),
            environ={"VCF_BASE_URL": "https://legacy.example/",
                     "VCF_TOKEN_URL": "https://legacy.example/token/"})
        self.assertEqual(settings.base_url, "https://legacy.example")
        self.assertEqual(settings.token_url, "https://legacy.example/token")


if __name__ == "__main__":
    unittest.main()
