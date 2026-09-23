"""Offline protocol/configuration regressions; no live issuance."""
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from vcf_cert_renewer.config import ACME_DIRECTORIES, ConfigurationError, Settings
from vcf_cert_renewer.signer import lego_command, sign_csr


class AcmeTests(unittest.TestCase):
    def load(self, **env):
        return Settings.load(config_path=Path('/missing'), secrets_path=Path('/missing'), environ=env)

    def signer(self, **env):
        return replace(self.load(**env), acme_email='admin@example.com',
                       dns_nameserver='192.0.2.53:53', dns_tsig_key='example-key',
                       dns_tsig_secret='test-tsig')

    def test_explicit_server_overrides_mode(self):
        for mode in ('staging', 'production', 'ignored'):
            s = self.load(ACME_MODE=mode, ACME_SERVER='https://acme.example.com/directory')
            self.assertEqual(s.acme_server, 'https://acme.example.com/directory')
            self.assertEqual(s.acme_mode, 'custom')

    def test_legacy_production(self):
        self.assertEqual(self.load(ACME_MODE='production').acme_server, ACME_DIRECTORIES['production'])

    def test_legacy_staging(self):
        self.assertEqual(self.load(ACME_MODE='staging').acme_server, ACME_DIRECTORIES['staging'])

    def test_default_and_empty_server_preserve_staging(self):
        self.assertEqual(self.load().acme_server, ACME_DIRECTORIES['staging'])
        self.assertEqual(self.load(ACME_SERVER='').acme_server, ACME_DIRECTORIES['staging'])

    @patch.dict('os.environ', {'LEGO_EAB': 'true', 'LEGO_EAB_HMAC': 'test-inherited', 'LEGO_EAB_KID': 'test-kid'})
    def test_eab_disabled_and_inherited_credentials_removed(self):
        cmd, env = lego_command(self.signer(), Path('example.csr'))
        self.assertNotIn('--eab', cmd)
        for name in ('LEGO_EAB', 'LEGO_EAB_KID', 'LEGO_EAB_HMAC'):
            self.assertNotIn(name, env)

    def test_eab_enabled_environment_only(self):
        s = self.signer(ACME_EAB_KID='test-kid', ACME_EAB_HMAC='test-hmac')
        cmd, env = lego_command(s, Path('example.csr'))
        self.assertIn('--eab', cmd)
        self.assertEqual(env['LEGO_EAB_KID'], 'test-kid')
        self.assertEqual(env['LEGO_EAB_HMAC'], 'test-hmac')
        for secret in ('test-kid', 'test-hmac'):
            self.assertNotIn(secret, repr(s))
            self.assertNotIn(secret, repr(cmd))

    def test_kid_only_fails_without_value(self):
        with self.assertRaisesRegex(ConfigurationError, 'must both be set') as caught:
            self.load(ACME_EAB_KID='test-hidden')
        self.assertNotIn('test-hidden', str(caught.exception))

    def test_hmac_only_fails_without_value(self):
        with self.assertRaisesRegex(ConfigurationError, 'must both be set') as caught:
            self.load(ACME_EAB_HMAC='test-hidden')
        self.assertNotIn('test-hidden', str(caught.exception))

    def test_whitespace_pair_is_disabled(self):
        s = self.load(ACME_EAB_KID=' ', ACME_EAB_HMAC=' ')
        self.assertIsNone(s.acme_eab_hmac)
        self.assertIsNone(s.acme_eab_kid)

    def test_lego_passes_custom_directory(self):
        cmd, _ = lego_command(self.signer(ACME_SERVER='https://acme.example.com/directory'), Path('example.csr'))
        self.assertEqual(cmd[cmd.index('--server')+1], 'https://acme.example.com/directory')

    def test_eab_secrets_file_and_env_precedence(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/'secrets.env'
            p.write_text('ACME_EAB_KID="test-kid"\nACME_EAB_HMAC="test-file"\n')
            s = Settings.load(config_path=Path('/missing'), secrets_path=p, environ={'ACME_EAB_HMAC': 'test-env'})
            self.assertEqual(s.acme_eab_kid, 'test-kid')
            self.assertEqual(s.acme_eab_hmac, 'test-env')

    def test_tsig_alias_preserves_original_precedence(self):
        self.assertEqual(self.load(DNSUPDATE_TSIG_KEY_NAME='alias').dns_tsig_key, 'alias')
        self.assertEqual(self.load(DNSUPDATE_TSIG_KEY_NAME='alias', DNSUPDATE_TSIG_KEY='original').dns_tsig_key, 'original')

    def test_subprocess_failure_suppresses_credentials(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'ops.example.com')])).sign(key, hashes.SHA256())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'example.csr'
            path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
            s = replace(self.signer(ACME_EAB_KID='test-kid', ACME_EAB_HMAC='test-hmac'), output_dir=Path(folder))
            error = subprocess.CalledProcessError(1, ['lego'], output='test-hmac', stderr='test-kid')
            with patch('vcf_cert_renewer.signer.subprocess.run', side_effect=error), self.assertRaises(ValueError) as caught:
                sign_csr(s, path)
            self.assertNotIn('test-hmac', str(caught.exception))
            self.assertNotIn('test-kid', str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
