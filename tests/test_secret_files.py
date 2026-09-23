"""Mounted-secret regressions using only synthetic credentials."""
import os
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from vcf_cert_renewer.config import ConfigurationError, Settings, SECRET_ENV_NAMES
from vcf_cert_renewer.signer import lego_command

FIELDS = {
    "VCF_API_TOKEN": "api_token", "SDDC_USERNAME": "sddc_username",
    "SDDC_PASSWORD": "sddc_password", "VCF_CLIENT_ID": "client_id",
    "VCF_CLIENT_SECRET": "client_secret", "DNSUPDATE_TSIG_SECRET": "dns_tsig_secret",
    "ACME_EAB_KID": "acme_eab_kid", "ACME_EAB_HMAC": "acme_eab_hmac",
}

def load(env, **kw):
    return Settings.load(config_path=Path('/missing-test-config'),
                         secrets_path=kw.pop('secrets_path', Path('/missing-test-secrets')),
                         environ=env, **kw)

def paired(env, name):
    env = dict(env)
    if name == 'ACME_EAB_KID':
        env['ACME_EAB_HMAC'] = 'dummy-hmac'
    elif name == 'ACME_EAB_HMAC':
        env['ACME_EAB_KID'] = 'dummy-kid'
    return env

def test_all_secret_fields_covered():
    assert set(FIELDS) == SECRET_ENV_NAMES

@pytest.mark.parametrize('name', FIELDS)
def test_direct_compatibility(name):
    settings = load(paired({name: 'dummy-value'}, name))
    assert getattr(settings, FIELDS[name]) == 'dummy-value'
    assert 'dummy-value' not in repr(settings)

@pytest.mark.parametrize('name', FIELDS)
@pytest.mark.parametrize('ending', ['', '\n', '\n\n', '\r\n', '\r\n\n'])
def test_mounted_secret_preserves_contents(tmp_path, name, ending):
    p = tmp_path / 'credential'
    value = '  dummy\r\ninterior\r value\t '
    p.write_bytes((value + ending).encode())
    settings = load(paired({name + '_FILE': str(p)}, name))
    assert getattr(settings, FIELDS[name]) == value
    assert value not in repr(settings)
    assert name not in os.environ

@pytest.mark.parametrize('name', FIELDS)
@pytest.mark.parametrize('direct', ['', 'dummy-value'])
def test_conflict_even_if_empty(tmp_path, name, direct):
    with pytest.raises(ConfigurationError, match='Set only one') as caught:
        load(paired({name: direct, name + '_FILE': str(tmp_path/'dummy-hidden')}, name))
    assert 'dummy-hidden' not in str(caught.value)
    assert 'dummy-value' not in str(caught.value)

@pytest.mark.parametrize('name', FIELDS)
@pytest.mark.parametrize('kind', ['missing', 'directory', 'empty', 'newline', 'invalid_utf8', 'unreadable', 'empty_path'])
def test_invalid_files_safe(tmp_path, name, kind):
    p = tmp_path/'dummy-hidden'
    if kind == 'directory': p.mkdir()
    elif kind not in ('missing', 'empty_path'):
        p.write_bytes({'empty': b'', 'newline': b'\r\n\n', 'invalid_utf8': b'\xff'}.get(kind, b'dummy-hidden'))
    env = paired({name + '_FILE': '' if kind == 'empty_path' else str(p)}, name)
    if kind == 'unreadable':
        with patch.object(Path, 'read_bytes', side_effect=PermissionError('dummy-hidden')):
            with pytest.raises(ConfigurationError) as caught: load(env)
    else:
        with pytest.raises(ConfigurationError) as caught: load(env)
    assert name + '_FILE' in str(caught.value)
    assert 'dummy-hidden' not in str(caught.value)
    assert caught.value.__suppress_context__ or kind in ('empty', 'newline')

def test_file_reference_in_legacy_secrets_file(tmp_path):
    p = tmp_path/'value'; p.write_text('dummy-value\n')
    env = tmp_path/'secrets.env'; env.write_text(f'VCF_API_TOKEN_FILE={p}\n')
    assert load({}, secrets_path=env).api_token == 'dummy-value'
    with pytest.raises(ConfigurationError, match='Set only one'):
        load({'VCF_API_TOKEN': 'dummy-other'}, secrets_path=env)

def test_signer_file_credentials_and_no_unrelated_inheritance(tmp_path):
    env = {}
    for name in ('ACME_EAB_KID', 'ACME_EAB_HMAC', 'DNSUPDATE_TSIG_SECRET'):
        p = tmp_path/name; p.write_text('dummy-' + name + '\n')
        env[name + '_FILE'] = str(p)
    s = replace(load(env), acme_email='admin@example.com',
                dns_nameserver='192.0.2.53:53', dns_tsig_key='example-key')
    with patch.dict(os.environ, {'SDDC_PASSWORD': 'dummy-unrelated', 'VCF_API_TOKEN': 'dummy-token'}):
        cmd, child = lego_command(s, tmp_path/'example.csr')
    assert child['LEGO_EAB_HMAC'] == 'dummy-ACME_EAB_HMAC'
    assert child['DNSUPDATE_TSIG_SECRET'] == 'dummy-DNSUPDATE_TSIG_SECRET'
    assert 'SDDC_PASSWORD' not in child and 'VCF_API_TOKEN' not in child
    assert 'dummy-' not in repr(cmd)
    assert 'dummy-' not in repr(s)

def test_single_cr_is_preserved(tmp_path):
    p = tmp_path/'value'; p.write_bytes(b'dummy-value\r')
    assert load({'VCF_API_TOKEN_FILE': str(p)}).api_token == 'dummy-value\r'


def test_file_read_each_load_for_rotation(tmp_path):
    p = tmp_path/'value'; p.write_text('dummy-first')
    env = {'VCF_API_TOKEN_FILE': str(p)}
    assert load(env).api_token == 'dummy-first'
    p.write_text('dummy-second')
    assert load(env).api_token == 'dummy-second'


def test_file_signing_failure_suppresses_all_secrets(tmp_path, caplog):
    import subprocess
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from vcf_cert_renewer.signer import sign_csr
    values = {}
    for name in ('ACME_EAB_KID', 'ACME_EAB_HMAC', 'DNSUPDATE_TSIG_SECRET'):
        p = tmp_path/name; p.write_text('dummy-hidden-' + name)
        values[name + '_FILE'] = str(p)
    settings = replace(load(values), acme_email='admin@example.com',
                       dns_nameserver='192.0.2.53:53', dns_tsig_key='example-key',
                       output_dir=tmp_path/'output')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, 'ops.example.com')])).sign(key, hashes.SHA256())
    path = tmp_path/'example.csr'; path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    error = subprocess.CalledProcessError(1, ['lego'], output='dummy-hidden-ACME_EAB_HMAC',
                                          stderr='dummy-hidden-DNSUPDATE_TSIG_SECRET')
    with patch('vcf_cert_renewer.signer.subprocess.run', side_effect=error), pytest.raises(ValueError) as caught:
        sign_csr(settings, path)
    assert 'dummy-hidden' not in str(caught.value)
    assert 'dummy-hidden' not in caplog.text
    assert caught.value.__suppress_context__


def test_inherited_lego_eab_files_cannot_enable_credentials(tmp_path):
    s = replace(load({}), acme_email='admin@example.com',
                dns_nameserver='192.0.2.53:53', dns_tsig_key='example-key',
                dns_tsig_secret='dummy-tsig')
    with patch.dict(os.environ, {'LEGO_EAB_KID_FILE': '/dummy-kid', 'LEGO_EAB_HMAC_FILE': '/dummy-hmac'}):
        cmd, child = lego_command(s, tmp_path/'example.csr')
    assert '--eab' not in cmd
    assert 'LEGO_EAB_KID_FILE' not in child
    assert 'LEGO_EAB_HMAC_FILE' not in child
