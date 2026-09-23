"""Offline Docker runtime checks. Never executes plan, CSR or renewal APIs."""
import json
import subprocess
import sys

image = sys.argv[1] if len(sys.argv) > 1 else 'vcf-cert-renewer:1.3.0'
def docker(*args):
    return subprocess.check_output(['docker', *args], text=True)
def run(*args):
    return docker('run', '--rm', '--network', 'none', '--read-only',
                  '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', *args)
assert '1.3.0' in run(image, '--version')
assert 'renew' in run(image, '--help')
assert '5.4.1' in run('--entrypoint', 'lego', image, '--version')
assert '3.12.12' in run('--entrypoint', 'python', image, '--version')
config = json.loads(docker('image', 'inspect', image))[0]['Config']
assert config['User'] == '10001:10001'
assert config['Entrypoint'] == ['/usr/local/bin/vcf-cert-renewer']
assert all(not item.startswith(('VCF_API_TOKEN=', 'SDDC_PASSWORD=', 'ACME_EAB_HMAC=',
                                 'DNSUPDATE_TSIG_SECRET=', 'VCF_CLIENT_SECRET='))
           for item in config['Env'])
code = r"""
import os
from pathlib import Path
from vcf_cert_renewer.config import Settings, ConfigurationError
assert os.getuid() == 10001
assert Path('/etc/ssl/certs/ca-certificates.crt').stat().st_size > 0
p = Path('/tmp/secret'); p.write_text('dummy-runtime-value\n'); p.chmod(0o600)
s = Settings.load(environ={'VCF_API_TOKEN_FILE': str(p)})
assert s.api_token == 'dummy-runtime-value'
assert 'dummy-runtime-value' not in repr(s)
p.chmod(0)
try:
    Settings.load(environ={'VCF_API_TOKEN_FILE': str(p)})
except ConfigurationError:
    pass
else:
    raise AssertionError('Unreadable file accepted')
assert not any(Path('/app').rglob('.git'))
assert not any(Path('/app').rglob('.env'))
assert not any(Path('/app').rglob('*.key'))
print('Offline non-root configuration smoke passed')
"""
print(run('--entrypoint', 'python', image, '-c', code).strip())
print('Image version/help, Python, lego, CA trust, UID and environment checks passed')
