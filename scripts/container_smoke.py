"""Offline Docker runtime checks. Never executes plan, CSR or renewal APIs."""
import json
import subprocess
import sys

image = sys.argv[1] if len(sys.argv) > 1 else 'vcf-cert-renewer:1.3.1'
def docker(*args):
    return subprocess.check_output(['docker', *args], text=True)
def run(*args):
    return docker('run', '--rm', '--network', 'none', '--read-only',
                  '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', *args)
assert '1.3.1' in run(image, '--version')
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

# Model Kubernetes root-owned, group-readable Secret files. Fixtures contain only
# dummy values; the workload still runs as the image's non-root UID/GID.
import uuid
volume = "vcf-secret-smoke-" + uuid.uuid4().hex
docker('volume', 'create', volume)
try:
    fixture = r"""
import os
from pathlib import Path
root = Path('/fixtures')
for name in ('vcf_api_token', 'sddc_password', 'dns_tsig_secret', 'acme_eab_hmac'):
    p = root / name
    p.write_text('dummy-mounted-value\n')
    p.chmod(0o440)
"""
    run('--user', '0:10001', '--mount', f'type=volume,src={volume},dst=/fixtures',
        '--entrypoint', 'python', image, '-c', fixture)
    mounted = r"""
import os
from pathlib import Path
from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.cli import _write_csr
os.umask(0o077)
s = Settings.load()
assert os.getuid() == os.getgid() == 10001
assert all(v == 'dummy-mounted-value' for v in
           (s.api_token, s.sddc_password, s.dns_tsig_secret, s.acme_eab_hmac))
assert s.acme_eab_kid == 'example-kid'
assert not any(k in os.environ for k in
               ('VCF_API_TOKEN', 'SDDC_PASSWORD', 'DNSUPDATE_TSIG_SECRET', 'ACME_EAB_HMAC'))
assert 'dummy-mounted-value' not in repr(s)
for folder in ('/app', '/run/secrets'):
    try:
        Path(folder, 'must-not-write').write_text('dummy')
    except OSError:
        pass
    else:
        raise AssertionError('Protected mount was writable')
assert _write_csr(s.output_dir / 'test', 'test.example.com', 'dummy-csr').is_file()
account = s.output_dir / 'acme' / 'staging' / 'accounts'
account.mkdir(parents=True)
(account / 'dummy-state').write_text('dummy')
Path('/tmp/runtime-check').write_text('dummy')
print('Read-only root, mounted secrets/EAB, writable data/account/temp paths passed')
"""
    print(run('--mount', f'type=volume,src={volume},dst=/run/secrets,readonly',
              '--tmpfs', '/data:rw,nosuid,uid=10001,gid=10001,mode=0700',
              '-e', 'VCF_API_TOKEN_FILE=/run/secrets/vcf_api_token',
              '-e', 'SDDC_PASSWORD_FILE=/run/secrets/sddc_password',
              '-e', 'DNSUPDATE_TSIG_SECRET_FILE=/run/secrets/dns_tsig_secret',
              '-e', 'ACME_EAB_KID=example-kid',
              '-e', 'ACME_EAB_HMAC_FILE=/run/secrets/acme_eab_hmac',
              '--entrypoint', 'python', image, '-c', mounted).strip())
finally:
    docker('volume', 'rm', volume)
