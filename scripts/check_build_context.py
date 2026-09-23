"""Build a poisoned temporary context and check no canary reaches any layer."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
image = 'vcf-cert-renewer:context-check-' + str(os.getpid())
with tempfile.TemporaryDirectory(prefix='vcf-context-') as folder:
    dest = Path(folder)
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    for name in filter(None, tracked):
        source = root/name
        if source.is_file():
            target = dest/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    for name in ('.env', '.git/vcf-build-context-canary',
                 'out/vcf-build-context-canary.csr',
                 'vcf_cert_renewer/vcf-build-context-canary.env',
                 'vcf_cert_renewer/components/vcf-build-context-canary.key',
                 'vcf_cert_renewer/secrets/vcf-build-context-canary'):
        p = dest/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('vcf-build-context-canary\n')
    try:
        subprocess.run(['docker', 'build', '-t', image, str(dest)], check=True)
        subprocess.run([sys.executable, str(root/'scripts/check_container_layers.py'), image],
                       cwd=root, check=True)
    finally:
        subprocess.run(['docker', 'image', 'rm', image], check=False, stdout=subprocess.DEVNULL)
print('Poisoned build-context test passed')
