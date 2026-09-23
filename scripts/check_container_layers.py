"""Inspect every saved image layer for forbidden project material (offline)."""
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

image = sys.argv[1] if len(sys.argv) > 1 else 'vcf-cert-renewer:1.3.0'
marker_file = Path('.public-scan-private-markers')
private = (b'vcf-build-context-canary',) + tuple(
    line.strip().lower() for line in marker_file.read_bytes().splitlines()
    if line.strip() and not line.lstrip().startswith(b'#')
) if marker_file.exists() else (b'vcf-build-context-canary',)
forbidden = {'.git', '.env', '.lego', 'secrets', 'out', '__pycache__'}
count = 0
with tempfile.TemporaryFile() as archive:
    subprocess.run(['docker', 'save', image], stdout=archive, check=True)
    archive.seek(0)
    with tarfile.open(fileobj=archive) as outer:
        manifest = json.load(outer.extractfile('manifest.json'))
        for item in manifest:
            config = outer.extractfile(item['Config']).read()
            assert not any(marker in config.lower() for marker in private), 'Private image metadata'
            for layer in item['Layers']:
                with tarfile.open(fileobj=outer.extractfile(layer), mode='r|*') as inner:
                    for member in inner:
                        path = PurePosixPath(member.name)
                        if not member.isfile(): continue
                        # Application source and every potential build-context artifact.
                        if str(path).startswith('app/'):
                            assert not (set(path.parts) & forbidden), 'Forbidden application artifact'
                            assert path.suffix not in {'.pem', '.key', '.csr', '.crt', '.log', '.env'}, 'Private application artifact'
                            data = inner.extractfile(member).read()
                            assert not any(marker in data.lower() for marker in private), 'Private application marker'
                            count += 1
                        assert 'vcf-build-context-canary' not in str(path), 'Build context leakage'
print(f'All image layers passed private-artifact scan ({count} application files checked)')
