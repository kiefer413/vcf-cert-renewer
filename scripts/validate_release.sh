#!/bin/sh
# Run with repository mounted at /work, --network none and /tmp writable.
set -eu
export VCF_CONFIG_FILE=/nonexistent/config VCF_SECRETS_FILE=/nonexistent/secrets
export PYTHONPYCACHEPREFIX=/tmp/vcf-pycache
python -m compileall -q vcf_cert_renewer scripts tests
python -m pytest -q -p no:cacheprovider
python -m scripts.smoke_test
python -m vcf_cert_renewer --version
python -m vcf_cert_renewer --help >/dev/null
