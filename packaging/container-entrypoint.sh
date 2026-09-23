#!/bin/sh
set -eu
umask 077
exec python -m vcf_cert_renewer "$@"
