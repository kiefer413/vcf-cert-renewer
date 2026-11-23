#!/bin/sh
# Install managed logging and watchdog files. Preserve existing log contents.
set -eu
test "$(id -u)" -eq 0
cd "$(dirname "$0")/.."
install -d -o root -g root -m 0700 /var/log/vcf-cert-renewer
install -o root -g root -m 0644 packaging/logrotate/vcf-cert-renewer /etc/logrotate.d/vcf-cert-renewer
for name in vcf-cert-renewer-watchdog.service vcf-cert-renewer-watchdog.timer; do
    install -o root -g root -m 0644 "packaging/systemd/$name" "/etc/systemd/system/$name"
done
systemctl daemon-reload
