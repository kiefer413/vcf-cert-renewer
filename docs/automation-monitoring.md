# Automatic renewal and monitoring

## Configure the approved targets

Choose Linux/systemd or Docker for an environment. Both use the same scheduler
and operation records. Run only one scheduler against a given target set.
The example policy is disabled for mutation until the recovery acknowledgement
lists each approved role.

```dotenv
VCF_RENEW_TARGETS=SDDC_MANAGER=sddc.example.com,VCENTER=vcenter.example.com,NSX=nsx.example.com,OPERATIONS=operations.example.com,AUTOMATION=automation.example.com
# Add only the roles approved for unattended replacement.
# VCF_ACCEPT_UNVERIFIED_RECOVERY=SDDC_MANAGER,VCENTER,NSX,OPERATIONS,AUTOMATION
RENEW_BEFORE_DAYS=30
ACME_MODE=production
```

Set the SDDC, NSX VIP, Operations Fleet API and SSO endpoint settings explicitly.
See the Compose environment example for file-backed credentials and DNS-01
settings. Use a CA bundle trusted by the runtime for the API endpoints and the
management hosts. The scheduler always uses validated HTTPS. A custom CA or
staging ACME directory is not currently supported by the unattended replacement
policy. Verify prod DNS credentials with a supported isolated test.

| Role | Installation workflow |
|---|---|
| SDDC Manager | Verified domain resource, appliance CSR and managed replacement task |
| vCenter | Exact SDDC domain resource and managed replacement task |
| NSX | Cluster VIP, native CSR import and explicit MGMT_CLUSTER assignment |
| Operations | Exact Fleet-managed TLS resource, Fleet CSR/import/replace and workflow poll |
| Automation | Unambiguous fully Fleet-managed external TLS resource, Fleet CSR/import/replace and workflow poll |

Fleet uses the current SAN set only when authenticated inventory agrees with the live
certificate. For a multi-node Automation deployment, verify that Fleet and the
existing certificate include the node FQDNs and VIP required for the deployment.
Add missing identities through the vendor-supported configuration before approving
renewal. Scheduler verification covers trusted live TLS and authenticated
management inventory. Monitor application-specific Automation APIs separately.

## Linux setup and upgrade

Install Python requirements, OpenSSL and a supported lego build. Run from a
protected application directory and configure a root-owned environment file
at `/etc/vcf-cert-renewer/vcf-cert-renewer.env` (mode 0600). Preserve its
credentials, the existing output directory and task journal during upgrades.

From the checkout, as root:

```bash
install -d -m 0700 /var/log/vcf-cert-renewer
scripts/install-linux-monitoring.sh
install -m 0644 packaging/systemd/vcf-cert-renewer.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify vcf-cert-renewer.service vcf-cert-renewer.timer
logrotate --debug /etc/logrotate.d/vcf-cert-renewer
```

Review existing drop-ins before starting. Test a scheduled check with the
acknowledgement unset and inspect status. Set the approved roles and verify the
effective service command, then enable both timers.

```bash
systemctl enable --now vcf-cert-renewer.timer vcf-cert-renewer-watchdog.timer
systemctl list-timers 'vcf-cert-renewer*'
python3 -m vcf_cert_renewer status --all --json
```

Load the same protected environment for CLI status if it sets a custom output
directory. Status exits 1 for stale state, failed or unresolved targets, imminent
expiration, or other health errors. The independent watchdog also checks whether
the renewal timer is enabled and active, and its service result.

## Logging and alerts

Linux writes JSON Lines to `/var/log/vcf-cert-renewer/renewer.log` with root-only
access. systemd lifecycle diagnostics remain in journald. Default rotation is daily
with 30 rotations, delayed compression and a 50 MiB early threshold, evaluated
when logrotate executes. The writer notices a renamed file and reopens the active path.
Package upgrades preserve retained logs.

Container events go to stdout. Use a bounded Docker logging driver or a collector.
For application syslog set `VCF_SYSLOG_HOST`, optionally `VCF_SYSLOG_PORT` (6514),
`VCF_SYSLOG_TRANSPORT=tls` or `tcp`, `VCF_SYSLOG_APP`,
`VCF_SYSLOG_FACILITY` (16 is local0) and `VCF_SYSLOG_CA_FILE` for a private CA.
TLS uses hostname verification and needs a trusted server certificate. TCP and TLS
use RFC 5424 events with octet-count framing. An in-memory queue of 128 events
drops events when full or when a send fails. The scheduler keeps running during
an outage. Forward through one path to avoid duplicate events. Syslog has no
durable acknowledgements. Configure alert delivery in the receiving system.

| Event | Meaning and sample alert |
|---|---|
| VCF-1000 | Check completed. Alert on failed completion or a missing completion for 26 hours. |
| VCF-1010 | Target was outside the renewal window. Useful for confirming the configured policy. |
| VCF-1100 | Issuance and installation verified. Close the related incident after health checks. |
| VCF-1110 | Issuance and chain validated. Installation may still be pending or fail. |
| VCF-1200 | Live installation verified. Correlate by target and operation ID. |
| VCF-2000 | Certificate crossed 30, 14 or 7 days. Route by target and threshold. |
| VCF-2100 | Replacement outcome unresolved. Investigate the saved VMware task before retry. |
| VCF-2200 | Configured target omitted from recovery approval. Review policy. |
| VCF-3000 | Issuance failed. Alert on the first failure and repeated failures. |
| VCF-3100 | Installation or target validation failed. Inspect stage and error code. |
| VCF-3200 | VMware API or authentication failure. Check credentials, trust and API access. |
| VCF-3300 | Scheduler or target health failure. Inspect watchdog and scheduler journal state. |
| VCF-4000 | Certificate crossed 3 or 1 days. Page the certificate owner. |
| VCF-4100 | Stale heartbeat, incomplete run, failed service or disabled timer. Page the scheduler owner. |
| VCF-5000 | Recovery transition. Close the prior alert for that condition. |

Alert on the third consecutive target failure separately. The scheduler suppresses
repeated identical messages between thresholds. Configure external host or container
availability monitoring. A lost host cannot report itself, and Docker healthcheck
does not send an alert.

## Troubleshooting and recovery

- Inspect `status --all --json`, the local JSON Lines log and both systemd timers.
- Compare the trusted live fingerprint with the persisted expected fingerprint.
- Reconcile the saved VMware task or the explicit NSX certificate assignment.
  An ambiguous request without matching evidence remains blocked for that target.
- Preserve the output directory and task state. Do not delete a pending marker
  to force renewal. Use the documented vendor recovery process and record the
  evidence before repairing operation state.
- The acknowledgement records a recovery limitation. It neither exports a prior
  appliance private key nor asserts that the old certificate can be restored.
- A certificate that already fails trusted TLS validation requires appliance
  recovery before the automated path can verify the live identity.

## Software update notifications

After certificate processing, the shared Linux and Docker scheduler checks
[the public GitHub Release API](https://api.github.com/repos/kiefer413/vcf-cert-renewer/releases/latest).
No account is needed. The check sends an application version in the User-Agent,
and sends an ETag for conditional stable-channel checks when available. It sends
no VMware, ACME, certificate, endpoint or DNS data. Networks that permit outbound
HTTPS can allow `api.github.com:443`. There is no telemetry service or automatic installer.

| Environment setting | Default | Allowed values |
|---|---|---|
| `UPDATE_CHECK_ENABLED` | true | true, false |
| `UPDATE_CHECK_INTERVAL_HOURS` | 24 | Integer 1–720 |
| `UPDATE_CHECK_TIMEOUT_SECONDS` | 10 | Integer 1–30 |
| `UPDATE_CHECK_INCLUDE_PRERELEASE` | false | true, false |

For Linux set these optionally in the protected service environment file. For Docker
add them to `container.env`. Invalid optional values report a warning and leave
certificate processing functional. Prerelease opt-in queries the releases list,
ignores drafts and uses semantic version ordering. The scan is bounded to five
pages and fails safely rather than selecting from an incomplete result.

`status --all --json` adds `software_update`, including cached and last-check
status. Reading status never contacts GitHub. `check-update [--json]` checks
immediately while respecting disabled policy. It returns 0 for a successful or
disabled check, including an available update, and 1 for a failed check. In JSON
mode structured log events go to stderr unless a logfile is configured.
Existing certificate health and exit codes are unaffected by update availability
or a GitHub outage.

The cache is in `.software-update/state.json` under the configured output path
and persists across restart. Keep that directory when upgrading or recreating
containers. A failed check preserves the last release information and flags it
as potentially stale. Warnings only repeat if the failure type changes. Check
DNS, outbound trust and GitHub rate limits if the failure persists.

| Event | Meaning |
|---|---|
| VCF-6000 | A newly discovered update is available |
| VCF-6010 | The installed version is up to date |
| VCF-6020 | The version check failed |
| VCF-6030 | A version check recovered |

Linux operators should back up and verify the new runtime separately while
preserving the existing environment, ACME material, certificates, operation
journals, health, notification history and logging settings. Docker operators
should select an explicit version tag and follow the container upgrade procedure
without deleting the data volume. Software updates always require an operator.
