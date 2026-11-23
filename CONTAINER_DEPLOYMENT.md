# Docker, Podman and Kubernetes deployment

The container includes Python, the required libraries, lego and VCF Certificate
Renewer. You supply configuration, credentials, persistent storage and network
access. You do not install Python or lego on the Docker host or Kubernetes nodes.
The same GHCR image runs on amd64 and arm64, including directly in Kubernetes.
There is no Kubernetes-specific build.

This guide targets the unpublished v1.5.0 candidate. The image defaults to `DNS_PROVIDER=dnsupdate` for bundled lego 5.4.1. Update older environment files or ConfigMaps that explicitly set `rfc2136`. The signer checks the selected provider with local lego help before invoking ACME.

The program is a batch workflow: start, inspect certificates, renew those that are
due, verify, then exit. Use a **CronJob**, not a continuously running Deployment.
The existing Operations, SDDC Manager, vCenter and NSX Manager MGMT_CLUSTER
workflows remain available. v1.4.0 also supports the dynamically discovered
customer-managed VCF Automation external TLS leaf through Fleet. Internal
Automation VMCA certificates remain outside mutation scope. Container deployment
does not change authentication.

```text
ConfigMap (ordinary settings)     Secret (credentials)
          | env                       | read-only /run/secrets/*
          +---------------------------+
                          |
                 VCF Certificate Renewer
                    CronJob -> Job
                          |
                 ACME CA / DNS / VCF
                          |
             persistent /data (ACME state,
                  CSR/fullchain artifacts)
```

## Docker quick start

Work in a private deployment directory outside your Git checkout. Copy
[`examples/container.env.example`](examples/container.env.example) there as
`container.env`, then replace the example addresses, username, DNS key name and
ACME email. Set `VCF_RENEW_TARGETS` to your role-to-FQDN policy, and add approved roles to `VCF_ACCEPT_UNVERIFIED_RECOVERY` only when ready.
Keep `OUTPUT_DIR=/data`. Preserve TLS verification and configure CSR subject fields
as needed (see [configuration](.env.example)).

```sh
docker pull ghcr.io/kiefer413/vcf-cert-renewer:1.5.0
docker volume create vcf-renewer-data
```

Have your secret manager write these UTF-8 files into a protected `secrets/`
directory: `vcf_api_token`, `sddc_password`, `dns_tsig_secret`. Do not put their
values in `container.env`. For rootful Docker on Linux, files owned by UID 10001
with mode 0400 inside a directory owned by UID 10001 with mode 0700 are suitable.
A trusted administrator can set ownership without displaying the contents:

```sh
sudo chown -R 10001:10001 ./secrets
sudo chmod 0700 ./secrets
sudo chmod 0400 ./secrets/*
```

Rootless engines have different host UID mappings; provision ownership through
that engine's user namespace instead. Avoid world-readable files as a workaround.
The example environment already contains:

```ini
VCF_API_TOKEN_FILE=/run/secrets/vcf_api_token
SDDC_PASSWORD_FILE=/run/secrets/sddc_password
DNSUPDATE_TSIG_SECRET_FILE=/run/secrets/dns_tsig_secret
```

Run a read-only plan first. It contacts your configured VCF endpoints; it is **not
an offline test**, but it does not replace certificates:

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --env-file ./container.env \
  --mount type=bind,src="$(pwd)/secrets",dst=/run/secrets,readonly \
  --mount type=volume,src=vcf-renewer-data,dst=/data \
  ghcr.io/kiefer413/vcf-cert-renewer:1.5.0 plan --all
```

Review target scope before making changes. Set `ACME_MODE=production` and configure
the exact role-to-FQDN policy. Leave the recovery acknowledgement unset while
checking discovery and health. Add only approved roles before running
`scheduled` or starting the persistent `scheduler`. Test issuance and DNS
permissions in an isolated environment before enabling unattended renewal.

For an offline installation check, use `docker run --rm --network none
 ghcr.io/kiefer413/vcf-cert-renewer:1.5.0 --version` as one command.

### Podman and Compose

Podman pulls the same image and supports native mounted secrets. Follow the
[Podman commands and ownership guidance](docs/secret-handling.md#docker-and-podman),
including the rootless UID mapping notes.

For Compose, place [`examples/compose.yaml`](examples/compose.yaml) beside
`container.env` and `secrets/`, then run:

```sh
docker compose pull
docker compose run --rm renewer plan --all
# After reviewing the plan and choosing the intended trusted CA:
docker compose up -d renewer
```

Compose uses the same files, read-only filesystem and persistent `/data` model.
Its local file-backed secrets are bind mounts; their host permissions must allow
UID 10001 to read them. Docker alone does **not** encrypt passwords. Neither
`--env-file`, Compose secrets nor `_FILE` automatically encrypt their backing
storage. `_FILE` keeps values out of ordinary configuration and the application's
parent environment; access controls and encryption belong to your secret store.
Never set both a direct value (even empty) and its `_FILE` counterpart. See
[secret handling](docs/secret-handling.md) for all supported pairs and rotation.

## Kubernetes installation

Use a supported Kubernetes release with `batch/v1` CronJobs and stable `timeZone`
support (the manifests require Kubernetes 1.27 or later). You need `kubectl`,
Python 3 locally for the plan conversion below, and a StorageClass providing a
writable persistent volume. No Helm chart or operator is required.

The application needs **no Kubernetes API permissions or custom ServiceAccount**.
It uses the namespace's default ServiceAccount with token automount disabled.
No Roles or RoleBindings are installed. The person installing resources still
needs permission to manage them; external secret integrations may have their own
identity requirements. Do not grant permissions to the workload's default account.

### 1. Choose the cluster and prepare ordinary settings

Confirm that your current context is the intended cluster before applying anything:

```sh
kubectl config current-context
kubectl apply -f deploy/kubernetes/namespace.yaml
```

Copy `deploy/kubernetes/configmap.example.yaml` to a private directory **outside
Git**, edit it and save it as `configmap.yaml`. Replace all example endpoints,
username, target FQDNs, CSR subject fields, email and DNS settings. The ConfigMap
holds ordinary strings and `_FILE` paths, not passwords. Even site-specific
configuration should stay out of the public repository.

```sh
kubectl apply -f /path/to/private-deployment/configmap.yaml
```

### 2. Create credentials without a plaintext Secret YAML

Use existing protected files supplied by your secret manager. From a directory
where those files are readable by your administrative user:

```sh
kubectl -n vcf-cert-renewer create secret generic vcf-cert-renewer \
  --from-file=vcf_api_token=./secrets/vcf_api_token \
  --from-file=sddc_password=./secrets/sddc_password \
  --from-file=dns_tsig_secret=./secrets/dns_tsig_secret
```

This sends the files directly to the API; no Secret YAML is needed. `--from-literal`
also works but may expose values through shell history or process arguments.
Prefer `--from-file`; do not type values into command lines, enable shell tracing,
print Secret YAML or commit secret files. This is an initial-create command: if
the Secret already exists, use your approved rotation process rather than deleting
an externally managed Secret. Keep credentials stable throughout a batch run.

| Kubernetes Secret key / filename | ConfigMap setting |
| --- | --- |
| `vcf_api_token` | `VCF_API_TOKEN_FILE=/run/secrets/vcf_api_token` |
| `sddc_password` | `SDDC_PASSWORD_FILE=/run/secrets/sddc_password` |
| `dns_tsig_secret` | `DNSUPDATE_TSIG_SECRET_FILE=/run/secrets/dns_tsig_secret` |
| `acme_eab_hmac` (optional) | `ACME_EAB_HMAC_FILE=/run/secrets/acme_eab_hmac` |

For EAB, add `--from-file=acme_eab_hmac=./secrets/acme_eab_hmac` to the initial
creation command, and enable **both** `ACME_EAB_KID` and `ACME_EAB_HMAC_FILE` in the
ConfigMap. The volume mounts every key, so no CronJob change is needed. Empty,
unreadable or missing credential files fail safely. Remove corresponding direct
secret environment assignments when migrating from older configuration.

### 3. Add persistent storage and the suspended CronJob

Review [`pvc.yaml`](deploy/kubernetes/pvc.yaml). It requests 1 GiB using the default
StorageClass; set `storageClassName` in a private copy if needed. The storage driver
must honor `fsGroup: 10001` or provide equivalent ownership. Keep the PVC as the
recommended default. `/data/acme/<staging|production|custom>` persists lego's ACME
account private key, registration and account identity, plus issued certificate
files. Preserve this identity, especially with custom ACME CAs and External Account
Binding (EAB), and protect and back up the volume. `/data` also holds the generated
`<fqdn>.csr.pem` and `<fqdn>.vcf-fullchain.pem` artifacts; these can be regenerated.
The endpoint's private TLS key remains in VCF/NSX.

Writable ephemeral storage such as `emptyDir` is technically possible if the CA
allows repeated account registration. It is not recommended as the default:
Pod recreation discards the account state and may cause a new ACME account
registration, which can fail because of registration limits, EAB requirements
or custom CA rules.

```sh
kubectl apply -f deploy/kubernetes/pvc.yaml
kubectl apply -f deploy/kubernetes/cronjob.yaml
kubectl -n vcf-cert-renewer get cronjob,pvc
```

The CronJob is **suspended by default**. A PVC using WaitForFirstConsumer may stay
Pending until the first Job is scheduled. Keep a private copy of the manifests
for image, schedule and storage customizations.

### 4. Run a one-off plan before enabling renewal

Generate a Job from the installed CronJob without starting it, then change only
its arguments to `plan --all`. The command below needs local Python 3, but no
extra Python packages. It keeps the same image, mounts, configuration and security:

```sh
kubectl -n vcf-cert-renewer create job vcf-cert-renewer-plan \
  --from=cronjob/vcf-cert-renewer --dry-run=client -o json > plan-job.json
python3 - <<'PYCODE'
import json
from pathlib import Path
path = Path("plan-job.json")
job = json.loads(path.read_text())
job["spec"]["template"]["spec"]["containers"][0]["args"] = ["plan", "--all"]
path.write_text(json.dumps(job, indent=2) + "\n")
PYCODE
kubectl create -f plan-job.json
kubectl -n vcf-cert-renewer logs -f job/vcf-cert-renewer-plan
kubectl -n vcf-cert-renewer get job vcf-cert-renewer-plan
```

Check that the Job completes successfully and inspect the plan. Planning makes
VCF API reads but no certificate changes. If you repeat it, use a new Job name or
delete the completed plan Job first. Generated `plan-job.json` contains references,
not Secret values; keep deployment files outside Git anyway.

### 5. Test renewal and enable the daily schedule

Select the intended trusted production CA in your private ConfigMap and reapply
it before proceeding. Staging renewal is only for labs, not a harmless test on
live endpoints. Keep the CronJob suspended and ensure **no other renewal job,
Docker command or systemd timer** is running for these targets. Run manually:

```sh
kubectl -n vcf-cert-renewer create job vcf-cert-renewer-manual \
  --from=cronjob/vcf-cert-renewer
kubectl -n vcf-cert-renewer logs -f job/vcf-cert-renewer-manual
kubectl -n vcf-cert-renewer get job vcf-cert-renewer-manual
```

This executes `scheduled` and can change certificates for approved roles. Investigate failures
before retrying: some targets may already have completed. After it succeeds,
enable scheduling:

```sh
kubectl -n vcf-cert-renewer patch cronjob vcf-cert-renewer \
  --type=merge -p '{"spec":{"suspend":false}}'
```

The schedule is daily at **03:00 UTC** (`0 3 * * *`, `Etc/UTC`); change it to suit
your maintenance window. Record `suspend: false` in your private manifest after
commissioning; applying the shipped example again suspends scheduling.
`Forbid` prevents overlap between scheduled Jobs from this CronJob. It does not
serialize manually created Jobs, other CronJobs or external schedulers. Never
run two against the same targets/state. See the [Kubernetes CronJob documentation](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).

Jobs use `restartPolicy: Never` and `backoffLimit: 0` to avoid automatic retries of
partially completed changes. Two successful and three failed scheduled Jobs are
retained; manual Jobs need separate cleanup. A missed start is allowed for up to
10 minutes. No hard execution deadline is imposed, to avoid terminating a
certificate replacement halfway through; monitor long-running Jobs, as they block
later scheduled runs.

## Logs and troubleshooting

CronJob renewal output goes to stdout/container logs, available through
`kubectl logs`; the entrypoint does not save reports under `/data`. That volume
holds ACME state and the CSR/fullchain artifacts described above.

```sh
kubectl -n vcf-cert-renewer get cronjob,jobs,pods,pvc
kubectl -n vcf-cert-renewer describe cronjob vcf-cert-renewer
kubectl -n vcf-cert-renewer get events --sort-by=.metadata.creationTimestamp
# Replace JOB_NAME with the actual name shown above:
kubectl -n vcf-cert-renewer logs job/JOB_NAME
kubectl -n vcf-cert-renewer describe job JOB_NAME
```

- No scheduled runs: check `suspend`, the UTC schedule and any unfinished Job.
- Pending Pod: inspect Pod events and the PVC/StorageClass. Check available memory.
- ImagePullBackOff: confirm the version has been published and nodes can reach
  GHCR. Public images need no imagePullSecret; apply your site's registry policy.
- Secret/config error: verify key names and `_FILE` paths, readable permissions
  and the absence of direct/file conflicts. Do not print values to troubleshoot.
- Permission denied under `/data`: ensure the storage driver supports the declared
  fsGroup or provision ownership for UID/GID 10001. Do not switch to root.
- TLS error: mount an appropriate CA bundle and configure requests/lego trust as
  described in [secret handling](docs/secret-handling.md). Keep verification on.
- Failed renewal: inspect per-target results, DNS reachability and CA policy before
  retrying. A failure does not mean that every target remained unchanged.

## Security and network access

The Pod runs as UID/GID 10001, with no privilege escalation, all capabilities
dropped and `RuntimeDefault` seccomp. Its root filesystem is read-only; `/data`
and the bounded in-memory `/tmp` are writable. Secret files are mounted read-only
with mode 0440 and group access through fsGroup 10001. There is no hostPath,
host networking, privileged mode or Kubernetes API token. See
[Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

Kubernetes Secret base64 is **encoding, not encryption**. Configure etcd encryption
at rest and least-privilege RBAC, including who can create Pods that mount Secrets.
Protect backups and persistent volume data too. Vault, External Secrets and
CSI-mounted secrets can supply the same files without application changes:
`_FILE` only requires readable files. Those integrations may need their own
permissions. See [Kubernetes Secret good practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/).

Allow outbound HTTPS to the configured VCF endpoints and ACME CA, plus DNS
resolution/propagation checks and RFC2136 updates to the configured authoritative
DNS server (normally TCP/UDP 53). Cluster nodes also need GHCR access to pull the
image. No inbound service or Ingress is needed. If your cluster enforces egress
NetworkPolicies, allow cluster DNS, configured resolvers and these destinations.
A universal policy is intentionally not shipped: addresses, CAs and DNS routing
vary by site. Standard NetworkPolicy does not provide portable FQDN allowlists;
use your network plugin's documented options where needed. See
[Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Updating safely

Pin an explicit published image version (or verified multi-architecture digest),
not `latest`. Back up `/data`. Suspend the CronJob, let active Jobs finish, update
the image in your private manifest, then apply it while still suspended. Run a
new plan Job and review it before resuming. ConfigMap and Secret updates are read
by new Pods; avoid rotating credentials during an active run. Changing the
CronJob image does not update existing Jobs. For Docker/Podman/Compose, pull the
new version and keep the same protected secrets and data volume, then plan first.

## Uninstall without losing credentials or account state

Suspend the CronJob and wait for active Jobs to finish before deleting it:

```sh
kubectl -n vcf-cert-renewer patch cronjob vcf-cert-renewer \
  --type=merge -p '{"spec":{"suspend":true}}'
kubectl -n vcf-cert-renewer get jobs
# Only after active work has finished:
kubectl -n vcf-cert-renewer delete cronjob vcf-cert-renewer
kubectl -n vcf-cert-renewer delete configmap vcf-cert-renewer
# Remove these completed manual Jobs if they were created:
kubectl -n vcf-cert-renewer delete job vcf-cert-renewer-plan vcf-cert-renewer-manual --ignore-not-found
```

Retain the Namespace, Secret and PVC by default. Deleting the namespace would
also delete its Secrets and PVCs, including externally managed ones. Delete these
only as a separate intentional cleanup after backups and checking ownership.
Do not use `kubectl delete -f deploy/kubernetes/` for routine uninstall.
For Docker/Podman/Compose, keep the data volume and secret files; avoid
`docker compose down -v` unless deliberately discarding account state.

## v1.5.0 Compose scheduler

Copy `examples/compose.yaml` and `examples/container.env.example` to a protected
deployment directory. Rename the latter to `container.env`, configure exact
roles and FQDNs, and supply mounted secret files readable by UID 10001.
Build from the reviewed checkout and tag the image named in the Compose file
when testing an unpublished candidate. Do not use the same targets from a Linux
timer and a container scheduler concurrently.

The Compose service runs `scheduler` immediately and every
`VCF_CHECK_INTERVAL_SECONDS` seconds (default 86400). The same named volume at
`/data` retains ACME material, journals and health. No log volume is needed.
The image healthcheck reads the heartbeat and certificate state. Monitor
container status externally. The default Compose `local` driver bounds logs
to five 10 MiB rotations. Docker's driver can also use TCP syslog on supported
hosts. TLS example for the Docker daemon driver:

```yaml
logging:
  driver: syslog
  options:
    syslog-address: "tcp+tls://syslog.example.com:6514"
    syslog-format: "rfc5424"
    syslog-tls-ca-cert: "/etc/docker/certs/syslog-ca.pem"
```

The CA path in this example belongs to the Docker daemon host. If Docker
supplies forwarding, leave application syslog disabled. See
[automatic renewal and monitoring](docs/automation-monitoring.md) for status,
event IDs and recovery.

## Back up and restore the named data volume

Identify the actual volume with `docker volume ls`. Stop the scheduler
with `docker compose stop renewer` before backing up or restoring it.
Backups contain ACME keys and may include other private data. Use a directory
accessible only to the operator, and encrypt backups at rest.

```bash
umask 077
volume=vcf-renewer_renewer-data   # Replace with the actual Compose volume.
docker run --rm --network none -v "$volume:/data:ro" alpine tar -C /data -czf - . > renewer-data.tar.gz
```

To restore, create an empty volume, then extract a trusted archive while
preserving numeric UID/GID 10001 and modes. Point Compose at that restored
volume before recreating the service. Keep the original volume intact until
health and pending operation state have been checked.

```bash
docker volume create renewer-data-restored
docker run --rm -i --network none -v renewer-data-restored:/data alpine tar -C /data -xzpf - < renewer-data.tar.gz
```

For an upgrade, save a backup, pull or build the reviewed version, and use
`docker compose up -d --no-deps renewer` with the same volume mapping. Preserve
the environment and secrets. Check `docker compose ps`, `docker compose logs renewer`
and `docker compose exec renewer vcf-cert-renewer status --all --json`.
If stuck in an unresolved replacement, preserve the journal and reconcile the
saved VMware task. Avoid concurrent schedulers and avoid `docker compose down -v`.
Confirmed live validation and Fleet limitations are in the [release notes](docs/releases/v1.5.0.md).
