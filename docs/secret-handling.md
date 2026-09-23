# Secret handling and batch containers (v1.3.0)

Direct environment values and the existing secrets.env deployment remain supported.
For production, use mounted files and NAME_FILE instead. The central resolver runs
when Settings is loaded; it never exports resolved values into os.environ.
Files are UTF-8. Only trailing LF or CRLF newline sequences are removed; spaces,
tabs, embedded newlines and a standalone carriage return are preserved. Missing,
unreadable, invalid UTF-8 and empty files fail without printing values or paths.
A direct NAME and NAME_FILE together are an error, even if either is empty or
comes from a different configuration layer. Remove obsolete direct assignments
from both EnvironmentFile and the legacy secrets.env file when migrating.

Supported pairs:

| Direct setting | File setting |
| --- | --- |
| VCF_API_TOKEN | VCF_API_TOKEN_FILE |
| SDDC_PASSWORD | SDDC_PASSWORD_FILE |
| VCF_CLIENT_SECRET (legacy OAuth) | VCF_CLIENT_SECRET_FILE |
| DNSUPDATE_TSIG_SECRET | DNSUPDATE_TSIG_SECRET_FILE |
| ACME_EAB_HMAC | ACME_EAB_HMAC_FILE |
| SDDC_USERNAME | SDDC_USERNAME_FILE |
| VCF_CLIENT_ID (legacy OAuth) | VCF_CLIENT_ID_FILE |
| ACME_EAB_KID | ACME_EAB_KID_FILE |

The last three identifiers are supported for consistency with the existing
credentials file; they need not be treated as passwords. The audit found no
additional application password/token configuration. DNSUPDATE_TSIG_KEY is a key
*name*, not key material. Direct EAB values retain legacy whitespace normalization;
file-backed EAB values retain their exact non-newline contents.

File-based secrets are **not inherently encrypted at rest**. Protected native
files, systemd Credentials, Docker/Podman secrets, Kubernetes mounted Secrets and
Vault-agent files all use the same resolver. Storage encryption, access policy,
rotation and delivery belong to the external secret store. Values remain in
application memory. The current lego interface requires DNS TSIG and EAB values
in the lego child environment; they are never placed on its command line or
printed, and unrelated VCF/SDDC credentials are removed from that environment.
Do not enable external process tracing or dump process environments in production.

## Native protected files

Provision files through your secret manager, with parent directory mode 0700 and
file mode 0600 owned by the service user. Do not put actual values in shell history.
Set ordinary configuration to, for example:

```ini
VCF_API_TOKEN_FILE=/etc/vcf-cert-renewer/credentials/vcf_api_token
SDDC_PASSWORD_FILE=/etc/vcf-cert-renewer/credentials/sddc_password
DNSUPDATE_TSIG_SECRET_FILE=/etc/vcf-cert-renewer/credentials/dns_tsig_secret
# When EAB is required, also set ACME_EAB_KID:
ACME_EAB_HMAC_FILE=/etc/vcf-cert-renewer/credentials/acme_eab_hmac
```

Paths are literal; application code does not expand shell variables or systemd
specifiers. Kubernetes and Vault-agent mounts work identically by pointing these
settings at readable mounted files. Coordinate rotation between batch runs.

## systemd Credentials (recommended native production deployment)

Keep the existing service and EnvironmentFile for non-secret configuration. Install
`packaging/systemd/credentials.conf` as a drop-in under
`/etc/systemd/system/vcf-cert-renewer.service.d/`. Provision the referenced source
files and remove all corresponding direct secret assignments. Run
`systemctl daemon-reload`; the next scheduled start loads fresh credentials.
Do not restart the renewal service merely to validate configuration: it renews.

`LoadCredential=id:/protected/source` supplies a read-only per-service copy.
`Environment=VCF_API_TOKEN_FILE=%d/vcf_api_token` uses systemd's credential-directory
specifier (systemd >= 247). `%d` belongs in the unit/drop-in, **not** in an
EnvironmentFile. systemd also supplies CREDENTIALS_DIRECTORY; no PID-specific path
or application-specific systemd provider is needed. Where supported, use
`LoadCredentialEncrypted=` with files provisioned by `systemd-creds` for encrypted
at-rest source credentials; `LoadCredential=` alone does not encrypt source files.
See [systemd credentials](https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md).

## Image and persistent state

Build the **sanitized public repository**: internal source defaults contain local
site configuration and must never be distributed. The image uses Python 3.12.12
on Debian bookworm slim (manifest digest pinned), controlled Python dependencies,
CA trust, and lego 5.4.1 archives pinned by SHA-256 for linux/amd64 and linux/arm64.
The runtime UID/GID is 10001:10001 and its entrypoint sets umask 077. It runs one
batch command, with no scheduler. Schedule it externally. Do not run concurrent
renewals against the same targets or state directory.

```sh
docker build -t vcf-cert-renewer:1.3.0 .
docker run --rm --network none vcf-cert-renewer:1.3.0 --version
docker run --rm --network none vcf-cert-renewer:1.3.0 --help
```

`OUTPUT_DIR=/data` contains renewal artifacts and lego state under
`/data/acme/<staging|production|custom>`, including ACME account private keys.
Persist /data to reuse accounts (including EAB registration); back it up securely.
Lego further scopes account storage by CA/email. No additional .lego mount is
needed: the signer already passes an explicit --path. Protect retained CSRs,
certificates, keys and reports and define your own retention policy.

## Docker and Podman

Copy `examples/container.env.example` to a private deployment directory as
`container.env` and edit non-secret values. Provision a `secrets/` directory with
files readable by UID 10001, while keeping the host directory restricted. For
rootless Podman, account for UID mapping (e.g. use podman unshare when provisioning).
Docker named volumes inherit /data ownership on first initialization; pre-existing
or bind-mounted data directories must already be writable by UID 10001.

```sh
docker volume create vcf-renewer-data
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --env-file ./container.env \
  --mount type=bind,src="$(pwd)/secrets",dst=/run/secrets,readonly \
  --mount type=volume,src=vcf-renewer-data,dst=/data \
  ghcr.io/kiefer413/vcf-cert-renewer:1.3.0 plan --all
```

Use `renew --all --yes` instead of `plan --all` when ready to authorize renewal.
Planning uses network reads; only --help/--version/configuration smoke checks are
offline. The image will become available after the separate approved release.
Docker standalone `run` has no `--secret` option: the example uses read-only mounts.
Podman supports the same image/mount approach and native secrets, for example:

```sh
podman secret create vcf_api_token ./secrets/vcf_api_token
podman secret create sddc_password ./secrets/sddc_password
podman secret create dns_tsig_secret ./secrets/dns_tsig_secret
podman volume create vcf-renewer-data
podman run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 --env-file ./container.env \
  --secret vcf_api_token,uid=10001,gid=10001,mode=0400 \
  --secret sddc_password,uid=10001,gid=10001,mode=0400 \
  --secret dns_tsig_secret,uid=10001,gid=10001,mode=0400 \
  -v vcf-renewer-data:/data \
  ghcr.io/kiefer413/vcf-cert-renewer:1.3.0 plan --all
```

For EAB, also mount/create acme_eab_hmac and enable both EAB settings. For private
CAs, mount a CA bundle and configure the trust settings supported by requests and
lego; do not disable TLS verification to work around missing trust.

## Compose

Place `examples/compose.yaml` next to container.env and secrets/. Then:

```sh
docker compose run --rm renewer plan --all
docker compose run --rm renewer renew --all --yes
```

Local Compose file-backed secrets are bind-mounted files: **not automatically
encrypted at rest**. File ownership/permissions on the host must allow UID 10001
to read them; Compose uid/gid/mode options cannot fix bind-mounted file ownership.
For EAB add acme_eab_hmac to both the top-level secrets map and service secrets
list, then enable ACME_EAB_KID and ACME_EAB_HMAC_FILE in container.env.
Do not use `docker compose down -v` unless intentionally deleting account state.
Docker itself does not encrypt passwords. `_FILE` separates credentials from main
configuration and the parent process environment; external storage supplies protection.

## Release validation and publishing

Container CI first runs the full offline tests and image smoke on native amd64 and
arm64 runners. Version tags matching vX.Y.Z may publish a multi-platform image only
after both pass. Stable tags produce X.Y.Z, X.Y and latest. PR/branch builds do not
log into GHCR or publish. A protected `ghcr-release` GitHub environment should gate
publishing; configure required reviewers before pushing a release tag.

Build the test-only image with
`docker build -t vcf-cert-renewer-test:1.3.0 - < packaging/Dockerfile.test`.
Run it with `docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m
-v "$PWD:/work:ro" vcf-cert-renewer-test:1.3.0` (one command). Use a source-only
checkout with no production config/state mounted. The entrypoint runs
`scripts/validate_release.sh`; it requires --network none.
`python scripts/container_smoke.py IMAGE` validates the runtime without API calls.
Do not run live CSR/renewal commands as release tests.
