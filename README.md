# VCF Certificate Renewer

Automated public TLS certificate lifecycle management for VMware Cloud Foundation (VCF) 9.x.

VCF Certificate Renewer discovers browser-facing certificates, builds a read-only renewal plan, requests product-generated CSRs, completes ACME DNS-01 validation, imports and applies the resulting certificate chain through the appropriate product API, and verifies the live HTTPS certificate.

> [!IMPORTANT]
> This is an independent open source project. It is not affiliated with, endorsed by, or supported by Broadcom. VMware and Broadcom product names are used only to identify compatible products.

**Tested with VCF 9.1.x.** Other VCF 9.x releases may work, but are not claimed as validated.

## What it does

- Discovers certificate inventory and inspects live TLS endpoints.
- Classifies endpoints through an explicit component allowlist.
- Produces a complete read-only plan before any batch mutation.
- Keeps endpoint private keys inside VCF or NSX by using product-generated CSRs.
- Uses ACME with DNS-01 validation through an RFC2136 DNS provider.
- Imports, applies, and verifies renewed public certificate chains.
- Supports unattended renewal checks through a hardened systemd oneshot service and timer.

## Supported components

Only four browser-facing endpoints are authorized for full renewal. Other known components are deliberately limited to planning, discovery, or unsupported status.

| Component | Discovery | Plan | Renewal |
|---|:---:|:---:|:---:|
| VCF Operations | Yes | Yes | Yes |
| SDDC Manager | Yes | Yes | Yes |
| vCenter Server | Yes | Yes | Yes |
| NSX Manager cluster VIP | Yes | Yes | Yes |
| NSX manager node/API | Yes | Yes | No |
| Identity Broker / ACS | Yes | Yes | No |
| Runtime / Automation / Logs | Yes | Yes | No |
| Operations for Networks | Yes | No | No |
| Supervisor | Yes | Yes | No |
| ESXi | No | No | No |
| Other Fleet TLS endpoints | Yes | No | No |

For capability definitions and mutation routes, see [Component support](docs/component-support.md).

## Architecture

The tool separates inventory, classification, certificate lifecycle work, and live verification. An ordered adapter registry maps each endpoint to exactly one supported API family; it never falls back to another mutation route.

```text
Fleet inventory + live TLS inspection
                |
                v
       classify and plan (read-only)
                |
                v
        VCF/NSX-generated CSR
                |
                v
  lego -> ACME DNS-01 -> RFC2136 DNS
                |
                v
 validate chain -> import -> explicit apply
                |
                v
       live HTTPS/SNI verification
```

- Operations uses Fleet CSR, import, and replace APIs.
- SDDC Manager and vCenter use the domain resource-certificate API.
- NSX uses the native `MGMT_CLUSTER` certificate profile for the cluster VIP.
- The live HTTPS leaf is authoritative for renewal timing and final verification.

See [Architecture](docs/architecture.md) and [Renewal flow](docs/renewal-flow.md) for details.

## Quick Start

The following development setup gets you from a checkout to a safe, read-only plan. Replace every placeholder in the configuration before use.

```bash
git clone <repository-url> vcf-cert-renewer
cd vcf-cert-renewer

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

cp examples/vcf-cert-renewer.env.example .env
chmod 600 .env
${EDITOR:-vi} .env
set -a
. ./.env
set +a

python -m vcf_cert_renewer discover --all
python -m vcf_cert_renewer plan --all
```

Start with ACME staging (`ACME_MODE=staging`). Review the plan for all four configured targets before approving any renewal. Never commit `.env` or real credentials.

## Production installation

Install the checked-out release under `/opt/vcf-cert-renewer` and keep production secrets under `/etc/vcf-cert-renewer`:

```bash
sudo install -d -o root -g root -m 0755 /opt/vcf-cert-renewer
sudo cp -a . /opt/vcf-cert-renewer/
sudo chown -R root:root /opt/vcf-cert-renewer

sudo install -d -o root -g root -m 0750 /etc/vcf-cert-renewer
sudo install -o root -g root -m 0600 \
  /opt/vcf-cert-renewer/examples/vcf-cert-renewer.env.example \
  /etc/vcf-cert-renewer/vcf-cert-renewer.env
sudoedit /etc/vcf-cert-renewer/vcf-cert-renewer.env
```

The supplied systemd unit invokes `/usr/bin/python3`, so install the dependencies for that interpreter according to your operating-system packaging policy. For interactive or development use, a virtual environment is recommended.

### Production configuration

`/etc/vcf-cert-renewer/vcf-cert-renewer.env` is a root-only environment file. At minimum, configure:

- VCF, SDDC Manager, and NSX endpoints and credentials.
- TLS verification settings.
- ACME mode and account email.
- RFC2136 nameserver and restricted TSIG credentials.
- Exactly four `VCF_RENEW_TARGETS`, ordered as Operations, SDDC Manager, vCenter, and NSX Manager VIP.
- Renewal threshold, public DNS resolvers, `lego` path, and output directory.

The complete documented template is [examples/vcf-cert-renewer.env.example](examples/vcf-cert-renewer.env.example). Configuration precedence is CLI override, process environment, secrets file, optional YAML, then safe built-in defaults. See [Authentication and configuration](docs/authentication.md).

### systemd service and timer

Install the supplied units, review them, run read-only checks, and then enable the timer:

```bash
sudo install -o root -g root -m 0644 \
  packaging/systemd/vcf-cert-renewer.service \
  /etc/systemd/system/vcf-cert-renewer.service
sudo install -o root -g root -m 0644 \
  packaging/systemd/vcf-cert-renewer.timer \
  /etc/systemd/system/vcf-cert-renewer.timer
sudo systemctl daemon-reload

cd /opt/vcf-cert-renewer
sudo /usr/bin/python3 -m vcf_cert_renewer discover --all
sudo /usr/bin/python3 -m vcf_cert_renewer plan --all

sudo systemctl start vcf-cert-renewer.service
sudo systemctl enable --now vcf-cert-renewer.timer
systemctl list-timers vcf-cert-renewer.timer
```

The oneshot service runs `renew --all --yes`. The daily persistent timer adds a randomized delay of up to one hour. It deliberately does not use `--force`.

## CLI examples

```bash
# Inspect version and help
python3 -m vcf_cert_renewer --version
python3 -m vcf_cert_renewer --help
python3 -m vcf_cert_renewer renew --help

# Read-only discovery and planning
python3 -m vcf_cert_renewer discover --all
python3 -m vcf_cert_renewer plan --all
python3 -m vcf_cert_renewer plan ops.vcf.example.com

# Preview or approve renewal
python3 -m vcf_cert_renewer renew ops.vcf.example.com
python3 -m vcf_cert_renewer renew ops.vcf.example.com --yes
python3 -m vcf_cert_renewer renew --all
python3 -m vcf_cert_renewer renew --all --yes
```

`renew` first inspects the live leaf certificate. If it has more than `RENEW_BEFORE_DAYS` remaining, the command returns `NO_RENEWAL_NEEDED` without OAuth or mutation. Recovery-oriented `csr`, `sign`, `import`, `replace`, and `verify` commands are also available; review their command help before use.

## Safety model

- `discover --all` and `plan --all` are read-only.
- Batch renewal plans every target before changing any target and fails closed if planning fails.
- Production ACME renewal requires `--yes` or `--apply`.
- `--force` changes only the expiry decision; it does not grant approval.
- Endpoint private keys remain inside VCF or NSX.
- Import and apply are separate boundaries, followed by live SNI verification.
- Mutating API requests are not automatically retried after an ambiguous response.
- Unsupported endpoints cannot acquire mutation authority through fallback behavior.

## DNS-01 and RFC2136

Public issuance uses Let's Encrypt, or another compatible ACME directory, with `lego` and its RFC2136 provider. Delegate a public zone such as `vcf.example.com` to an authoritative DNS server and restrict the TSIG key to the required `_acme-challenge` TXT updates. Use `ACME_MODE=staging` during initial validation; switch to `production` only after discovery, planning, DNS updates, and credentials have been verified. `ACME_SERVER` may select another compatible ACME directory.

## Known limitations

- Full renewal is limited to the four allowlisted endpoints in the support matrix.
- NSX manager-node/API certificates are not replaced; only the cluster VIP `MGMT_CLUSTER` profile is supported.
- ESXi certificates are outside the release scope.
- Internal roots, intermediates, trust anchors, and private/internal certificates are not replaced.
- Some discovered products are plan-only or discovery-only because no verified mutation route is available.
- Full renewal has been live-validated with VCF 9.1.x only.
- The deployment expects network access to VCF APIs, the live HTTPS endpoints, an ACME directory, public resolvers, and the authoritative RFC2136 DNS server.

## Documentation and project policies

- [Architecture](docs/architecture.md)
- [Authentication and configuration](docs/authentication.md)
- [Component support](docs/component-support.md)
- [Renewal flow](docs/renewal-flow.md)
- [Security guide](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Apache License 2.0](LICENSE)

## Development checks

```bash
python3 -m compileall -q vcf_cert_renewer scripts tests
python3 -m unittest discover -s tests -v
python3 -m scripts.smoke_test
python3 scripts/check_public_markers.py
```
