# Architecture

VCF Certificate Renewer separates inventory, target classification, certificate
lifecycle work, and live verification. The ordered adapter registry maps a
discovered endpoint to one API family and capability; it never falls back to a
different mutation route.

## Boundaries

The four configured administrative endpoints keep their established mutation routes: Operations through Fleet, SDDC Manager and vCenter through the domain resource-certificate API, and the NSX Manager VIP through native `MGMT_CLUSTER`. VCF Automation adds a separately discovered Fleet-managed external TLS leaf. Internal Automation VMCA/runtime and all other ineligible records remain read-only, discovery-only, or unsupported.

`discover --all` performs Fleet inventory and live TLS inspection. `plan --all`
adds normalized capability and planned-action output. Neither command creates a
CSR, invokes ACME, imports material, replaces a certificate, or writes output.

## API families

- Operations uses Fleet certificate discovery, CSR, import, and replace APIs.
- VCF Automation selects only a fully managed External CA TLS leaf and uses the same Fleet lifecycle with strict resource/CSR identity checks.
- SDDC Manager and vCenter share the official domain-managed engine. It
  discovers dynamic domain/resource identifiers and polls returned tasks.
- Native NSX uses the `MGMT_CLUSTER` certificate profile for the cluster VIP.
  It never supplies a node ID or applies the node-scoped `API` profile.

Fleet inventory is advisory. The live HTTPS leaf obtained with SNI is the
authority for renewal timing and final activation. Missing inventory fields are
reported as unknown rather than treated as conflicts.

## Data flow

```text
inventory -> classify -> live plan -> VCF/NSX CSR -> lego/RFC2136 -> ACME
          -> validate/import -> explicit apply -> task polling -> HTTPS verify
```

VCF or NSX creates and retains the endpoint private key. `lego` receives the
public CSR and stores only its own ACME account key below `OUTPUT_DIR`. The
fullchain builder verifies issuer relationships and emits the ordering expected
by VCF.

Batch renewal plans all four configured endpoints and separately discovers the eligible Automation certificate. A configured-target planning failure aborts before mutation; absent or failed Automation discovery is reported without broadening scope or blocking unrelated configured targets. Approved, due targets then run independently in deterministic order.

See [renewal flow](renewal-flow.md), [authentication](authentication.md), and
[security](security.md) for operational details.

ACME directory selection and optional EAB are documented in the README.
EAB credentials are environment-only inputs to lego, excluded from Settings repr.
