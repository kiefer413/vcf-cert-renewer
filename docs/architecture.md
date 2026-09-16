# Architecture

VCF Certificate Renewer separates inventory, target classification, certificate
lifecycle work, and live verification. The ordered adapter registry maps a
discovered endpoint to one API family and capability; it never falls back to a
different mutation route.

## Boundaries

Only four browser-facing endpoints have mutation authority: Operations through
Fleet, SDDC Manager and vCenter through the domain resource-certificate API,
and the NSX Manager VIP through native `MGMT_CLUSTER`. All other records remain
read-only, discovery-only, or unsupported.

`discover --all` performs Fleet inventory and live TLS inspection. `plan --all`
adds normalized capability and planned-action output. Neither command creates a
CSR, invokes ACME, imports material, replaces a certificate, or writes output.

## API families

- Operations uses Fleet certificate discovery, CSR, import, and replace APIs.
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

Batch renewal plans all four configured endpoints before any mutation. A
planning failure aborts the batch. Approved, due targets then run independently
in deterministic order so one target failure cannot broaden scope.

See [renewal flow](renewal-flow.md), [authentication](authentication.md), and
[security](security.md) for operational details.
