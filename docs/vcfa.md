# VCF Automation external TLS

## Observed Fleet representation (2026-10-06)

Read-only investigation used OAuth exchange, the inventory query and an
individual certificate GET, with API TLS verification enabled. No CSR was
created and no certificate was imported, renewed or replaced.

Inventory source: `POST /suite-api/api/fleet-management/certificate-management/certificates/query`
with an empty search body. This POST is a read-only query. The client reads all
pages using `pageInfo.totalCount`, `pageInfo.page` and the `page` query parameter.

| Field | External browser TLS record |
| --- | --- |
| `appliance` | `VCF_AUTOMATION` |
| `displayApplianceType` | `VCF Automation` |
| `vcfComponent` | `ARIA` (shared with other services; not a selector) |
| `category` / `categoryDisplayName` | `TLS_CERT` / `TLS Certificate` |
| `type` | `EXTERNAL_CA` |
| `certificateResourceKey` | Discovered UUID; CSR/import/replacement identity |
| `applianceFqdn` | `vcfa.example.com` (discovered DNS/SNI endpoint) |
| `vcfEndpoint` | Internal management endpoint; NOT the browser endpoint |
| `subjectAlternativeNames.dns` | Contains the external DNS endpoint |
| `expiryDate` / `daysToExpire` | Fleet inventory hints; live HTTPS controls renewal timing |
| `certificateMetadata.certificatePurpose` | `TLS_CERT` |
| `certificateMetadata.certificateChainRole` | `LEAF` |
| `certificateMetadata.managementLevel` | `CUSTOMER_MANAGED_FULL_MANAGEMENT` |
| `autoRenewState` / `autoRenewInfo.autoRenewStatus` | `NOT_SUPPORTED` |

The external record contained no fingerprint or per-action capability list.
`NOT_SUPPORTED` describes Fleet's built-in auto-renew status, not an advertised
CSR/import/replace capability. The operator reports a completed VCF 9.1.x
production validation: Fleet discovery and CSR generation, ACME signing,
certificate import, replacement workflow `COMPLETED`, and live HTTPS verification
all succeeded for the discovered Automation endpoint (represented here as
`vcfa.example.com`); the served certificate was issued by Let's Encrypt YR1.
The operator reports that after the retained-CSR fix, the targeted plan for that
endpoint and `plan --all` both succeeded. A later live mutating scheduled `renew --all`
has not been run. The internal Automation VMCA endpoint remained unchanged during
the completed replacement validation.

A certificate detail response may use the `ARIA_AUTOMATION` appliance enum and
`applianceIp` instead of the inventory query's `applianceFqdn`. Both known
Automation appliance enums are recognized; the endpoint is taken from a DNS
identity field, never guessed from an internal endpoint or display label.

## Selection and execution

The semantic candidates must be Automation + External CA + TLS + leaf + TLS
purpose. Exactly one candidate is required, with full-management metadata, a
valid DNS endpoint and a resource key. VMCA root and internal VMCA TLS records
cannot match. Missing candidates produce NOT_DISCOVERED. Multiple candidates
fail Automation without guessing; unrelated batch renewals continue.

The selected external record normalizes as `managementPath=FLEET_MANAGED` and
`renewalCapability=FULL_RENEW`. Internal runtime-managed Automation records
normalize as `RUNTIME_MANAGED` and `DISCOVER_ONLY`. That classification is
independent of the shared `ARIA` component label; the appliance enum, external
CA type, TLS category, leaf role, TLS purpose and full-management metadata are
all required for the mutable path.

Operations is the closest existing component. Automation reuses its Fleet
client, orchestration, ACME/lego signer, RFC2136/TSIG provider, full-chain builder,
importer, replacement workflow polling and live verifier. The selected resource
key is passed between phases and rechecked against refreshed semantic inventory
before CSR creation, import and replacement. Changed identity aborts the flow.

The Fleet CSR GET is queried with the selected certificate resource and common
name, but its `certificateId` filter is only a hint: retained CSR history may be
returned after replacement changes the active `certificateResourceKey`. VCFA
reuse therefore requires a CSR record with the exact current resource identity,
matching Automation appliance identity and `applianceFqdn`, and a CSR whose DNS
SAN names the discovered endpoint. Records for prior resource keys, another
appliance/endpoint, or missing identity are historical/non-reusable and are
ignored during planning and CSR preflight. A fresh CSR is generated instead.
Multiple fully matching candidates remain an ambiguity and fail safely, and the
CSR fetched after generation undergoes the same strict identity and SAN checks.

The supported paths are:

1. `POST .../certificate-management/csrs`, passing discovered `certificateId`.
2. `GET /suite-api/api/workflows/requests/{requestId}` and
   `GET .../certificate-management/csrs` to fetch the matching CSR.
3. Existing ACME signing of the Fleet CSR; no locally generated VCFA private key.
4. `POST /suite-api/api/certificate` to import the validated signed chain.
5. `PUT .../certificate-management/certificates/{certificateId}` with
   `caType=EXTERNAL_CA` and `certificateChain`, then workflow polling.
6. Live HTTPS on discovered FQDN:443 must serve the exact expected leaf. The
   existing verifier retries activation lag and compares DNS SANs, subject,
   issuer, validity and SHA-256 fingerprint. Import additionally requires the
   endpoint DNS SAN and CSR public-key equality. No post-change Fleet refresh
   is required for success.

The excluded cloudapi certificate-library interface is not used. Internal
Automation Runtime/Kubernetes/VMCA roots and TLS certificates, SAML signing or
encryption certificates, Broadcom signing certificates and trust anchors are
out of scope. No scheduler or TLS verification policy is changed by VCFA support.

## Validation and remaining uncertainties

Failures identify their workflow phase and list Fleet mutations already
confirmed. A failed signing attempt after CSR creation reports the CSR and does
not claim that replacement occurred. If a mutating request times out before a
response, the result marks its outcome as unknown and advises workflow inspection;
no automatic rollback or account recreation occurs. Lego diagnostics are bounded
and redact configured TSIG, EAB, token and password values. An
`accountDoesNotExist` diagnostic asks the operator to inspect ACME account state.

Tests run in the existing test image with `--network none`, read-only repository
mount, dropped capabilities and no host production configuration. Mutating APIs,
ACME/DNS and live HTTPS are mocked. Tests cover discovery, internal exclusions,
hostname independence, absence, ambiguity, pagination, threshold/force, batch
participation, approval, CSR resource rotation with retained history, batch retry
behavior, and every renewal failure stage. Existing component and security tests
remain part of the full suite. Offline fixtures also verify internal
`automation-internal.example.com` and Automation VMCA protection. No production
endpoint was contacted during this release-preparation task.

Primary API contracts:
- [Inventory query](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/certificates/query/post/)
- [Generate CSR](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/csrs/post/)
- [Replace certificate](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/certificates/certificateId/put/)
