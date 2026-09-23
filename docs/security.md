# Security Model

- Endpoint private keys are generated and retained by VCF or NSX.
- The ACME account key and generated public artifacts live under `OUTPUT_DIR`,
  which must be root-only and is ignored by Git.
- RFC2136 credentials are passed to `lego` through its process environment,
  never command arguments.
- Production configuration is a root-owned mode `0600` environment file.
- TLS verification is enabled by default.
- Planning is read-only; production mutation requires explicit approval.
- Mutation requests are not automatically replayed after ambiguous failures.
- Exact API families and component capabilities prevent fallback or accidental
  expansion to internal certificate classes.
- `VCF_RENEW_TARGETS` accepts exactly four unique names; each still has to map
  to one of the four validated FULL_RENEW adapters.

Rotate credentials after suspected exposure. If a real secret entered Git
history, treat it as compromised and publish only a clean history.

EAB KID and HMAC are supplied together through root-only configuration. They are
passed to lego through environment variables, excluded from Settings repr and
command arguments. Captured signing output is suppressed on errors.
