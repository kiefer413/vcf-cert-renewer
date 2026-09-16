# Authentication

Use one dedicated, non-interactive, least-privilege service account.

- Operations and native NSX use `VCF_API_TOKEN`. The token is exchanged at
  `VCF_TOKEN_ENDPOINT` for a short-lived bearer token. NSX accepts that VCF
  Identity Broker token; the client does not fall back to Basic/session auth.
- SDDC Manager and the domain-managed vCenter path use `SDDC_USERNAME` and
  `SDDC_PASSWORD` with `POST /v1/tokens`. The returned access token is kept in
  memory for the process.

Store credentials only in the root-owned production environment file or an
equivalently protected secret store. Do not put credentials in YAML, command
arguments, logs, issues, fixtures, or Git. TLS verification defaults to enabled;
disable it only for a controlled test environment.
