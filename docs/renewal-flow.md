# Renewal Flow

1. Inspect the live SNI certificate and evaluate `RENEW_BEFORE_DAYS`.
2. Resolve the endpoint to exactly one supported adapter and API route. For Automation, select only the fully managed external CA TLS leaf from Fleet metadata.
3. Ask VCF or NSX to generate a CSR; its private key stays in the product.
4. Submit the CSR to ACME and satisfy DNS-01 through restricted RFC2136 updates.
5. Build and cryptographically validate the certificate chain.
6. Validate/import the chain without changing the active certificate.
7. After explicit production approval, apply the selected imported certificate.
8. Poll bounded workflow state and verify the exact live HTTPS leaf.

`renew --all` completes the expiry plan for all four configured targets and separately discovers eligible VCF Automation external TLS before any later step. A configured-target planning error results in zero mutations; Automation discovery failures are isolated from unrelated configured targets. A per-target renewal error does not redirect work to another component or API family.
