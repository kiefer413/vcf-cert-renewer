# Renewal Flow

1. Inspect the live SNI certificate and evaluate `RENEW_BEFORE_DAYS`.
2. Resolve the endpoint to exactly one supported adapter and API route.
3. Ask VCF or NSX to generate a CSR; its private key stays in the product.
4. Submit the CSR to ACME and satisfy DNS-01 through restricted RFC2136 updates.
5. Build and cryptographically validate the certificate chain.
6. Validate/import the chain without changing the active certificate.
7. After explicit production approval, apply the selected imported certificate.
8. Poll bounded workflow state and verify the exact live HTTPS leaf.

`renew --all` completes step 1 for all four targets before any later step. A
planning error results in zero mutations. A per-target renewal error is recorded
and does not redirect work to another component or API family.
