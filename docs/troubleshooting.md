# Troubleshooting

- **OAuth failures:** verify the token endpoint, token validity, system clock,
  and service-account roles.
- **SDDC authentication:** verify `SDDC_USERNAME`, `SDDC_PASSWORD`, and account
  permissions. The VCF API token is not used as an SDDC password.
- **Empty/ambiguous discovery:** confirm the exact FQDN and Fleet visibility.
- **DNS-01:** verify public delegation, TCP/UDP 53 reachability, TSIG name,
  algorithm, secret, and narrow update policy.
- **CSR task succeeds but no CSR appears:** allow the built-in bounded inventory
  propagation retries; the tool does not create a second CSR automatically.
- **Import fails:** confirm the leaf identity and CSR public key match.
- **Apply/verification fails:** inspect task state, DNS/SNI, certificate chain,
  and activation delay. Do not blindly repeat a mutation.
- **Interrupted after import:** select the already imported certificate by its
  SHA-256 thumbprint, then run explicit replace and verify commands.

Run `plan <fqdn>` first. It reports `No changes have been made.` and provides
the safest diagnostic snapshot.
