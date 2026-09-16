# Security Policy

## Supported versions

Security fixes are provided for the latest release line.

## Reporting a vulnerability

Do not open a public issue containing credentials, private infrastructure data,
or exploit details. Use GitHub's private vulnerability reporting feature for
the repository. Include the affected version, impact, reproduction steps, and a
minimal sanitized example. Maintainers should acknowledge a complete report
within seven days and coordinate disclosure after a fix is available.

Immediately rotate any VCF token, password, TSIG secret, or ACME account key
that may have been disclosed. Removing a value from the current tree does not
remove it from Git history.
