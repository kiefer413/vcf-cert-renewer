# v1.2.0

## v1.3.0

- Central `_FILE` secret resolution with safe errors and strict conflict handling.
- systemd Credentials examples; backward-compatible direct environment settings.
- Non-root batch container, controlled dependencies and lego 5.4.1 for amd64/arm64.
- Docker/Podman/Compose examples and gated GHCR release workflow.
- Offline secret, container and release regression checks.
- Existing VCF/NSX authentication and FULL_RENEW scope remain unchanged.

- Generic ACME v2 directory selection with optional EAB account registration.
- Preserve explicit-server precedence, legacy ACME_MODE and staging defaults.
- Validate EAB pairs early; keep credentials out of argv, repr and signing errors.
- Accept DNSUPDATE_TSIG_KEY_NAME without changing the existing TSIG key setting.
- Verify generic certificate chains and document provider support boundaries.
- Preserve four-target renewal scope, authentication and systemd behavior.

# Changelog

## 1.1.0 - 2026-09-16

- Prepare the first public open source release with neutral examples and a
  clean public history.
- Add Apache-2.0 licensing, contribution, security, conduct, and GitHub files.
- Add credential-free CI and a regression scan for known private markers.
- Expand public architecture, authentication, support, renewal, security, and
  troubleshooting documentation.
- Keep FULL_RENEW scope exactly limited to Operations, SDDC Manager, vCenter,
  and the native NSX Manager `MGMT_CLUSTER` VIP.
- No change to the core certificate renewal behavior.

## 1.1.0

- Fix the packaged systemd service to use the available `/usr/bin/python3`.
- Simplify the recommended production deployment to one root-only environment file.
- Retain YAML configuration as an optional advanced and backwards-compatible path.
- Remove unused OAuth client credentials from recommended examples while retaining
  parser compatibility; v1 authentication uses API-token exchange and SDDC credentials.
- No change to the four production-validated VCF component targets.

## 1.0.1

- Centralize layered configuration with precedence CLI, environment, secrets file,
  YAML configuration, then safe built-in defaults.
- Add production examples and hardened systemd service/timer packaging for daily
  unattended checks.
- Preserve the existing .env/environment workflow and 30-day renewal threshold.
- No change to the four production-validated VCF component targets.

## 1.0.0 - 2026-09-14

- Declare the production-validated v1 scope: Operations, SDDC Manager, vCenter,
  and the NSX `MGMT_CLUSTER` VIP.
- Add safe batch renewal with plan-first behavior, explicit production approval,
  deterministic per-target summaries, and non-zero partial-failure exit status.
- Add daily systemd service/timer examples without forced renewal or embedded secrets.
- Retain the 30-day configurable renewal threshold and all single-target commands.
- Keep NSX node/API and internal VCF trust/TLS certificates outside mutation scope.
