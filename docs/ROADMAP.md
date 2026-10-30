# Roadmap

What we plan to build next, roughly in priority order. Nothing here is a promise of dates. Ideas and help are welcome:
open a feature request or comment on the matching issue. The design rules stay the same for everything below: secrets
never reach the AI, the server never sees plaintext, and the user types a password once and approves with one click.

## Near term

### Cross-platform desktop
The core (vault, broker, redaction, rotation, exposure, teams) is plain Python. `secretbroker/winsec.py` (service
account isolation, DPAPI, ACLs) and `secretbroker/hello.py` (Windows Hello presence) are the only Windows-specific
modules. They become a **platform interface** with implementations for:
- macOS: Keychain, Touch ID / Secure Enclave presence, a launchd daemon under its own user;
- Linux: Secret Service / kernel keyring, polkit or FIDO2 presence, a systemd service under its own user.

### Internationalisation
The interface is Spanish today. Move the strings in `secretbroker/web/app.js` and the service's user-facing messages
into translation catalogues, ship **English** first, and make adding a language a pull request with one file.

### Browser extension for autofill
Fill logins from the vault in Chromium and Firefox through native messaging to the local service, with the same
per-credential domain allow-list the AI broker uses. Phishing resistance by exact origin matching.

### CLI client with machine identities
A headless `sb` for CI runners and servers that reads a team collection with a **machine identity** (a service account
with its own key pair and `use` permission), so pipelines and servers get secrets without a desktop or a personal
account. Includes `sb run` and `sb export --format env` for platforms that need files.

### Team features for organizations
- **OIDC single sign-on** and **SCIM** provisioning, so joining and leaving the company drives membership (and the
  re-key and "rotate: <person> had access" flow).
- **Postgres** backend for the server (the SQL is already kept Postgres-compatible) for larger and highly available
  deployments.
- **Organization-wide policies**: minimum rotation period, maximum AI permission levels, required approvals for
  sensitive collections, allowed domains, exposure scanning on by default.

### Mobile, read-only
iOS and Android apps to look up and copy shared credentials, approve requests from the desktop broker, and see
rotation and exposure alerts. Read-only at first.

## Later

- More providers with automatic rotation through their APIs, and dynamic short-lived credentials where providers
  support them (cloud roles, databases).
- Passkeys, TOTP codes and secure notes.
- Integrations to sync secrets into platforms (Vercel, Netlify, Fly.io, Kubernetes) and keep `used_in` up to date
  automatically.
- Signed Windows installer (Authenticode) and reproducible builds.
- Independent security audit.

## Open source and SaaS

SecretBroker is and stays open source under the MIT License. The hosted offering will run **the same server code**
that anyone can self-host. What the hosted offering adds is operational: managed hosting (backups and upgrades included),
SSO (OIDC) and SCIM provisioning, and support with response times. The **self-hosted server stays fully featured for teams**:
sharing, permissions, re-keying, audit events and policies are not held back to sell the hosted version.
