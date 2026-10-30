# Security policy

SecretBroker holds people's credentials, so we take reports seriously and are grateful for them.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub: go to the repository's **Security** tab → **Report a vulnerability**
([direct link](https://github.com/xBofi/SecretBroker/security/advisories/new)). Include:

- the affected version (Settings in the app, or `secretbroker/__init__.py`) and component (desktop, team server, installer);
- steps to reproduce or a proof of concept, using fake credentials only;
- the impact you expect (what an attacker gains, and from which position: AI agent, local program, teammate, server…).

What to expect:

- acknowledgement within **3 working days**;
- an initial assessment within **10 working days**;
- a fix and a published advisory as fast as the severity requires; we will agree a disclosure date with you and credit
  you unless you prefer otherwise.

## Scope

In scope:

- **SecretBroker Desktop** (`secretbroker/`): the service, the app, the MCP server, `sb`, redaction, approvals,
  account isolation, vault encryption, exposure scanning, rotation, updates.
- **SecretBroker Server** (`server/`): authentication, authorization between organizations and collections, anything
  that lets the server or another user learn secrets, keys or names they should not.
- **Installer and release pipeline** (`installer/`, `tools/`, `.github/workflows/`): anything that lets an unsigned or
  tampered build be installed.

Especially interesting: an AI agent obtaining a secret value through an MCP tool, bypassing an approval or a policy
allow-list; a process in the user's session reading the vault or service memory without elevation; a team server or
teammate obtaining plaintext or forging a key grant.

Out of scope (see the limits in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):

- attacks that need administrator/SYSTEM rights on the user's PC, or physical access to an unlocked PC;
- programs the user explicitly allowed in `run_command` / `sb run` reading the key they were given;
- keyloggers, screen or clipboard capture in the user's session;
- a teammate with a modified client extracting credentials they have `use` permission on;
- metadata the team server is documented to see (e-mails, organization names, membership, timestamps);
- denial of service against a self-hosted server you run, missing hardening headers without a concrete impact,
  and reports from automated scanners without a demonstrated issue.

## Supported versions

SecretBroker is young and moves fast. Security fixes are made on the **latest release** only; the app updates itself
with one click, so please update before reporting. The team server follows the same rule: run the latest image.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No |

## Release integrity

Installers are signed with an Ed25519 release key held only by the maintainers (as a GitHub Actions secret); the
public key is pinned in `secretbroker/update.py` and checked before any update is installed. If you believe the
release key or pipeline is compromised, report it as above.
