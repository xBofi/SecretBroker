# SecretBroker

**English** · [Español](README.es.md)

SecretBroker lets AI agents **use** your API keys, passwords and server logins **without ever seeing them**. Claude Code
(or any MCP client) asks to call an API, run `psql` or SSH into a server; SecretBroker injects the credential, runs the
operation in an isolated service and redacts the secret from everything that comes back. Your team can share those
same credentials **end-to-end encrypted** through a zero-knowledge server you can host yourself, and SecretBroker
helps you keep them healthy: it finds keys that leaked into chat logs and shell history, tells you when one stops
working, and walks you through rotating it everywhere it is used.

```
 You (SecretBroker app)                SecretBroker service                Internet / servers
 - store keys from templates   ──▶    (separate Windows account)    ──▶   HTTPS · SSH · CLIs
 - approve with one click             - encrypted vault                    with the key injected
                                      - verifies your Hello signature
 AI ── MCP: "use 'github'" ─────▶    - runs it and redacts output  ◀──   response without secrets
```

> **Status.** SecretBroker Desktop runs on **Windows 10/11** and **Ubuntu 22.04 / 24.04**; the **macOS 12+** port
> (Apple silicon and Intel) is built and installed by CI but not yet tried on real Macs (see
> [docs/RELEASING.md](docs/RELEASING.md)). The app, the browser extension and the service's messages are in
> **32 languages**: English, Spanish, Catalan, Galician, Basque, German, French, Italian, Portuguese, Dutch, Danish,
> Swedish, Norwegian, Finnish, Polish, Czech, Slovak, Slovenian, Croatian, Hungarian, Romanian, Bulgarian, Greek,
> Estonian, Latvian, Lithuanian, Irish, Maltese, Russian, Ukrainian, Turkish and Simplified Chinese. It follows your
> system's language; Settings › Language changes it. The team server runs anywhere Docker runs. What changed in each
> version: [CHANGELOG.md](CHANGELOG.md).

## Screenshots

_Coming soon: vault list, one-click AI approval, guided rotation wizard, exposure report, team sharing._

<!-- Put images in docs/img/ and reference them here, e.g. ![Vault](docs/img/vault.png) -->

## Install

1. Download `SecretBroker-Setup-<version>.exe` from the [latest release](https://github.com/xBofi/SecretBroker/releases/latest).
2. Run it and accept the administrator prompt. No command line, no internet connection and no Python install needed.

The installer puts the app in `C:\Program Files\SecretBroker` (writable only by administrators), creates a hidden
`SecretBroker` Windows account that cannot log in, stores the vault in a folder only that account can read, starts the
service with Windows and connects Claude Code and Claude Desktop if they are installed.

**Updates** are one click: the app checks GitHub Releases every few hours, downloads the new installer, verifies its
Ed25519 signature and only then installs it. Your vault and settings are kept. Uninstall from Windows "Installed apps";
it asks whether to delete the vault (the default is to keep it).

> The installer is not Authenticode-signed yet, so Windows SmartScreen may warn ("More info" → "Run anyway").

### Ubuntu

1. Download `secretbroker_<version>_amd64.deb`.
2. Double-click it and choose **Install** in the software installer (it asks for your password once).

The package installs to `/opt/secretbroker` (with its own Python, so 22.04 works too), creates a `secretbroker` system
user that cannot log in, keeps each user's vault in `/var/lib/secretbroker/<user>` where only that user's service can
read it, and starts the service (`secretbroker@<user>.service`) at boot. Open **SecretBroker** from the app grid. The
icon next to the clock needs the AppIndicator extension, which Ubuntu enables by default. Removing the package keeps
the vaults; purging deletes them. To build the package yourself: `tools/build_deb.sh` on Linux or WSL.

### macOS (preview)

1. Download `SecretBroker-<version>-macos-arm64.pkg` (Apple silicon) or `-macos-x86_64.pkg` (Intel).
2. Open it and follow the installer.

Until the package is signed with the project's Apple Developer ID, macOS says it "cannot be verified": right-click it
and choose **Open**, or allow it in **System Settings › Privacy & Security**. Touch ID also needs the signed app;
until then you unlock with your Mac or master password once per session, then approve with one click. The service
runs under its own hidden user, from a copy of the code that only root can change.

### Browser extension

Until the extension is published in the browser stores, it is loaded from the app's folder, with no terminal:

1. In the app, open **Settings › Browser** and click **Install the extension**. It opens your browser's extensions
   page and the folder.
2. **Chrome, Edge, Brave**: turn on *Developer mode*, click *Load unpacked* and pick the folder.
   **Firefox**: `about:debugging` › *This Firefox* › *Load Temporary Add-on…* › `manifest.json`, and allow access to
   all sites from the extensions button. Firefox forgets it when it closes until the extension is on addons.mozilla.org.
3. Click the SecretBroker button in the toolbar and press **Connect**: the app shows the same 6-digit code and
   connects it with one click.

## Quick start

1. **Create your vault.** Pick a master password. Optionally enable Windows Hello (PIN, fingerprint, face) and
   "open with my Windows session" so you never type it again on this PC.
2. **Add a credential** from a template (website, API key, SSH server, database, AWS, other secret). Known providers
   (OpenAI, Anthropic, GitHub, Stripe, Cloudflare…) fill in the URL, auth header and environment variable for you.
3. **Ask your AI to use it.** For example: _"List my open GitHub issues using the `github` credential."_ The first time,
   SecretBroker pops up and you approve with one click ("allow today" lasts 24 h by default).
4. **Move a project's `.env` into the vault**: in the app, *Import a project's .env* (pick the file, tick its keys,
   one click, then take them out of the file). From a terminal, or by asking your AI (it never prints values):
   ```
   sb import .env --delete     # stores the keys, writes a .secretbroker file you can commit
   sb run -- npm run dev       # your app gets the variables straight from the vault
   ```

## Features

### AI broker
- MCP tools (`http_request`, `ssh_exec`, `run_command`, `push_github_secret`…) let the AI act with a credential but
  never return its value. Output is redacted: literal text, base64, URL encoding, JSON and connection strings.
- Per-credential allow-lists: which domains (HTTPS only, no redirects), which local programs and which environment
  variables a key may reach.
- One-click approvals with a presence check (Windows Hello signature over a single-use challenge). One request per task
  (`request_access`), "allow today", unusual-use limits, "pause the AI" kill switch, and per-action levels for what the
  AI may change (free, notify, ask, never).
- AI-readable notes per credential, so the agent knows what each one is for without seeing it.
- `sb run`, `sb import`, `sb check`: run your own apps with secrets from the vault instead of a `.env` file.

### Browser autofill
- An extension for Chrome, Edge, Brave and Firefox fills logins and 2FA codes, only on the site each one was saved
  for (registrable domain, so lookalike phishing domains get nothing) and only after your click or Ctrl+Shift+L.
  It offers to save new and changed passwords, never fills team credentials marked "use only", and talks to the
  app through native messaging (no open port). Install and connect it from Settings › Browser (see
  [Browser extension](#browser-extension)).

### Rotation
- One-click rotation through the provider API where possible (Cloudflare, GitLab), re-uploading the new key to the
  GitHub Actions secrets it was pushed to.
- **Guided rotation** for everyone else: where to create the new key (direct link and suggested name), test it against
  the provider **before** replacing the old one, update every place it is used (`used_in`: dev, staging, prod, Vercel,
  CI…), then confirm the old key is really dead.
- Database passwords: generates a safe password and gives the exact command for PostgreSQL, MySQL, SQL Server, MongoDB
  or Redis (or the managed provider's console link). Paired identifiers (OAuth client ids, app ids) are kept in sync.
- Rotation reminders per credential or globally, expiry warnings, and AI-researched rotation guides for unknown providers.

### Exposure
- A traffic light per credential: is it still only in the vault?
- Scans Claude Code and Codex transcripts, PowerShell/bash history, app configs (`.claude.json`, `.npmrc`, `.aws`,
  `.ssh`…), environment variables, project folders and their git history for your secrets, including JSON, URL and
  base64 forms. Incremental after the first run.
- Liveness checks with read-only calls to the provider (configurable schedule): if a working key suddenly stops working,
  it was probably revoked after a leak.
- Have I Been Pwned password checks by k-anonymity (only 5 hex characters of the SHA-1 leave your PC).

### Teams (preview)
- Organizations, shared collections and per-member permissions (`manage`, `edit`, `view`, `use`: the AI can use it, you
  cannot reveal it).
- **End-to-end encrypted**: the server never sees a secret, a credential name or a collection name.
- Key pinning with fingerprints, signed key grants, automatic re-keying when someone leaves, and every credential they
  could see flagged "rotate: <person> had access" in the rotation wizard.
- Teammates' changes that widen where a key can go, or rewrite the description your AI reads, are quarantined until
  you accept them with one click.
- Member lists, edits and deletions are signed by whoever made them: a hostile server can't add people, forge changes
  or delete credentials, and Actividad names who changed what. Many deletions at once wait for your decision.
- Invites only reach verified e-mail addresses; organization owners can always recover a collection; the people you
  verify are trusted on all your PCs.
- Shared credentials work with the AI broker, `sb run`, exposure checks and rotation exactly like personal ones.

### Everyday
- Backups of the encrypted vault to a folder of your choice (OneDrive by default), restorable on a new PC.
- Tray icon, auto-start, keyboard shortcuts, clipboard cleared after 30 s and kept out of Windows clipboard history.
- Tags, expiry dates, activity history (encrypted, readable only when unlocked).

## How it compares

Honest summary as of late 2026. The big products are mature and broad; SecretBroker is young and focused.

| | Best at | Where SecretBroker is different | Where SecretBroker is behind |
|---|---|---|---|
| **1Password** | Polished password manager on every platform, browser autofill, passkeys, Watchtower, `op run` and service accounts for developers | AI agents use keys without reading them, with output redaction; guided rotation that tracks every place a key is used; local leak scanning of AI transcripts and shell history; open source and self-hostable | macOS maturity, browser extension not yet in the stores, mobile apps, passkeys, integrations, maturity, audits |
| **Bitwarden** | Open-source password manager, self-hostable, cross-platform, Secrets Manager for machines | Same AI broker, rotation and exposure angle; one-click approvals designed around AI agents | Mobile, extension stores, enterprise features (SSO, SCIM, policies), independent security audits |
| **Doppler** | Hosted secrets for apps and CI with many sync integrations and environments | Local-first vault; AI broker; personal credentials (logins, SSH) as well as app secrets; self-hostable | Hosted SaaS convenience, number of integrations, environments and config inheritance, automatic sync to platforms |
| **Infisical** | Open-source secrets platform for teams and infrastructure: environments, Kubernetes/CI integrations, dynamic secrets, secret scanning | AI broker with redaction; desktop app built for one person approving an AI; guided rotation for providers without APIs | Infrastructure integrations, environments, machine identities, Kubernetes operator, dynamic secrets, scale |
| **HashiCorp Vault** | Infrastructure secrets at scale: dynamic credentials, leasing, PKI, transit encryption, policies | Easy for an individual developer: install an `.exe`, one-click approvals, no cluster to run; AI broker | Almost everything infrastructure: dynamic secrets, PKI, HA, auth backends, policy language |

Where SecretBroker fits: you work with AI coding agents, you have a pile of API keys and server logins, and you want
the agent to be productive without your keys ending up in a transcript, plus a simple way to share them with your team
and rotate them when someone leaves.

## Self-hosting the team server

The team server is a small Python service (Starlette + SQLite) that only stores ciphertext and public keys. Run it with
Docker Compose; Caddy obtains HTTPS certificates automatically:

```
cd server
docker compose up -d
```

See [server/README.md](server/README.md) for configuration (`SB_PUBLIC_URL`, `SB_SIGNUPS`, `SB_ADMIN_EMAILS`…),
backups and upgrades. The design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security model

- The vault is AES-256-GCM with a random data key wrapped by scrypt (128 MiB) of your master password and by Windows
  DPAPI.
- The service runs under a separate account (a hidden Windows account, the `secretbroker` user on Ubuntu, a hidden
  user on macOS) from code only administrators can change, run with `python -I`, so programs in your session
  (including the AI) cannot read its memory, files or code.
- Unlocks and approvals require a Windows Hello (or Touch ID) signature over a single-use challenge bound to that
  operation, or the system or master password where there is none. Service responses are signed (Ed25519) so the app
  cannot be spoofed.
- Browser autofill only offers a login on the site it was saved for and only sends it to the exact origin the service
  matched; a teammate's new web address for a shared login waits for your review.
- AI operations never return values; output is redacted; keys only go to allow-listed HTTPS hosts or programs.
- Team sharing is end-to-end encrypted (X25519 + AES-256-GCM, pinned fingerprints, Ed25519-signed key grants, member
  lists, edits and deletions). A fully compromised server leaks e-mails, organization names, membership and
  timestamps, not credentials, and cannot forge who is in a collection or what it contains. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Updates are verified against a pinned Ed25519 release key.

**Known limits.** Anything that passes through your desktop is visible to programs in your session (clipboard, keyboard,
fake windows), as with any password manager. Programs you allow in `run_command` and `sb run` receive the key in
clear. The `use` permission for teams is enforced by the client, so a teammate running a modified client could extract
a key they can use. Never run your AI agent as administrator.

Read the full [threat model](docs/THREAT_MODEL.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Roadmap

macOS on real hardware (signed and notarized), the browser extension in the Chrome, Edge and Firefox stores, a hosted
team server, CLI client with machine identities for CI and servers, OIDC SSO and SCIM, Postgres, organization-wide policies and a read-only mobile app.
Details in [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, tests and code style, and
please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © 2026 xBofi
