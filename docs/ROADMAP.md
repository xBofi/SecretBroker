# Roadmap

What we plan to build next, roughly in priority order. Nothing here is a promise of dates. Ideas and help are welcome:
open a feature request or comment on the matching issue. The design rules stay the same for everything below: secrets
never reach the AI, the server never sees plaintext, and the user types a password once and approves with one click.

## Near term

### 0.20: everyday items and appearance
- Six personal types: cards, secure notes, identity documents, Wi-Fi, bank accounts and software licenses. The AI
  cannot list or use them. Bitwarden and CSV imports keep the supported personal data.
- Settings > Appearance: system/light/dark theme, seven palettes or a custom colour, four text sizes, compact
  density and reduced motion. Preferences apply immediately and survive a restart.
- English and Spanish website and guides, with screenshots of the current app. The source lives in `site-src/`;
  `python site-src/build.py` writes `site/` and `python tools/check_site.py site` checks its links and resources.

### Launch tasks that need the owner
1. Enable GitHub Pages in repository Settings > Pages > Source > GitHub Actions, then run the Pages workflow.
2. Follow [STORES.md](STORES.md) to upload extension drafts. Send back Chrome's Item ID and Edge's CRX ID; an app
   release must allow those IDs before either store submission. Firefox already has its stable ID.
3. Supply the public support/privacy contact and the store trader declaration. Review the privacy policy and
   any commercial terms before operating a hosted service.
4. Set up platform signing accounts and certificates as described in [RELEASING.md](RELEASING.md), then test on
   real Intel and Apple silicon Macs, including Touch ID once the app is signed.
5. Before offering managed hosting: choose the hosting and mail providers, configure monitored off-site backups,
   test restoration and incident response, and arrange an independent security review.

### First use and help
- Offer an everyday/developer usage profile so the first screen shows the controls each person needs.
- Link contextual help to the public guide and provide a diagnostic report that excludes secrets.
- Expand import compatibility with other password managers using real, sanitized export fixtures.

### Shipped in 0.16.0
- **Cross-platform desktop**: Windows, Ubuntu 22.04 / 24.04 and macOS 12+ through `secretbroker/platform`. Still to
  do on macOS: try it on real Macs, sign and notarize it (turns on Touch ID); see docs/RELEASING.md.
- **Internationalisation**: 32 languages in the app, the service's messages, the extension and the installer
  (docs/I18N.md explains how to add one).
- **Browser autofill** in Chrome, Edge, Brave and Firefox through native messaging. Still to do: publish it in the
  Chrome Web Store, Edge Add-ons and addons.mozilla.org.

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

### Mobile, deferred
iOS and Android apps to look up and copy shared credentials, approve requests from the desktop broker, and see
rotation and exposure alerts. Read-only at first.

## Later

- More providers with automatic rotation through their APIs, and dynamic short-lived credentials where providers
  support them (cloud roles, databases).
- Passkeys (TOTP codes and secure notes are already supported).
- Integrations to sync secrets into platforms (Vercel, Netlify, Fly.io, Kubernetes) and keep `used_in` up to date
  automatically.
- Signed Windows installer (Authenticode) and reproducible builds.
- Independent security audit.

## Open source and SaaS

SecretBroker is and stays open source under the MIT License. The hosted offering will run **the same server code**
that anyone can self-host. What the hosted offering adds is operational: managed hosting (backups and upgrades included),
SSO (OIDC) and SCIM provisioning, and support with response times. The **self-hosted server stays fully featured for teams**:
sharing, permissions, re-keying, audit events and policies are not held back to sell the hosted version.
