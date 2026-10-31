# Changelog

What changed for people who use SecretBroker. The commit history has the details.

## 0.16.0 (2026-10-31)

The biggest release so far: SecretBroker leaves Windows, speaks 32 languages, fills logins in the browser and
shares credentials with your team, end-to-end encrypted.

### Windows, Ubuntu and macOS
- **Ubuntu 22.04 / 24.04**: `secretbroker_0.16.0_amd64.deb`, installed with a double click in the software installer.
  The service runs as its own `secretbroker` system user, each person's vault lives in `/var/lib/secretbroker/<user>`,
  and the app updates the package itself.
- **macOS 12+** (Apple silicon and Intel): `SecretBroker-0.16.0-macos-<arch>.pkg`. Keychain, Touch ID, lock screen
  detection and a menu bar icon. Built and installed by CI but not yet tried on real Macs, and unsigned until the
  project has an Apple Developer account: macOS asks you to confirm the first install, and Touch ID stays off
  (you use the Mac or master password once per session, then one click).
- Windows behaves exactly as before.

### Your language
- The app, the service's messages, the browser extension and the Windows installer are translated. 32 languages:
  English, Spanish, Catalan, Galician, Basque, German, French, Italian, Portuguese, Dutch, Danish, Swedish,
  Norwegian Bokmål, Finnish, Polish, Czech, Slovak, Slovenian, Croatian, Hungarian, Romanian, Bulgarian, Greek,
  Estonian, Latvian, Lithuanian, Irish, Maltese, Russian, Ukrainian, Turkish and Simplified Chinese.
- It follows your system's language; **Settings › Language** changes it. Dates, times, numbers and plurals follow
  the language too («12 345», «1:35 PM»), and the layout holds in long languages like German and Finnish.
- The Windows installer speaks English or Spanish depending on Windows, without asking.

### Browser autofill
- A SecretBroker extension for **Chrome, Edge, Brave and Firefox** fills logins and 2FA codes: a button in login
  fields, a toolbar popup, **Ctrl+Shift+L** to fill and **Ctrl+Shift+Y** for the popup, and «Save this login?» after
  you sign in somewhere new or change a password.
- Phishing resistant: a login is only offered on the site it was saved for (registrable domain), never on page load,
  never into hidden fields or frames of another site. Team credentials marked «use only» are never filled.
- It talks to the app through native messaging, never a network port. Connect it from **Settings › Browser** with
  one click (the app and the extension show the same 6-digit code). Until the extension is in the stores it is
  loaded from the app's folder; Settings › Browser walks you through it.

### Teams (preview)
- Organizations, shared collections and per-person permissions (manage, edit, view, use-only), synced through a
  **zero-knowledge server** you can host yourself with Docker (`server/`). The server never sees a secret, a
  credential name or a collection name.
- When someone leaves, the collection is re-keyed and every credential they could see is flagged for rotation.
- Invites only reach verified e-mail addresses; member lists, edits and deletions are signed by whoever made them;
  many deletions at once wait for your decision; organization owners can always recover a collection; the people
  you verify are trusted on all your PCs.
- A teammate's change that widens where a key can go, rewrites the notes your AI reads, or adds a new web address
  for a shared login waits until you accept it.

### The personal vault
- Password generator (Ctrl+G), including passphrases.
- **Health**: a 0–100 score and what to fix first (weak, reused, old, expired or exposed passwords).
- Import from Bitwarden, 1Password, KeePass / KeePassXC, Chrome, Edge and Firefox, with a preview and a filter for
  developer keys. Export to an encrypted file, or to JSON / CSV after a clear warning.
- Real 2FA codes (TOTP) and private notes the AI never sees.
- «Connect your AI» connects Claude Code and Claude Desktop with one click.

### Approvals and everyday use
- Your master password once per session, then one click. Approvals say which AI is asking, for which credential and
  why.
- The list stays fresh when the AI or a teammate changes something, and two edits to the same credential no longer
  overwrite each other silently.
- Rotations resume where they stopped, and database passwords can be applied by the service.
- A redesigned interface: one design system across the vault, Health, rotation, Team, AI access and Activity.

### Security
- Team cryptography reviewed: no trust on first sight, re-keys only to verified people, signed authors in Activity,
  proven approvals for destructive AI actions.
- An organization's invite code no longer verifies an e-mail for other people's invites.
- Autofill only sends a login to the exact origin the service matched.
- macOS: root and the service never run code from `/Applications`. Linux: the service's token stays yours, shared
  with the service through a group.
- Every GitHub Action in the release workflow is pinned to a commit, since those jobs hold the update signing key.
- Updates on every system are verified against the pinned Ed25519 release key before they install.

### Still needs the project owner's accounts
- The browser extension in the Chrome Web Store, Edge Add-ons and Firefox Add-ons (one-click install; Firefox keeps
  unsigned extensions only until it restarts).
- A signed and notarized macOS package (Apple Developer Program), which also turns on Touch ID.
- An Authenticode certificate, so SmartScreen stops warning about the Windows installer.
- A hosted team server. Today you host your own; e-mail verification codes need an SMTP server (`SB_SMTP_*`),
  otherwise the server's admin verifies accounts.
