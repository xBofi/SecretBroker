# Changelog

What changed for people who use SecretBroker. The commit history has the details.

## Unreleased

### Nobody on a team loses access for good
- **Recovery code for the team account.** Creating an account shows a recovery code once (30 letters and digits)
  with «Copiar», «Guardar como archivo» and «Guardar en mi bóveda personal» (fine, but it does not help if the vault
  is what you lose, and the dialog says so). Accounts made before get a banner in Equipo › Tu cuenta, once; a new
  code can be made there at any time and the old one stops working. SecretBroker and the server keep nothing that
  opens it.
- **Forgot the account password on a PC that is still connected?** Equipo › Tu cuenta › «La he olvidado» sets a new
  one without the old: that PC has the account's keys and proves it to the server. The account's other devices sign
  in again with the new password.
- **Forgot it with no PC left?** On the sign-in form, «¿Has olvidado la contraseña?» takes the e-mail, the recovery
  code and a new password: the same keys come back, and with them what is shared with you and the people you
  verified. Every other session of the account ends.
- **Neither the code nor a PC?** Admins have «Ha perdido el acceso» on each person in Personas: it removes the old
  account like any removal (collections re-encrypted, what they could see flagged to change) and invites the same
  e-mail again. The new account takes the old one's place only after it proves the e-mail (the code the server
  e-mails, or the server admin's verification): the invite code alone is never enough, so an admin can't take
  someone's account. The admin gives access back once it is confirmed.
- After recovering with the code, the app makes a new one at once and shows it: the used one no longer works.
- Actividad (Equipo) shows recovered accounts, passwords set from a device and these invitations.

### Moving to another PC
- **Ajustes › Pasar a otro PC** (also linked from Tu cuenta): save an encrypted backup of the vault to a file, restore
  it on the new PC, sign in to the team, and close the session on the old one. No commands.
- A backup restored on a new PC no longer reuses the old PC's team session: Equipo asks for the account password,
  and the account carries on with its collections and verified people (no duplicates).
- On a Mac, Dutch and Danish texts now say «Mac» / «computer» too (they write «pc» in lowercase).

The team server needs this version for recovery codes, «La he olvidado» and «Ha perdido el acceso» (its database
upgrades by itself to schema 4, and it now needs the `cryptography` package, installed with it).

### Windows installer
- **The installer speaks the app's 32 languages**, not only Spanish and English: it opens in the language of Windows
  without asking, and lists the languages only when Windows speaks one SecretBroker doesn't. Its own texts say «PC»
  like the app.
- **The app starts in the language you installed it in**, when you picked one different from Windows'. A language
  chosen in the app is never changed, and updates don't change it.

## 0.17.0 (2026-11-12)

Teams: pass a credential to one person, invitations by e-mail, a server that is easy to host and back up, and
the fixes of two independent security reviews. Update the team server together with (or before) the apps.

### Sharing with one person
- **Pass a credential to a teammate in one step.** «Compartir» now opens on «Con una persona»: choose who and what
  they may do (Editor, Lector or Solo uso; Lector by default) and it reaches them encrypted. Behind it is a private
  collection of the two of you, made the first time and reused after; no collection to create, nobody to add. Any
  member can do it, not only admins (the team server needs this version).
- From **Equipo › Personas**, «Compartir con Bob…» on each verified person: tick credentials from a list.
- **Colecciones** lists these apart, «Con una persona», as «Con Bob»: change Bob's permission or stop sharing with
  him there. Credentials say «Compartida con Bob» or, on Bob's PC, «Compartida por Alicia».
- Someone not verified on your PC yet: the dialog shows their security code and «Verificar a Bob», one click;
  nothing is shared with a key you have not confirmed.
- **Stopping sharing with someone** (or removing them from the organization) leaves those credentials as yours and
  flags each one to change, because they could have copied it: «Cambiar: la tenía Bob» while they are still on the
  team, «Cambiar: salió Bob» if they left. The list of what to change opens at once.
- Removing someone who shared credentials directly is no longer blocked: what they shared with one person goes with
  them.
- Removing someone or changing a role: when the server says no, the app says why in your language and what to do
  (for example, which collections only that person manages), instead of the server's Spanish message.
- In Personas, «Compartir con Bob…» sits next to the role; removing someone you share with directly says that it
  stops reaching them.
- The status line at the bottom of the sidebar wraps to two lines instead of cutting longer languages short.

### Invitations and versions
- **Invitations by e-mail.** On a team server with e-mail, inviting someone e-mails them the join link and plain
  steps, including where to download SecretBroker; the invite dialog says it was sent, with «Hecho», and keeps the
  instructions one click away. Without e-mail nothing changes: you pass the instructions on. Pending invites say
  when they expire, in the warning colour in their last two days.
- **Invitations expire** after 14 days. Equipo › Personas shows «Invitación caducada» with «Renovar» (a new code,
  e-mailed again) and «Retirar»; pending ones can be re-sent («Reenviar») or withdrawn.
- **App and server versions.** If the team server is too old for this app, Equipo says «El servidor del equipo es
  una versión antigua: pide a quien lo administra que lo actualice» instead of failing later; if the app is too old
  for the server, it says to update the app. 0.16 apps keep working with the new server.

### Security
Fixes from an independent review of team sharing. Update every desktop of a team and the server together.
- **Automatic key checks.** A teammate could empty a shared API key's web hosts (which looked like narrowing) and
  point its address and test request at their own server: the automatic check sent the key there, also after the
  team rotated it. Every host a credential's fields, test request or way of sending the key imply now counts as a
  destination, so such a change waits for review like a new web; until it is accepted the credential keeps its old
  address and test, and the check of a shared key only ever calls hosts the credential's own list names.
- **Database names.** The database name is quoted in `{{connection_url}}`, so a name like `app?host=…` can't send
  the password to another server, and a teammate's change to it waits for review.
- **A server hiding a collection.** A malicious server could hide a collection from a manager's PC for one sync and
  then show it with an old member list, and the manager's app re-keyed it to someone already removed. The app now
  never forgets a member list it verified, nor who it saw removed (both travel encrypted to the account's other
  devices), never re-keys from an unverified list, and never gives a new key to someone it saw removed unless a
  manager adds them again.
- **Forks and stale lists.** Items name the member list their writer had verified. A PC that sees a list it was not
  shown, or a different one with the same number, stops writing to that collection and says so: the server is
  showing people different lists.
- **Invites.** The invite shows the inviter's security code, to compare if you can (accepting is still one click).
  An owner trusted only by accepting their invite no longer gets recovery access to your collections until you
  verify their code («Por verificar»).
- **One odd item no longer stops a sync**: it is refused and reported, the rest syncs (re-keys after a removal
  included).
- **Member lists.** Someone who does not manage a collection may only take themselves out of it, nothing else; and
  someone downgraded to read can no longer write, even before the next re-key.
- **Account password.** The app refuses a server that asks for weaker password hashing than it uses (scrypt
  2^17), unless this PC already logged in to that account with it. The server no longer says whether an e-mail
  has an account when someone signs up with it.
- **Tu cuenta** lists the account's devices, logs out any of them with one click and changes the account password.
- **Links or files dropped on the window.** Dropping a link or an .html file on the app's window opened it there,
  and that page could use the app's bridge (reveal, export, share, approve). The window now takes no drops (the
  page refuses them; WebView2 and Qt refuse external drops and any navigation away from the app; macOS stops taking
  dragged types), a page that loads anyway is replaced by the app, and every call from a page is refused unless the
  window shows the app's own page.
- **Accepting a teammate's change** to where a key goes (or to the texts it carries) needs Hello or a password once
  after opening with the Windows session, like approving the AI widening a destination; then one click.
- **Invite codes.** The list of people no longer carries invite codes (they work as sign-up codes and the list needs
  no proof). «Copiar instrucciones», «Renovar», «Reenviar» and «Retirar» get the invite inside the operation, one
  click.
- **Rotation guides from teammates** are checked like the AI's (an invalid one is dropped), a changed one waits for
  review like the description, and the app says who wrote it («Guía escrita por Bob, del equipo»), not «la IA».
- **Server texts.** The app no longer shows the team server's own error text: known answers in your language, any
  other in general words (the server's text goes to the log).
- **Database commands.** The user and database names in the command to copy are quoted for each engine (and a name
  with a line break gets no command), so a name can't add SQL of its own; Redis passwords are quoted too.
- **Server**: organization, person and device names refuse control, separator and invisible formatting
  characters; invite e-mails keep names out of the subject, and one that can't be written no longer fails the
  invite after it was saved.

### SecretBroker Server
- Invites by e-mail (`SB_SMTP_*`), expiry (`SB_INVITE_DAYS`, 14), renewal and re-sending, at most
  `SB_MAX_INVITES_PER_HOUR` (30) per organization and per account.
- Account management from the command line: `secretbroker-server users`, `disable-user` (revokes its sessions,
  blocks sign-in, takes it out of its organizations: the managers' apps re-key what it could read and flag it to
  rotate), `enable-user`, `delete-user` (refused while it is an organization's last owner or a collection's only
  manager, saying what to do), `transfer-owner` (makes a confirmed member owner of an organization whose only owner
  can't sign in). Each change is in the organization's Actividad. Only accounts with a verified e-mail make the
  server send invites.
- `GET /api/v1/health` (the Docker `HEALTHCHECK`), `secretbroker-server backup` (consistent, timestamped, prunes old
  ones) and `restore` (refused while the server runs). The Compose file adds a daily backup service keeping 14, and
  runs the containers read-only, unprivileged and without capabilities; data files are readable by the server only.
- `/api/v1/info` has `api` and `min_client`; apps send their version and older ones than `SB_MIN_CLIENT` are asked to
  update (`426 client_too_old`). Databases from every earlier server version upgrade on start.
- The README covers an Ubuntu VPS from scratch, hosting on your own PC or home server (Docker Desktop, Cloudflare
  Tunnel, Tailscale, and their trade-offs), backups, restore and upgrades.
- `POST /orgs/{id}/collections` takes `direct: true` (any confirmed member; two members at most, `400
  direct_full`); `GET /collections` says `direct`; removing a member deletes the direct shares only they manage and
  lists them in `deleted`. The database gains a column on start.

### Ubuntu and macOS
- The real-app test suite now runs on Ubuntu in CI too; it found labels cut short in German, Finnish and Greek,
  now fixed. macOS gets a smoke check of the installed app.
- macOS: quitting the app (Cmd+Q, the Dock, logging out or shutting down) quits it instead of only hiding the
  window.
- On a Mac the app says «Mac» for this computer and «ordenador» / "computer" for another one, instead of «PC», in
  every language.

## 0.16.2 (2026-10-31)

The first public build of everything in 0.16.0 below (the 0.16.0 and 0.16.1 tags never produced a release).

- macOS: the app could not reach its service after installing, when the setup re-applied the folder's permissions
  while the service was writing its address file; the service now gives the owner read access to that file itself.

## 0.16.1 (not released)

- macOS: closing the browser no longer leaves its connection to SecretBroker running for 30 seconds; a password
  copied from the extension is cleared when the browser closes.
- Tests: the exposure scan tests compare resolved paths, as on macOS and GitHub's Windows runners.

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
  fields, a toolbar popup, **Alt+Shift+L** to fill and **Ctrl+Shift+Y** for the popup, and «Save this login?» after
  you sign in somewhere new or change a password. (Chrome and Edge no longer give Ctrl+Shift+L to extensions; if a
  browser leaves the shortcut unset, the popup offers «Choose a shortcut» instead of naming a key that does nothing.)
- Phishing resistant: a login is only offered on the site it was saved for (registrable domain), never on page load,
  never into hidden fields or frames of another site. Team credentials marked «use only» are never filled.
- It talks to the app through native messaging, never a network port. Connect it from **Settings › Browser** with
  one click (the app and the extension show the same 6-digit code). Until the extension is in the stores it is
  loaded from the app's folder; Settings › Browser walks you through it, for the browsers on your PC (and Firefox,
  with a note when it isn't installed yet).
- The menu in login fields and the popup show each site's own icon (fetched from the site itself and cached by the
  extension, never through an icon service that would learn which sites you have), and how to fill from the
  keyboard: ↑ ↓ and Enter in the menu, Enter in the popup, Alt+Shift+L anywhere.
- Tested in a real Edge and Chrome for Testing with the extension, its native host and the app
  (`tests/test_browser.py`): connecting, filling user, password and 2FA code, nothing on lookalike domains or in
  another site's frame, saving and updating a login only after the click, «use only» team logins refused, the
  locked vault, site icons, light and dark. Fixed on the way: copying a password from the popup now goes through
  SecretBroker like in the app (out of clipboard history and the cloud clipboard, cleared after 30 seconds); «Save»
  no longer says «It's no longer pending» when the page finished loading at the same moment; the menu in a login
  field scrolls instead of running off a small window or frame; Chromium builds connect as «Chromium», not
  «Browser».

### Teams (preview)
- Organizations, shared collections and per-person permissions (manage, edit, view, use-only), synced through a
  **zero-knowledge server** you can host yourself with Docker (`server/`). The server never sees a secret, a
  credential name or a collection name.
- When someone leaves, the collection is re-keyed and every credential they could see is flagged for rotation.
- Invites only reach verified e-mail addresses; member lists, edits and deletions are signed by whoever made them;
  many deletions at once wait for your decision; organization owners can always recover a collection; the people
  you verify are trusted on all your PCs.
- A teammate's change that widens where a key can go, rewrites the notes your AI reads, or adds a new web address
  for a shared login waits until you accept it. The card lists each change in your language, with one-click
  «Reject» (the recommended choice) or «Allow».

### The personal vault
- Password generator (Ctrl+G), including passphrases.
- **Health**: a 0–100 score and what to fix first (weak, reused, old, expired or exposed passwords).
- Import from Bitwarden, 1Password, KeePass / KeePassXC, Chrome, Edge and Firefox, with a preview and a filter for
  developer keys. Export to an encrypted file, or to JSON / CSV after a clear warning.
- **Import a project's .env** from the app, no terminal: pick the file, tick its keys (you only see names), import
  with one click, then take them out of the file. The project gets a `.secretbroker` with the names for `sb run`.
- Real 2FA codes (TOTP) and private notes the AI never sees.
- «Connect your AI» connects Claude Code and Claude Desktop with one click.

### Approvals and everyday use
- Your master password once per session, then one click. Approvals say which AI is asking, for which credential and
  why, and make «Allow for 24 hours» the recommended button with «Just this once» right next to it.
- When the AI asks to change a credential's settings (its name, notes, allowed websites, programs, variables…), the
  approval lists each change in your language, not in Spanish.
- The Windows file dialogs (backups, imports, exports, .env files) name their file types in your language.
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
