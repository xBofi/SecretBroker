# SecretBroker privacy policy

> **This text has not been reviewed by a lawyer.** It is the maintainers' plain description of what the software
> does, written from its source code (the last section says where each statement comes from). It is not legal
> advice. If you publish SecretBroker under your own name, or run a team server for other people, have it reviewed
> for the laws that apply to you.

Last updated: 2026-11-18, for SecretBroker 0.19.

It covers the three parts of SecretBroker: the **desktop app** (Windows, Linux, macOS), the **browser extension**
(Chrome, Edge, Brave, Firefox) and the **team server** that an organization can host for itself.

## In short

- Your vault lives on your computer, encrypted. The SecretBroker project has no server that receives it, and
  nobody at the project can see your credentials, the sites you visit or how you use the app.
- There is **no telemetry, analytics, crash reporting, advertising or tracking** in the app, the extension or the
  server. No account with us is needed and none exists.
- The browser extension talks only to the SecretBroker app on the same computer. It sends nothing to us or to any
  server of ours; the only thing it asks the internet for is a website's own icon.
- The app connects to the internet for a short, fixed list of reasons, all listed below: to look for updates
  (GitHub), to test that your keys still work (each key's own provider), to check passwords against known breaches
  without revealing them (Have I Been Pwned), to do what you or an AI agent you approved ask for, and to sync with
  a team server if you connect one.
- A team server stores only ciphertext it cannot read, plus the metadata needed to route it (e-mail addresses,
  names, who belongs to what). Whoever runs that server is responsible for it, not the SecretBroker project.

## Who is responsible for what

SecretBroker is open source software (MIT License) published at <https://github.com/xBofi/SecretBroker>. The
project distributes the software; it does not operate a service that receives your data. At the time of writing
the project runs **no hosted team server**: every team server is installed and run by the organization that uses
it, and that organization decides what happens with the data on it. If the project ever offers a hosted server,
this policy will be changed before it opens.

The browser extension is distributed through the Chrome Web Store, Microsoft Edge Add-ons and addons.mozilla.org,
and the installers through GitHub. Those services see your download as they see any other, under their own
privacy policies.

## The desktop app

### What stays on your computer

- **The vault**: your credentials, their notes, where each one may be used and their history. Encrypted on disk.
  When installed, it is kept in a folder that only the SecretBroker service account can read.
- **The activity log** ("Activity" in the app): what was used, filled, copied, saved, approved or refused, when,
  and by which program or browser. For the browser it records the website where a login was filled or saved. It is
  stored encrypted, on your computer only.
- **Connected browsers**: a name, the extension's id, a date and the hash of each browser's connection key.
- **Exposure results**: where a copy of a secret was found on this computer, and the result of the tests below.
- **The search for copies**: the app looks through files on this computer (AI conversations, terminal history,
  program settings, project folders and their git history) for copies of your secrets: when you ask, and when you
  unlock (at most every 12 hours) unless you turn that off in Settings. This happens on your computer; nothing it
  reads or finds is sent anywhere.

### Connections the app makes

| When | To | What is sent |
|---|---|---|
| When the app starts and then once an hour while it runs | GitHub (`api.github.com`) | A request for the latest release of SecretBroker. No identifier, account or version number of yours; GitHub sees your IP address, as any site you visit does. This check cannot be turned off in the app. |
| When you click to update | GitHub (`github.com`, `*.githubusercontent.com`) | The download of the installer and its signature. Nothing is installed unless the signature verifies. |
| While the vault is unlocked, as often as you chose (every 24 hours unless you change it; "never" is a choice, in general or per credential), and when you or an AI agent you connected ask for a test | The provider of each API key that SecretBroker recognizes: Anthropic, OpenAI, OpenRouter, GitHub, GitLab, Stripe, Groq, Hugging Face, AssemblyAI, Mistral, ElevenLabs, Deepgram, Cloudflare | One harmless read-only request with that key, to learn whether it still works (a key that stops working was probably revoked after a leak). A key is only ever sent to the provider it belongs to: it is matched by the address saved with it or by an unmistakable prefix. For a key of another provider, a test request is made only if one was saved with the credential, and only to the hosts that credential allows. For an SSH credential, the app connects and signs in to its server. |
| On the same schedule | Have I Been Pwned (`api.pwnedpasswords.com`) | For passwords of website logins, databases and SSH: the **first 5 characters of the password's SHA-1 hash**, with padding requested so the size of the answer says nothing. The password and its full hash never leave your computer; the comparison is made locally. |
| When you, or an AI agent you approved, rotate a key with the app's help | That key's provider (today Cloudflare and GitLab can be rotated through their API) | The requests needed to create the new key and retire the old one. |
| When you, or an AI agent you approved, use a credential | The hosts that credential is allowed to reach: an HTTP API, an SSH server, GitHub (to store a repository secret), or a program on your computer | The request you approved, with the secret put in its place by the app. Every use is in the activity log. |
| Only if you connect the app to a team server | That server, at the address you typed | See "The team server" below. |

The app also opens links in your browser when you click them (a provider's console, the releases page). It has no
other connection in its code. Its window is drawn by the system's web view (WebView2 on Windows, Qt WebEngine on
Linux, WKWebView on macOS), which SecretBroker gives only its own local files, in private mode; those components
belong to their vendors.

AI agents talk to the app on your computer (a local program, or `127.0.0.1`): they get the results of what they
ask for with the secrets removed, never the secrets. What an AI agent then does with those results is governed by
that agent's own provider.

## The browser extension

The extension fills the logins and two-factor codes you keep in SecretBroker and offers to save the ones you type.
It works only together with the app installed on the same computer.

### What it reads in the browser

- **The address of the tab** you are on, when you open the extension's window, click the SecretBroker button in a
  field, press the fill shortcut, or send a login form.
- **Login fields of the page**: it looks for user name, password and one-time code fields (their type, name and
  label) to show its button in them and to know where to fill. To notice that a login form is being sent, it also
  looks at the button you click and at the Enter key in those fields, and then reads the **user name and password
  you typed** in the form.
- Nothing else of the pages you visit is read, kept or sent: no page content, no browsing history, no cookies.

### Where that goes

Only to the **SecretBroker app on the same computer**, through the browser's native messaging (a private channel
between the browser and a local program; no network port, no server):

- the page's address, so the app can decide which of your logins belong to that site;
- the user name and password of a login form you just sent, so the app can tell whether it is new or changed. The
  app stores them **only if you click "Save" or "Update"**; otherwise it discards them. The extension keeps them in
  the browser's memory, where the offer can be accepted for 5 minutes, until you answer, the tab closes or the
  browser closes;
- what you type in the extension's search box.

The app answers with the names and user names of the logins for that site, and hands over one login's user name,
password or current two-factor code only after you click it (or press the shortcut), to be typed into the page you
are on. "Copy" puts the value on the clipboard from the app, which clears it after 30 seconds; on Windows it is
also kept out of the clipboard history and the cloud clipboard.

The extension sends **nothing to the SecretBroker project, to its developers or to any third party**. It contains
no analytics and loads no code from the internet.

### What it keeps in the browser

- A random key that identifies this browser to your app (created when you connect the browser; "Disconnect" in the
  app's Settings › Browser revokes it).
- A small cache of website icons (at most 300, renewed after a week), which shows which sites it fetched an icon
  for.
- In memory only, until the tab or the browser closes: which frames of a tab have a login form, the user name of a
  sign-in in two steps, and a login waiting for your "Save?" answer.

Removing the extension deletes all of it.

### The one thing it asks the internet for: website icons

To show a site's icon next to its logins, the extension downloads that icon from the site itself (the icon the
browser already shows for the tab, or the site's `/favicon.ico`), **without cookies and without saying which page
asked**. This happens when the extension lists logins for the site you are on, and for the sites of the logins a
search in the extension's window finds. It never uses an icon service, so no third party learns which sites you
have logins for. The site sees a request for its icon from your IP address, as it does when you visit it.

## The team server

A team server lets an organization share credentials between its members. It is optional; the app works without
one. **Whoever installs and runs a server is responsible for the data on it** (in data-protection terms, they are
its controller): ask them for access to your data, its correction or its deletion. The SecretBroker project has no
access to any server.

### What a server stores

- **Accounts**: e-mail address, the name you chose, whether the address is verified, whether the account is an
  administrator or disabled, when it was created.
- **To sign in**: a value derived from your account password, stored hashed (scrypt). The password itself never
  leaves your app. The same for the recovery code, if you made one.
- **Your keys**: your public keys, and your private keys encrypted with a key only your password (or recovery
  code) gives.
- **Devices**: for each signed-in device, the device name the app sent, when it signed in and when it was last
  seen, and the hash of its session token.
- **Organizations**: their names (not encrypted), who belongs to each, with which role, and pending invites
  (e-mail address, role, who invited, when it was sent and expires).
- **Shared credentials**: only ciphertext. The credentials, their names and the names of the collections are
  encrypted by the apps before they are sent; the server keeps who can open each collection and with which
  permission, the signed member lists, sizes, counts and times, and who changed each item last.
- **Activity**: a log of actions in each organization (who invited, shared, removed or changed what, and when; ids
  and e-mail addresses, never contents), and a log of what server administrators did.

### What a server never receives

Credentials, their names, notes or addresses in clear; your account password; your recovery code; your vault's
master password; anything about credentials you do not share; the sites you visit or anything from the browser
extension.

### Addresses, logs and e-mail

- Your IP address is used, in memory only, to slow down repeated sign-in and sign-up attempts. It is not written
  to the database. The server program prints a line per request to its log (the address the connection came
  from, the path and the result); behind the bundled Caddy proxy that address is the proxy's own, and the bundled
  Caddy configuration keeps no access log. An operator who puts something else in front of the server (another
  proxy, a tunnel) may log more: ask them.
- The app tells the server its version number with each request.
- If the operator configured an e-mail (SMTP) server, the team server sends two kinds of e-mail and no others:
  the code that verifies your address, and invitations to an organization (to the address the inviter typed, with
  the organization's name). They pass through that SMTP provider.
- A server installed with `install-server.sh` asks GitHub once a day for a newer signed release of itself (GitHub
  sees the server's IP address). Nothing about its users is sent.
- Backups made on the server hold the same data as the server and are kept where its operator keeps them.

Whoever ends the TLS connection in front of a server (a tunnel or proxy service the operator chose) can see what
the server sees: the metadata above, never the contents.

## Others who receive something

Only as described above, and only for what is listed there:

- **GitHub**: update checks and downloads (app and server), and anything you ask the app to do on GitHub with your
  own credentials. <https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement>
- **Have I Been Pwned**: the 5-character hash prefixes. <https://haveibeenpwned.com/Privacy>
- **The providers of your own keys**, when a key is tested, rotated or used, each under the account you already
  have with them.
- **Your team server and its operator**, if you connect one.

Nothing is sold, shared for advertising, or used to build a profile: the project receives nothing to sell.

## Your choices

- Key tests and breach checks: Settings (general) or each credential, down to "never".
- The search for copies on your computer: Settings.
- The browser extension: "Disconnect" in Settings › Browser, or remove it from the browser.
- A team account: disconnect the app from the server in Team; to have the account deleted, ask the server's
  operator.
- Everything else: uninstalling the app leaves the encrypted vault on disk until you delete its folder.

## Changes and contact

Changes to this policy are made in this file, with their history, at
<https://github.com/xBofi/SecretBroker/commits/main/docs/PRIVACY.md>. Questions: open an issue at
<https://github.com/xBofi/SecretBroker/issues> (it is public: never paste a secret there); to report a security
problem privately, see [SECURITY.md](../SECURITY.md).

## Where each statement comes from

So that anyone can check this policy against the code:

| Statement | Source |
|---|---|
| Update check, hourly, GitHub only, signature required | `secretbroker/update.py`, `secretbroker/web/app.js` (`checkUpdate`) |
| Key tests, their providers and schedule | `secretbroker/exposure.py` (`PROVIDERS`, `check_alive`), `secretbroker/service.py` (`_check_loop`, `_due_checks`), `secretbroker/vault.py` (`check_every_hours`) |
| Have I Been Pwned with the first 5 characters of the hash | `secretbroker/exposure.py` (`pwned_count`) |
| Rotation through a provider's API | `secretbroker/rotation.py` |
| Uses of a credential, each approved and logged | `secretbroker/actions.py`, `secretbroker/service.py` |
| The search for copies runs locally | `secretbroker/exposure.py`, `secretbroker/scanner.py` |
| The app's window loads only local files | `secretbroker/web/index.html`, `secretbroker/app.py` |
| What the extension reads, keeps and sends, and to whom | `extension/background.js`, `extension/content.js`, `extension/popup.js`, `extension/manifest.json` |
| The app only answers its own extension and a connected browser; what it stores from it | `secretbroker/native_host.py`, `secretbroker/service.py` (`op_ext_*`) |
| What a team server stores | `server/secretbroker_server/db.py` (the whole schema) |
| IP addresses for throttling, in memory | `server/secretbroker_server/security.py`, `accounts.py`, `web.py` |
| The server's e-mails | `server/secretbroker_server/mail.py` |
| The server's update check | `server/secretbroker_server/updater.py` |
| No telemetry or analytics | No such code exists: search the repository for network calls (`httpx`, `urllib`, `fetch(`, `smtplib`); the ones above are all there is. |
