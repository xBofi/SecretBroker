# SecretBroker threat model

This document says what SecretBroker protects, from whom, how, and where the protection ends. It is based on the
security model in [README.es.md](../README.es.md#modelo-de-seguridad) and on sections 2-4 of
[ARCHITECTURE.md](ARCHITECTURE.md). If you find a gap that is not listed under "limits", please report it as described
in [SECURITY.md](../SECURITY.md).

## 1. Assets

| Asset | Where it lives |
|---|---|
| Secret values (API keys, passwords, SSH keys, connection strings) | Encrypted vault, service memory while unlocked, the target process during `run_command` / `sb run` |
| Vault data key and master password | Data key wrapped by scrypt(master password) and by DPAPI; master password only typed in the app |
| Credential metadata (names, notes, tags, policies, `used_in`) | Encrypted vault; shared items encrypted with their collection key |
| Credential policies (allowed hosts, programs, env variables) | Encrypted vault; they decide where a key can go |
| Approvals and presence | Service memory; Windows Hello key in the TPM |
| Activity history | Encrypted with an X25519 public key derived from the vault (write-only while locked) |
| Team account keys (X25519, Ed25519) | Vault; on the server only as `private_blob` wrapped by a key derived from the account password, and as `recovery_blob` wrapped by a key derived from the recovery code |
| Recovery code of a team account | Shown once; wherever the user keeps it (paper, a file, their vault). Neither the app nor the server stores it |
| Collection keys | Sealed to each member's X25519 key, grants signed by the granter's Ed25519 key |
| Who is in each collection, item authorship, deletions | Signed by the member who changed them (Ed25519), chained per collection |
| The people a user verified (pins) | Vault; on the server encrypted with a key derived from the account's private keys |
| Release signing key | GitHub Actions secret (maintainers only); public key pinned in `secretbroker/update.py` |

## 2. Trust boundaries

1. **The user's Windows session**: the app window, the AI agent, the user's other programs.
2. **The SecretBroker service**: a separate, non-interactive Windows account, code in Program Files run with `python -I`.
   Only it can read the vault files. On Linux: the system user `secretbroker` (one sandboxed systemd unit per owner),
   code in `/opt/secretbroker` owned by root; see ARCHITECTURE.md §6.1.
3. **Remote endpoints**: providers and servers that receive the injected key.
4. **The team server**: stores ciphertext, public keys and routing metadata. Untrusted for confidentiality.
5. **The update channel**: GitHub Releases. Untrusted; every installer is signature-checked.

## 3. Actors

### 3.1 Curious or malicious AI agent

The agent is assumed to be capable, possibly prompt-injected, and to run with the user's privileges.

**Mitigations**
- No AI operation returns a secret value. Output from HTTP, SSH and commands is redacted (literal, base64, URL-encoded,
  JSON-escaped and connection-string forms).
- Per-credential allow-lists: HTTPS only to listed hosts, no redirects followed, SSH host taken from the vault, only
  listed programs and environment variables.
- Approvals need the user's presence: a Windows Hello signature (or Windows/master password where Hello is missing)
  over a single-use challenge bound to that operation. The agent cannot approve itself.
- AI changes that widen where a key can go wait for the user's approval; the AI cannot change approval modes or secret
  values. Per-action levels (free, notify, ask, never), unusual-use limits and a "pause the AI" kill switch.
- The MCP endpoint listens on `127.0.0.1`, requires a token and checks `Host` and `Origin`, so web pages cannot drive it.
- The exposure scanner only answers "is this text in the vault?" inside a session granted at unlock, so it cannot be
  used as a guessing oracle.

**Limits**
- A program allowed in `run_command` or started with `sb run` receives the key in clear. An agent that can write and run
  code in such a program (for example `node -e`, `python`) can exfiltrate it. Allow only the programs you need.
- Redaction is best effort against transformations it knows. An allowed endpoint that echoes data back in an unusual
  encoding, or an allowed host the agent controls, can leak a key. Keep allow-lists tight.
- An approved "allow today" credential can be used for any allowed operation during that window.
- Approval prompts show what is being asked; a user who approves without reading can be socially engineered.

### 3.2 Malware in the user's session

A program running as the user, without administrator rights.

**Mitigations**
- The vault, the service memory and its code belong to another Windows account; reading or patching them needs
  administrator elevation.
- The service ignores user environment variables and user site-packages (`python -I`).
- On macOS, where an administrator's programs can replace anything in `/Applications` without a password, nothing
  that runs as root or as the service account comes from there: the installer copies the setup script and the
  service's Python to root-owned folders. On Linux, the folder with the service's token is readable only by the
  owner even when their primary group is shared (an ACL instead of the group).
- Service responses are signed (Ed25519) with a key only the real service has, so a fake service cannot impersonate it
  to the app.
- Registering a new Windows Hello key requires the master or Windows password.
- Clipboard copies are cleared after 30 s and excluded from clipboard history.
- The app's window takes no drops and never shows another page; a page that is not the app's gets every call to
  the app refused (a dropped link or .html file would otherwise get the app's one-click bridge).

**Limits**
- Anything shown or typed on the desktop is exposed: keyloggers can capture the master password, screen capture and
  clipboard snooping can capture revealed or copied secrets, and fake windows can trick the user. This applies to every
  password manager.
- With "open with my Windows session" enabled, anyone who can use the unlocked session can use the vault through the
  app, and any program running as the user can open it (that is what the option means; the inactivity lock then only
  limits how long the key stays in memory). Revealing, copying, editing, exporting and sharing still need Hello or a
  password once after such an unlock, and so does approving an AI request that deletes, rotates or widens where a
  key may go, accepting a teammate's change to a shared credential, or reading an invite's code; approving ordinary
  uses stays one click, so such a program could approve the AI using a credential.
- Malware with administrator rights (or a user who runs the AI agent as administrator) defeats the account isolation.
  On Linux the same holds for root and for members of `sudo` who use it. The `secretbroker` service has the `shadow`
  group (to check the account password with PAM), so code execution inside the service would expose password hashes.

### 3.3 Malicious teammate

A member of an organization, with some permission on a collection.

**Mitigations**
- A member only receives keys for collections they were granted; the server cannot add itself or others because grants
  and member lists are signed and fingerprints are pinned.
- Synced changes to anything that decides where a key can go (policy hosts, commands, env, and the pages where the
  browser fills a web login: its address, autofill sites and how strictly they match) and to the description
  (which the AI reads as instructions) are quarantined locally until the user accepts them. So a teammate (one
  about to be removed included) cannot point a shared login at their own site and collect the password the team
  sets after rotating it. The local approval mode is
  never taken from the server.
- A destination is everywhere the key can actually travel, not just the policy's list: hosts the fields imply
  (an API's address, a generic credential's URL), the saved test request's host and how the key is sent. Emptying
  the list while pointing the address and the test elsewhere is reviewed like a new host, and the automatic check of
  a shared credential only ever calls hosts its policy names. Database names are quoted in connection URLs and reviewed when changed.
- A teammate's malformed item is refused on its own and reported; it cannot stop anyone's sync (and with it the
  re-keys that follow a removal).
- Someone who does not manage a collection can only sign their own departure from it; someone downgraded to read
  can no longer write, even before the next re-key.
- Item versions and deletions must be signed by someone with `edit` or `manage` in the signed member list: a `view` or
  `use` member who holds the collection key cannot write or delete items, even with the server's help.
- Many deletions at once (a compromised account, ransomware with a stolen session) are held until each user decides,
  and the server limits deletions per account and hour. Actividad names who signed each change.
- `use` permission: the app does not reveal or copy the credential; the AI and `sb run` can still use it.
- The server keeps an audit log of metadata events (grants, removals, item writes) readable by admins.

**Limits**
- `use` is enforced by the member's client. A teammate running a modified client can decrypt anything they can use.
  Treat `use` as "will not see it by accident", not as a cryptographic barrier.
- A member with `edit` can change names, private notes, `used_in` and secret values of shared items (these apply
  immediately, signed with their name). A changed rotation guide waits for review and is shown as written by that
  person; its links still deserve a look. The AI only sees `used_in` marked as written by the team, but a
  malicious text there is still a prompt-injection vector; policies still bound where keys can go.
- A credential new to the PC arrives with its description (marked as team-written for the AI): only changes are
  reviewed, so deleting and re-sharing a credential is a way to send new text without review.
- A member with `manage` can grant access to others in the organization. A few deletions at a time (below the hold
  threshold) apply at once; backups are the remedy.

### 3.4 Removed teammate

**Mitigations**
- Removal marks every collection they could read `needs_rekey`; a member with `manage` re-keys it atomically (new key,
  items re-encrypted, new grants), and the server refuses grants with the old key version.
- The server stops serving those collections to them as soon as they are removed.
- Every credential they could see is flagged "rotate: <person> had access" in reminders and the guided rotation wizard.
- Whatever they signed stops counting at the re-key: their old key can't produce accepted items, and the re-key
  re-signs as the manager the items they wrote. A collection whose only manager leaves stays recoverable: the
  organization's owners hold a signed `manage` grant (Equipo warns while one person manages a collection alone).
- When their account itself must go (a lost laptop, someone who left on bad terms), the server admin can disable it
  (`secretbroker-server disable-user`): every session ends at once, it can't sign in, and it leaves its organizations
  with the same re-keying and "rotate" flags as a removal by an org admin, done by the managers' apps on their next
  sync.

**Limits**
- Re-keying protects future changes only. Anything they saw, copied or used while they were a member must be rotated
  at the provider; SecretBroker reminds you, it cannot do it for every provider.
- Copies already synced to their devices stay readable by them until the underlying keys are rotated.

### 3.5 Compromised or malicious team server

**Mitigations**
- Zero knowledge: the server never sees secrets, credential names or collection names. Items, names and keys are
  encrypted client side (AES-256-GCM, X25519 sealing) with associated data binding each ciphertext to its collection,
  item and key version, so ciphertexts cannot be swapped between items.
- The account password never leaves the client: the server gets an HKDF-derived `auth_hash` (stored hashed with scrypt)
  and an opaque `private_blob`.
- Key grants are Ed25519-signed by the granter and verified against pinned keys, so the server cannot inject its own
  collection keys or substitute a member's public key without a fingerprint change the user must confirm.
- Member lists are a hash chain of lists signed by the collection's managers: a member, a permission or a manager the
  chain does not back is refused and reported, and no key is sealed to anyone outside it.
- A verified list is never forgotten: dropping a collection keeps it, and it travels encrypted to the account's
  other devices, so hiding a collection for a sync and then serving an older list (or none) gets nowhere. Automatic
  re-keys need a verified list, and a new key never goes to someone this account saw removed unless a manager adds
  them again with a new signed list.
- Items name the list their writer had verified. A device shown a different list than its teammates with the same
  number (a fork), or kept behind a newer one, stops writing to that collection and tells the user.
- Accepting an invite shows the inviter's code; a pin made only from an invite is not enough for owners' recovery
  grants, which need a verified code.
- At login the app refuses scrypt parameters weaker than the ones it registers accounts with, so the server cannot
  lower the cost of guessing the password from `auth_hash`. Sign-ups do not reveal which e-mails have an account.
- The recovery code never reaches the server: it gets an HKDF-derived `recovery_auth_hash` (stored hashed with
  scrypt) and `recovery_blob`, the keys wrapped by another key derived from the code. The code has 150 random bits, so
  guessing it offline from the blob is infeasible even for the server, unlike a password; the app also refuses
  scrypt parameters below 2^17 for it, and the server cannot use the blob. Setting a code, or a password without the
  old one, needs a signature by the account's own Ed25519 key over a single-use challenge, so a stolen session token
  is not enough. A hostile server could still overwrite what it stores, which only denies service: a blob it makes
  does not hold the account's keys, and the app checks the keys it opens against the account's public keys.
- Replacing an account whose owner lost access is limited: only through an org admin's new invite naming that
  account, only once the account is in no organization, never for a server admin, and only after the new account
  proves the e-mail (the code e-mailed to it, or a server admin who checked who the person is). Until then the old
  account is untouched. The new account has new keys that teammates must verify like anyone's.
- Item versions and deletions carry the author's signature and a write counter: the server cannot forge, attribute
  or delete content, nor serve an older version again; unsigned deletions are ignored and reported, and a collection
  that disappears with many credentials is held for the user.
- Invites only bind to e-mail addresses the account verified (code by e-mail, or the server admin), so registering
  someone's address first does not get their invites. Registering with an organization's invite code opens only
  that organization's invites: anyone can create an organization and invite any address, so their own invite code
  proves nothing to anybody else.
- Pins of verified people are stored encrypted with the account's own keys and never rolled back.
- Quarantine of policy-widening and description changes (3.3) also covers changes forged by the server.
- The server's free error texts are never shown to the user (only translated messages chosen by its error code), and
  the names it relays are checked for control and invisible characters.

**Limits**
- Metadata is visible: e-mail addresses, organization names, membership graph, permissions, item counts, sizes and
  timestamps.
- The server can deny service, delete data on the server, withhold updates or hide the newest member list, and serve
  stale data to a device that has never seen newer. It cannot make clients delete their copies unasked beyond the
  hold threshold.
- Organization roles are asserted by the server. A manager's app gives `manage` on its collections to every
  organization owner the user has verified (so a collection can always be recovered); a hostile server could
  therefore promote a verified teammate to owner to reach those collections. The grant is signed, shows in the member
  list and Actividad, and needs that teammate's cooperation.
- A device seeing a collection for the first time trusts the newest member list signed by a manager it verified,
  without checking older links (trust on first use of the chain). Collections from before 0.16 keep working
  unsigned until a manager whose PC verified every member signs them (automatically, with a re-key to the members
  the server lists and this PC trusts, and only for collections the account never saw signed).
- Fork and freshness detection is not a guarantee (there is no transparency log or gossip between members):
  - A server that partitions people completely, showing a device only an old list and only items written under it
    (its own and those of others it keeps behind with it), is not detected: nothing that device sees names a newer
    list. During that time it keeps writing with a key a removed member may hold, and a removed manager can extend
    the old chain for it. Detection needs one item, or one of the account's own devices, that saw the other branch.
  - It works per account: two devices of the same account compare what they verified through the encrypted account
    data; different people only through the lists items name. Apps before 0.17 do not name one, and rewrite the
    account data without what newer devices verified (the next newer device puts it back).
  - Only the newest 20 list hashes per collection are remembered, and a device that starts mid-chain knows none
    older, so a fork at an older link that only an old item names goes unnoticed.
  - A collection marked forked stays so (on every device of the account): nothing more is written to it from there.
    The remedy is a new collection created by a manager the team verifies, and rotating its secrets.
- A pin made by accepting an invite is still the server's word on who sent it (the code is shown, but comparing it is
  optional). It is enough to trust what that person shares and the grants they sign; only owners' recovery access
  needs a verified code. Pins from before 0.17 carry no origin and count as verified.
- Sign-ups no longer say whether an e-mail has an account, but other answers still differ for known addresses (an
  invite to an address that has an account, login throttling per e-mail), and timing is only roughly uniform.
- Accounts registered with scrypt below 2^17 (none by this app) can only log in on PCs that already did so.
- Without SMTP, e-mail verification relies on the admin checking who asks to be verified; a server with
  `SB_EMAIL_VERIFICATION=off` gives invites to whoever registered the address.
- With SMTP the server e-mails invites, and the inviter writes the organization name they carry. Anyone who can
  create an account (`SB_SIGNUPS=open`) can make the server send an invite with a misleading organization name to
  any address, once it has verified its own address (unverified accounts never make the server send one). The
  e-mail never asks for a password (and says so), its link only fills in the app's form, and invites are limited per
  organization and per account each hour; with `SB_SIGNUPS=invite` (the default) only people the admins let in can
  send them. A compromised server can send whatever e-mails it likes from its SMTP account.
- Whoever terminates TLS in front of the server sees what the server sees: a Cloudflare Tunnel (TLS ends at
  Cloudflare) or another TLS-terminating proxy is part of this actor. Tailscale `serve` / `funnel` and Caddy keep TLS
  on the operator's machine. Payloads stay end-to-end encrypted either way.
- A server restored from an old backup forgets later removals and disabled accounts until they are done again; apps
  refuse content older than what they already have.
- An attacker who controls the server can try offline guessing of weak account passwords from `private_blob` and the
  scrypt parameters. Use a strong account password.
- First contact with a new member is trust on first use: if the server lies about a key the first time you see a user,
  only comparing fingerprints out of band detects it.
- **A recovery code holder** (someone who finds the paper, the file, or the vault entry where it was kept) can do
  everything the account can: set a new password, read what is shared with it, sign as it. Recovering ends every
  session of the account and shows in its organizations' Actividad («Recuperó su cuenta…»), so the owner notices on
  their next sync; making a new code invalidates the old one. Keep it like a password, away from the PC it protects.
- Whether an account has a recovery code is not answered directly, but its scrypt salt changes when a new code is
  made, so someone who keeps asking `recover/prelogin` can tell that an account has one.
- A malicious org admin can use «Ha perdido el acceso» on someone who has not lost anything: they are removed (which
  the admin could do anyway), but the invite code the admin knows does not take their address: a sign-up with it
  waits until it proves the e-mail, by a code sent to that mailbox or through the server admin. Whoever controls the
  mailbox (or fools the server admin) can therefore take the address of an account that is in no organization; that
  is the same trust the server already puts in e-mail for invites. Someone with the invite code can also keep
  replacing a waiting sign-up with their own, which only delays the real person (each new sign-up e-mails a new
  code to the real address).

**The server's own updates and administration** (`install-server.sh`, `updater.py`, `/admin/...`)
- The automatic updater runs as root and installs only an archive whose Ed25519 signature (over the version and the
  archive's SHA-256) verifies with the release key built into the version already running, checked before anything
  is unpacked; the unpacked `VERSION` must be the signed one, and it never installs an older or the same version, so
  an old signed release can't be replayed. Downloads come only from GitHub's hosts over HTTPS, but that is not what
  is trusted: a compromised GitHub account, release page or network can withhold updates, not install anything. The
  signing key is the same `UPDATE_SIGNING_KEY` as the desktop app's (a GitHub Actions secret): whoever holds it can
  ship code that runs as root on every self-hosted server with automatic updates on, exactly as on every desktop.
  Self-hosters who don't want that turn automatic updates off (the app's server panel, or `SB_AUTO_UPDATE=0`).
- What the archive contains is built in CI from the hash-pinned locks (`requirements/server.txt` and `sign.txt`, the
  same `cryptography` as the signing job) and a checksummed CPython, then signed by the release's `sign` job.
- `SB_UPDATE_TRUST` (extra keys) and `SB_UPDATE_SOURCE` live in the root-only `server.env`: changing them needs root,
  which could replace the code anyway. The server process can't: it only reads the updater's status file, and the
  only update setting it can write (`auto_update`, from the app) turns signed updates on or off.
- A new version that does not answer `/health` within a minute is rolled back to the previous version and the
  database backed up just before; a version that starts but misbehaves later is not caught by this, and the rollback
  loses what was written in that minute (the apps push it again).
- The first install trusts HTTPS to GitHub for `install-server.sh` itself (`curl … | sudo bash`); the archive it
  installs is signature-checked. Whoever wants more checks `install-server.sh.sig` first (the same key and message).
- The admin API is reachable wherever the server is (it is the same HTTPS endpoint): it needs a server admin's
  session, answers `403` to anyone else before reading ids, is rate-limited per admin, and refuses to let the last
  admin lock themselves out. A stolen admin session can disable, delete or move accounts and organizations' ownership
  (each recorded in the server admin log and the organization's Actividad), change signups and automatic updates,
  and make backups, but it gains no secret: disabling or removing someone triggers the same re-keying as an org admin
  removing them, and the apps verify every key, member list and item signature as before. It cannot restore backups,
  change addresses, keys, SMTP or the update source, or read backups' contents (only names, times and sizes).
- The signup token the installer prints is bound to the admin's e-mail, so seeing it (in a terminal scrollback, say)
  doesn't let anyone else register; it is single-use and expires in 14 days.

### 3.6 Network attacker

**Mitigations**
- Provider calls are HTTPS only, with certificate validation and no redirects.
- The team server refuses a non-HTTPS public URL (except an explicit local-testing switch), and its payloads are
  end-to-end encrypted anyway.
- Updates are only installed when their Ed25519 signature matches the pinned release key, regardless of the transport.
- The MCP endpoint is loopback-only.

**Limits**
- SSH host keys are remembered on first use and checked afterwards; the very first connection to a host is trust on
  first use.
- Metadata of team traffic (timing, sizes) is visible to the network path.

### 3.7 Stolen disk or backup

**Mitigations**
- The vault is AES-256-GCM under a random data key wrapped by scrypt (128 MiB) of the master password; on the PC the
  copy is additionally wrapped with DPAPI (Linux: AES-GCM with a key in a separate 0600 file of the service account,
  which a backup of the vault does not include).
- Backups are the encrypted vault; restoring needs the master password the backup had. Restored on a PC without a
  vault, a backup's team session is not used: that PC signs in to the team with the account password itself.
- Online guessing through the app is slowed with increasing delays after each failure.

**Limits**
- A weak master password can be brute-forced offline from a stolen backup, slowly. Choose a long passphrase.
- Windows Hello and Windows-password recovery work only on the original PC; they do not help an attacker with a backup,
  but they also mean the backup alone is only as strong as the master password.
- Linux has no DPAPI: a stolen *unencrypted disk* holds both `device_key.bin` and `machine.key`, so the vault opens
  without the master password. Use full-disk encryption (Ubuntu's installer offers it). Windows has the same limit
  against an attacker who can also recover the service account's DPAPI master key from the disk.

### 3.8 Malicious or phishing web page (browser autofill)

**Mitigations**
- Logins are matched by the service, by registrable domain (Public Suffix List, private suffixes included):
  lookalike domains (`example.com.evil.net`, `examp1e.com`, IDN homographs), other tenants of shared suffixes
  (`github.io`, `blogspot.com`), `http` pages for `https` logins and other ports get nothing, not even the names.
- Nothing is filled on page load. Values are requested one login at a time after a trusted click in the extension's
  own UI (a closed shadow root the page cannot script) or its keyboard shortcut, and are sent only to the frame
  being filled, which must still show the origin the service matched (a frame that navigated elsewhere meanwhile
  gets nothing); frames of another registrable domain, hidden or tiny frames and invisible fields are never filled.
- Team credentials with `use` permission are never filled (that would give the value to the page).
- Saving a typed login needs the user's click; every fill, copy and save is in Actividad («Navegador»).

**Limits**
- A page on the right domain that is itself compromised (XSS) receives what is filled there, as with any manager.
- Clickjacking: a page could try to trick the user into clicking the extension's menu; the menu only ever offers
  logins of that page's own domain.
- Subdomains share a registrable domain: with the default match, a login saved for `example.com` is offered on
  any `*.example.com`. Use "Solo esta dirección exacta" for sites whose subdomains belong to other people.

### 3.9 Malware in the user's session and the browser

**Mitigations**
- The service only answers the extension ids it knows (the browser tells the native host, the page cannot), and only
  a browser the user connected with one click in the app after comparing a code. It stores only the hash of the
  browser's key; "Desconectar" in Ajustes revokes it.
- No network port is opened for the browser: it uses native messaging.

**Limits**
- The browser's connection key lives in the extension's storage in the user's profile. A program running as the
  user (an AI agent with a shell included) that reads it can ask, through the service, for the logins of any site,
  one at a time, while the vault is unlocked; each one is logged in Actividad. Anything running as the user can
  also read what the browser itself shows or fills. Treat a connected browser like the unlocked vault.
- A program running as the user can also ask to connect as a browser (it can start the native host with our
  extension's id). The app shows each request with the code the browser's popup shows: accept only a request
  whose code your own popup is showing.
- A page on the right domain can rewrite a password field after the user typed in it, so «Actualizar» could
  save what that page chose, replacing the saved one. Only that site's own pages can do it (a compromised site,
  as above); backups keep the earlier value.
- Until the extension is published, it is loaded unpacked (Chromium) or temporarily (Firefox); store builds get
  other ids, which must be added to the app before they can connect.

## 4. Out of scope

- Compromise of the provider or server that legitimately receives a key.
- Physical attacks on an unlocked, unattended PC.
- An attacker with administrator or SYSTEM rights on the user's PC.
- Supply-chain compromise of Python dependencies before they are bundled into a signed release: a malicious version
  the locks were updated to (`tools/update_locks.py` takes what PyPI serves at that moment; reviewing the lock diff
  is the only check), or one of the locked packages being malicious already. What the release workflow does about
  the rest:
  - every GitHub Action is pinned to a commit SHA and the bundled CPython by checksum;
  - every Python package that CI and the release install (the app's dependencies on each system, the server's,
    the test tools, the build backend) comes from the locks in `requirements/`, with its exact version and the
    SHA-256 of every file, installed with `pip install --require-hashes --no-deps`. A new upload to PyPI, even
    under a pinned version, is refused. Builds run without build isolation against the locked setuptools, so pip
    never fetches an unpinned build backend. CI fails if `pyproject.toml` asks for a package a lock lacks;
  - the jobs that install and run build dependencies never see `UPDATE_SIGNING_KEY`: they upload the installers
    unsigned, and a separate job signs them with nothing installed but the hash-pinned `cryptography` and no code
    run but `tools/sign_release.py`. A compromised build dependency could still alter the installer of the
    release it is built into (the signature covers whatever the build produced), but it cannot take the key to sign
    other files later. The Apple Developer ID certificates, once added, are still used inside the macOS build job
    (`codesign` runs during `tools/build_macos.sh`); Inno Setup comes from Chocolatey, unpinned.
- The update signature binds the version and the installer's hash, not which system it is for: a signed package
  of the same version for another system could be offered in its place. It would fail to install (it is not
  code for this system), never install something unsigned.
