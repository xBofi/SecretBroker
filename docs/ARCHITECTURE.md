# SecretBroker architecture

SecretBroker has two products built from one repository:

| Part | What it is | Where it runs |
|---|---|---|
| **SecretBroker Desktop** (`secretbroker/`) | Personal vault + broker that lets AI agents *use* credentials without reading them. Windows, Ubuntu and macOS (§6). | The user's PC, as an isolated service (its own system account) + tray app |
| **SecretBroker Server** (`server/`) | Zero-knowledge sync and sharing server for teams. Self-hostable (Docker), and the same code runs the hosted SaaS. | Any Linux host / container |

The server **never sees a secret, a credential name or a collection name**. It stores ciphertext, public keys and the
metadata needed to route it (who belongs to which organization, which collection an item is in, revisions). Everything
is encrypted and decrypted by the desktop app's service. A full compromise of the server leaks: e-mail addresses,
organization names, membership graph, item counts and timestamps. It does not leak credentials.

## 1. Desktop (unchanged core)

See README.md: the service runs under a separate Windows account, the vault is AES-256-GCM with a random data key
wrapped by scrypt(master password) and by DPAPI, every AI operation goes through the service, output is redacted, and
approvals are one click after unlock.

### 1.0 Friction, approvals and freshness

- **Presence strength.** Unlocking hands the app a one-click token (`presence`). After a proof (master or Windows
  password, Hello) it is *strong*: `reveal`, `save_entry`, `delete_entry`, `rotate`, `set_settings`, `exposure_begin`
  and `enable_session_unlock` (`service.PROVEN_OPS`) take it, like everything in `PRESENCE_OPS`. After "open with my
  Windows session" it is *weak* (anything running as the user could get one), so those and `TEAM_EXPORT_OPS` answer
  `proof_required`. The app then sends a proof **with its token** (`proof.presence`): the service makes that token
  strong and returns it in the response envelope (`presence`, read with `client.request(..., meta=)`). A proof without
  a token (sb, scripts) leaves the app's token alone. A `proof_required` caused by a weak token carries `weak: true`
  so the app says why it asks.
* **AI approvals.** Approving the AI's use of a credential is one click with any token. Requests that delete,
  rotate or widen where a key may go (`STRONG_APPROVALS`: the AI's `delete`, `rotate` and `edit_config`; the request
  carries `strong: true`) take a strong token, so after a Windows-session unlock the first one needs Hello or a
  password (typed at most once a session: it makes the token strong, as above).
- **Inactivity lock** applies with the session unlock too. `status.lock_reason` is `idle`, `manual` or `windows`. With
  the session unlock on, `client.call` opens the vault again by itself on the AI's next request
  (`client.reopen_with_session`), and the app does when the user comes back to the window; never after «Bloquear».
  App reloads that are not the user (`_poll: true` in the params) don't count as activity.
- **Approvals** carry `client` `{name, folder}` (MCP `clientInfo` mapped to "Claude Code"/"Claude Desktop", the stdio
  server's working folder; `sb` sends its own), `reason` (optional argument of the MCP tools), `host`, `last_used`,
  `uses_today` and `expires`. Requests nobody answered in time are listed by `expired_approvals` for a few minutes.
- **Freshness.** `status.revision` goes up with every vault write (`Vault.revision`), every AI or team audit event
  and every approval or withdrawal; the app reloads and redraws the list and the detail in place when it changes.
  `save_entry` takes `base_updated` (the `updated` the editor started from) and answers `conflict` if it differs.
  `audit {secret_id}` is the activity of one credential (the detail's «Actividad reciente»); `entries` carry `last_used`.

Team data lives **inside the existing encrypted vault payload** (section `team`), so it inherits the same at-rest
protection, backups and lock behaviour. Shared credentials are ordinary vault entries with an extra `shared` block,
so the AI broker, `sb run`, exposure checks and rotation work on them unchanged.

### 1.1 Personal vault features

Logic in their own modules, wired into `service.py` as GUI-only operations (none is in `AI_OPS`):

| Module | Service op | Notes |
|---|---|---|
| `generator.py` | — (the app calls it directly) | Random passwords and Spanish/English passphrases from `secrets`; `strength()` estimate. |
| `health.py` | `health` | Weak (`generator.strength`), reused (compared by `vault.mac`, never a hash leaves the service), old, expired, exposed; a 0-100 score. Names and reasons only. |
| `importers.py` | `import_file` | The service account cannot read the user's files, so the app reads the file and sends `{content, source, format, password?, selected?}`; without `selected` it returns a preview (names, users, sites, status, `dev`, `totp`) and an `import_id`: the plan stays in the service for 30 min (forgotten on lock), and the app sends the selection in batches `{import_id, selected, done?}` → `{created, failed: [{key, name, reason}]}`, showing progress. Each batch is one `vault.put_many()` (validated one by one, saved once). `postgres://`, `mysql://`, `ssh://`… addresses become databases and SSH servers; `dev` (API keys, SSH, databases, cloud, key-like secrets) drives the «Solo claves de desarrollo» filter. Presence proof. |
| `totp.py` | `totp_code` | RFC 6238 (SHA1/256/512, 6–8 digits, any period) from an otpauth:// URI or a base32 seed. `{id, copy?}` → `{code, period, remaining, digits}`. In `PRESENCE_OPS` and `TEAM_EXPORT_OPS` (a Windows-session unlock needs Hello or a password once; a real proof returns a full presence). Shown codes are audited once per 10 min per credential, copies always. |
| `exports.py` | `export_vault` | `{format: encrypted \| json \| csv, password?}` → `{content}`; the app writes it. Presence proof. Format in `docs/EXPORT_FORMAT.md`. |

`import_file` and `export_vault` are in `PRESENCE_OPS` (one click from the app that unlocked). `replace_key` also
accepts web logins and SSH passwords (the password-change helper behind "Rotar con ayuda" in *Salud*).

Every template has an optional **private notes** field (`fields.notes`, `secret` + `note`): hidden and revealed like
a secret, never given to the AI, programs, the scanner or the redactor, and not part of `secret_fields()` (editing it
does not reset a key's age). Imported notes and custom fields go there. It travels with shared items like
any other field.

Web logins also have **Código 2FA (TOTP)** (`fields.totp`, kept like the notes: `secret` + `note`, not substitutable).
Imports put a login's TOTP there when it parses (Bitwarden `login.totp`, 1Password `OTPAuth`, KeePassXC `TOTP`), else
in the notes. The AI never gets the seed; it gets the current code only as `{{totp_code}}` when the user ticks it in
the credential's AI permissions (`policy.ai_totp`, local to this PC like `policy.approval`: never synced to or from
the team). The detail shows the code with a countdown ring, fetched with the presence token only while on screen.

**AI clients.** The MCP server reads the client's name from the handshake (`clientInfo.name`) and sends it with every
request (`client` next to `op`); the service records `{first, last, requests}` per name for AI ops only, in
`data/ai_clients.json` (names and times, no secrets), and `ai_clients` (GUI only) returns them. `integrations.py`
connects Claude Code (CLI), Claude Desktop (stdio), Cursor (`~/.cursor/mcp.json`), VS Code (`%APPDATA%/Code/User/mcp.json`,
`servers`, JSON with comments), Windsurf (`~/.codeium/windsurf/mcp_config.json`, `serverUrl`) over the app's HTTP server
with its bearer token, and Codex (`~/.codex/config.toml`, stdio), keeping the rest of each file.

### 1.2 Rotation, health and copies found

* **Rotations that can't be lost.** A new password is kept in the vault (section `rotation`, per entry
  `pending = {field, value, since, generated}`) before the app tells the user to set it anywhere:
  `rotation_begin {id, generate | value}` (the service generates it; the page never gets it),
  `replace_key {id, pending: true}` saves it as the current one, `rotation_discard {id}` forgets it. Entries carry
  `pending_rotation = {since, generated}` (never the value) and the wizard reopens with "Rotación a medias".
  `rotation_secret {id, what: value | command}` returns it for the app to copy to the clipboard; like
  `export_vault` it is in `TEAM_EXPORT_OPS`, so a Windows-session unlock is not enough.
* **Database passwords applied by the service.** `rotation_apply {id, used_in?}` runs the engine's own client
  (`psql`, `mysql`, `sqlcmd`, `redis-cli`; found on PATH and allowed by the credential's `policy.commands`), with
  the SQL on stdin: it connects with the current password, changes it, logs in with the new one, and only then
  saves it. On failure nothing is saved and the new one stays pending (`apply_failed`, `unverified`,
  `no_client`). `guide.apply = {client, available, reason}` tells the app whether it can.
* **Uploads that fail after a rotation** (GitHub secrets) stay in `rotation.entries[id].failed_uploads`; entries
  show `failed_uploads` (without the token id) and `retry_uploads {id}` tries again.
* **Test requests.** An API key of a provider the app does not know can have `test_request = {method: GET | HEAD,
  url, status}` (an allowed host of the credential; a path is joined to its API address), set by the user
  (`set_test_request`) or the AI (`update_credential`). `exposure.check_alive` uses it, so the key is tested by
  the periodic checks, when rotating it and when checking that the old one is dead.
* **Copies found.** `exposure_ignore {session, id, location, ignore}` keeps a finding but stops it counting.
  `exposure_redact {session, id, location, data}` returns a piece of an AI conversation or a shell history with the
  secret replaced by `[REDACTED:id]`: the app (which alone can read the user's files) sends the file in whole
  lines, writes the result in place, keeps a `.secretbroker.bak` copy next to it (found by the next search until
  deleted) and calls `exposure_redacted`. The secret never leaves the service.
* **Health** (`health`) also counts team access, old keys not revoked yet, failed uploads, rotations left halfway
  and keys never tested, and returns `scanned`, `checked` and `complete`: without a search for copies and a check
  with the providers the app shows "Sin datos aún" instead of a score.

### 1.3 Browser autofill

A Manifest V3 extension (`extension/`, one source for Chrome, Edge, Brave and Firefox; see `extension/README.md`)
fills web logins. It never opens or uses a network port: the browser starts `secretbroker/native_host.py` through a
launcher (native messaging, 4-byte length + JSON on stdin/stdout), and the host relays to the service with
`client.request`, adding `_ext = {origin, pair, key, browser}`. `origin` comes from the browser's command line
(`chrome-extension://<id>/`, or Firefox's extension id), so the extension cannot choose it.

* **Ops** (`service.EXTENSION_OPS`, never in `AI_OPS`; the service refuses `_ext` on any other op):
  `ext_hello` → `{state, paired, browser, pending: {code}?}`; `ext_pair {name}` → `{pending, code}`;
  `ext_logins {url, frame_url?}` → `{host, domain, secure, frame, logins: [{id, name, username, site, exact, can_fill,
  why, totp, collection}]}` (never a value); `ext_search {query}` → web logins to open their site (not fillable from
  there); `ext_fill {id, url, frame_url?, what: login | totp | username | password, copy?}` → the values;
  `ext_save_check {url, username, password}` → `{action: new | update | none, id?, name}`; `ext_save` (same, `name?`).
  The host relays only these (`hello pair logins search fill save_check save`) plus `open_app`, which it does itself.
* **Who may ask.** `origin` must be in `native_host.ALLOWED_ORIGINS` (the id pinned by `key` in the manifest, store
  ids to be added). Except `ext_hello` / `ext_pair`, the browser must be **connected**: the extension makes a random
  `{pair, key}` (kept in `storage.local`); `ext_pair` queues a request with a 6-digit code (5 min), which the app
  shows (`status.browser_pairing`) with the same code the popup shows, and `browser_pair_answer {id, accept}` (in
  `PROVEN_OPS`: one click, but after a session unlock Hello or a password once) stores `sha256(key)`, the origin and
  the name in `data/browsers.json` (outside the vault, so a locked vault can still say "connected but locked").
  `browser_status` lists them (with `last_seen`, in memory), `browser_forget {id}` removes one.
* **Matching** (`secretbroker/autofill.py`, vendored Public Suffix List in `secretbroker/data/`, private section
  included). A web login's addresses are `fields.url` plus `entry.autofill.sites`; `entry.autofill.match` is
  `domain` (default: same registrable domain, any subdomain), `host` (exact host) or `never`. IP addresses,
  `localhost`, single-label names and public suffixes only match themselves. A saved port must match; an `https`
  login is never offered on `http` (except loopback). A frame is only served if it is of the top page's registrable
  domain (`frame` error otherwise); the extension sends `frame_url` from `sender.url`, the top URL from `tab.url`.
  `ext_fill` re-checks the match, so asking for another site's id gets `mismatch`.
* **Permissions.** Team credentials with `use` are listed with `can_fill: false, why: "use_only"` and refused by
  `ext_fill` (`forbidden`, audited as denied): filling would hand the value to the page. Saving never changes a
  credential this user may not write (`can_write_shared`); `ext_save` is in `TEAM_PUSH_OPS`.
* **Activity.** Fills, copies and saves are audited with `actor: "browser"` and `client: "Navegador · <browser>"`
  (`browser_fill`, `browser_copy`, `browser_save`, `browser_pair`, `browser_forget`); Actividad has a «Navegador»
  filter. Asking which logins a page has does not count as activity for the inactivity lock; a fill or save does.
  After the inactivity lock, with "open with my Windows session" on, the host reopens the vault like the AI does
  (`client.reopen_with_session`), never after «Bloquear».
* **In the extension.** Nothing is filled on page load: only after a trusted click in its menu (closed shadow
  root) or popup, or the `fill-login` command; values go only to the frame that will be filled (`tabs.sendMessage`
  with `frameId` and the origin the service matched: a frame that shows another origin by then refuses them),
  which fills only visible, enabled fields in a frame of a usable size; for a sub-frame the top page must show a
  visible iframe of that origin. After a form is sent (trusted submit, click or Enter) it asks
  `ext_save_check`; the offer (with the typed values) waits in `storage.session` for 5 minutes and is saved only
  when the user clicks «Guardar» / «Actualizar» in the page's bar or the popup.
* **Registration.** `native_host.register()` writes a launcher (`secretbroker-host.cmd`: the bundled `python.exe -I`)
  and two host manifests in `%LOCALAPPDATA%\SecretBroker\native-host`, and the HKCU keys of Chrome, Chromium, Edge,
  Brave and Firefox. The installer runs it as the desktop user and the app again at every start (not for test
  instances); uninstalling removes the keys. On Linux and macOS, `register()` / `install_manifests(launcher)` write
  a `secretbroker-host` shell launcher and the manifests into each browser's per-user folder; the `.deb`'s `postinst`
  and the `.pkg`'s `postinstall` run it for every desktop account, and the app again at every start. The installer copies `extension/` to `{app}\extension`;
  Ajustes › Navegador opens the browser's extensions page and that folder until the extension is in the stores.

## 2. Team cryptography

All primitives already exist in `secretbroker/crypto.py` (scrypt, HKDF-SHA256, AES-256-GCM, X25519 `seal_to`/`open_from`)
plus Ed25519 from `cryptography`.

### 2.1 Account keys

On sign-up the desktop service generates, client side:

* `enc_keypair`: X25519 (others seal collection keys to it)
* `sign_keypair`: Ed25519 (signs key grants, so the server cannot inject its own collection keys)

From the **account password** (the user may reuse their master password; it is typed once when linking the account):

```
kdf          = {"name": "scrypt", "n": 2**17, "r": 8, "p": 1, "salt": <16 random bytes, b64>}
master       = scrypt(password, kdf)                          # 32 bytes, never leaves the client
auth_key     = HKDF(master, info=b"secretbroker/team-auth/v1") # sent to the server as auth_hash (b64)
wrap_key     = HKDF(master, info=b"secretbroker/team-wrap/v1") # never leaves the client
private_blob = AES-GCM(wrap_key, json{x25519, ed25519 raw private keys b64}, aad=b"secretbroker/team-keys/v1|" + user_id)
```

The server stores `scrypt(auth_hash, server_salt, n=2**14, r=8, p=1)` (it never stores auth_hash itself) and the
opaque `private_blob`, so a second device can log in and recover the keys. After login the desktop keeps the private
keys and a session token in the vault: **no further password prompts** (see "approval friction" rule: password once,
then one click).

Changing the account password re-wraps `private_blob`; it does not change keys.

### 2.2 Fingerprints and key pinning

`fingerprint(user) = SHA-256(x25519_pub || ed25519_pub)` as 40 decimal digits (`int(digest) mod 10^40`, 133 bits)
in 8 groups of 5: the **código de seguridad** the app shows, easy to read out over the phone. A typed code is also
accepted as the 32 hex chars earlier versions showed, and pins are compared by recomputing the code from the pinned
keys, so pins made by earlier versions keep working. The server hands out
public keys, so a client never trusts one on first sight: a key is pinned (`team.pinned`) only by an explicit act of
the user on this PC:

* **confirming** someone (an admin lets in who accepted an invite) or **verifying** them (any member, for someone
  already in the organization): one click, the fingerprint is shown to compare over another channel;
* **accepting an invite** pins whoever sent it (accepting is the user saying they know that person).

Only pinned keys are used: a grant is sealed only to a pinned key, and a received grant is only opened if it is
signed by this user or by a pinned person who `manage`s the collection (by its signed member list, 2.6). Anything
else leaves the collection (or the new key version) unused and lists that person in `team_status.waiting` until the
user verifies them. A pinned key that changed is never re-pinned with one click: the user must type the fingerprint
the other person reads out.

**Pins follow the account.** Every pin carries `at` (when it was made) and the pins live, encrypted, on the server
as the account's own data (`GET/PUT /me/data`): `blob = AES-GCM(HKDF(x25519_priv || ed25519_priv,
"secretbroker/account-data/v1"), {pinned, counter}, aad="secretbroker/account-data/v1|" + user_id)`. Only devices
of the account have that key (not derived from the password, so a password change does not strand it). Each sync,
`connect` and `confirm_member` merge it with the local pins (per person, the newest `at` wins), refuse a blob whose
`counter` is lower than one already seen (no rollback), and upload the result with `base_revision` (a `409` is
merged on the next sync). Verifying someone once is enough for all of the user's PCs.

### 2.3 Organizations, collections and items

* **Organization**: a team. Roles: `owner`, `admin`, `member`. Admins invite and remove members and create collections.
* **Collection**: a shared folder of credentials with its own random 32-byte **collection key** (`key_version` starts at 1).
  Members get the key through a **key grant**:
  ```
  grant = {
    "sealed": seal_to(member_x25519_pub, collection_key, aad=b"secretbroker/grant/v1|" + cid + "|" + str(key_version) + "|" + member_id),
    "granted_by": <user id>,
    "signature": Ed25519(granter, b"secretbroker/grant/v1|" + cid + "|" + str(key_version) + "|" + member_id + "|" + sha256(sealed json))
  }
  ```
  The receiving client verifies the signature against the granter's pinned key before trusting the key.
* **Permissions per collection member**: `manage` (members, rotate, edit), `edit` (write items), `view` (read and reveal),
  `use` (the AI and `sb run` can use the credential; the app does not reveal or copy it). `use` is enforced by the client
  service: a malicious modified client of a member *could* extract it, exactly like "hide passwords" in other managers.
  The UI says so.
* **Collection name**: encrypted with the collection key (`AES-GCM`, aad `secretbroker/collection-name/v1|cid`).
* **Item**: one credential. Plaintext is the vault entry JSON (without local-only data: approvals, destinations,
  exposure, used_in stays shared), encrypted with the collection key:
  `aad = b"secretbroker/item/v1|" + cid + "|" + item_id + "|" + str(key_version)`. The plaintext includes
  `author` and `updated` so clients can show who changed what, and `seq`, a per-item counter every write increments:
  a client refuses an item whose `seq` is lower than the one it has (or equal with other content), so the server
  cannot serve an older version again. Items with a `key_version` older than the collection's are refused (every
  live item is re-encrypted at a re-key, so only someone who left could have made them), and clients keep only the
  current collection key; a collection served with an older `key_version` than the client knows is refused.

### 2.4 Membership changes and offboarding

Removing a member (or downgrading them out of a collection) **re-keys** every collection they could read: a member with
`manage` generates a new collection key, re-encrypts all items and seals new grants for the remaining members, in one
atomic `rotate` call (`key_version + 1`). The server marks a collection `needs_rekey` until that happens and refuses
new grants and item writes (`409 needs_rekey`) with the old version; clients keep such edits local and push them
after the re-key. The new key is sealed only to listed members this client trusts (2.2), never to the person just
removed; if the server lists anyone else, the re-key stops and asks the user to verify them. Which collections to
re-key comes from the server's answer *and* from the members this client last saw in each collection. Removing from
the organization the only `manage` member of a collection is refused (`400 last_manager`, with `collections`).

Re-keying protects *future* changes only: the removed person may have seen the secrets. Every credential in those
collections is flagged **"rotate: <person> had access"** and appears in the reminders and in the guided rotation
wizard. This is the main team pain point other managers leave to the admin's memory.

### 2.5 Incoming changes that widen where a key can go

A teammate with `edit` could change a shared credential's `policy` (allowed hosts, commands, env) to send it somewhere
else through *your* AI. So a synced change to anything that decides where a key can go is **quarantined** locally:
the entry keeps its previous policy and shows "change to review" until the user accepts it with one click. Names,
notes, tags and secret values (a teammate rotated the key) apply immediately. The local approval mode
(`policy.approval`) is always the local user's own and is never taken from the server. A credential new to this PC
arrives with its programs and environment variables (`policy.commands`, code that would run on this PC) quarantined
the same way; its web hosts and server fields apply. A local id freed by a synced deletion is never given to another
credential in that round, and the service forgets the approvals, destinations and exposure records of every
credential a sync removes.

The browser hands a filled password to the page, so the pages where it fills a shared web login are a destination
too: a change that lets it fill somewhere new (`fields.url`, `autofill.sites`, or `autofill.match` from `host` to
`domain`; `teams.new_fill_sites`) is quarantined the same way (`pending_policy.fill`), and until the user accepts it
the browser fills only where it did. Without this, a teammate about to be removed could point the login at their
own site and receive the password the team sets after rotating it.

The **description** is what the AI reads as instructions about a credential, so a teammate's new description is a
prompt-injection vector: it is quarantined like a new destination (`text_changes`; `pending_policy.texts` and
`description`). The AI keeps reading the previous text until the user accepts it with one click; an editor may
reject it for the team; writing the description by hand settles it. Removing the text applies at once. A change
signed by the user's own account (another of their PCs) is never quarantined. Descriptions, `used_in` and rotation
guides of shared credentials are still marked for the AI with `shared.texts_by = "team"` (information, not its
user's instructions), and an AI edit of a shared credential always asks the user.

### 2.6 Signed member lists, item versions and deletions

The server routes membership, so without signatures it could add anyone to a collection, change a permission,
claim a teammate wrote something or delete credentials. Everything that decides who is in a collection, what an
item says and what is deleted is signed with the author's Ed25519 key and checked against pinned keys (2.2):

* **Member lists.** Each membership change (create, grant, permission change, removal, re-key) carries the new full
  list: `record = {body: {cid, seq, prev, key_version, by, members: {uid: permission}, at}, signature}`,
  `signature = Ed25519(by, "secretbroker/members/v1|" + canonical(body))`, `prev = sha256(canonical(previous
  body))`, `seq` counts from 1. The server stores the chain as received (`collection_manifests`) after checking that
  the record is the next link, is in the caller's name and describes exactly what it is about to store
  (`400/409 members_record` otherwise); once a collection has one, every membership change must bring the next.
  Clients keep the last verified link (`collections[cid].manifest = {seq, hash, members, by, key_version,
  writers}`) and extend it with `GET /collections/{cid}/manifest?since=seq`: each link must be signed by someone
  pinned (else `untrusted`, the person goes to `waiting`) who was `manage` in the previous list, or only take its
  signer out (leaving). A device that sees the chain for the first time starts from the newest link signed by a
  pinned manager. Any other break is `bad_members`: the collection is not used, nothing is shared into it, and the
  user is told the server shows an unsigned member list. The server's member rows must match the signed list
  (people missing were removed from the organization; the next re-key signs the list without them), and the user's
  own permission is the signed one, never the server's.
* **Item versions.** Item plaintext adds `sig = {by, signature}` over `"secretbroker/item-sig/v1|" + canonical({cid,
  iid, seq, hash: sha256(canonical(entry)), by, at: updated})` (inside the encryption, so re-encrypting at a re-key
  keeps it). In a collection with a signed list, a new version is applied only if signed by a pinned `writer`
  (someone with `manage`/`edit` since the last re-key); others are refused (`unsigned`) and reported. A re-key
  re-signs, as the manager, items whose signer can no longer write, and items from before 0.16.
* **Deletions.** `DELETE /collections/{cid}/items/{iid}` takes `deletion = {by, seq, signature}` over
  `"secretbroker/delete/v1|" + canonical({cid, iid, seq, by})`, stored with the tombstone and returned as
  `items[].deletion`. A client deletes its copy only if a pinned writer signed it with a `seq` above the one it
  knows; anything else is ignored (the credential stays; an editor's next edit writes it again over the tombstone),
  reported (`notes.unsigned`, a notice, `team_unsigned` in Actividad) and shown as an error of that collection.
  Apps before 0.16 delete without signing, so a team should update every desktop together.
* **Collections from before 0.16** have no list. The first sync of a manager whose PC trusts every member signs one
  with a re-key (which also signs the items); until then they work as before.
* **Who did it.** Actividad records each incoming change (`team_add`, `team_update`, `team_review`,
  `team_delete`) with `by`: the name of whoever signed it (else the server's `updated_by`, unverified).

### 2.7 Mass deletions and recovery

* **Many deletions at once.** If one sync would delete more than 5 credentials of a collection, or at least 3
  that are half of it or more, nothing is deleted: they are held (`collections[cid].held`, `shared.pending_delete =
  {by, at}`), `team_status.held_deletions = [{collection, collection_name, count, by, gone, at, can_restore}]` and
  the user decides with one click (`team_resolve_deletions {collection, apply}`): delete them here too, or keep
  them, which restores them for the whole team when the user can edit (the next push writes them over the
  tombstones) and otherwise leaves them as personal credentials. A collection the server stops listing is treated
  the same way when it held that many credentials (`gone`). Leaving an organization or a collection on purpose
  removes its credentials at once. The server also limits deletions to `SB_MAX_DELETES_PER_HOUR` per account
  (`429`); the client keeps the rest for a later sync.
* **Owners can recover every collection.** A manager's app gives each organization `owner` it has pinned a signed
  `manage` grant on every collection it manages (at creation and on each sync), so a collection never depends on one
  person. Owners not verified yet are listed in `waiting` with `reason: "recovery"`. `team_collections` carries
  `managers`, `single_manager` and `signed`, and Equipo warns about collections only one person manages.

## 3. Sync

* The desktop service syncs while the vault is unlocked: on unlock, every 5 minutes and on demand.
* Pull: `GET /collections/{cid}/items?since=<revision>` returns items with a server-assigned, collection-wide increasing
  `revision` (tombstones included).
* Push: `PUT /collections/{cid}/items/{iid}` with `base_revision`; the server answers `409` if someone changed it first.
  On conflict the server version wins and the local edit is kept as a separate local entry `<id>-conflict` for the user
  to compare. Credentials rarely change concurrently, so this stays simple and visible.
* Local entry ↔ item mapping: `entry["shared"] = {"collection": cid, "item": iid, "revision": n, "permission": p,
  "org": oid}`. Local ids stay unique; an incoming item whose id clashes gets a suffix.

## 4. Server

* Python, Starlette + uvicorn (already dependencies of `mcp`), stdlib `sqlite3` in WAL mode. Plain SQL kept
  Postgres-compatible for a later backend. Package `server/secretbroker_server`, its own `pyproject.toml`, no Windows
  dependencies. Docker image + `docker-compose.yml` with Caddy for TLS.
* Configuration by environment: `SB_DATA_DIR`, `SB_SIGNUPS` (`open` | `invite` | `closed`), `SB_PUBLIC_URL`,
  `SB_ADMIN_EMAILS`, `SB_SESSION_DAYS` (30).
* Security: HTTPS expected (refuses non-TLS `SB_PUBLIC_URL` unless `SB_ALLOW_HTTP=1` for local tests), bearer tokens
  stored as SHA-256, login rate limiting per IP and per e-mail, constant-time compares, uniform `prelogin` answers for
  unknown e-mails (deterministic fake salt) to avoid account enumeration, request size limits, strict JSON validation,
  security headers, no CORS (only the desktop client talks to it).
* Audit: the server records metadata events (login, invite, join, remove, grant, revoke, rotate, item put/delete with
  ids) readable by org admins. It cannot record contents because it never has them.

### 4.1 HTTP API (`/api/v1`, JSON, `Authorization: Bearer <token>` except where noted)

| Method & path | Body → Response |
|---|---|
| `GET /info` (no auth) | → `{name, version, signups, verification: email|admin|off}` |
| `POST /accounts/prelogin` (no auth) | `{email}` → `{kdf}` |
| `POST /accounts/register` (no auth) | `{user_id, email, name, kdf, auth_hash, public_key, signing_public_key, private_blob, invite_token?}` → `{user_id}`. The client picks `user_id` (UUIDv4) so it can bind `private_blob` to it; the server only checks it is new. |
| `POST /accounts/login` (no auth) | `{email, auth_hash, device_name}` → `{token, user: {id, email, name}, kdf, private_blob, public_key, signing_public_key}` |
| `POST /accounts/logout` | → `{}` (revokes this token) |
| `GET /me` | → `{user, devices: [{id, name, created, last_seen, current}]}` |
| `POST /accounts/verify/send` | `{}` → `{verified, sent, verification?}` (a new e-mail code; one a minute, else `429`) |
| `POST /accounts/verify` | `{code}` → `{verified: true}` (`400 invalid_code`, `400 code_expired` after 30 min or 5 wrong tries) |
| `GET /me/data` | → `{blob, revision}` (the account's encrypted data, 2.2; `blob` null at first) |
| `PUT /me/data` | `{blob, base_revision}` → `{revision}` / `409 {revision}` |
| `DELETE /me/devices/{id}` | → `{}` |
| `POST /accounts/password` | `{current_auth_hash, kdf, auth_hash, private_blob}` → `{}` (revokes other sessions; a wrong current password is `403 invalid_credentials` and counts like a failed login) |
| `GET /users/{uid}/keys` | → `{id, email, name, public_key, signing_public_key}` (only users sharing an org with you, or invited by your org) |
| `GET /users/keys?ids=a,b,…` | → `[{id, email, name, public_key, signing_public_key}]`, at most 200 ids; people you may not see are left out (one request for a team's members; clients fall back to the single endpoint on a `404`) |
| `POST /orgs` | `{name}` → `{id}` (caller is owner) |
| `GET /orgs` | → `[{id, name, role}]` |
| `GET /orgs/{oid}/members` | → `[{user_id, email, name, role, status: invited|accepted|confirmed}]` |
| `POST /orgs/{oid}/invites` | `{email, role}` → `{id}` (admin) |
| `GET /invites` | → invites addressed to my e-mail `[{id, org_id, org_name, role, invited_by}]` (`[]` until the e-mail is verified) |
| `POST /invites/{id}/accept` | → `{}` (status accepted; an admin must confirm, see fingerprints; `403 email_unverified` until verified) |
| `POST /orgs/{oid}/members/{uid}/confirm` | → `{}` (admin) |
| `PATCH /orgs/{oid}/members/{uid}` | `{role}` → `{}` (owner/admin rules) |
| `DELETE /orgs/{oid}/members/{uid}` | → `{needs_rekey: [cid…]}` (admin, or self to leave; `400 last_manager {collections}` if they are a collection's only manager) |
| `POST /orgs/{oid}/collections` | `{id, encrypted_name, grant, members_record?}` → `{}` (admin; creator gets `manage`; the first signed list, 2.6) |
| `GET /collections` | → my collections `[{id, org_id, encrypted_name, key_version, permission, grant, needs_rekey, revision}]` |
| `DELETE /collections/{cid}` | → `{}` (manage) |
| `GET /collections/{cid}/members` | → `[{user_id, email, name, permission}]` |
| `GET /collections/{cid}/manifest?since=N` | → `{records: [{body, signature}]}` (the signed member lists after `seq` N, oldest first) |
| `PUT /collections/{cid}/members/{uid}` | `{permission, grant?, members_record?}` → `{}` (manage; `grant` required when adding; member must be confirmed in the org; `members_record` required once the collection has one) |
| `DELETE /collections/{cid}/members/{uid}` | `{members_record?}` → `{}` (manage, or self to leave; sets `needs_rekey`) |
| `POST /collections/{cid}/rotate` | `{key_version, encrypted_name, grants: {uid: grant}, items: {iid: ciphertext}, members_record?}` → `{revision}` (manage; atomic; must cover every member and every live item) |
| `GET /collections/{cid}/items?since=N` | → `{revision, items: [{id, revision, key_version, ciphertext, deleted, updated_by, updated, deletion?}]}` |
| `PUT /collections/{cid}/items/{iid}` | `{ciphertext, key_version, base_revision}` → `{revision}` / `409 {revision}` (edit; `409 needs_rekey` while the collection waits for a re-key; `413 collection_full` past the quota) |
| `DELETE /collections/{cid}/items/{iid}` | `{base_revision, deletion?: {by, seq, signature}}` → `{revision}` (edit; `429` past `SB_MAX_DELETES_PER_HOUR`) |
| `GET /orgs/{oid}/events?before=` | → `[{time, actor, action, target}]` (admin) |

Errors: `{"error": "<message>", "code": "<code>"}` with proper HTTP status (400 invalid, 401 auth, 403 forbidden,
404 not found, 409 conflict, 413 too large, 429 rate limited).

Implementation notes (`server/`, binding for clients):

* **Formats.** Every id (user, org, invite, collection, item, device) is a UUID; a malformed id in a URL is `404`.
  Opaque blobs are the dicts produced by `secretbroker/crypto.py`: `private_blob`, `encrypted_name` and item
  `ciphertext` are `{nonce, ciphertext}` (`seal`), `grant.sealed` is `{epk, nonce, ciphertext}` (`seal_to`); all
  values base64. `kdf` must be scrypt with `n` a power of two in 2^14..2^20. `auth_hash`, `public_key`,
  `signing_public_key` are 32 bytes, `signature` 64 bytes, base64. Unknown body fields are `400`. Item ciphertext ≤ 256 KiB.
* **Grants** must have `granted_by` = the caller. A grant (adding or replacing a member) while `needs_rekey` is `409`
  with code `needs_rekey`. Member removal from a collection, by a manager or by the member leaving, sets `needs_rekey`;
  the last `manage` member cannot leave or be downgraded (`400 last_manager`); the last owner likewise (`400 last_owner`).
* **Revisions.** New items use `base_revision: 0`. Conflicts are `409 {error, code: "conflict", revision}`; a write
  with a stale `key_version` is `409 {code: "key_version", key_version}`. `rotate` must send `key_version` = current + 1
  (else `409 key_version`), grants for exactly the current members and ciphertext for exactly the live items (else
  `400 incomplete`); all rotated items get the one new revision.
* **Extra response fields** (additive): `GET /orgs` items carry `status`; invited rows of `GET /orgs/{oid}/members`
  carry `invite_id` for org admins only (it works as a signup token) (and `user_id` null if not registered yet); `GET /invites` adds `invited_by_email`,
  `invited_by_name`; `user` objects add `admin` (server admin); events add `id` (newest first, 100 per page,
  `before=<id>`); the 429 answer has `retry_after` and a `Retry-After` header.
* **Extra endpoints.** `DELETE /invites/{id}` → `{}` (the invitee declines, or an org admin withdraws it).
  `POST /admin/invites` `{days?}` → `{token, expires}` (server admin: a single-use signup token).
* **Signups.** `open`: anyone; the first account becomes server admin. `invite`: `invite_token` must be a signup
  token (`POST /admin/invites` or `secretbroker-server create-invite`) or the id of a pending org invite for that
  same e-mail. `closed`: nobody. E-mails in `SB_ADMIN_EMAILS` are server admins and register (in any mode, `closed`
  included) only with a signup token, normally from the server's command line (`secretbroker-server
  create-invite`), so nobody can take the address first.
* **E-mail verification** (`SB_EMAIL_VERIFICATION=required`, the default). `register` answers `{user_id, verified,
  invited_to?}` and `user` objects carry `verified`. An account is verified by the e-mailed code (`SB_SMTP_*`; 8
  digits, stored as an HMAC with the server secret) or by the admin (`secretbroker-server verify-email <e-mail>`;
  `unverified` lists who is waiting). Until then `GET /invites` is empty, `accept` is `403 email_unverified`, invite
  rows of `GET /orgs/{oid}/members` do not name the account and the invite path of `/users/{uid}/keys` does not
  show its keys. Registering with a pending org invite id for that e-mail (`users.invited_to`) lifts this for that
  one organization only: anyone can create an organization and invite any address, so its own invite code must
  not hand the address the invites of others. `SB_EMAIL_VERIFICATION=off` (a self-hoster's
  explicit choice) verifies everyone at registration. Accounts that existed before schema 2 count as verified.
* **Limits.** Login failures are throttled per e-mail (5 free) and per client address (20 free), then each failure
  doubles the wait (max 15 min) and attempts during the wait get `429`, even with the right password. Registrations
  are throttled per address. A collection's ciphertext is capped at `SB_MAX_BODY / 2` so a re-key always fits in
  one `rotate` request. An account deletes at most `SB_MAX_DELETES_PER_HOUR` items an hour (100). More settings:
  `SB_ALLOW_HTTP`, `SB_TRUST_PROXY` (use `X-Forwarded-For`, only behind the bundled Caddy), `SB_MAX_BODY`,
  `SB_SERVER_NAME`, `SB_EMAIL_VERIFICATION`, `SB_SMTP_HOST/PORT/SECURITY/USER/PASSWORD/FROM`.

## 5. Desktop service operations for teams

Added to `secretbroker/service.py` (GUI only, never reachable from the AI unless listed in `AI_OPS`):
`team_status`, `team_connect` (server url + email + password + register|login), `team_disconnect`, `team_sync`,
`team_orgs`, `team_create_org`, `team_invite`, `team_invites`, `team_accept_invite`, `team_members`,
`team_confirm_member`, `team_set_role`, `team_remove_member`, `team_collections`, `team_create_collection`,
`team_collection_members`, `team_grant`, `team_revoke`, `team_share_entry`, `team_share_entries`,
`team_unshare_entry`, `team_accept_change`, `team_events`, `team_overview`, `team_offboarding`,
`team_verify_email {code}`, `team_send_code` (→ `{sent, verified, verification}`), `team_resolve_deletions
{collection, apply}` (→ `{applied, count, collection_name}`; a proven op like `delete_entry`). Client logic and
crypto live in `secretbroker/teams.py`.

The AI sees shared credentials like any other (with `shared: {org, collection, permission}` in `list_secrets`), and
`reveal`/copy is refused for `use` permission.

Implementation notes (`secretbroker/teams.py`, `service.py`, binding for the GUI):

* **Plaintext formats.** Item plaintext is `{"entry": <entry without shared/updated/secret_since and without
  policy.approval>, "author": {id, name}, "updated", "seq", "sig": {by, signature}}`; the author shown is the signer
  (`shared.author.verified`), else the server's `updated_by` (the plaintext `author` is informative). The collection name plaintext is JSON `{"name"}`, plus `{"removed": [names], "version": n}`
  after a re-key, which is how members who did not re-key learn who to "rotate because" of.
* **Local state.** Vault section `team`: `server_url, token, user {id, email, name, verified}, verification, device,
  keys {x25519, ed25519}, public_key, signing_public_key, pinned {uid: {fp, public_key, signing_public_key, email,
  name, at}}, data_counter, orgs, collections {cid: {org, name, keys {version: b64}, key_version, permission,
  revision, needs_rekey, members, manifest, held?, gone?, items {iid: {revision, hash, content, seq}}}}, waiting,
  last_sync`. `items[*].content` is the last synced content ("base"):
  a local entry whose content differs from it has an unpushed edit.
* **Entry block.** `entry.shared = {org, org_name, collection, collection_name, item, revision, permission, author,
  changed, pending_policy?, pending_delete?, rotate?}`. `pending_policy = {by, at, changes: [lines], hosts,
  only_hosts, texts, description?, policy, fields}` (or `entry` when the template changed; `hosts`: the new web
  hosts, named in the review box). Quarantined: new hosts, new programs, new or changed env vars, a different HTTP
  auth, the `host`/`port`/`engine` fields, and a new description (`texts`).
  `rotate = {people, since, fp, seen}`; the reminder (`kind: "team_access"`, `people`, `can_rotate`) lasts while the
  secret's fingerprint is `fp`, so any rotation (wizard, API, a teammate's) clears it. `seen` keeps everyone who ever
  had access, for `team_offboarding` (`[{person, since, total, pending: [ids]}]`: "Bob pudo ver 3 · 1 cambiada").
* **Display cache.** Vault section `team_view` (`orgs, invites, members {oid}, collection_members {cid}, events
  {oid}`): what the read ops last got from the server. `team_overview` returns it with the status, the collections,
  `unsent` and `offboarding`, from this PC only, so the Equipo view draws at once and then refreshes. Read ops use
  short timeouts (8 s), don't take the team lock and never write the team state (a sync owns it), only this cache.
* **Unsent edits.** `entries` adds `shared.unsent`: `"rekey"` (its collection waits to be re-encrypted) or
  `"pending"` (next sync); `status.team_held` counts the edits the last round held.
* **Permissions on this PC.** Without `edit`/`manage`, the service refuses edits, deletes and rotations of a shared
  credential; only its local approval mode may change. `delete_entry` with write permission deletes it for the team
  (tombstone); `team_unshare_entry` removes it from the collection but keeps it here as a personal credential.
  Losing access to a collection (removed, left, deleted, `team_disconnect`) removes its credentials from this PC,
  except a credential this user shared from their personal vault (`shared.own`), which stays as a personal one, and
  edits not pushed yet, kept as a personal `<id>-conflict` copy.
* **Waiting for trust.** `team_status.waiting = [{user_id, name, email, fingerprint, org, collections, reason?}]`:
  people whose key is not pinned here and who signed a collection key or member list for this user (or must receive
  one in a re-key, or are owners who should get recovery access: `reason: "recovery"`). `team_status` also has
  `verified`, `verification` and `held_deletions` (2.7).
  The sync notes add `trust` (their names) and `held` (edits kept local while a collection waits for a re-key).
* **Proofs.** `team_status, team_sync, team_orgs, team_invites, team_members, team_collections,
  team_collection_members, team_events` only need an unlocked vault; every other team op needs a proof and accepts
  the presence token (one click). After an unlock with the Windows session (no proof; anything running as the user
  could do it), the ops that can send credentials or keys to another account (`team_connect, team_invite,
  team_accept_invite, team_confirm_member, team_set_role, team_grant, team_share_entry`) answer `proof_required`
  once; a real proof returns a full presence token in the result (`presence`), and they are one click again. `team_sync` and the background sync never raise: `team_status.state` is
  `off | idle | syncing | ok | error | offline | reconnect`, with `error` and counts of the `last` round.
  The general `status` op also carries `team` (that state) and `team_sync` (time of the last finished round), so
  the GUI's 1.5 s poll notices a finished round and reloads only when `team_status.last` says something arrived.
  `error` is always one sentence for the user with what to do (`teams.explain`); codes and exception types only go
  to the service log. A session that expires raises one Windows notice.
* **Op parameters.** `team_connect {server_url, email, password, mode: register|login, name?, device_name?,
  invite_token?}`, `team_invite {org, email, role}`, `team_accept_invite {id}`, `team_members {org}` (rows add
  `fingerprint`, `key_changed`, `trusted`, `me`), `team_confirm_member {org, user_id, fingerprint?}`, `team_set_role {org,
  user_id, role}` (`team_confirm_member` pins the key on this PC; for a member already confirmed in the org it
  only verifies them locally, so any member may call it; a changed key needs `fingerprint`), `team_remove_member
  {org, user_id}` → `{rekeyed, pending, failed, offline, person, credentials}` (once the server let them go it never
  raises: a collection that can't be re-encrypted now stays `needs_rekey` for the next sync, the state is always
  saved, and every credential they could see is flagged at once), `team_create_collection {org, name}`,
  `team_collection_members {collection}`, `team_grant {collection, user_id, permission}`, `team_revoke {collection,
  user_id}` (own id: leave), `team_share_entry {id, collection}`, `team_share_entries {ids, collection}` →
  `{shared, failed: [{id, error}], collection_name}` (in `TEAM_EXPORT_OPS` like `team_share_entry`), `team_unshare_entry {id}`,
  `team_accept_change {id, accept?}`, `team_events {org, before?}`.

### 5.1 GUI (`secretbroker/web/app.js`)

* Sidebar view **Equipo** (a warning badge when the session expired, the server can't be reached, a sync failed or
  edits are held): not connected, an explainer and the link form (server, e-mail, account password; create account
  or log in; nothing prefilled, except from an invite link). Connected: the organization picker, sync state
  («Actualizando…» while it asks the server) and «Sincronizar ahora» in the header; banners on top (session expired,
  offline, invitations to accept, «Por verificar (N)» with each person's code and one-click «Confirmar» /
  «Verificar», "Bob pudo ver N credenciales · M cambiadas" opening the offboarding queue, «Por revisar» with
  quarantined changes and unsent edits); then tabs **Colecciones** (members and permission Gestor / Editor / Lector /
  Solo uso with a «?» popover, add / change / remove, create), **Personas** (invite, «Invitada · aún no ha entrado»
  with «Copiar instrucciones», role, remove), **Actividad** (admins) and **Tu cuenta** (código de seguridad,
  «Desconectar»). Offline, buttons that need the server are disabled.
* Banners also cover «Verifica tu e-mail» (the 8-digit code, «Enviar otro código»; on servers without e-mail, who
  to ask), held deletions («N credenciales esperan tu decisión»: «Recuperarlas para el equipo» / «Conservarlas en
  este PC» and «Borrarlas también aquí»), and the change review names a new description («… ha cambiado las
  instrucciones que lee la IA», with the text quoted). Collections that only one person manages say «Un solo gestor».
* Invites: no invite e-mail is sent. The admin gets instructions to pass on with a link
  `secretbroker://join?server=…&email=…&code=…` (the code is the invite id, which works as a sign-up code). The
  installer registers the `secretbroker:` protocol; `app.py` keeps a link it was opened with (also when the app is
  already running) in `join_link.json` for 10 minutes, and the page fills in the team form from it. Pasting the link
  into the server field does the same.
* Removing someone opens the **offboarding queue**: what they could see, the guided rotation for each one back to
  back, with «Saltar» and progress. Also reachable from Salud and the Equipo banner.
* Credential detail: «Compartir» (choose a writable collection or «Nueva colección…»), a «Compartida · <colección>»
  badge (permission in its tooltip and in the detail), «Dejar de compartir», the change review box («<Persona>
  quiere que la IA pueda enviar esta clave a: <hosts>»; «Rechazar y mantener como estaba», only with edit permission,
  undoes it for the whole team; «Permitir <host>»), reveal and copy hidden for `use`, and edit / delete / rotate
  limited to what the permission allows. Deleting a shared credential warns that it is deleted for the whole collection.
* Credential list: a team mark on shared rows, collection chips next to the tag filter, «Sin enviar» / «Cambiar:
  salió Bob» badges, and with a team account a checkbox on hover (shift-click for a range) to «Compartir N en…».

## 6. Platforms

Everything that depends on the operating system goes through `secretbroker.platform` (`platform/__init__.py`
picks `windows.py`, `linux.py` or `macos.py`; `_common.INTERFACE` lists what each must provide, and
`tests/test_platform.py` checks that all three do). The rest of the code never tests `sys.platform` for these.

| Concern | Windows | Linux (Ubuntu 22.04 / 24.04) | macOS 12+ (not yet tried on real Macs, see RELEASING.md) |
|---|---|---|---|
| Service account | local account `SecretBroker`, hidden, no interactive/network logon | system user `secretbroker` (nologin) | hidden role account `_secretbroker` (uid < 500, shell `/usr/bin/false`, no password) |
| Starting the service | scheduled task at boot (`installer/configure.ps1`) | systemd template unit `secretbroker@<owner>.service`, enabled per desktop account | LaunchDaemon `com.secretbroker.service.<owner>` per desktop account (`packaging/macos/secretbroker-setup`) |
| Data (`data/`) | `C:\ProgramData\SecretBroker\data`, ACL: service account only | `/var/lib/secretbroker/<owner>/data`, 0700 `secretbroker` | `/Library/Application Support/SecretBroker/<owner>/data`, 0700 `_secretbroker` |
| `broker.json` (`public/`) | ACL: users read | `public/` is `secretbroker:<owner's group>` 2750 (setgid), `broker.json` 0640: **only the owner** reads the token | `public/` 0750 `_secretbroker` plus an inherited ACL entry for the owner (every account shares the group `staff`): **only the owner** reads the token |
| Device key ("unlock with this PC") | DPAPI under the service account | AES-GCM with a 32-byte key in `data/machine.key` (0600); the device key file alone (e.g. in a backup) opens nothing | same as Linux (a role account has no keychain) |
| "Open with my session" token | DPAPI under the user | Secret Service (GNOME Keyring / KWallet) holds the key, else a 0600 file in `~/.local/state/secretbroker` | the login Keychain holds the key (a generic password; never shows a dialog), else a 0600 file |
| Account password proof | `LogonUser` | PAM, service `/etc/pam.d/secretbroker` (pam_unix only); the unit adds the `shadow` group so pam_unix may check another account | Open Directory (`ODRecord.verifyPassword`), never on a command line |
| Biometric proof | Windows Hello (TPM key, RSA) | none yet: password proofs (fprintd is a TODO) | Touch ID: a Secure Enclave P-256 key bound to the enrolled fingers (`secretbroker/touchid.py`); needs a signed build, otherwise password proofs |
| Lock screen | `WTSQuerySessionInformation` | logind `LockedHint`, else the screensaver's D-Bus `GetActive` | `com.apple.screenIsLocked` / `screenIsUnlocked` distributed notifications (delivered immediately), first state from `CGSessionCopyCurrentDictionary` |
| Start with the session | `HKCU\…\Run` | `~/.config/autostart/secretbroker.desktop` | LaunchAgent `~/Library/LaunchAgents/com.secretbroker.app.plist` (`open -g -a SecretBroker`) |
| Tray, notifications | WinForms `NotifyIcon` | Qt `QSystemTrayIcon` (StatusNotifierItem; GNOME needs Ubuntu's AppIndicator extension, otherwise closing minimizes), Qt / `notify-send` | menu bar icon (pystray, template image `assets/menubar.png`), Notification Center through `osascript`; the Dock icon reopens the window |
| Web view | WebView2 (pywebview WinForms) | QtWebEngine (pywebview Qt) | WKWebView (pywebview Cocoa) |
| One window | named mutex + event | Unix socket in `$XDG_RUNTIME_DIR`, peer uid checked | Unix socket in the per-user `$TMPDIR`, peer uid checked (`LOCAL_PEERCRED`) |
| Clipboard | Win32, excluded from history / cloud clipboard | Qt clipboard with `x-kde-passwordManagerHint` (else wl-copy / xclip), cleared after 30 s | `NSPasteboard` marked `org.nspasteboard.ConcealedType` / `TransientType` (else `pbcopy`), cleared after 30 s |
| Updates | signed `SecretBroker-Setup-<v>.exe`, UAC | signed `secretbroker_<v>_amd64.deb` (release.yml builds it on 22.04), `pkexec apt-get install`, then the app restarts | signed `SecretBroker-<v>-macos-<arm64 or x86_64>.pkg` (the Mac's own processor), `installer -pkg` after the administrator dialog, then the app restarts |
| AI apps, shells | `%APPDATA%`, PSReadLine history, registry environment | `~/.config`, fish / pwsh history, `/etc/environment` + `environment.d` | `~/Library/Application Support`, `~/.zsh_history` plus Terminal's `~/.zsh_sessions/*.history`, fish / pwsh, `launchctl` environment |

### 6.1 Linux isolation

The design mirrors Windows: the owner's programs, AI agents included, run as the owner and can neither read the
service's memory (another uid) nor its files.

* `secretbroker@<owner>.service` runs `python -I -m secretbroker.service --isolated --root /var/lib/secretbroker/<owner>`
  as `secretbroker`, `UMask=0027`. systemd creates `/var/lib/secretbroker/<owner>` (`StateDirectory`); the root-run
  `ExecStartPre=+…/secretbroker-prepare` creates `data/` (0700) and `public/` (owner's group, setgid 2750), refusing
  owners that are not desktop accounts (uid 1000–59999). Each instance runs with `TemporaryFileSystem=/var/lib/secretbroker`
  plus a bind mount of its own folder, so one owner's service cannot even see another's vault; also `ProtectSystem=strict`,
  `PrivateTmp`, `PrivateDevices`, kernel protections and `LimitCORE=0` (no core dumps with secrets).
* The owner reads `broker.json` (port, token, the service's public key) through the group; no other user can, unlike
  Windows where every local user may read it (the token alone does not unlock anything there either). That is the
  owner's own primary group as Ubuntu creates it (`USERGROUPS=yes`); when the primary group is shared with other
  accounts (a site-wide `users`), `secretbroker-prepare` gives `public/` to the group `secretbroker` instead and lets
  the owner in with an ACL (`u:<owner>:rX`, inherited; the package depends on `acl`).
* The app finds the service through `paths.is_installed()` (`/var/lib/secretbroker/$USER/public` exists). If it is
  stopped, `client.ensure_service` asks systemd to start the user's own unit; `/usr/share/polkit-1/rules.d/50-secretbroker.rules`
  allows exactly `start`/`restart` of `secretbroker@<that user>.service` for a local, active session, and nothing else
  (polkit 0.106+; on 22.04 the rule is ignored and `postinst` has already enabled the unit for every desktop account).
* Verifying the account password needs `/etc/shadow`: the unit adds the `shadow` group to the service only
  (`SupplementaryGroups=`), not to the account.

### 6.2 Ubuntu package

`tools/build_deb.sh` (run on Linux or WSL) builds `dist/secretbroker_<version>_amd64.deb`, one package for 22.04 and
24.04: a standalone CPython 3.12 (python-build-standalone, checksum pinned) in `/opt/secretbroker/python` and a venv
with SecretBroker and its dependencies in `/opt/secretbroker/venv` (22.04's Python is 3.10). `tools/deb_trim_qt.py`
drops the Qt modules the app never loads, and the build checks that the web view still renders. It installs with a
double click in the software installer: `postinst` creates the `secretbroker` user and enables and (re)starts the unit
for every desktop account; a menu entry (`/usr/share/applications/secretbroker.desktop`, also the handler of
`secretbroker://` invite links), the icon, and `/usr/bin/sb` / `/usr/bin/secretbroker` are installed. `prerm` (remove,
not upgrade) disconnects each owner's AI apps and deletes their preferences, like the Windows uninstaller; `postrm
purge` deletes `/var/lib/secretbroker` and the account; a plain remove keeps the vaults for a later reinstall.

### 6.3 macOS isolation

The same design as Linux, with launchd and an ACL:

* Nothing that runs as root or as `_secretbroker` is taken from `/Applications`, which an administrator's programs
  can rename and replace without a password: `postinstall` (the installer, with the administrator's consent) copies
  `secretbroker-setup` to `/Library/PrivilegedHelperTools/com.secretbroker.setup` and the bundled Python, with
  SecretBroker in it, to `/Library/Application Support/SecretBroker/.runtime` (root:wheel, read-only for others,
  `secretbroker-setup --install-runtime`); the daemons run that copy. At boot nothing is copied from the app.
* `secretbroker-setup` (root; run by the package's `postinstall`, and by the LaunchDaemon `com.secretbroker.setup`
  at boot and whenever `/Users` changes, so accounts created later get a service too) creates `_secretbroker`, and
  for each desktop account (uid 501+, home in `/Users`, a real shell) the folders and
  `/Library/LaunchDaemons/com.secretbroker.service.<owner>.plist`: `UserName _secretbroker`, `python -I -m
  secretbroker.service --isolated --root … --owner <owner>`, `Umask 027`, core dumps off, and `KeepAlive` only while
  the bundled Python exists (an app moved to the Trash leaves its services stopped). Daemons of deleted accounts
  are removed; their vaults stay. It never follows a symbolic link planted in a service folder.
* An account cannot start a system daemon: `start_service()` only tells the client there is one, and launchd
  restarts it within seconds when it stops.
* The owner reads `public/` through the ACL entry `user:<owner> allow list,search,…,file_inherit,directory_inherit`,
  which files the service creates there (`broker.json`, downloaded updates) inherit; no other account can.
* The Mac password is verified through Open Directory from the service (a role account may ask it); it is never
  stored nor passed on a command line.
* Touch ID runs in the app (as the owner), like Windows Hello: `create_key()` makes a Secure Enclave key with
  `kSecAccessControlBiometryCurrentSet | PrivateKeyUsage` (adding a finger invalidates it; the user activates Touch
  ID again), `sign()` shows the system's fingerprint sheet and returns an ECDSA-SHA256 signature, which the service
  checks with the stored public key (`winsec.verify_hello_signature` accepts RSA ≥ 2048 and P-256). The key needs
  the data protection keychain, i.e. a signed app (`packaging/macos/entitlements.plist`); unsigned, `is_supported()`
  is False and the app uses password proofs. The page names it «Touch ID» (`info().biometric_label`).

### 6.4 macOS package

`tools/build_macos.sh` (run on a Mac of the target processor) builds `dist/SecretBroker-<v>-macos-<arch>.pkg`:
`/Applications/SecretBroker.app` with a standalone CPython 3.12 (python-build-standalone, checksum pinned) in
`Contents/Resources/python` and SecretBroker installed into it (no venv: nothing to relocate), the extension, the
icon (`tools/make_icon.py --iconset` + `iconutil`, on Apple's 824/1024 grid), `secretbroker-setup` and `sb`.
`Contents/MacOS/SecretBroker` is a shell launcher that `exec`s the bundled Python, so Launch Services keeps the
process as SecretBroker.app (Dock, menu bar, `secretbroker://` links, which arrive as an Apple event and are
handled by `app._listen_for_links`). The component is not relocatable, so updates always replace the copy the
daemons use. `postinstall` copies the setup script and the runtime out of the bundle (§6.3), runs
`secretbroker-setup --restart`, links `/usr/local/bin/sb`, registers the browser
host for every account and opens the app for the logged-in user on a first install. Signing and notarization are
optional (`MACOS_SIGN_APP`, `MACOS_SIGN_INSTALLER`, `MACOS_NOTARY_PROFILE`; see docs/RELEASING.md).

## 7. Roadmap beyond this release

* macOS: try the port on real Macs (docs/RELEASING.md lists what CI cannot show), sign and notarize it with the
  owner's Apple Developer account (which also turns Touch ID on), and an uninstaller. Linux: fprintd as a
  biometric proof; a signed apt repository so updates also arrive through the system updater; Fedora (`.rpm`).
* English/Spanish UI (i18n of `web/app.js`).
* SSO (OIDC) and SCIM for the hosted SaaS; Postgres backend; org-wide policies (minimum rotation period, AI levels).
* A CLI-only client for servers/CI that reads a collection with a machine identity (service accounts).
