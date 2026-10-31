# SecretBroker architecture

SecretBroker has two products built from one repository:

| Part | What it is | Where it runs |
|---|---|---|
| **SecretBroker Desktop** (`secretbroker/`) | Personal vault + broker that lets AI agents *use* credentials without reading them. Windows today. | The user's PC, as an isolated Windows service + tray app |
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
* **E-mail verification** (`SB_EMAIL_VERIFICATION=required`, the default). `register` answers `{user_id, verified}`
  and `user` objects carry `verified`. An account is verified by the e-mailed code (`SB_SMTP_*`; 8 digits, stored as
  an HMAC with the server secret), by registering with a pending org invite id for that e-mail, or by the admin
  (`secretbroker-server verify-email <e-mail>`; `unverified` lists who is waiting). Until then `GET /invites` is
  empty, `accept` is `403 email_unverified`, invite rows of `GET /orgs/{oid}/members` do not name the account and
  the invite path of `/users/{uid}/keys` does not show its keys. `SB_EMAIL_VERIFICATION=off` (a self-hoster's
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

## 6. Roadmap beyond this release

* Cross-platform desktop (macOS Keychain/Touch ID, Linux Secret Service) — the core is plain Python; `winsec`/`hello`
  are the only Windows-specific modules and should become a platform interface.
* English/Spanish UI (i18n of `web/app.js`).
* SSO (OIDC) and SCIM for the hosted SaaS; Postgres backend; org-wide policies (minimum rotation period, AI levels).
* A CLI-only client for servers/CI that reads a collection with a machine identity (service accounts).
