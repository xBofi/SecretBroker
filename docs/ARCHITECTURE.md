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

Team data lives **inside the existing encrypted vault payload** (section `team`), so it inherits the same at-rest
protection, backups and lock behaviour. Shared credentials are ordinary vault entries with an extra `shared` block,
so the AI broker, `sb run`, exposure checks and rotation work on them unchanged.

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

`fingerprint(user) = SHA-256(x25519_pub || ed25519_pub)`, shown as 8 groups of 4 hex chars. Clients pin the first
fingerprint they see for each user id (`team.pinned`) and refuse to seal to a changed key without the user confirming
again. Confirming a new member shows their fingerprint so it can be compared over another channel (optional, but the
UI recommends it for admins).

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
  `author` and `updated` so clients can show who changed what.

### 2.4 Membership changes and offboarding

Removing a member (or downgrading them out of a collection) **re-keys** every collection they could read: a member with
`manage` generates a new collection key, re-encrypts all items and seals new grants for the remaining members, in one
atomic `rotate` call (`key_version + 1`). The server marks a collection `needs_rekey` until that happens and refuses
new grants with the old version.

Re-keying protects *future* changes only: the removed person may have seen the secrets. Every credential in those
collections is flagged **"rotate: <person> had access"** and appears in the reminders and in the guided rotation
wizard. This is the main team pain point other managers leave to the admin's memory.

### 2.5 Incoming changes that widen where a key can go

A teammate with `edit` could change a shared credential's `policy` (allowed hosts, commands, env) to send it somewhere
else through *your* AI. So a synced change to anything that decides where a key can go is **quarantined** locally:
the entry keeps its previous policy and shows "change to review" until the user accepts it with one click. Names,
notes, tags and secret values (a teammate rotated the key) apply immediately. The local approval mode
(`policy.approval`) is always the local user's own and is never taken from the server.

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
| `GET /info` (no auth) | → `{name, version, signups}` |
| `POST /accounts/prelogin` (no auth) | `{email}` → `{kdf}` |
| `POST /accounts/register` (no auth) | `{user_id, email, name, kdf, auth_hash, public_key, signing_public_key, private_blob, invite_token?}` → `{user_id}`. The client picks `user_id` (UUIDv4) so it can bind `private_blob` to it; the server only checks it is new. |
| `POST /accounts/login` (no auth) | `{email, auth_hash, device_name}` → `{token, user: {id, email, name}, kdf, private_blob, public_key, signing_public_key}` |
| `POST /accounts/logout` | → `{}` (revokes this token) |
| `GET /me` | → `{user, devices: [{id, name, created, last_seen, current}]}` |
| `DELETE /me/devices/{id}` | → `{}` |
| `POST /accounts/password` | `{kdf, auth_hash, private_blob}` → `{}` (revokes other sessions) |
| `GET /users/{uid}/keys` | → `{id, email, name, public_key, signing_public_key}` (only users sharing an org with you, or invited by your org) |
| `POST /orgs` | `{name}` → `{id}` (caller is owner) |
| `GET /orgs` | → `[{id, name, role}]` |
| `GET /orgs/{oid}/members` | → `[{user_id, email, name, role, status: invited|accepted|confirmed}]` |
| `POST /orgs/{oid}/invites` | `{email, role}` → `{id}` (admin) |
| `GET /invites` | → invites addressed to my e-mail `[{id, org_id, org_name, role, invited_by}]` |
| `POST /invites/{id}/accept` | → `{}` (status accepted; an admin must confirm, see fingerprints) |
| `POST /orgs/{oid}/members/{uid}/confirm` | → `{}` (admin) |
| `PATCH /orgs/{oid}/members/{uid}` | `{role}` → `{}` (owner/admin rules) |
| `DELETE /orgs/{oid}/members/{uid}` | → `{needs_rekey: [cid…]}` (admin, or self to leave) |
| `POST /orgs/{oid}/collections` | `{id, encrypted_name, grant}` → `{}` (admin; creator gets `manage`) |
| `GET /collections` | → my collections `[{id, org_id, encrypted_name, key_version, permission, grant, needs_rekey, revision}]` |
| `DELETE /collections/{cid}` | → `{}` (manage) |
| `GET /collections/{cid}/members` | → `[{user_id, email, name, permission}]` |
| `PUT /collections/{cid}/members/{uid}` | `{permission, grant?}` → `{}` (manage; `grant` required when adding; member must be confirmed in the org) |
| `DELETE /collections/{cid}/members/{uid}` | → `{}` (manage; sets `needs_rekey`) |
| `POST /collections/{cid}/rotate` | `{key_version, encrypted_name, grants: {uid: grant}, items: {iid: ciphertext}}` → `{revision}` (manage; atomic; must cover every member and every live item) |
| `GET /collections/{cid}/items?since=N` | → `{revision, items: [{id, revision, key_version, ciphertext, deleted, updated_by, updated}]}` |
| `PUT /collections/{cid}/items/{iid}` | `{ciphertext, key_version, base_revision}` → `{revision}` / `409 {revision}` (edit) |
| `DELETE /collections/{cid}/items/{iid}` | `{base_revision}` → `{revision}` (edit) |
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
  carry `invite_id` (and `user_id` null if not registered yet); `GET /invites` adds `invited_by_email`,
  `invited_by_name`; `user` objects add `admin` (server admin); events add `id` (newest first, 100 per page,
  `before=<id>`); the 429 answer has `retry_after` and a `Retry-After` header.
* **Extra endpoints.** `DELETE /invites/{id}` → `{}` (the invitee declines, or an org admin withdraws it).
  `POST /admin/invites` `{days?}` → `{token, expires}` (server admin: a single-use signup token).
* **Signups.** `open`: anyone; the first account becomes server admin. `invite`: `invite_token` must be a signup
  token (`POST /admin/invites` or `secretbroker-server create-invite`) or the id of a pending org invite for that
  same e-mail. `closed`: nobody. E-mails in `SB_ADMIN_EMAILS` can always register and are server admins.
* **Limits.** Login failures are throttled per e-mail (5 free) and per client address (20 free), then each failure
  doubles the wait (max 15 min) and attempts during the wait get `429`, even with the right password. Registrations
  are throttled per address. More settings: `SB_ALLOW_HTTP`, `SB_TRUST_PROXY` (use `X-Forwarded-For`, only behind the
  bundled Caddy), `SB_MAX_BODY`, `SB_SERVER_NAME`.

## 5. Desktop service operations for teams

Added to `secretbroker/service.py` (GUI only, never reachable from the AI unless listed in `AI_OPS`):
`team_status`, `team_connect` (server url + email + password + register|login), `team_disconnect`, `team_sync`,
`team_orgs`, `team_create_org`, `team_invite`, `team_invites`, `team_accept_invite`, `team_members`,
`team_confirm_member`, `team_set_role`, `team_remove_member`, `team_collections`, `team_create_collection`,
`team_collection_members`, `team_grant`, `team_revoke`, `team_share_entry`, `team_unshare_entry`,
`team_accept_change`, `team_events`. Client logic and crypto live in `secretbroker/teams.py`.

The AI sees shared credentials like any other (with `shared: {org, collection, permission}` in `list_secrets`), and
`reveal`/copy is refused for `use` permission.

Implementation notes (`secretbroker/teams.py`, `service.py`, binding for the GUI):

* **Plaintext formats.** Item plaintext is `{"entry": <entry without shared/updated/secret_since and without
  policy.approval>, "author": {id, name}, "updated"}`; the author shown is the server's `updated_by` (the plaintext
  one is informative). The collection name plaintext is JSON `{"name"}`, plus `{"removed": [names], "version": n}`
  after a re-key, which is how members who did not re-key learn who to "rotate because" of.
* **Local state.** Vault section `team`: `server_url, token, user, device, keys {x25519, ed25519},
  public_key, signing_public_key, pinned {uid: {fp, public_key, signing_public_key, email, name}}, orgs,
  collections {cid: {org, name, keys {version: b64}, key_version, permission, revision, needs_rekey, members,
  items {iid: {revision, hash, content}}}}, last_sync`. `items[*].content` is the last synced content ("base"):
  a local entry whose content differs from it has an unpushed edit.
* **Entry block.** `entry.shared = {org, org_name, collection, collection_name, item, revision, permission, author,
  changed, pending_policy?, rotate?}`. `pending_policy = {by, at, changes: [lines], policy, fields}` (or `entry` when
  the template changed). Quarantined: new hosts, new programs, new or changed env vars, a different HTTP auth, and the
  `host`/`port`/`engine` fields. `rotate = {people, since, fp}`; the reminder (`kind: "team_access"`, `people`,
  `can_rotate`) lasts while the secret's fingerprint is `fp`, so any rotation (wizard, API, a teammate's) clears it.
* **Permissions on this PC.** Without `edit`/`manage`, the service refuses edits, deletes and rotations of a shared
  credential; only its local approval mode may change. `delete_entry` with write permission deletes it for the team
  (tombstone); `team_unshare_entry` removes it from the collection but keeps it here as a personal credential.
  Losing access to a collection (removed, left, deleted, `team_disconnect`) removes its credentials from this PC.
* **Proofs.** `team_status, team_sync, team_orgs, team_invites, team_members, team_collections,
  team_collection_members, team_events` only need an unlocked vault; every other team op needs a proof and accepts
  the presence token (one click). `team_sync` and the background sync never raise: `team_status.state` is
  `off | idle | syncing | ok | error | offline | reconnect`, with `error` and counts of the `last` round.
  The general `status` op also carries `team` (that state) and `team_sync` (time of the last finished round), so
  the GUI's 1.5 s poll notices a finished round and reloads only when `team_status.last` says something arrived.
* **Op parameters.** `team_connect {server_url, email, password, mode: register|login, name?, device_name?,
  invite_token?}`, `team_invite {org, email, role}`, `team_accept_invite {id}`, `team_members {org}` (rows add
  `fingerprint`, `key_changed`, `me`), `team_confirm_member {org, user_id, fingerprint?}`, `team_set_role {org,
  user_id, role}`, `team_remove_member {org, user_id}` → `{rekeyed, pending}`, `team_create_collection {org, name}`,
  `team_collection_members {collection}`, `team_grant {collection, user_id, permission}`, `team_revoke {collection,
  user_id}` (own id: leave), `team_share_entry {id, collection}`, `team_unshare_entry {id}`,
  `team_accept_change {id, accept?}`, `team_events {org, before?}`.

### 5.1 GUI (`secretbroker/web/app.js`)

* Sidebar view **Equipo**: not connected, an explainer and the link form (server, e-mail, account password; create
  account or log in; nothing prefilled). Connected: sync state and «Sincronizar ahora» in the header; items to review
  (quarantined changes, "rotate because <person> had access" with a link to the guided rotation); invitations to
  accept; per organization its collections (members and permission, add / change / remove, create) and people
  (invite with role, pending confirmations with the fingerprint to compare and one-click «Confirmar», role, remove
  with the re-key / rotate warning), and the org events for admins; the account, its fingerprint and «Desconectar».
* Credential detail: «Compartir» (choose a writable collection), a collection · permission badge, «Dejar de
  compartir», the quarantined change box («Aceptar» / «Mantener la actual», the latter only with edit permission),
  reveal and copy hidden for `use`, and edit / delete / rotate limited to what the permission allows. Deleting a
  shared credential warns that it is deleted for the whole collection.
* Credential list: a team mark on shared rows and collection chips next to the tag filter.

## 6. Roadmap beyond this release

* Cross-platform desktop (macOS Keychain/Touch ID, Linux Secret Service) — the core is plain Python; `winsec`/`hello`
  are the only Windows-specific modules and should become a platform interface.
* English/Spanish UI (i18n of `web/app.js`).
* SSO (OIDC) and SCIM for the hosted SaaS; Postgres backend; org-wide policies (minimum rotation period, AI levels).
* A CLI-only client for servers/CI that reads a collection with a machine identity (service accounts).
