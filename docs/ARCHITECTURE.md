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

### 1.1 Personal vault features

Logic in their own modules, wired into `service.py` as GUI-only operations (none is in `AI_OPS`):

| Module | Service op | Notes |
|---|---|---|
| `generator.py` | — (the app calls it directly) | Random passwords and Spanish/English passphrases from `secrets`; `strength()` estimate. |
| `health.py` | `health` | Weak (`generator.strength`), reused (compared by `vault.mac`, never a hash leaves the service), old, expired, exposed; a 0-100 score. Names and reasons only. |
| `importers.py` | `import_file` | The service account cannot read the user's files, so the app reads the file and sends `{content, source, format, password?, selected?}`; without `selected` it returns a preview (names, users, sites, status), with it it imports. Presence proof. |
| `exports.py` | `export_vault` | `{format: encrypted \| json \| csv, password?}` → `{content}`; the app writes it. Presence proof. Format in `docs/EXPORT_FORMAT.md`. |

`import_file` and `export_vault` are in `PRESENCE_OPS` (one click from the app that unlocked). `replace_key` also
accepts web logins and SSH passwords (the password-change helper behind "Rotar con ayuda" in *Salud*).

Every template has an optional **private notes** field (`fields.notes`, `secret` + `note`): hidden and revealed like
a secret, never given to the AI, programs, the scanner or the redactor, and not part of `secret_fields()` (editing it
does not reset a key's age). Imported notes, TOTP seeds and custom fields go there. It travels with shared items like
any other field.

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
404 not found, 409 conflict, 429 rate limited).

## 5. Desktop service operations for teams

Added to `secretbroker/service.py` (GUI only, never reachable from the AI unless listed in `AI_OPS`):
`team_status`, `team_connect` (server url + email + password + register|login), `team_disconnect`, `team_sync`,
`team_orgs`, `team_create_org`, `team_invite`, `team_invites`, `team_accept_invite`, `team_members`,
`team_confirm_member`, `team_set_role`, `team_remove_member`, `team_collections`, `team_create_collection`,
`team_collection_members`, `team_grant`, `team_revoke`, `team_share_entry`, `team_unshare_entry`,
`team_accept_change`, `team_events`. Client logic and crypto live in `secretbroker/teams.py`.

The AI sees shared credentials like any other (with `shared: {org, collection, permission}` in `list_secrets`), and
`reveal`/copy is refused for `use` permission.

## 6. Roadmap beyond this release

* Cross-platform desktop (macOS Keychain/Touch ID, Linux Secret Service) — the core is plain Python; `winsec`/`hello`
  are the only Windows-specific modules and should become a platform interface.
* English/Spanish UI (i18n of `web/app.js`).
* SSO (OIDC) and SCIM for the hosted SaaS; Postgres backend; org-wide policies (minimum rotation period, AI levels).
* A CLI-only client for servers/CI that reads a collection with a machine identity (service accounts).
