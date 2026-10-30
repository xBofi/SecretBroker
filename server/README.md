# SecretBroker Server

Zero-knowledge sync and sharing server for SecretBroker teams. The desktop app encrypts everything before it leaves
the PC; this server only stores and routes ciphertext. The same code runs the hosted service and your own instance.
Design and API: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md), sections 2 and 4.

## What it stores

- Accounts: e-mail, display name, public keys (X25519 and Ed25519), the client's KDF parameters, an encrypted blob
  with the private keys, and `scrypt(auth_hash, per-user salt)` (never the `auth_hash` itself, never the password).
- Sessions: SHA-256 of each token, device name, created / last seen.
- Organizations (names in clear), members, roles, pending invites.
- Collections and items: ids, revisions, key versions, ciphertext, who changed what and when.
- Audit events: who did what to which id, never contents.

## What it can never see

Passwords, credentials, credential names, notes, collection names and collection keys. They are encrypted on the
client with keys the server never receives. If the server is fully compromised, the attacker learns e-mails,
organization names, who belongs to what, item counts and timestamps, not secrets. Key grants are signed by the
member who issued them, so a malicious server cannot slip in its own collection key without the clients noticing.

## Run it (Docker Compose, automatic HTTPS)

You need a Linux host with Docker, ports 80 and 443 open, and a DNS name pointing at it.

```sh
cd server
cat > .env <<'ENV'
SB_DOMAIN=secrets.example.com
SB_ADMIN_EMAILS=you@example.com
ENV
docker compose up -d
```

Caddy gets the TLS certificate by itself. Then point the desktop app's team settings at
`https://secrets.example.com`, and create your account with the e-mail you put in `SB_ADMIN_EMAILS`.

With the default `SB_SIGNUPS=invite`, other people join through an organization invite (they register with the
invite id) or with a single-use signup token:

```sh
docker compose exec server secretbroker-server create-invite --days 7
docker compose exec server secretbroker-server stats
```

Without Docker: `pip install ./server`, set the variables below and run `secretbroker-server serve --port 8080`
behind any TLS reverse proxy.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SB_DATA_DIR` | `./data` (`/data` in Docker) | SQLite database and the server secret |
| `SB_PUBLIC_URL` | (required) | Public `https://` URL; plain http is refused |
| `SB_ALLOW_HTTP` | off | Allow an `http://` URL. Only for local tests |
| `SB_SIGNUPS` | `invite` | `open` (anyone), `invite` (org invite or signup token), `closed` (only `SB_ADMIN_EMAILS`) |
| `SB_ADMIN_EMAILS` | empty | Comma-separated e-mails that are server admins and can always register |
| `SB_SESSION_DAYS` | `30` | A device stays signed in this many days after its last use |
| `SB_TRUST_PROXY` | off | Take the client address from `X-Forwarded-For` (set in the Compose file, behind Caddy) |
| `SB_MAX_BODY` | `8388608` | Largest request in bytes |
| `SB_SERVER_NAME` | `SecretBroker` | Name shown by `/api/v1/info` |

The first account created on a server with `SB_SIGNUPS=open` becomes server admin. Server admins can create signup
tokens (`POST /api/v1/admin/invites`). Failed logins are throttled per e-mail and per address with a growing wait.

## Backups

Everything lives in one SQLite file plus `server_secret`. Take a consistent copy while the server runs:

```sh
docker compose exec server python -c "import sqlite3; s=sqlite3.connect('/data/secretbroker.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close()"
docker compose cp server:/data/backup.db ./secretbroker-$(date +%F).db
```

or, with the `sqlite3` tool on the host: `sqlite3 secretbroker.db ".backup backup.db"`. Back up `server_secret` once.
Backups contain only ciphertext, but they still reveal e-mails and membership: store them privately.

## Upgrade

```sh
git pull
docker compose up -d --build
```

The schema is created and kept up to date on start. Take a backup first.

## Tests

```sh
.venv/Scripts/python.exe server/tests/test_server.py    # Windows; python server/tests/test_server.py elsewhere
```
