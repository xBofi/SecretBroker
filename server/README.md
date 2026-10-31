# SecretBroker Server

Zero-knowledge sync and sharing server for SecretBroker teams. The desktop app encrypts everything before it leaves
the PC; this server only stores and routes ciphertext. The same code runs the hosted service and your own instance.
Design and API: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md), sections 2 and 4.

## What it stores

- Accounts: e-mail (and whether it is verified), display name, public keys (X25519 and Ed25519), the client's KDF
  parameters, an encrypted blob with the private keys, an encrypted blob with the people the account verified, and
  `scrypt(auth_hash, per-user salt)` (never the `auth_hash` itself, never the password). Pending verification codes
  are stored as an HMAC.
- Sessions: SHA-256 of each token, device name, created / last seen.
- Organizations (names in clear), members, roles, pending invites.
- Collections and items: ids, revisions, key versions, ciphertext, who changed what and when, the chain of member
  lists signed by each collection's managers, and the deleter's signature on each deletion.
- Audit events: who did what to which id, never contents.

## What it can never see

Passwords, credentials, credential names, notes, collection names and collection keys. They are encrypted on the
client with keys the server never receives. If the server is fully compromised, the attacker learns e-mails,
organization names, who belongs to what, item counts and timestamps, not secrets. Key grants, member lists, item
versions and deletions are signed by the member who made them, so a malicious server cannot slip in its own
collection key, add someone to a collection, change a credential or delete one without the clients noticing.

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

### E-mail verification

Organization invites are addressed to an e-mail, so an account only receives them once it proves it owns that
address; otherwise whoever registered someone's address first would get their invites. There are three ways:

- **A code by e-mail** (recommended): set the `SB_SMTP_*` variables below. New accounts get an 8-digit code, valid
  30 minutes, which they type in SecretBroker › Equipo (at most one new code a minute, 5 tries per code).
- **Registering with an organization invite code**: the link an admin passes on (`secretbroker://join?…&code=…`)
  verifies the address at once, since the admin chose who to give it to.
- **The admin, from the command line**, for servers without e-mail, after checking who the person is:

  ```sh
  docker compose exec server secretbroker-server unverified
  docker compose exec server secretbroker-server verify-email someone@example.com
  ```

A server without any e-mail may turn verification off with `SB_EMAIL_VERIFICATION=off`: then anyone who registers an
address receives its invites. Accounts that existed before 0.16 count as verified.

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
| `SB_EMAIL_VERIFICATION` | `required` | `required` (invites only reach verified e-mails) or `off` |
| `SB_SMTP_HOST` | empty | SMTP server for verification codes. Empty: the admin verifies accounts (`verify-email`) |
| `SB_SMTP_PORT` | `587` | SMTP port |
| `SB_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` (port 465) or `none` (only to a relay on the same host) |
| `SB_SMTP_USER`, `SB_SMTP_PASSWORD` | empty | SMTP login, if the server needs one |
| `SB_SMTP_FROM` | (required with SMTP) | Sender address, e.g. `secrets@example.com` |
| `SB_MAX_DELETES_PER_HOUR` | `100` | Credentials one account may delete in an hour (a stolen session can't wipe a team) |

The first account created on a server with `SB_SIGNUPS=open` becomes server admin. Server admins can create signup
tokens (`POST /api/v1/admin/invites`). Failed logins are throttled per e-mail and per address with a growing wait.
The desktop apps also refuse to apply many deletions at once: they ask the user first.

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

The schema is created and kept up to date on start. Take a backup first. Upgrade the server before (or together
with) the desktop apps: SecretBroker 0.16 sends signed member lists and deletions that older servers refuse.

## Tests

```sh
.venv/Scripts/python.exe server/tests/test_server.py    # Windows; python server/tests/test_server.py elsewhere
```
