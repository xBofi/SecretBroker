# SecretBroker Server

Zero-knowledge sync and sharing server for SecretBroker teams. The desktop app encrypts everything before it leaves
the PC; this server only stores and routes ciphertext. The same code runs the hosted service and your own instance.
Design and API: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md), sections 2 and 4.

## What it stores

- Accounts: e-mail (and whether it is verified or disabled), display name, public keys (X25519 and Ed25519), the
  client's KDF parameters, an encrypted blob with the private keys, an encrypted blob with the people the account
  verified, and `scrypt(auth_hash, per-user salt)` (never the `auth_hash` itself, never the password). Pending
  verification codes are stored as an HMAC.
- Sessions: SHA-256 of each token, device name, created / last seen.
- Organizations (names in clear), members, roles, pending invites (e-mail, role, when they expire, when they were
  e-mailed).
- Collections and items: ids, revisions, key versions, ciphertext, who changed what and when, the chain of member
  lists signed by each collection's managers, and the deleter's signature on each deletion.
- Audit events: who did what to which id, never contents.

## What it can never see

Passwords, credentials, credential names, notes, collection names and collection keys. They are encrypted on the
client with keys the server never receives. If the server is fully compromised, the attacker learns e-mails,
organization names, who belongs to what, item counts and timestamps, not secrets. Key grants, member lists, item
versions and deletions are signed by the member who made them, so a malicious server cannot slip in its own
collection key, add someone to a collection, change a credential or delete one without the clients noticing.

## Where to run it

| | Good for | You need |
|---|---|---|
| **A small VPS** (recommended) | Any team; always on | A Linux server with Docker (1 vCPU, 1 GB RAM is plenty), a domain name, ports 80 and 443 |
| **Your own PC or a home server, through a tunnel** | Trying it out, small teams | Docker (Docker Desktop on Windows or macOS) and a Cloudflare or Tailscale account; no open ports |
| **Your own PC or a home server, ports open** | If you already run services at home | A domain or dynamic DNS name pointing at your home address, ports 80 and 443 forwarded on the router |

Whatever you pick, two things hold: the desktop apps only talk to the server over **HTTPS** (TLS must end on a
machine you trust, see the tunnel trade-offs below), and the **payloads are end-to-end encrypted** regardless: neither
the server, nor the VPS provider, nor a tunnel provider can read credentials or collection names. What they can see
is the metadata above.

A team server on a PC that sleeps or is switched off is fine for SecretBroker (each app keeps working with what it
has and syncs when the server is back), but nobody receives changes in the meantime.

### Quick start: an Ubuntu VPS

1. Create the server (Ubuntu 24.04 LTS) and point a DNS name at it, for example `secrets.example.com` → its IP.
2. Install Docker and get the code:

   ```sh
   sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
   sudo systemctl enable --now docker
   git clone https://github.com/xBofi/SecretBroker.git
   cd SecretBroker/server
   ```

3. Configure it (the SMTP lines are optional but recommended: verification codes and invites by e-mail):

   ```sh
   cat > .env <<'ENV'
   SB_DOMAIN=secrets.example.com
   SB_ADMIN_EMAILS=you@example.com
   SB_SMTP_HOST=smtp.example.com
   SB_SMTP_USER=secrets@example.com
   SB_SMTP_PASSWORD=the-smtp-password
   SB_SMTP_FROM=secrets@example.com
   ENV
   chmod 600 .env
   ```

4. Start it, with a firewall that only lets in SSH and the web:

   ```sh
   sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443 && sudo ufw --force enable
   sudo docker compose up -d
   sudo docker compose ps        # server "healthy", caddy and backup "running"
   ```

   Caddy gets and renews the TLS certificate by itself (Let's Encrypt). Docker publishes ports past `ufw`, which is
   fine here: only Caddy publishes any.

5. Create your admin account: on the server run `sudo docker compose exec server secretbroker-server create-invite`,
   then in SecretBroker › Equipo create an account on `https://secrets.example.com` with the e-mail you put in
   `SB_ADMIN_EMAILS` and that code. Then create your organization and invite your team from the app.

### Your own PC or a home server (Docker Desktop, tunnels)

On **Windows or macOS**, install [Docker Desktop](https://www.docker.com/products/docker-desktop/), clone this
repository and run the same commands from the `server` folder in a terminal (PowerShell or Terminal), without
`sudo`. On Windows, enable "Start Docker Desktop when you sign in" so the server comes back after a restart.

The apps need a public **HTTPS** address. The simplest at home is a tunnel, which needs no open ports and hides your
home IP. Run only the server and its backups, reachable from this machine alone, and point the tunnel at it:

```sh
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d server backup
# the server now answers on http://127.0.0.1:8080, only on this machine
```

`SB_DOMAIN` in `.env` must be the public name the tunnel gives you (it becomes `SB_PUBLIC_URL`).

- **Cloudflare Tunnel** (`cloudflared`, free with a domain on Cloudflare): create a tunnel for
  `secrets.example.com` with the service `http://127.0.0.1:8080`. Trade-off: **TLS ends at Cloudflare**, so
  Cloudflare sees each request in clear, metadata and session tokens included (never credentials or collection
  names: those are encrypted by the apps). For SecretBroker that makes Cloudflare as trusted as the server itself
  (docs/THREAT_MODEL.md 3.5): it could act as a signed-in user towards the server, though not read or forge
  anything the apps encrypt and sign.
- **Tailscale**: `tailscale serve --bg 8080` gives the server an address like `https://pc.tail1234.ts.net` with a
  certificate **on your machine** (TLS ends there; Tailscale's relays only see encrypted traffic). With `serve`, only
  devices in your tailnet reach it, so every teammate installs Tailscale and joins (or you share the machine with
  them). `tailscale funnel --bg 8080` publishes the same address on the internet instead, still with TLS on your
  machine. Trade-off: everyone depends on Tailscale being up, and with `serve` on being in your tailnet.

Behind a tunnel every request seems to come from 127.0.0.1 unless the tunnel sets `X-Forwarded-For` (both do). The
login throttling uses it because `SB_TRUST_PROXY=1` in the Compose file; keep port 8080 bound to 127.0.0.1 (as
`docker-compose.local.yml` does), or anyone reaching it could forge that header.

**Ports open instead of a tunnel**: use the plain `docker compose up -d` (with Caddy) and forward ports 80 and 443 of
your router to this machine; `SB_DOMAIN` must point at your home address (a dynamic DNS name if it changes). TLS ends
on your machine, but your home IP is public and the machine is reachable from the internet: keep it updated.

## E-mail

With the `SB_SMTP_*` variables set, the server e-mails two things, and nothing else:

- **Verification codes.** Organization invites are addressed to an e-mail, so an account only receives them once it
  proves it owns that address; otherwise whoever registered someone's address first would get their invites. New
  accounts get an 8-digit code, valid 30 minutes, which they type in SecretBroker › Equipo (at most one new code a
  minute, 5 tries per code).
- **Invites.** Inviting someone in the app e-mails them the join link (`secretbroker://join?server=…&email=…&code=…`),
  where to download SecretBroker, and the same steps in plain words. The code is the invite id: a sign-up code for
  that e-mail and that organization only, never a password or a key. The admin can still copy the instructions in
  the app. An invite lasts `SB_INVITE_DAYS` (14); expired ones show in Equipo › Personas as «Invitación caducada»
  with «Renovar» (a new code, e-mailed again) and «Retirar»; pending ones can be re-sent (once every 10 minutes).
  An organization, and an account, may create, renew or re-send `SB_MAX_INVITES_PER_HOUR` (30) invites an hour.
  Only accounts that verified their own e-mail make the server send invites: an unverified one can still invite,
  and the app gives it the instructions to pass on.

Without SMTP nothing is e-mailed: the app gives the admin the instructions to pass on, and accounts are verified
either by registering with the organization's invite code (it proves the address to that organization only) or by
the server admin, after checking who the person is:

```sh
docker compose exec server secretbroker-server unverified
docker compose exec server secretbroker-server verify-email someone@example.com
```

A server without any e-mail may turn verification off with `SB_EMAIL_VERIFICATION=off`: then anyone who registers an
address receives its invites. Accounts that existed before 0.16 count as verified.

## Accounts

With the default `SB_SIGNUPS=invite`, people join through an organization invite or with a single-use signup token
(`create-invite`). The server admin manages accounts from the command line (prefix each with
`docker compose exec server`):

| Command | What it does |
|---|---|
| `secretbroker-server users` | Every account: e-mail, name, verified, admin, disabled, organizations with role, last seen. Never keys or secrets. |
| `secretbroker-server disable-user <e-mail>` | Revokes all its sessions and blocks its sign-in; its data stays. It leaves every organization, as if an org admin removed it: each collection it could read waits for a re-key, which the managers' apps do on their next sync, flagging its credentials «rotate: <person> had access». Where it is an organization's last owner or a collection's only manager it stays a member (unable to sign in) and the command says what to hand over first. |
| `secretbroker-server enable-user <e-mail>` | Lets it sign in again. It is not back in the organizations it left: invite it. |
| `secretbroker-server delete-user <e-mail> --yes` | Takes it out of its organizations (same re-keying) and deletes the account. Refused, changing nothing, while it is an organization's last owner or a collection's only manager: the command says what to do. |
| `secretbroker-server transfer-owner <org> <e-mail>` | Makes a confirmed member of an organization (its id, or its exact name) an owner, for an organization whose only owner can't sign in any more. The other owners stay owners. |
| `secretbroker-server create-invite [--days N]` | A single-use signup token (needed with `SB_SIGNUPS=invite` for someone without an org invite, and always for `SB_ADMIN_EMAILS`). |
| `secretbroker-server stats` | Counts, never contents. |

Each removal is recorded in the organization's Actividad («El administrador del servidor…»). Disabling is the
emergency brake for a lost laptop or someone who left on bad terms: it cuts access to the server at once, and the
re-keying protects every future change. What that person already saw is theirs: rotate it (the apps remind you).

## Backups and restore

Everything lives in `secretbroker.db` plus `server_secret` in the data volume. The Compose file runs a `backup`
service that writes a consistent copy of both (SQLite's online backup, safe while the server runs) once a day to the
`sb-backups` volume and keeps the last `SB_BACKUP_KEEP` (14); a backup that fails (on a brand-new server the
database may not exist yet) is retried in 10 minutes. By hand, at any time:

```sh
docker compose exec backup secretbroker-server backup --dir /backups --keep 14
docker compose exec backup ls -l /backups
docker compose cp backup:/backups ./secretbroker-backups      # copy them off the server
```

**Copy backups off the machine** (another server, a NAS, a storage bucket): a backup on the same disk does not
survive losing that disk. Backups hold only ciphertext and public keys, but they still reveal e-mails, organization
names and who belongs to what: keep them as private as the server. The files are readable only by the server's
account; `server_secret` only changes the fake answers for unknown e-mails, so an old one is harmless.

To restore, stop the server (the restore refuses while it runs), restore, start it again. The current files are kept
in `before-restore-<time>/` inside the data volume:

```sh
docker compose stop server backup
docker compose run --rm backup secretbroker-server restore /backups/secretbroker-backup-20261112-031500.zip
# or a file from this machine:
docker compose run --rm -v "$PWD/my-backup.zip:/restore.zip:ro" backup secretbroker-server restore /restore.zip
docker compose up -d
```

After a restore the server is back in time: the apps keep what they have, push their newer edits again, and refuse
anything older than what they already saw (rollbacks are detected). A member removed after that backup is back in
the server's lists until removed again: do it, and rotate what they could see.

## Upgrades and versions

```sh
docker compose exec backup secretbroker-server backup --dir /backups   # first, a backup
git pull
docker compose up -d --build
```

The database is upgraded on start (from any earlier version). Apps and server tell each other their versions:
`GET /api/v1/info` has `api` (the protocol: 1 = 0.16, 2 = this version) and `min_client` (the oldest app it serves),
and the apps send `X-SecretBroker-Version` on every request. An app older than `min_client` gets `426
client_too_old` and asks its user to update; an app newer than the server tells its user «El servidor del equipo es
una versión antigua: pide a quien lo administra que lo actualice» when the server is too old for it. Apps that don't
send their version (0.16) keep working. `SB_MIN_CLIENT` raises the minimum, for example after a security fix in the
app. Upgrading the server first is always safe.

## Health

`GET /api/v1/health` answers `200 {"status": "ok"}` while the database answers and `503` otherwise, without
authentication and without saying anything else. The Docker image uses it as its `HEALTHCHECK`; point an uptime
monitor at `https://secrets.example.com/api/v1/health`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SB_DATA_DIR` | `./data` (`/data` in Docker) | SQLite database and the server secret |
| `SB_PUBLIC_URL` | (required) | Public `https://` URL; plain http is refused. Also the server address in invite e-mails |
| `SB_ALLOW_HTTP` | off | Allow an `http://` URL. Only for local tests |
| `SB_SIGNUPS` | `invite` | `open` (anyone), `invite` (org invite or signup token), `closed` (only `SB_ADMIN_EMAILS`) |
| `SB_ADMIN_EMAILS` | empty | Comma-separated e-mails that are server admins and can always register |
| `SB_SESSION_DAYS` | `30` | A device stays signed in this many days after its last use |
| `SB_TRUST_PROXY` | off | Take the client address from `X-Forwarded-For` (set in the Compose file, behind Caddy or a local tunnel) |
| `SB_MAX_BODY` | `8388608` | Largest request in bytes |
| `SB_SERVER_NAME` | `SecretBroker` | Name shown by `/api/v1/info` |
| `SB_EMAIL_VERIFICATION` | `required` | `required` (invites only reach verified e-mails) or `off` |
| `SB_SMTP_HOST` | empty | SMTP server for verification codes and invites. Empty: nothing is e-mailed |
| `SB_SMTP_PORT` | `587` | SMTP port |
| `SB_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` (port 465) or `none` (only to a relay on the same host) |
| `SB_SMTP_USER`, `SB_SMTP_PASSWORD` | empty | SMTP login, if the server needs one |
| `SB_SMTP_FROM` | (required with SMTP) | Sender address, e.g. `secrets@example.com` |
| `SB_MAX_DELETES_PER_HOUR` | `100` | Credentials one account may delete in an hour (a stolen session can't wipe a team) |
| `SB_INVITE_DAYS` | `14` | How long an organization invite lasts (1–365) |
| `SB_MAX_INVITES_PER_HOUR` | `30` | Invites an organization, and an account, may create, renew or re-send in an hour |
| `SB_MIN_CLIENT` | empty | Oldest app version served (never below 0.16.0); older apps are asked to update |
| `SB_BACKUP_KEEP` | `14` | (Compose) Daily backups kept |

The first account created on a server with `SB_SIGNUPS=open` becomes server admin. Server admins can create signup
tokens (`POST /api/v1/admin/invites`). Failed logins are throttled per e-mail and per address with a growing wait.
The desktop apps also refuse to apply many deletions at once: they ask the user first.

The container runs as an unprivileged user (uid 10001) with a read-only filesystem except its volumes, no Linux
capabilities and `no-new-privileges`; the data and backup folders are `700` and every file the server writes is
`600`.

Without Docker: `pip install ./server`, set the variables above and run `secretbroker-server serve --port 8080`
behind any TLS reverse proxy, as its own unprivileged user, with `secretbroker-server backup --dir <folder>` daily
from cron.

## Tests

```sh
.venv/Scripts/python.exe server/tests/test_server.py    # Windows; python server/tests/test_server.py elsewhere
```
