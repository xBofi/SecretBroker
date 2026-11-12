# SecretBroker Server

Zero-knowledge sync and sharing server for SecretBroker teams. The desktop app encrypts everything before it leaves
the PC; this server only stores and routes ciphertext. The same code runs the hosted service and your own instance.
Design and API: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md), sections 2 and 4.

## Install it on a server: one command

For a small Linux server you rent (a VPS) or own, reached by SSH, without a desktop and without Docker. After this
one command there is nothing else to do on the server: you administer it from the SecretBroker desktop app, it backs
itself up every day, and signed updates install themselves.

**You need:** an x86-64 server with **Ubuntu 22.04, 24.04 or 26.04** (1 vCPU and 1 GB of RAM are plenty), a domain name
you can add a DNS record to, and the server's **ports 80 and 443** open.

1. **Point a name at the server.** In your DNS provider, add an `A` record such as `secrets.example.com` → the
   server's public IP address (your provider's panel shows it).
2. **Open ports 80 and 443** in the provider's firewall (often called "security group" or "firewall" in its panel).
   If the server itself runs `ufw`, the installer opens them there.
3. **Run this on the server** (connect with SSH; it asks the domain name and your e-mail):

   ```sh
   curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh | sudo bash
   ```

4. **Open SecretBroker on your PC**, go to **Equipo › Crear cuenta** and use the server address, your e-mail and the
   one-time code the installer printed (or paste the `secretbroker://join?…` link it printed into «Servidor»: it
   fills in the rest). That code works only for your e-mail and makes you the server's administrator, so nobody can
   take the admin account before you. Then create your organization and invite your team from the app.

The installer checks every step and says what to fix in plain words; if the domain does not answer yet (DNS takes a
while, or the ports are closed), it says so, and HTTPS starts working by itself once they are right. Running the
same command again repairs and upgrades the installation; your data and settings stay.

**Without questions** (for scripts), give the answers as variables; the e-mail settings are optional:

```sh
curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh \
  | sudo SB_DOMAIN=secrets.example.com SB_ADMIN_EMAIL=you@example.com \
         SB_SMTP_HOST=smtp.example.com SB_SMTP_USER=secrets@example.com SB_SMTP_PASSWORD='…' \
         SB_SMTP_FROM=secrets@example.com bash
```

Any variable from [Configuration](#configuration) can be given this way, plus `SB_PORT` (the local port, 8080).

### What it installs

| What | Where |
|---|---|
| The server: one signed, self-contained archive (its own Python and the hash-pinned packages of `requirements/server.txt`; nothing is fetched from PyPI on the server) | `/opt/secretbroker-server/versions/<version>`, `current` links to the one in use |
| Its account, `secretbroker-server`, and its data (database, server secret, backups), `700` | `/var/lib/secretbroker-server` |
| Settings (`SB_*`, readable only by root) | `/etc/secretbroker-server/server.env` |
| `secretbroker-server.service`: the server on `127.0.0.1:8080` only, sandboxed by systemd (read-only system, no privileges, private /tmp, its own folder only) | `/etc/systemd/system` |
| `secretbroker-server-backup.timer`: a backup every night, the last 14 kept | `/var/lib/secretbroker-server/backups` |
| `secretbroker-server-update.timer`: signed automatic updates every night (below) | |
| Caddy, from [its official repository](https://caddyserver.com/docs/install#debian-ubuntu-raspbian): HTTPS for your domain with a free Let's Encrypt certificate it renews by itself | `/etc/caddy/secretbroker.caddy` |

The installer only downloads from GitHub (the server) and Caddy's repository, and installs the server only if its
Ed25519 signature verifies with the SecretBroker release key built into the installer (the same key the desktop app's
updates use). Python 3.11+ is needed and Ubuntu 22.04 has 3.10, so the archive brings its own (the same
python-build-standalone build as the desktop app's Ubuntu package): nothing on the system changes when the server
updates.

### Administering it

From the desktop app's server panel (the account the installer's code created is the server admin; others can be
made admin with `SB_ADMIN_EMAILS`): accounts (disable, enable, verify an e-mail, delete), organizations (hand over
ownership), backups (see them, make one now), signups (open, by invite, closed), automatic updates (on or off) and the
log of everything server admins did. The app uses the admin API (`/api/v1/admin/…`, docs/ARCHITECTURE.md 4.1),
which only server admins can use.

On the server, the same is available from the command line, as the server's own account and with its settings:
`sudo secretbroker-server users`, `sudo secretbroker-server disable-user someone@example.com`, and so on (see
[Accounts](#accounts)). The only thing that needs it is restoring a backup, because the server has to be stopped:

```sh
sudo ls /var/lib/secretbroker-server/backups
sudo secretbroker-server restore /var/lib/secretbroker-server/backups/secretbroker-backup-20261112-031500.zip
```

(it stops the server, restores, and starts it again; the replaced files are kept in
`/var/lib/secretbroker-server/before-restore-<time>/`).

### Automatic updates

Every night `secretbroker-server-update.timer` checks the latest SecretBroker release. When there is a newer server,
it downloads it, **checks its signature with the release key before using it** (an unsigned or wrongly signed file
is never installed, and never an older version), makes a backup, installs it, restarts the server and checks that
it answers (`/api/v1/health`) with the new version. If it does not within a minute, it goes back to the previous
version and the database as it was just before, and waits for the next release. The app's server panel shows the
version, whether a newer one exists and what the last check did.

To turn them off: the switch in the app, or `SB_AUTO_UPDATE=0` in `/etc/secretbroker-server/server.env` (once the
app's switch has been used, the app's choice wins). To update by hand at any time: `sudo secretbroker-server update`,
or run the install command again.

### Behind a tunnel instead (no open ports)

At home, or where ports 80/443 can't be opened, a tunnel gives the server its public HTTPS address. Install without
Caddy, with the tunnel's public name as the domain:

```sh
curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh \
  | sudo SB_DOMAIN=secrets.example.com SB_ADMIN_EMAIL=you@example.com bash -s -- --local
```

The server then answers only on `http://127.0.0.1:8080`; point the tunnel at that address (Cloudflare Tunnel:
service `http://127.0.0.1:8080`; Tailscale: `tailscale serve --bg 8080`). Be honest with yourself about the
trade-off: with **Cloudflare Tunnel, TLS ends at Cloudflare**, which therefore sees the requests in clear (metadata
and session tokens, never credentials or collection names, which the apps encrypt) and is as trusted as the server
itself (docs/THREAT_MODEL.md 3.5); with **Tailscale** TLS ends on your machine, but every teammate needs Tailscale
(with `serve`) or the address is public (with `funnel`). The details are in [Tunnels](#your-own-pc-or-a-home-server-docker-desktop-tunnels)
below. `--local` without `SB_DOMAIN` is a server for this machine only, over plain HTTP: for tests.

### Removing it

```sh
curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh | sudo bash -s -- --uninstall
```

removes the programs and services and keeps the data, backups and settings (`--uninstall --purge` deletes those too).
Caddy stays installed, without the SecretBroker site.

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

## Other ways to run it: Docker

| | Good for | You need |
|---|---|---|
| **A small VPS** with the command above (recommended) | Any team; always on | Ubuntu 22.04/24.04, a domain name, ports 80 and 443 |
| **A server with Docker** | If you already run things in Docker, or another Linux | Docker with Compose, a domain name, ports 80 and 443 |
| **Your own PC or a home server, through a tunnel** | Trying it out, small teams | Docker (Docker Desktop on Windows or macOS) and a Cloudflare or Tailscale account; no open ports |
| **Your own PC or a home server, ports open** | If you already run services at home | A domain or dynamic DNS name pointing at your home address, ports 80 and 443 forwarded on the router |

Whatever you pick, two things hold: the desktop apps only talk to the server over **HTTPS** (TLS must end on a
machine you trust, see the tunnel trade-offs below), and the **payloads are end-to-end encrypted** regardless: neither
the server, nor the VPS provider, nor a tunnel provider can read credentials or collection names. What they can see
is the metadata above.

A team server on a PC that sleeps or is switched off is fine for SecretBroker (each app keeps working with what it
has and syncs when the server is back), but nobody receives changes in the meantime.

With Docker, updates are yours to run (see [Upgrades](#upgrades-and-versions)): the automatic updater is part of the
command-line install only. The app's server panel works the same, except that it shows no update status.

### Docker on a VPS

1. Create the server and point a DNS name at it, for example `secrets.example.com` → its IP.
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

5. Create your admin account: on the server run
   `sudo docker compose exec server secretbroker-server create-invite --email you@example.com`, then in SecretBroker ›
   Equipo › Crear cuenta use `https://secrets.example.com`, the e-mail you put in `SB_ADMIN_EMAILS` and that code.
   Then create your organization and invite your team from the app.

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
(`create-invite`). The server admin manages accounts from the desktop app's server panel, or from the command line:
`sudo secretbroker-server <command>` on a server installed with `install-server.sh`, `docker compose exec server
secretbroker-server <command>` with Docker. Both do exactly the same (the same code), and both are recorded in the
server admin log the app shows:

| Command | What it does |
|---|---|
| `secretbroker-server users` | Every account: e-mail, name, verified, admin, disabled, organizations with role, last seen. Never keys or secrets. |
| `secretbroker-server disable-user <e-mail>` | Revokes all its sessions and blocks its sign-in; its data stays. It leaves every organization, as if an org admin removed it: each collection it could read waits for a re-key, which the managers' apps do on their next sync, flagging its credentials «rotate: <person> had access». Where it is an organization's last owner or a collection's only manager it stays a member (unable to sign in) and the command says what to hand over first. |
| `secretbroker-server enable-user <e-mail>` | Lets it sign in again. It is not back in the organizations it left: invite it. |
| `secretbroker-server delete-user <e-mail> --yes` | Takes it out of its organizations (same re-keying) and deletes the account. Refused, changing nothing, while it is an organization's last owner or a collection's only manager: the command says what to do. |
| `secretbroker-server transfer-owner <org> <e-mail>` | Makes a confirmed member of an organization (its id, or its exact name) an owner, for an organization whose only owner can't sign in any more. The other owners stay owners. |
| `secretbroker-server create-invite [--days N] [--email E]` | A single-use signup token (needed with `SB_SIGNUPS=invite` for someone without an org invite, and always for `SB_ADMIN_EMAILS`). With `--email`, only that address can use it. |
| `secretbroker-server verify-email <e-mail>` | Marks an account's e-mail as verified (servers without SMTP, after checking who it is). |
| `secretbroker-server stats` | Counts, never contents. |

Each removal is recorded in the organization's Actividad («El administrador del servidor…»). Disabling is the
emergency brake for a lost laptop or someone who left on bad terms: it cuts access to the server at once, and the
re-keying protects every future change. What that person already saw is theirs: rotate it (the apps remind you).

## Backups and restore

Everything lives in `secretbroker.db` plus `server_secret` in the data folder. With `install-server.sh`, a timer backs
up every night into `/var/lib/secretbroker-server/backups` (the last `SB_BACKUP_KEEP`, 14), the app's server panel
lists them and makes one on demand, and `sudo secretbroker-server restore <file>` restores one ([above](#administering-it)).
With Docker, the Compose file runs a `backup` service that writes a consistent copy of both (SQLite's online backup, safe while the server runs) once a day to the
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
# --no-deps: without it Compose would start the server again first, and the restore would refuse
docker compose run --rm --no-deps backup secretbroker-server restore /backups/secretbroker-backup-20261112-031500.zip
# or a file from this machine:
docker compose run --rm --no-deps -v "$PWD/my-backup.zip:/restore.zip:ro" backup secretbroker-server restore /restore.zip
docker compose up -d
```

After a restore the server is back in time: the apps keep what they have, push their newer edits again, and refuse
anything older than what they already saw (rollbacks are detected). A member removed after that backup is back in
the server's lists until removed again: do it, and rotate what they could see.

## Upgrades and versions

A server installed with `install-server.sh` updates itself ([Automatic updates](#automatic-updates)). With Docker:

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
| `SB_BACKUP_DIR` | `SB_DATA_DIR/backups` (`/backups` in Compose) | Where backups go (the daily ones and the app's «back up now») |
| `SB_BACKUP_KEEP` | `14` | Backups kept |
| `SB_AUTO_UPDATE` | `1` | Signed automatic updates (`install-server.sh` installs only); the app's switch wins once used |
| `SB_INSTALL` | `other` | How the server was installed (`systemd` by install-server.sh, `docker` in the image): the app's server panel shows the matching restore command |
| `SB_PORT` | `8080` | (`install-server.sh`) The local port the server listens on, on 127.0.0.1 |
| `SB_UPDATE_SOURCE` | GitHub | (`install-server.sh`) Where the updater looks for releases: an `https://` GitHub API URL or a folder. Signatures are checked the same |
| `SB_UPDATE_TRUST` | empty | (`install-server.sh`) Extra Ed25519 public keys (base64, comma-separated) the updater and installer accept besides the release key: for a fork that signs its own releases, and for CI |

**Which value wins.** The server admin's choices in the app (signups, automatic updates) are saved in
`SB_DATA_DIR/settings.json` and win over the variables above; the variables win over the defaults. To go back to
the variable, change the setting in the app (or delete that file and restart the server).

The first account created on a server with `SB_SIGNUPS=open` becomes server admin. Server admins can create signup
tokens (`POST /api/v1/admin/invites`). Failed logins are throttled per e-mail and per address with a growing wait.
The desktop apps also refuse to apply many deletions at once: they ask the user first.

The container runs as an unprivileged user (uid 10001) with a read-only filesystem except its volumes, no Linux
capabilities and `no-new-privileges`; the data and backup folders are `700` and every file the server writes is
`600`.

By hand, on any system: `pip install ./server`, set the variables above and run `secretbroker-server serve --port 8080`
behind any TLS reverse proxy, as its own unprivileged user, with `secretbroker-server backup` daily from cron (no
automatic updates then).

## Tests

```sh
.venv/Scripts/python.exe server/tests/test_server.py    # Windows; python server/tests/test_server.py elsewhere
```

The installer and the updater for real (a throwaway Ubuntu with systemd only: it installs into the system; CI's
`server-install` job runs it):

```sh
bash tools/build_server.sh
sudo bash server/tests/test_install.sh dist/secretbroker-server-*-linux-x86_64.tar.gz
```
