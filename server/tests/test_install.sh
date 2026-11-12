#!/usr/bin/env bash
# The one-command install and the signed automatic updates, for real, on a throwaway Ubuntu with systemd (the CI
# runner, or WSL with systemd). It installs into the system: don't run it on a server you use.
#
#   sudo bash server/tests/test_install.sh dist/secretbroker-server-<version>-linux-x86_64.tar.gz
#
# 1. install-server.sh --local from that artifact, non-interactively, signed with a throwaway key it is told to trust
#    (SB_UPDATE_TRUST); the service runs as its own account, healthy, listening on 127.0.0.1 only; timers present;
#    the admin's one-time token registers the admin (and nobody else), whose session reaches the admin API;
# 2. running it again repairs without changing anything;
# 3. the updater installs a signed newer version (health ok, the new version answers);
# 4. it refuses one signed with another key, and one without a signature;
# 5. it rolls back a signed version that does not start, to the previous version and its database.
set -euo pipefail

ARTIFACT=$(readlink -f "$1")
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d /srv/sb-install-test.XXXXXX)   # not /tmp nor /home: the updater's sandbox can't see those
chmod 755 "$WORK"
STATUS=/var/lib/secretbroker-updater/status.json
fail() { echo "::error::$*"; journalctl -u secretbroker-server -u secretbroker-server-update -n 60 --no-pager || true; exit 1; }
ok() { echo "  OK   $*"; }

VERSION=$(basename "$ARTIFACT" | sed -n 's/^secretbroker-server-\([0-9.]*\)-linux-.*$/\1/p')
mkdir -p "$WORK/py" "$WORK/a" "$WORK/rel"
tar -xzf "$ARTIFACT" -C "$WORK/py" ./python
PY="$WORK/py/python/bin/python3"
FAKE="$REPO/server/tests/fake_release.py"
json() { "$PY" -I -c "import json,sys; print(json.load(sys.stdin)$1)"; }

KEYS=$("$PY" -I "$FAKE" keygen)
export TEST_SIGNING_KEY; TEST_SIGNING_KEY=$(json '["private"]' <<< "$KEYS")
PUBLIC=$(json '["public"]' <<< "$KEYS")
cp "$ARTIFACT" "$WORK/a/"
"$PY" -I "$FAKE" sign "$WORK/a/$(basename "$ARTIFACT")" "$VERSION"

echo "1. Install ($VERSION, --local, non-interactive)"
CI=1 SB_ADMIN_EMAIL=admin@example.com SB_UPDATE_TRUST="$PUBLIC" \
    bash "$REPO/server/install-server.sh" --local --artifact "$WORK/a/$(basename "$ARTIFACT")" | tee "$WORK/out1"
TOKEN=$(sed -n 's/.*Código de invitación: \(sbi_[A-Za-z0-9_-]*\).*/\1/p' "$WORK/out1")
[ -n "$TOKEN" ] || fail "no signup token printed for the admin"
ok "it printed the admin's one-time token"
systemctl is-active --quiet secretbroker-server || fail "the service is not active"
[ "$(curl -fsS http://127.0.0.1:8080/api/v1/health)" = '{"status":"ok"}' ] || fail "health"
ok "the service is active and healthy"
[ "$(ps -o user= -p "$(systemctl show -p MainPID --value secretbroker-server)")" = secretbroker-server ] \
    || fail "the server does not run as secretbroker-server"
ss -Hltn 'sport = :8080' | awk '{print $4}' | grep -qv '^127.0.0.1:8080$' && fail "it listens beyond 127.0.0.1"
ok "as its own account, on 127.0.0.1 only"
for timer in secretbroker-server-backup.timer secretbroker-server-update.timer; do
    systemctl is-enabled --quiet "$timer" && systemctl is-active --quiet "$timer" || fail "$timer"
done
systemctl list-timers --all --no-pager | grep -E 'secretbroker-server-(backup|update)'
ok "backup and update timers are on"
[ "$(stat -c '%a %U' /var/lib/secretbroker-server)" = "700 secretbroker-server" ] || fail "data folder permissions"
[ "$(stat -c '%a %U' /var/lib/secretbroker-server/secretbroker.db)" = "600 secretbroker-server" ] || fail "database permissions"
[ "$(stat -c '%a %U' /etc/secretbroker-server/server.env)" = "600 root" ] || fail "settings permissions"
ok "private data and settings"
systemd-analyze security secretbroker-server.service --no-pager | tail -1
systemctl start secretbroker-server-backup.service
backup=$(ls /var/lib/secretbroker-server/backups/secretbroker-backup-*.zip | tail -1)
[ "$(stat -c '%a %U' "$backup")" = "600 secretbroker-server" ] || fail "backup"
ok "the backup service writes a private backup ($(basename "$backup"))"
secretbroker-server users > /dev/null || fail "the sudo secretbroker-server wrapper"
ok "the wrapper runs the command line"

# The admin's token works for the admin's address only; the admin's session reaches the admin API.
"$PY" -I - "$TOKEN" <<'EOF' || fail "admin account and admin API"
import base64, json, os, sys, urllib.error, urllib.request, uuid
base = "http://127.0.0.1:8080/api/v1"
def call(method, path, body=None, token=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
r = lambda n: base64.b64encode(os.urandom(n)).decode()
kdf = {"name": "scrypt", "n": 2**17, "r": 8, "p": 1, "salt": r(16)}
def register(email, token):
    body = {"user_id": str(uuid.uuid4()), "email": email, "name": "Admin", "kdf": kdf, "auth_hash": AUTH,
            "public_key": r(32), "signing_public_key": r(32), "private_blob": {"nonce": r(12), "ciphertext": r(200)},
            "invite_token": token}
    return call("POST", "/accounts/register", body)[0]
AUTH = r(32)
assert register("mallory@example.com", sys.argv[1]) == 403, "another address used the admin's token"
assert register("admin@example.com", sys.argv[1]) == 200, "the admin could not register"
status, login = call("POST", "/accounts/login", {"email": "admin@example.com", "auth_hash": AUTH, "device_name": "CI"})
assert status == 200 and login["user"]["admin"], login
status, view = call("GET", "/admin/overview", token=login["token"])
assert status == 200 and view["updates"]["updater"] and view["restore"] == "cli" and view["backups"]["count"] >= 1, view
assert view["install"] == "systemd" and view["restore_command"] == [
    "sudo secretbroker-server restore /var/lib/secretbroker-server/backups/<file>"], view
status, made = call("POST", "/admin/backups", {}, token=login["token"])
assert status == 200 and made["file"].startswith("secretbroker-backup-"), made
open("/root/.sb-test-admin-token", "w").write(login["token"])
print("  OK   the token registers the admin only; the admin API answers (overview, backup now)")
EOF

echo "2. Run the installer again"
CI=1 bash "$REPO/server/install-server.sh" --artifact "$WORK/a/$(basename "$ARTIFACT")" | tee "$WORK/out2"
grep -q "already exists and is the administrator" "$WORK/out2" || fail "the second run should see the admin account"
grep -q "SB_UPDATE_TRUST='$PUBLIC'" /etc/secretbroker-server/server.env || fail "the second run lost a setting"
systemctl is-active --quiet secretbroker-server && curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null || fail "after the second run"
ok "repairs in place, keeps the settings and the local mode"

updater() {  # run the daily update now; its exit code says refused/rolled back, which some steps expect
    systemctl start secretbroker-server-update.service || true
    cat "$STATUS"; echo
}
running() { curl -fsS http://127.0.0.1:8080/api/v1/info | json '["version"]'; }
echo "SB_UPDATE_SOURCE='$WORK/rel'" >> /etc/secretbroker-server/server.env

echo "3. A signed newer version"
"$PY" -I "$FAKE" repack "$ARTIFACT" "$WORK/rel" 0.99.0 >/dev/null
"$PY" -I "$FAKE" sign "$WORK/rel/secretbroker-server-0.99.0-linux-x86_64.tar.gz" 0.99.0
updater
[ "$(json '["last_result"]' < "$STATUS")" = updated ] || fail "the update was not installed"
[ "$(running)" = 0.99.0 ] || fail "0.99.0 does not answer"
[ "$(readlink /opt/secretbroker-server/current)" = versions/0.99.0 ] || fail "current link"
[ "$(curl -fsS http://127.0.0.1:8080/api/v1/health)" = '{"status":"ok"}' ] || fail "health after the update"
[ "$(find /var/lib/secretbroker-server/backups -name 'secretbroker-backup-*.zip' | wc -l)" -ge 3 ] \
    || fail "no backup before the update"
ok "installed, healthy, after a backup"
TOKEN_ADMIN=$(cat /root/.sb-test-admin-token)
latest=$(curl -fsS -H "Authorization: Bearer $TOKEN_ADMIN" http://127.0.0.1:8080/api/v1/admin/overview | json '["latest"]')
[ "$latest" = 0.99.0 ] || fail "the overview does not show the updater's result ($latest)"
ok "the admin overview shows it"

echo "4. Refused: another key, no signature"
OTHER=$("$PY" -I "$FAKE" keygen)
"$PY" -I "$FAKE" repack "$ARTIFACT" "$WORK/rel" 1.0.0 >/dev/null
TEST_SIGNING_KEY=$(json '["private"]' <<< "$OTHER") "$PY" -I "$FAKE" sign "$WORK/rel/secretbroker-server-1.0.0-linux-x86_64.tar.gz" 1.0.0
updater
[ "$(json '["last_result"]' < "$STATUS")" = refused ] && [ "$(running)" = 0.99.0 ] && [ ! -e /opt/secretbroker-server/versions/1.0.0 ] \
    || fail "a wrongly signed version was not refused"
ok "a version signed with another key is refused"
rm "$WORK/rel/secretbroker-server-1.0.0-linux-x86_64.tar.gz.sig"
updater
[ "$(json '["last_result"]' < "$STATUS")" = refused ] && [ "$(running)" = 0.99.0 ] || fail "an unsigned version was not refused"
ok "an unsigned version is refused"
rm "$WORK/rel/secretbroker-server-1.0.0-linux-x86_64.tar.gz"

echo "5. A signed version that does not start"
"$PY" -I "$FAKE" repack "$ARTIFACT" "$WORK/rel" 0.99.1 --broken >/dev/null
"$PY" -I "$FAKE" sign "$WORK/rel/secretbroker-server-0.99.1-linux-x86_64.tar.gz" 0.99.1
updater
[ "$(json '["last_result"]' < "$STATUS")" = rolled_back ] || fail "it did not roll back"
[ "$(running)" = 0.99.0 ] && [ "$(readlink /opt/secretbroker-server/current)" = versions/0.99.0 ] \
    && [ ! -e /opt/secretbroker-server/versions/0.99.1 ] || fail "not back on 0.99.0"
[ "$(curl -fsS http://127.0.0.1:8080/api/v1/health)" = '{"status":"ok"}' ] || fail "health after the rollback"
curl -fsS -H "Authorization: Bearer $TOKEN_ADMIN" http://127.0.0.1:8080/api/v1/admin/users | grep -q admin@example.com \
    || fail "the admin account is gone after the rollback"
ok "rolled back to 0.99.0 with its database, healthy"
updater
[ "$(json '["last_result"]' < "$STATUS")" = skipped ] || fail "the failed version was tried again"
ok "the failed version is not tried again"

if [ "${SB_TEST_CADDY:-}" = 1 ]; then
    # Caddy from its official repository, in front of the server. sb.example.test can never get a certificate, so
    # this checks the setup (package, configuration, the redirect to HTTPS), not TLS itself.
    echo "6. Switch to Caddy (HTTPS) with a domain"
    CI=1 SB_DOMAIN=sb.example.test bash "$REPO/server/install-server.sh" --caddy --artifact "$WORK/a/$(basename "$ARTIFACT")" \
        | tee "$WORK/out3"
    grep -q "keeping it" "$WORK/out3" || fail "the installer should keep the newer version"
    [ "$(running)" = 0.99.0 ] || fail "the installer changed the version"
    systemctl is-active --quiet caddy || fail "caddy is not running"
    apt-cache policy caddy
    # The installed version (the *** line) comes from Caddy's repository.
    apt-cache policy caddy | awk '/\*\*\*/ {getline; print}' | grep -q "dl.cloudsmith.io" \
        || fail "caddy is not from its official repository"
    grep -q "^import /etc/caddy/secretbroker.caddy" /etc/caddy/Caddyfile || fail "the Caddyfile does not import the site"
    grep -q "reverse_proxy 127.0.0.1:8080" /etc/caddy/secretbroker.caddy || fail "the site does not proxy to the server"
    grep -q "^SB_PUBLIC_URL='https://sb.example.test'" /etc/secretbroker-server/server.env || fail "public URL"
    grep -q "^SB_ALLOW_HTTP" /etc/secretbroker-server/server.env && fail "plain HTTP is still allowed"
    redirect=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: sb.example.test' http://127.0.0.1/)
    [ "$redirect" = "308 https://sb.example.test/" ] || fail "caddy does not redirect to HTTPS ($redirect)"
    grep -q "Not reachable from the internet yet" "$WORK/out3" || fail "it should say the domain is not reachable"
    curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null || fail "health with https settings"
    ok "Caddy from its repository proxies the domain, redirects to HTTPS, and the installer says what to check"
fi

rm -f /root/.sb-test-admin-token
echo "All install and update checks passed."
