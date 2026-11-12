#!/usr/bin/env bash
# SecretBroker Server: install on a headless Ubuntu 22.04 / 24.04 / 26.04 server with one command, without Docker.
#
#   curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh | sudo bash
#
# It asks two things (the server's domain name and your e-mail), then installs the server under
# /opt/secretbroker-server as its own unprivileged account with a hardened systemd unit, Caddy for automatic HTTPS,
# a daily backup (14 kept) and signed automatic updates, and prints what to do next in the desktop app.
# Running it again repairs and upgrades; your data and settings stay.
#
# Without questions (all optional except the first two on a new server):
#   curl -fsSL .../install-server.sh | sudo SB_DOMAIN=secrets.example.com SB_ADMIN_EMAIL=you@example.com bash
#   SB_SMTP_HOST, SB_SMTP_PORT, SB_SMTP_SECURITY, SB_SMTP_USER, SB_SMTP_PASSWORD, SB_SMTP_FROM   e-mail (optional)
#   SB_PORT (8080), SB_SIGNUPS (invite), SB_SERVER_NAME, SB_EMAIL_VERIFICATION, SB_BACKUP_KEEP (14),
#   SB_AUTO_UPDATE (1)
#
# Options (after `bash -s --` when piped):
#   --local             no Caddy: the server answers on http://127.0.0.1:<port> only. For a tunnel (Cloudflare
#                       Tunnel, Tailscale: give SB_DOMAIN = its public name) or for tests (no SB_DOMAIN).
#   --artifact FILE     install this server archive (its signature FILE.sig next to it) instead of downloading
#   --uninstall         remove the server's programs and units; keeps the data and settings (--purge: those too)
#
# Nothing is installed unless its Ed25519 signature verifies with the release key below (the same key the
# desktop app and the server's updater trust). This script itself comes over HTTPS from GitHub; its signature is
# published next to it (install-server.sh.sig) for whoever wants to check it first.
set -euo pipefail

REPO=xBofi/SecretBroker
RELEASE_KEY="Y54EWQu13b79ilylP/cAvqFDvzxjkwiYkEq/puedHos="
ROOT=/opt/secretbroker-server
ETC=/etc/secretbroker-server
ENV_FILE=$ETC/server.env
DATA=/var/lib/secretbroker-server
UPDATER_STATE=/var/lib/secretbroker-updater
ACCOUNT=secretbroker-server
UNITS=(secretbroker-server.service secretbroker-server-backup.service secretbroker-server-backup.timer
       secretbroker-server-update.service secretbroker-server-update.timer)
WRAPPER=/usr/local/sbin/secretbroker-server
CADDY_SITE=/etc/caddy/secretbroker.caddy

say() { printf '%s\n' "$*"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------- settings file (KEY='value' lines)

declare -A CONF=()
CONF_ORDER=(SB_INSTALL SB_INSTALL_MODE SB_DOMAIN SB_PUBLIC_URL SB_ALLOW_HTTP SB_ADMIN_EMAILS SB_PORT SB_SIGNUPS SB_SERVER_NAME
            SB_TRUST_PROXY SB_EMAIL_VERIFICATION SB_SMTP_HOST SB_SMTP_PORT SB_SMTP_SECURITY SB_SMTP_USER
            SB_SMTP_PASSWORD SB_SMTP_FROM SB_BACKUP_KEEP SB_AUTO_UPDATE SB_UPDATE_SOURCE SB_UPDATE_TRUST)

load_conf() {
    [ -f "$ENV_FILE" ] || return 0
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            SB_*=*)
                key=${line%%=*}
                value=${line#*=}
                value=${value#\'}
                value=${value%\'}
                CONF[$key]=$value
                ;;
        esac
    done < "$ENV_FILE"
}

set_conf() {  # set_conf KEY VALUE: an empty VALUE leaves what was there
    [ -n "${2:-}" ] || return 0
    case "$2" in *"'"*|*$'\n'*) die "$1 can't contain a single quote or a new line." ;; esac
    CONF[$1]=$2
}

write_conf() {
    local tmp key seen=" "
    install -d -m 0755 -o root -g root "$ETC"
    tmp=$(mktemp "$ETC/.server.env.XXXXXX")
    chmod 600 "$tmp"
    {
        say "# SecretBroker Server settings, read by its systemd units (written by install-server.sh; re-running it"
        say "# keeps them). After changing a value by hand: sudo systemctl restart secretbroker-server"
        say "# The desktop app's server panel saves its own choices (signups, automatic updates) in"
        say "# $DATA/settings.json, and those win over SB_SIGNUPS and SB_AUTO_UPDATE here."
        for key in "${CONF_ORDER[@]}" $(printf '%s\n' "${!CONF[@]}" | sort); do
            case "$seen" in *" $key "*) continue ;; esac
            seen="$seen$key "
            [ -n "${CONF[$key]+x}" ] && [ -n "${CONF[$key]}" ] && printf "%s='%s'\n" "$key" "${CONF[$key]}"
        done
    } > "$tmp"
    mv "$tmp" "$ENV_FILE"
}

# ---------------------------------------------------------------------- signatures

# Ed25519 over "SecretBroker release\0" + version + "\0" + SHA-256(file), as tools/sign_release.py makes them.
verify_signature() {  # FILE VERSION SIGFILE -> 0 when one of the trusted keys signed it
    local file=$1 version=$2 sigfile=$3 work key
    [ -s "$sigfile" ] || return 1
    work=$(mktemp -d)
    { printf 'SecretBroker release\0'; printf '%s\0' "$version"; openssl dgst -sha256 -binary "$file"; } > "$work/msg"
    if ! tr -d ' \r\n' < "$sigfile" | base64 -d > "$work/sig" 2>/dev/null || [ "$(stat -c %s "$work/sig")" != 64 ]; then
        rm -rf "$work"
        return 1
    fi
    for key in $RELEASE_KEY ${CONF[SB_UPDATE_TRUST]//,/ }; do
        { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; printf '%s' "$key" | base64 -d 2>/dev/null; } > "$work/key.der"
        if openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/key.der" -rawin -in "$work/msg" \
                -sigfile "$work/sig" >/dev/null 2>&1; then
            rm -rf "$work"
            return 0
        fi
    done
    rm -rf "$work"
    return 1
}

version_key() {  # 0.17.10 -> 000000017000010, for comparisons
    local IFS=.
    # shellcheck disable=SC2086
    set -- $1
    printf '%05d%05d%05d' "${1:-0}" "${2:-0}" "${3:-0}"
}

# ---------------------------------------------------------------------- pieces

ask() {  # ask VAR "question": reads from the terminal even when the script comes through a pipe
    local answer=""
    if [ "$INTERACTIVE" = 1 ]; then
        read -r -p "$2 " answer < /dev/tty || true
    fi
    printf -v "$1" '%s' "$answer"
}

check_system() {
    [ "$(id -u)" = 0 ] || die "run it as root: curl -fsSL https://github.com/$REPO/releases/latest/download/install-server.sh | sudo bash"
    [ -d /run/systemd/system ] || die "this system does not run systemd. Use Docker instead (server/README.md)."
    local arch
    arch=$(uname -m)
    [ "$arch" = x86_64 ] || die "this installer is for x86-64 servers (this one is $arch). Use Docker instead (server/README.md)."
    ARCH=$arch
    if [ -r /etc/os-release ]; then
        local os
        # In a subshell: os-release sets VERSION, NAME and others.
        # shellcheck disable=SC1091
        os=$(. /etc/os-release && printf '%s:%s:%s' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-}")
        case "$os" in
            ubuntu:22.04:*|ubuntu:24.04:*|ubuntu:26.04:*) ;;
            ubuntu:*|debian:*) say "Note: tested on Ubuntu 22.04 and 24.04; this is ${os##*:}. Continuing." ;;
            *) die "this installer is for Ubuntu (22.04 or 24.04). Use Docker instead (server/README.md)." ;;
        esac
    fi
}

apt_install() {
    local missing=() pkg
    for pkg in "$@"; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
    done
    [ ${#missing[@]} -eq 0 ] && return 0
    say "Installing ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
}

current_version() {
    cat "$ROOT/current/VERSION" 2>/dev/null || true
}

fetch_artifact() {  # sets ARTIFACT, SIGNATURE, VERSION
    if [ -n "$LOCAL_ARTIFACT" ]; then
        [ -f "$LOCAL_ARTIFACT" ] || die "no such file: $LOCAL_ARTIFACT"
        ARTIFACT=$(readlink -f "$LOCAL_ARTIFACT")
        SIGNATURE="$ARTIFACT.sig"
    else
        local url latest
        url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") \
            || die "GitHub could not be reached. Check this server's internet connection and try again."
        latest=${url##*/}
        latest=${latest#v}
        [[ "$latest" =~ ^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$ ]] || die "could not tell the latest version ($url)."
        local name="secretbroker-server-$latest-linux-$ARCH.tar.gz"
        install -d -m 0700 "$ROOT/downloads"
        ARTIFACT="$ROOT/downloads/$name"
        SIGNATURE="$ARTIFACT.sig"
        say "Downloading SecretBroker Server $latest"
        curl -fsSL --retry 3 -o "$SIGNATURE" "https://github.com/$REPO/releases/download/v$latest/$name.sig" \
            || die "release $latest has no server for this system yet ($name)."
        curl -fsSL --retry 3 -o "$ARTIFACT" "https://github.com/$REPO/releases/download/v$latest/$name" \
            || die "could not download $name."
    fi
    local base
    base=$(basename "$ARTIFACT")
    [[ "$base" =~ ^secretbroker-server-([0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})-linux-([a-z0-9_]+)\.tar\.gz$ ]] \
        || die "$base is not a SecretBroker Server archive."
    VERSION=${BASH_REMATCH[1]}
    [ "${BASH_REMATCH[2]}" = "$ARCH" ] || die "$base is for ${BASH_REMATCH[2]}, this server is $ARCH."
    verify_signature "$ARTIFACT" "$VERSION" "$SIGNATURE" \
        || die "the signature of $base does not verify with the SecretBroker release key: nothing was installed."
    say "Signature of $base: valid."
}

install_code() {
    local current
    current=$(current_version)
    if [ -n "$current" ] && [ "$(version_key "$current")" \> "$(version_key "$VERSION")" ]; then
        say "Version $current is installed, newer than $VERSION: keeping it."
        return 0
    fi
    if [ "$current" = "$VERSION" ] && [ -x "$ROOT/current/python/bin/python3" ] && [ "$REINSTALL" != 1 ]; then
        say "Version $VERSION is already installed."
        return 0
    fi
    local unpack="$ROOT/versions/.unpack-$VERSION"
    install -d -m 0755 "$ROOT" "$ROOT/versions"
    rm -rf "$unpack"
    mkdir -p "$unpack"
    tar -xzf "$ARTIFACT" -C "$unpack" --no-same-owner
    [ "$(cat "$unpack/VERSION" 2>/dev/null)" = "$VERSION" ] || { rm -rf "$unpack"; die "the archive's VERSION is not $VERSION."; }
    "$unpack/python/bin/python3" -I -c "import secretbroker_server.web" \
        || { rm -rf "$unpack"; die "the server in the archive does not start on this system."; }
    if [ -n "$current" ] && [ "$current" != "$VERSION" ]; then
        ln -sfn "versions/$current" "$ROOT/previous"
    fi
    rm -rf "$ROOT/versions/$VERSION.old"
    [ -d "$ROOT/versions/$VERSION" ] && mv "$ROOT/versions/$VERSION" "$ROOT/versions/$VERSION.old"
    mv "$unpack" "$ROOT/versions/$VERSION"
    ln -sfn "versions/$VERSION" "$ROOT/current.new"
    mv -T "$ROOT/current.new" "$ROOT/current"
    rm -rf "$ROOT/versions/$VERSION.old"
    # Keep the current and the previous version, as the updater does.
    local keep_prev dir
    keep_prev=$(readlink "$ROOT/previous" 2>/dev/null || true)
    for dir in "$ROOT"/versions/*; do
        [ -d "$dir" ] || continue
        case "versions/$(basename "$dir")" in "versions/$VERSION"|"$keep_prev") ;; *) rm -rf "$dir" ;; esac
    done
    say "Installed SecretBroker Server $VERSION in $ROOT."
}

create_account() {
    if ! id -u "$ACCOUNT" >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin \
            --comment "SecretBroker Server" "$ACCOUNT"
    fi
}

install_units() {
    local unit
    for unit in "${UNITS[@]}"; do
        install -m 0644 "$ROOT/current/systemd/$unit" "/etc/systemd/system/$unit"
    done
    ln -sfn "$ROOT/current/bin/secretbroker-server" "$WRAPPER"
    systemctl daemon-reload
    systemctl enable --quiet secretbroker-server.service secretbroker-server-backup.timer secretbroker-server-update.timer
    systemctl restart secretbroker-server.service
    systemctl start secretbroker-server-backup.timer secretbroker-server-update.timer
}

wait_health() {
    local port=${CONF[SB_PORT]}
    for _ in $(seq 60); do
        if curl -fsS --max-time 3 "http://127.0.0.1:$port/api/v1/health" 2>/dev/null | grep -q '"ok"'; then
            return 0
        fi
        sleep 1
    done
    journalctl -u secretbroker-server.service -n 40 --no-pager >&2 || true
    die "the server did not start (its log is above). Fix what it says and run this again."
}

setup_caddy() {
    if ! command -v caddy >/dev/null 2>&1; then
        step "Caddy (automatic HTTPS) from its official repository"
        apt_install ca-certificates curl gnupg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
            | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
        chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
        # Caddy's own package, even where the distribution has one with a higher version number (Ubuntu 26.04).
        printf '%s\n' "# Caddy from its official repository (install-server.sh)." "Package: caddy" \
            "Pin: origin dl.cloudsmith.io" "Pin-Priority: 600" > /etc/apt/preferences.d/caddy-stable
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null
    fi
    install -d -m 0755 /etc/caddy
    cat > "$CADDY_SITE.new" <<EOF
# SecretBroker Server, managed by install-server.sh (re-run it to change this). Caddy gets and renews the
# certificate by itself; only it is reachable from the internet, the server listens on 127.0.0.1.
${CONF[SB_DOMAIN]} {
	request_body {
		max_size 10MB
	}
	reverse_proxy 127.0.0.1:${CONF[SB_PORT]}
	header -Server
}
EOF
    chmod 644 "$CADDY_SITE.new"
    mv "$CADDY_SITE.new" "$CADDY_SITE"
    local main=/etc/caddy/Caddyfile
    if ! grep -qs "import $CADDY_SITE" "$main"; then
        # The package's own example (a page on :80) is replaced; any other configuration is kept and imports ours.
        local meaningful
        meaningful=$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$main" 2>/dev/null | tr -d '\n')
        if [ -f "$main" ] && [ ! -e "$main.orig" ]; then
            cp "$main" "$main.orig"
        fi
        if [ -z "$meaningful" ] || [ "$meaningful" = ":80{root*/usr/share/caddyfile_server}" ]; then
            printf '# Managed by install-server.sh (SecretBroker Server).\nimport %s\n' "$CADDY_SITE" > "$main"
        else
            printf '\n# SecretBroker Server (install-server.sh)\nimport %s\n' "$CADDY_SITE" >> "$main"
        fi
    fi
    caddy validate --config "$main" --adapter caddyfile >/dev/null 2>&1 \
        || { caddy validate --config "$main" --adapter caddyfile || true; die "Caddy does not accept $main (above)."; }
    systemctl enable --quiet caddy
    systemctl reload caddy 2>/dev/null || systemctl restart caddy
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null && ufw allow 443/udp >/dev/null
        say "Firewall (ufw): ports 80 and 443 open."
    fi
}

check_public() {
    local url=${CONF[SB_PUBLIC_URL]}
    for _ in $(seq 20); do
        if curl -fsS --max-time 5 "$url/api/v1/health" 2>/dev/null | grep -q '"ok"'; then
            PUBLIC_OK=1
            return 0
        fi
        sleep 3
    done
    PUBLIC_OK=0
}

admin_token() {  # prints a one-time signup token for the admin e-mail, unless that account exists already
    local address=$1
    if "$WRAPPER" users 2>/dev/null | awk -v e="$address" '$1 == e {found=1} END {exit !found}'; then
        return 0
    fi
    "$WRAPPER" create-invite --days 14 --email "$address" 2>/dev/null | head -1
}

uninstall() {
    check_system
    step "Removing SecretBroker Server"
    systemctl disable --now "${UNITS[@]}" 2>/dev/null || true
    for unit in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$unit"; done
    systemctl daemon-reload
    rm -rf "$ROOT" "$WRAPPER"
    if [ -f "$CADDY_SITE" ]; then
        rm -f "$CADDY_SITE"
        sed -i "\#import $CADDY_SITE#d; /# SecretBroker Server (install-server.sh)/d; /# Managed by install-server.sh/d" /etc/caddy/Caddyfile 2>/dev/null || true
        systemctl reload caddy 2>/dev/null || true
        say "Caddy stays installed; its SecretBroker site is gone."
    fi
    if [ "$PURGE" = 1 ]; then
        rm -rf "$DATA" "$UPDATER_STATE" "$ETC"
        userdel "$ACCOUNT" 2>/dev/null || true
        say "Removed, with its data, backups and settings."
    else
        say "Removed. The data and backups stay in $DATA and the settings in $ETC"
        say "(run with --uninstall --purge to delete them too)."
    fi
}

# ---------------------------------------------------------------------- main

main() {
    MODE="" LOCAL_ARTIFACT=${SB_ARTIFACT:-} UNINSTALL=0 PURGE=0 REINSTALL=0 PUBLIC_OK=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --local) MODE=local ;;
            --caddy) MODE=caddy ;;
            --artifact) LOCAL_ARTIFACT=${2:?--artifact needs a file}; shift ;;
            --artifact=*) LOCAL_ARTIFACT=${1#*=} ;;
            --reinstall) REINSTALL=1 ;;
            --uninstall) UNINSTALL=1 ;;
            --purge) PURGE=1 ;;
            -h|--help) sed -n '2,27p' "$0" 2>/dev/null || true; exit 0 ;;
            *) die "unknown option $1 (see --help)" ;;
        esac
        shift
    done
    umask 022
    if [ "$UNINSTALL" = 1 ]; then
        uninstall
        return 0
    fi
    INTERACTIVE=0
    if [ -z "${CI:-}" ] && (exec < /dev/tty) 2>/dev/null; then INTERACTIVE=1; fi

    check_system
    load_conf
    local fresh=1
    [ -f "$ENV_FILE" ] && fresh=0
    MODE=${MODE:-${CONF[SB_INSTALL_MODE]:-caddy}}

    step "SecretBroker Server: $([ "$fresh" = 1 ] && echo installing || echo "repairing and upgrading") ($MODE)"
    local domain=${SB_DOMAIN:-} email=${SB_ADMIN_EMAIL:-}
    if [ -z "$domain" ] && [ -z "${CONF[SB_DOMAIN]:-}" ] && [ "$MODE" = caddy ]; then
        say "The server needs a name on the internet, for example secrets.example.com, whose DNS A record points"
        say "at this server's IP address, with ports 80 and 443 open (Caddy gets the HTTPS certificate for it)."
        ask domain "Domain name:"
        [ -n "$domain" ] || die "a domain name is needed (or SB_DOMAIN=... on the command line; --local for none)."
    fi
    domain=${domain#https://}
    domain=${domain%%/*}
    if [ -n "$domain" ] && ! [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ && "$domain" == *.* ]]; then
        die "$domain is not a domain name."
    fi
    if [ -z "$email" ] && [ -z "${CONF[SB_ADMIN_EMAILS]:-}" ]; then
        say "Your e-mail: the account you will create in the desktop app becomes this server's administrator."
        ask email "Your e-mail:"
    fi
    email=$(printf '%s' "$email" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    if [ -n "$email" ] && ! [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
        die "$email is not an e-mail address."
    fi
    [ -n "$email" ] || [ -n "${CONF[SB_ADMIN_EMAILS]:-}" ] \
        || die "an admin e-mail is needed (SB_ADMIN_EMAIL=you@example.com on the command line)."

    set_conf SB_INSTALL_MODE "$MODE"
    set_conf SB_INSTALL systemd  # GET /admin/overview `install`: the app shows the matching restore command
    set_conf SB_DOMAIN "$domain"
    if [ -n "$email" ]; then
        case ",${CONF[SB_ADMIN_EMAILS]:-}," in
            *",$email,"*) ;;
            ,,) CONF[SB_ADMIN_EMAILS]=$email ;;
            *) CONF[SB_ADMIN_EMAILS]="${CONF[SB_ADMIN_EMAILS]},$email" ;;
        esac
    fi
    set_conf SB_PORT "${SB_PORT:-${CONF[SB_PORT]:-8080}}"
    [[ "${CONF[SB_PORT]}" =~ ^[0-9]{2,5}$ ]] || die "SB_PORT must be a port number."
    set_conf SB_SIGNUPS "${SB_SIGNUPS:-${CONF[SB_SIGNUPS]:-invite}}"
    set_conf SB_TRUST_PROXY 1  # only Caddy (or the tunnel) reaches 127.0.0.1, so its X-Forwarded-For is trustworthy
    set_conf SB_BACKUP_KEEP "${SB_BACKUP_KEEP:-${CONF[SB_BACKUP_KEEP]:-14}}"
    set_conf SB_AUTO_UPDATE "${SB_AUTO_UPDATE:-${CONF[SB_AUTO_UPDATE]:-1}}"
    local var
    for var in SB_SERVER_NAME SB_EMAIL_VERIFICATION SB_SMTP_HOST SB_SMTP_PORT SB_SMTP_SECURITY SB_SMTP_USER \
               SB_SMTP_PASSWORD SB_SMTP_FROM SB_UPDATE_SOURCE SB_UPDATE_TRUST SB_MIN_CLIENT; do
        set_conf "$var" "${!var:-}"
    done
    if [ -n "${CONF[SB_DOMAIN]:-}" ]; then
        CONF[SB_PUBLIC_URL]="https://${CONF[SB_DOMAIN]}"
        unset 'CONF[SB_ALLOW_HTTP]'
    else
        [ "$MODE" = local ] || die "a domain name is needed without --local."
        CONF[SB_PUBLIC_URL]="http://127.0.0.1:${CONF[SB_PORT]}"
        CONF[SB_ALLOW_HTTP]=1
    fi

    step "Programs"
    apt_install ca-certificates curl openssl tar util-linux
    install -d -m 0755 "$ROOT"
    exec 9> "$ROOT/.update.lock"
    flock 9   # not while the updater runs
    fetch_artifact
    create_account
    install_code
    write_conf
    rm -rf "$ROOT/downloads"

    step "Services"
    install_units
    wait_health
    say "The server answers on http://127.0.0.1:${CONF[SB_PORT]} (health: ok)."
    if [ "$MODE" = caddy ]; then
        setup_caddy
        step "Checking ${CONF[SB_PUBLIC_URL]} from here"
        check_public
    fi
    flock -u 9

    local token="" admin
    admin=${email:-${CONF[SB_ADMIN_EMAILS]%%,*}}
    token=$(admin_token "$admin" || true)
    local url=${CONF[SB_PUBLIC_URL]} version
    version=$(current_version)

    step "Done: SecretBroker Server $version"
    say "  Address:  $url"
    if [ "$MODE" = caddy ] && [ "$PUBLIC_OK" != 1 ]; then
        say ""
        say "  Not reachable from the internet yet. Caddy keeps trying to get the certificate by itself; check that:"
        say "    - the DNS A record of ${CONF[SB_DOMAIN]} points at this server's public IP address (your"
        say "      provider's panel shows it);"
        say "    - ports 80 and 443 are open in your provider's firewall (the cloud panel, not only this server)."
        say "  Then it works without running anything again (sudo journalctl -u caddy shows its progress)."
    fi
    if [ "$MODE" = local ] && [ -z "${CONF[SB_DOMAIN]:-}" ]; then
        say "  Local mode: only this machine reaches it, over plain HTTP. For a team, put a tunnel in front"
        say "  (see server/README.md) and run this again with SB_DOMAIN=<the tunnel's public name>."
    fi
    say ""
    say "Next, in the SecretBroker desktop app on your PC:"
    say "  1. Equipo › Crear cuenta."
    say "  2. Servidor: $url"
    if [ -n "$token" ]; then
        say "  3. E-mail: $admin"
        say "  4. Código de invitación: $token"
        say "     (valid 14 days, once, only for $admin: it makes you this server's administrator)"
        say "     Or paste this link in «Servidor» and it fills in the rest:"
        say "     secretbroker://join?server=$url&email=${admin//+/%2B}&code=$token"
    else
        say "  3. Sign in («Entrar») with $admin: that account already exists and is the administrator."
    fi
    say "  Then the server is administered from the app: accounts, organizations, backups, updates."
    say ""
    say "Backups: every day, the last ${CONF[SB_BACKUP_KEEP]} in $DATA/backups (copy them off this machine too)."
    say "Updates: signed ones install by themselves every night; switch them off in the app if you prefer."
    if [ -z "${CONF[SB_SMTP_HOST]:-}" ]; then
        say "E-mail: not set up, so invitations are passed on by hand (the app gives you the text) and new"
        say "accounts are verified from the app's server panel. To add it, run this again with the SB_SMTP_* values."
    fi
}

main "$@"
