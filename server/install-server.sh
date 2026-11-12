#!/usr/bin/env bash
# SecretBroker Server: install on a headless Ubuntu 22.04 / 24.04 / 26.04 server with one command, without Docker.
#
#   curl -fsSL https://github.com/xBofi/SecretBroker/releases/latest/download/install-server.sh | sudo bash
#
# It asks two things (the server's domain name and your e-mail), then installs the server under
# /opt/secretbroker-server as its own unprivileged account with a hardened systemd unit, Caddy for automatic HTTPS,
# a daily backup (14 kept) and signed automatic updates, and prints what to do next in the desktop app.
# Running it again repairs and upgrades; your data, settings and the way it is reached (below) stay.
#
# Before installing anything it checks who uses ports 80 and 443. When another program has them (nginx, Apache,
# another Caddy, Docker...) it never stops or changes it: it says so and offers the ways that fit, below.
#
# Without questions (all optional except the first two on a new server):
#   curl -fsSL .../install-server.sh | sudo SB_DOMAIN=secrets.example.com SB_ADMIN_EMAIL=you@example.com bash
#   SB_SMTP_HOST, SB_SMTP_PORT, SB_SMTP_SECURITY, SB_SMTP_USER, SB_SMTP_PASSWORD, SB_SMTP_FROM   e-mail (optional)
#   SB_PORT (8080, on 127.0.0.1 only), SB_SIGNUPS (invite), SB_SERVER_NAME, SB_EMAIL_VERIFICATION, SB_BACKUP_KEEP
#   (14), SB_AUTO_UPDATE (1), SB_MAX_BODY
#   SB_MODE             caddy (the default), proxy (--behind-proxy) or local (--local)
#   SB_HTTPS_PORT       the public HTTPS port (443); with Caddy, another one such as 8443 when 443 is taken
#   SB_PROXY_CONFIGURE  1: behind nginx, add SecretBroker's site to it and get its certificate with certbot
#                       (the questions this would ask otherwise); also lets SecretBroker's site join a Caddy that
#                       serves other sites
#   SB_TLS_CERT, SB_TLS_KEY   behind a web server: your own certificate for the domain (PEM files)
#
# Options (after `bash -s --` when piped):
#   --behind-proxy      no Caddy: your web server (nginx, Apache, Traefik...) keeps ports 80 and 443 and forwards
#                       the domain to SecretBroker on 127.0.0.1. For nginx it can add the site itself (it asks).
#   --https-port PORT   Caddy on another HTTPS port (8443...) when 443 is taken; port 80 must be free.
#   --local             no Caddy: the server answers on http://127.0.0.1:<port> only. For a tunnel (Cloudflare
#                       Tunnel, Tailscale: give SB_DOMAIN = its public name) or for tests (no SB_DOMAIN).
#   --caddy             Caddy on ports 80 and 443 (the default; to come back from another mode)
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
CADDYFILE=/etc/caddy/Caddyfile
ACME_ROOT=/var/www/secretbroker-acme
NGINX_MARK="written by install-server.sh"
INSTALL_URL="https://github.com/$REPO/releases/latest/download/install-server.sh"

say() { printf '%s\n' "$*"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------- settings file (KEY='value' lines)

declare -A CONF=()
CONF_ORDER=(SB_INSTALL SB_INSTALL_MODE SB_DOMAIN SB_HTTPS_PORT SB_PUBLIC_URL SB_ALLOW_HTTP SB_ADMIN_EMAILS SB_PORT
            SB_SIGNUPS SB_SERVER_NAME SB_TRUST_PROXY SB_PROXY_SITE SB_TLS_CERT SB_TLS_KEY SB_EMAIL_VERIFICATION
            SB_SMTP_HOST SB_SMTP_PORT SB_SMTP_SECURITY SB_SMTP_USER SB_SMTP_PASSWORD SB_SMTP_FROM SB_BACKUP_KEEP
            SB_AUTO_UPDATE SB_UPDATE_SOURCE SB_UPDATE_TRUST)

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

# ---------------------------------------------------------------------- questions

ask() {  # ask VAR "question": reads from the terminal even when the script comes through a pipe
    local _reply=""  # (a name no caller uses: printf -v would set this local instead of the caller's variable)
    if [ "$INTERACTIVE" = 1 ]; then
        read -r -p "$2 " _reply < /dev/tty || true
    fi
    printf -v "$1" '%s' "$_reply"
}

ask_yes() {  # ask_yes "question": yes unless the answer starts with n (interactive only)
    local answer
    [ "$INTERACTIVE" = 1 ] || return 1
    ask answer "$1 [Y/n]"
    case "$answer" in [Nn]*) return 1 ;; esac
    return 0
}

consent() {  # consent "question": to change something that is not SecretBroker's (nginx, a Caddy with other sites)
    [ "${SB_PROXY_CONFIGURE:-}" = 1 ] && return 0
    ask_yes "$1"
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# ---------------------------------------------------------------------- ports: who uses them

caddy_config_kind() {  # ours: only SecretBroker's site (or Caddy's example page); shared: ours and others; theirs
    local meaningful
    meaningful=$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$CADDYFILE" 2>/dev/null | tr -d '\n')
    case "$meaningful" in
        ""|":80{root*/usr/share/caddyfile_server}"|"import$CADDY_SITE") echo ours ;;
        *) if grep -qs "^import $CADDY_SITE" "$CADDYFILE"; then echo shared; else echo theirs; fi ;;
    esac
}

port_owner() {  # PORT -> OWNER (free ours nginx apache caddy-system caddy docker other unknown) and OWNER_TEXT
    local port=$1 line name="" pid="" uid="" container="" re='users:\(\("([^"]+)",pid=([0-9]+)'
    OWNER=free OWNER_TEXT=""
    line=$(ss -Hltnp "sport = :$port" 2>/dev/null | head -1) || true
    [ -n "$line" ] || return 0
    if [[ "$line" =~ $re ]]; then
        name=${BASH_REMATCH[1]} pid=${BASH_REMATCH[2]}
        uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ') || true
    fi
    if [ -n "$uid" ] && [ "$uid" = "$(id -u "$ACCOUNT" 2>/dev/null)" ]; then
        OWNER=ours
        return 0
    fi
    case "$name" in
        "") OWNER=unknown OWNER_TEXT="a program this installer can't name" ;;
        nginx) OWNER=nginx OWNER_TEXT="nginx, a web server" ;;
        apache2|httpd) OWNER=apache OWNER_TEXT="Apache, a web server" ;;
        caddy)
            if [ "$pid" = "$(systemctl show -p MainPID --value caddy 2>/dev/null)" ]; then
                if [ "$(caddy_config_kind)" != theirs ]; then
                    OWNER=ours
                    return 0
                fi
                OWNER=caddy-system OWNER_TEXT="Caddy (the system's caddy service), with sites of its own in $CADDYFILE"
            else
                OWNER=caddy OWNER_TEXT="a Caddy that is not the system's caddy service (in a container, or started by hand)"
            fi
            ;;
        docker-proxy)
            container=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
                | awk -v p=":$port->" 'index($0, p) {print $1; exit}') || true
            OWNER=docker OWNER_TEXT="Docker${container:+, for the container \"$container\"}"
            ;;
        *) OWNER=other OWNER_TEXT="a program called $name" ;;
    esac
    [ -z "$pid" ] || OWNER_TEXT="$OWNER_TEXT (process $pid)"
}

busy() {  # busy OWNER -> 0 when someone else has the port
    case "$1" in free|ours) return 1 ;; esac
    return 0
}

web_server_name() {  # OWNER -> how the options call it
    case "$1" in
        nginx) echo nginx ;;
        apache) echo Apache ;;
        caddy|caddy-system) echo Caddy ;;
        docker) echo "Docker container" ;;
        *) echo "web server" ;;
    esac
}

# Ports 80 and 443 (or SB_HTTPS_PORT) for Caddy. Sets MODE, or explains and asks, or stops before anything changed.
preflight() {
    case "$MODE" in local|proxy) return 0 ;; esac
    if ! command -v ss >/dev/null 2>&1; then
        say "Note: ss (iproute2) is missing, so ports 80 and $HTTPS_PORT were not checked."
        MODE=caddy
        return 0
    fi
    local o80 t80 o443 t443 oh th
    port_owner 80; o80=$OWNER t80=$OWNER_TEXT
    port_owner 443; o443=$OWNER t443=$OWNER_TEXT
    oh=$o443 th=$t443
    if [ "$HTTPS_PORT" != 443 ]; then
        port_owner "$HTTPS_PORT"; oh=$OWNER th=$OWNER_TEXT
    fi
    if ! busy "$o80" && ! busy "$oh"; then
        MODE=caddy
        caddy_consent
        return 0
    fi
    # The system's Caddy with sites of its own: SecretBroker's site can join them, if you agree.
    if [ "$HTTPS_PORT" = 443 ] && [[ "$o80" =~ ^(free|ours|caddy-system)$ && "$oh" =~ ^(free|ours|caddy-system)$ ]]; then
        say ""
        say "Ports 80 and 443 belong to this server's Caddy, which serves sites of its own ($CADDYFILE)."
        say "SecretBroker's site can join them: one line, import $CADDY_SITE, at the end of that file; your sites"
        say "stay as they are and Caddy gets the certificate for SecretBroker's domain too."
        if consent "Add SecretBroker's site to your Caddy?"; then
            MODE=caddy CADDY_SHARED=1
            return 0
        fi
    fi

    # Someone else has them: say who, and which ways work here.
    local proxy_owner=$o443 web rec_proxy=0 port_ok=0 n=0 keys=() default=1 choice example="SB_MODE=proxy"
    busy "$o443" || proxy_owner=$o80
    web=$(web_server_name "$proxy_owner")
    case "$proxy_owner" in nginx|apache|caddy|caddy-system|docker) rec_proxy=1 ;; esac
    busy "$o80" || port_ok=1
    say ""
    say "Ports for HTTPS are already in use on this server:"
    busy "$o80" && say "  - port 80:  $t80"
    busy "$o443" && say "  - port 443: $t443"
    if [ "$HTTPS_PORT" != 443 ] && busy "$oh"; then say "  - port $HTTPS_PORT: $th"; fi
    say "SecretBroker normally brings its own web server, Caddy, which needs port 80 (to get the HTTPS certificate)"
    say "and port $HTTPS_PORT (to serve it). This installer never stops or changes a program that is not its own;"
    say "SecretBroker can work alongside it instead, in one of these ways:"
    say ""
    n=$((n + 1)); keys+=(proxy)
    say "  $n) Behind your $web$([ "$rec_proxy" = 1 ] && echo " (recommended here)"): it keeps ports 80 and 443 and forwards your domain to"
    say "     SecretBroker, which listens on 127.0.0.1 only."
    case "$proxy_owner" in
        nginx) say "     The installer can add SecretBroker's site to nginx (one new file; it shows it and asks first)."
               say "     Without questions: SB_MODE=proxy SB_PROXY_CONFIGURE=1"
               example="SB_MODE=proxy SB_PROXY_CONFIGURE=1" ;;
        apache) say "     The installer prints the VirtualHost to add to Apache."
                say "     Without questions: SB_MODE=proxy" ;;
        *) say "     The installer prints what that proxy must forward."
           say "     Without questions: SB_MODE=proxy" ;;
    esac
    if [ "$port_ok" = 1 ]; then
        n=$((n + 1)); keys+=(port)
        [ "$rec_proxy" = 1 ] || { default=$n; example="SB_HTTPS_PORT=8443"; }
        say "  $n) Caddy on another HTTPS port$([ "$rec_proxy" = 1 ] || echo " (recommended here)"), such as 8443: the address becomes https://<domain>:8443."
        say "     Port 80 is free, so the certificate still works; the port must be open in your provider's firewall."
        say "     Without questions: SB_HTTPS_PORT=8443"
    fi
    n=$((n + 1)); keys+=(local)
    say "  $n) Through a tunnel (Cloudflare Tunnel or Tailscale): no ports at all; the installer says how."
    say "     Without questions: SB_MODE=local (the same as --local)"
    if [ "$port_ok" = 0 ]; then
        say ""
        say "  (Caddy on another HTTPS port is not possible here: the certificate is checked on port 80, which is in use.)"
    fi
    say ""
    if [ "$INTERACTIVE" != 1 ]; then
        die "ports 80/$HTTPS_PORT are in use (above). Nothing was installed or changed. Run the same command again with one of the ways above, for example: curl -fsSL $INSTALL_URL | sudo $example SB_DOMAIN=... SB_ADMIN_EMAIL=... bash"
    fi
    ask choice "Your choice [$default]:"
    choice=${choice:-$default}
    [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $n ] || die "no choice made: nothing was installed or changed."
    MODE=${keys[$((choice - 1))]}
    if [ "$MODE" = port ]; then
        local port
        ask port "HTTPS port [8443]:"
        port=${port:-8443}
        valid_port "$port" && [ "$port" != 80 ] && [ "$port" != 443 ] || die "$port is not a port Caddy can use for HTTPS."
        port_owner "$port"
        busy "$OWNER" && die "port $port is in use too ($OWNER_TEXT). Nothing was installed or changed."
        HTTPS_PORT=$port MODE=caddy
        caddy_consent
    fi
}

caddy_consent() {  # Caddy on this server already serving sites of its own (running or not): only with your yes
    local kind
    kind=$(caddy_config_kind)
    if [ "$kind" = theirs ] && [ "$CADDY_SHARED" != 1 ]; then
        say ""
        say "Caddy is installed here with sites of its own ($CADDYFILE). SecretBroker's site can join them (one line,"
        say "import $CADDY_SITE, at the end of that file); your sites stay as they are."
        consent "Add SecretBroker's site to your Caddy?" \
            || die "your Caddy was left as it is and nothing was installed. Say yes, or SB_PROXY_CONFIGURE=1, or choose another way: --behind-proxy, --local (see --help)."
        CADDY_SHARED=1
    fi
}

# SecretBroker's own port on 127.0.0.1 (SB_PORT): another one when it is taken, said so (and kept from then on).
check_internal_port() {
    local port=${CONF[SB_PORT]} candidate
    command -v ss >/dev/null 2>&1 || return 0
    port_owner "$port"
    busy "$OWNER" || return 0
    local text=$OWNER_TEXT
    [ -z "${SB_PORT:-}" ] || die "port $port (SB_PORT) is used by $text. Choose a free one, such as SB_PORT=$((port + 1)). Nothing was installed or changed."
    for candidate in $(seq $((port + 1)) $((port + 100))); do
        [ "$candidate" = "$HTTPS_PORT" ] && continue
        port_owner "$candidate"
        busy "$OWNER" || break
    done
    say "Port $port, where SecretBroker would listen on this machine (127.0.0.1 only), is used by $text."
    if [ "$INTERACTIVE" = 1 ]; then
        local answer
        ask answer "Use port $candidate instead? [Y/n, or another port number]"
        case "$answer" in
            ""|[Yy]*) ;;
            [Nn]*) die "nothing was installed or changed. Run it again with SB_PORT=<a free port>." ;;
            *) valid_port "$answer" || die "$answer is not a port number."
               port_owner "$answer"
               busy "$OWNER" && die "port $answer is in use too ($OWNER_TEXT)."
               candidate=$answer ;;
        esac
    fi
    say "SecretBroker listens on 127.0.0.1:$candidate (kept on the next runs)."
    CONF[SB_PORT]=$candidate
}

# ---------------------------------------------------------------------- pieces

check_system() {
    [ "$(id -u)" = 0 ] || die "run it as root: curl -fsSL $INSTALL_URL | sudo bash"
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

body_mb() {  # the largest request the web server in front lets through, in MB: SB_MAX_BODY (8 MiB) and some room
    local bytes=${CONF[SB_MAX_BODY]:-8388608}
    [[ "$bytes" =~ ^[0-9]+$ ]] || bytes=8388608
    echo $(( (bytes + 1048575) / 1048576 + 2 ))
}

# ---------------------------------------------------------------------- Caddy

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
    local address=${CONF[SB_DOMAIN]} tls=""
    if [ "$HTTPS_PORT" != 443 ]; then
        # The port in the site's address: Caddy serves it there and its redirect from port 80 says it. (Not the
        # global https_port: that one is for a port forwarded from 443, and its redirects leave the port out.)
        # Let's Encrypt checks on port 80 (HTTP-01); its TLS-ALPN check always comes to 443, which is someone else's.
        address="${CONF[SB_DOMAIN]}:$HTTPS_PORT"
        tls=$(printf '\ttls {\n\t\tissuer acme {\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}\n')
    fi
    {
        say "# SecretBroker Server, managed by install-server.sh (re-run it to change this). Caddy gets and renews the"
        say "# certificate by itself; only it is reachable from the internet, the server listens on 127.0.0.1."
        say "$address {"
        [ -z "$tls" ] || printf '%s\n' "$tls"
        cat <<EOF
	request_body {
		max_size $(body_mb)MB
	}
	reverse_proxy 127.0.0.1:${CONF[SB_PORT]}
	header -Server
}
EOF
    } > "$CADDY_SITE.new"
    chmod 644 "$CADDY_SITE.new"
    mv "$CADDY_SITE.new" "$CADDY_SITE"
    if ! grep -qs "^import $CADDY_SITE" "$CADDYFILE"; then
        if [ -f "$CADDYFILE" ] && [ ! -e "$CADDYFILE.orig" ]; then
            cp "$CADDYFILE" "$CADDYFILE.orig"
        fi
        if [ "$(caddy_config_kind)" = ours ]; then
            # Empty, or the package's own example (a page on :80): replaced.
            printf '# Managed by install-server.sh (SecretBroker Server).\nimport %s\n' "$CADDY_SITE" > "$CADDYFILE"
        else
            # Caddy's own sites stay; with your yes (asked before anything was installed) ours joins them.
            [ "$CADDY_SHARED" = 1 ] || die "$CADDYFILE has sites of its own; SecretBroker's site was not added (see --help)."
            printf '\n# SecretBroker Server (install-server.sh)\nimport %s\n' "$CADDY_SITE" >> "$CADDYFILE"
        fi
    fi
    caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 \
        || { caddy validate --config "$CADDYFILE" --adapter caddyfile || true; die "Caddy does not accept $CADDYFILE (above)."; }
    systemctl enable --quiet caddy
    if systemctl is-active --quiet caddy; then systemctl reload caddy || systemctl restart caddy; else systemctl restart caddy; fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 80/tcp >/dev/null && ufw allow "$HTTPS_PORT/tcp" >/dev/null && ufw allow "$HTTPS_PORT/udp" >/dev/null
        say "Firewall (ufw): ports 80 and $HTTPS_PORT open."
    fi
}

remove_caddy_site() {  # SecretBroker's Caddy site and its import line; Caddy itself stays (stopped if it served only us)
    [ -f "$CADDY_SITE" ] || return 0
    rm -f "$CADDY_SITE"
    sed -i "\#^import $CADDY_SITE\$#d; /^# SecretBroker Server (install-server.sh)\$/d; /^# Managed by install-server.sh/d" "$CADDYFILE" 2>/dev/null || true
    if [ -z "$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$CADDYFILE" 2>/dev/null | tr -d '\n')" ]; then
        systemctl disable --now --quiet caddy 2>/dev/null || true
        say "Caddy: SecretBroker's site removed. It served nothing else, so it is stopped (still installed)."
    else
        systemctl reload caddy 2>/dev/null || true
        say "Caddy: SecretBroker's site removed; your other sites stay."
    fi
}

# ---------------------------------------------------------------------- behind your web server

proxy_kind() {  # PROXY_KIND: nginx, apache or other: whoever has port 443 (or 80), or the one installed
    local port
    for port in "$HTTPS_PORT" 80; do
        port_owner "$port"
        case "$OWNER" in
            nginx|apache) PROXY_KIND=$OWNER; return 0 ;;
            free|ours) ;;
            *) PROXY_KIND=other PROXY_TEXT=$OWNER_TEXT; return 0 ;;
        esac
    done
    if [ -n "${CONF[SB_PROXY_SITE]:-}" ] || command -v nginx >/dev/null 2>&1; then PROXY_KIND=nginx
    elif command -v apache2 >/dev/null 2>&1; then PROXY_KIND=apache
    else PROXY_KIND=other
    fi
}

tls_files() {  # sets CERT and KEY: SB_TLS_CERT/SB_TLS_KEY, or certbot's certificate for the domain
    local live="/etc/letsencrypt/live/${CONF[SB_DOMAIN]}"
    CERT="" KEY=""
    if [ -n "${CONF[SB_TLS_CERT]:-}" ]; then
        [ -r "${CONF[SB_TLS_CERT]}" ] && [ -r "${CONF[SB_TLS_KEY]:-}" ] \
            || die "SB_TLS_CERT and SB_TLS_KEY must both be readable files (${CONF[SB_TLS_CERT]}, ${CONF[SB_TLS_KEY]:-})."
        CERT=${CONF[SB_TLS_CERT]} KEY=${CONF[SB_TLS_KEY]}
    elif [ -f "$live/fullchain.pem" ] && [ -f "$live/privkey.pem" ]; then
        CERT=$live/fullchain.pem KEY=$live/privkey.pem
    fi
}

https_suffix() {  # ":8443", or nothing for 443
    [ "$HTTPS_PORT" = 443 ] || printf ':%s' "$HTTPS_PORT"
}

nginx_proxy_lines() {  # the location that forwards to SecretBroker (tab-indented, for a server block)
    cat <<EOF
	client_max_body_size $(body_mb)m;
	location / {
		proxy_pass http://127.0.0.1:${CONF[SB_PORT]};
		proxy_http_version 1.1;
		proxy_set_header Connection "";
		proxy_set_header Host \$host;
		# SecretBroker takes the client's address from the last X-Forwarded-For entry: set it to nginx's own view.
		proxy_set_header X-Forwarded-For \$remote_addr;
		proxy_set_header X-Forwarded-Proto https;
		proxy_buffering off;
		proxy_read_timeout 120s;
	}
EOF
}

nginx_site() {  # the whole site file, with HTTPS when CERT/KEY are known
    local d=${CONF[SB_DOMAIN]} v6=0
    # (grep without -q: it reads all of nginx -T's output, so pipefail does not see nginx cut short)
    if nginx -T 2>/dev/null | grep -E '^[[:space:]]*listen[[:space:]]+\[::\]' >/dev/null; then v6=1; fi
    cat <<EOF
# SecretBroker Server for $d, $NGINX_MARK (running it again rewrites this file; --uninstall
# removes it). Only this file is SecretBroker's: nothing else in nginx was changed.
server {
	listen 80;
$([ "$v6" = 1 ] && printf '\tlisten [::]:80;')
	server_name $d;
	# For certbot (--webroot), when it gets or renews the certificate.
	location /.well-known/acme-challenge/ {
		root $ACME_ROOT;
	}
EOF
    if [ -n "$CERT" ]; then
        cat <<EOF
	location / {
		return 301 https://\$host$(https_suffix)\$request_uri;
	}
}

server {
	listen $HTTPS_PORT ssl;
$([ "$v6" = 1 ] && printf '\tlisten [::]:%s ssl;' "$HTTPS_PORT")
	server_name $d;
	ssl_certificate $CERT;
	ssl_certificate_key $KEY;
$(nginx_proxy_lines)
}
EOF
    else
        cat <<EOF
	# No certificate for $d yet: only the health check gets through (the apps talk HTTPS only).
	location = /api/v1/health {
		proxy_pass http://127.0.0.1:${CONF[SB_PORT]};
		proxy_set_header Host \$host;
		proxy_set_header X-Forwarded-For \$remote_addr;
	}
	location / {
		default_type text/plain;
		return 503 "SecretBroker: $d has no HTTPS certificate yet.\n";
	}
}
EOF
    fi
}

nginx_paths() {  # sets NGINX_FILE and NGINX_LINK (empty without sites-enabled)
    local d=${CONF[SB_DOMAIN]}
    if [ -d /etc/nginx/sites-available ] && [ -d /etc/nginx/sites-enabled ]; then
        NGINX_FILE=/etc/nginx/sites-available/secretbroker-$d NGINX_LINK=/etc/nginx/sites-enabled/secretbroker-$d
    else
        NGINX_FILE=/etc/nginx/conf.d/secretbroker-$d.conf NGINX_LINK=""
    fi
}

nginx_other_site() {  # prints the file of another site that already answers for the domain, if any
    nginx -T 2>/dev/null | awk -v d="${CONF[SB_DOMAIN]}" -v a="$NGINX_FILE" -v b="$NGINX_LINK" '
        /^# configuration file / { f = $4; sub(/:$/, "", f); next }
        f != a && f != b && $1 == "server_name" {
            for (i = 2; i <= NF; i++) { n = $i; sub(/;$/, "", n); if (n == d && !found) { print f; found = 1 } }
        }' || true
}

print_nginx_manual() {
    say "nginx was not changed. To put SecretBroker behind it, run this (it is exactly what the installer would do):"
    say ""
    say "sudo tee $NGINX_FILE > /dev/null <<'EOF'"
    printf '%s\n' "$1"
    say "EOF"
    [ -z "$NGINX_LINK" ] || say "sudo ln -sfn $NGINX_FILE $NGINX_LINK"
    say "sudo nginx -t && sudo systemctl reload nginx"
    say ""
    say "(or run this installer again with SB_PROXY_CONFIGURE=1 and it does that itself.)"
}

write_nginx_site() {  # TEXT: write, enable, nginx -t (or back as it was), reload
    local backup=""
    install -d -m 0755 "$ACME_ROOT" "$(dirname "$NGINX_FILE")"
    if [ -f "$NGINX_FILE" ]; then backup=$(mktemp); cp -p "$NGINX_FILE" "$backup"; fi
    printf '%s\n' "$1" > "$NGINX_FILE.new"
    chmod 644 "$NGINX_FILE.new"
    mv "$NGINX_FILE.new" "$NGINX_FILE"
    [ -z "$NGINX_LINK" ] || ln -sfn "$NGINX_FILE" "$NGINX_LINK"
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t || true
        if [ -n "$backup" ]; then mv "$backup" "$NGINX_FILE"; else rm -f "$NGINX_FILE"; [ -z "$NGINX_LINK" ] || rm -f "$NGINX_LINK"; fi
        die "nginx does not accept SecretBroker's site (above), so it was taken out again and nginx was not reloaded: it runs as before. The server itself is installed; run this again once that is fixed."
    fi
    rm -f "$backup"
    CONF[SB_PROXY_SITE]=$NGINX_FILE
    write_conf
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        say "nginx: SecretBroker's site is in $NGINX_FILE (checked with nginx -t, nginx reloaded)."
    else
        say "nginx: SecretBroker's site is in $NGINX_FILE (checked with nginx -t). nginx is not running: sudo systemctl start nginx"
    fi
}

remove_nginx_site() {  # FILE: SecretBroker's nginx site (only if it still carries our mark) and its link
    local file=${1:-}
    [ -n "$file" ] && [ -f "$file" ] || return 0
    case "$(head -1 "$file")" in
        *"$NGINX_MARK"*) ;;
        *) say "Note: $file is no longer the installer's own, so it stays as it is."; return 0 ;;
    esac
    rm -f "/etc/nginx/sites-enabled/$(basename "$file")" "$file"
    if systemctl is-active --quiet nginx && nginx -t >/dev/null 2>&1; then systemctl reload nginx; fi
    say "nginx: SecretBroker's site ($file) removed; the rest of nginx is as it was."
}

get_certificate() {  # certbot, through the site's /.well-known/acme-challenge/: only with your yes
    local d=${CONF[SB_DOMAIN]}
    if ! command -v certbot >/dev/null 2>&1; then
        CERT_NOTE="certbot is not installed. Install it (sudo apt install certbot) and run this installer again: it gets a free certificate for $d (Let's Encrypt) and renews it. Or give your own: SB_TLS_CERT=/path/fullchain.pem SB_TLS_KEY=/path/privkey.pem"
        return 1
    fi
    if ! consent "Get a free HTTPS certificate for $d from Let's Encrypt with certbot (you accept Let's Encrypt's terms)?"; then
        CERT_NOTE="No certificate was requested. Run this again with SB_PROXY_CONFIGURE=1 for certbot to get one, or give your own: SB_TLS_CERT=/path/fullchain.pem SB_TLS_KEY=/path/privkey.pem"
        return 1
    fi
    say "certbot: asking Let's Encrypt for a certificate for $d"
    if ! certbot certonly --webroot -w "$ACME_ROOT" -d "$d" --non-interactive --agree-tos -m "$ADMIN" \
            --deploy-hook "systemctl reload nginx" --keep-until-expiring; then
        CERT_NOTE="certbot could not get a certificate for $d (above). Check that its DNS A record points at this server's public IP and that port 80 is open in your provider's firewall, then run this again."
        return 1
    fi
}

setup_nginx() {
    nginx_paths
    local old=${CONF[SB_PROXY_SITE]:-} other text
    if [ -n "$old" ] && [ "$old" != "$NGINX_FILE" ]; then
        remove_nginx_site "$old"
        unset 'CONF[SB_PROXY_SITE]'
    fi
    other=$(nginx_other_site)
    if [ -n "$other" ]; then
        say "nginx already has a site for ${CONF[SB_DOMAIN]}, in $other. This installer leaves it as it is: in its HTTPS"
        say "server block, forward to SecretBroker like this, then: sudo nginx -t && sudo systemctl reload nginx"
        say ""
        nginx_proxy_lines
        PROXY_STATE=manual
        return 0
    fi
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t || true
        say "nginx's configuration has an error already (above), not from SecretBroker: nginx was not changed."
        PROXY_STATE=manual
        return 0
    fi
    tls_files
    text=$(nginx_site)
    # Once added with your yes, the file is SecretBroker's own: later runs keep it up to date without asking again.
    local ours=0
    if [ "${CONF[SB_PROXY_SITE]:-}" = "$NGINX_FILE" ] && [ -f "$NGINX_FILE" ]; then
        case "$(head -1 "$NGINX_FILE")" in *"$NGINX_MARK"*) ours=1 ;; esac
    fi
    if [ "${SB_PROXY_CONFIGURE:-}" != 1 ] && [ "$ours" != 1 ]; then
        if [ "$INTERACTIVE" = 1 ]; then
            say "SecretBroker's site for nginx, a new file ($NGINX_FILE); nothing else in nginx changes:"
            say ""
            printf '%s\n' "$text" | sed 's/^/    /'
            say ""
        fi
        if ! ask_yes "Add it, check nginx with nginx -t and reload it?"; then
            print_nginx_manual "$text"
            PROXY_STATE=manual
            return 0
        fi
    fi
    write_nginx_site "$text"
    if [ -z "$CERT" ]; then
        if get_certificate; then
            tls_files
            write_nginx_site "$(nginx_site)"
        fi
    fi
    PROXY_STATE=$([ -n "$CERT" ] && echo https || echo http)
}

print_apache() {
    local d=${CONF[SB_DOMAIN]} p=${CONF[SB_PORT]} name
    name=secretbroker-$d
    tls_files
    say "Apache has ports 80/443 here and this installer does not change it. To put SecretBroker behind it, run:"
    say ""
    say "sudo a2enmod proxy proxy_http headers ssl"
    say "sudo tee /etc/apache2/sites-available/$name.conf > /dev/null <<'EOF'"
    if [ -n "$CERT" ]; then
        cat <<EOF
<VirtualHost *:80>
    ServerName $d
    Redirect permanent / https://$d$(https_suffix)/
</VirtualHost>
<VirtualHost *:$HTTPS_PORT>
    ServerName $d
    SSLEngine on
    SSLCertificateFile $CERT
    SSLCertificateKeyFile $KEY
EOF
    else
        cat <<EOF
<VirtualHost *:80>
    ServerName $d
EOF
    fi
    cat <<EOF
    # SecretBroker on 127.0.0.1 (Apache adds X-Forwarded-For with the client's address itself).
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:$p/
    ProxyPassReverse / http://127.0.0.1:$p/
    RequestHeader set X-Forwarded-Proto "https"
    LimitRequestBody $(( $(body_mb) * 1048576 ))
    ProxyTimeout 120
</VirtualHost>
EOF
    say "EOF"
    say "sudo a2ensite $name && sudo apachectl configtest && sudo systemctl reload apache2"
    if [ -z "$CERT" ]; then
        say "sudo apt install certbot python3-certbot-apache && sudo certbot --apache -d $d"
        say "(certbot gets the certificate, adds HTTPS to that site and redirects plain HTTP to it: run it right away.)"
    fi
}

print_generic() {
    local d=${CONF[SB_DOMAIN]} p=${CONF[SB_PORT]}
    say "Port $HTTPS_PORT here belongs to ${PROXY_TEXT:-a web server this installer does not set up}."
    say "Make it forward SecretBroker's domain, without changing anything else:"
    say "  - https://$d$(https_suffix) (its certificate is that web server's job) to http://127.0.0.1:$p"
    say "  - keep the Host header, and set X-Forwarded-For to the client's address: SecretBroker takes the last"
    say "    entry as the client's address (most proxies add it by themselves)"
    say "  - let requests up to $(body_mb) MB through"
    say "  - a proxy inside a Docker container reaches 127.0.0.1 of this machine only with network_mode: host;"
    say "    without it, use a tunnel instead (--local)"
    say "  Another Caddy, in its Caddyfile:   $d$(https_suffix) { reverse_proxy 127.0.0.1:$p }"
    say "  Traefik: a router for Host(\`$d\`) with TLS, to the service url http://127.0.0.1:$p"
}

# ---------------------------------------------------------------------- the rest

check_public() {  # [tries]
    local url=${CONF[SB_PUBLIC_URL]} tries=${1:-20}
    for _ in $(seq "$tries"); do
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
    load_conf
    step "Removing SecretBroker Server"
    systemctl disable --now "${UNITS[@]}" 2>/dev/null || true
    for unit in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$unit"; done
    systemctl daemon-reload
    rm -rf "$ROOT" "$WRAPPER"
    remove_caddy_site
    remove_nginx_site "${CONF[SB_PROXY_SITE]:-}"
    if [ "$PURGE" = 1 ]; then
        rm -rf "$DATA" "$UPDATER_STATE" "$ETC" "$ACME_ROOT"
        userdel "$ACCOUNT" 2>/dev/null || true
        say "Removed, with its data, backups and settings."
    else
        say "Removed. The data and backups stay in $DATA and the settings in $ETC"
        say "(run with --uninstall --purge to delete them too)."
    fi
}

mode_label() {
    case "$MODE" in
        caddy) printf 'Caddy, HTTPS on port %s' "$HTTPS_PORT" ;;
        proxy) printf 'behind your web server' ;;
        local) printf 'local, for a tunnel' ;;
    esac
}

print_tunnel_steps() {
    local p=${CONF[SB_PORT]}
    say "  Local mode: the server answers on http://127.0.0.1:$p, only on this machine. To reach it from your"
    say "  team's PCs, put a tunnel in front of it (no open ports needed), then run this again with"
    say "  SB_DOMAIN=<the tunnel's public name> so the server knows its address:"
    say ""
    say "  Cloudflare Tunnel (free, with a domain on Cloudflare; TLS ends at Cloudflare, see server/README.md):"
    say "    1. Cloudflare dashboard › Zero Trust › Networks › Tunnels › Create a tunnel (Cloudflared), named secretbroker."
    say "    2. Run on this server the install command it shows: sudo cloudflared service install <token>"
    say "       (Debian/Ubuntu: it first shows how to add its repository and install cloudflared)."
    say "    3. Public hostname: secrets.example.com, service type HTTP, URL 127.0.0.1:$p."
    say ""
    say "  Tailscale (TLS ends on this server; turn on MagicDNS and HTTPS certificates in its admin console):"
    say "    curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up"
    say "    sudo tailscale serve --bg $p     # https://<this machine>.<tailnet>.ts.net, for your tailnet only"
    say "    sudo tailscale funnel --bg $p    # or: the same address, public on the internet"
    say "    (sudo tailscale serve status shows the address to give as SB_DOMAIN.)"
}

# ---------------------------------------------------------------------- main

main() {
    MODE="" LOCAL_ARTIFACT=${SB_ARTIFACT:-} UNINSTALL=0 PURGE=0 REINSTALL=0 PUBLIC_OK=0 HTTPS_PORT_ARG=""
    CADDY_SHARED=0 PROXY_STATE="" PROXY_KIND="" PROXY_TEXT="" CERT_NOTE="" CERT="" KEY=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --local) MODE=local ;;
            --caddy) MODE=caddy ;;
            --behind-proxy|--proxy) MODE=proxy ;;
            --https-port) HTTPS_PORT_ARG=${2:?--https-port needs a port number}; shift ;;
            --https-port=*) HTTPS_PORT_ARG=${1#*=} ;;
            --artifact) LOCAL_ARTIFACT=${2:?--artifact needs a file}; shift ;;
            --artifact=*) LOCAL_ARTIFACT=${1#*=} ;;
            --reinstall) REINSTALL=1 ;;
            --uninstall) UNINSTALL=1 ;;
            --purge) PURGE=1 ;;
            -h|--help) sed -n '2,/^set -euo pipefail$/p' "$0" 2>/dev/null | sed '$d' || true; exit 0 ;;
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
    local fresh=1 previous=${CONF[SB_INSTALL_MODE]:-}
    [ -f "$ENV_FILE" ] && fresh=0
    if [ -z "$MODE" ] && [ -n "${SB_MODE:-}" ]; then
        case "$SB_MODE" in caddy|proxy|local) MODE=$SB_MODE ;; *) die "SB_MODE must be caddy, proxy or local." ;; esac
    fi
    HTTPS_PORT=${HTTPS_PORT_ARG:-${SB_HTTPS_PORT:-}}
    # A new HTTPS port asks for Caddy, unless a mode says otherwise; without one, the mode and port of last time.
    if [ -n "$HTTPS_PORT" ] && [ "$HTTPS_PORT" != 443 ] && [ -z "$MODE" ] && [ "$previous" != proxy ]; then MODE=caddy; fi
    MODE=${MODE:-$previous}
    HTTPS_PORT=${HTTPS_PORT:-${CONF[SB_HTTPS_PORT]:-443}}
    [ "$MODE" != local ] || HTTPS_PORT=443
    valid_port "$HTTPS_PORT" && [ "$HTTPS_PORT" != 80 ] || die "SB_HTTPS_PORT must be a port number other than 80."

    preflight   # before anything changes: may ask, or stop with what is using the ports
    MODE=${MODE:-caddy}

    step "SecretBroker Server: $([ "$fresh" = 1 ] && echo installing || echo "repairing and upgrading") ($(mode_label))"
    local domain=${SB_DOMAIN:-} email=${SB_ADMIN_EMAIL:-}
    if [ -z "$domain" ] && [ -z "${CONF[SB_DOMAIN]:-}" ] && [ "$MODE" != local ]; then
        if [ "$MODE" = proxy ]; then
            say "The server needs a name on the internet, for example secrets.example.com, whose DNS A record points"
            say "at this server's IP address: your web server will answer for it and forward it to SecretBroker."
        else
            say "The server needs a name on the internet, for example secrets.example.com, whose DNS A record points"
            say "at this server's IP address, with ports 80 and $HTTPS_PORT open (Caddy gets the HTTPS certificate for it)."
        fi
        ask domain "Domain name:"
        [ -n "$domain" ] || die "a domain name is needed (or SB_DOMAIN=... on the command line; --local for none)."
    fi
    domain=${domain#https://}
    domain=${domain%%/*}
    domain=${domain%%:*}
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
    if [ "$HTTPS_PORT" = 443 ]; then unset 'CONF[SB_HTTPS_PORT]'; else CONF[SB_HTTPS_PORT]=$HTTPS_PORT; fi
    if [ -n "$email" ]; then
        case ",${CONF[SB_ADMIN_EMAILS]:-}," in
            *",$email,"*) ;;
            ,,) CONF[SB_ADMIN_EMAILS]=$email ;;
            *) CONF[SB_ADMIN_EMAILS]="${CONF[SB_ADMIN_EMAILS]},$email" ;;
        esac
    fi
    set_conf SB_PORT "${SB_PORT:-${CONF[SB_PORT]:-8080}}"
    [[ "${CONF[SB_PORT]}" =~ ^[0-9]{2,5}$ ]] && valid_port "${CONF[SB_PORT]}" || die "SB_PORT must be a port number."
    [ "${CONF[SB_PORT]}" != "$HTTPS_PORT" ] && [ "${CONF[SB_PORT]}" != 80 ] \
        || die "SB_PORT (${CONF[SB_PORT]}) is SecretBroker's own port on 127.0.0.1: it can't be 80 or the HTTPS port."
    set_conf SB_SIGNUPS "${SB_SIGNUPS:-${CONF[SB_SIGNUPS]:-invite}}"
    # Only Caddy, your web server or the tunnel reach 127.0.0.1, so the last X-Forwarded-For entry (the one it
    # added) is the client's address.
    set_conf SB_TRUST_PROXY 1
    set_conf SB_BACKUP_KEEP "${SB_BACKUP_KEEP:-${CONF[SB_BACKUP_KEEP]:-14}}"
    set_conf SB_AUTO_UPDATE "${SB_AUTO_UPDATE:-${CONF[SB_AUTO_UPDATE]:-1}}"
    local var
    for var in SB_SERVER_NAME SB_EMAIL_VERIFICATION SB_SMTP_HOST SB_SMTP_PORT SB_SMTP_SECURITY SB_SMTP_USER \
               SB_SMTP_PASSWORD SB_SMTP_FROM SB_UPDATE_SOURCE SB_UPDATE_TRUST SB_MIN_CLIENT SB_MAX_BODY \
               SB_TLS_CERT SB_TLS_KEY; do
        set_conf "$var" "${!var:-}"
    done
    if [ -n "${CONF[SB_DOMAIN]:-}" ]; then
        CONF[SB_PUBLIC_URL]="https://${CONF[SB_DOMAIN]}$(https_suffix)"
        unset 'CONF[SB_ALLOW_HTTP]'
    else
        [ "$MODE" = local ] || die "a domain name is needed without --local."
        CONF[SB_PUBLIC_URL]="http://127.0.0.1:${CONF[SB_PORT]}"
        CONF[SB_ALLOW_HTTP]=1
    fi
    check_internal_port
    [ -n "${CONF[SB_DOMAIN]:-}" ] || CONF[SB_PUBLIC_URL]="http://127.0.0.1:${CONF[SB_PORT]}"
    ADMIN=${email:-${CONF[SB_ADMIN_EMAILS]%%,*}}

    step "Programs"
    apt_install ca-certificates curl openssl tar util-linux iproute2
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
    # What another mode set up and is SecretBroker's own goes; nothing else.
    [ "$MODE" = caddy ] || remove_caddy_site
    if [ "$MODE" != proxy ] && [ -n "${CONF[SB_PROXY_SITE]:-}" ]; then
        remove_nginx_site "${CONF[SB_PROXY_SITE]}"
        unset 'CONF[SB_PROXY_SITE]'
        write_conf
    fi
    case "$MODE" in
        caddy)
            setup_caddy
            step "Checking ${CONF[SB_PUBLIC_URL]} from here"
            check_public
            ;;
        proxy)
            proxy_kind
            step "Behind your web server ($PROXY_KIND)"
            case "$PROXY_KIND" in
                nginx) setup_nginx ;;
                apache) print_apache; PROXY_STATE=manual ;;
                *) print_generic; PROXY_STATE=manual ;;
            esac
            if [ "$PROXY_STATE" = https ]; then
                step "Checking ${CONF[SB_PUBLIC_URL]} from here"
                check_public 5
            fi
            ;;
        local)
            [ -z "${CONF[SB_DOMAIN]:-}" ] || check_public 3
            ;;
    esac
    flock -u 9

    local token=""
    token=$(admin_token "$ADMIN" || true)
    local url=${CONF[SB_PUBLIC_URL]} version
    version=$(current_version)

    step "Done: SecretBroker Server $version"
    say "  Address:  $url"
    case "$MODE" in
        caddy)
            if [ "$PUBLIC_OK" != 1 ]; then
                say ""
                say "  Not reachable from the internet yet. Caddy keeps trying to get the certificate by itself; check that:"
                say "    - the DNS A record of ${CONF[SB_DOMAIN]} points at this server's public IP address (your"
                say "      provider's panel shows it);"
                say "    - ports 80 and $HTTPS_PORT are open in your provider's firewall (the cloud panel, not only this server)."
                say "  Then it works without running anything again (sudo journalctl -u caddy shows its progress)."
            fi
            ;;
        proxy)
            say ""
            case "$PROXY_STATE" in
                https)
                    if [ "$PUBLIC_OK" = 1 ]; then
                        say "  nginx forwards it to SecretBroker over HTTPS (checked from here)."
                    else
                        say "  nginx forwards it to SecretBroker over HTTPS, but it does not answer from here yet: check that the"
                        say "  DNS A record of ${CONF[SB_DOMAIN]} points at this server and port $HTTPS_PORT is open in your provider's firewall."
                    fi ;;
                http)
                    say "  nginx answers for ${CONF[SB_DOMAIN]}, but without a certificate yet, so the apps can't connect."
                    [ -z "$CERT_NOTE" ] || say "  $CERT_NOTE" ;;
                *)
                    say "  SecretBroker waits on 127.0.0.1:${CONF[SB_PORT]} for your web server (above). Then check from any PC:"
                    say "  curl $url/api/v1/health    -> {\"status\":\"ok\"}" ;;
            esac
            ;;
        local)
            if [ -z "${CONF[SB_DOMAIN]:-}" ]; then
                print_tunnel_steps
            elif [ "$PUBLIC_OK" != 1 ]; then
                say "  The tunnel does not answer for ${CONF[SB_DOMAIN]} yet. Point it at http://127.0.0.1:${CONF[SB_PORT]}:"
                say ""
                print_tunnel_steps
            fi
            ;;
    esac
    say ""
    say "Next, in the SecretBroker desktop app on your PC:"
    say "  1. Equipo › Crear cuenta."
    say "  2. Servidor: $url"
    if [ -n "$token" ]; then
        say "  3. E-mail: $ADMIN"
        say "  4. Código de invitación: $token"
        say "     (valid 14 days, once, only for $ADMIN: it makes you this server's administrator)"
        say "     Or paste this link in «Servidor» and it fills in the rest:"
        say "     secretbroker://join?server=$url&email=${ADMIN//+/%2B}&code=$token"
    else
        say "  3. Sign in («Entrar») with $ADMIN: that account already exists and is the administrator."
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
