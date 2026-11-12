#!/usr/bin/env bash
# Builds dist/secretbroker-server-<version>-linux-x86_64.tar.gz: the whole server for install-server.sh and the
# signed automatic updates (server/secretbroker_server/updater.py).
#
# Self-contained, like the desktop .deb (tools/build_deb.sh): a standalone CPython (python-build-standalone) with
# the server and its dependencies installed into it. Ubuntu 22.04's python3 is 3.10 and the server needs 3.11+, and
# a bundled interpreter means installing or updating never runs pip or reaches PyPI on the server: everything that
# runs there is inside this one signed file. The interpreter is relocatable (no venv paths to fix), so the archive
# unpacks anywhere: /opt/secretbroker-server/versions/<version>/.
#
#   VERSION                       the version (the updater checks it matches the signed one)
#   python/                       CPython + secretbroker_server, starlette, uvicorn, cryptography
#   systemd/                      the units (the updater installs them when they change)
#   bin/secretbroker-server       the root wrapper (sudo secretbroker-server <command>)
#   install-server.sh             the installer, for repairs without downloading it again
#
# Run on Linux (or WSL) from anywhere:  tools/build_server.sh
# Needs: bash, curl, tar, sha256sum, binutils (strip).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(tr -d '\r' < "$REPO/pyproject.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1)
SERVER_VERSION=$(tr -d '\r' < "$REPO/server/secretbroker_server/__init__.py" | sed -n 's/^__version__ = "\(.*\)"$/\1/p')
ARCH=x86_64
PYTHON_RELEASE=20241016
PYTHON_VERSION=3.12.7
PYTHON_TARBALL="cpython-${PYTHON_VERSION}+${PYTHON_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_RELEASE}/${PYTHON_TARBALL}"
PYTHON_SHA256=43576f7db1033dd57b900307f09c2e86f371152ac8a2607133afa51cbfc36064
BUILD_DIR=${BUILD_DIR:-${TMPDIR:-/tmp}/secretbroker-server-build}
CACHE_DIR=${CACHE_DIR:-$HOME/.cache/secretbroker-build}
OUT_DIR=${OUT_DIR:-$REPO/dist}
STAGE="$BUILD_DIR/stage"
OUT="$OUT_DIR/secretbroker-server-${VERSION}-linux-${ARCH}.tar.gz"

step() { printf '\n==> %s\n' "$*"; }
# Only the bundled interpreter's own packages: never the builder's ~/.local ones.
export PYTHONNOUSERSITE=1

if [ "$VERSION" != "$SERVER_VERSION" ]; then
    echo "pyproject.toml says $VERSION but secretbroker_server.__version__ says $SERVER_VERSION" >&2
    exit 1
fi
step "SecretBroker Server $VERSION -> $OUT"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$CACHE_DIR" "$OUT_DIR"

step "Python $PYTHON_VERSION (python-build-standalone $PYTHON_RELEASE)"
if [ ! -f "$CACHE_DIR/$PYTHON_TARBALL" ]; then
    curl -fsSL -o "$CACHE_DIR/$PYTHON_TARBALL.part" "$PYTHON_URL"
    mv "$CACHE_DIR/$PYTHON_TARBALL.part" "$CACHE_DIR/$PYTHON_TARBALL"
fi
echo "$PYTHON_SHA256  $CACHE_DIR/$PYTHON_TARBALL" | sha256sum -c --quiet -
tar -xzf "$CACHE_DIR/$PYTHON_TARBALL" -C "$STAGE"   # -> $STAGE/python
PY="$STAGE/python/bin/python3"

step "The server and its dependencies"
SRC="$BUILD_DIR/src"
rm -rf "$SRC" && mkdir -p "$SRC"
tar -C "$REPO/server" --exclude=tests --exclude='__pycache__' --exclude='*.egg-info' --exclude=build \
    -cf - pyproject.toml secretbroker_server | tar -C "$SRC" -xf -
# Every package from the hash-pinned locks (requirements/, tools/update_locks.py): server.txt (the server's
# dependencies) and sign.txt (cryptography alone, for the updater's signature checks). The build backend is locked
# too and the build runs without isolation, so pip never fetches anything unpinned.
PIP=("$PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir --no-warn-script-location)
"${PIP[@]}" --require-hashes --no-deps -r "$REPO/requirements/build.txt"
"${PIP[@]}" --require-hashes --no-deps --only-binary :all: -r "$REPO/requirements/server.txt" -r "$REPO/requirements/sign.txt"
"${PIP[@]}" --no-deps --no-build-isolation --no-index "$SRC"
"$PY" -m pip check
"$PY" -m pip uninstall --quiet --disable-pip-version-check -y setuptools

step "Leaving out what is never used"
rm -rf "$STAGE"/python/lib/python3.*/{test,idlelib,tkinter,turtledemo,lib2to3,ensurepip} \
       "$STAGE"/python/lib/python3.*/config-* "$STAGE"/python/lib/{tcl,tk,itcl,thread}* "$STAGE"/python/lib/Tix* \
       "$STAGE"/python/share "$STAGE"/python/include "$STAGE"/python/lib/pkgconfig \
       "$STAGE"/python/lib/python3.*/site-packages/pip* "$STAGE"/python/bin/pip* "$STAGE"/python/bin/idle* \
       "$STAGE"/python/bin/pydoc* "$STAGE"/python/bin/2to3* "$STAGE"/python/bin/*-config \
       "$STAGE"/python/bin/secretbroker-server "$STAGE"/python/bin/uvicorn
strip --strip-unneeded "$STAGE"/python/lib/libpython3*.so.* "$STAGE"/python/bin/python3.* 2>/dev/null || true
find "$STAGE/python" -name '__pycache__' -type d -prune -exec rm -rf {} +
# Compiled now: /opt is read-only for the service. unchecked-hash: valid whatever the files' times become.
"$PY" -m compileall -q -j 0 --invalidation-mode unchecked-hash -s "$STAGE" -p /opt/secretbroker-server/current \
    "$STAGE/python/lib" >/dev/null || true
"$PY" -I -c "import secretbroker_server.web, secretbroker_server.admin_api, secretbroker_server.updater, cryptography.hazmat.primitives.asymmetric.ed25519, uvicorn; print('imports ok')"

step "Units, wrapper, installer"
install -d "$STAGE/systemd" "$STAGE/bin"
install -m 0644 "$REPO"/server/packaging/systemd/* "$STAGE/systemd/"
install -m 0755 "$REPO/server/packaging/secretbroker-server" "$STAGE/bin/"
install -m 0755 "$REPO/server/install-server.sh" "$STAGE/"
# A Windows checkout may have CRLF lines.
sed -i 's/\r$//' "$STAGE"/systemd/* "$STAGE/bin/secretbroker-server" "$STAGE/install-server.sh"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"

step "Archive"
find "$STAGE" -type d -exec chmod 0755 {} +
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${SOURCE_DATE_EPOCH:-$(date +%s)}" \
    -C "$STAGE" -czf "$OUT.part" .
mv "$OUT.part" "$OUT"
ls -lh "$OUT"
