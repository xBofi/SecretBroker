#!/usr/bin/env bash
# Builds dist/secretbroker_<version>_amd64.deb for Ubuntu 22.04 and 24.04 (and other x86-64 Debian-based systems).
#
# The package is self-contained: a standalone CPython (python-build-standalone) in /opt/secretbroker/python and
# SecretBroker with its dependencies in its own venv, /opt/secretbroker/venv (Ubuntu 22.04's Python is 3.10;
# SecretBroker needs 3.11+). Installing it is a double click in the software installer; postinst creates the
# `secretbroker` user and starts secretbroker@<user>.service for each desktop account.
#
# Run on Linux (or WSL) from anywhere:  tools/build_deb.sh
# Needs: bash, curl, tar, dpkg-deb, sha256sum, binutils (strip, readelf) and the libraries in Depends below
# (the build renders a page with the bundled Qt to check it). The work happens in a Linux folder ($BUILD_DIR), because
# dpkg-deb needs real Unix permissions (a Windows drive mounted in WSL does not have them).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)
ARCH=amd64
PYTHON_RELEASE=20241016
PYTHON_VERSION=3.12.7
PYTHON_TARBALL="cpython-${PYTHON_VERSION}+${PYTHON_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_RELEASE}/${PYTHON_TARBALL}"
PYTHON_SHA256=43576f7db1033dd57b900307f09c2e86f371152ac8a2607133afa51cbfc36064
BUILD_DIR=${BUILD_DIR:-${TMPDIR:-/tmp}/secretbroker-deb}
CACHE_DIR=${CACHE_DIR:-$HOME/.cache/secretbroker-build}
OUT_DIR=${OUT_DIR:-$REPO/dist}
PREFIX=/opt/secretbroker
STAGE="$BUILD_DIR/secretbroker_${VERSION}_${ARCH}"
DEB="$OUT_DIR/secretbroker_${VERSION}_${ARCH}.deb"

step() { printf '\n==> %s\n' "$*"; }

step "SecretBroker $VERSION -> $DEB"
rm -rf "$STAGE"
mkdir -p "$STAGE$PREFIX" "$CACHE_DIR" "$OUT_DIR"

step "Python $PYTHON_VERSION (python-build-standalone $PYTHON_RELEASE)"
if [ ! -f "$CACHE_DIR/$PYTHON_TARBALL" ]; then
    curl -fsSL -o "$CACHE_DIR/$PYTHON_TARBALL.part" "$PYTHON_URL"
    mv "$CACHE_DIR/$PYTHON_TARBALL.part" "$CACHE_DIR/$PYTHON_TARBALL"
fi
echo "$PYTHON_SHA256  $CACHE_DIR/$PYTHON_TARBALL" | sha256sum -c --quiet -
tar -xzf "$CACHE_DIR/$PYTHON_TARBALL" -C "$STAGE$PREFIX"   # -> $PREFIX/python
rm -rf "$STAGE$PREFIX"/python/lib/python3.*/{test,idlelib,tkinter,turtledemo,lib2to3} \
       "$STAGE$PREFIX"/python/lib/{tcl,tk,itcl,thread}* "$STAGE$PREFIX"/python/share

step "venv with SecretBroker and its dependencies"
"$STAGE$PREFIX/python/bin/python3" -m venv "$STAGE$PREFIX/venv"
VENV_PY="$STAGE$PREFIX/venv/bin/python"
"$VENV_PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir --upgrade pip
# A copy of the sources: building from a Windows checkout mounted in WSL leaves no build/ files behind there.
SRC="$BUILD_DIR/src"
rm -rf "$SRC" && mkdir -p "$SRC"
tar -C "$REPO" --exclude=.git --exclude=.venv --exclude=dist --exclude=build --exclude=.claude \
    --exclude='__pycache__' --exclude='*.egg-info' -cf - pyproject.toml README.md secretbroker | tar -C "$SRC" -xf -
"$VENV_PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir "$SRC"

step "Leaving out what is never loaded"
"$VENV_PY" -I "$REPO/tools/deb_trim_qt.py" "$STAGE$PREFIX/venv/lib/python3.12/site-packages"
# python-build-standalone keeps debug symbols (libpython alone is ~200 MB); the build-only parts go too.
strip --strip-unneeded "$STAGE$PREFIX"/python/lib/libpython3*.so.* "$STAGE$PREFIX"/python/bin/python3.* 2>/dev/null || true
rm -rf "$STAGE$PREFIX"/python/lib/python3.*/config-* "$STAGE$PREFIX"/python/include "$STAGE$PREFIX"/python/lib/pkgconfig \
       "$STAGE$PREFIX"/python/lib/python3.*/ensurepip "$STAGE$PREFIX"/python/lib/python3.*/site-packages/pip* \
       "$STAGE$PREFIX"/python/lib/Tix* "$STAGE$PREFIX"/venv/lib/python3.*/site-packages/pip*
"$VENV_PY" -I -c "import secretbroker.app, secretbroker.service, secretbroker.mcp_server, secretbroker.platform.linux, webview, qtpy, PyQt6.QtWebEngineWidgets, secretstorage, paramiko; print('imports ok')"
# The web view still renders a page after the trimming (offscreen; no display needed).
QT_QPA_PLATFORM=offscreen QTWEBENGINE_DISABLE_SANDBOX=1 QTWEBENGINE_CHROMIUM_FLAGS="--disable-gpu" timeout 60 "$VENV_PY" -I -c "
import sys
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView
app = QApplication(sys.argv)
view = QWebEngineView()
done = lambda ok: (print('web view renders:', ok), app.exit(0 if ok else 1))
view.loadFinished.connect(done)
view.setHtml('<h1>SecretBroker</h1>')
QTimer.singleShot(45000, lambda: app.exit(2))
sys.exit(app.exec())" 2>/dev/null

step "Making the venv live in $PREFIX"
# The venv was created in the staging folder: point it (pyvenv.cfg, the python links, script shebangs) at $PREFIX.
sed -i "s#$STAGE##g" "$STAGE$PREFIX/venv/pyvenv.cfg"
for link in "$STAGE$PREFIX"/venv/bin/python*; do
    if [ -L "$link" ]; then
        target=$(readlink "$link")
        ln -sfn "${target#"$STAGE"}" "$link"
    fi
done
grep -rlI --null "$STAGE" "$STAGE$PREFIX/venv/bin" | xargs -0 -r sed -i "s#$STAGE##g"
find "$STAGE$PREFIX" -name '__pycache__' -type d -prune -exec rm -rf {} +
# Compiled now (the folder is read-only for users), with the installed paths in tracebacks.
"$STAGE$PREFIX/python/bin/python3" -m compileall -q -j 0 -s "$STAGE" -p / "$STAGE$PREFIX/venv/lib" "$STAGE$PREFIX/python/lib" >/dev/null || true
if grep -rlI "$STAGE" "$STAGE$PREFIX" | grep -v '\.pyc$' | head -5 | grep -q .; then
    echo "AVISO: quedan rutas del directorio de construcción:" >&2
    grep -rlI "$STAGE" "$STAGE$PREFIX" | grep -v '\.pyc$' | head -5 >&2
fi

step "Launchers, service, polkit, PAM, menu entry and icon"
PKG="$REPO/packaging/linux"
install -d "$STAGE$PREFIX/bin" "$STAGE$PREFIX/libexec" "$STAGE/usr/bin" "$STAGE/lib/systemd/system" \
    "$STAGE/usr/share/polkit-1/rules.d" "$STAGE/etc/pam.d" "$STAGE/usr/share/applications" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps" "$STAGE/usr/share/doc/secretbroker" "$STAGE/DEBIAN"
install -m 0755 "$PKG/bin/secretbroker" "$PKG/bin/sb" "$STAGE$PREFIX/bin/"
install -m 0755 "$PKG/secretbroker-prepare" "$STAGE$PREFIX/libexec/"
ln -s "$PREFIX/bin/secretbroker" "$STAGE/usr/bin/secretbroker"
ln -s "$PREFIX/bin/sb" "$STAGE/usr/bin/sb"
install -m 0644 "$PKG/secretbroker@.service" "$STAGE/lib/systemd/system/"
install -m 0644 "$PKG/50-secretbroker.rules" "$STAGE/usr/share/polkit-1/rules.d/"
install -m 0644 "$PKG/pam.d-secretbroker" "$STAGE/etc/pam.d/secretbroker"
install -m 0644 "$PKG/secretbroker.desktop" "$STAGE/usr/share/applications/"
install -m 0644 "$REPO/secretbroker/assets/icon.png" "$STAGE/usr/share/icons/hicolor/256x256/apps/secretbroker.png"
install -m 0644 "$REPO/LICENSE" "$STAGE/usr/share/doc/secretbroker/copyright" 2>/dev/null || true
install -m 0755 "$PKG/postinst" "$PKG/prerm" "$PKG/postrm" "$STAGE/DEBIAN/"
echo "/etc/pam.d/secretbroker" > "$STAGE/DEBIAN/conffiles"
# Line endings: a Windows checkout may have turned these into CRLF (see .gitattributes).
sed -i 's/\r$//' "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm" "$STAGE$PREFIX"/bin/* \
    "$STAGE$PREFIX/libexec/secretbroker-prepare" "$STAGE/lib/systemd/system/secretbroker@.service" \
    "$STAGE/etc/pam.d/secretbroker" "$STAGE/usr/share/applications/secretbroker.desktop" \
    "$STAGE/usr/share/polkit-1/rules.d/50-secretbroker.rules"

SIZE=$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: secretbroker
Version: $VERSION
Architecture: $ARCH
Maintainer: SecretBroker <secretbroker@users.noreply.github.com>
Installed-Size: $SIZE
Section: utils
Priority: optional
Homepage: https://github.com/xBofi/SecretBroker
Depends: systemd, passwd, libpam-runtime, libpam0g, polkitd | policykit-1, xdg-utils, libglib2.0-bin,
 libnss3, libxkbcommon0, libxkbcommon-x11-0, libegl1, libgl1, libopengl0, libfontconfig1, libfreetype6, libdbus-1-3,
 libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0,
 libxcb-shape0, libxcb-xinerama0, libxcb-xkb1, libxcomposite1, libxdamage1, libxrandr2, libxtst6, libxshmfence1,
 libxkbfile1, libwayland-client0, libwayland-cursor0, libwayland-egl1, libasound2t64 | libasound2
Recommends: gnome-shell-extension-appindicator, libnotify-bin, wl-clipboard | xclip
Description: Password and API key manager your AI can use without seeing the keys
 SecretBroker keeps passwords, API keys, SSH logins and databases in an encrypted
 vault. AI agents (Claude Code, Claude Desktop, Cursor, VS Code, Codex) use them
 through MCP: the service fills them in and removes them from what the AI reads.
 .
 The service runs as the system user "secretbroker" (one systemd unit per desktop
 user), so the user's own programs cannot read the vault or the service's memory.
EOF

step "Package"
find "$STAGE" -type d -exec chmod 0755 {} +
chmod 0755 "$STAGE/DEBIAN"
dpkg-deb --root-owner-group -Zxz -z6 --build "$STAGE" "$DEB" >/dev/null
ls -lh "$DEB"
