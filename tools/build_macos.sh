#!/usr/bin/env bash
# Builds dist/SecretBroker-<version>-macos-<arch>.pkg (macOS 12+; arch = arm64 or x86_64, the Mac it is built on).
#
# The package installs /Applications/SecretBroker.app, which is self-contained: a standalone CPython
# (python-build-standalone, checksum pinned, relocatable) in Contents/Resources/python with SecretBroker and its
# dependencies installed into it, the browser extension and the root setup script. Installing it is a double click;
# postinstall creates the hidden `_secretbroker` account and a LaunchDaemon per desktop account (see
# packaging/macos/secretbroker-setup and docs/ARCHITECTURE.md, "Platforms").
#
# Run on a Mac from anywhere:  tools/build_macos.sh
# Needs: the Xcode command line tools (pkgbuild, productbuild, iconutil, plutil), curl and shasum.
# The build is unsigned unless these are set (docs/RELEASING.md):
#   MACOS_SIGN_APP="Developer ID Application: <name> (<team>)"      signs the app (hardened runtime, entitlements)
#   MACOS_SIGN_INSTALLER="Developer ID Installer: <name> (<team>)"  signs the package
#   MACOS_NOTARY_PROFILE=<keychain profile of `xcrun notarytool store-credentials`>  notarizes and staples it
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(tr -d '\r' < "$REPO/pyproject.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -1)
ARCH=${ARCH:-$(uname -m)}
PYTHON_RELEASE=20241016
PYTHON_VERSION=3.12.7
case "$ARCH" in
    arm64)  PYTHON_TRIPLE=aarch64-apple-darwin; PYTHON_SHA256=4c18852bf9c1a11b56f21bcf0df1946f7e98ee43e9e4c0c5374b2b3765cf9508 ;;
    x86_64) PYTHON_TRIPLE=x86_64-apple-darwin;  PYTHON_SHA256=60c5271e7edc3c2ab47440b7abf4ed50fbc693880b474f74f05768f5b657045a ;;
    *) echo "Arquitectura no soportada: $ARCH" >&2; exit 1 ;;
esac
if [ "$ARCH" != "$(uname -m)" ]; then
    echo "Hay que construir en un Mac $ARCH (pip instala las dependencias de este equipo)" >&2
    exit 1
fi
PYTHON_TARBALL="cpython-${PYTHON_VERSION}+${PYTHON_RELEASE}-${PYTHON_TRIPLE}-install_only.tar.gz"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_RELEASE}/${PYTHON_TARBALL}"
BUILD_DIR=${BUILD_DIR:-${TMPDIR:-/tmp}/secretbroker-pkg}
CACHE_DIR=${CACHE_DIR:-$HOME/Library/Caches/secretbroker-build}
OUT_DIR=${OUT_DIR:-$REPO/dist}
PKG="$OUT_DIR/SecretBroker-${VERSION}-macos-${ARCH}.pkg"
STAGE="$BUILD_DIR/root"
APP="$STAGE/SecretBroker.app"
RES="$APP/Contents/Resources"
PY="$RES/python/bin/python3"
MAC="$REPO/packaging/macos"

step() { printf '\n==> %s\n' "$*"; }

step "SecretBroker $VERSION ($ARCH) -> $PKG"
rm -rf "$BUILD_DIR"
mkdir -p "$APP/Contents/MacOS" "$RES" "$CACHE_DIR" "$OUT_DIR"

step "Python $PYTHON_VERSION (python-build-standalone $PYTHON_RELEASE)"
if [ ! -f "$CACHE_DIR/$PYTHON_TARBALL" ]; then
    curl -fsSL -o "$CACHE_DIR/$PYTHON_TARBALL.part" "$PYTHON_URL"
    mv "$CACHE_DIR/$PYTHON_TARBALL.part" "$CACHE_DIR/$PYTHON_TARBALL"
fi
echo "$PYTHON_SHA256  $CACHE_DIR/$PYTHON_TARBALL" | shasum -a 256 -c --quiet -
tar -xzf "$CACHE_DIR/$PYTHON_TARBALL" -C "$RES"   # -> Resources/python
rm -rf "$RES"/python/lib/python3.*/{test,idlelib,tkinter,turtledemo,lib2to3} \
       "$RES"/python/lib/{tcl,tk,itcl,thread}* "$RES"/python/lib/Tix* "$RES"/python/share

step "SecretBroker and its dependencies, into the bundled Python"
# Straight into its site-packages, not a venv: the standalone Python finds them relative to itself, so the
# bundle keeps working wherever the build happened (no absolute paths to rewrite).
"$PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir --upgrade pip
SRC="$BUILD_DIR/src"
mkdir -p "$SRC"
tar -C "$REPO" --exclude=.git --exclude=.venv --exclude=dist --exclude=build --exclude=.claude \
    --exclude='__pycache__' --exclude='*.egg-info' -cf - pyproject.toml README.md secretbroker | tar -C "$SRC" -xf -
"$PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir "$SRC"
"$PY" -I -c "import secretbroker.app, secretbroker.service, secretbroker.mcp_server, secretbroker.native_host, \
secretbroker.platform.macos, secretbroker.touchid, webview, objc, AppKit, Security, LocalAuthentication, OpenDirectory, \
Quartz, pystray, PIL, paramiko; print('imports ok')"

step "Leaving out what is never loaded"
# No strip: on Apple silicon every binary must keep its (linker) signature, and strip would break it.
rm -rf "$RES"/python/include "$RES"/python/lib/pkgconfig "$RES"/python/lib/python3.*/config-* \
       "$RES"/python/lib/python3.*/ensurepip "$RES"/python/lib/python3.*/site-packages/pip* "$RES"/python/bin/pip*
# pip's console scripts point at the build folder; the bundle starts everything with `python3 -m` instead.
rm -f "$RES"/python/bin/{sb,secretbroker,secretbroker-mcp,secretbroker-service}
find "$RES/python" -name '__pycache__' -type d -prune -exec rm -rf {} +
# Compiled now (the bundle is read-only for users), with the installed paths in tracebacks.
"$PY" -m compileall -q -j 0 -s "$STAGE" -p /Applications "$RES/python/lib" >/dev/null || true

step "Bundle: launcher, Info.plist, icon, extension, setup"
install -m 0755 "$MAC/SecretBroker" "$APP/Contents/MacOS/SecretBroker"
sed "s/@VERSION@/$VERSION/g" "$MAC/Info.plist" > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
printf 'APPL????' > "$APP/Contents/PkgInfo"
"$PY" -I "$REPO/tools/make_icon.py" --iconset "$BUILD_DIR/SecretBroker.iconset" >/dev/null
iconutil -c icns -o "$RES/SecretBroker.icns" "$BUILD_DIR/SecretBroker.iconset"
install -m 0755 "$MAC/secretbroker-setup" "$MAC/sb" "$RES/"
install -m 0644 "$MAC/com.secretbroker.setup.plist" "$RES/"
plutil -lint "$RES/com.secretbroker.setup.plist" >/dev/null
# The browser extension, loaded from here until it is in the stores (native_host.extension_dir: next to python/).
cp -R "$REPO/extension" "$RES/extension"
find "$APP" -type d -exec chmod 0755 {} +
find "$RES/extension" -type f -exec chmod 0644 {} +
xattr -cr "$APP"

if [ -n "${MACOS_SIGN_APP:-}" ]; then
    step "Signing the app ($MACOS_SIGN_APP)"
    entitlements="$BUILD_DIR/entitlements.plist"
    team=$(echo "$MACOS_SIGN_APP" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')
    sed "s/TEAMID/$team/" "$MAC/entitlements.plist" > "$entitlements"
    # Inside out: every Mach-O file, then the bundle (its main executable is the launcher script).
    find "$RES/python" -type f \( -perm -u+x -o -name '*.so' -o -name '*.dylib' \) -print0 |
        xargs -0 codesign --force --timestamp --options runtime --entitlements "$entitlements" -s "$MACOS_SIGN_APP"
    codesign --force --timestamp --options runtime --entitlements "$entitlements" -s "$MACOS_SIGN_APP" "$APP"
    codesign --verify --strict --deep "$APP"
fi

step "Package"
SCRIPTS="$BUILD_DIR/scripts"
mkdir -p "$SCRIPTS"
install -m 0755 "$MAC/scripts/postinstall" "$SCRIPTS/postinstall"
# Never relocatable: an update must replace /Applications/SecretBroker.app, which the LaunchDaemons point at,
# not a copy the user moved elsewhere.
COMPONENTS="$BUILD_DIR/components.plist"
pkgbuild --analyze --root "$STAGE" "$COMPONENTS" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$COMPONENTS"
plutil -replace 0.BundleHasStrictIdentifier -bool NO "$COMPONENTS"
plutil -replace 0.BundleOverwriteAction -string upgrade "$COMPONENTS"
pkgbuild --root "$STAGE" --component-plist "$COMPONENTS" --identifier com.secretbroker.app --version "$VERSION" \
    --install-location /Applications --scripts "$SCRIPTS" --ownership recommended \
    "$BUILD_DIR/SecretBroker-component.pkg" >/dev/null
sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" "$MAC/distribution.xml" > "$BUILD_DIR/distribution.xml"
sign_args=()
if [ -n "${MACOS_SIGN_INSTALLER:-}" ]; then sign_args=(--sign "$MACOS_SIGN_INSTALLER" --timestamp); fi
rm -f "$PKG"
productbuild --distribution "$BUILD_DIR/distribution.xml" --resources "$MAC/resources" \
    --package-path "$BUILD_DIR" "${sign_args[@]+"${sign_args[@]}"}" "$PKG" >/dev/null

if [ -n "${MACOS_NOTARY_PROFILE:-}" ]; then
    step "Notarizing"
    xcrun notarytool submit "$PKG" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
fi

# What ended up in the package, for a quick look in the build log.
pkgutil --payload-files "$PKG" | grep -E 'MacOS/SecretBroker$|Resources/(secretbroker-setup|sb|SecretBroker.icns)$' || true
ls -lh "$PKG"
