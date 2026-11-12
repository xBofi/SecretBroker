# Releasing SecretBroker

A release is one version tag, `v<version>` matching `pyproject.toml`. Pushing it runs
`.github/workflows/release.yml`, which:

1. checks that the tag and the version match;
2. runs the suites (`test_platform`, `test_e2e`, `test_personal`, `test_exposure`, `test_teams`, `test_autofill`,
   and on Ubuntu `server/tests/test_server.py`) on Windows, Ubuntu and macOS; nothing is built if one fails;
3. builds the installers, each on its own system, installs the Ubuntu and macOS packages on the runner and checks
   that the service starts under its own account:

   | System | Built by | Asset |
   |---|---|---|
   | Windows 10/11 | `tools/build_installer.ps1` (Inno Setup, `windows-latest`) | `SecretBroker-Setup-<v>.exe` |
   | Ubuntu 22.04 / 24.04 | `tools/build_deb.sh` (`ubuntu-22.04`) | `secretbroker_<v>_amd64.deb` |
   | macOS 12+ (Apple silicon) | `tools/build_macos.sh` (`macos-latest`) | `SecretBroker-<v>-macos-arm64.pkg` |
   | macOS 12+ (Intel) | `tools/build_macos.sh` (`macos-15-intel`) | `SecretBroker-<v>-macos-x86_64.pkg` |

   Each build job uploads its installer **unsigned** (artifacts `unsigned-windows`, `unsigned-ubuntu`,
   `unsigned-macos-<arch>`); none of them sees the release key;
4. `sign`, the only job with the secret `UPDATE_SIGNING_KEY`, takes each installer from the artifact of the job that
   built it and signs it for the in-app updater (`tools/sign_release.py`): a `<asset>.sig` next to each one, an
   Ed25519 signature over the version and the installer's SHA-256, checked against the public key built into
   `secretbroker/update.py`. That job installs nothing but `cryptography`, hash-pinned (`requirements/sign.txt`),
   and `tools/sign_release.py` imports nothing else (it reads the key and prefix out of `update.py` as text);
5. `publish` checks all the signatures again (`tools/sign_release.py --verify`) and publishes the eight files as
   the latest GitHub Release.

```
version ─ test (3 systems) ─┬─ windows ────────┬─ sign ─ publish
                            ├─ ubuntu ─────────┤
                            └─ macos (2 archs) ┘
```

Nothing is published if any test, build or signature check fails. The
updater only looks at published releases (`/releases/latest`), picks the asset of its own system (and on a Mac,
of its processor: `platform.INSTALLER_RE`) and installs it only if its `.sig` verifies.

Before tagging, run `tests/test_gui.py` and `tests/test_browser.py` on a Windows desktop (they open the real app and a
real browser; CI cannot on Windows). CI runs `test_gui.py` on Ubuntu (job `desktop-gui-ubuntu`, screenshots in the
`gui-screenshots-ubuntu` artifact) and only a smoke check of the app on macOS (`macos-package`: the page loads and
reaches the service, `sb` works, one screenshot), because WKWebView cannot be driven from outside.

## Dependencies are locked with hashes

Every Python package CI and the release install comes from a lock in `requirements/`, with its exact version and
the SHA-256 of each file on PyPI (`pip install --require-hashes --no-deps -r ...`). One lock serves every system:
packages for one system only (winrt and pywin32 on Windows, PyQt6 and secretstorage on Linux, pyobjc and pystray on
macOS) carry markers, and pip skips the lines that are not for the system it runs on.

| Lock | Used by |
|---|---|
| `app.txt` | the installers: `tools/build_installer.ps1`, `tools/build_deb.sh`, `tools/build_macos.sh` |
| `build.txt` | setuptools, installed before `app.txt`; builds run with `--no-build-isolation`, so pip never fetches an unpinned build backend (SecretBroker itself, and proxy-tools, which has no wheel) |
| `dev.txt` | the suites in `ci.yml` and `release.yml` (app + `dev` extra + server + setuptools) |
| `server.txt` | `ci.yml` › `linux-server` |
| `sign.txt` | `cryptography` alone, for `release.yml` › `sign` and `publish` |
| `tools.txt` | `uv`, for the lock check |

After changing a dependency in `pyproject.toml` or `server/pyproject.toml`, run `python tools/update_locks.py`
(it needs [uv](https://docs.astral.sh/uv/)) and commit the changed locks; `python tools/update_locks.py --upgrade`
moves every lock to the newest versions allowed. Read the diff of the locks before committing: it is the list of
code that will be bundled into the next release. CI's `locks` job fails when a lock no longer matches what it is
compiled from. `requirements/constraints.txt` holds what one system needs differently (Intel Macs stay on
`cryptography` 48, the last version with an x86_64 macOS wheel).

## Dry runs before tagging

`release.yml` also runs, without the release key and without publishing, on pull requests and pushes to `main` that
change the release path (the workflow, `requirements/`, `pyproject.toml`, the build scripts, `installer/`,
`packaging/`, `tools/sign_release.py`, `secretbroker/update.py`): every installer is built unsigned from the locks,
installed and checked as in a release, signed by `sign` with a throwaway key and verified by `publish`. A dry run
that passes means the next tag only adds the suites (which `ci.yml` already runs), the release key and the
`gh release create`.

## Builds without the owner's accounts are unsigned

Code signing proves to the operating system who made the installer. Every certificate below belongs to the
project owner's accounts; none is in the repository, and until each secret exists the workflow builds without it.
The in-app updater does not depend on any of them: it trusts only `UPDATE_SIGNING_KEY`.

### macOS: Apple Developer Program

Needs the owner's Apple Developer account (99 USD a year). Without it:

* the `.pkg` is unsigned. Opening a downloaded one, macOS says it "cannot be verified": the user right-clicks it
  and chooses **Open**, or opens it from **System Settings › Privacy & Security › Open Anyway**.
  Updates from the app are not affected (the service downloads the package; the system asks for an
  administrator's password, as for any installer);
* **Touch ID is not available**: keeping a Secure Enclave key needs the data protection keychain, which macOS only
  grants to a signed app with a `keychain-access-groups` entitlement. The app sees that (`touchid.is_supported()`
  is False) and uses password proofs: the Mac password or the master password, once per session, then one click,
  exactly as on a PC without Windows Hello.

With the account, add these repository secrets and the next tag signs, notarizes and staples the package
(`tools/build_macos.sh` reads `MACOS_SIGN_APP`, `MACOS_SIGN_INSTALLER` and `MACOS_NOTARY_PROFILE`, which the
workflow sets from them):

| Secret | What |
|---|---|
| `MACOS_CERTIFICATES` | base64 of a `.p12` holding the **Developer ID Application** and **Developer ID Installer** certificates |
| `MACOS_CERTIFICATES_PASSWORD` | the `.p12`'s password |
| `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | for `notarytool` (an app-specific password of that Apple ID) |

The app is signed with the hardened runtime and `packaging/macos/entitlements.plist` (the build puts the team id
in place of `TEAMID`). After the first signed release, check on a Mac with Touch ID that Settings › Security
offers Touch ID and that unlocking with it works.

### Windows: code signing certificate

`SecretBroker-Setup-<v>.exe` is not Authenticode-signed: SmartScreen warns ("Windows protegió su PC" ›
**Más información › Ejecutar de todas formas**) until the installer has a reputation or is signed. Signing needs
a certificate in the owner's name (an OV/EV certificate, or Azure Trusted Signing); add a signing step after
"Build the installer" in the `windows` job with `signtool sign /fd sha256 /tr <timestamp server>`.

### Ubuntu: apt repository

The `.deb` installs with a double click, and the app updates it (`pkexec apt-get install`). A signed apt
repository, so that updates also arrive with the system's updates, needs a GPG key and a host owned by the owner.

### Browser extension stores

The extension (`extension/`) is loaded unpacked from the app's folder for now (Settings › Browser shows how).
Publishing it needs the owner's **Chrome Web Store** developer account (one-off 5 USD), a **Microsoft Partner
Center** account for Edge Add-ons, and an **addons.mozilla.org** account for Firefox. Each store gives the
extension its own id: add it to `native_host.CHROME_EXTENSION_IDS` / `FIREFOX_EXTENSION_IDS` in the same release,
or the native host refuses it.

## macOS: what is untested

The macOS port was written without a Mac. CI runs the suites and builds, installs and checks the package on
GitHub's macOS runners (`ci.yml` › `macos-package`, `release.yml` › `macos`), so the installer, the
`_secretbroker` account, the LaunchDaemon, the folder permissions and the service are exercised on every push.
What a runner cannot show, and should be tried by hand on a real Mac before the first macOS release:

* the window (pywebview's Cocoa backend), the menu bar icon (pystray), closing to the menu bar and reopening from
  the Dock;
* Touch ID end to end (needs a signed build, see above) and the Mac password as a proof;
* "open with my session": the key in the login Keychain, and the vault locking with the screen
  (`com.apple.screenIsLocked`) and reopening after it;
* starting with the session (the LaunchAgent; System Settings › General › Login Items lists it);
* the browser extension's native host in Chrome, Edge, Brave and Firefox;
* invite links (`secretbroker://`) opening the app;
* updating from the app (the administrator dialog, then the app restarting) and a new account created after
  installing getting its own service (`com.secretbroker.setup`).

There is no uninstaller on macOS yet: moving the app to the Trash stops the services (their LaunchDaemons only
run while the app exists), but the daemons' files, `/usr/local/bin/sb` and the vaults stay.
