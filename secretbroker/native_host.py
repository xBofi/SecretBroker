"""Native messaging host of the SecretBroker browser extension (extension/).

The browser starts this module through a small launcher when the extension calls chrome.runtime.connectNative,
and talks to it over stdin/stdout (4-byte length + JSON). No network port is opened: the host relays a short list
of operations to the service with client.py, adding which extension is asking (the browser tells the host, the
page cannot). The service decides everything (pairing, unlocked vault, which logins match the page).

    python -m secretbroker.native_host <origin>        (started by the browser)

register() writes the host manifests and the launcher for this user (HKCU registry keys on Windows, the
per-browser folders on Linux and macOS: install_manifests, for packaging). The installer and the app call it.
"""

import json
import os
import shutil
import struct
import sys
from pathlib import Path

from . import __version__, client, paths, platform
from .i18n import tr

HOST_NAME = "com.secretbroker.autofill"
# The extension's id is pinned by the "key" in extension/manifest.json. Store builds get their own ids: add them here.
CHROME_EXTENSION_IDS = ("cekklnambceaikefialdjijgolamnnab",)
FIREFOX_EXTENSION_IDS = ("autofill@secretbroker",)
ALLOWED_ORIGINS = tuple(f"chrome-extension://{i}/" for i in CHROME_EXTENSION_IDS) + \
    tuple(f"moz-extension:{i}" for i in FIREFOX_EXTENSION_IDS)
# What the extension may ask for (service op ext_<name>), plus open_app and copy, which the host does itself.
RELAYED = ("hello", "pair", "logins", "search", "fill", "save_check", "save")
# «Copy» in the popup: the host asks for the value (ext_fill, copy) and puts it on the clipboard like the app does,
# out of clipboard history and the cloud clipboard and cleared after a while; the extension never gets the value.
CLIPBOARD_CLEAR_SECONDS = 30
COPY_FIELDS = ("username", "password", "totp")
REOPEN_OPS = ("logins", "fill")  # after the inactivity lock, with the Windows session unlock: open it again
MAX_MESSAGE = 1024 * 1024

# HKCU keys each browser reads (Brave and Chromium also read Chrome's).
WINDOWS_KEYS = {
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "chromium": r"Software\Chromium\NativeMessagingHosts",
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    "firefox": r"Software\Mozilla\NativeMessagingHosts",
}
# Per-user manifest folders, relative to the home folder.
POSIX_DIRS = {
    "linux": {
        "chrome": ".config/google-chrome/NativeMessagingHosts",
        "chromium": ".config/chromium/NativeMessagingHosts",
        "edge": ".config/microsoft-edge/NativeMessagingHosts",
        "brave": ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        "firefox": ".mozilla/native-messaging-hosts",
    },
    "darwin": {
        "chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        "chromium": "Library/Application Support/Chromium/NativeMessagingHosts",
        "edge": "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
        "brave": "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        "firefox": "Library/Application Support/Mozilla/NativeMessagingHosts",
    },
}
BROWSER_NAMES = {"chrome": "Chrome", "chromium": "Chromium", "edge": "Edge", "brave": "Brave", "firefox": "Firefox"}


# ---------------------------------------------------------------------------------------------- registration

def manifest(browser, launcher):
    """The host manifest one browser reads. Chromium-based browsers list allowed origins, Firefox extension ids."""
    data = {"name": HOST_NAME, "description": "SecretBroker: autorrellenado del navegador",
            "path": str(launcher), "type": "stdio"}
    if browser == "firefox":
        data["allowed_extensions"] = list(FIREFOX_EXTENSION_IDS)
    else:
        data["allowed_origins"] = [f"chrome-extension://{i}/" for i in CHROME_EXTENSION_IDS]
    return data


def host_dir():
    """Where this user's launcher and (on Windows) manifests live: the app's per-user folder (platform.user_dir)."""
    return paths.user_dir() / "native-host"


def write_launcher(folder, python=None):
    """A launcher that runs this module with this Python. Installed, isolated (-I) like the app; in development
    from the source folder."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    python = str(python or Path(sys.executable).with_name("python.exe" if sys.platform == "win32" else Path(sys.executable).name))
    source = Path(__file__).resolve().parents[1]
    installed = paths.is_installed() or "site-packages" in Path(__file__).resolve().parts
    if sys.platform == "win32":
        launcher = folder / "secretbroker-host.cmd"
        lines = ["@echo off"] + ([] if installed else [f'cd /d "{source}"'])
        lines.append(f'"{python}" {"-I " if installed else ""}-m secretbroker.native_host %*')
        launcher.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    else:
        launcher = folder / "secretbroker-host"
        lines = ["#!/bin/sh"] + ([] if installed else [f"cd '{source}' || exit 1"])
        lines.append(f"exec '{python}' {'-I ' if installed else ''}-m secretbroker.native_host \"$@\"")
        launcher.write_text("\n".join(lines) + "\n", encoding="utf-8")
        launcher.chmod(0o755)
    return launcher


def install_manifests(launcher, home=None, system=None, browsers=None):
    """Write the host manifest into each browser's per-user folder (Linux and macOS packaging call this after
    installing the launcher). Returns the files written."""
    system = system or ("darwin" if sys.platform == "darwin" else "linux")
    home = Path(home or Path.home())
    written = []
    for browser, relative in POSIX_DIRS[system].items():
        if browsers and browser not in browsers:
            continue
        target = home / relative / f"{HOST_NAME}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest(browser, launcher), indent=2), encoding="utf-8")
        written.append(target)
    return written


def remove_manifests(home=None, system=None):
    system = system or ("darwin" if sys.platform == "darwin" else "linux")
    home = Path(home or Path.home())
    for relative in POSIX_DIRS[system].values():
        (home / relative / f"{HOST_NAME}.json").unlink(missing_ok=True)


def register(host_name=HOST_NAME, folder=None):
    """Make the extension able to start this host, for the current user. Safe to call on every start."""
    folder = Path(folder or host_dir())
    launcher = write_launcher(folder)
    if sys.platform != "win32":
        install_manifests(launcher)
        return {"launcher": str(launcher)}
    import winreg
    files = {}
    for kind in ("chrome", "firefox"):
        path = folder / f"{host_name}.{kind}.json"
        data = {**manifest(kind, launcher), "name": host_name}
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        files[kind] = path
    for browser, key in WINDOWS_KEYS.items():
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + "\\" + host_name) as handle:
            winreg.SetValueEx(handle, "", 0, winreg.REG_SZ, str(files["firefox" if browser == "firefox" else "chrome"]))
    return {"launcher": str(launcher), "manifests": {k: str(v) for k, v in files.items()}}


def unregister(host_name=HOST_NAME, folder=None):
    folder = Path(folder or host_dir())
    if sys.platform == "win32":
        import winreg
        for key in WINDOWS_KEYS.values():
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key + "\\" + host_name)
            except OSError:
                pass
    else:
        remove_manifests()
    shutil.rmtree(folder, ignore_errors=True)


def registered(host_name=HOST_NAME):
    """Per browser, whether it can start this host (its manifest is registered and its launcher exists)."""
    result = {}
    if sys.platform == "win32":
        import winreg
        for browser, key in WINDOWS_KEYS.items():
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key + "\\" + host_name) as handle:
                    path = Path(winreg.QueryValueEx(handle, "")[0])
                result[browser] = path.is_file() and Path(json.loads(path.read_text(encoding="utf-8"))["path"]).is_file()
            except (OSError, ValueError, KeyError):
                result[browser] = False
        return result
    system = "darwin" if sys.platform == "darwin" else "linux"
    for browser, relative in POSIX_DIRS[system].items():
        result[browser] = (Path.home() / relative / f"{host_name}.json").is_file()
    return result


def extension_dir():
    """The extension's folder, to load it unpacked until it is in the stores: next to the bundled Python when
    installed, the repository's extension/ in development."""
    for candidate in (Path(sys.prefix).parent / "extension", Path(__file__).resolve().parents[1] / "extension"):
        if (candidate / "manifest.json").is_file():
            return candidate
    return None


# ---------------------------------------------------------------------------------------------- the host

def origin_from(argv):
    """Which extension started the host. Chromium passes `chrome-extension://<id>/`, Firefox the manifest path
    and the extension id."""
    for arg in argv:
        if arg.startswith("chrome-extension://"):
            return arg if arg.endswith("/") else arg + "/"
    if len(argv) >= 2 and not argv[1].startswith("-"):
        return "moz-extension:" + argv[1]
    return ""


def read_message(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    if length > MAX_MESSAGE:
        raise ValueError("message too large")
    body = stream.read(length)
    if len(body) < length:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(stream, message):
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


def answer(message, origin):
    """The reply to one message of the extension: {id, ok, result} or {id, ok: false, code, error}."""
    reply = {"id": message.get("id") if isinstance(message, dict) else None}
    try:
        if not isinstance(message, dict):
            raise client.BrokerError(tr("native_host.invalid_message"), "bad_request")
        op = message.get("op")
        if op == "open_app":
            client.launch_app()
            return {**reply, "ok": True, "result": True}
        if op not in RELAYED and op != "copy":
            raise client.BrokerError(tr("service.unknown_operation", op=op), "unknown_op")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if op == "copy":
            if params.get("what") not in COPY_FIELDS:
                raise client.BrokerError(tr("service.what_fill_in_login_totp"), "invalid")
            op, params = "fill", {**params, "copy": True}
            copying = params["what"]
        else:
            copying = None
        pair = message.get("pair") if isinstance(message.get("pair"), dict) else {}
        params = {**params, "_ext": {"origin": origin, "pair": str(pair.get("id") or ""), "key": str(pair.get("key") or ""),
                                     "browser": str(message.get("browser") or "")[:40], "host_version": __version__}}
        try:
            result = client.request("ext_" + op, params, timeout=30)
        except client.BrokerError as exc:
            if exc.code != "locked" or op not in REOPEN_OPS or not _reopen():
                raise
            result = client.request("ext_" + op, params, timeout=30)
        if copying:
            platform.copy_to_clipboard(str(result.get(copying) or ""), True, CLIPBOARD_CLEAR_SECONDS)
            if sys.platform == "win32":
                import ctypes
                copied_at[0] = ctypes.windll.user32.GetClipboardSequenceNumber()
            result = {"copied": copying, "clear_seconds": CLIPBOARD_CLEAR_SECONDS}
        return {**reply, "ok": True, "result": result}
    except client.BrokerError as exc:
        return {**reply, "ok": False, "code": exc.code, "error": str(exc)}
    except client.BrokerUnavailable as exc:
        return {**reply, "ok": False, "code": "unavailable", "error": str(exc)}


def _clear_copied():
    """The browser closed the host before the clipboard was cleared: clear it now if it still holds what was copied."""
    if sys.platform == "darwin":
        try:
            platform.clear_copied()
        except Exception:
            pass
        return
    if copied_at[0] and sys.platform == "win32":
        import ctypes
        user32 = ctypes.windll.user32
        if user32.GetClipboardSequenceNumber() == copied_at[0] and user32.OpenClipboard(None):
            user32.EmptyClipboard()
            user32.CloseClipboard()


copied_at = [0]  # the clipboard's sequence number after the last copy (Windows), to clear it on exit


def _reopen():
    """Locked for inactivity with "open with my Windows session" on: open it again, as for the AI. Never after the
    user locked it by hand."""
    try:
        if client.request("status", timeout=5).get("lock_reason") != "idle":
            return False
    except (client.BrokerError, client.BrokerUnavailable):
        return False
    return client.reopen_with_session()


def main(argv=None):
    argv = sys.argv if argv is None else argv
    origin = origin_from(argv[1:])
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(stdout.fileno(), os.O_BINARY)
    while True:
        try:
            message = read_message(stdin)
        except ValueError:
            return 1
        if message is None:
            _clear_copied()
            return 0
        write_message(stdout, answer(message, origin))


if __name__ == "__main__":
    sys.exit(main())
