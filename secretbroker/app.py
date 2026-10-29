"""SecretBroker desktop app (runs as the desktop user). Holds no secrets: it talks to the service."""

import base64
import ctypes
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from . import __version__, client, hello, integrations, links, paths, resident, scanner, templates, winsec
from .client import BrokerError, BrokerUnavailable

WEB_DIR = Path(__file__).with_name("web")
ICON = Path(__file__).with_name("assets") / "icon.ico"
CLIPBOARD_CLEAR_SECONDS = 30
AUTO_SCAN_HOURS = 12
SESSION_FILE = integrations.PREFS_FILE.parent / "session.bin"
SESSION_ENTROPY = b"SecretBroker/session-unlock/v1"
LOG_FILE = integrations.PREFS_FILE.parent / "app.log"
log = logging.getLogger("secretbroker.app")
BACKUP_EVERY_HOURS = 24
BACKUPS_KEPT = 10
# What the app that unlocked may do with one click (see service.PRESENCE_OPS).
PRESENCE_OPS = ("approve", "complete_draft", "resume_ai", "set_ai_permissions", "backup", "restore")
# Operations the service only accepts with a proof of identity.
PROOF_OPS = {"unlock", "approve", "save_entry", "delete_entry", "reveal", "rotate", "complete_draft",
             "enable_session_unlock", "resume_ai", "set_ai_permissions", "backup", "restore",
             "change_master_password", "set_settings", "remove_hello", "exposure_begin"}


class Api:
    """Methods exposed to the web UI as window.pywebview.api.*"""

    def __init__(self):
        self._window = None
        self._hwnd = None
        self._presence = None  # lets this app approve the AI's requests without asking again
        # Handed out by the service on unlock: lets this app scan files and see where secrets were found.
        # Kept here, never given to the page.
        self._scan_session = None
        self._scan = None
        self._tray = None
        self._quitting = False
        self._hidden_once = False
        self._backup_tried = 0.0

    # ----- generic bridge

    def info(self):
        return {"version": __version__, "installed": paths.is_installed(),
                "hello_supported": hello.is_supported(), "templates": templates.export(), "providers": links.catalog(),
                "prefs": integrations.load_prefs(), "integrations": integrations.status(),
                "start_with_windows": resident.start_with_windows(), "session_unlock_here": self.has_session_unlock()}

    def set_pref(self, key, value):
        if key in ("palette", "auto_scan", "scan_folders"):
            integrations.set_pref(key, value)
        return True

    def connect_claude_code(self):
        return self._integration(integrations.connect_claude_code)

    def connect_claude_desktop(self):
        return self._integration(integrations.connect_claude_desktop)

    def _integration(self, connect):
        try:
            connect()
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def status(self):
        try:
            return {"ok": True, "result": client.request("status", {"gui": True}, timeout=10)}
        except BrokerUnavailable as exc:
            if client.ensure_service():
                return self.status()
            return {"ok": False, "code": "unavailable", "error": str(exc)}
        except BrokerError as exc:
            return {"ok": False, "code": exc.code, "error": str(exc)}

    def call(self, op, params=None, proof=None):
        """Call the service. Operations that need a proof use Windows Hello automatically when it is
        set up; otherwise (or if cancelled) the UI is asked to collect a password proof."""
        params = dict(params or {})
        try:
            if op in PRESENCE_OPS and proof is None and self._presence:
                try:
                    return {"ok": True, "result": client.request(op, {**params, "proof": {"kind": "presence", "token": self._presence}})}
                except BrokerError as exc:
                    if exc.code != "proof_invalid":
                        raise
                    self._presence = None
            if op in PROOF_OPS and proof is None:
                status = client.request("status", timeout=10)
                if not (status["hello_enrolled"] and hello.is_supported()):
                    return {"ok": False, "code": "proof_required", "error": "Verifica tu identidad"}
                proof = self._hello_proof(op, params)
            if proof is not None:
                params["proof"] = proof
            result = client.request(op, params)
            if op in ("unlock", "exposure_begin", "restore", "create_vault") and isinstance(result, dict):
                self._scan_session = result.pop("exposure_session", None) or result.get("session") or self._scan_session
            if op in ("unlock", "approve", "restore", "create_vault") and isinstance(result, dict) and result.get("presence"):
                self._presence = result.pop("presence")
            return {"ok": True, "result": result}
        except hello.HelloCancelled:
            return {"ok": False, "code": "hello_cancelled", "error": "Verificación cancelada"}
        except hello.HelloError as exc:
            return {"ok": False, "code": "hello_failed", "error": str(exc)}
        except BrokerError as exc:
            return {"ok": False, "code": exc.code, "error": str(exc)}
        except BrokerUnavailable as exc:
            return {"ok": False, "code": "unavailable", "error": str(exc)}

    def _hello_proof(self, op, params):
        challenge = client.request("challenge", {"op": op, "params": params})
        self._bring_to_front()
        signature = hello.sign(base64.b64decode(challenge["message"]))
        return {"kind": "hello", "nonce": challenge["nonce"], "signature": base64.b64encode(signature).decode()}

    # ----- exposure

    def exposure_report(self):
        result = self.call("exposure_report", {"session": self._scan_session})
        if result["ok"] and not result["result"]["details"]:
            self._scan_session = None
        return result

    def open_exposure_session(self, proof=None):
        """Prove identity to see where secrets were found (the session from unlocking expired)."""
        result = self.call("exposure_begin", {}, proof)
        if result["ok"]:
            result["result"] = True
        return result

    def check_exposure(self, entry_id=None):
        return self.call("exposure_check", {"id": entry_id, "session": self._scan_session}, None)

    def start_scan(self, proof=None):
        if self._scan and self._scan.progress["running"]:
            return {"ok": True}
        if not self._scan_session or proof is not None:
            opened = self.open_exposure_session(proof)
            if not opened["ok"]:
                return opened
        scan = scanner.Scan(self._scan_session, integrations.load_prefs().get("scan_folders") or [],
                            on_session=lambda token: setattr(self, "_scan_session", token))
        self._scan = scan

        def run():
            scan.run()
            if scan.progress.get("code") == "session_expired":
                self._scan_session = None

        threading.Thread(target=run, daemon=True, name="scan").start()
        return {"ok": True}

    def auto_scan(self):
        """Scan in the background after unlocking, at most every few hours."""
        if integrations.load_prefs().get("auto_scan") is False or not self._scan_session:
            return False
        last = scanner.last_finished()
        if last and time.time() - last < AUTO_SCAN_HOURS * 3600:
            return False
        return self.start_scan()["ok"]

    def scan_status(self):
        return dict(self._scan.progress) if self._scan else None

    def cancel_scan(self):
        if self._scan:
            self._scan.cancelled = True
        return True

    def scan_folders(self):
        extra = integrations.load_prefs().get("scan_folders") or []
        detected = [str(f) for f in scanner.project_folders()]
        return {"extra": extra, "detected": detected}

    def add_scan_folder(self):
        import webview
        chosen = self._window.create_file_dialog(webview.FOLDER_DIALOG) if self._window else None
        if not chosen:
            return None
        folder = str(chosen[0] if isinstance(chosen, (list, tuple)) else chosen)
        folders = integrations.load_prefs().get("scan_folders") or []
        if folder not in folders:
            integrations.set_pref("scan_folders", folders + [folder])
        return folder

    def show_location(self, location):
        """Show a file where a secret was found in Explorer."""
        path = Path(location[4:] if location.startswith("git:") else location)
        if location.startswith("env:") or not path.exists():
            return False
        if path.is_dir():
            subprocess.Popen(["explorer", str(path)])
        else:
            subprocess.Popen(["explorer", "/select,", str(path)])
        return True

    def update_status(self, force=False):
        return self.call("update_status", {"force": bool(force)})

    def install_update(self):
        """Download and verify the new version (in the service), then run its installer.
        Windows asks for administrator consent; the installer closes this app and reopens it."""
        result = self.call("update_download", {})
        if not result["ok"]:
            return result
        try:
            os.startfile(result["result"]["path"], "open", "/SILENT /SUPPRESSMSGBOXES /NORESTART")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1223:  # the user said no to UAC
                return {"ok": False, "code": "cancelled", "error": "Cancelado"}
            return {"ok": False, "code": "error", "error": f"No se pudo abrir el instalador: {exc}"}
        return {"ok": True, "result": result["result"]["version"]}

    def open_link(self, url):
        """Open a provider page (API keys, billing...) in the default browser."""
        if not isinstance(url, str) or not url.startswith("https://"):
            return False
        return webbrowser.open(url)

    # ----- Windows Hello

    def enroll_hello(self, proof):
        """Register this user's Windows Hello key. Needs a password proof (see service)."""
        try:
            public_key = hello.create_key()
        except hello.HelloCancelled:
            return {"ok": False, "code": "hello_cancelled", "error": "Verificación cancelada"}
        except hello.HelloError as exc:
            return {"ok": False, "code": "hello_failed", "error": str(exc)}
        return self.call("enroll_hello", {"public_key": base64.b64encode(public_key).decode()}, proof)

    def disable_hello(self, proof=None):
        result = self.call("remove_hello", {}, proof)
        if result["ok"]:
            hello.delete_key()
        return result

    # ----- helpers

    def suggest_policy(self, template_id, fields):
        return templates.default_policy(template_id, fields or {})

    def copy_secret(self, entry_id, field, proof=None):
        result = self.call("reveal", {"id": entry_id, "field": field}, proof)
        if result["ok"]:
            _copy_to_clipboard(result.pop("result"))
            result["result"] = CLIPBOARD_CLEAR_SECONDS
        return result

    def copy_text(self, text):
        _copy_to_clipboard(str(text), auto_clear=False)
        return True

    def _bring_to_front(self, activate=False):
        """Show the window (it may be hidden next to the clock), raise it and flash it in the taskbar.

        Only asynchronous Win32 calls: pywebview's restore()/on_top wait for the UI thread, which
        can be waiting for this very call to return (a JS API call), and the window froze."""
        if not self._hwnd or sys.platform != "win32":
            return
        user32 = ctypes.windll.user32
        hwnd = ctypes.c_void_p(self._hwnd)
        flags = 0x0001 | 0x0002 | 0x0010 | 0x4000  # NOSIZE | NOMOVE | NOACTIVATE | ASYNCWINDOWPOS
        try:
            user32.ShowWindowAsync(hwnd, 9 if user32.IsIconic(hwnd) else 5)  # SW_RESTORE / SW_SHOW
            if activate:
                user32.SetForegroundWindow(hwnd)
            user32.SetWindowPos(hwnd, ctypes.c_void_p(-1), 0, 0, 0, 0, flags)  # HWND_TOPMOST
            user32.SetWindowPos(hwnd, ctypes.c_void_p(-2), 0, 0, 0, 0, flags)  # HWND_NOTOPMOST
            user32.FlashWindow(hwnd, True)
        except OSError:
            pass

    def focus(self):
        self._bring_to_front()
        return True

    # ----- living in the background

    def show(self):
        self._bring_to_front(activate=True)

    def hide(self):
        if self._hwnd and sys.platform == "win32":
            ctypes.windll.user32.ShowWindowAsync(ctypes.c_void_p(self._hwnd), 0)  # SW_HIDE
            if not self._hidden_once and self._tray:
                self._hidden_once = True
                self._tray.notify("SecretBroker sigue activo", "Está junto al reloj para atender a la IA. Ciérralo desde ese icono.")

    def quit(self):
        self._quitting = True
        if self._tray:
            self._tray.close()
        if self._window:
            self._window.destroy()

    def set_start_with_windows(self, enabled):
        integrations.set_pref("start_with_windows", bool(enabled))
        resident.set_start_with_windows(bool(enabled))
        return True

    # ----- backups

    def backup_info(self):
        prefs = integrations.load_prefs()
        return {"folder": prefs.get("backup_folder"), "last": prefs.get("last_backup"), "suggested": str(_default_backup_folder())}

    def choose_backup_folder(self):
        import webview
        chosen = self._window.create_file_dialog(webview.FOLDER_DIALOG) if self._window else None
        if not chosen:
            return {"ok": False, "code": "cancelled", "error": ""}
        return self.set_backup_folder(chosen[0])

    def set_backup_folder(self, folder):
        integrations.set_pref("backup_folder", str(folder) if folder else None)
        return self.backup_now() if folder else {"ok": True}

    def backup_due(self):
        prefs = integrations.load_prefs()
        if not prefs.get("backup_folder") or time.time() - self._backup_tried < 3600:
            return False
        try:
            return time.time() - datetime.fromisoformat(prefs["last_backup"]).timestamp() > BACKUP_EVERY_HOURS * 3600
        except (KeyError, TypeError, ValueError):
            return True

    def backup_now(self):
        """Copy the encrypted vault into the chosen folder (OneDrive, a USB drive...), keeping the last ones."""
        folder = integrations.load_prefs().get("backup_folder")
        if not folder:
            return {"ok": False, "error": "Elige primero una carpeta"}
        self._backup_tried = time.time()
        result = self.call("backup")
        if not result["ok"]:
            return result
        try:
            target = Path(folder)
            target.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            (target / f"SecretBroker_{stamp}.sbbackup").write_text(result["result"]["vault"], encoding="utf-8")
            for old in sorted(target.glob("SecretBroker_*.sbbackup"))[:-BACKUPS_KEPT]:
                old.unlink()
        except OSError as exc:
            return {"ok": False, "error": f"No se pudo escribir en {folder}: {exc.strerror or exc}"}
        integrations.set_pref("last_backup", datetime.now().isoformat(timespec="seconds"))
        return {"ok": True, "result": {"entries": result["result"]["entries"]}}

    def pick_backup_file(self):
        import webview
        folder = integrations.load_prefs().get("backup_folder") or str(_default_backup_folder())
        chosen = self._window.create_file_dialog(webview.OPEN_DIALOG, directory=folder if Path(folder).is_dir() else "",
                                                 file_types=("Copia de SecretBroker (*.sbbackup)", "Todos los archivos (*.*)")) if self._window else None
        return chosen[0] if chosen else None

    def restore_backup(self, path, master_password, proof=None):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return {"ok": False, "error": f"No se pudo leer el archivo: {exc}"}
        if proof is None and client.request("status")["state"] == "no_vault":
            proof = {"kind": "none"}  # a new PC: there is no vault to protect yet (the service ignores it)
        return self.call("restore", {"vault": text, "master_password": master_password}, proof)

    # ----- open the vault with the Windows session

    def has_session_unlock(self):
        return SESSION_FILE.exists()

    def has_presence(self):
        return self._presence is not None

    def session_unlock(self):
        """Unlock with the token kept under the user's Windows login. Returns True if it worked."""
        try:
            token = winsec.dpapi_unprotect(SESSION_FILE.read_bytes(), SESSION_ENTROPY).decode()
        except OSError:
            return False
        result = self.call("unlock", {}, {"kind": "session", "token": token})
        if not result["ok"] and result.get("code") == "proof_invalid":
            SESSION_FILE.unlink(missing_ok=True)  # the service forgot it (turned off elsewhere)
        return result["ok"]

    def enable_session_unlock(self, proof=None):
        result = self.call("enable_session_unlock", {}, proof)
        if result["ok"]:
            SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
            SESSION_FILE.write_bytes(winsec.dpapi_protect(result.pop("result")["token"].encode(), SESSION_ENTROPY))
        return result

    def disable_session_unlock(self):
        SESSION_FILE.unlink(missing_ok=True)
        return self.call("disable_session_unlock")

    def resume_ai(self):
        return self._presence is not None and self.call("resume_ai")["ok"]


def _default_backup_folder():
    """OneDrive if the user has it (a copy outside this PC), otherwise Documents."""
    onedrive = os.environ.get("OneDrive")
    base = Path(onedrive) if onedrive and Path(onedrive).is_dir() else Path.home() / "Documents"
    return base / "SecretBroker"


# ----------------------------------------------------------------- clipboard (Windows)


def _copy_to_clipboard(text, auto_clear=True):
    if sys.platform != "win32":
        return
    from ctypes import wintypes
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

    def put(fmt, data):
        handle = kernel32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        ctypes.memmove(kernel32.GlobalLock(handle), data, len(data))
        kernel32.GlobalUnlock(handle)
        user32.SetClipboardData(fmt, handle)

    for _ in range(10):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.05)
    else:
        return
    try:
        user32.EmptyClipboard()
        put(13, (text + "\0").encode("utf-16-le"))  # CF_UNICODETEXT
        if auto_clear:
            # Keep passwords out of Windows clipboard history and cloud clipboard.
            zero = (0).to_bytes(4, "little")
            put(user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing"), zero)
            put(user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory"), zero)
            put(user32.RegisterClipboardFormatW("CanUploadToCloudClipboard"), zero)
    finally:
        user32.CloseClipboard()

    if auto_clear:
        sequence = user32.GetClipboardSequenceNumber()

        def clear():
            time.sleep(CLIPBOARD_CLEAR_SECONDS)
            if user32.GetClipboardSequenceNumber() == sequence and user32.OpenClipboard(None):
                user32.EmptyClipboard()
                user32.CloseClipboard()

        threading.Thread(target=clear, daemon=True).start()


# ----------------------------------------------------------------- entry point


def _single_instance():
    if sys.platform != "win32":
        return True
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\SecretBrokerApp" + paths.instance_suffix())
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def main():
    import webview

    if not _single_instance():
        resident.signal_running_instance()
        return
    _start_logging()
    background = "--background" in sys.argv
    # Keep the page running at full speed while hidden: it answers the AI's requests.
    os.environ.setdefault("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                          "--disable-background-timer-throttling --disable-renderer-backgrounding "
                          "--disable-backgrounding-occluded-windows --disable-features=CalculateNativeWinOcclusion")
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecretBroker.App")
        except Exception:
            pass
    api = Api()
    window = webview.create_window(
        "SecretBroker", url=str(WEB_DIR / "index.html"), js_api=api,
        width=1120, height=740, min_size=(880, 600), background_color="#0f1115", minimized=background,
    )
    api._window = window
    window.events.shown += lambda: _on_shown(window, api, background)
    # Closing the window keeps the app next to the clock, where it can answer the AI; "Salir" quits.
    window.events.closing += lambda: True if api._quitting else (api.hide() or False)
    # WebView2 would otherwise try to write next to python.exe (read-only under Program Files).
    storage = paths.user_dir() / "webview"
    webview.start(private_mode=True, storage_path=str(storage))


def _start_logging():
    """What the app did and what failed, for diagnosing problems. Never secrets: the app has none,
    and requests to the service are not logged."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    for name in ("secretbroker", "pywebview"):
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    log.info("SecretBroker %s started (%s)", __version__, " ".join(sys.argv[1:]) or "window")


def _step(name, action):
    try:
        action()
        log.info("%s: ok", name)
    except Exception:
        log.exception("%s failed", name)


def _start_resident(api):
    if sys.platform != "win32" or api._tray:
        return
    api._tray = resident.Tray(api, ICON)
    _step("show event", lambda: resident.listen_for_show(api.show))
    _step("tray icon", api._tray.start)

    def watch():
        watcher = resident.Watcher(api, on_status=api._tray.update)
        watcher.notify = api._tray.notify
        watcher.start()

    _step("watcher", watch)
    _step("MCP over HTTP", lambda: resident.serve_mcp(api.show))
    if paths.is_installed():
        _step("start with Windows", lambda: resident.set_start_with_windows(resident.start_with_windows()))
    threading.Thread(target=lambda: _step("Claude Code connection", integrations.upgrade_claude_code), daemon=True).start()


def _let_windows_close(api, args):
    """Hiding instead of closing must not block signing out or shutting down Windows. Runs after
    pywebview's own handler, which may have cancelled the close."""
    from System.Windows.Forms import CloseReason
    if args.CloseReason in (CloseReason.WindowsShutDown, CloseReason.TaskManagerClosing):
        api._quitting = True
        args.Cancel = False


def _on_shown(window, api, background=False):
    """pywebview has no icon option on Windows: set it on the underlying WinForms form. Also keep
    the window handle, to raise the window later without going through the UI thread."""
    try:
        from System import Action
        from System.Drawing import Icon
        form = window.native

        def apply():
            form.Icon = Icon(str(ICON))
            api._hwnd = int(form.Handle.ToInt64())
            form.FormClosing += lambda sender, args: _let_windows_close(api, args)
            if background:
                api._hidden_once = True
                api.hide()

        form.Invoke(Action(apply))
    except Exception:
        log.exception("window setup failed")
    _start_resident(api)  # here: pywebview has loaded WinForms by now


if __name__ == "__main__":
    main()
