"""SecretBroker desktop app (runs as the desktop user). Holds no secrets: it talks to the service."""

import base64
import ctypes
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__, client, hello, integrations, links, paths, scanner, templates
from .client import BrokerError, BrokerUnavailable

WEB_DIR = Path(__file__).with_name("web")
ICON = Path(__file__).with_name("assets") / "icon.ico"
CLIPBOARD_CLEAR_SECONDS = 30
AUTO_SCAN_HOURS = 12
# Operations the service only accepts with a proof of identity.
PROOF_OPS = {"unlock", "approve", "save_entry", "delete_entry", "reveal", "rotate",
             "change_master_password", "set_settings", "remove_hello", "exposure_begin"}


class Api:
    """Methods exposed to the web UI as window.pywebview.api.*"""

    def __init__(self):
        self._window = None
        # Handed out by the service on unlock: lets this app scan files and see where secrets were found.
        # Kept here, never given to the page.
        self._scan_session = None
        self._scan = None

    # ----- generic bridge

    def info(self):
        return {"version": __version__, "installed": paths.is_installed(),
                "hello_supported": hello.is_supported(), "templates": templates.export(), "providers": links.catalog(),
                "prefs": integrations.load_prefs(), "integrations": integrations.status()}

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
            if op in PROOF_OPS and proof is None:
                status = client.request("status", timeout=10)
                if not (status["hello_enrolled"] and hello.is_supported()):
                    return {"ok": False, "code": "proof_required", "error": "Verifica tu identidad"}
                proof = self._hello_proof(op, params)
            if proof is not None:
                params["proof"] = proof
            result = client.request(op, params)
            if op in ("unlock", "exposure_begin") and isinstance(result, dict):
                self._scan_session = result.pop("exposure_session", None) or result.get("session") or self._scan_session
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

    def _bring_to_front(self):
        if self._window:
            try:
                self._window.restore()
                self._window.on_top = True
                self._window.on_top = False
            except Exception:
                pass

    def focus(self):
        self._bring_to_front()
        return True


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
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\SecretBrokerApp")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def main():
    import webview

    if not _single_instance():
        return
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecretBroker.App")
        except Exception:
            pass
    api = Api()
    window = webview.create_window(
        "SecretBroker", url=str(WEB_DIR / "index.html"), js_api=api,
        width=1120, height=740, min_size=(880, 600), background_color="#0f1115",
    )
    api._window = window
    window.events.shown += lambda: _set_window_icon(window)
    # WebView2 would otherwise try to write next to python.exe (read-only under Program Files).
    storage = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretBroker" / "webview"
    webview.start(private_mode=True, storage_path=str(storage))


def _set_window_icon(window):
    """pywebview has no icon option on Windows; set it on the underlying WinForms form."""
    try:
        from System import Action
        from System.Drawing import Icon
        form = window.native

        def apply():
            form.Icon = Icon(str(ICON))

        form.Invoke(Action(apply))
    except Exception:
        pass


if __name__ == "__main__":
    main()
