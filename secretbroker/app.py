"""SecretBroker desktop app (runs as the desktop user). Holds no secrets: it talks to the service."""

import base64
import ctypes
import inspect
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__, cli, client, generator, i18n, integrations, links, native_host, paths, platform, resident, scanner, templates
from .client import BrokerError, BrokerUnavailable
from .i18n import tr

hello = platform.biometric  # Windows Hello, Touch ID on macOS; on Linux is_supported() is False (TODO: fprintd)
WEB_DIR = Path(__file__).with_name("web")
ICON = Path(__file__).with_name("assets") / ("icon.ico" if platform.NAME == "windows" else "icon.png")
CLIPBOARD_CLEAR_SECONDS = 30
AUTO_SCAN_HOURS = 12
SESSION_FILE = client.SESSION_FILE  # the same file client.reopen_with_session reads
SESSION_ENTROPY = client.SESSION_ENTROPY
LOG_FILE = integrations.PREFS_FILE.parent / "app.log"
# An invite link (secretbroker://join?server=…&email=…&code=…) the app was opened with, until the page takes it.
JOIN_FILE = integrations.PREFS_FILE.parent / "join_link.json"
JOIN_LINK_MINUTES = 10
log = logging.getLogger("secretbroker.app")
BACKUP_EVERY_HOURS = 24
BACKUPS_KEPT = 10
# Team changes (see service.TEAM_CHANGE_OPS): one click too.
TEAM_CHANGE_OPS = ("team_connect", "team_disconnect", "team_create_org", "team_invite", "team_accept_invite",
                   "team_confirm_member", "team_set_role", "team_remove_member", "team_create_collection", "team_grant",
                   "team_revoke", "team_share_entry", "team_share_entries", "team_unshare_entry", "team_accept_change",
                   "team_verify_email", "team_send_code", "team_resolve_deletions", "team_share_with",
                   "team_unshare_with", "team_revoke_device", "team_change_password", "team_renew_invite",
                   "team_resend_invite", "team_drop_invite", "team_invite_code", "team_admin_backup_now",
                   "team_admin_settings", "team_admin_disable", "team_admin_enable", "team_admin_verify",
                   "team_admin_delete", "team_admin_transfer_owner", "team_admin_signup_token")
# What the app that unlocked may do with one click (see service.PRESENCE_OPS).
PRESENCE_OPS = ("approve", "complete_draft", "replace_key", "resume_ai", "set_ai_permissions", "backup", "restore",
                "import_file", "import_env_file", "export_vault") + TEAM_CHANGE_OPS
# Operations the service only accepts with a proof of identity.
PROOF_OPS = {"unlock", "approve", "save_entry", "delete_entry", "reveal", "rotate", "complete_draft",
             "enable_session_unlock", "resume_ai", "set_ai_permissions", "backup", "restore",
             "change_master_password", "set_settings", "remove_hello", "exposure_begin",
             "import_file", "import_env_file", "export_vault", *TEAM_CHANGE_OPS}
# Rotations (see service.ROTATION_OPS): one click too.
ROTATION_OPS = ("rotation_begin", "rotation_discard", "rotation_apply", "rotation_secret", "retry_uploads", "set_test_request")
PRESENCE_OPS += ROTATION_OPS
PROOF_OPS |= set(ROTATION_OPS)
# Everyday work (see service.PROVEN_OPS): one click after unlocking with a password or Hello; after opening with
# the Windows session, Hello or a password once.
PRESENCE_OPS += ("reveal", "save_entry", "delete_entry", "rotate", "set_settings", "exposure_begin", "enable_session_unlock")
# Proofs that bring the token along, so the service makes it one click for the rest of the session.
OPENING_OPS = ("unlock", "create_vault", "restore")
# A login's current 2FA code (see service.op_totp_code): one click too.
PRESENCE_OPS += ("totp_code",)
PROOF_OPS.add("totp_code")
# Connecting a browser to fill logins (see service.op_browser_pair_answer): one click too.
PRESENCE_OPS += ("browser_pair_answer",)
PROOF_OPS.add("browser_pair_answer")
# Browsers the extension supports: (id, name, executable, its extensions page). Chromium-based ones load the
# extension unpacked until it is in their stores; Firefox only temporarily, until it is on addons.mozilla.org.
BROWSERS = (("chrome", "Chrome", "chrome.exe", "chrome://extensions/"), ("edge", "Edge", "msedge.exe", "edge://extensions/"),
            ("brave", "Brave", "brave.exe", "brave://extensions/"),
            ("firefox", "Firefox", "firefox.exe", "about:debugging#/runtime/this-firefox"))
# Their commands on Linux (deb, snap and flatpak-exported names).
POSIX_BROWSER_COMMANDS = {"chrome.exe": ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"),
                          "msedge.exe": ("microsoft-edge", "microsoft-edge-stable"),
                          "brave.exe": ("brave-browser", "brave"), "firefox.exe": ("firefox",)}
# Where a secret found in clear may be removed in place (see exposure.REDACTABLE_SOURCES): conversations
# of Claude Code and Codex, and shell histories. A copy of the file is kept next to it, just in case.
REDACT_BACKUP_SUFFIX = ".secretbroker.bak"
REDACT_CHUNK_BYTES = 1024 * 1024


ALL_FILES = (None, "*.*")


def _file_types(*filters):
    """pywebview file dialog filters, «Label (*.a;*.b)», with the label in the app's language. pywebview takes only
    letters, digits and spaces in a label: an apostrophe becomes the letter apostrophe (ʼ, «dʼentorn»), any other
    sign a space. `filters`: (label, patterns); a None label is «All files»."""
    result = []
    for label, patterns in filters:
        label = tr("app.all_files") if label is None else label
        label = re.sub(r"['’]", "ʼ", label)
        label = " ".join(re.sub(r"[^\w ]", " ", label).split()) or "Files"
        result.append(f"{label} ({patterns})")
    return tuple(result)


# ----- only the app's own page may use the app
#
# pywebview gives every page its window loads the bridge to Python (window.pywebview.api), and the app adds its
# one-click presence token by itself. A link or an .html file dropped on the window, or anything else that makes
# it navigate, would load a page that could reveal, export, share or approve with it. So: the page refuses drops
# (app.js), each system's web view refuses external drops and other pages (_on_shown, _guard_qt_navigation), a
# foreign page that loads anyway is replaced by the app (_back_to_the_app), and every call from a page is refused
# unless the window shows the app's own page (page_api). Fail closed: an address that can't be read is refused.


def _same_page(url, expected):
    """Whether `url` is the app's own page (the address pywebview serves it at), fragment aside."""
    if not url or not expected:
        return False
    try:
        a, b = urlsplit(str(url)), urlsplit(str(expected))
    except ValueError:
        return False
    return (a.scheme, a.netloc, a.path, a.query) == (b.scheme, b.netloc, b.path, b.query)


def _shows_the_app(window):
    """Whether the window shows the app's page now. Asks the web view itself (each backend's own get_current_url;
    pywebview's Window.get_current_url would wait for a page load)."""
    try:
        return _same_page(window.gui.get_current_url(window.uid), window.real_url)
    except Exception:
        return False


def page_api(api, window=None):
    """What the page gets as window.pywebview.api: every public method of `api`, with the same arguments (pywebview
    builds the page's functions from them), refused with PermissionError while the window shows another page."""
    def expose(name, function):
        def method(self, *args, **kwargs):
            shown = window or api._window
            if shown is None or not _shows_the_app(shown):
                log.warning("a page that is not the app's called %s: refused", name)
                raise PermissionError("Only SecretBroker's own page can use it.")
            return getattr(api, name)(*args, **kwargs)
        method.__name__ = name
        method.__signature__ = inspect.signature(function)
        return method

    methods = {name: expose(name, function) for name, function in vars(type(api)).items()
               if not name.startswith("_") and callable(function)}
    return type("PageApi", (), methods)()


def _back_to_the_app(window):
    """A page that is not the app's loaded anyway (the web view let a navigation through): show the app again."""
    if window.real_url and not _shows_the_app(window):
        log.warning("the window navigated away from the app: loading the app again")
        try:
            window.load_url(window.real_url)
        except Exception:
            log.exception("could not load the app again")


def _guard_qt_navigation(window):
    """Linux (Qt): the page never navigates the window anywhere but the app's own page. Set before the window
    exists, on pywebview's page class (a reimplementation of QWebEnginePage.acceptNavigationRequest)."""
    from webview.platforms import qt
    page_class = qt.BrowserView.WebPage
    original = page_class.acceptNavigationRequest

    def accept(self, url, kind, main_frame):
        if main_frame and not _same_page(url.toString(), window.real_url):
            log.warning("a navigation away from the app was refused")
            return False
        return original(self, url, kind, main_frame)

    page_class.acceptNavigationRequest = accept


def _refuse_drops(window):
    """The web view takes no drops from outside the window: a dropped link or file would open in it. Windows:
    WebView2's AllowExternalDrop, and every navigation to another page is cancelled. Linux: Qt widgets that don't
    accept drops. macOS: the WKWebView stops taking dragged types. Run on the window's UI thread."""
    if platform.NAME == "windows":
        view = window.native.webview
        view.AllowExternalDrop = False

        def starting(_sender, args):
            if not _same_page(str(args.Uri), window.real_url):
                log.warning("a navigation away from the app was cancelled")
                args.Cancel = True
        view.NavigationStarting += starting
    elif platform.NAME == "linux":
        from qtpy.QtWidgets import QWidget
        native = window.native
        for widget in [native, native.webview, *native.webview.findChildren(QWidget)]:
            widget.setAcceptDrops(False)
    elif platform.NAME == "macos":
        from webview.platforms.cocoa import BrowserView
        BrowserView.instances[window.uid].webview.unregisterDraggedTypes()


class Api:
    """Methods exposed to the web UI as window.pywebview.api.* (through page_api)."""

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
                "start_with_windows": resident.start_with_windows(), "session_unlock_here": self.has_session_unlock(),
                "os": platform.NAME, "os_label": platform.OS_LABEL, "biometric_label": getattr(hello, "LABEL", "Windows Hello"),
                "languages": i18n.available()}

    def set_pref(self, key, value):
        if key in ("palette", "auto_scan", "scan_folders") or (key == "language" and (value is None or i18n.valid(value))):
            integrations.set_pref(key, value)
        return True

    # ----- language (see docs/I18N.md)

    def locale(self, code):
        """The page's messages in `code` (web/locales/<code>.json), or None."""
        return i18n.page_catalog(code)

    def set_language(self, code):
        """The language the page shows: the app's own texts follow it (the service's answers, the icon next to
        the clock). Returns what info() has that depends on it."""
        if i18n.valid(code):
            i18n.set_default(code)
            client.LANG = code
        return {"templates": templates.export(), "providers": links.catalog()}

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

    def ai_clients(self):
        """Every AI app the app can connect ({id, label, status}) with when it last used SecretBroker
        (`last`, `requests`), and `others`: programs that used it and the app doesn't know by name."""
        try:
            used = client.request("ai_clients", timeout=10)
        except (BrokerError, BrokerUnavailable):
            used = []
        apps = integrations.clients()
        by_id, others = {}, []
        for record in used:  # newest first
            client_id = integrations.client_of(record.get("name"))
            if client_id is None:
                others.append({"label": record.get("name"), "last": record.get("last"), "requests": record.get("requests", 0)})
            elif client_id not in by_id:
                by_id[client_id] = record
            else:
                by_id[client_id] = {**by_id[client_id], "requests": by_id[client_id].get("requests", 0) + record.get("requests", 0)}
        for app in apps:
            record = by_id.get(app["id"]) or {}
            app.update(last=record.get("last"), requests=record.get("requests", 0))
        return {"ok": True, "result": {"clients": apps, "others": others}}

    def connect_ai(self, client_id):
        return self._integration(lambda: integrations.connect(client_id))

    def totp_code(self, entry_id, copy=False, auto=False, proof=None):
        """A login's current 2FA code: shown (the code, for this moment) or copied to the clipboard.
        `auto` (the detail refreshing it by itself) never asks for Hello or a password: it answers
        proof_required and the page shows «Mostrar» instead."""
        params = {"id": entry_id, "copy": bool(copy)}
        if auto:
            if not self._presence:
                return {"ok": False, "code": "proof_required", "error": tr("app.verify_your_identity")}
            try:
                result = client.request("totp_code", {**params, "proof": {"kind": "presence", "token": self._presence}})
            except BrokerError as exc:
                return {"ok": False, "code": exc.code, "error": str(exc)}
            except BrokerUnavailable as exc:
                return {"ok": False, "code": "unavailable", "error": str(exc)}
            result = {"ok": True, "result": result}
        else:
            result = self.call("totp_code", params, proof)
        if result["ok"]:
            presence = result["result"].pop("presence", None)
            if presence:
                self._presence = presence  # proved it: one click again from now on
            if copy:
                _copy_to_clipboard(result["result"].pop("code"))
                result["result"]["clear"] = CLIPBOARD_CLEAR_SECONDS
        return result

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
            weak = False  # opened with the Windows session: sharing with others needs Hello or a password once
            if op in PRESENCE_OPS and proof is None and self._presence:
                try:
                    return {"ok": True, "result": client.request(op, {**params, "proof": {"kind": "presence", "token": self._presence}})}
                except BrokerError as exc:
                    if exc.code == "proof_required":
                        weak = True
                    elif exc.code != "proof_invalid":
                        raise
                    else:
                        self._presence = None
                        # Locked and opened again meanwhile (inactivity, then the AI with the Windows session): take
                        # a token the same way instead of asking for a password.
                        if not getattr(self, "_reopening", False) and SESSION_FILE.exists() \
                                and client.request("status", timeout=10)["state"] == "unlocked":
                            self._reopening = True
                            try:
                                if self.session_unlock():
                                    return self.call(op, params, proof)
                            finally:
                                self._reopening = False
            if (op in PROOF_OPS or weak) and proof is None:
                status = client.request("status", timeout=10)
                if not (status["hello_enrolled"] and hello.is_supported()):
                    # `weak`: opened with the Windows session, so the page says this is asked once.
                    return {"ok": False, "code": "proof_required", "error": tr("app.verify_your_identity"), "weak": weak}
                proof = self._hello_proof(op, params)
            if proof is not None:
                params["proof"] = proof
                if op not in OPENING_OPS and proof.get("kind") in ("hello", "windows_password", "master_password"):
                    params["proof"] = {**proof, "presence": self._presence}
            meta = {}
            result = client.request(op, params, meta=meta)
            if meta.get("presence"):
                self._presence = meta["presence"]  # proved it once: one click for the rest of the session
            if op in ("unlock", "exposure_begin", "restore", "create_vault") and isinstance(result, dict):
                self._scan_session = result.pop("exposure_session", None) or result.get("session") or self._scan_session
            if (op in ("unlock", "approve", "restore", "create_vault") or op in TEAM_CHANGE_OPS) \
                    and isinstance(result, dict) and result.get("presence"):
                self._presence = result.pop("presence")
            return {"ok": True, "result": result}
        except hello.HelloCancelled:
            return {"ok": False, "code": "hello_cancelled", "error": tr("app.verification_cancelled")}
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

    def exposure_report(self, background=False):
        session = self._scan_session
        result = self.call("exposure_report", {"session": session, **({"_poll": True} if background else {})})
        if result["ok"] and not result["result"]["details"]:
            self._forget_scan_session(session)
        return result

    def _forget_scan_session(self, session):
        """The service no longer knows `session`: forget it, unless it has been replaced meanwhile. A scan renews
        the session as it begins (scanner.Scan, on_session), so a report or a scan that went out with the old one
        and answers late must not clear the new one: the page would then ask who you are again, and anything done
        in Salud meanwhile («Borrar de este archivo», «Ignorar») would be refused."""
        if session is not None and self._scan_session == session:
            self._scan_session = None

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
                self._forget_scan_session(scan.session)

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
        """Show a file where a secret was found in Explorer (Linux: the file manager)."""
        path = Path(location[4:] if location.startswith("git:") else location)
        if location.startswith("env:") or not path.exists():
            return False
        platform.show_in_folder(path)
        return True

    def ignore_finding(self, entry_id, location, ignore=True):
        """Ignore one place where a secret was found (kept by the service with the finding)."""
        return self.call("exposure_ignore", {"session": self._scan_session, "id": entry_id, "location": location,
                                             "ignore": bool(ignore)})

    def redact_finding(self, entry_id, location):
        """Remove a secret from a Claude Code / Codex conversation or a shell history, in place. This app
        reads the file (the service account cannot) and the service returns it with the secret replaced:
        the value never reaches this process or the page. A copy is left next to it (…secretbroker.bak)."""
        path = Path(str(location))
        if not self._scan_session:
            return {"ok": False, "code": "session_expired", "error": tr("service.verify_your_identity_see_which")}
        if not _redactable(path):
            return {"ok": False, "code": "invalid", "error": tr("app.this_file_can_be_edited")}
        for _ in range(3):  # Claude Code may be writing to its conversation: start again if it changed meanwhile
            try:
                before = path.stat()
                data = path.read_bytes()
            except OSError as exc:
                return {"ok": False, "code": "error", "error": tr("app.couldn_read_file", value=exc.strerror or exc)}
            parts, count, start = [], 0, 0
            while start < len(data):
                end = min(len(data), start + REDACT_CHUNK_BYTES)
                newline = data.rfind(b"\n", start, end) if end < len(data) else -1
                end = newline + 1 if newline > start else end  # whole lines: a secret is never split
                result = self.call("exposure_redact", {"session": self._scan_session, "id": entry_id, "location": str(path),
                                                       "data": base64.b64encode(data[start:end]).decode("ascii")})
                if not result["ok"]:
                    return result
                parts.append(base64.b64decode(result["result"]["data"]))
                count += result["result"]["count"]
                start = end
            if count:
                try:
                    if path.stat().st_mtime_ns != before.st_mtime_ns or path.stat().st_size != before.st_size:
                        continue
                    backup = path.with_name(path.name + REDACT_BACKUP_SUFFIX)
                    backup.write_bytes(data)
                    temporary = path.with_name(path.name + ".secretbroker.tmp")
                    temporary.write_bytes(b"".join(parts))
                    os.replace(temporary, path)
                except OSError as exc:
                    path.with_name(path.name + ".secretbroker.tmp").unlink(missing_ok=True)
                    return {"ok": False, "code": "error", "error": tr("app.couldn_write_file_it_may", value=exc.strerror or exc)}
            done = self.call("exposure_redacted", {"session": self._scan_session, "id": entry_id, "location": str(path),
                                                   "count": count})
            if done["ok"]:
                done["result"] = {"count": count, "report": done["result"],
                                  "backup": str(path.with_name(path.name + REDACT_BACKUP_SUFFIX)) if count else None}
            return done
        return {"ok": False, "code": "busy", "error": tr("app.file_keeps_changing_is_conversation")}

    def delete_redaction_backup(self, location):
        """Delete a copy left by redact_finding, once the user is happy with the result."""
        path = Path(str(location))
        if not path.name.endswith(REDACT_BACKUP_SUFFIX) or not _redactable(path.with_name(path.name[:-len(REDACT_BACKUP_SUFFIX)])):
            return False
        existed = path.exists()
        path.unlink(missing_ok=True)
        return existed

    def copy_rotation_secret(self, entry_id, what="value", proof=None):
        """Copy the new password of a rotation in progress (or the command that sets it) to the clipboard;
        the page never gets it."""
        result = self.call("rotation_secret", {"id": entry_id, "what": what}, proof)
        if result["ok"]:
            _copy_to_clipboard(result.pop("result"))
            result["result"] = CLIPBOARD_CLEAR_SECONDS
        return result

    def update_status(self, force=False):
        return self.call("update_status", {"force": bool(force)})

    def install_update(self):
        """Download and verify the new version (in the service), then run its installer.
        The system asks for administrator consent (UAC, polkit). Windows' installer closes this app and reopens
        it; on Linux apt installs the package and the app starts again by itself."""
        result = self.call("update_download", {})
        if not result["ok"]:
            return result
        try:
            after = platform.run_installer(result["result"]["path"])
        except platform.InstallCancelled:
            return {"ok": False, "code": "cancelled", "error": tr("app.cancelled")}
        except OSError as exc:
            return {"ok": False, "code": "error", "error": tr("app.couldn_open_installer", exc=exc)}
        if after == "restart":
            threading.Timer(1.5, self._restart).start()
        return {"ok": True, "result": result["result"]["version"]}

    def _restart(self):
        """Start the newly installed version, then quit: it takes over once this instance is gone."""
        restart = getattr(platform, "restart_command", None)  # macOS: the bundle, through Launch Services
        platform.spawn_detached(restart() if restart else
                                ["/bin/sh", "-c", 'sleep 2; exec "$0" -I -m secretbroker.app', platform.python_gui()])
        self.quit()

    # ----- browser extension (see native_host.py)

    def browser_info(self):
        """For Ajustes › Navegador: the browsers connected (from the service), which browsers are installed and can
        start the native host, and the extension's folder (to load it until it is in the stores)."""
        try:
            status = client.request("browser_status", timeout=10)
        except (BrokerError, BrokerUnavailable):
            status = {"paired": [], "pending": []}
        registered = native_host.registered()
        folder = native_host.extension_dir()
        return {"ok": True, "result": {
            **status, "extension_dir": str(folder) if folder else None,
            "browsers": [{"id": b, "name": name, "installed": bool(_browser_exe(exe)), "registered": registered.get(b, False)}
                         for b, name, exe, _ in BROWSERS]}}

    def open_browser_page(self, browser_id):
        """Open a browser on its extensions page (a page the default browser can't be told to open)."""
        for b, _, exe, page in BROWSERS:
            path = _browser_exe(exe) if b == browser_id else None
            if path:
                subprocess.Popen([path, page], close_fds=True)
                return True
        return False

    def show_extension_folder(self):
        folder = native_host.extension_dir()
        if not folder:
            return False
        platform.show_in_folder(folder)
        return True

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
            return {"ok": False, "code": "hello_cancelled", "error": tr("app.verification_cancelled")}
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
        if platform.NAME != "windows":
            if self._window:  # pywebview (Qt) shows it from its own thread; never wait for it here
                threading.Thread(target=self._show_portable, daemon=True).start()
            return
        if not self._hwnd:
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

    def _show_portable(self):
        try:
            self._window.show()
            self._window.restore()
        except Exception:
            log.exception("show window")

    def focus(self):
        self._bring_to_front()
        return True

    # ----- living in the background

    def show(self):
        self._bring_to_front(activate=True)
        if self._window and JOIN_FILE.exists():  # opened again with an invite link
            try:
                self._window.evaluate_js("window.onJoinLink && window.onJoinLink()")
            except Exception:
                log.exception("invite link")

    def take_join_link(self):
        """The invite link this app was opened with (once), or None. It only fills in the team form."""
        try:
            data = json.loads(JOIN_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        finally:
            JOIN_FILE.unlink(missing_ok=True)
        if not isinstance(data, dict) or time.time() - float(data.get("at") or 0) > JOIN_LINK_MINUTES * 60:
            return None
        return {k: data.get(k) or "" for k in ("server", "email", "code")}

    def hide(self):
        if platform.NAME != "windows" and self._window:
            if not (self._tray and self._tray.available):
                # No icon next to the clock (GNOME without the AppIndicator extension): a hidden window could
                # not be found again, so it stays in the dock, minimized, still answering the AI.
                threading.Thread(target=self._window.minimize, daemon=True).start()
                return
            threading.Thread(target=self._window.hide, daemon=True).start()
        elif self._hwnd and sys.platform == "win32":
            ctypes.windll.user32.ShowWindowAsync(ctypes.c_void_p(self._hwnd), 0)  # SW_HIDE
        else:
            return
        if not self._hidden_once and self._tray:
            self._hidden_once = True
            self._tray.notify(tr("app.secretbroker_is_still_running"), tr("app.it_next_clock_serve_ai"))

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
            return {"ok": False, "error": tr("app.choose_folder_first")}
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
            return {"ok": False, "error": tr("app.couldn_write", folder=folder, value=exc.strerror or exc)}
        integrations.set_pref("last_backup", datetime.now().isoformat(timespec="seconds"))
        return {"ok": True, "result": {"entries": result["result"]["entries"]}}

    def pick_backup_file(self):
        import webview
        folder = integrations.load_prefs().get("backup_folder") or str(_default_backup_folder())
        chosen = self._window.create_file_dialog(webview.OPEN_DIALOG, directory=folder if Path(folder).is_dir() else "",
                                                 file_types=_file_types((tr("app.backup_files"), "*.sbbackup"), ALL_FILES)) if self._window else None
        return chosen[0] if chosen else None

    def restore_backup(self, path, master_password, proof=None):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return {"ok": False, "error": tr("app.couldn_read_file_2", exc=exc)}
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
        token = client.session_token()
        if not token:
            return False
        result = self.call("unlock", {}, {"kind": "session", "token": token})
        if not result["ok"] and result.get("code") == "proof_invalid":
            SESSION_FILE.unlink(missing_ok=True)  # the service forgot it (turned off elsewhere)
        return result["ok"]

    def enable_session_unlock(self, proof=None):
        result = self.call("enable_session_unlock", {}, proof)
        if result["ok"]:
            SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
            SESSION_FILE.write_bytes(platform.protect_for_user(result.pop("result")["token"].encode(), SESSION_ENTROPY))
        return result

    def disable_session_unlock(self):
        SESSION_FILE.unlink(missing_ok=True)
        return self.call("disable_session_unlock")

    def resume_ai(self):
        return self._presence is not None and self.call("resume_ai")["ok"]

    # ----- password generator, import and export

    _import_path = None  # the file last imported from, which the user may then delete

    def generate_password(self, options=None):
        try:
            return {"ok": True, "result": generator.generate(options)}
        except generator.GeneratorError as exc:
            return {"ok": False, "code": "invalid", "error": str(exc)}

    def copy_generated(self, value):
        """Copy a password from the generator like a secret: out of the clipboard history, cleared in 30 s."""
        _copy_to_clipboard(str(value))
        return CLIPBOARD_CLEAR_SECONDS

    def pick_import_file(self):
        import webview
        chosen = self._window.create_file_dialog(webview.OPEN_DIALOG, directory=str(Path.home() / "Downloads"), file_types=_file_types(
            (tr("app.manager_exports"), "*.csv;*.json;*.sbexport"), ALL_FILES)) if self._window else None
        return chosen[0] if chosen else None

    def import_file(self, path, fmt="auto", selected=None, password=None, proof=None):
        """Read another manager's export and hand its text to the service (this app holds no secrets:
        the service answers with names only). `selected` None: preview."""
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            return {"ok": False, "code": "invalid", "error": tr("app.couldn_read_file", value=exc.strerror or exc)}
        if len(data) > 3 * 1024 * 1024:
            return {"ok": False, "code": "invalid", "error": tr("app.file_is_too_big_3")}
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")  # old KeePass / Excel CSVs
        params = {"content": text, "source": Path(path).name, "format": fmt, "selected": selected, "password": password or None}
        result = self.call("import_file", params, proof)
        if result["ok"]:
            self._import_reading = str(path)
            if selected is not None:
                self._import_path = str(path)
        return result

    def import_batch(self, import_id, selected, done=False, proof=None):
        """Import part of a previewed file (the service kept its plan): the page sends a few hundred at a
        time to show progress, and the vault is saved once per batch."""
        result = self.call("import_file", {"import_id": import_id, "selected": list(selected or []), "done": bool(done)}, proof)
        if result["ok"]:
            self._import_path = getattr(self, "_import_reading", None)
        return result

    def delete_import_source(self):
        """Delete the file just imported: it holds every password in clear."""
        if not self._import_path:
            return {"ok": False, "error": tr("app.there_no_file_delete")}
        try:
            Path(self._import_path).unlink(missing_ok=True)
        except OSError as exc:
            return {"ok": False, "error": tr("app.couldn_delete", value=exc.strerror or exc)}
        self._import_path = None
        return {"ok": True}

    # ----- a project's .env («Importar un .env»): picked, previewed and imported here, no terminal

    _env_plan = None   # the file being imported: its path, the keys (with values, never sent to the page)…
    _env_done = None   # …and, once imported, the lines that may be taken out of it

    def pick_env_file(self):
        import webview
        if not self._window:
            return None
        patterns = "*.env;*.local;*.development;*.production;*.staging;*.test;*.example"
        chosen = self._window.create_file_dialog(webview.OPEN_DIALOG, directory=str(Path.home()), file_types=_file_types(
            (tr("app.env_files"), patterns), ALL_FILES))
        return chosen[0] if chosen else None

    def env_preview(self, path):
        """The variables of a .env, by name only: which look like keys (ticked to start with), the credential each
        would become, and the id it goes with. The values stay in this process until the import."""
        try:
            env_path = Path(path).resolve()
            if env_path.stat().st_size > 1024 * 1024:
                return {"ok": False, "code": "invalid", "error": tr("app.file_is_too_big_1")}
            items, left, project = cli.plan_env(env_path, everything=True)
        except (OSError, UnicodeError) as exc:
            return {"ok": False, "code": "invalid", "error": tr("app.couldn_read_file", value=getattr(exc, "strerror", None) or exc)}
        self._env_plan = {"path": env_path, "project": project, "items": {i["var"]: i for i in items}}
        self._env_done = None
        return {"ok": True, "result": {
            "name": env_path.name, "folder": str(env_path.parent), "project": project, "empty": left,
            "vars": [{"var": i["var"], "id": i["id"], "key": cli.looks_secret(i["var"], i["value"]),
                      "paired_var": i.get("paired_var")} for i in items]}}

    def env_import(self, selected, proof=None):
        """Import the ticked variables (one click with the app's token), then note them in the project's
        .secretbroker (names, no values) so the AI and `sb run` can hand them to the project's programs."""
        plan = self._env_plan
        if not plan:
            return {"ok": False, "code": "invalid", "error": tr("app.choose_env_file_again")}
        items = [plan["items"][var] for var in selected or [] if var in plan["items"]]
        params = {"source": str(plan["path"]), "project": cli.slug(plan["project"])[:30],
                  "items": [{k: v for k, v in item.items() if k != "line"} for item in items]}
        result = self.call("import_env_file", params, proof)
        if not result["ok"]:
            return result
        done = result["result"]
        mapped = {i["var"]: i["id"] for i in done["created"] + done["skipped"]}
        try:
            config = cli.write_config(plan["path"], mapped)
        except OSError:
            config = None  # a read-only folder: the credentials are in the vault all the same
        self._env_plan = None
        self._env_done = {"path": plan["path"], "lines": {plan["items"][var]["line"] for var in mapped}}
        return {"ok": True, "result": {**done, "config": str(config) if config else None, "name": plan["path"].name}}

    def env_remove_keys(self):
        """Take the imported keys out of the .env (the other variables stay), or delete it if nothing is left."""
        done = self._env_done
        if not done:
            return {"ok": False, "error": tr("app.there_no_file_delete")}
        try:
            how = cli.remove_from_env(done["path"], done["lines"])
        except (OSError, UnicodeError) as exc:
            return {"ok": False, "error": tr("app.couldn_delete", value=getattr(exc, "strerror", None) or exc)}
        self._env_done = None
        return {"ok": True, "result": how}

    def export_vault(self, fmt, password=None, proof=None):
        """Ask where to save, have the service build the file and write it there."""
        import webview
        plain = tr("app.export_unencrypted_file_name")
        names = {"encrypted": (tr("app.export_encrypted_file_name") + ".sbexport", (tr("app.export_encrypted_file_type"), "*.sbexport")),
                 "json": (plain + ".json", ("JSON", "*.json")), "csv": (plain + ".csv", ("CSV", "*.csv"))}
        if fmt not in names:
            return {"ok": False, "code": "invalid", "error": tr("app.invalid_format")}
        chosen = self._window.create_file_dialog(webview.SAVE_DIALOG, directory=str(Path.home() / "Documents"),
                                                 save_filename=names[fmt][0], file_types=_file_types(names[fmt][1])) if self._window else None
        if not chosen:
            return {"ok": False, "code": "cancelled", "error": tr("app.cancelled")}
        target = Path(chosen if isinstance(chosen, str) else chosen[0])
        result = self.call("export_vault", {"format": fmt, "password": password or None}, proof)
        if not result["ok"]:
            return result
        try:
            target.write_text(result["result"].pop("content"), encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "code": "error", "error": tr("app.couldn_write_2", target=target, value=exc.strerror or exc)}
        return {"ok": True, "result": {"path": str(target), "entries": result["result"]["entries"]}}


def _browser_exe(name):
    """The full path of an installed browser (chrome.exe, msedge.exe…), or None. Browsers register it in App Paths."""
    if sys.platform != "win32":
        names = POSIX_BROWSER_COMMANDS.get(name, (name.removesuffix(".exe"),))
        return next((path for path in map(shutil.which, names) if path), None)
    import winreg
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{name}") as key:
                path = str(winreg.QueryValueEx(key, "")[0]).strip('"')
            if Path(path).is_file():
                return path
        except OSError:
            continue
    return None


def _redactable(path):
    """Is this one of the AI conversations or shell histories the scan reads (text, not a database)?"""
    try:
        target = path.resolve()
        return any(source in ("ai", "history") and found.suffix.lower() in (".jsonl", ".txt", "") and found.resolve() == target
                   for source, found in scanner.fixed_files())
    except (OSError, ValueError):
        return False


def _default_backup_folder():
    """OneDrive if the user has it (a copy outside this PC), otherwise Documents."""
    onedrive = os.environ.get("OneDrive")
    base = Path(onedrive) if onedrive and Path(onedrive).is_dir() else Path.home() / "Documents"
    return base / "SecretBroker"


# ----------------------------------------------------------------- clipboard


def _copy_to_clipboard(text, auto_clear=True):
    """Secrets stay out of clipboard history (and Windows' cloud clipboard) and are cleared after a while."""
    platform.copy_to_clipboard(text, auto_clear, CLIPBOARD_CLEAR_SECONDS)


# ----------------------------------------------------------------- entry point


def parse_join_link(text):
    """{server, email, code} from secretbroker://join?server=…&email=…&code=…, or None. Only values that look
    right: it comes from outside (a web page can open such a link), and it only ever fills in a form."""
    try:
        parts = urlsplit(str(text or "").strip())
        query = parse_qs(parts.query, max_num_fields=10)
    except ValueError:
        return None
    if parts.scheme.lower() != "secretbroker" or (parts.netloc or parts.path.strip("/")).lower() != "join":
        return None
    value = lambda name: (query.get(name) or [""])[0].strip()
    server, email, code = value("server"), value("email").lower(), value("code")
    try:
        target = urlsplit(server if "://" in server else "https://" + server)
    except ValueError:
        return None
    if not server or len(server) > 300 or target.scheme not in ("https", "http") or not target.hostname \
            or target.username or target.password:
        return None
    if len(email) > 254 or (email and ("@" not in email or any(c.isspace() for c in email))):
        email = ""
    if len(code) > 200 or not all(c.isalnum() or c in "-_." for c in code):
        code = ""
    return {"server": server, "email": email, "code": code}


def _keep_join_link(argv):
    """Opened from an invite link (the installer registers secretbroker://): keep it for the page."""
    link = next((a for a in argv if a.lower().startswith("secretbroker:")), None)
    data = parse_join_link(link) if link else None
    if not data:
        return
    try:
        JOIN_FILE.parent.mkdir(parents=True, exist_ok=True)
        JOIN_FILE.write_text(json.dumps({**data, "at": time.time()}), encoding="utf-8")
    except OSError:
        pass


def _single_instance():
    return platform.single_instance()


def main():
    import webview

    _keep_join_link(sys.argv[1:])
    if not _single_instance():
        resident.signal_running_instance()
        return
    _start_logging()
    language = integrations.load_prefs().get("language")
    i18n.set_default(language if i18n.valid(language) else i18n.system_language())  # until the page says
    client.LANG = i18n.language()
    background = "--background" in sys.argv
    # Keep the page running at full speed while hidden: it answers the AI's requests.
    os.environ.setdefault("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                          "--disable-background-timer-throttling --disable-renderer-backgrounding "
                          "--disable-backgrounding-occluded-windows --disable-features=CalculateNativeWinOcclusion")
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-background-timer-throttling "
                          "--disable-renderer-backgrounding --disable-backgrounding-occluded-windows")
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecretBroker.App")
        except Exception:
            pass
    api = Api()
    window = webview.create_window(
        "SecretBroker", url=str(WEB_DIR / "index.html"), js_api=page_api(api),
        width=1120, height=740, min_size=(880, 600), background_color="#0f1115", minimized=background,
    )
    api._window = window
    window.events.loaded += lambda: _back_to_the_app(window)
    if platform.NAME == "linux":
        _step("navigation guard", lambda: _guard_qt_navigation(window))
    window.events.shown += lambda: _on_shown(window, api, background)
    # Closing the window keeps the app next to the clock, where it can answer the AI; "Salir" quits.
    window.events.closing += lambda: True if api._quitting else (api.hide() or False)
    # WebView2 would otherwise try to write next to python.exe (read-only under Program Files).
    storage = paths.user_dir() / "webview"
    if platform.NAME == "macos":
        _step("invite links", lambda: _listen_for_links(api))
    if platform.NAME == "linux":
        # Qt: the tray icon (QSystemTrayIcon) and the clipboard live on the same GUI thread (see platform.linux.gui_call).
        webview.start(private_mode=True, storage_path=str(storage), gui="qt", icon=str(ICON))
    else:
        webview.start(private_mode=True, storage_path=str(storage))
    _exit_after_window()


def _exit_after_window():
    """The window loop is over («Salir», or the system ending the session): end the process now. pywebview runs
    every call from the page in a thread of its own that is not a daemon, and such a call (a status poll, «Salir»
    itself handing back its answer) may be waiting for the window's UI thread, which is gone (Qt: get_current_url
    and evaluate_js wait on a semaphore only the UI thread releases). Python would wait for those threads forever
    at exit, leaving the app running with no window: «Salir» sometimes did not quit on Linux."""
    stuck = [t.name for t in threading.enumerate() if t is not threading.current_thread() and not t.daemon and t.is_alive()]
    log.info("window closed: quitting%s", f" ({len(stuck)} page calls left unanswered)" if stuck else "")
    logging.shutdown()
    os._exit(0)


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
    args = ["invite-link" if a.lower().startswith("secretbroker:") else a for a in sys.argv[1:]]  # no codes in logs
    log.info("SecretBroker %s started (%s)", __version__, " ".join(args) or "window")
    if os.environ.get("SECRETBROKER_THREAD_DUMPS") and hasattr(signal, "SIGUSR1"):
        # Tests: SIGUSR1 writes every thread's stack to app-threads.log (tests/test_gui.py, when the app hangs).
        import faulthandler
        global _thread_dumps
        _thread_dumps = open(LOG_FILE.with_name("app-threads.log"), "w", encoding="utf-8")
        faulthandler.register(signal.SIGUSR1, file=_thread_dumps, all_threads=True)


def _step(name, action):
    try:
        action()
        log.info("%s: ok", name)
    except Exception:
        log.exception("%s failed", name)


def _start_resident(api):
    if api._tray or getattr(api, "_resident", False):
        return
    api._resident = True
    api._tray = resident.make_tray(api, ICON)
    _step("show event", lambda: resident.listen_for_show(api.show))
    if api._tray:
        _step("tray icon", api._tray.start)

    def watch():
        watcher = resident.Watcher(api, on_status=api._tray.update if api._tray else None)
        watcher.notify = api._tray.notify if api._tray else platform.notify
        watcher.start()

    _step("watcher", watch)
    _step("MCP over HTTP", lambda: resident.serve_mcp(api.show))
    if not paths.instance_suffix():  # never a test instance: it would point the browsers at it
        threading.Thread(target=lambda: _step("browser extension host", native_host.register), daemon=True).start()
    if paths.is_installed():
        _step("start with the session", lambda: resident.set_start_with_windows(resident.start_with_windows()))
    threading.Thread(target=lambda: _step("Claude Code connection", integrations.upgrade_claude_code), daemon=True).start()


def _let_windows_close(api, args):
    """Hiding instead of closing must not block signing out or shutting down Windows. Runs after
    pywebview's own handler, which may have cancelled the close."""
    from System.Windows.Forms import CloseReason
    if args.CloseReason in (CloseReason.WindowsShutDown, CloseReason.TaskManagerClosing):
        api._quitting = True
        args.Cancel = False


def _reopen_from_dock(api):
    """macOS: closing hides the window (the app keeps answering the AI); clicking the Dock icon brings it back,
    as Mac apps do, and quitting the app (Cmd+Q, the Dock, log out) quits it. pywebview's application delegate does
    not handle the first and refuses the second while the window only hides, so both are set on its class."""
    import objc
    from AppKit import NSApplication

    def reopen(self, _app, _visible):
        threading.Thread(target=api.show, daemon=True).start()
        return True

    def terminate(self, _app):
        # Quit from the app menu (Cmd+Q) or the Dock, logging out or shutting down: the app quits. pywebview asks
        # the window's closing handler, which only hides the window, and macOS reported that SecretBroker had
        # cancelled the log out. Only the window's close button keeps it running (like _let_windows_close).
        api._quitting = True
        return 1  # NSTerminateNow

    delegate = NSApplication.sharedApplication().delegate()
    if delegate is not None:
        cls = type(delegate)
        objc.classAddMethods(cls, [
            objc.selector(reopen, selector=b"applicationShouldHandleReopen:hasVisibleWindows:", signature=b"Z@:@Z")])
        # The same signature as pywebview's own method (its type encoding differs between PyObjC versions).
        existing = getattr(cls, "applicationShouldTerminate_", None)
        signature = getattr(existing, "signature", None) or b"Q@:@"
        objc.classAddMethods(cls, [objc.selector(terminate, selector=b"applicationShouldTerminate:", signature=signature)])


_link_handler = None  # macOS: kept alive for as long as the app runs


def _listen_for_links(api):
    """macOS hands secretbroker:// links to the app as an Apple event (kAEGetURL), not on the command line:
    also when it starts the app for one. Registered before the run loop starts, so that first one arrives."""
    global _link_handler
    import objc
    from Foundation import NSAppleEventManager, NSObject

    get_url = int.from_bytes(b"GURL", "big")  # kInternetEventClass and kAEGetURL
    direct_object = int.from_bytes(b"----", "big")  # keyDirectObject

    class SecretBrokerLinkHandler(NSObject):
        @objc.typedSelector(b"v@:@@")
        def handleURL_withReply_(self, event, _reply):
            link = event.paramDescriptorForKeyword_(direct_object).stringValue()
            _keep_join_link([str(link or "")])
            threading.Thread(target=api.show, daemon=True).start()

    _link_handler = SecretBrokerLinkHandler.alloc().init()
    NSAppleEventManager.sharedAppleEventManager().setEventHandler_andSelector_forEventClass_andEventID_(
        _link_handler, b"handleURL:withReply:", get_url, get_url)


def _on_shown(window, api, background=False):
    """pywebview has no icon option on Windows: set it on the underlying WinForms form. Also keep
    the window handle, to raise the window later without going through the UI thread."""
    if platform.NAME != "windows":
        if platform.NAME == "macos":
            _step("Dock icon reopens the window", lambda: _reopen_from_dock(api))
            from PyObjCTools import AppHelper
            AppHelper.callAfter(lambda: _step("no drops from outside", lambda: _refuse_drops(window)))
        else:
            from .platform import linux
            linux.gui_call(lambda: _step("no drops from outside", lambda: _refuse_drops(window)))
        _start_resident(api)  # first: hiding needs to know whether there is an icon next to the clock
        if background:
            api._hidden_once = True
            api.hide()
        return
    try:
        from System import Action
        from System.Drawing import Icon
        form = window.native

        def apply():
            form.Icon = Icon(str(ICON))
            api._hwnd = int(form.Handle.ToInt64())
            form.FormClosing += lambda sender, args: _let_windows_close(api, args)
            _step("no drops from outside", lambda: _refuse_drops(window))
            if background:
                api._hidden_once = True
                api.hide()

        form.Invoke(Action(apply))
    except Exception:
        log.exception("window setup failed")
    _start_resident(api)  # here: pywebview has loaded WinForms by now


if __name__ == "__main__":
    main()
