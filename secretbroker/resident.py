"""What keeps the desktop app useful while its window is hidden: the icon next to the clock, starting
with Windows, following the Windows session (lock / unlock), and serving the AI's tools over HTTP.

Serving the MCP tools from the app (instead of a process started by Claude Code) is what lets Claude
Code reconnect by itself after an update: the installer restarts the app and Claude Code retries a
dropped HTTP server, while a stdio server that was killed stays dead until the user runs /mcp.
"""

import asyncio
import ctypes
import hmac
import logging
import os
import sys
import threading
import time
from pathlib import Path

from . import client, integrations, paths
from .client import BrokerError, BrokerUnavailable

log = logging.getLogger("secretbroker.resident")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "SecretBroker"
SHOW_EVENT = "Local\\SecretBrokerShow" + paths.instance_suffix()
WATCH_SECONDS = 2


# ----------------------------------------------------------------- start with Windows


def startup_command():
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return f'"{pythonw if pythonw.exists() else sys.executable}" -I -m secretbroker.app --background'


def set_start_with_windows(enabled):
    if sys.platform != "win32":
        return
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError:
                pass


def start_with_windows():
    return integrations.load_prefs().get("start_with_windows", paths.is_installed())


# ----------------------------------------------------------------- one window: a second start shows the first


def signal_running_instance():
    """Called when the app is already running: ask it to show its window."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenEventW(0x0002, False, SHOW_EVENT)  # EVENT_MODIFY_STATE
    if handle:
        kernel32.SetEvent(handle)
        kernel32.CloseHandle(handle)


def listen_for_show(show):
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.restype = ctypes.c_void_p
    handle = kernel32.CreateEventW(None, False, False, SHOW_EVENT)

    def wait():
        while kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0xFFFFFFFF) == 0:
            show()

    threading.Thread(target=wait, daemon=True, name="show-event").start()


# ----------------------------------------------------------------- Windows session


class _SessionInfo(ctypes.Structure):
    # WTSINFOEXW: the union after Level is 8-byte aligned (it holds LARGE_INTEGERs)
    _fields_ = [("Level", ctypes.c_uint32), ("_pad", ctypes.c_uint32), ("SessionId", ctypes.c_uint32),
                ("SessionState", ctypes.c_int32), ("SessionFlags", ctypes.c_int32)]


def workstation_locked():
    """True while the Windows lock screen is showing."""
    wtsapi = ctypes.windll.wtsapi32
    buffer, size = ctypes.c_void_p(), ctypes.c_uint32()
    # WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionInfoEx
    if not wtsapi.WTSQuerySessionInformationW(None, ctypes.c_uint32(0xFFFFFFFF), 25, ctypes.byref(buffer), ctypes.byref(size)):
        return False
    try:
        return ctypes.cast(buffer, ctypes.POINTER(_SessionInfo)).contents.SessionFlags == 0  # WTS_SESSIONSTATE_LOCK
    finally:
        wtsapi.WTSFreeMemory(buffer)


class Watcher:
    """Tells the service the app is alive (so the AI's requests can wait for an answer even while
    the window is hidden), shows the window when the user has to answer something, and makes the
    vault follow the Windows session when the user turned that on."""

    def __init__(self, api, on_status=None):
        self.api = api
        self.on_status = on_status
        self._locked = None
        self._pending = 0
        self._drafts = None
        self._notice = None
        self._reminded = None
        self.notify = None  # set to show a Windows notification

    def start(self):
        threading.Thread(target=self._run, daemon=True, name="watcher").start()

    def _run(self):
        while True:
            try:
                self._step()
            except (BrokerError, BrokerUnavailable, OSError):
                pass  # the service is restarting, or the vault locked meanwhile
            except Exception:
                log.exception("watcher")
            time.sleep(WATCH_SECONDS)

    def _show_notices(self):
        """Things the AI did without asking that the user wanted to hear about."""
        notices = client.request("notices", {"after": self._notice or 0}, timeout=10)
        if self._notice is not None and self.notify:
            for notice in notices[-3:]:
                self.notify(notice["title"], notice["text"])
        if notices:
            self._notice = notices[-1]["id"]
        elif self._notice is None:
            self._notice = 0

    def _step(self):
        status = client.request("status", {"gui": True}, timeout=10)
        locked = workstation_locked() if sys.platform == "win32" else False
        if status["session_unlock"]:
            if locked and self._locked is False and status["state"] == "unlocked":
                status = client.request("lock", {"reason": "windows"})
            elif not locked and self._locked in (None, True) and status["state"] == "locked" and self.api.has_session_unlock():
                if self.api.session_unlock():
                    status = client.request("status", {"gui": True}, timeout=10)
        if status["state"] == "unlocked" and not locked and not self.api.has_presence() \
                and status["session_unlock"] and self.api.has_session_unlock():
            self.api.session_unlock()
        self._locked = locked
        drafts = status.get("drafts", 0)
        if (status["pending"] > self._pending or (self._drafts is not None and drafts > self._drafts)) and not locked:
            self.api.show()
        self._pending, self._drafts = status["pending"], drafts
        if status["state"] == "unlocked":
            self._show_notices()
            today = time.strftime("%Y-%m-%d")
            if status.get("reminders") and self._reminded != today and self.notify:
                self._reminded = today
                self.notify(f"{status['reminders']} clave(s) necesitan atención",
                            "Caducadas, a punto de caducar o muy antiguas. Ábrelas en SecretBroker para rotarlas.")
            if self.api.backup_due():
                self.api.backup_now()
        if self.on_status:
            self.on_status(status)


# ----------------------------------------------------------------- icon next to the clock


class Tray:
    """A NotifyIcon on its own WinForms thread (pywebview already loads WinForms through pythonnet)."""

    def __init__(self, api, icon_path):
        self.api = api
        self.icon_path = icon_path
        self._icon = None
        self._status = {}
        self._ready = threading.Event()

    def start(self):
        try:
            from System.Threading import ApartmentState, Thread, ThreadStart
        except Exception:
            return
        thread = Thread(ThreadStart(self._run))
        thread.SetApartmentState(ApartmentState.STA)
        thread.IsBackground = True
        thread.Start()
        self._ready.wait(5)

    def _run(self):
        import clr
        clr.AddReference("System.Windows.Forms")
        clr.AddReference("System.Drawing")
        from System.Drawing import Font, FontStyle, Icon
        from System.Windows.Forms import Application, ContextMenuStrip, NotifyIcon, ToolStripSeparator, ToolTipIcon

        menu = ContextMenuStrip()
        self._open = menu.Items.Add("Abrir SecretBroker")
        self._pause = menu.Items.Add("Pausar la IA")
        self._lock = menu.Items.Add("Bloquear")
        menu.Items.Add(ToolStripSeparator())
        self._quit = menu.Items.Add("Salir")
        self._open.Font = Font(self._open.Font, FontStyle.Bold)
        self._info = ToolTipIcon.Info
        self._open.Click += lambda *_: self.api.show()
        self._pause.Click += lambda *_: self._toggle_pause()
        self._lock.Click += lambda *_: self._safe(lambda: client.request("lock"))
        self._quit.Click += lambda *_: self.api.quit()
        menu.Opening += lambda *_: self._refresh_menu()

        icon = NotifyIcon()
        icon.Icon = Icon(str(self.icon_path))
        icon.Text = "SecretBroker"
        icon.ContextMenuStrip = menu
        icon.Visible = True
        icon.DoubleClick += lambda *_: self.api.show()
        icon.BalloonTipClicked += lambda *_: self.api.show()
        self._icon = icon
        self._ready.set()
        Application.Run()
        icon.Visible = False
        icon.Dispose()

    @staticmethod
    def _safe(action):
        try:
            action()
        except (BrokerError, BrokerUnavailable):
            pass

    def _refresh_menu(self):
        status = self._status
        self._pause.Text = "Reanudar la IA" if status.get("ai_paused") else "Pausar la IA"
        self._lock.Enabled = status.get("state") == "unlocked"

    def _toggle_pause(self):
        if self._status.get("ai_paused"):
            if not self.api.resume_ai():
                self.api.show()  # the app has to prove it is the user: done in the window
        else:
            self._safe(lambda: client.request("pause_ai"))
            self.notify("IA en pausa", "La IA no puede usar ninguna credencial hasta que la reanudes.")

    def update(self, status):
        self._status = status
        if self._icon is not None:
            text = "SecretBroker · IA en pausa" if status.get("ai_paused") else (
                "SecretBroker · bloqueado" if status.get("state") == "locked" else "SecretBroker")
            try:
                self._icon.Text = text
            except Exception:
                pass

    def notify(self, title, text):
        if self._icon is not None:
            try:
                self._icon.ShowBalloonTip(5000, title, text, self._info)
            except Exception:
                pass

    def close(self):
        if self._icon is not None:
            try:
                self._icon.Visible = False
                from System.Windows.Forms import Application
                Application.ExitThread()
            except Exception:
                pass


# ----------------------------------------------------------------- the AI's tools over HTTP


def _require_token(app, token):
    expected = f"Bearer {token}".encode()

    async def guarded(scope, receive, send):
        if scope["type"] == "http":
            given = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(given, expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
                await send({"type": "http.response.body", "body": "SecretBroker: token no válido".encode()})
                return
        await app(scope, receive, send)

    return guarded


def serve_mcp(show):
    """Serve the MCP tools on 127.0.0.1 in a background thread. Approvals and unlocking happen in
    this same app, so `show` (bring the window forward) replaces starting the app."""
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings
    from . import mcp_server

    mcp_server.open_app = show
    _, token = integrations.mcp_endpoint()
    port = integrations.MCP_PORT
    hosts = [f"127.0.0.1:{port}", f"localhost:{port}"]
    app = mcp_server.mcp.streamable_http_app(transport_security=TransportSecuritySettings(
        allowed_hosts=hosts, allowed_origins=[f"http://{h}" for h in hosts]))
    if sys.stdout is None:  # pythonw: uvicorn writes to the console
        sys.stdout = sys.stderr = open(os.devnull, "w")
    config = uvicorn.Config(_require_token(app, token), host="127.0.0.1", port=port,
                            log_config=None, log_level="warning", access_log=False, lifespan="on")
    server = uvicorn.Server(config)

    def run():
        try:
            asyncio.run(server.serve())
        except (OSError, SystemExit):
            log.exception("MCP over HTTP: port %s not available", port)

    threading.Thread(target=run, daemon=True, name="mcp-http").start()
    return server
