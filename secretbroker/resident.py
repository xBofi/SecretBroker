"""What keeps the desktop app useful while its window is hidden: the icon next to the clock, starting
with the session, following the session (lock / unlock), and serving the AI's tools over HTTP.
What differs per operating system (autostart, lock screen, a second start) is in secretbroker.platform.

Serving the MCP tools from the app (instead of a process started by Claude Code) is what lets Claude
Code reconnect by itself after an update: the installer restarts the app and Claude Code retries a
dropped HTTP server, while a stdio server that was killed stays dead until the user runs /mcp.
"""

import asyncio
import hmac
import logging
import os
import sys
import threading
import time
from pathlib import Path

from . import client, integrations, paths, platform
from .client import BrokerError, BrokerUnavailable
from .i18n import language, tr

log = logging.getLogger("secretbroker.resident")
WATCH_SECONDS = 2


# ----------------------------------------------------------------- start with the session (Windows: the Run key)


def startup_command():
    return platform.autostart_command()


def set_start_with_windows(enabled):
    platform.set_autostart(bool(enabled))


def start_with_windows():
    return integrations.load_prefs().get("start_with_windows", paths.is_installed())


# ----------------------------------------------------------------- one window: a second start shows the first


def signal_running_instance():
    """Called when the app is already running: ask it to show its window."""
    platform.signal_running_instance()


def listen_for_show(show):
    platform.listen_for_show(show)


# ----------------------------------------------------------------- the session (lock screen)


def workstation_locked():
    """True while the lock screen is showing."""
    try:
        return platform.session_locked()
    except NotImplementedError:
        return False


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
        locked = workstation_locked()
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
                self.notify(tr("resident.reminders_need_attention", count=status["reminders"]),
                            tr("resident.expired_about_expire_or_very"))
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
        self.available = True  # the desktop shows icons next to the clock (Linux: see QtTray)

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
        self._open = menu.Items.Add(tr("resident.open_secretbroker"))
        self._pause = menu.Items.Add(tr("resident.pause_ai"))
        self._lock = menu.Items.Add(tr("resident.lock"))
        menu.Items.Add(ToolStripSeparator())
        self._quit = menu.Items.Add(tr("resident.quit"))
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
        self._open.Text, self._lock.Text, self._quit.Text = tr("resident.open_secretbroker"), tr("resident.lock"), tr("resident.quit")  # the language may have changed
        self._pause.Text = tr("resident.resume_ai") if status.get("ai_paused") else tr("resident.pause_ai")
        self._lock.Enabled = status.get("state") == "unlocked"

    def _toggle_pause(self):
        if self._status.get("ai_paused"):
            if not self.api.resume_ai():
                self.api.show()  # the app has to prove it is the user: done in the window
        else:
            self._safe(lambda: client.request("pause_ai"))
            self.notify(tr("resident.ai_paused"), tr("resident.ai_can_use_any_credential"))

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


class QtTray(Tray):
    """Linux: a QSystemTrayIcon on the Qt thread of pywebview's Qt backend. Desktops show it as a
    StatusNotifierItem (KDE; GNOME through Ubuntu's AppIndicator extension), and it shows notifications."""

    def start(self):
        from .platform import linux
        self.available = False
        ready = threading.Event()

        def build():
            try:
                self._build()
            except Exception:
                log.exception("tray icon")
            finally:
                ready.set()

        if linux.gui_call(build):
            ready.wait(5)

    def _build(self):
        from qtpy.QtGui import QIcon
        from qtpy.QtWidgets import QMenu, QSystemTrayIcon

        menu = QMenu()
        self._open = menu.addAction(tr("resident.open_secretbroker"))
        self._pause = menu.addAction(tr("resident.pause_ai"))
        self._lock = menu.addAction(tr("resident.lock"))
        menu.addSeparator()
        self._quit = menu.addAction(tr("resident.quit"))
        font = self._open.font()
        font.setBold(True)
        self._open.setFont(font)
        self._open.triggered.connect(lambda *_: self.api.show())
        self._pause.triggered.connect(lambda *_: self._toggle_pause())
        self._lock.triggered.connect(lambda *_: self._safe(lambda: client.request("lock")))
        self._quit.triggered.connect(lambda *_: self.api.quit())
        menu.aboutToShow.connect(self._refresh_menu)

        icon = QSystemTrayIcon(QIcon(str(self.icon_path)))
        icon.setToolTip("SecretBroker")
        icon.setContextMenu(menu)
        activations = (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick)
        icon.activated.connect(lambda reason: self.api.show() if reason in activations else None)
        icon.messageClicked.connect(lambda: self.api.show())
        icon.show()
        self._menu, self._icon = menu, icon
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        if not self.available:
            log.info("no system tray here (GNOME needs the AppIndicator extension): closing minimizes instead")

        self._info = QSystemTrayIcon.MessageIcon.Information

    def _refresh_menu(self):
        status = self._status
        for action, key in ((self._open, "resident.open_secretbroker"), (self._lock, "resident.lock"), (self._quit, "resident.quit")):
            action.setText(tr(key))  # the language may have changed
        self._pause.setText(tr("resident.resume_ai") if status.get("ai_paused") else tr("resident.pause_ai"))
        self._lock.setEnabled(status.get("state") == "unlocked")

    def update(self, status):
        from .platform import linux
        self._status = status
        if self._icon is not None:
            text = "SecretBroker · IA en pausa" if status.get("ai_paused") else (
                "SecretBroker · bloqueado" if status.get("state") == "locked" else "SecretBroker")
            linux.gui_call(lambda: self._icon.setToolTip(text))

    def notify(self, title, text):
        from .platform import linux
        from qtpy.QtWidgets import QSystemTrayIcon
        if self._icon is not None and QSystemTrayIcon.supportsMessages():
            linux.gui_call(lambda: self._icon.showMessage(title, text, self._info, 5000))
        else:
            platform.notify(title, text)

    def close(self):
        from .platform import linux
        if self._icon is not None:
            linux.gui_call(self._icon.hide)


class MacTray(Tray):
    """macOS: an icon in the menu bar (pystray's NSStatusItem). pywebview's Cocoa backend owns the main thread
    and its run loop, so the item is built there (AppHelper.callAfter) and pystray only attaches to that loop
    (run_detached). Notifications go to Notification Center (platform.notify)."""

    _shown = None  # what the title and menu were last drawn for

    def start(self):
        self.available = False
        ready = threading.Event()

        def build():
            try:
                self._build()
            except Exception:
                log.exception("menu bar icon")
            finally:
                ready.set()

        try:
            from PyObjCTools import AppHelper
        except ImportError:
            return
        AppHelper.callAfter(build)
        ready.wait(5)

    def _build(self):
        import pystray
        from PIL import Image

        def later(action):
            # Menu actions run on the main thread: anything that waits for the service goes to its own thread.
            return lambda *_: threading.Thread(target=action, daemon=True).start()

        menu = pystray.Menu(
            # Texts are read each time the menu is drawn: the language may have changed.
            pystray.MenuItem(lambda _: tr("resident.open_secretbroker"), later(self.api.show), default=True),
            pystray.MenuItem(lambda _: tr("resident.resume_ai") if self._status.get("ai_paused") else tr("resident.pause_ai"),
                             later(self._toggle_pause)),
            pystray.MenuItem(lambda _: tr("resident.lock"), later(lambda: self._safe(lambda: client.request("lock"))),
                             enabled=lambda _: self._status.get("state") == "unlocked"),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda _: tr("resident.quit"), later(self.api.quit)),
        )
        # A monochrome shield (assets/menubar.png, from tools/make_icon.py --menubar) marked as a template image,
        # so macOS draws it like the other menu bar icons, in light and dark bars.
        template = Path(self.icon_path).with_name("menubar.png")
        image = Image.open(template if template.is_file() else self.icon_path)
        image.load()
        self._icon = pystray.Icon("SecretBroker", image, "SecretBroker", menu)
        self._icon.run_detached()
        self._icon.visible = True
        try:
            self._icon._status_item.button().image().setTemplate_(True)  # pystray has no option for it
        except Exception:
            log.info("menu bar icon: not a template image")
        self.available = True

    def _on_main(self, action):
        try:
            from PyObjCTools import AppHelper
            AppHelper.callAfter(action)
        except Exception:
            pass

    def update(self, status):
        text = tr("resident.menu_title_ai_paused") if status.get("ai_paused") else (
            tr("resident.menu_title_locked") if status.get("state") == "locked" else "SecretBroker")
        shown = (text, status.get("state"), status.get("ai_paused"), language())  # the language may have changed
        self._status = status
        if self._icon is not None and shown != self._shown:
            self._shown = shown

            def apply():
                self._icon.title = text
                self._icon.update_menu()

            self._on_main(apply)

    def notify(self, title, text):
        platform.notify(title, text)

    def close(self):
        if self._icon is not None:
            # Only hidden: pystray's stop() would also stop the application's run loop, which belongs to pywebview.
            self._on_main(lambda: setattr(self._icon, "visible", False))


def make_tray(api, icon_path):
    """The icon next to the clock (the menu bar on macOS) for this system."""
    if platform.NAME == "windows":
        return Tray(api, icon_path)
    if platform.NAME == "linux":
        return QtTray(api, icon_path)
    return MacTray(api, icon_path)


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
