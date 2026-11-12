"""What tests/test_gui.py needs from the desktop it runs on: starting and stopping the app's processes, finding its
window, telling whether it shows, closing it like the X button, reading the clipboard, and the system's name in the
page's texts. The page itself is driven the same way everywhere (Chrome DevTools Protocol: WebView2 on Windows,
QtWebEngine on Linux).

    Windows  Win32 (EnumWindows, IsWindowVisible, WM_SYSCOMMAND SC_CLOSE), pythonw.exe, taskkill
    Linux    X11 through python-xlib (_NET_WM_PID, map state, WM_STATE, WM_DELETE_WINDOW), the app on XWayland or
             Xvfb (QT_QPA_PLATFORM=xcb), process groups
"""

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

NAME = "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux"
OS_LABEL = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}[NAME]
BROWSER_FLAGS = ("--disable-background-timer-throttling --disable-renderer-backgrounding "
                 "--disable-backgrounding-occluded-windows")


def skip(reason):
    """A step this system doesn't have: said, not failed."""
    print(f"  SKIP {reason}", flush=True)


def os_text(text):
    """A text of the page as this system shows it: the copy names Windows, and app.js's osText() names the system
    the app runs on instead (and drops «(Win+L)»). «Windows Hello» stays: it only shows where there is one."""
    if NAME == "windows":
        return text
    import re
    return re.sub(r"Windows(?! Hello)", OS_LABEL, text).replace(" (Win+L)", "")


def browser_env(devtools_port):
    """Environment for the app so that its web view listens for the DevTools Protocol on `devtools_port`."""
    if NAME == "windows":
        return {"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={devtools_port} {BROWSER_FLAGS} "
                "--disable-features=CalculateNativeWinOcclusion"}
    return {"QTWEBENGINE_REMOTE_DEBUGGING": f"127.0.0.1:{devtools_port}",
            "QTWEBENGINE_CHROMIUM_FLAGS": f"{BROWSER_FLAGS} --remote-allow-origins=*",
            "QT_QPA_PLATFORM": "xcb"}  # the window is found and closed through X11 (XWayland under a Wayland session)


def python_gui():
    """The interpreter the app is started with: pythonw.exe on Windows (no console window)."""
    if NAME == "windows":
        return str(Path(sys.executable).with_name("pythonw.exe"))
    return sys.executable


def start(args, cwd, env):
    """Start one of the app's processes; on Linux in a process group of its own, so that stopping it also stops
    QtWebEngine's helper processes."""
    if NAME == "windows":
        return subprocess.Popen([python_gui(), *args], cwd=cwd, env=env)
    return subprocess.Popen([python_gui(), *args], cwd=cwd, env=env, start_new_session=True)


def app_pid(process):
    """The pid that owns the window. A venv's pythonw.exe starts the real interpreter as a child process."""
    if NAME != "windows":
        return process.pid
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          f"(Get-CimInstance Win32_Process -Filter 'ParentProcessId={process.pid}').ProcessId"],
                         capture_output=True, text=True).stdout.split()
    return int(out[0]) if out else process.pid


def stop_tree(process):
    if NAME == "windows":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()


def stop_pid(pid):
    if NAME == "windows":
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def fake_command(folder, name, script):
    """A program `name` in `folder` that runs the Python file `script` (next to it) with this interpreter."""
    folder = Path(folder)
    if NAME == "windows":
        (folder / f"{name}.cmd").write_text(f'@"{sys.executable}" "%~dp0{script}" %*\r\n', encoding="utf-8")
        return
    launcher = folder / name
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$(dirname "$0")/{script}" "$@"\n', encoding="utf-8")
    launcher.chmod(0o755)


def appdata(profile):
    """Where programs keep their settings in a user profile (VS Code's Code/User, Claude's config)."""
    if NAME == "windows":
        return Path(profile) / "AppData" / "Roaming"
    if NAME == "macos":
        return Path(profile) / "Library" / "Application Support"
    return Path(profile) / ".config"


def read_clipboard():
    """The clipboard's text, or None when this desktop gives no way to read it."""
    if NAME == "windows":
        return subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"], capture_output=True, text=True).stdout
    for tool in (["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]):
        if shutil.which(tool[0]):
            result = subprocess.run(tool, capture_output=True, text=True, timeout=5)
            return result.stdout if result.returncode == 0 else ""
    # Qt reads the X11 selection itself (it is what the app writes with).
    result = subprocess.run([sys.executable, "-c", "import sys; from PyQt6.QtWidgets import QApplication; "
                             "app = QApplication(sys.argv); sys.stdout.write(app.clipboard().text())"],
                            capture_output=True, text=True, timeout=20, env={**os.environ, "QT_QPA_PLATFORM": "xcb"})
    return result.stdout if result.returncode == 0 else None


# ----------------------------------------------------------------- the window


if NAME == "windows":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.windll.user32

    def find_window(pid):
        found = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def visit(hwnd, _):
            owner = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            title = ctypes.create_unicode_buffer(256)
            _user32.GetWindowTextW(hwnd, title, 256)
            if owner.value == pid and title.value == "SecretBroker":
                found.append(hwnd)
            return True

        _user32.EnumWindows(visit, 0)
        return found[0] if found else None

    def visible(window):
        """On screen: shown and not minimized."""
        return bool(_user32.IsWindowVisible(window)) and not _user32.IsIconic(window)

    def shown(window):
        """Shown, minimized or not (closing hides it: not shown)."""
        return bool(_user32.IsWindowVisible(window))

    def minimized(window):
        return bool(_user32.IsIconic(window))

    def close_window(window):
        """The X button. (A plain WM_CLOSE from another program, like the installer or Task Manager, quits.)"""
        _user32.PostMessageW(window, 0x0112, 0xF060, 0)  # WM_SYSCOMMAND SC_CLOSE

    def can_minimize():
        return True

else:
    _x = None

    def _display():
        global _x
        if _x is None:
            from Xlib import display
            _x = display.Display()
        return _x

    def _atom(name):
        return _display().intern_atom(name)

    def _windows(window):
        yield window
        for child in window.query_tree().children:
            yield from _windows(child)

    def _property(window, name, kind=0):
        from Xlib import error
        try:
            prop = window.get_full_property(_atom(name), kind)
        except error.XError:
            return None
        return prop.value if prop else None

    def find_window(pid):
        from Xlib import error
        display = _display()
        display.sync()
        for window in _windows(display.screen().root):
            try:
                owner = _property(window, "_NET_WM_PID")
                if owner is None or owner[0] != pid:
                    continue
                title = _property(window, "_NET_WM_NAME")
                title = title.decode("utf-8", "replace") if isinstance(title, bytes) else window.get_wm_name()
                if title == "SecretBroker":
                    return window
            except error.XError:
                continue
        return None

    def minimized(window):
        state = _property(window, "WM_STATE")
        hidden = _property(window, "_NET_WM_STATE") or []
        return bool(state is not None and len(state) and state[0] == 3) or _atom("_NET_WM_STATE_HIDDEN") in hidden

    def shown(window):
        """Mapped by the app (a window manager unmaps it to minimize it: that still counts as shown)."""
        from Xlib import X, error
        _display().sync()
        try:
            return window.get_attributes().map_state == X.IsViewable or minimized(window)
        except error.XError:
            return False

    def visible(window):
        from Xlib import X, error
        _display().sync()
        try:
            return window.get_attributes().map_state == X.IsViewable and not minimized(window)
        except error.XError:
            return False

    def close_window(window):
        """The X button: what a window manager sends the window (WM_DELETE_WINDOW), so it works without one too."""
        from Xlib import X, protocol
        message = protocol.event.ClientMessage(window=window, client_type=_atom("WM_PROTOCOLS"),
                                               data=(32, [_atom("WM_DELETE_WINDOW"), X.CurrentTime, 0, 0, 0]))
        window.send_event(message, event_mask=X.NoEventMask)
        _display().flush()

    def can_minimize():
        """A window manager that minimizes windows (Xvfb alone has none: there a minimized window stays put)."""
        supported = _property(_display().screen().root, "_NET_SUPPORTED") or []
        return _atom("_NET_WM_STATE_HIDDEN") in supported
