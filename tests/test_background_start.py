"""Windows: the app started with the session (--background, hidden next to the clock) shows its page the first time
the window is opened. A window created minimized kept WebView2 blank on that first show (only the background
colour), which a DevTools screenshot does not see: this test looks at the screen itself.

Run with:  python tests/test_background_start.py   (Windows, a desktop session; starts its own test instance)
"""

import ctypes
import os
import socket
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gui_desktop as desktop  # noqa: E402

failures = []
user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
user32.GetDC.restype = wintypes.HDC
user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
gdi32.CreateCompatibleDC.restype = wintypes.HDC
gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
gdi32.SelectObject.restype = wintypes.HGDIOBJ
gdi32.BitBlt.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wintypes.HDC]
gdi32.GetPixel.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
gdi32.GetPixel.restype = wintypes.DWORD


def check(condition, label):
    print(("ok   " if condition else "FAIL ") + label, flush=True)
    if not condition:
        failures.append(label)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def app_window(pid):
    """The app's main window (titled SecretBroker) owned by `pid`, or None."""
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        title = ctypes.create_unicode_buffer(64)
        user32.GetWindowTextW(hwnd, title, 64)
        if owner.value == pid and title.value == "SecretBroker":
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(each, 0)
    return found[0] if found else None


def colours_shown(hwnd):
    """How many different colours the window's page shows on screen (a blank web view: one). The screen is copied
    once (BitBlt) and read from memory: GetPixel on the screen itself takes milliseconds per pixel."""
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    screen = user32.GetDC(None)
    memory = gdi32.CreateCompatibleDC(screen)
    bitmap = gdi32.CreateCompatibleBitmap(screen, width, height)
    try:
        gdi32.SelectObject(memory, bitmap)
        gdi32.BitBlt(memory, 0, 0, width, height, screen, rect.left, rect.top, 0x00CC0020)  # SRCCOPY
        return len({gdi32.GetPixel(memory, x, y) for y in range(60, height - 10, 7) for x in range(10, width - 10, 7)})
    finally:
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory)
        user32.ReleaseDC(None, screen)


def main():
    if desktop.NAME != "windows":
        desktop.skip("Windows only")
        return
    home = tempfile.mkdtemp(prefix="sb-background-")
    env = {**os.environ, "SECRETBROKER_HOME": home, "SECRETBROKER_MCP_PORT": str(free_port())}
    app = desktop.start(["-m", "secretbroker.app", "--background"], ROOT, env)
    try:
        pid = hwnd = None
        deadline = time.time() + 30
        while time.time() < deadline and not hwnd:
            time.sleep(0.5)
            pid = desktop.app_pid(app)
            hwnd = app_window(pid)
        check(bool(hwnd), "the app started with the session has its window")
        if not hwnd:
            return
        time.sleep(8)  # the page loads while the window is hidden
        check(not user32.IsWindowVisible(hwnd), "started with the session: the window stays hidden")
        # Opened again (the Start menu, the icon next to the clock): the running app shows its window.
        desktop.start(["-m", "secretbroker.app"], ROOT, env).wait(30)
        colours = 0
        deadline = time.time() + 10
        while time.time() < deadline and colours < 20:
            time.sleep(0.5)
            colours = colours_shown(hwnd) if user32.IsWindowVisible(hwnd) else 0
        check(user32.IsWindowVisible(hwnd), "opened again: the window shows")
        check(colours >= 20, f"opened for the first time: the page shows, not a blank window ({colours} colours)")
    finally:
        desktop.stop_tree(app)
    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
