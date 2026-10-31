"""Windows: DPAPI, LogonUser, Windows Hello, the Run key, WTS session state, named kernel objects.

This is the code SecretBroker always ran on Windows, gathered here unchanged."""

import ctypes
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from .. import hello as biometric  # noqa: F401  (Windows Hello)
from .. import winsec
from ._common import INTERFACE, InstallCancelled

NAME = "windows"
OS_LABEL = "Windows"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW
INSTALLER_RE = r"^SecretBroker-Setup-(\d+\.\d+\.\d+)\.exe$"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "SecretBroker"


def _suffix():
    from .. import paths
    return paths.instance_suffix()


# --------------------------------------------------------------------------- folders


def installed_root():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecretBroker"


def dev_root():
    return Path(os.environ.get("APPDATA", Path.home())) / "SecretBroker"


def user_dir():
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretBroker"


def roaming_dir(home):
    return Path(os.environ.get("APPDATA") or Path(home) / "AppData" / "Roaming")


def local_dir(home):
    return Path(os.environ.get("LOCALAPPDATA") or Path(home) / "AppData" / "Local")


def profile_app_dirs(home):
    return [Path(home) / "AppData"]


def secure_data_dir(path):
    """The installer sets the folder's ACL (installer/configure.ps1); nothing to do at run time."""


def write_public_file(path, text, isolated):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- identity


def default_owner():
    return f"{os.environ.get('USERDOMAIN', '.')}\\{os.environ.get('USERNAME', '')}"


def os_password_available():
    return True


def verify_os_password(owner, password):
    return winsec.verify_windows_password(owner, password)


def protect_for_service(data, entropy, folder=None):
    """DPAPI under the service account: only that account, on this PC, can decrypt."""
    return winsec.dpapi_protect(data, entropy)


def unprotect_for_service(blob, entropy, folder=None):
    return winsec.dpapi_unprotect(blob, entropy)


def protect_for_user(data, entropy):
    """DPAPI under the desktop user's login."""
    return winsec.dpapi_protect(data, entropy)


def unprotect_for_user(blob, entropy):
    return winsec.dpapi_unprotect(blob, entropy)


# --------------------------------------------------------------------------- processes


def python_gui():
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate if candidate.exists() else sys.executable)


def python_console():
    candidate = Path(sys.executable).with_name("python.exe")
    return str(candidate if candidate.exists() else sys.executable)


def spawn_detached(args):
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(args, creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_service():
    """The installed service is a scheduled task under its own account: Windows starts it, users cannot."""
    return False


# --------------------------------------------------------------------------- the Windows session


class _SessionInfo(ctypes.Structure):
    # WTSINFOEXW: the union after Level is 8-byte aligned (it holds LARGE_INTEGERs)
    _fields_ = [("Level", ctypes.c_uint32), ("_pad", ctypes.c_uint32), ("SessionId", ctypes.c_uint32),
                ("SessionState", ctypes.c_int32), ("SessionFlags", ctypes.c_int32)]


def session_locked():
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


def autostart_command():
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return f'"{pythonw if pythonw.exists() else sys.executable}" -I -m secretbroker.app --background'


def set_autostart(enabled):
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, autostart_command())
        else:
            try:
                winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError:
                pass


def remove_autostart():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except OSError:
        pass


# --------------------------------------------------------------------------- one window: a second start shows the first


def single_instance():
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\SecretBrokerApp" + _suffix())
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def signal_running_instance():
    """Called when the app is already running: ask it to show its window."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenEventW(0x0002, False, "Local\\SecretBrokerShow" + _suffix())  # EVENT_MODIFY_STATE
    if handle:
        kernel32.SetEvent(handle)
        kernel32.CloseHandle(handle)


def listen_for_show(show):
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.restype = ctypes.c_void_p
    handle = kernel32.CreateEventW(None, False, False, "Local\\SecretBrokerShow" + _suffix())

    def wait():
        while kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0xFFFFFFFF) == 0:
            show()

    threading.Thread(target=wait, daemon=True, name="show-event").start()


# --------------------------------------------------------------------------- clipboard, notifications, opening files


def copy_to_clipboard(text, auto_clear=True, clear_seconds=30):
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
            time.sleep(clear_seconds)
            if user32.GetClipboardSequenceNumber() == sequence and user32.OpenClipboard(None):
                user32.EmptyClipboard()
                user32.CloseClipboard()

        threading.Thread(target=clear, daemon=True).start()


def notify(title, text):
    """On Windows the tray icon shows balloons (resident.Tray.notify)."""


def open_path(path):
    os.startfile(str(path))


def show_in_folder(path):
    path = Path(path)
    subprocess.Popen(["explorer", str(path)] if path.is_dir() else ["explorer", "/select,", str(path)])


def run_installer(path):
    """Windows asks for administrator consent; the installer closes the app and reopens it."""
    try:
        os.startfile(str(path), "open", "/SILENT /SUPPRESSMSGBOXES /NORESTART")
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1223:  # the user said no to UAC
            raise InstallCancelled() from None
        raise


# --------------------------------------------------------------------------- other programs


def claude_desktop_config_dirs(home):
    yield roaming_dir(home) / "Claude"
    packages = local_dir(home) / "Packages"
    if packages.is_dir():
        for package in packages.glob("Claude_*"):
            yield package / "LocalCache" / "Roaming" / "Claude"


def history_files(home):
    folder = roaming_dir(home) / "Microsoft/Windows/PowerShell/PSReadLine"
    return sorted(p for p in folder.glob("*_history.txt") if p.is_file()) if folder.is_dir() else []


def saved_environment():
    """The environment saved in the registry (user and machine), for sessions started later."""
    import winreg
    values = {}
    for hive, key in ((winreg.HKEY_CURRENT_USER, "Environment"),
                      (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
        try:
            with winreg.OpenKey(hive, key) as handle:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(handle, index)
                    except OSError:
                        break
                    values.setdefault(name, str(value))
                    index += 1
        except OSError:
            pass
    return values


__all__ = list(INTERFACE)
