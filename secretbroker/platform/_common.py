"""What every platform module provides, and helpers shared by the POSIX ones."""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Every platform module defines all of these (tests/test_platform.py checks it).
INTERFACE = [
    # identity
    "NAME",                       # "windows", "linux", "macos"
    "OS_LABEL",                   # how the user calls it: "Windows", "Linux", "macOS"
    "NO_WINDOW",                  # subprocess creationflags that keep a console from flashing (0 off Windows)
    "biometric",                  # module with is_supported / create_key / sign / delete_key / HelloError / HelloCancelled
    # folders
    "installed_root",             # () -> Path: data of the isolated service (data/ + public/)
    "dev_root",                   # () -> Path: the same in development mode, as the current user
    "user_dir",                   # () -> Path: the desktop user's preferences, logs and web view data
    "roaming_dir",                # (home) -> Path: where apps keep their settings (%APPDATA%, ~/.config, ~/Library/Application Support)
    "local_dir",                  # (home) -> Path: where apps install per user (%LOCALAPPDATA%, ~/.local/share, ~/Applications)
    "profile_app_dirs",           # (home) -> [Path]: folders of the profile that hold program data, never projects
    "secure_data_dir",            # (path) -> None: make the service's data folder private to the service account
    "write_public_file",          # (path, text, isolated) -> None: broker.json, readable by the owner only where possible
    # who the user is and how they prove it
    "default_owner",              # () -> str: the desktop user the service works for
    "os_password_available",      # () -> bool: verify_os_password can work here
    "verify_os_password",         # (owner, password) -> bool
    # keys kept by the operating system
    "protect_for_service",        # (data, entropy, folder) -> bytes: only the service account can open it
    "unprotect_for_service",      # (blob, entropy, folder) -> bytes (OSError if it cannot)
    "protect_for_user",           # (data, entropy) -> bytes: only the desktop user's login can open it
    "unprotect_for_user",         # (blob, entropy) -> bytes (OSError / ValueError if it cannot)
    # processes
    "python_gui",                 # () -> str: the interpreter for windowless processes (pythonw.exe on Windows)
    "python_console",             # () -> str: the interpreter for stdio processes (MCP server)
    "spawn_detached",             # (args) -> None: start a process that outlives this one, without a console
    "start_service",              # () -> bool: ask the system to start the installed service for this user
    # the desktop session
    "session_locked",             # () -> bool: the lock screen is showing
    "autostart_command",          # () -> str: what starting with the session runs
    "set_autostart",              # (enabled) -> None
    "remove_autostart",           # () -> None: the uninstaller's cleanup
    "single_instance",            # () -> bool: True for the first app of this user (and test instance)
    "signal_running_instance",    # () -> None: ask the first app to show its window
    "listen_for_show",            # (show) -> None: call show() whenever a second start asks for it
    "copy_to_clipboard",          # (text, auto_clear, clear_seconds) -> None
    "notify",                     # (title, text) -> None: a desktop notification (when the tray icon cannot)
    "open_path",                  # (path) -> None: open a file or folder with its default program
    "show_in_folder",             # (path) -> None: open the file manager on a file (selected) or a folder
    "run_installer",              # (path) -> None: run a downloaded update (InstallCancelled when the user says no)
    "INSTALLER_RE",               # str: regular expression of this platform's installer in a release
    # where other programs keep things (AI apps, shells)
    "claude_desktop_config_dirs", # (home) -> [Path]
    "history_files",              # (home) -> [Path]: shell histories besides the POSIX ones in scanner.HISTORY_FILES
    "saved_environment",          # () -> {name: value}: environment variables saved for future sessions
]


class InstallCancelled(Exception):
    """The user said no to installing an update (UAC, polkit...)."""


class ProtectError(OSError):
    pass


# --------------------------------------------------------------------------- POSIX helpers

KEY_MAGIC = b"SBK1"


def write_private(path, data, mode=0o600):
    """Write a file only its owner (and `mode`) can read, atomically, never following a planted symlink."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)  # the umask may have taken bits away
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def key_file(path):
    """A random 256-bit key kept in a 0600 file, created the first time."""
    path = Path(path)
    try:
        data = path.read_bytes()
        if len(data) == 32:
            return data
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    write_private(path, key)
    return key


def seal(key, data, entropy):
    nonce = os.urandom(12)
    return KEY_MAGIC + nonce + AESGCM(key).encrypt(nonce, data, entropy)


def open_sealed(key, blob, entropy):
    if not blob.startswith(KEY_MAGIC) or len(blob) < len(KEY_MAGIC) + 12 + 16:
        raise ProtectError("Formato de clave protegida desconocido")
    nonce, sealed = blob[4:16], blob[16:]
    try:
        return AESGCM(key).decrypt(nonce, sealed, entropy)
    except InvalidTag:
        raise ProtectError("La clave protegida no corresponde a esta cuenta") from None


def xdg(name, default):
    value = os.environ.get(name)
    return Path(value) if value and os.path.isabs(value) else Path.home() / default


def parse_env_file(path):
    """KEY=VALUE lines (/etc/environment, environment.d): comments and `export` allowed, quotes removed."""
    values = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.removeprefix("export ").partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name.replace("_", "").isalnum():
            values.setdefault(name, value)
    return values
