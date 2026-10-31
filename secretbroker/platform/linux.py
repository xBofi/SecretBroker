"""Linux (Ubuntu 22.04 / 24.04 and similar desktops): PAM, Secret Service, logind, XDG autostart, systemd.

Isolation mirrors Windows (see docs/ARCHITECTURE.md, "Platforms"): the installed service runs as the system
user `secretbroker` under the systemd unit secretbroker@<owner>.service, its data lives in
/var/lib/secretbroker/<owner>/data (0700, only that user) and broker.json in .../public (setgid group = the
owner's group, 0640), so only the owner can read the service's token.
"""

import ctypes
import ctypes.util
import os
import pwd
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from .. import hello as biometric  # noqa: F401  (no Windows Hello here: is_supported() is False)
from ._common import INTERFACE, InstallCancelled, ProtectError, key_file, open_sealed, parse_env_file, seal, write_private, xdg
from ..i18n import tr

NAME = "linux"
OS_LABEL = "Linux"
NO_WINDOW = 0
INSTALLER_RE = r"^secretbroker_(\d+\.\d+\.\d+)_amd64\.deb$"
INSTALL_DIR = Path("/opt/secretbroker")
STATE_ROOT = Path("/var/lib/secretbroker")
SERVICE_UNIT = "secretbroker@{user}.service"
PAM_SERVICE = "secretbroker"  # /etc/pam.d/secretbroker, installed by the .deb (pam_unix only)
SERVICE_KEY_FILE = "machine.key"
USER_KEY_FILE = "user.key"
SECRET_ATTRIBUTES = {"application": "SecretBroker", "purpose": "session-unlock"}
SECRET_SERVICE_SECONDS = 5
DESKTOP_FILE = "secretbroker{suffix}.desktop"


def _suffix():
    from .. import paths
    return paths.instance_suffix()


def _user():
    return pwd.getpwuid(os.getuid()).pw_name


def _run(args, timeout=5):
    """A short helper program; None when it is missing or fails."""
    if not shutil.which(args[0]):
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return result if result.returncode == 0 else None


# --------------------------------------------------------------------------- folders


def installed_root():
    return STATE_ROOT / _user()


def dev_root():
    return xdg("XDG_DATA_HOME", ".local/share") / "secretbroker"


def user_dir():
    return xdg("XDG_STATE_HOME", ".local/state") / "secretbroker"


def roaming_dir(home):
    if Path(home) == Path.home():
        return xdg("XDG_CONFIG_HOME", ".config")
    return Path(home) / ".config"


def local_dir(home):
    if Path(home) == Path.home():
        return xdg("XDG_DATA_HOME", ".local/share")
    return Path(home) / ".local" / "share"


def profile_app_dirs(home):
    home = Path(home)
    return [home / ".config", home / ".local", home / ".cache", home / "snap"]


def secure_data_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_public_file(path, text, isolated):
    """Installed, the folder belongs to the owner's group (setgid): 0640 lets the owner, and only the owner,
    read the token. In development everything runs as the user: 0600."""
    write_private(path, text.encode("utf-8"), 0o640 if isolated else 0o600)


# --------------------------------------------------------------------------- identity


def default_owner():
    return _user()


def os_password_available():
    return _libpam() is not None


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]  # resp: malloc'd, PAM frees it


_CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_PamMessage)),
                         ctypes.POINTER(ctypes.POINTER(_PamResponse)), ctypes.c_void_p)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


_pam = None


def _libpam():
    global _pam
    if _pam is None:
        name = ctypes.util.find_library("pam")
        libc_name = ctypes.util.find_library("c")
        if not name or not libc_name:
            return None
        lib, libc = ctypes.CDLL(name), ctypes.CDLL(libc_name)
        lib.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
        lib.pam_authenticate.argtypes = lib.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        libc.calloc.argtypes, libc.calloc.restype = [ctypes.c_size_t, ctypes.c_size_t], ctypes.c_void_p
        libc.strdup.argtypes, libc.strdup.restype = [ctypes.c_char_p], ctypes.c_void_p
        _pam = (lib, libc)
    return _pam


def verify_os_password(owner, password):
    """The owner's login password, checked by PAM (service `secretbroker`: pam_unix). The installed service
    user belongs to the `shadow` group so pam_unix's helper may check another account's password."""
    loaded = _libpam()
    if not loaded or not password or not owner or "\\" in owner:
        return False
    lib, libc = loaded
    secret = password.encode("utf-8")

    @_CONV
    def conversation(count, messages, responses, _data):
        array = libc.calloc(count, ctypes.sizeof(_PamResponse))
        if not array:
            return 5  # PAM_BUF_ERR
        responses[0] = ctypes.cast(array, ctypes.POINTER(_PamResponse))
        for i in range(count):
            if messages[i].contents.msg_style == 1:  # PAM_PROMPT_ECHO_OFF: the password
                responses[0][i].resp = libc.strdup(secret)
        return 0

    handle = ctypes.c_void_p()
    conv = _PamConv(conversation, None)
    if lib.pam_start(PAM_SERVICE.encode(), owner.encode("utf-8"), ctypes.byref(conv), ctypes.byref(handle)) != 0:
        return False
    result = lib.pam_authenticate(handle, 0x8000)  # PAM_DISALLOW_NULL_AUTHTOK
    if result == 0:
        result = lib.pam_acct_mgmt(handle, 0x8000)
    lib.pam_end(handle, result)
    return result == 0


# --------------------------------------------------------------------------- keys kept by the system


def protect_for_service(data, entropy, folder):
    """AES-GCM with a key in a 0600 file of the service account (next to the vault, in a 0700 folder).
    A copy of the protected file alone (a backup) cannot be opened."""
    return seal(key_file(Path(folder) / SERVICE_KEY_FILE), data, entropy)


def unprotect_for_service(blob, entropy, folder):
    path = Path(folder) / SERVICE_KEY_FILE
    if not path.exists():
        raise ProtectError(tr("linux.this_computer_key_is_missing"))
    return open_sealed(key_file(path), blob, entropy)


def _secret_service_key(create):
    """A random key kept in the user's keyring (GNOME Keyring / KWallet via the Secret Service), or None.

    Never waits for the user: creating a keyring or unlocking a locked one shows a prompt, and this also runs
    when the AI's request reopens the vault (client.session_token). The login keyring is open once the user
    has logged in; anything else falls back to the key file. A keyring that does not answer in time too."""
    result = {}

    def work():
        try:
            result["key"] = _keyring_key(create)
        except Exception:
            result["key"] = None

    worker = threading.Thread(target=work, daemon=True, name="secret-service")
    worker.start()
    worker.join(SECRET_SERVICE_SECONDS)
    return result.get("key")


def _keyring_key(create):
    try:
        import secretstorage
        from secretstorage.collection import get_collection_by_alias
    except ImportError:
        return None
    connection = secretstorage.dbus_init()
    try:
        collection = get_collection_by_alias(connection, "default")  # never creates one (that prompts)
        if collection.is_locked():
            return None
        attributes = {**SECRET_ATTRIBUTES, "instance": _suffix() or "default"}
        for item in collection.search_items(attributes):
            secret = item.get_secret()
            if len(secret) == 32:
                return bytes(secret)
        if not create:
            return None
        key = os.urandom(32)
        collection.create_item("SecretBroker (abrir con la sesión)", attributes, key, replace=True)
        return key
    finally:
        connection.close()


def protect_for_user(data, entropy):
    """Under the desktop user's login: the key is in the Secret Service keyring when there is one (unlocked
    with the login), else in a 0600 file of the user. Either way, anything running as the user can use it:
    that is what "open with my session" means."""
    key = _secret_service_key(create=True)
    if key is not None:
        return b"s" + seal(key, data, entropy)
    return b"f" + seal(key_file(user_dir() / USER_KEY_FILE), data, entropy)


def unprotect_for_user(blob, entropy):
    kind, rest = blob[:1], blob[1:]
    if kind == b"s":
        key = _secret_service_key(create=False)
        if key is None:
            raise ProtectError(tr("linux.session_keyring_isn_available"))
    elif kind == b"f" and (user_dir() / USER_KEY_FILE).exists():
        key = key_file(user_dir() / USER_KEY_FILE)
    else:
        raise ProtectError(tr("common.unknown_protected_key_format"))
    return open_sealed(key, rest, entropy)


# --------------------------------------------------------------------------- processes


def python_gui():
    return sys.executable


def python_console():
    return sys.executable


def spawn_detached(args):
    subprocess.Popen(args, start_new_session=True, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_service():
    """The .deb's polkit rule lets each user start their own unit, and only that one, without a password."""
    if not shutil.which("systemctl"):
        return False
    try:
        return subprocess.run(["systemctl", "start", "--no-ask-password", SERVICE_UNIT.format(user=_user())],
                              capture_output=True, timeout=30, stdin=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# --------------------------------------------------------------------------- the desktop session

_lock_method = None  # what answered last time: "logind" or a screensaver D-Bus name


def _logind_locked():
    session = os.environ.get("XDG_SESSION_ID")
    if not session:
        display = _run(["loginctl", "show-user", _user(), "-p", "Display", "--value"])
        session = display.stdout.strip() if display else ""
    if not session:
        return None
    result = _run(["loginctl", "show-session", session, "-p", "LockedHint", "--value"])
    return None if result is None else result.stdout.strip() == "yes"


def _screensaver_locked(name):
    path = "/" + name.replace(".", "/")
    result = _run(["gdbus", "call", "--session", "--dest", name, "--object-path", path,
                   "--method", name + ".GetActive"])
    return None if result is None else "true" in result.stdout


def session_locked():
    """True while the lock screen shows: logind's LockedHint (GNOME, KDE), else the screensaver's D-Bus API."""
    global _lock_method
    methods = ["logind", "org.gnome.ScreenSaver", "org.freedesktop.ScreenSaver"]
    if _lock_method:
        methods.remove(_lock_method)
        methods.insert(0, _lock_method)
    for method in methods:
        locked = _logind_locked() if method == "logind" else _screensaver_locked(method)
        if locked is not None:
            _lock_method = method
            return locked
    return False


def _autostart_file():
    return roaming_dir(Path.home()) / "autostart" / DESKTOP_FILE.format(suffix=_suffix())


def autostart_command():
    return f'"{sys.executable}" -I -m secretbroker.app --background'


def set_autostart(enabled):
    file = _autostart_file()
    if not enabled:
        file.unlink(missing_ok=True)
        return
    file.parent.mkdir(parents=True, exist_ok=True)
    icon = Path(__file__).resolve().parent.parent / "assets" / "icon.png"
    file.write_text("[Desktop Entry]\nType=Application\nName=SecretBroker\nComment=Gestor de contraseñas y claves para la IA\n"
                    f"Exec={autostart_command()}\nIcon={icon}\nTerminal=false\nNoDisplay=true\n"
                    "X-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=3\n", encoding="utf-8")


def remove_autostart():
    _autostart_file().unlink(missing_ok=True)


# --------------------------------------------------------------------------- one window: a second start shows the first

_instance = None  # the listening socket of the first app


def _instance_address():
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    name = f"secretbroker-app{_suffix()}.sock"
    if runtime and os.path.isdir(runtime):
        return os.path.join(runtime, name)
    return f"\0{name}-{os.getuid()}"  # abstract socket: no file to leave behind


def single_instance():
    global _instance
    address = _instance_address()
    for _ in range(2):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(address)
            if not address.startswith("\0"):
                os.chmod(address, 0o600)
            sock.listen(4)
            _instance = sock
            return True
        except OSError:
            sock.close()
        try:  # someone listening: the app is running. A file nobody listens on: left by a crash.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(2)
                probe.connect(address)
            return False
        except OSError:
            if address.startswith("\0"):
                return False
            try:
                os.unlink(address)
            except OSError:
                return False
    return False


def signal_running_instance():
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(_instance_address())
            sock.sendall(b"show\n")
    except OSError:
        pass


def listen_for_show(show):
    if _instance is None:
        return

    def serve():
        while True:
            try:
                conn, _ = _instance.accept()
            except OSError:
                return
            with conn:
                try:
                    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    uid = int.from_bytes(creds[4:8], sys.byteorder)
                    conn.settimeout(2)
                    if uid == os.getuid() and conn.recv(16).startswith(b"show"):
                        show()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True, name="show-socket").start()


# --------------------------------------------------------------------------- clipboard, notifications, opening files


def gui_call(function):
    """Run `function` on the Qt GUI thread (pywebview's Qt backend), without waiting. False without Qt."""
    try:
        from qtpy.QtCore import QCoreApplication, QObject, Qt, Signal, Slot
    except Exception:
        return False
    app = QCoreApplication.instance()
    if app is None:
        return False
    global _invoker
    if _invoker is None:
        class Invoker(QObject):
            call = Signal(object)

            @Slot(object)
            def run(self, function):
                try:
                    function()
                except Exception:
                    import logging
                    logging.getLogger("secretbroker.platform").exception("on the GUI thread")

        invoker = Invoker()
        invoker.moveToThread(app.thread())
        # A slot of an object that lives on the GUI thread: queued calls run there (a lambda would run nowhere).
        invoker.call.connect(invoker.run, Qt.ConnectionType.QueuedConnection)
        _invoker = invoker
    _invoker.call.emit(function)
    return True


_invoker = None


def _qt_clipboard(text, auto_clear, clear_seconds):
    def put():
        from qtpy.QtCore import QMimeData
        from qtpy.QtGui import QGuiApplication
        data = QMimeData()
        data.setText(text)
        if auto_clear:
            data.setData("x-kde-passwordManagerHint", b"secret")  # Klipper and others leave it out of their history
        QGuiApplication.clipboard().setMimeData(data)

    def clear():
        from qtpy.QtGui import QGuiApplication
        board = QGuiApplication.clipboard()
        if board.text() == text:
            board.clear()

    if not gui_call(put):
        return False
    if auto_clear:
        threading.Timer(clear_seconds, lambda: gui_call(clear)).start()
    return True


def _tool_clipboard(text, auto_clear, clear_seconds):
    wayland = bool(os.environ.get("WAYLAND_DISPLAY"))
    tools = ([["wl-copy"], ["wl-paste", "--no-newline"]] if wayland and shutil.which("wl-copy") else
             [["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"]] if shutil.which("xclip") else
             [["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"]] if shutil.which("xsel") else None)
    if not tools:
        return
    copy, paste = tools
    try:
        subprocess.run(copy, input=text.encode("utf-8"), timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return

    def clear():
        time.sleep(clear_seconds)
        current = _run(paste)
        if current is not None and current.stdout == text:
            subprocess.run(copy, input=b"", timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if auto_clear:
        threading.Thread(target=clear, daemon=True).start()


def copy_to_clipboard(text, auto_clear=True, clear_seconds=30):
    if not _qt_clipboard(text, auto_clear, clear_seconds):
        _tool_clipboard(text, auto_clear, clear_seconds)


def notify(title, text):
    icon = Path(__file__).resolve().parent.parent / "assets" / "icon.png"
    _run(["notify-send", "--app-name=SecretBroker", f"--icon={icon}", title, text])


def open_path(path):
    spawn_detached(["xdg-open", str(path)])


def show_in_folder(path):
    """The file manager with the file selected (org.freedesktop.FileManager1: Files, Dolphin...), else its folder."""
    path = Path(path).resolve()
    if path.is_file() and _run(["gdbus", "call", "--session", "--dest", "org.freedesktop.FileManager1",
                                "--object-path", "/org/freedesktop/FileManager1",
                                "--method", "org.freedesktop.FileManager1.ShowItems", f"['{path.as_uri()}']", ""]):
        return
    open_path(path if path.is_dir() else path.parent)


def run_installer(path):
    """Install a downloaded .deb with apt, after the administrator's consent (polkit). The caller restarts the
    app afterwards (Windows' installer does that by itself)."""
    if not shutil.which("pkexec"):
        raise OSError(tr("linux.pkexec_is_missing_install_update"))
    result = subprocess.run(["pkexec", "/usr/bin/apt-get", "install", "-y", "--allow-downgrades", str(path)],
                            capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if result.returncode in (126, 127):  # the user dismissed the dialog, or was not allowed
        raise InstallCancelled()
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "apt-get falló").strip().splitlines()[-1])
    return "restart"


# --------------------------------------------------------------------------- other programs


def claude_desktop_config_dirs(home):
    yield roaming_dir(home) / "Claude"


def history_files(home):
    home = Path(home)
    files = [local_dir(home) / "fish" / "fish_history",
             local_dir(home) / "powershell" / "PSReadLine" / "ConsoleHost_history.txt"]
    return [p for p in files if p.is_file()]


def saved_environment():
    """/etc/environment and systemd's environment.d: what every new session starts with."""
    values = parse_env_file("/etc/environment")
    folder = roaming_dir(Path.home()) / "environment.d"
    if folder.is_dir():
        for file in sorted(folder.glob("*.conf")):
            for name, value in parse_env_file(file).items():
                values.setdefault(name, value)
    return values


__all__ = list(INTERFACE)
