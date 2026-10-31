"""macOS (12 Monterey and later): OpenDirectory, the login Keychain, Touch ID, launchd, distributed notifications.

Isolation mirrors Linux (see docs/ARCHITECTURE.md, "Platforms"): the installed service runs as the hidden role
account `_secretbroker` under the LaunchDaemon com.secretbroker.service.<owner>, its data lives in
/Library/Application Support/SecretBroker/<owner>/data (0700, only that account) and broker.json in .../public,
which belongs to `_secretbroker` and which an ACL lets the owner, and only the owner, read (on macOS every
desktop account shares the primary group `staff`, so a group could not do it). The package's
secretbroker-setup (packaging/macos) creates all of this as root.

Everything that needs a macOS framework (pyobjc) is imported inside the function that uses it: Windows and
Linux never import pyobjc, and the service only loads OpenDirectory.

Written without a Mac to test on: what has run is listed in docs/RELEASING.md ("macOS: what is untested").
"""

import os
import plistlib
import pwd
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from .. import touchid as biometric  # noqa: F401  Touch ID (falls back to password proofs where it cannot work)
from ._common import INTERFACE, InstallCancelled, ProtectError, key_file, open_sealed, seal, write_private
from ..i18n import tr

NAME = "macos"
OS_LABEL = "macOS"
NO_WINDOW = 0
APP_BUNDLE = Path("/Applications/SecretBroker.app")
STATE_ROOT = Path("/Library/Application Support/SecretBroker")
DAEMON_LABEL = "com.secretbroker.service.{user}"
DAEMON_DIR = Path("/Library/LaunchDaemons")
AGENT_LABEL = "com.secretbroker.app{suffix}"
SERVICE_KEY_FILE = "machine.key"
USER_KEY_FILE = "user.key"
KEYCHAIN_SERVICE = "SecretBroker"
KEYCHAIN_ACCOUNT = "session-unlock{suffix}"
KEYCHAIN_SECONDS = 5
SUPPORT = Path.home() / "Library" / "Application Support"


def _machine():
    """arm64 (Apple silicon) or x86_64 (Intel): each has its own package."""
    return "arm64" if os.uname().machine == "arm64" else "x86_64"


INSTALLER_RE = rf"^SecretBroker-(\d+\.\d+\.\d+)-macos-{_machine()}\.pkg$"


def _suffix():
    from .. import paths
    return paths.instance_suffix()


def _user():
    return pwd.getpwuid(os.getuid()).pw_name


def _run(args, timeout=5, input=None):
    """A short helper program; None when it is missing or fails."""
    if not shutil.which(args[0]):
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input,
                                stdin=None if input is not None else subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return result if result.returncode == 0 else None


# --------------------------------------------------------------------------- folders


def installed_root():
    return STATE_ROOT / _user()


def dev_root():
    return SUPPORT / "SecretBroker" / "service"


def user_dir():
    return SUPPORT / "SecretBroker" / "app"


def roaming_dir(home):
    return Path(home) / "Library" / "Application Support"


def local_dir(home):
    return Path(home) / "Applications"


def profile_app_dirs(home):
    return [Path(home) / "Library"]


def secure_data_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_public_file(path, text, isolated):
    """Installed, public/ carries an inherited ACL entry that lets the owner read what the service writes there
    (secretbroker-setup); the mode bits stay 0640 (`_secretbroker`'s own group). In development: 0600."""
    write_private(path, text.encode("utf-8"), 0o640 if isolated else 0o600)


# --------------------------------------------------------------------------- identity


def default_owner():
    return _user()


def _od_record(owner):
    from OpenDirectory import ODNode, ODSession, kODNodeTypeAuthentication, kODRecordTypeUsers
    node, error = ODNode.nodeWithSession_type_error_(ODSession.defaultSession(), kODNodeTypeAuthentication, None)
    if node is None:
        return None
    record, error = node.recordWithRecordType_name_attributes_error_(kODRecordTypeUsers, owner, None, None)
    return record


def os_password_available():
    try:
        import OpenDirectory  # noqa: F401
        return True
    except ImportError:
        return False


def verify_os_password(owner, password):
    """The owner's login password, checked by Open Directory (the system's own check, the one the lock screen
    uses: it also counts failed attempts). Nothing is stored and the password never reaches a command line."""
    if not password or not owner or "/" in owner or "\\" in owner:
        return False
    try:
        record = _od_record(owner)
        if record is None:
            return False
        ok, _error = record.verifyPassword_error_(password, None)
        return bool(ok)
    except Exception:
        return False


# --------------------------------------------------------------------------- keys kept by the system


def protect_for_service(data, entropy, folder):
    """AES-GCM with a key in a 0600 file of `_secretbroker` (next to the vault, in a 0700 folder). A role account
    has no keychain of its own; a copy of the protected file alone (a backup) cannot be opened."""
    return seal(key_file(Path(folder) / SERVICE_KEY_FILE), data, entropy)


def unprotect_for_service(blob, entropy, folder):
    path = Path(folder) / SERVICE_KEY_FILE
    if not path.exists():
        raise ProtectError(tr("linux.this_computer_key_is_missing"))
    return open_sealed(key_file(path), blob, entropy)


def _keychain_query(Security):
    return {Security.kSecClass: Security.kSecClassGenericPassword,
            Security.kSecAttrService: KEYCHAIN_SERVICE,
            Security.kSecAttrAccount: KEYCHAIN_ACCOUNT.format(suffix=_suffix())}


def _keychain_key_now(create):
    try:
        import Security
        from Foundation import NSData
    except ImportError:
        return None
    query = _keychain_query(Security)
    # Never show a dialog ("python wants to use your confidential information"): this also runs when the AI's
    # request reopens the vault, with nobody looking. Failing falls back to the password.
    status, found = Security.SecItemCopyMatching({**query, Security.kSecReturnData: True,
                                                  Security.kSecUseAuthenticationUI: Security.kSecUseAuthenticationUIFail}, None)
    if status == 0 and found is not None and len(bytes(found)) == 32:
        return bytes(found)
    if not create or status not in (0, -25300):  # anything but "not found" (locked, refused): do not overwrite
        return None
    key = os.urandom(32)
    Security.SecItemDelete(query)
    attributes = {**query, Security.kSecValueData: NSData.dataWithBytes_length_(key, len(key)),
                  Security.kSecAttrLabel: tr("macos.keychain_item_label")}
    # Any error (a refused or unexpected attribute included) leaves the 0600 file to the caller: never worse.
    return key if Security.SecItemAdd(attributes, None)[0] == 0 else None


def _keychain_key(create):
    """A random key kept in the user's login Keychain (unlocked with the login), or None. Never waits for the
    user: a Keychain that does not answer in time counts as missing."""
    result = {}

    def work():
        try:
            result["key"] = _keychain_key_now(create)
        except Exception:
            result["key"] = None

    worker = threading.Thread(target=work, daemon=True, name="keychain")
    worker.start()
    worker.join(KEYCHAIN_SECONDS)
    return result.get("key")


def protect_for_user(data, entropy):
    """Under the desktop user's login: the key is in the login Keychain, else in a 0600 file of the user.
    Either way, programs running as the user can use it: that is what "open with my session" means."""
    key = _keychain_key(create=True)
    if key is not None:
        return b"k" + seal(key, data, entropy)
    return b"f" + seal(key_file(user_dir() / USER_KEY_FILE), data, entropy)


def unprotect_for_user(blob, entropy):
    kind, rest = blob[:1], blob[1:]
    if kind == b"k":
        key = _keychain_key(create=False)
        if key is None:
            raise ProtectError(tr("macos.session_keychain_isn_available"))
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
    """launchd keeps the owner's LaunchDaemon running (KeepAlive) and restarts it within seconds when it stops;
    an account cannot start a system daemon itself. True when there is one to wait for."""
    return (DAEMON_DIR / f"{DAEMON_LABEL.format(user=_user())}.plist").is_file()


# --------------------------------------------------------------------------- the desktop session

_lock = {"locked": None, "watch": "new"}  # watch: new, on (notifications arrive) or off (ask CGSession)
_lock_guard = threading.Lock()


def _cgsession_locked():
    try:
        import Quartz
        session = Quartz.CGSessionCopyCurrentDictionary() or {}
        return bool(session.get("CGSSessionScreenIsLocked", False))
    except Exception:
        return False


def _watch_lock_notifications():
    """com.apple.screenIsLocked / screenIsUnlocked, posted by loginwindow, on a thread with its own run loop.
    Delivered immediately: by default AppKit holds distributed notifications back while the app is inactive,
    which it always is while the screen is locked."""
    import objc
    from Foundation import NSDate, NSDistributedNotificationCenter, NSObject, NSRunLoop

    class SecretBrokerLockObserver(NSObject):
        @objc.typedSelector(b"v@:@")
        def locked_(self, _notification):
            _lock["locked"] = True

        @objc.typedSelector(b"v@:@")
        def unlocked_(self, _notification):
            _lock["locked"] = False

    observer = SecretBrokerLockObserver.alloc().init()
    center = NSDistributedNotificationCenter.defaultCenter()
    immediately = 4  # NSNotificationSuspensionBehaviorDeliverImmediately
    center.addObserver_selector_name_object_suspensionBehavior_(observer, b"locked:", "com.apple.screenIsLocked", None, immediately)
    center.addObserver_selector_name_object_suspensionBehavior_(observer, b"unlocked:", "com.apple.screenIsUnlocked", None, immediately)
    _lock["watch"] = "on"
    loop = NSRunLoop.currentRunLoop()
    while True:
        loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(5.0))


def session_locked():
    """True while the lock screen shows. The first answer comes from the window server (CGSession); after
    that, loginwindow's notifications keep it current."""
    with _lock_guard:
        if _lock["watch"] == "new":
            _lock["watch"] = "starting"
            _lock["locked"] = _cgsession_locked()

            def watch():
                try:
                    _watch_lock_notifications()
                except Exception:
                    _lock["watch"] = "off"  # no pyobjc here: ask CGSession every time

            threading.Thread(target=watch, daemon=True, name="lock-notifications").start()
            return bool(_lock["locked"])
    if _lock["watch"] == "on":
        return bool(_lock["locked"])
    return _cgsession_locked()


def _agent_file():
    return Path.home() / "Library" / "LaunchAgents" / f"{AGENT_LABEL.format(suffix=_suffix())}.plist"


def _autostart_args():
    if APP_BUNDLE.is_dir() and str(sys.executable).startswith(str(APP_BUNDLE) + "/"):
        # Through Launch Services, so the Dock and the menu bar show SecretBroker, not Python.
        return ["/usr/bin/open", "-g", "-a", str(APP_BUNDLE), "--args", "--background"]
    return [sys.executable, "-I", "-m", "secretbroker.app", "--background"]


def autostart_command():
    return " ".join(f'"{a}"' if " " in a else a for a in _autostart_args())


def set_autostart(enabled):
    """A LaunchAgent in ~/Library/LaunchAgents: launchd starts it at the next login (System Settings lists it
    under Login Items, where the user can turn it off too)."""
    file = _agent_file()
    if not enabled:
        file.unlink(missing_ok=True)
        return
    file.parent.mkdir(parents=True, exist_ok=True)
    data = plistlib.dumps({"Label": AGENT_LABEL.format(suffix=_suffix()), "ProgramArguments": _autostart_args(),
                           "RunAtLoad": True, "LimitLoadToSessionType": "Aqua", "ProcessType": "Interactive"})
    if not file.is_file() or file.read_bytes() != data:
        file.write_bytes(data)


def remove_autostart():
    _agent_file().unlink(missing_ok=True)


# --------------------------------------------------------------------------- one window: a second start shows the first

_instance = None  # the listening socket of the first app


def _instance_address():
    """A socket in the user's private temporary folder ($TMPDIR is per user on macOS, 0700)."""
    folder = os.environ.get("TMPDIR") or "/tmp"
    return os.path.join(folder, f"secretbroker-app{_suffix()}-{os.getuid()}.sock")


def _peer_uid(conn):
    # LOCAL_PEERCRED (SOL_LOCAL = 0, LOCAL_PEERCRED = 1): struct xucred {u_int cr_version; uid_t cr_uid; ...}
    creds = conn.getsockopt(0, 1, 76)
    return int.from_bytes(creds[4:8], sys.byteorder)


def single_instance():
    global _instance
    address = _instance_address()
    for _ in range(2):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(address)
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
                    conn.settimeout(2)
                    if _peer_uid(conn) == os.getuid() and conn.recv(16).startswith(b"show"):
                        show()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True, name="show-socket").start()


# --------------------------------------------------------------------------- clipboard, notifications, opening files


def _pasteboard_copy(text, auto_clear, clear_seconds):
    """NSPasteboard, marked with org.nspasteboard.ConcealedType so clipboard managers (Alfred, Raycast, Paste...)
    leave secrets out of their history, and TransientType so they do not keep it at all."""
    try:
        from AppKit import NSPasteboard, NSPasteboardTypeString
    except ImportError:
        return False
    board = NSPasteboard.generalPasteboard()
    board.clearContents()
    board.setString_forType_(text, NSPasteboardTypeString)
    if auto_clear:
        board.setString_forType_("", "org.nspasteboard.ConcealedType")
        board.setString_forType_("", "org.nspasteboard.TransientType")
        count = board.changeCount()
        _copied_count[0] = count

        def clear():
            if board.changeCount() == count:  # nothing else was copied since
                board.clearContents()

        timer = threading.Timer(clear_seconds, clear)
        timer.daemon = True  # never keeps a short-lived process (the browser's native host) alive
        timer.start()
    return True


_copied_count = [0]  # the pasteboard's change count after our last copy


def clear_copied():
    """Clear the pasteboard now if it still holds our last copy: a process about to exit cannot wait for the timer."""
    if not _copied_count[0]:
        return
    from AppKit import NSPasteboard
    board = NSPasteboard.generalPasteboard()
    if board.changeCount() == _copied_count[0]:
        board.clearContents()


def copy_to_clipboard(text, auto_clear=True, clear_seconds=30):
    try:
        if _pasteboard_copy(text, auto_clear, clear_seconds):
            return
    except Exception:
        pass
    if not shutil.which("pbcopy"):
        return
    subprocess.run(["pbcopy"], input=text.encode("utf-8"), timeout=5)
    if auto_clear:
        def clear():
            time.sleep(clear_seconds)
            current = subprocess.run(["pbpaste"], capture_output=True, timeout=5)
            if current.stdout.decode("utf-8", "replace") == text:
                subprocess.run(["pbcopy"], input=b"", timeout=5)

        threading.Thread(target=clear, daemon=True).start()


def notify(title, text):
    """Notification Center through AppleScript: the user notification API needs a signed app. Title and text
    go as arguments, never inside the script."""
    script = ['on run argv', 'display notification (item 2 of argv) with title (item 1 of argv)', 'end run']
    args = ["osascript"] + [part for line in script for part in ("-e", line)] + [title, text]
    _run(args, timeout=10)


def open_path(path):
    spawn_detached(["open", str(path)])


def show_in_folder(path):
    path = Path(path)
    spawn_detached(["open", str(path)] if path.is_dir() else ["open", "-R", str(path)])


def run_installer(path):
    """Install a downloaded .pkg with the system's installer, after an administrator's consent (the standard
    macOS dialog, like UAC on Windows). The package restarts the service; the caller restarts the app."""
    script = ['on run argv',
              'do shell script "/usr/sbin/installer -pkg " & quoted form of (item 1 of argv) & " -target /" '
              'with administrator privileges',
              'end run']
    args = ["osascript"] + [part for line in script for part in ("-e", line)] + [str(path)]
    result = subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if "-128" in message or re.search(r"cancel", message, re.IGNORECASE):  # the user closed the dialog
            raise InstallCancelled()
        raise OSError(message.splitlines()[-1] if message else tr("macos.installer_failed"))
    return "restart"


def restart_command():
    """What starts the app again after an update: the bundle through Launch Services when installed."""
    if APP_BUNDLE.is_dir():
        return ["/bin/sh", "-c", 'sleep 2; exec /usr/bin/open -n -a "$0"', str(APP_BUNDLE)]
    return ["/bin/sh", "-c", 'sleep 2; exec "$0" -I -m secretbroker.app', sys.executable]


# --------------------------------------------------------------------------- other programs


def claude_desktop_config_dirs(home):
    yield roaming_dir(home) / "Claude"


def history_files(home):
    """Besides ~/.zsh_history (scanner.HISTORY_FILES): Terminal.app keeps one zsh history per window in
    ~/.zsh_sessions, and fish / PowerShell keep theirs in XDG folders on macOS too."""
    home = Path(home)
    files = [home / ".local" / "share" / "fish" / "fish_history",
             home / ".local" / "share" / "powershell" / "PSReadLine" / "ConsoleHost_history.txt"]
    sessions = home / ".zsh_sessions"
    if sessions.is_dir():
        files += sorted(sessions.glob("*.history"))
    return [p for p in files if p.is_file()]


def saved_environment():
    """`launchctl setenv` values (what new GUI programs start with). ~/.MacOSX/environment.plist is long gone."""
    values = {}
    result = _run(["launchctl", "export"])
    if result is None:
        return values
    for line in result.stdout.splitlines():  # `NAME="value"; export NAME;`
        match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)="(.*)"; export \1;$', line.strip())
        if match:
            values.setdefault(match[1], match[2].replace('\\"', '"'))
    return values


__all__ = list(INTERFACE) + ["restart_command", "clear_copied"]
