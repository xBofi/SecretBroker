"""macOS: not finished yet. What only needs POSIX works; what needs a macOS API raises NotImplementedError.

TODO(macos) for whoever completes the port (see docs/ARCHITECTURE.md, "Platforms"):
  - isolation: a hidden `_secretbroker` role account and a LaunchDaemon per owner (/Library/LaunchDaemons),
    data in /Library/Application Support/SecretBroker/<owner>/{data,public} with the same modes as Linux;
  - verify_os_password: PAM works on macOS too (service "secretbroker" -> pam_opendirectory), or
    OpenDirectory's ODRecord.verifyPassword;
  - biometric: Touch ID through LocalAuthentication (LAContext.evaluatePolicy) signing with a Secure Enclave key;
  - protect_for_user: the login Keychain (Security.framework, kSecClassGenericPassword);
  - session_locked: CGSessionCopyCurrentDictionary()["CGSSessionScreenIsLocked"];
  - autostart: a LaunchAgent plist in ~/Library/LaunchAgents (or SMAppService on macOS 13+);
  - tray: pystray's darwin backend or an NSStatusItem; clipboard: NSPasteboard with org.nspasteboard.ConcealedType;
  - updates: a signed, notarized .dmg or .pkg (INSTALLER_RE below) opened with `open`.
"""

import os
import pwd
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from .. import hello as biometric  # noqa: F401  TODO(macos): Touch ID; until then is_supported() is False
from ._common import INTERFACE, ProtectError, key_file, open_sealed, seal, write_private
from ..i18n import tr

NAME = "macos"
OS_LABEL = "macOS"
NO_WINDOW = 0
INSTALLER_RE = r"^SecretBroker-(\d+\.\d+\.\d+)\.dmg$"
SERVICE_KEY_FILE = "machine.key"
SUPPORT = Path.home() / "Library" / "Application Support"


def _todo(what):
    raise NotImplementedError(f"macOS: {what} todavía no está implementado")


def _user():
    return pwd.getpwuid(os.getuid()).pw_name


# --------------------------------------------------------------------------- folders


def installed_root():
    return Path("/Library/Application Support/SecretBroker") / _user()


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
    write_private(path, text.encode("utf-8"), 0o640 if isolated else 0o600)


# --------------------------------------------------------------------------- identity


def default_owner():
    return _user()


def os_password_available():
    return False  # TODO(macos): PAM / OpenDirectory


def verify_os_password(owner, password):
    _todo("comprobar la contraseña de la cuenta")


def protect_for_service(data, entropy, folder):
    """Same as Linux until the LaunchDaemon exists: a 0600 key file of the service account."""
    return seal(key_file(Path(folder) / SERVICE_KEY_FILE), data, entropy)


def unprotect_for_service(blob, entropy, folder):
    path = Path(folder) / SERVICE_KEY_FILE
    if not path.exists():
        raise ProtectError(tr("linux.this_computer_key_is_missing"))
    return open_sealed(key_file(path), blob, entropy)


def protect_for_user(data, entropy):
    _todo("guardar la clave en el Llavero")  # TODO(macos): Keychain


def unprotect_for_user(blob, entropy):
    raise ProtectError(tr("macos.macos_opening_with_session_isn"))  # TODO(macos): Keychain


# --------------------------------------------------------------------------- processes


def python_gui():
    return sys.executable


def python_console():
    return sys.executable


def spawn_detached(args):
    subprocess.Popen(args, start_new_session=True, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_service():
    return False  # TODO(macos): launchctl kickstart of the owner's LaunchDaemon


# --------------------------------------------------------------------------- the desktop session


def session_locked():
    _todo("detectar la pantalla bloqueada")  # TODO(macos): CGSessionCopyCurrentDictionary


def autostart_command():
    return f'"{sys.executable}" -I -m secretbroker.app --background'


def set_autostart(enabled):
    if enabled:
        _todo("arrancar con la sesión")  # TODO(macos): ~/Library/LaunchAgents plist / SMAppService


def remove_autostart():
    pass  # TODO(macos): remove the LaunchAgent


def single_instance():
    return True  # TODO(macos): the Linux socket approach works on macOS too (no SO_PEERCRED: use LOCAL_PEERCRED)


def signal_running_instance():
    pass


def listen_for_show(show):
    pass


def copy_to_clipboard(text, auto_clear=True, clear_seconds=30):
    """pbcopy works everywhere. TODO(macos): NSPasteboard with org.nspasteboard.ConcealedType for secrets."""
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
    pass  # TODO(macos): UNUserNotificationCenter (osascript "display notification" as a stopgap)


def open_path(path):
    spawn_detached(["open", str(path)])


def show_in_folder(path):
    path = Path(path)
    spawn_detached(["open", str(path)] if path.is_dir() else ["open", "-R", str(path)])


def run_installer(path):
    _todo("instalar actualizaciones")  # TODO(macos): open the .dmg / installer -pkg with admin consent


# --------------------------------------------------------------------------- other programs


def claude_desktop_config_dirs(home):
    yield roaming_dir(home) / "Claude"


def history_files(home):
    return []


def saved_environment():
    return {}  # TODO(macos): launchctl getenv / ~/.MacOSX/environment.plist are rarely used; nothing for now


__all__ = list(INTERFACE)
