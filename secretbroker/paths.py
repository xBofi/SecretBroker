"""Where SecretBroker keeps its files.

Installed (isolated) mode:  C:\\ProgramData\\SecretBroker\\{data,public}
    data   -> only the SecretBroker service account can read it (vault, keys, audit log)
    public -> written by the service, readable by users (port + public key of the running service)
Development mode:           %APPDATA%\\SecretBroker\\{data,public}, everything as the current user.
SECRETBROKER_HOME overrides both (used by the tests).
"""

import os
from pathlib import Path

INSTALLED_ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecretBroker"
DEV_ROOT = Path(os.environ.get("APPDATA", Path.home())) / "SecretBroker"


def is_installed():
    return not os.environ.get("SECRETBROKER_HOME") and (INSTALLED_ROOT / "public").is_dir()


def root():
    if os.environ.get("SECRETBROKER_HOME"):
        return Path(os.environ["SECRETBROKER_HOME"])
    return INSTALLED_ROOT if is_installed() else DEV_ROOT


def instance_suffix():
    """"" for the real app; a tag for a test instance (SECRETBROKER_HOME), so that it never touches
    the real one's window, settings, registry entries or Claude Code connection."""
    home = os.environ.get("SECRETBROKER_HOME")
    if not home:
        return ""
    import hashlib
    return "-test-" + hashlib.sha256(home.encode("utf-8")).hexdigest()[:8]


def user_dir():
    """Per-user files of the desktop app (preferences, logs, WebView2 data)."""
    if os.environ.get("SECRETBROKER_HOME"):
        return Path(os.environ["SECRETBROKER_HOME"]) / "user"
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretBroker"


def broker_file(base=None):
    return (base or root()) / "public" / "broker.json"
