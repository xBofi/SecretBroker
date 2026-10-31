"""Where SecretBroker keeps its files.

Installed (isolated) mode:  {data,public} in
    Windows  C:\\ProgramData\\SecretBroker
    Linux    /var/lib/secretbroker/<owner>          (see platform/linux.py)
    data   -> only the SecretBroker service account can read it (vault, keys, audit log)
    public -> written by the service, readable by the owner (port + public key of the running service)
Development mode:           {data,public} in %APPDATA%\\SecretBroker (Linux: ~/.local/share/secretbroker),
                            everything as the current user.
SECRETBROKER_HOME overrides both (used by the tests).
"""

import os
from pathlib import Path

from . import platform

INSTALLED_ROOT = platform.installed_root()
DEV_ROOT = platform.dev_root()


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
    return platform.user_dir()


def broker_file(base=None):
    return (base or root()) / "public" / "broker.json"
