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


def broker_file(base=None):
    return (base or root()) / "public" / "broker.json"
