"""Client for the SecretBroker service, shared by the desktop app and the MCP server."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto, paths


UNLOCK_WAIT_SECONDS = 120
APP_START_WAIT_SECONDS = 20


class BrokerUnavailable(Exception):
    pass


class BrokerError(Exception):
    def __init__(self, message, code="error"):
        super().__init__(message)
        self.code = code


def _broker_info():
    try:
        return json.loads(paths.broker_file().read_text())
    except (OSError, ValueError):
        raise BrokerUnavailable("El servicio SecretBroker no está en marcha") from None


def request(op, params=None, timeout=600):
    info = _broker_info()
    nonce = os.urandom(16)
    message = {"token": info["token"], "op": op, "params": params or {}, "nonce": crypto.b64(nonce)}
    try:
        with socket.create_connection(("127.0.0.1", info["port"]), timeout=5) as sock:
            sock.settimeout(timeout)
            sock.sendall(json.dumps(message).encode("utf-8") + b"\n")
            with sock.makefile("rb") as reader:
                line = reader.readline()
    except OSError:
        raise BrokerUnavailable("No se puede conectar con el servicio SecretBroker") from None
    if not line:
        raise BrokerUnavailable("El servicio SecretBroker cerró la conexión")
    envelope = json.loads(line)
    # Only the real service holds the private key published in broker.json.
    try:
        Ed25519PublicKey.from_public_bytes(crypto.unb64(info["public_key"])).verify(
            crypto.unb64(envelope["sig"]), nonce + envelope["body"].encode("utf-8"))
    except (InvalidSignature, KeyError, ValueError):
        raise BrokerUnavailable("La respuesta no viene del servicio SecretBroker auténtico") from None
    response = json.loads(envelope["body"])
    if not response.get("ok"):
        raise BrokerError(response.get("error", "Error desconocido"), response.get("code", "error"))
    return response["result"]


def is_running():
    try:
        request("status", timeout=5)
        return True
    except (BrokerUnavailable, BrokerError):
        return False


def _pythonw():
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate if candidate.exists() else sys.executable)


def _spawn(module):
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    # -I: ignore PYTHON* variables and the user's site-packages, which other processes could tamper with.
    subprocess.Popen([_pythonw(), "-I", "-m", module], creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_service(wait_seconds=15):
    """In development mode the service runs as the current user and is started on demand.
    In installed mode it is started by Windows and must never be replaced by a user process."""
    if is_running():
        return True
    if paths.is_installed():
        return False
    _spawn("secretbroker.service")
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        time.sleep(0.3)
        if is_running():
            return True
    return False


def launch_app():
    _spawn("secretbroker.app")


def _wait(condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if condition(request("status", timeout=10)):
                return True
        except (BrokerError, BrokerUnavailable):
            pass
        time.sleep(1)
    return False


def call(op, params=None):
    """Like request(), but if the vault is locked or an approval needs the app, open it, wait and retry once."""
    if not ensure_service():
        raise BrokerUnavailable("El servicio SecretBroker no está en marcha. Pide al usuario que lo revise.")
    for attempt in (1, 2):
        try:
            return request(op, params or {})
        except BrokerError as exc:
            if attempt == 2 or exc.code not in ("locked", "gui_required"):
                raise
            launch_app()
            if exc.code == "locked":
                if not _wait(lambda s: s["state"] == "unlocked", UNLOCK_WAIT_SECONDS):
                    raise BrokerError("La bóveda sigue bloqueada. Se ha abierto SecretBroker para que el usuario la desbloquee; "
                                      "reintenta cuando lo haya hecho.", "locked") from None
            elif not _wait(lambda s: s.get("gui_connected"), APP_START_WAIT_SECONDS):
                raise BrokerError("Hace falta la aprobación del usuario, pero la app SecretBroker no se ha abierto.",
                                  "gui_required") from None
