"""Client for the SecretBroker service, shared by the desktop app and the MCP server."""

import json
import os
import socket
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto, paths, platform
from .i18n import tr


UNLOCK_WAIT_SECONDS = 120
# The language the app shows (set by app.py): sent with every request so the service answers in it. The MCP
# server and sb leave it unset and get the service's (the last one the app used).
LANG = None
APP_START_WAIT_SECONDS = 20
# "Open with my Windows session": a token kept under the user's login (Windows: DPAPI; Linux: the Secret
# Service keyring, see platform.protect_for_user), written by the app.
SESSION_FILE = paths.user_dir() / "session.bin"
SESSION_ENTROPY = b"SecretBroker/session-unlock/v1"


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
        raise BrokerUnavailable(tr("client.secretbroker_service_isn_running")) from None


def request(op, params=None, timeout=600, meta=None, client=None):
    """`meta`: a dict that receives what the service answers besides the result (a new one-click token).
    `client`: the AI program (MCP client name), for «Clientes conectados»."""
    info = _broker_info()
    nonce = os.urandom(16)
    message = {"token": info["token"], "op": op, "params": params or {}, "nonce": crypto.b64(nonce)}
    if client:
        message["client"] = client  # the AI program (MCP client name), for «Clientes conectados»
    if LANG:
        message["lang"] = LANG
    try:
        with socket.create_connection(("127.0.0.1", info["port"]), timeout=5) as sock:
            sock.settimeout(timeout)
            sock.sendall(json.dumps(message).encode("utf-8") + b"\n")
            with sock.makefile("rb") as reader:
                line = reader.readline()
    except OSError:
        raise BrokerUnavailable(tr("client.can_connect_secretbroker_service")) from None
    if not line:
        raise BrokerUnavailable(tr("client.secretbroker_service_closed_connection"))
    envelope = json.loads(line)
    # Only the real service holds the private key published in broker.json.
    try:
        Ed25519PublicKey.from_public_bytes(crypto.unb64(info["public_key"])).verify(
            crypto.unb64(envelope["sig"]), nonce + envelope["body"].encode("utf-8"))
    except (InvalidSignature, KeyError, ValueError):
        raise BrokerUnavailable(tr("client.answer_doesn_come_from_genuine")) from None
    response = json.loads(envelope["body"])
    if not response.get("ok"):
        raise BrokerError(response.get("error", "Error desconocido"), response.get("code", "error"))
    if meta is not None:
        meta.update({k: v for k, v in response.items() if k not in ("ok", "result")})
    return response["result"]


def is_running():
    try:
        request("status", timeout=5)
        return True
    except (BrokerUnavailable, BrokerError):
        return False


def _spawn(module):
    # -I: ignore PYTHON* variables and the user's site-packages, which other processes could tamper with.
    platform.spawn_detached([platform.python_gui(), "-I", "-m", module])


def ensure_service(wait_seconds=15):
    """In development mode the service runs as the current user and is started on demand.
    In installed mode it is started by the system and must never be replaced by a user process
    (on Linux the user may ask systemd to start their own unit; on Windows it is always running)."""
    if is_running():
        return True
    if paths.is_installed():
        if not platform.start_service():
            return False
    else:
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


def session_token():
    """The token of "open with my Windows session", or None when it is off on this PC."""
    try:
        return platform.unprotect_for_user(SESSION_FILE.read_bytes(), SESSION_ENTROPY).decode()
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def reopen_with_session():
    """Open the vault again without a password when the user turned on the Windows session unlock (after the
    inactivity lock). Anything running as the user can do this: that is what that option means."""
    token = session_token()
    if not token:
        return False
    try:
        request("unlock", {"proof": {"kind": "session", "token": token}}, timeout=30)
        return True
    except (BrokerError, BrokerUnavailable):
        return False


def call(op, params=None, open_app=None, client=None):
    """Like request(), but if the vault is locked or an approval needs the app, open it, wait and retry once.
    open_app shows the app; by default it is started (or, if it is already running, brought forward).
    Locked with the Windows session unlock on, it opens again by itself: nobody has to type anything."""
    if not ensure_service():
        raise BrokerUnavailable(tr("client.secretbroker_service_isn_running_ask"))
    for attempt in (1, 2):
        try:
            return request(op, params or {}, client=client)
        except BrokerError as exc:
            if attempt == 2 or exc.code not in ("locked", "gui_required"):
                raise
            if exc.code == "locked" and reopen_with_session():
                continue
            (open_app or launch_app)()
            if exc.code == "locked":
                if not _wait(lambda s: s["state"] == "unlocked", UNLOCK_WAIT_SECONDS):
                    raise BrokerError(tr("client.vault_is_still_locked_secretbroker"), "locked") from None
            elif not _wait(lambda s: s.get("gui_connected"), APP_START_WAIT_SECONDS):
                raise BrokerError(tr("client.user_approval_is_needed_but"),
                                  "gui_required") from None
