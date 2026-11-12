"""SecretBroker service: owns the vault and performs actions with secrets.

In installed mode it runs as a dedicated account (Windows: a local account; Linux: the `secretbroker` system
user, see platform/linux.py), so processes of the desktop user
(including AI agents) can neither read its memory nor its files. Clients talk to it over
127.0.0.1; every response is signed so clients can tell it is the real service.

Sensitive operations need a *proof* the service verifies by itself:
  hello            RSA signature from the owner's Windows Hello key over a one-time challenge
  windows_password the owner's operating system account password (Windows: LogonUser; Linux: PAM)
  master_password  the vault master password
"""

import argparse
import base64
import collections
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import socketserver
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import actions, autofill, crypto, exposure, links, native_host, paths, platform, presets, rotation, teams, update, winsec
from .inject import ActionError, Redactor, substitute
from .vault import (
    CHECK_ONCE, DEFAULT_SETTINGS, ID_RE, valid_check_hours, TAG_RE, Vault, VaultLocked, ValidationError, WrongPassword, agent_view, secret_age_days, clean_used_in,
    check_master_password, convert_legacy_entry, entry_summary, can_write_shared, shared_content,
)
from . import templates
from . import __version__, exports, health, importers, totp
from . import i18n
from .i18n import tr

PROTOCOL_VERSION = 2
MAX_REQUEST_BYTES = 4 * 1024 * 1024
APPROVAL_TIMEOUT_SECONDS = 120
GUI_SEEN_SECONDS = 6
CHALLENGE_TTL_SECONDS = 180
AGENT_ACTIONS = set(actions.ACTIONS)
POLL_OPS = {"status", "pending_approvals", "audit", "update_status", "notices", "expired_approvals", "ai_clients"}
ALL_PROOFS = ("hello", "windows_password", "master_password")
APPROVAL_HOURS = (0, 8, 24)  # how long "don't ask again" lasts; 0: until the vault is locked
AUDIT_AAD = b"secretbroker/audit/v1"
SCAN_SESSION_SECONDS = 12 * 3600
RETIRED_CHECK_SECONDS = 24 * 3600  # old keys of a rotation by hand still waiting to be deleted
IMPORT_SESSION_SECONDS = 30 * 60   # between the preview of an import and its last batch
TOTP_AUDIT_SECONDS = 10 * 60       # showing a 2FA code is audited once in this time per credential
AI_CLIENT_NAME_RE = re.compile(r"^[\w .:@()/+-]{1,60}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SLUG_RE = re.compile(r"[^a-z0-9]+")
# Team operations that change something: the app that unlocked does them with one click. None is for the AI.
TEAM_CHANGE_OPS = ("team_connect", "team_disconnect", "team_create_org", "team_invite", "team_accept_invite",
                   "team_confirm_member", "team_set_role", "team_remove_member", "team_create_collection", "team_grant",
                   "team_revoke", "team_share_entry", "team_share_entries", "team_unshare_entry", "team_accept_change",
                   "team_verify_email", "team_send_code", "team_resolve_deletions", "team_share_with",
                   "team_unshare_with", "team_revoke_device", "team_change_password", "team_renew_invite",
                   "team_resend_invite", "team_drop_invite", "team_invite_code", "team_admin_backup_now",
                   "team_admin_settings", "team_admin_disable", "team_admin_enable", "team_admin_verify",
                   "team_admin_delete", "team_admin_transfer_owner", "team_admin_signup_token")
PRESENCE_OPS = ("approve", "complete_draft", "replace_key", "resume_ai", "set_ai_permissions", "backup", "restore",
                "import_file", "import_env_file", "export_vault") + TEAM_CHANGE_OPS  # what the app that unlocked may do with one click
# Operations that can send credentials or keys out of the vault (to someone else's account, or a file in clear).
# "Open with my Windows session" needs no proof, and anything running as the user (the AI's shell too) could use
# it to get a one-click token, so after such an unlock these need Hello or a password once; from then on they are
# one click again.
TEAM_EXPORT_OPS = ("team_connect", "team_invite", "team_renew_invite", "team_accept_invite", "team_confirm_member",
                   "team_set_role", "team_grant", "team_share_entry", "team_share_entries", "team_share_with",
                   "export_vault", "team_invite_code")  # an invite's code works as a sign-up code for its e-mail
# The server admin's changes that hand a server to someone else or take an account away: like inviting, a session
# unlock alone is not enough (a sign-up code lets anyone create an account; an owner gets recovery access).
TEAM_EXPORT_OPS += ("team_admin_disable", "team_admin_delete", "team_admin_transfer_owner", "team_admin_signup_token")
# Operations that may change a shared credential: the team sync runs soon after them to push it.
TEAM_PUSH_OPS = {"save_entry", "delete_entry", "replace_key", "rotate", "update_credential", "ai_rotate", "ai_delete"}
# Rotations from the app: one click. Copying a new password not applied yet gives it out, like exporting.
ROTATION_OPS = ("rotation_begin", "rotation_discard", "rotation_apply", "rotation_secret", "retry_uploads", "set_test_request")
PRESENCE_OPS += ROTATION_OPS
TEAM_EXPORT_OPS += ("rotation_secret",)
TEAM_PUSH_OPS |= {"rotation_apply", "set_test_request"}
# Everyday work in the app: one click once the user proved it at unlock (master password, Windows password or
# Hello). They show, change or delete secrets, so like TEAM_EXPORT_OPS a session unlock alone is not enough.
PROVEN_OPS = ("reveal", "save_entry", "delete_entry", "rotate", "set_settings", "exposure_begin", "enable_session_unlock",
              "team_resolve_deletions")
# Accepting a teammate's change lets a shared key go where they said (or the AI read their text): like approving
# the AI widening where a key may go (STRONG_APPROVALS), a session unlock alone is not enough.
PROVEN_OPS += ("team_accept_change",)
PRESENCE_OPS += PROVEN_OPS
# Connecting a browser lets it fill this user's logins: like the ops above, a session unlock is not enough.
PROVEN_OPS += ("browser_pair_answer",)
# An AI request the user approves with one click, except these: they delete, rotate or change where a key may go,
# so after a Windows-session unlock (no proof) the first one needs Hello or a password, like PROVEN_OPS.
STRONG_APPROVALS = ("delete", "rotate", "edit_config")
# What a proof is for, said after «Confirma que eres tú una vez … para» (messages service.purpose_*).
PROVEN_PURPOSE = {op: f"service.purpose_{op}" for op in (
    "browser_pair_answer", "reveal", "save_entry", "delete_entry", "team_resolve_deletions", "approve", "rotate", "set_settings",
    "exposure_begin", "enable_session_unlock", "export_vault", "rotation_secret", "totp_code", "team_accept_change",
    "team_invite_code", "team_admin_disable", "team_admin_delete", "team_admin_transfer_owner", "team_admin_signup_token")}
APPROVAL_EXPIRED_SECONDS = 600  # how long the app is told about a request nobody answered in time
# The browser extension, through native_host.py (see the browser section of Service). None is for the AI.
EXTENSION_OPS = ("ext_hello", "ext_pair", "ext_logins", "ext_search", "ext_fill", "ext_save_check", "ext_save")
BROWSER_PAIR_SECONDS = 300  # how long a request to connect a browser waits for the user's click
PRESENCE_OPS += ("browser_pair_answer",)
TEAM_PUSH_OPS.add("ext_save")
AI_USE_ACTIONS = AGENT_ACTIONS | {"release_env", "push_github_secret"}  # "last used" and "uses today" in approvals
# The current code of a login's 2FA (TOTP): one click from the app, but it gives a secret out, like copying.
PRESENCE_OPS += ("totp_code",)
TEAM_EXPORT_OPS += ("totp_code",)
TEAM_SYNC_SECONDS = 300
# What a sync records in Actividad: done by the team (with the name of who signed it), whoever started the sync.
TEAM_SYNC_EVENTS = {"team_add", "team_update", "team_delete", "team_review", "team_held", "team_unsigned",
                    "team_recovery", "team_conflict"}
# Everything the AI can ask for. "Pause the AI" refuses all of it without locking the vault.
AI_OPS = AGENT_ACTIONS | {"list_secrets", "release_env", "push_github_secret", "create_draft", "update_credential",
                          "request_access", "check_env", "import_env", "ai_check", "ai_rotate", "ai_activity",
                          "ai_delete"}
# What the AI may do beyond using a credential, and how freely. The user sets each one in the app:
#   free    follows each credential's own approval      notify  the same, and the user gets a notice
#   ask     the user confirms every time                 off     refused
AI_LEVELS = ("free", "notify", "ask", "off")
AI_CAPABILITIES = {
    "create": ("free", "Preparar credenciales nuevas"),
    "edit_notes": ("free", "Cambiar el nombre y las notas"),
    "edit_config": ("ask", "Cambiar adónde puede ir una clave guardada (webs, programas, variables)"),
    "local_env": ("free", "Pasar claves a programas de este PC"),
    "github": ("free", "Guardar claves como secretos de GitHub Actions"),
    "rotate": ("ask", "Rotar claves con su proveedor"),
}


def _capability_label(key):
    """The capability's name in the language of the request (the Spanish above is its source)."""
    return tr(f"service.capability_{key}")


MAX_USES = (0, 50, 100, 500)  # uses per hour of one credential before asking again (0: no limit)
REMINDER_DAYS = (0, 90, 180, 365)
EXPIRY_WARNING_DAYS = 14
NOTICE_EVERY_SECONDS = 600  # at most one "the AI used X" notice per credential in this time
# Who the operation running on this thread is for, written with each audit event: "ai" (an AI_OPS
# request), "user" (the app) or, outside any request (auto-lock, scheduled checks, team sync), none.
_ACTOR = threading.local()


class ServiceError(Exception):
    def __init__(self, message, code="error"):
        super().__init__(message)
        self.code = code


def op_digest(op, params):
    canonical = json.dumps({"op": op, "params": {k: v for k, v in params.items() if k != "proof"}},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


class Service:
    def __init__(self, root, owner, isolated):
        self.root = Path(root)
        self.data_dir = self.root / "data"
        self.public_dir = self.root / "public"
        self.owner = owner
        self.isolated = isolated
        self.vault = Vault(self.data_dir)
        self.hello_file = self.data_dir / "hello.json"
        self.session_file = self.data_dir / "session_unlock.json"  # "open with my Windows session" is on
        self.pause_file = self.data_dir / "ai_paused"
        self.audit_file = self.data_dir / "audit.log"
        self.legacy_files = [self.data_dir / "legacy_vault.json", self.root / "vault.json"]
        actions.configure(self.data_dir / "known_hosts")

        self.token = secrets.token_urlsafe(32)
        self.signing_key = Ed25519PrivateKey.generate()
        self._lock = threading.RLock()
        self._challenges = {}
        self._approvals = {}
        self._grants = {}      # secret id -> monotonic expiry of "don't ask again" (None: until locked)
        self._presence = None  # (token, expiry, strong): the app that unlocked may approve without a password
        self._last_activity = time.monotonic()
        self._gui_seen = 0.0
        self._failures = 0
        self._pending_audit = []
        self._scan_sessions = {}
        self._imports = {}     # import id -> the plan of a file being imported (see op_import_file)
        self._totp_seen = {}   # entry id -> monotonic time the 2FA code was last shown (audited once in a while)
        self.ai_clients_file = self.data_dir / "ai_clients.json"
        self._ai_clients = None  # client name -> {first, last, requests}: who used the MCP tools (no secrets)
        self._notices = collections.deque(maxlen=50)
        self._notice_id = 0
        self._noticed = {}
        self._uses = collections.defaultdict(collections.deque)  # secret id -> monotonic times of recent uses
        self._usage = None     # secret id -> {"last": iso, "days": {date: count}}: the AI's uses, for approvals
        self._audit_opened = {}  # audit line -> its event, decrypted (see op_audit); forgotten when locking
        self._expired = collections.deque(maxlen=20)  # approvals nobody answered in time (the app says so)
        self._revision = 0     # what the app shows changed outside the vault (approvals, the AI's uses)
        self._lock_reason = None  # why the vault is locked: "idle", "manual", "windows" (None: never opened)
        self._server = None
        self.updates = update.Checker()
        self.team = teams.Team(self.vault, on_removed=self._entry_removed)
        self._team_lock = threading.Lock()   # one team operation or sync at a time
        self._team_wake = threading.Event()  # set to sync now instead of waiting for the next round
        self._team_info = {"state": "idle"}
        self.browsers_file = self.data_dir / "browsers.json"  # browsers the user connected (key hashes, names)
        self._browser_pairs = None     # pair id -> {name, origin, key_hash, created}, read from browsers_file
        self._browser_requests = {}    # request id -> a browser asking to connect, until the user answers
        self._browser_seen = {}        # pair id -> when that browser last asked (since the service started)
        self._browser_used = {}        # entry id -> when the browser last filled it (to list it first)

    # ------------------------------------------------------------------ server

    def start(self, port=0):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        platform.secure_data_dir(self.data_dir)
        self.public_dir.mkdir(parents=True, exist_ok=True)
        self._server = _Server(("127.0.0.1", port), _Handler)
        self._server.service = self
        threading.Thread(target=self._server.serve_forever, daemon=True, name="server").start()
        threading.Thread(target=self._auto_lock_loop, daemon=True, name="auto-lock").start()
        threading.Thread(target=self._check_loop, daemon=True, name="exposure-check").start()
        threading.Thread(target=self._team_loop, daemon=True, name="team-sync").start()
        public_key = self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        info = {"port": self._server.server_address[1], "token": self.token, "pid": os.getpid(),
                "public_key": crypto.b64(public_key), "isolated": self.isolated, "protocol": PROTOCOL_VERSION}
        platform.write_public_file(paths.broker_file(self.root), json.dumps(info), self.isolated)
        return self._server.server_address[1]

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        self._lock_vault()

    def sign(self, nonce, body):
        return crypto.b64(self.signing_key.sign(nonce + body))

    # ------------------------------------------------------------------ dispatch

    def handle(self, op, params, client=None):
        # The app reloading by itself (`_poll`) is not someone using the vault: it must not keep it from locking.
        # Neither does the browser asking which logins a page has: only a click to fill or save (see op_ext_fill).
        if op not in POLL_OPS and op not in EXTENSION_OPS and not (isinstance(params, dict) and params.pop("_poll", None)):
            self._last_activity = time.monotonic()
        _ACTOR.value = "ai" if op in AI_OPS else "browser" if op in EXTENSION_OPS else "user"
        # Who is asking (Claude Code, Claude Desktop, sb…) and in which folder: shown in approvals and the activity.
        _ACTOR.client = _clean_client(params.pop("_client", None)) if isinstance(params, dict) else None
        _ACTOR.reason = str(params.get("reason") or "").strip()[:500] if op in AI_OPS and isinstance(params, dict) else ""
        _ACTOR.presence = _ACTOR.host = None
        try:
            if op in EXTENSION_OPS and not isinstance(params, dict):
                raise ServiceError(tr("service.malformed_request"), "bad_request")
            if isinstance(params, dict) and "_ext" in params and op not in EXTENSION_OPS:
                raise ServiceError(tr("service.operation_not_available_browser"), "forbidden")
            if op in AI_OPS and client:
                self._ai_client_seen(client)
            if op in AI_OPS and self.pause_file.exists():
                raise ServiceError(tr("service.user_has_paused_ai_access"), "paused")
            if op in AGENT_ACTIONS:
                return {"ok": True, "result": self._run_action(op, params)}
            handler = getattr(self, "op_" + str(op), None)
            if handler is None:
                raise ServiceError(tr("service.unknown_operation", op=op), "unknown_op")
            result = handler(params)
            if op in TEAM_PUSH_OPS:
                self._team_wake.set()
            response = {"ok": True, "result": result}
            if _ACTOR.presence:
                response["presence"] = _ACTOR.presence  # proved it: one click from now on (see _verify_proof)
            return response
        except (ServiceError, teams.TeamError) as exc:
            return {"ok": False, "code": exc.code, "error": str(exc), **({"weak": True} if getattr(exc, "weak", False) else {})}
        except VaultLocked:
            return {"ok": False, "code": "locked",
                    "error": tr("service.secretbroker_vault_is_locked_user")}
        except (ValidationError, ActionError) as exc:
            return {"ok": False, "code": "invalid", "error": str(exc)}
        except KeyError as exc:
            return {"ok": False, "code": "not_found", "error": tr("service.doesn_exist", value=exc.args[0] if exc.args else '')}
        finally:
            _ACTOR.value = _ACTOR.client = _ACTOR.presence = _ACTOR.host = _ACTOR.reason = None

    # ------------------------------------------------------------------ proofs

    def _hello_public_key(self):
        try:
            return crypto.unb64(json.loads(self.hello_file.read_text())["public_key"])
        except (OSError, ValueError, KeyError):
            return None

    def _throttle(self):
        if self._failures >= 3:
            time.sleep(min(60, 2 ** (self._failures - 3)))

    def _verify_proof(self, op, params, allowed=ALL_PROOFS, strong=False):
        """`strong`: this call needs a proven presence even if `op` usually does not (see STRONG_APPROVALS)."""
        proof = params.get("proof") or {}
        kind = proof.get("kind")
        if kind == "presence" and op in PRESENCE_OPS:
            with self._lock:
                presence = self._presence
            if presence and presence[1] > time.monotonic() and hmac.compare_digest(
                    str(proof.get("token", "")).encode(), presence[0].encode()):
                if (strong or op in TEAM_EXPORT_OPS or op in PROVEN_OPS) and not presence[2]:
                    error = ServiceError(tr("service.confirm_it_you_once_windows")
                                         + tr(PROVEN_PURPOSE.get(op, "service.purpose_share"), os=platform.OS_LABEL), "proof_required")
                    error.weak = True  # the app explains why: it was opened with the Windows session
                    raise error
                return kind
            raise ServiceError(tr("service.verification_has_expired_try_again"), "proof_invalid")
        if kind not in allowed:
            raise ServiceError(tr("service.this_operation_requires_verifying_your"), "proof_required")
        kind = self._check_proof(op, params, proof, kind)
        if "presence" in proof and self.vault.is_unlocked and op not in ("unlock", "create_vault", "restore"):
            # The app that unlocked sends its token with a proof: from now on it is one click, even after
            # opening with the Windows session. The same token if it is the current one, else a new one.
            with self._lock:
                current = self._presence
                if current and current[1] > time.monotonic() and hmac.compare_digest(
                        str(proof.get("presence") or "").encode(), current[0].encode()):
                    self._presence = (current[0], current[1], True)
                    _ACTOR.presence = current[0]
            if not getattr(_ACTOR, "presence", None):
                _ACTOR.presence = self._new_presence()
        return kind

    def _check_proof(self, op, params, proof, kind):
        if kind == "hello":
            public_key = self._hello_public_key()
            if not public_key:
                raise ServiceError(tr("service.windows_hello_isn_set_up"), "proof_invalid")
            with self._lock:
                challenge = self._challenges.pop(str(proof.get("nonce")), None)
            if not challenge or challenge["expires"] < time.monotonic():
                raise ServiceError(tr("service.verification_has_expired_try_again"), "proof_invalid")
            if not hmac.compare_digest(challenge["digest"], op_digest(op, params)):
                raise ServiceError(tr("service.verification_doesn_match_this_operation"), "proof_invalid")
            try:
                signature = crypto.unb64(proof.get("signature", ""))
            except ValueError:
                signature = b""
            if not winsec.verify_hello_signature(public_key, challenge["message"], signature):
                raise ServiceError(tr("service.invalid_windows_hello_signature"), "proof_invalid")
            return kind

        self._throttle()
        value = proof.get("value") or ""
        if kind == "windows_password":
            ok = platform.verify_os_password(self.owner, value)
            message = f"Contraseña de {platform.OS_LABEL} incorrecta"
        else:
            ok = self.vault.exists() and self.vault.verify_master(value)
            message = "Contraseña maestra incorrecta"
        if not ok:
            self._failures += 1
            raise ServiceError(message, "proof_invalid")
        self._failures = 0
        return kind

    def op_challenge(self, params):
        """One-time challenge bound to a specific operation, to be signed with Windows Hello."""
        op, op_params = params.get("op"), params.get("params") or {}
        nonce = secrets.token_bytes(32)
        digest = op_digest(op, op_params)
        message = b"SecretBroker/v2\0" + nonce + digest
        with self._lock:
            now = time.monotonic()
            self._challenges = {k: v for k, v in self._challenges.items() if v["expires"] > now}
            self._challenges[crypto.b64(nonce)] = {"digest": digest, "message": message,
                                                   "expires": now + CHALLENGE_TTL_SECONDS}
        return {"nonce": crypto.b64(nonce), "message": crypto.b64(message)}

    # ------------------------------------------------------------------ status & lifecycle

    def op_status(self, params):
        if params.get("gui"):
            self._gui_seen = time.monotonic()
        state = "unlocked" if self.vault.is_unlocked else ("locked" if self.vault.exists() else "no_vault")
        settings = self.vault.settings() if self.vault.is_unlocked else {}
        return {
            "state": state,
            "isolated": self.isolated,
            "owner": self.owner,
            "hello_enrolled": self._hello_public_key() is not None,
            "device_unlock": self.vault.device_unlock_available(),
            "windows_password": platform.os_password_available(),
            "os": platform.NAME,
            "legacy_vault": state == "no_vault" and any(p.exists() for p in self.legacy_files),
            "auto_lock_minutes": settings.get("auto_lock_minutes"),
            "approval_hours": settings.get("approval_hours"),
            "max_uses_per_hour": settings.get("max_uses_per_hour", 100),
            "rotate_reminder_days": settings.get("rotate_reminder_days", 365),
            "check_every_hours": settings.get("check_every_hours", 24),
            "reminders": len(self._reminders()) if self.vault.is_unlocked else 0,
            "session_grants": len(self._live_grants()),
            "gui_connected": time.monotonic() - self._gui_seen < GUI_SEEN_SECONDS,
            "pending": len(self._approvals),
            "session_unlock": self.session_file.exists(),
            "ai_paused": self.pause_file.exists(),
            "drafts": sum(1 for e in self.vault.entries() if e.get("draft")) if self.vault.is_unlocked else 0,
            "team": self._team_info.get("state"),
            "team_sync": self._team_info.get("last_sync"),  # the GUI reloads when a sync round ends
            "team_held": (self._team_info.get("last") or {}).get("held", 0),  # edits waiting for a re-key
            # Goes up whenever something the app shows changes (the AI's edits, sb import, team sync, approvals):
            # the app then reloads what it shows, in place.
            "revision": self.vault.revision + self._revision,
            "lock_reason": self._lock_reason if state == "locked" else None,
            "browser_pairing": self._browser_pending() if state == "unlocked" else [],  # browsers asking to connect
            "protocol": PROTOCOL_VERSION,
        }

    def op_create_vault(self, params):
        password = params.get("master_password", "")
        check_master_password(password)
        entries = {}
        if params.get("import_legacy"):
            entries = self._read_legacy(params.get("legacy_password") or password)
        self.vault.create(password, entries)
        self._seal_audit_log()
        self._audit("vault", "create", f"{len(entries)} credenciales", "ok")
        return self._unlocked_result()  # whoever created it is the user

    def _read_legacy(self, password):
        for path in self.legacy_files:
            if path.exists():
                try:
                    payload = crypto.decrypt_legacy_v1(password, json.loads(path.read_bytes()))
                except WrongPassword:
                    raise ServiceError(tr("service.previous_vault_password_isn_correct"), "proof_invalid") from None
                return {e["id"]: convert_legacy_entry(e) for e in payload["entries"].values()}
        raise ServiceError(tr("service.previous_vault_wasn_found"), "not_found")

    def op_unlock(self, params):
        proof = params.get("proof") or {}
        if self.vault.is_unlocked:
            # An app opened while the vault was already unlocked (e.g. after "Salir" and opening it
            # again) proves it is the user's to get its one-click token; without proof, just the state.
            if not proof:
                return self.op_status({})
            if proof.get("kind") == "session":
                self._check_session_token(proof.get("token"))
            elif proof.get("kind") == "master_password":
                self._verify_proof("unlock", params, ("master_password",))
            else:
                self._verify_proof("unlock", params, ("hello", "windows_password"))
            return self._unlocked_result(strong=proof.get("kind") != "session")
        if proof.get("kind") == "session":
            self._check_session_token(proof.get("token"))
            self.vault.unlock_with_device()
        elif proof.get("kind") == "master_password":
            self._throttle()
            try:
                self.vault.unlock_with_master(proof.get("value") or "")
            except WrongPassword:
                self._failures += 1
                self._audit("vault", "unlock", "contraseña maestra", "error", "Contraseña incorrecta")
                raise ServiceError(tr("service.wrong_master_password"), "proof_invalid") from None
            self._failures = 0
        else:
            kind = self._verify_proof("unlock", params, ("hello", "windows_password"))
            if not self.vault.device_unlock_available():
                raise ServiceError(tr("service.this_pc_can_unlock_vault"), "invalid")
            self.vault.unlock_with_device()
            proof = {"kind": kind}
        self._last_activity = time.monotonic()
        self._seal_audit_log()
        self._audit("vault", "unlock", proof.get("kind", ""), "ok")
        self._team_wake.set()  # sync in the background: unlocking never waits for the network
        return self._unlocked_result(strong=proof.get("kind") != "session")

    def _unlocked_result(self, strong=True):
        # Whoever unlocked may look for copies of the secrets and approve the AI's requests without
        # proving it again (see op_exposure_begin and _verify_proof), until the vault is locked.
        return {**self.op_status({}), "exposure_session": self._new_scan_session(),
                "presence": self._new_presence(strong)}

    def _check_session_token(self, token):
        """The app keeps this token protected with the user's Windows login (DPAPI): whoever is
        signed in to Windows as the user can open the vault without typing anything."""
        self._throttle()
        try:
            stored = json.loads(self.session_file.read_text())["hash"]
        except (OSError, ValueError, KeyError):
            raise ServiceError(tr("service.unlocking_with_session_isn_turned", OS_LABEL=platform.OS_LABEL), "proof_invalid") from None
        digest = hashlib.sha256(str(token or "").encode()).hexdigest()
        if not (self.vault.device_unlock_available() and hmac.compare_digest(digest, stored)):
            self._failures += 1
            raise ServiceError(tr("service.session_can_unlock_vault_use", OS_LABEL=platform.OS_LABEL), "proof_invalid")
        self._failures = 0

    def op_enable_session_unlock(self, params):
        self._verify_proof("enable_session_unlock", params)
        if not self.vault.is_unlocked:
            raise VaultLocked()
        if not self.vault.device_unlock_available():
            raise ServiceError(tr("service.unlock_once_with_master_password"), "invalid")
        token = secrets.token_urlsafe(32)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session_file.write_text(json.dumps({"hash": hashlib.sha256(token.encode()).hexdigest(),
                                                 "created": datetime.now().isoformat(timespec="seconds")}))
        self._audit("vault", "session_unlock", "activado", "ok")
        return {"token": token}

    def op_disable_session_unlock(self, params):
        if self.session_file.exists():
            self.session_file.unlink()
            self._audit("vault", "session_unlock", "desactivado", "ok")
        return True

    # ------------------------------------------------------------------ the AI's access

    def op_pause_ai(self, params):
        """Anyone may pause the AI (it only takes access away); resuming needs the user."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pause_file.write_text(datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            for request in self._approvals.values():
                request["answer"] = "deny"
                request["event"].set()
        self._audit("vault", "pause_ai", "", "ok")
        return self.op_status({})

    def op_resume_ai(self, params):
        self._verify_proof("resume_ai", params)
        self.pause_file.unlink(missing_ok=True)
        self._audit("vault", "resume_ai", "", "ok")
        return self.op_status({})

    def _ai_level(self, capability):
        chosen = (self.vault.settings().get("ai_permissions") or {}).get(capability)
        return chosen if chosen in AI_LEVELS else AI_CAPABILITIES[capability][0]

    def op_ai_permissions(self, params):
        settings = self.vault.settings()
        return {"capabilities": [{"id": key, "label": _capability_label(key), "default": default, "level": self._ai_level(key)}
                                 for key, (default, label) in AI_CAPABILITIES.items()],
                "notify_uses": settings.get("notify_uses", True)}

    def op_set_ai_permissions(self, params):
        """Making the AI's permissions stricter needs nothing; loosening them needs the user (the app
        that unlocked, or a proof)."""
        changes = params.get("permissions") or {}
        if any(key not in AI_CAPABILITIES or level not in AI_LEVELS for key, level in changes.items()):
            raise ServiceError(tr("service.invalid_permission"), "invalid")
        looser = any(AI_LEVELS.index(level) < AI_LEVELS.index(self._ai_level(key)) for key, level in changes.items())
        notify = params.get("notify_uses")
        if looser or notify is False:
            self._verify_proof("set_ai_permissions", params)
        current = dict(self.vault.settings().get("ai_permissions") or {})
        current.update(changes)
        update = {"ai_permissions": current}
        if notify is not None:
            update["notify_uses"] = bool(notify)
        self.vault.update_settings(update)
        detail = ", ".join(f"{_capability_label(k)}: {v}" for k, v in changes.items())
        self._audit("vault", "ai_permissions", detail, "ok")
        return self.op_ai_permissions({})

    def _gate(self, capability, entry, action, detail, strict=False, changes=None):
        """Apply the user's choice for one of the AI's capabilities. Returns True if the user was
        asked (and agreed), so the caller can skip the credential's own approval. `strict`: at least ask.
        `changes`: `detail` structured (_describe_changes), for the app to word in its language."""
        level = self._ai_level(capability)
        if strict and level in ("free", "notify"):
            level = "ask"
        if level == "off":
            raise ServiceError(tr("service.user_doesn_allow_ai_ask", value=_capability_label(capability)[0].lower() + _capability_label(capability)[1:]),
                               "forbidden")
        if level == "ask":
            self._ask_user(entry, action, detail, allow_session=False, strong=capability in STRONG_APPROVALS, changes=changes)
            return True
        if level == "notify":
            self._notify(tr(f"service.ai_did_{capability}", name=entry.get("name", entry.get("id"))),
                         change_line_text(changes[0]) if changes else detail.splitlines()[0] if detail else "")
        return False

    # ------------------------------------------------------------------ notices for the user

    def _notify(self, title, text="", key=None):
        now = time.monotonic()
        with self._lock:
            if key is not None:
                if now - self._noticed.get(key, -NOTICE_EVERY_SECONDS) < NOTICE_EVERY_SECONDS:
                    return
                self._noticed[key] = now
            self._notice_id += 1
            self._notices.append({"id": self._notice_id, "title": title, "text": text[:200],
                                  "ts": datetime.now().isoformat(timespec="seconds")})

    def op_notices(self, params):
        after = int(params.get("after") or 0)
        with self._lock:
            return [n for n in self._notices if n["id"] > after]

    def op_grants(self, params):
        """What the AI may use right now without asking: approvals still running, and credentials
        set to never ask."""
        now_wall, now = datetime.now(), time.monotonic()
        live = self._live_grants()
        result = []
        for entry in self.vault.entries():
            mode = (entry.get("policy") or {}).get("approval", "session")
            if mode == "never":
                result.append({"secret_id": entry["id"], "name": entry.get("name", entry["id"]),
                               "template": entry["template"], "kind": "never"})
            elif mode == "session" and entry["id"] in live:
                expiry = live[entry["id"]]
                until = None if expiry is None else (now_wall + timedelta(seconds=expiry - now)).isoformat(timespec="minutes")
                result.append({"secret_id": entry["id"], "name": entry.get("name", entry["id"]),
                               "template": entry["template"], "kind": "approved", "until": until})
        return result

    def _new_presence(self, strong=True):
        """`strong`: the user proved it (password or Hello), not just the Windows session (TEAM_EXPORT_OPS)."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._presence = (token, time.monotonic() + 24 * 3600, strong)
        return token

    def _approval_seconds(self):
        hours = self.vault.settings().get("approval_hours", 24)
        return hours * 3600 if hours in APPROVAL_HOURS and hours else None

    def _live_grants(self):
        now = time.monotonic()
        with self._lock:
            self._grants = {k: v for k, v in self._grants.items() if v is None or v > now}
            return dict(self._grants)

    def _forget_grants(self, *secret_ids):
        with self._lock:
            self._grants = {k: v for k, v in self._grants.items() if k not in secret_ids}

    def op_lock(self, params):
        # Locking Windows keeps the timed approvals, like the inactivity lock: it happens many times a day.
        windows = params.get("reason") == "windows"
        self._lock_vault(forget_approvals=not windows, reason="windows" if windows else "manual")
        self._audit("vault", "lock", f"{platform.OS_LABEL} bloqueado" if windows else "manual", "ok")
        return self.op_status({})

    def _lock_vault(self, forget_approvals=False, reason=None):
        """Locking by hand forgets every approval; locking after inactivity keeps the timed ones,
        so the user is not asked again for each credential after unlocking."""
        self._lock_reason = reason
        with self._lock:
            for request in self._approvals.values():
                request["answer"] = "deny"
                request["event"].set()
            self._grants = {} if forget_approvals else {k: v for k, v in self._grants.items() if v is not None}
            self._presence = None
            self._scan_sessions.clear()
            self._audit_opened = {}
            self._imports.clear()  # an import's plan holds the values of the file
        self.vault.lock()

    def _auto_lock_loop(self):
        while True:
            time.sleep(10)
            if not self.vault.is_unlocked or self._approvals:
                continue
            # With the Windows session unlock too: the app or the AI open it again by themselves, without a
            # password, the next time they need it (see client.reopen_with_session).
            minutes = self.vault.settings().get("auto_lock_minutes") if self.vault.is_unlocked else None
            if minutes and time.monotonic() - self._last_activity > minutes * 60:
                self._lock_vault(reason="idle")
                self._audit("vault", "lock", f"inactividad ({minutes} min)", "ok")

    # ------------------------------------------------------------------ management (GUI)

    def _summary(self, entry, destinations=None, states=None):
        destinations = self.vault.destinations() if destinations is None else destinations
        retired = self.vault.retired().get("entries", {}).get(entry["id"])
        state = (self.vault.rotation_state() if states is None else states).get("entries", {}).get(entry["id"]) or {}
        pending = state.get("pending")
        return {**entry_summary(entry), "rotation": rotation.info(entry), "provider": links.for_entry(entry),
                "guide": rotation.guide(entry), "destinations": destinations.get("entries", {}).get(entry["id"], []),
                "retired": {k: v for k, v in retired.items() if k != "fields"} if retired else None,
                # A new secret prepared but not saved as the current one yet: when, never the value.
                "pending_rotation": {k: v for k, v in pending.items() if k != "value"} if pending else None,
                "failed_uploads": [{k: v for k, v in u.items() if k != "token"} for u in state.get("failed_uploads") or []],
                "version": self._version(entry)}

    def _version(self, entry):
        """Changes with anything in the entry (to the second `updated` may not): the editor's base_version. Keyed, so
        it says nothing about the secrets in it."""
        return self.vault.mac(json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8"))[:16]

    def op_entries(self, params):
        destinations, states = self.vault.destinations(), self.vault.rotation_state()
        unsent = self.team.unsent() if teams.connected(self.vault.team()) else {}
        summaries = [self._summary(e, destinations, states) for e in self.vault.entries()]
        for summary in summaries:
            if summary.get("shared") and summary["id"] in unsent:
                summary["shared"]["unsent"] = unsent[summary["id"]]  # "rekey" or "pending" (see Team.unsent)
            summary["last_used"] = self._usage_of(summary["id"])["last_used"]  # «Usadas recientemente»
        return summaries

    def op_save_entry(self, params):
        self._verify_proof("save_entry", params)
        entry = dict(params.get("entry") or {})
        replaces = params.get("replaces")
        fields = {k: v for k, v in (entry.get("fields") or {}).items()}
        if replaces:
            # Secret fields sent as null mean "keep the stored value".
            old = self.vault.get(replaces)
            base, version = params.get("base_updated"), params.get("base_version")
            if (base is not None and base != old.get("updated")) or (version is not None and version != self._version(old)):
                # Changed meanwhile (the AI, a rotation, the team): the editor says what and lets the user choose.
                raise ServiceError(tr("service.it_changed_while_you_were"), "conflict")
            for name in templates.secret_field_names(entry.get("template", "")):
                if name in fields and fields[name] is None and old["fields"].get(name):
                    fields[name] = old["fields"][name]
        entry["fields"] = {k: v for k, v in fields.items() if v not in (None, "")}
        if replaces and "rotation_guide" not in entry and old.get("rotation_guide"):
            entry["rotation_guide"] = old["rotation_guide"]  # written by the AI; the editor doesn't show it
        if replaces and old.get("team_rotate"):
            entry["team_rotate"] = old["team_rotate"]  # who had it when it was shared: until its secret changes
        if replaces and old.get("shared"):
            entry = self._shared_edit(old, entry)
        if replaces and old.get("draft") and not all(
                entry["fields"].get(s["name"]) for s in templates.active_specs(entry.get("template", ""), entry["fields"])
                if s["secret"] and s["required"]):
            entry["draft"] = True
        self.vault.put(entry, replaces=replaces)
        if replaces and replaces != entry["id"]:
            def rename(data):
                records = data.get("entries", {})
                if replaces in records:
                    records[entry["id"]] = records.pop(replaces)
            self._update_exposure(rename)
            self._update_destinations(rename)
            self._update_retired(rename)
            self._update_rotation(rename)
        with self._lock:
            self._forget_grants(entry["id"], replaces)
        self._audit(entry["id"], "save", "creada" if not replaces else "modificada", "ok")
        return self._summary(self.vault.get(entry["id"]))

    def op_delete_entry(self, params):
        self._verify_proof("delete_entry", params)
        self._require_team_write(self.vault.get(params["id"]))
        self.vault.delete(params["id"])
        self._entry_removed(params["id"])
        self._audit(params["id"], "delete", "", "ok")
        return True

    def _entry_removed(self, entry_id):
        """Forget what this PC kept about a deleted credential, so nothing carries over to a later one
        with the same id (approvals, GitHub destinations, exposure and retired-key records)."""
        self._update_exposure(lambda data: data.get("entries", {}).pop(entry_id, None))
        self._update_destinations(lambda data: data.get("entries", {}).pop(entry_id, None))
        self._update_retired(lambda data: data.get("entries", {}).pop(entry_id, None))
        self._update_rotation(lambda data: data.get("entries", {}).pop(entry_id, None))
        with self._lock:
            self._forget_grants(entry_id)

    def op_reveal(self, params):
        self._verify_proof("reveal", params)
        entry = self.vault.get(params["id"])
        field = params.get("field")
        if (entry.get("shared") or {}).get("permission") == "use":
            self._audit(entry["id"], "reveal", field or "", "denied", "Permiso en el equipo: solo uso")
            raise ServiceError(tr("service.this_team_credential_is_use"), "forbidden")
        if field not in templates.secret_field_names(entry["template"]) or not entry["fields"].get(field):
            raise ServiceError(tr("service.that_field_doesn_exist"), "not_found")
        self._audit(entry["id"], "reveal", field, "ok")
        fingerprint = exposure.secret_fingerprint(self.vault, entry)

        def count(data):
            record = exposure.record_for(data, entry["id"], fingerprint)
            record["revealed"] = record.get("revealed", 0) + 1
        self._update_exposure(count)
        return entry["fields"][field]

    def op_rotate(self, params):
        """Replace a key with a new one issued by its provider, then upload it again wherever it was."""
        self._verify_proof("rotate", params)
        return self._rotate(self.vault.get(params["id"]))

    def _rotate(self, entry):
        self._require_team_write(entry)
        redact = Redactor(entry)
        try:
            value = rotation.rotate(entry)
        except ActionError as exc:
            self._audit(entry["id"], "rotate", "", "error", redact(str(exc)))
            raise
        # The old key may already be dead: store the new one before anything else can fail.
        entry["fields"]["value"] = value
        self.vault.put(entry, replaces=entry["id"])
        with self._lock:
            self._forget_grants(entry["id"])
        self._audit(entry["id"], "rotate", rotation.info(entry)["provider"], "ok")

        alive = exposure.check_alive(entry)
        uploads = self._upload_again(entry)
        return {"entry": self._summary(self.vault.get(entry["id"])), "check": alive, "uploads": uploads}

    def _upload_again(self, entry):
        """Upload a new secret wherever the old one was. What fails stays with the credential (Salud,
        «Reintentar subida»): until then that place still has the old secret."""
        uploads = [self._push_again(entry, d) for d in self.vault.destinations().get("entries", {}).get(entry["id"], [])]
        failed = [{**{k: v for k, v in u.items() if k != "ok"}, "at": exposure.now_iso()} for u in uploads if not u["ok"]]
        self._update_rotation(lambda data: _set_rotation(data, entry["id"], failed_uploads=failed))
        return uploads

    def _push_again(self, entry, destination):
        label = f"GitHub {destination['repo']}" + (f" ({destination['environment']})" if destination.get("environment") else "")
        detail = f"Subir como secret {destination['name']} a {label} tras rotarla"
        result = {**destination, "label": label, "ok": True}
        try:
            token_entry = self.vault.get(destination["token"])
            actions._check_destination(token_entry, {"url": actions.GITHUB_API})
            actions.push_github_secret(entry, token_entry, destination)
            self._audit(entry["id"], "push_github_secret", detail, "ok")
        except (KeyError, ActionError, httpx.HTTPError) as exc:
            message = Redactor(entry)(str(exc) or type(exc).__name__)
            self._audit(entry["id"], "push_github_secret", detail, "error", message)
            result.update(ok=False, error=message)
        return result

    # ------------------------------------------------------------------ rotation by hand
    #
    # For providers without an API to issue keys, the user creates the new key on the provider's
    # website and pastes it here. It is tested before it replaces the old one, which is kept (in the
    # vault) only to check that the user really deleted it at the provider.

    def op_replace_key(self, params):
        self._verify_proof("replace_key", params, ALL_PROOFS)
        entry = self._get_secret(params.get("id"))
        self._require_team_write(entry)
        if entry["template"] not in ("api_key", "generic", "database", "web_login", "ssh") or \
                (entry["template"] == "ssh" and entry["fields"].get("auth_method") == "key"):
            raise ServiceError(tr("service.only_api_keys_and_passwords"), "invalid")
        # A password (database, web, SSH) was already changed where it is used: same path as a database.
        database = entry["template"] in ("database", "web_login", "ssh")
        field = "password" if database else "value"
        value = str(params.get("value") or "") if database else str(params.get("value") or "").strip()
        if params.get("pending"):
            # The new one prepared earlier (rotation_begin): the page never had it.
            value = ((self._rotation_of(entry["id"]).get("pending") or {}).get("value")) or ""
            if not value:
                raise ServiceError(tr("service.there_no_new_password_prepared"), "invalid")
        if not value.strip():
            raise ServiceError(tr("service.type_new_password") if database else tr("service.paste_new_key"), "invalid")
        if value == (entry["fields"].get(field) or ""):
            raise ServiceError(tr("service.it_same_one_that_already") + (tr("service.generate_new_one") if database else tr("service.create_new_one_with_provider")), "invalid")
        candidate = copy.deepcopy(entry)
        candidate["fields"][field] = value
        if params.get("used_in") is not None:
            candidate["used_in"] = clean_used_in(params["used_in"])
            if not candidate["used_in"]:
                candidate.pop("used_in")
        # A secret paired with an id (OAuth client, app…): the user says whether it was made in the same
        # client (same id) or in a new one (new id). Never guessed: a new secret with a stale id fails.
        paired = rotation.paired_id(entry)
        new_id = params.get("paired_id")
        if paired and new_id is None:
            raise ServiceError(tr("service.say_whether_is_still_same", label=paired['label']), "id_unconfirmed")
        old_id = (entry["fields"].get("username") or "").strip()
        if new_id is not None and str(new_id).strip() != old_id:
            try:
                candidate["fields"]["username"] = rotation.clean_paired_id(entry, new_id)
            except ValueError as exc:
                raise ServiceError(str(exc), "invalid") from None
        id_changed = candidate["fields"].get("username", "") != entry["fields"].get("username", "")
        alive = exposure.check_alive(candidate)
        if alive and alive["status"] == "invalid":
            message = Redactor(candidate)(str(alive.get("message") or ""))
            self._audit(entry["id"], "rotate", "a mano", "error", f"La clave nueva no funciona: {message}")
            raise ServiceError(tr("service.new_key_doesn_work_nothing", message=message), "invalid")
        provider = (rotation.info(entry) or {}).get("provider")
        if database:
            # The user already changed it in the database: the old one is gone, nothing to keep.
            return self._save_new_password(entry, candidate, f"a mano ({provider})")
        self.vault.put(candidate, replaces=entry["id"])
        self._update_rotation(lambda data: _set_rotation(data, entry["id"], pending=None))
        with self._lock:
            self._forget_grants(entry["id"])
        label = paired["label"] if paired else "ID asociado"
        retired = {"fields": {"value": entry["fields"].get("value"), **({"username": old_id} if id_changed else {})},
                   "since": exposure.now_iso(), "provider": provider,
                   "checkable": exposure.testable(entry), "status": "pending",
                   **({"old_id": old_id, "id_label": label} if id_changed else {})}
        self._update_retired(lambda data: data["entries"].__setitem__(entry["id"], retired))
        self._audit(entry["id"], "rotate", "a mano" + (f" ({provider})" if provider else "")
                    + (f"; {label} nuevo: {candidate['fields']['username']}" if id_changed else ""), "ok")
        also = self._replace_id_elsewhere(entry["id"], old_id, candidate["fields"]["username"]) if id_changed and old_id else []
        uploads = []
        for secret_id in [entry["id"], *also]:
            uploads += self._upload_again(self.vault.get(secret_id))
        return {"entry": self._summary(self.vault.get(entry["id"])), "check": alive, "uploads": uploads,
                "id_changed": id_changed, "also_updated": [{"id": o, "name": self.vault.get(o)["name"]} for o in also]}

    def _save_new_password(self, entry, candidate, how):
        """A password already changed where it lives (a database, a website, a server): save it as the
        current one, forget the one prepared for it, and upload it again."""
        self.vault.put(candidate, replaces=entry["id"])
        self._update_rotation(lambda data: _set_rotation(data, entry["id"], pending=None))
        with self._lock:
            self._forget_grants(entry["id"])
        self._audit(entry["id"], "rotate", how, "ok")
        uploads = self._upload_again(candidate)
        return {"entry": self._summary(self.vault.get(entry["id"])), "check": None, "uploads": uploads,
                "id_changed": False, "also_updated": []}

    # ------------------------------------------------------------------ rotations in progress
    #
    # A new password is kept in the vault (section "rotation") from the moment the app shows it, before
    # the user sets it anywhere: locking, closing the app or pressing Esc can never lose a password that
    # is already set on a server. The app learns only that there is one and since when.

    def _rotation_of(self, entry_id):
        return self.vault.rotation_state().get("entries", {}).get(entry_id) or {}

    def _update_rotation(self, change):
        with self._lock:
            data = {"entries": self.vault.rotation_state().get("entries", {})}
            change(data)
            self.vault.set_rotation_state(data)

    def _rotatable_password(self, entry_id):
        entry = self._get_secret(entry_id)
        self._require_team_write(entry)
        if entry["template"] not in ("api_key", "generic", "database", "web_login", "ssh") or \
                (entry["template"] == "ssh" and entry["fields"].get("auth_method") == "key"):
            raise ServiceError(tr("service.only_api_keys_and_passwords"), "invalid")
        return entry, "value" if entry["template"] in ("api_key", "generic") else "password"

    def op_rotation_begin(self, params):
        """Keep a new secret before the user sets it anywhere: generated here (`generate`) or the user's own."""
        self._verify_proof("rotation_begin", params)
        entry, field = self._rotatable_password(params.get("id"))
        if params.get("generate"):
            value = rotation_password(entry)
        else:
            value = str(params.get("value") or "")
            value = value if field == "password" else value.strip()
        if not value.strip():
            raise ServiceError(tr("service.type_new_password"), "invalid")
        if any(c in value for c in "\r\n\0"):
            raise ServiceError(tr("service.new_password_can_contain_line"), "invalid")
        if value == (entry["fields"].get(field) or ""):
            raise ServiceError(tr("service.it_same_one_that_already_2"), "invalid")
        self._keep_pending(entry, field, value, bool(params.get("generate")))
        return self._summary(self.vault.get(entry["id"]))

    def _keep_pending(self, entry, field, value, generated):
        pending = {"field": field, "value": value, "since": exposure.now_iso(), "generated": generated}
        self._update_rotation(lambda data: _set_rotation(data, entry["id"], pending=pending))
        self._audit(entry["id"], "rotate", "contraseña nueva preparada, aún sin aplicar", "ok")

    def op_rotation_discard(self, params):
        """The user did not set the prepared one anywhere: forget it."""
        self._verify_proof("rotation_discard", params)
        entry = self.vault.get(params.get("id"))
        if self._rotation_of(entry["id"]).get("pending"):
            self._update_rotation(lambda data: _set_rotation(data, entry["id"], pending=None))
            self._audit(entry["id"], "rotate", "contraseña nueva descartada", "ok")
        return self._summary(self.vault.get(entry["id"]))

    def op_rotation_secret(self, params):
        """The prepared password (`what: value`) or the command that sets it (`what: command`), for the app
        to copy to the clipboard. It gives a secret out: a session unlock is not enough (TEAM_EXPORT_OPS)."""
        self._verify_proof("rotation_secret", params)
        entry = self.vault.get(params.get("id"))
        if (entry.get("shared") or {}).get("permission") == "use":
            raise ServiceError(tr("service.this_team_credential_is_use_2"), "forbidden")
        value = (self._rotation_of(entry["id"]).get("pending") or {}).get("value")
        if not value:
            raise ServiceError(tr("service.there_no_new_password_prepared_2"), "not_found")
        what = params.get("what") or "value"
        text = rotation.db_command(entry, value) if what == "command" and entry["template"] == "database" else value
        if not text:
            raise ServiceError(tr("service.this_database_has_no_command"), "invalid")
        self._audit(entry["id"], "reveal", "comando con la contraseña nueva" if what == "command" else "contraseña nueva", "ok")
        return text

    def op_rotation_apply(self, params):
        """Change a database's password with its own client, check the new one logs in, then save it.
        If anything fails the stored password stays the current one and the new one stays prepared."""
        self._verify_proof("rotation_apply", params)
        entry, _ = self._rotatable_password(params.get("id"))
        if entry["template"] != "database":
            raise ServiceError(tr("service.only_database_password_is_applied"), "invalid")
        if not self._rotation_of(entry["id"]).get("pending"):
            self._keep_pending(entry, "password", rotation_password(entry), True)
        new = self._rotation_of(entry["id"])["pending"]["value"]
        try:
            client = rotation.apply_database(entry, new)
        except rotation.ApplyError as exc:
            self._audit(entry["id"], "rotate", "aplicar en la base de datos", "error", str(exc))
            raise ServiceError(str(exc), {"no_client": "no_client", "unverified": "unverified"}.get(exc.code, "apply_failed")) from None
        candidate = copy.deepcopy(entry)
        candidate["fields"]["password"] = new
        if params.get("used_in") is not None:
            candidate["used_in"] = clean_used_in(params["used_in"])
            if not candidate["used_in"]:
                candidate.pop("used_in")
        return self._save_new_password(entry, candidate, f"aplicada en la base de datos con {client} y comprobada")

    def op_retry_uploads(self, params):
        """Upload again a rotated secret to the places where it failed."""
        self._verify_proof("retry_uploads", params)
        entry = self.vault.get(params.get("id"))
        failed = self._rotation_of(entry["id"]).get("failed_uploads") or []
        destinations = self.vault.destinations().get("entries", {}).get(entry["id"], [])
        wanted = {(f["repo"], f.get("environment"), f["name"]) for f in failed}
        uploads = [self._push_again(entry, d) for d in destinations if (d["repo"], d.get("environment"), d["name"]) in wanted]
        still = [{**{k: v for k, v in u.items() if k != "ok"}, "at": exposure.now_iso()} for u in uploads if not u["ok"]]
        self._update_rotation(lambda data: _set_rotation(data, entry["id"], failed_uploads=still))
        return {"entry": self._summary(self.vault.get(entry["id"])), "uploads": uploads}

    def op_set_test_request(self, params):
        """How to test an API key of a provider the app does not know (see exposure.check_alive)."""
        self._verify_proof("set_test_request", params)
        entry = self.vault.get(params.get("id"))
        self._require_team_write(entry)
        updated = copy.deepcopy(entry)
        try:
            test = _clean_test_request(entry, params.get("test"))
        except ValueError as exc:
            raise ServiceError(str(exc), "invalid") from None
        if test:
            updated["test_request"] = test
        else:
            updated.pop("test_request", None)
        self.vault.put(updated, replaces=entry["id"])
        self._audit(entry["id"], "edit", f"Petición de prueba: {test['method']} {test['url']} → {test['status']}" if test
                    else "Petición de prueba quitada", "ok")
        check = exposure.check_alive(updated) if test and params.get("check") else None
        if check:
            self._store_check(updated, check)
        return {"entry": self._summary(self.vault.get(entry["id"])), "check": check}

    def _store_check(self, entry, alive):
        timestamp = exposure.now_iso()
        fingerprint = exposure.secret_fingerprint(self.vault, entry)

        def store(data):
            record = exposure.record_for(data, entry["id"], fingerprint)
            record["alive"] = {**alive, "checked": timestamp,
                               "was_ok": alive["status"] == "ok" or bool((record.get("alive") or {}).get("was_ok"))}
            record["checked"] = timestamp
        self._update_exposure(store)

    def _replace_id_elsewhere(self, source_id, old_id, new_id):
        """Credentials that store the same id on its own (a GOOGLE_CLIENT_ID imported from a .env)
        get the new one too, so nothing is left with the new secret and the old id."""
        updated = []
        for other in self.vault.entries():
            names = [n for n in ("value", "username") if (other["fields"].get(n) or "").strip() == old_id]
            if other["id"] == source_id or not names or not can_write_shared(other):
                continue
            for name in names:
                other["fields"][name] = new_id
            self.vault.put(other, replaces=other["id"])
            self._audit(other["id"], "edit", f"ID actualizado al rotar {source_id}", "ok")
            updated.append(other["id"])
        return updated

    def op_check_retired(self, params):
        """Does the previous key of a credential rotated by hand still work? Once it doesn't, it is forgotten."""
        return self._check_retired(self.vault.get(params["id"]))

    def _check_retired(self, entry):
        record = self.vault.retired().get("entries", {}).get(entry["id"])
        if not record:
            return {"status": "done"}
        old = copy.deepcopy(entry)
        old["fields"].update(record["fields"])
        alive = exposure.check_alive(old)
        rejected = bool(alive and alive["status"] == "invalid")
        if not rejected and alive and 400 <= (alive.get("http") or 0) < 500 and alive["http"] != 429:
            # Some providers answer a deleted key with an unusual error (AssemblyAI: 409) instead of
            # 401/403. If the current key works, the old one being refused means it is gone.
            current = exposure.check_alive(entry)
            rejected = bool(current and current["status"] == "ok")
        if rejected:
            self._update_retired(lambda data: data["entries"].pop(entry["id"], None))
            self._audit(entry["id"], "rotate", "la clave anterior ya no funciona"
                        + (f" (HTTP {alive['http']})" if alive.get("http") else ""), "ok")
            return {"status": "done"}
        if alive and alive["status"] == "ok":
            status, message = "alive", ""
        else:
            status = "unknown"
            message = Redactor(old)(str((alive or {}).get("message") or "Esta clave no se puede comprobar"))
        checked = exposure.now_iso()

        def mark(data):
            item = data["entries"].get(entry["id"])
            if item:
                item.update(checked=checked, **({"status": "alive"} if status == "alive" else {}))
        self._update_retired(mark)
        return {"status": status, "message": message}

    def op_forget_retired(self, params):
        """The user says the previous key is deleted: stop keeping it."""
        entry = self.vault.get(params["id"])
        self._update_retired(lambda data: data["entries"].pop(entry["id"], None))
        self._audit(entry["id"], "rotate", "clave anterior borrada (según el usuario)", "ok")
        return True

    def _update_retired(self, change):
        with self._lock:
            data = {"entries": self.vault.retired().get("entries", {})}
            change(data)
            self.vault.set_retired(data)

    def _update_destinations(self, change):
        data = {"entries": self.vault.destinations().get("entries", {})}
        change(data)
        self.vault.set_destinations(data)

    def _remember_destination(self, secret_id, destination):
        def add(data):
            items = data["entries"].setdefault(secret_id, [])
            key = (destination["repo"], destination.get("environment"), destination["name"])
            items[:] = [d for d in items if (d["repo"], d.get("environment"), d["name"]) != key] + [destination]
        self._update_destinations(add)

    def op_change_master_password(self, params):
        # Any proof works: this is also how a forgotten master password is reset (via Windows).
        self._verify_proof("change_master_password", params)
        self.vault.change_master(params.get("new_password", ""))
        self._audit("vault", "change_master_password", "", "ok")
        return True

    def op_set_settings(self, params):
        self._verify_proof("set_settings", params)
        changes = {k: v for k, v in (params.get("settings") or {}).items() if k in DEFAULT_SETTINGS}
        minutes = changes.get("auto_lock_minutes")
        if minutes is not None and (not isinstance(minutes, int) or not 0 <= minutes <= 24 * 60):
            raise ServiceError(tr("service.invalid_lock_time"), "invalid")
        if "approval_hours" in changes and changes["approval_hours"] not in APPROVAL_HOURS:
            raise ServiceError(tr("service.invalid_approval_duration"), "invalid")
        if "max_uses_per_hour" in changes and changes["max_uses_per_hour"] not in MAX_USES:
            raise ServiceError(tr("service.invalid_usage_limit"), "invalid")
        if "rotate_reminder_days" in changes and changes["rotate_reminder_days"] not in REMINDER_DAYS:
            raise ServiceError(tr("service.invalid_reminder"), "invalid")
        if "check_every_hours" in changes and not valid_check_hours(changes["check_every_hours"]):
            raise ServiceError(tr("service.invalid_check_frequency"), "invalid")
        changes = {k: v for k, v in changes.items() if k not in ("ai_permissions", "notify_uses")}  # see set_ai_permissions
        self.vault.update_settings(changes)
        return self.vault.settings()

    def op_enroll_hello(self, params):
        # A Hello key can only be registered by someone who knows a password: otherwise any
        # local process could register its own key and then sign anything.
        self._verify_proof("enroll_hello", params, ("master_password", "windows_password", "hello"))
        der = crypto.unb64(params.get("public_key", ""))
        winsec.load_hello_public_key(der)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.hello_file.write_text(json.dumps({"public_key": crypto.b64(der), "enrolled": datetime.now().isoformat(timespec="seconds")}))
        self._audit("vault", "enroll_hello", "", "ok")
        return True

    def op_remove_hello(self, params):
        self._verify_proof("remove_hello", params)
        self.hello_file.unlink(missing_ok=True)
        self._audit("vault", "remove_hello", "", "ok")
        return True

    def op_revoke_sessions(self, params):
        secret_id = params.get("secret_id")
        with self._lock:
            self._grants = {k: v for k, v in self._grants.items() if secret_id and k != secret_id}
        self._revision += 1
        self._audit(secret_id or "vault", "revoke", "aprobación retirada", "ok")
        return True

    def op_audit(self, params):
        """The newest events first; `offset` skips that many of the newest (the app's «Cargar más»).
        With `secret_id`, those of one credential (its «Actividad reciente»), like the AI's credential_activity."""
        if params.get("secret_id"):
            return self._activity(str(params["secret_id"]), params.get("limit") or 50)
        limit = min(int(params.get("limit") or 200), 1000)
        offset = max(0, int(params.get("offset") or 0))
        private_key = self.vault.audit_private_key()
        try:
            with self.audit_file.open(encoding="utf-8") as log:
                lines = collections.deque((line for line in log if line.strip()), maxlen=limit + offset)
        except OSError:
            return []
        events = []
        # The app asks often (each credential's «Actividad reciente»): lines already opened are kept, until locking.
        known, opened = self._audit_opened, {}
        for line in list(reversed(lines))[offset:]:
            try:
                event = known.get(line) or self._open_audit_line(private_key, line)
                opened[line] = event
                events.append(dict(event))
            except Exception:
                events.append({"ts": "", "secret": "", "action": "audit", "detail": "",
                               "status": "error", "message": tr("service.unreadable_history_entry")})
        if offset == 0:
            self._audit_opened = opened
        return events

    # ------------------------------------------------------------------ exposure (GUI)
    #
    # The desktop app reads the user's files (the service account cannot) and streams them here;
    # the service, which alone knows the secrets, looks for them. Answering "is any secret in this
    # text?" would let any local program guess weak passwords, so it is only done inside a scan
    # session, handed out on unlock or after a proof of identity. The same session unlocks the
    # report's file paths, which would otherwise tell an agent where to read a secret in clear.

    def _new_scan_session(self):
        entries = self.vault.entries()
        needles = sorted((needle, entry["id"]) for entry in entries for needle in exposure.needles(entry))
        fingerprints = {entry["id"]: exposure.secret_fingerprint(self.vault, entry) for entry in entries}
        token = secrets.token_urlsafe(32)
        with self._lock:
            now = time.monotonic()
            self._scan_sessions = {k: v for k, v in self._scan_sessions.items() if v["expires"] > now}
            self._scan_sessions[token] = {
                "expires": now + SCAN_SESSION_SECONDS, "needles": needles, "fingerprints": fingerprints,
                # Changes whenever a secret is added, changed or removed: the app then rescans everything.
                "fingerprint": self.vault.mac(json.dumps(sorted(fingerprints.items())).encode("utf-8")),
                "matches": {}, "scanned": set(),
            }
        return token

    def _scan_session(self, params):
        with self._lock:
            session = self._scan_sessions.get(str(params.get("session") or ""))
            if session and session["expires"] > time.monotonic():
                return session
        return None

    def op_exposure_begin(self, params):
        """Start a scan: in the session given, or in a new one after a proof of identity."""
        token = params.get("session")
        if self._scan_session(params):
            # Secrets may have changed since the session was opened.
            with self._lock:
                self._scan_sessions.pop(token, None)
        else:
            self._verify_proof("exposure_begin", params)
        token = self._new_scan_session()
        session = self._scan_session({"session": token})
        return {"session": token, "fingerprint": session["fingerprint"], "max_needle": exposure.MAX_NEEDLE}

    def op_exposure_scan(self, params):
        session = self._scan_session(params)
        if not session:
            raise ServiceError(tr("service.scan_session_has_expired"), "session_expired")
        found = 0
        for item in params.get("items") or []:
            location, source = str(item.get("location", "")), str(item.get("source", ""))
            if not location or source not in exposure.SOURCE_LABELS:
                raise ServiceError(tr("service.invalid_scan_item"), "invalid")
            data = base64.b64decode(item.get("data") or "")
            hits = {entry_id for needle, entry_id in session["needles"] if needle in data}
            with self._lock:
                session["scanned"].add(location)
                for entry_id in hits:
                    session["matches"].setdefault(entry_id, {})[location] = source
            found += bool(hits)
        return {"found": found}

    def op_exposure_finish(self, params):
        session = self._scan_session(params)
        if not session:
            raise ServiceError(tr("service.scan_session_has_expired"), "session_expired")
        unchanged = {str(location) for location in params.get("unchanged") or []}
        timestamp = exposure.now_iso()
        current = {e["id"]: e for e in self.vault.entries()}
        new_findings = {}

        def merge(data):
            for entry_id, fingerprint in session["fingerprints"].items():
                entry = current.get(entry_id)
                if not entry or exposure.secret_fingerprint(self.vault, entry) != fingerprint:
                    continue  # changed during the scan: the results are for the old value
                record = exposure.record_for(data, entry_id, fingerprint)
                matches = session["matches"].get(entry_id, {})
                new = exposure.merge_scan(record, matches, session["scanned"], unchanged, timestamp)
                if new:
                    new_findings[entry_id] = new
            data["last_scan"] = {"ts": timestamp, "files": len(session["scanned"] | unchanged)}
        self._update_exposure(merge)
        for entry_id, count in new_findings.items():
            self._audit(entry_id, "exposure", tr("service.found_in_new_places", count=count), "error")
        return self.op_exposure_report(params)

    def op_exposure_report(self, params):
        details = self._scan_session(params) is not None
        data = self.vault.exposure()
        timestamp = exposure.now_iso()
        items = []
        for entry in self.vault.entries():
            record = (data.get("entries") or {}).get(entry["id"])
            if record and record.get("fp") != exposure.secret_fingerprint(self.vault, entry):
                record = None
            items.append(exposure.assess(entry, record, timestamp, details))
        return {"entries": items, "last_scan": data.get("last_scan"), "last_check": data.get("last_check"),
                "details": details}

    # What the user does with a place where a secret was found. Locations are only known inside a scan
    # session (see above), so these need one too.

    def _finding(self, params, sources=None):
        session = self._scan_session(params)
        if not session:
            raise ServiceError(tr("service.verify_your_identity_see_which"), "session_expired")
        entry = self.vault.get(params.get("id"))
        location = str(params.get("location") or "")
        record = (self.vault.exposure().get("entries") or {}).get(entry["id"]) or {}
        finding = (record.get("findings") or {}).get(location)
        if record.get("fp") != exposure.secret_fingerprint(self.vault, entry) or not finding:
            raise ServiceError(tr("service.that_place_isn_among_ones"), "not_found")
        if sources and finding["source"] not in sources:
            raise ServiceError(tr("service.this_type_file_can_be"), "invalid")
        return entry, location, finding

    def _change_finding(self, entry, location, change):
        fingerprint = exposure.secret_fingerprint(self.vault, entry)

        def apply(data):
            finding = exposure.record_for(data, entry["id"], fingerprint)["findings"].get(location)
            if finding:
                change(finding)
        self._update_exposure(apply)

    def op_exposure_ignore(self, params):
        """Ignore (or stop ignoring) one place: a test file, a copy kept on purpose. Kept with the finding."""
        entry, location, _ = self._finding(params)
        ignore = params.get("ignore", True)
        stamp = exposure.now_iso()
        self._change_finding(entry, location, lambda f: f.update(ignored=stamp) if ignore else f.pop("ignored", None))
        self._audit(entry["id"], "exposure", ("Ignorada una copia" if ignore else "Vuelve a contar una copia"), "ok")
        return self.op_exposure_report(params)

    def op_exposure_redact(self, params):
        """A piece of a file where the secret was found (an AI conversation, a shell history), returned with
        every form of the secret replaced by [REDACTED:id]. The app reads and writes the file; the secret
        never leaves the service."""
        entry, _, _ = self._finding(params, exposure.REDACTABLE_SOURCES)
        data = base64.b64decode(params.get("data") or "")
        redacted, count = exposure.redact(entry, data)
        return {"data": base64.b64encode(redacted).decode("ascii"), "count": count}

    def op_exposure_redacted(self, params):
        """The app rewrote the file without the secret: the place no longer has it (it did, so it counts
        as a past exposure until the secret is rotated)."""
        entry, location, _ = self._finding(params, exposure.REDACTABLE_SOURCES)
        stamp = exposure.now_iso()
        self._change_finding(entry, location, lambda f: f.update(present=False, redacted=stamp))
        self._audit(entry["id"], "exposure", f"Borrada de un archivo ({int(params.get('count') or 0)} veces)", "ok")
        return self.op_exposure_report(params)

    def op_exposure_check(self, params):
        """Test the keys with their providers and the passwords against known breaches."""
        wanted = {params["id"]} if params.get("id") else set(params["ids"]) if params.get("ids") is not None else None
        entries = [e for e in self.vault.entries()
                   if exposure.check_alive_possible(e) and (wanted is None or e["id"] in wanted)]
        timestamp = exposure.now_iso()
        stored = self.vault.exposure()
        records = {e["id"]: exposure.record_for(stored, e["id"], exposure.secret_fingerprint(self.vault, e)) for e in entries}

        actor = getattr(_ACTOR, "value", None)

        def run(entry):
            _ACTOR.value = actor  # a pool thread: audit the checks for whoever asked
            alive = exposure.check_entry(entry, records[entry["id"]], timestamp)
            if alive:
                self._audit(entry["id"], "check", alive["provider"], "ok" if alive["status"] == "ok" else "error",
                            alive.get("message", ""))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, entries))

        def store(data):
            for entry_id, checked in records.items():
                record = exposure.record_for(data, entry_id, checked["fp"])
                record.update({k: checked[k] for k in ("alive", "pwned", "checked") if k in checked})
            if not params.get("id"):
                data["last_check"] = timestamp
        self._update_exposure(store)
        return self.op_exposure_report(params)

    def _update_exposure(self, change):
        with self._lock:
            data = self.vault.exposure()
            change(data)
            self.vault.set_exposure(data)

    def _due_checks(self):
        """Credentials whose key should be tested now, by their own interval or the general one."""
        general = self.vault.settings().get("check_every_hours", 24)
        now = datetime.fromisoformat(exposure.now_iso())
        records = self.vault.exposure().get("entries") or {}
        due = []
        for entry in self.vault.entries():
            hours = entry["check_every_hours"] if entry.get("check_every_hours") is not None else general
            if entry.get("draft") or not hours or not exposure.check_alive_possible(entry):
                continue
            record = records.get(entry["id"])
            if record and record.get("fp") != exposure.secret_fingerprint(self.vault, entry):
                record = None  # results of a previous value
            last = exposure.last_checked(record)
            if not last or (hours != CHECK_ONCE and (now - datetime.fromisoformat(last)).total_seconds() >= hours * 3600):
                due.append(entry["id"])
        return due

    def _check_loop(self):
        """Test the keys while the vault is unlocked, each as often as the user chose."""
        retired_checked = 0.0
        while True:
            time.sleep(300)
            try:
                if not self.vault.is_unlocked:
                    continue
                due = self._due_checks()
                if due:
                    self.op_exposure_check({"ids": due})
                if time.monotonic() - retired_checked >= RETIRED_CHECK_SECONDS:
                    retired_checked = time.monotonic()
                    for entry_id in list(self.vault.retired().get("entries", {})):
                        self._check_retired(self.vault.get(entry_id))
            except (VaultLocked, OSError, ValueError, KeyError) as exc:  # e.g. locked halfway: try again later
                print(f"exposure check: {type(exc).__name__}: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------ updates

    def op_update_status(self, params):
        return self.updates.status(force=bool(params.get("force")))

    def op_update_download(self, params):
        """Download the newest release into the public folder and verify its signature.
        Installing it is up to the desktop app, which needs the user's consent (UAC)."""
        latest = self.updates.latest()
        if not latest:
            self.updates.status(force=True)
            latest = self.updates.latest()
        if not latest:
            raise ServiceError(tr("service.there_no_new_version"), "not_found")
        try:
            path = update.download(latest, self.public_dir / "updates")
        except (update.UpdateError, httpx.HTTPError) as exc:
            self._audit("vault", "update", latest["version"], "error", str(exc) or type(exc).__name__)
            raise ServiceError(str(exc) or type(exc).__name__, "update_failed") from None
        self._audit("vault", "update", latest["version"], "ok")
        return {"path": str(path), "version": latest["version"]}

    # ------------------------------------------------------------------ approvals (GUI)

    def op_pending_approvals(self, params):
        self._gui_seen = time.monotonic()
        with self._lock:
            return [{k: v for k, v in r.items() if k not in ("event", "answer")} for r in self._approvals.values()]

    def op_expired_approvals(self, params):
        """Requests nobody answered in time (the AI got an error), from the last minutes: the app says so."""
        now = time.monotonic()
        with self._lock:
            return [{"id": e["id"], "secret_name": e["secret_name"], "seconds_ago": int(now - e["at"])}
                    for e in self._expired if now - e["at"] < APPROVAL_EXPIRED_SECONDS]

    def _usage_of(self, secret_id):
        """When the AI last used a credential and how many times today (for the approval), from the activity."""
        if self._usage is None:
            usage = {}
            try:
                events = self.op_audit({"limit": 1000})
            except (VaultLocked, ValueError):
                events = []
            for e in reversed(events):
                actor = e.get("actor") or ("ai" if e.get("action") in AI_USE_ACTIONS else "user")
                if actor == "ai" and e.get("status") == "ok" and e.get("action") in AI_USE_ACTIONS and e.get("secret"):
                    self._count_use(usage, e["secret"], e.get("ts") or "")
            self._usage = usage
        record = self._usage.get(secret_id) or {}
        return {"last_used": record.get("last"), "uses_today": record.get("days", {}).get(datetime.now().strftime("%Y-%m-%d"), 0)}

    @staticmethod
    def _count_use(usage, secret_id, ts):
        record = usage.setdefault(secret_id, {"last": None, "days": {}})
        if ts and (not record["last"] or ts > record["last"]):
            record["last"] = ts
        record["days"] = {ts[:10]: record["days"].get(ts[:10], 0) + 1}  # only today's count is ever shown

    def op_approve(self, params):
        """Using a credential is one click. Deleting, rotating or widening where it goes (`strong` requests) is
        one click too, unless the vault was opened with the Windows session: then the first one is proven."""
        with self._lock:
            pending = self._approvals.get(params.get("id"))
        kind = self._verify_proof("approve", params, strong=bool(pending and pending.get("strong")))
        with self._lock:
            request = self._approvals.get(params.get("id"))
            if not request:
                raise ServiceError(tr("service.request_is_no_longer_pending"), "not_found")
            scope = params.get("scope")
            if scope not in ("once", "session") or (scope == "session" and not request["allow_session"]) \
                    or (scope == "once" and not request.get("allow_once", True)):
                raise ServiceError(tr("service.invalid_approval_type"), "invalid")
            request["answer"] = scope
            request["event"].set()
        # After proving it with a password or Hello, the next approvals are a single click.
        return {"presence": getattr(_ACTOR, "presence", None) or self._new_presence()} if kind != "presence" else True

    def op_deny(self, params):
        with self._lock:
            request = self._approvals.get(params.get("id"))
            if request:
                request["answer"] = "deny"
                request["event"].set()
        return True

    # ------------------------------------------------------------------ agent

    def op_list_secrets(self, params):
        return [agent_view(e) for e in self.vault.entries()]

    def _run_action(self, action, params):
        entry = self._get_secret(params.get("secret_id"))
        detail = actions.describe(action, params, entry)
        _ACTOR.host = _target_host(action, params, entry)  # highlighted in the approval
        redact = Redactor(entry)
        try:
            actions.precheck(action, entry, params)
            self._authorize(entry, action, detail)
            result = actions.ACTIONS[action](entry, params)
        except ServiceError as exc:
            self._audit(entry["id"], action, detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        except Exception as exc:
            # Exception messages may embed substituted values (e.g. a URL), so redact them too.
            message = redact(str(exc) or type(exc).__name__)
            if not isinstance(exc, ActionError):
                message = f"{type(exc).__name__}: {message}"
            self._audit(entry["id"], action, detail, "error", message)
            raise ServiceError(message, "action_failed") from None
        self._audit(entry["id"], action, detail, "ok")
        return result

    def _get_secret(self, secret_id):
        try:
            entry = self.vault.get(secret_id)
        except KeyError:
            raise ServiceError(tr("service.secret_doesn_exist_use_list", secret_id=secret_id), "not_found") from None
        if entry.get("draft"):
            raise ServiceError(tr("service.doesn_have_its_key_yet", secret_id=secret_id), "draft")
        return entry

    # ------------------------------------------------------------------ credentials prepared by the AI

    def _ai_changes(self, entry, params):
        """Apply the AI's changes to a copy of `entry`. The AI never writes secret values or the
        approval mode: those are the user's."""
        entry = copy.deepcopy(entry)
        template = entry["template"]
        secret_names = templates.secret_field_names(template)
        known = {s["name"] for s in templates.field_specs(template)}
        for name, value in (params.get("fields") or {}).items():
            if name in secret_names:
                raise ServiceError(tr("service.only_user_can_write_value", name=name), "invalid")
            if name not in known:
                raise ServiceError(tr("service.template_has_no_field_fields", template=template, name=name)
                                   + ", ".join(sorted(known - set(secret_names))), "invalid")
            if value in (None, ""):
                entry["fields"].pop(name, None)
            else:
                entry["fields"][name] = str(value)
        for key in ("name", "description"):
            if params.get(key) is not None:
                entry[key] = str(params[key]).strip()
        if params.get("tags") is not None:
            entry["tags"] = sorted({str(t).strip().lower() for t in params["tags"] if str(t).strip()})
        if params.get("expires") is not None:
            entry["expires"] = str(params["expires"]).strip() or None
            if not entry["expires"]:
                entry.pop("expires")
        if params.get("used_in") is not None:
            entry["used_in"] = clean_used_in(params["used_in"])
            if not entry["used_in"]:
                entry.pop("used_in")
        for key in ("rotate_every_days", "check_every_hours"):
            if params.get(key) is not None:
                try:
                    entry[key] = int(params[key])
                except (TypeError, ValueError):
                    raise ServiceError(tr("service.must_be_number", value=key), "invalid") from None
        if params.get("rotation_guide") is not None:
            if not params["rotation_guide"]:
                entry.pop("rotation_guide", None)
            else:
                try:
                    guide = rotation.clean_guide(params["rotation_guide"])
                except ValueError as exc:
                    raise ServiceError(str(exc), "invalid") from None
                entry["rotation_guide"] = {**guide, "written": datetime.now().date().isoformat()}
            if entry.get("shared"):  # this user's AI wrote it now, not the teammate who wrote the last one
                entry["shared"] = {k: v for k, v in entry["shared"].items() if k != "guide_by"}
        policy = entry.setdefault("policy", {})
        if params.get("allowed_hosts") is not None:
            policy.setdefault("http", {"auth": {"kind": "none"}})["allowed_hosts"] = \
                [str(h).strip().lower() for h in params["allowed_hosts"] if str(h).strip()]
        if params.get("commands") is not None:
            policy.setdefault("commands", {"allowed": [], "env": {}})["allowed"] = [str(c).strip() for c in params["commands"]]
        if params.get("env_vars") is not None:
            policy.setdefault("commands", {"allowed": [], "env": {}})["env"] = {str(k): str(v) for k, v in params["env_vars"].items()}
        if params.get("test_request") is not None:
            # After the hosts: the test may only go to one of them.
            try:
                test = _clean_test_request(entry, params["test_request"])
            except ValueError as exc:
                raise ServiceError(str(exc), "invalid") from None
            if test:
                entry["test_request"] = test
            else:
                entry.pop("test_request", None)
        return entry

    def op_create_draft(self, params):
        """A credential prepared by the AI with everything but its secret, which the user pastes in the app."""
        preset_id = params.get("provider")
        if preset_id:
            preset = presets.get(preset_id)
            if not preset:
                raise ServiceError(tr("service.unknown_provider_known", preset_id=preset_id, value=', '.join(presets.PRESETS)), "invalid")
            if params.get("template") not in (None, "api_key"):
                raise ServiceError(tr("service.providers_use_api_key_template"), "invalid")
            fields, description = presets.apply(preset_id, params.get("fields") or {}, str(params.get("description") or ""))
            params = {**params, "template": "api_key", "fields": fields, "description": description,
                      "name": params.get("name") or preset[0]}
        template = params.get("template")
        if template not in templates.TEMPLATES:
            raise ServiceError(tr("service.unknown_template_use_one", template=template, value=', '.join(templates.TEMPLATES)), "invalid")
        name = str(params.get("name") or "").strip()
        entry_id = params.get("id") or SLUG_RE.sub("-", name.lower()).strip("-")[:64]
        if entry_id in {e["id"] for e in self.vault.entries()}:
            raise ServiceError(tr("service.credential_already_exists_use_update", entry_id=entry_id), "invalid")
        entry = self._ai_changes({"id": entry_id, "name": name, "template": template, "fields": {}}, params)
        self._gate("create", entry, "draft", f"Preparar «{name}» ({templates.TEMPLATES[template]['label']})")
        placeholder_secrets = {n: "x" for n in templates.secret_field_names(template)}
        default = templates.default_policy(template, {**entry["fields"], **placeholder_secrets})
        overrides = entry.pop("policy")
        policy = copy.deepcopy(default)
        if "http" in overrides:
            policy.setdefault("http", {"auth": {"kind": "none"}})["allowed_hosts"] = overrides["http"]["allowed_hosts"]
        if "commands" in overrides:
            commands = policy.setdefault("commands", {"allowed": [], "env": {}})
            commands.update({k: v for k, v in overrides["commands"].items() if v or k not in commands})
        policy["approval"] = "session"
        entry.update(policy=policy, draft=True, description=entry.get("description", ""))
        self.vault.put(entry)
        self._audit(entry_id, "draft", "preparada por la IA", "ok")
        return {"credential": agent_view(self.vault.get(entry_id)), **_paired_question(entry),
                **({} if entry.get("used_in") else {"used_in_question": USED_IN_QUESTION}),
                "next": "El usuario debe pegar la clave en la app SecretBroker; hasta entonces no se puede usar."}

    def op_update_credential(self, params):
        """Change a credential's context or configuration. Name and notes change at once; anything that
        decides where its secret can go needs the user's OK in the app once it has a secret."""
        try:
            entry = self.vault.get(params.get("secret_id"))
        except KeyError:
            raise ServiceError(tr("service.secret_doesn_exist", get=params.get('secret_id')), "not_found") from None
        updated = self._ai_changes(entry, params)
        changes = _describe_changes(entry, updated)
        if changes:
            self._require_team_write(entry)
        if not changes:
            return {"credential": agent_view(entry), "changed": []}
        risky = [line for key, line, _ in changes if key not in CONTEXT_KEYS]
        detail = "\n".join(line for _, line, _ in changes)
        capability = "create" if entry.get("draft") else "edit_config" if risky else "edit_notes"
        try:
            # What the AI writes on a team credential reaches every teammate's AI: the user always confirms it.
            self._gate(capability, entry, "edit", detail, strict=bool(entry.get("shared")),
                       changes=[change for _, _, change in changes])
        except ServiceError as exc:
            self._audit(entry["id"], "edit", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        if capability == "edit_config":
            self._forget_grants(entry["id"])  # the user approved it going to the old places only
        self.vault.put(updated, replaces=entry["id"])
        self._audit(entry["id"], "edit", detail, "ok")
        return {"credential": agent_view(self.vault.get(entry["id"])), "changed": [line for _, line, _ in changes]}

    def op_check_env(self, params):
        """`sb check`: is every credential a project's .secretbroker names ready? No values involved."""
        entries = {e["id"]: e for e in self.vault.entries()}
        result = []
        for item in params.get("vars") or []:
            entry = entries.get(item.get("secret_id"))
            env = ((entry or {}).get("policy", {}).get("commands") or {}).get("env") or {}
            if entry is None:
                status = "missing"
            elif entry.get("draft"):
                status = "draft"
            elif not env:
                status = "no_env"
            elif item.get("name") and not item.get("field") and item["name"] not in env and "value" not in templates.placeholder_values(entry):
                status = "no_field"
            else:
                status = "ok"
            result.append({"name": item.get("name"), "secret_id": item.get("secret_id"), "status": status,
                           "approval": (entry or {}).get("policy", {}).get("approval")})
        return result

    def op_import_env(self, params):
        """`sb import`: the keys of a project's .env become credentials. The values travel from the
        user's file to the vault through that local program, never through the AI, and the user
        confirms the list (names only) in the app."""
        source, new, skipped = self._env_items(params)
        if not new:
            return {"created": [], "skipped": skipped}
        detail = f"Desde {source}\n" + "\n".join(f"{n['var']}  →  {n['id']}" + (f"  (con {n['paired_var'] or 'su ID'})" if n["paired_id"] else "")
                                                   for n in new)
        request = {"id": "vault", "name": f"Importar {len(new)} {'clave' if len(new) == 1 else 'claves'}", "template": "generic"}
        try:
            self._ask_user(request, "import_env", detail, allow_session=False)
        except ServiceError as exc:
            self._audit("vault", "import_env", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        return self._create_env_items(new, skipped, source, params.get("project"))

    def op_import_env_file(self, params):
        """The same from the app («Importar un .env»): the user picked the file and ticked the keys in the app
        itself, so there is nothing more to approve; one click with the app's token."""
        self._verify_proof("import_env_file", params)
        source, new, skipped = self._env_items(params)
        return self._create_env_items(new, skipped, source, params.get("project"))

    def _env_items(self, params):
        source = str(params.get("source") or "")[:300]
        existing = {e["id"] for e in self.vault.entries()}
        new, skipped = [], []
        for item in params.get("items") or []:
            var, value, entry_id = str(item.get("var") or ""), item.get("value"), str(item.get("id") or "")
            if not ENV_NAME_RE.match(var) or not isinstance(value, str) or not value or not ID_RE.match(entry_id):
                raise ServiceError(tr("service.invalid_variable", var=var), "invalid")
            paired = str(item.get("paired_id") or "").strip()
            if paired and (len(paired) > rotation.PAIRED_ID_MAX or not rotation.PAIRED_ID_RE.match(paired)):
                raise ServiceError(tr("service.invalid_associated_id_for", var=var), "invalid")
            if entry_id in existing or entry_id in {n["id"] for n in new}:
                skipped.append({"var": var, "id": entry_id, "reason": tr("service.already_exists")})
            else:
                new.append({"var": var, "value": value, "id": entry_id, "paired_id": paired,
                            "paired_var": str(item.get("paired_var") or "")[:100]})
        return source, new, skipped

    def _create_env_items(self, new, skipped, source, project):
        project = str(project or "")
        for item in new:
            entry = self._imported_entry(item, source)
            if TAG_RE.match(project):
                entry["tags"] = [project]
            self.vault.put(entry)
            self._audit(item["id"], "import_env", f"{item['var']} desde {source}", "ok")
        return {"created": [{"var": n["var"], "id": n["id"]} for n in new], "skipped": skipped}

    @staticmethod
    def _imported_entry(item, source):
        var, preset_id = item["var"], presets.for_env_var(item["var"])
        description = f"Importada de {source} ({var})."
        if preset_id:
            fields, description = presets.apply(preset_id, {"env_var": var}, description)
            template, name = "api_key", f"{presets.get(preset_id)[0]} ({var})"
        else:
            fields, template, name = {}, "generic", var
        fields["value"] = item["value"]
        if item.get("paired_id"):
            fields["username"] = item["paired_id"]
            description += f" Va con el ID de {item.get('paired_var') or 'la misma app'}."
        policy = templates.default_policy(template, fields)
        commands = policy.setdefault("commands", {"allowed": [], "env": {}})
        commands["env"] = {**(commands.get("env") or {}), var: "{{value}}"}
        policy["approval"] = "session"
        return {"id": item["id"], "name": name, "template": template, "description": description,
                "fields": fields, "policy": policy}

    # ------------------------------------------------------------------ more for the AI

    def op_ai_check(self, params):
        """Does the key still work? Plus what the AI may want to know before rotating it."""
        entry = self._get_secret(params.get("secret_id"))
        alive = exposure.check_alive(entry) or {"status": "unknown", "message": tr("service.this_type_credential_can_be")}
        alive = {**alive, "message": Redactor(entry)(str(alive.get("message") or ""))}
        self._audit(entry["id"], "check", alive.get("status", ""), "ok")
        guide = rotation.guide(entry)
        return {"check": alive, "rotation": rotation.info(entry), "key_age_days": secret_age_days(entry),
                "expires": entry.get("expires"), "rotate_every_days": entry.get("rotate_every_days"),
                "rotation_guide": guide and guide["source"], "used_in": entry.get("used_in") or [],
                **({} if entry.get("used_in") else {"used_in_question": USED_IN_QUESTION}), **_paired_question(entry),
                **({"test_question": TEST_QUESTION} if entry["template"] in ("api_key", "generic")
                   and not exposure.check_alive_possible(entry) else {})}

    def op_ai_rotate(self, params):
        entry = self._get_secret(params.get("secret_id"))
        info = rotation.info(entry) or {"supported": False, "reason": tr("service.only_api_keys_are_rotated")}
        if not info.get("supported"):
            raise ServiceError(tr("service.can_rotate_through_api_user", value=(info.get('reason') or 'proveedor no compatible').rstrip('.')), "invalid")
        detail = f"Rotar la clave con {info.get('provider')}" + (f"\nMotivo: {params['reason']}" if params.get("reason") else "")
        try:
            self._gate("rotate", entry, "rotate", detail)
        except ServiceError as exc:
            self._audit(entry["id"], "rotate", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        result = self._rotate(entry)
        return {"check": result["check"], "uploads": [{k: v for k, v in u.items() if k != "token"} for u in result["uploads"]]}

    def op_ai_activity(self, params):
        """What was done with the credentials (by the AI or the user): no values, only what and when."""
        return self._activity(params.get("secret_id"), params.get("limit") or 50)

    def _activity(self, secret_id, limit):
        events = self.op_audit({"limit": 1000})
        if secret_id:
            events = [e for e in events if e.get("secret") == secret_id]
        return events[:min(int(limit), 200)]

    def op_ai_delete(self, params):
        """The AI proposes deleting a credential; the user always confirms (it can't be undone, except
        from a backup)."""
        try:
            entry = self.vault.get(params.get("secret_id"))
        except KeyError:
            raise ServiceError(tr("service.secret_doesn_exist", get=params.get('secret_id')), "not_found") from None
        self._require_team_write(entry)
        detail = "Borrar esta credencial para siempre" + (f"\nMotivo: {params['reason']}" if params.get("reason") else "")
        try:
            self._ask_user(entry, "delete", detail, allow_session=False, strong=True)
        except ServiceError as exc:
            self._audit(entry["id"], "delete", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        self.vault.delete(entry["id"])
        self._forget_grants(entry["id"])
        self._audit(entry["id"], "delete", "propuesto por la IA", "ok")
        return {"deleted": entry["id"]}

    def _reminders(self):
        """Credentials that need attention: expired, expiring soon, or with a key older than the user's limit."""
        today = datetime.now().date()
        general = self.vault.settings().get("rotate_reminder_days", 365)
        retired = self.vault.retired().get("entries", {})
        found = []
        for entry in self.vault.entries():
            if entry.get("draft"):
                continue
            rotate = teams.rotate_info(entry)
            if rotate and rotate.get("fp") == teams.secret_fp(self.vault, entry):
                # Someone left a team collection with this credential in it, or it is no longer shared with
                # them (`unshared`): they may have seen it.
                found.append({"id": entry["id"], "name": entry.get("name"), "kind": "team_access",
                              "people": rotate.get("people") or [], "since": rotate.get("since"),
                              "can_rotate": can_write_shared(entry), "unshared": bool(rotate.get("unshared"))})
                continue
            if retired.get(entry["id"], {}).get("status") == "alive":
                found.append({"id": entry["id"], "name": entry.get("name"), "kind": "old_alive",
                              "provider": retired[entry["id"]].get("provider")})
                continue
            if entry.get("expires"):
                days = (datetime.strptime(entry["expires"], "%Y-%m-%d").date() - today).days
                if days < 0:
                    found.append({"id": entry["id"], "name": entry.get("name"), "kind": "expired", "days": -days})
                    continue
                if days <= EXPIRY_WARNING_DAYS:
                    found.append({"id": entry["id"], "name": entry.get("name"), "kind": "expiring", "days": days})
                    continue
            age = secret_age_days(entry)
            old_after = entry["rotate_every_days"] if entry.get("rotate_every_days") is not None else general
            if old_after and age is not None and age >= old_after:
                found.append({"id": entry["id"], "name": entry.get("name"), "kind": "old", "days": age})
        return found

    def op_reminders(self, params):
        return self._reminders()

    # ------------------------------------------------------------------ health, import and export (GUI only)

    def op_health(self, params):
        """Weak, reused, old and exposed secrets, with a score. Names and reasons only, never values."""
        report = self.op_exposure_report({})
        retired = self.vault.retired().get("entries", {})
        rotations = self.vault.rotation_state().get("entries", {})
        states = {e["id"]: {"retired": retired.get(e["id"]), "pending": bool((rotations.get(e["id"]) or {}).get("pending")),
                            "failed_uploads": (rotations.get(e["id"]) or {}).get("failed_uploads") or [],
                            "testable": e["template"] == "ssh" or exposure.testable(e)}
                  for e in self.vault.entries()}
        return health.report(self.vault.entries(), self.vault.mac, self._reminders(), report["entries"], states,
                             scanned=(report["last_scan"] or {}).get("ts"), checked=report["last_check"])

    def op_import_file(self, params):
        """Credentials from another manager's export. The app reads the file and sends its text; without
        `selected` the answer is what would happen to each one (names only) and an `import_id`; with it they
        are imported. The app sends a big selection in batches with that `import_id` (the plan made for the
        preview, kept here for a while, so ids stay put), to show progress; each batch saves the vault once."""
        self._verify_proof("import_file", params)
        source = str(params.get("source") or "")[:300]
        with self._lock:
            now = time.monotonic()
            self._imports = {k: v for k, v in self._imports.items() if v["expires"] > now}
            session = self._imports.get(str(params.get("import_id") or ""))
        if session:
            fmt, skipped, planned, source = session["format"], session["skipped"], session["planned"], session["source"]
        else:
            if params.get("import_id"):
                raise ServiceError(tr("service.import_has_expired_choose_file"), "expired")
            try:
                fmt, candidates, skipped = importers.parse(str(params.get("content") or ""), params.get("format") or "auto",
                                                           params.get("password"), source)
            except importers.ImportFileError as exc:
                raise ServiceError(str(exc), exc.code) from None
            planned = importers.plan(candidates, self.vault.entries())
        result = {"format": fmt, "label": importers.FORMATS[fmt], "skipped": skipped}
        if params.get("selected") is None:
            import_id = secrets.token_urlsafe(12)
            with self._lock:
                self._imports[import_id] = {"format": fmt, "skipped": skipped, "planned": planned, "source": source,
                                            "expires": time.monotonic() + IMPORT_SESSION_SECONDS}
            return {**result, "import_id": import_id, "items": [importers.preview(item) for item in planned]}
        selected = {int(k) for k in params["selected"] if str(k).isdigit()}
        batch = []
        for item in planned:
            if item["key"] in selected:
                entry = copy.deepcopy(item["entry"])
                entry.setdefault("description", f"Importada de {importers.FORMATS[fmt]}.")
                entry.setdefault("policy", templates.default_policy(entry["template"], entry["fields"]))
                batch.append(entry)
        created, failed = [], []
        for entry, (_, error) in zip(batch, self.vault.put_many(batch)):
            if error:
                failed.append({"key": next(i["key"] for i in planned if i["entry"]["id"] == entry["id"]),
                               "name": entry["name"], "reason": error})
            else:
                created.append({"id": entry["id"], "name": entry["name"]})
        if created:
            self._audit("vault", "import_file", f"{len(created)} {'credencial' if len(created) == 1 else 'credenciales'} "
                                                f"de {importers.FORMATS[fmt]} ({source})", "ok")
        if params.get("done") and session:
            with self._lock:
                self._imports.pop(str(params.get("import_id")), None)
        return {**result, "created": created, "failed": failed}

    def op_export_vault(self, params):
        """The whole vault as a file for another SecretBroker (encrypted) or another manager (plain)."""
        self._verify_proof("export_vault", params)
        fmt = params.get("format")
        entries = self.vault.entries()
        try:
            content = exports.build(entries, fmt, params.get("password"), __version__)
        except exports.ExportError as exc:
            raise ServiceError(str(exc), exc.code) from None
        self._audit("vault", "export", f"{len(entries)} credenciales ({'cifrada' if fmt == 'encrypted' else 'sin cifrar, ' + fmt})", "ok")
        return {"content": content, "entries": len(entries), "format": fmt}

    def op_totp_code(self, params):
        """The current 2FA code of a web login, computed here from its seed (which never leaves the
        service). It gives a secret out: after a Windows-session unlock it needs Hello or a password once."""
        kind = self._verify_proof("totp_code", params)
        entry = self.vault.get(params.get("id"))
        if (entry.get("shared") or {}).get("permission") == "use":
            raise ServiceError(tr("service.this_team_credential_is_use_3"), "forbidden")
        seed = entry["fields"].get("totp")
        if not seed:
            raise ServiceError(tr("service.this_credential_has_no_2fa"), "not_found")
        try:
            result = totp.code(seed)
        except totp.TotpError as exc:
            raise ServiceError(str(exc), "invalid") from None
        now = time.monotonic()
        with self._lock:
            quiet = params.get("copy") is not True and now - self._totp_seen.get(entry["id"], -TOTP_AUDIT_SECONDS) < TOTP_AUDIT_SECONDS
            if not quiet:
                self._totp_seen[entry["id"]] = now
        if not quiet:
            self._audit(entry["id"], "reveal", "código 2FA (copiado)" if params.get("copy") else "código 2FA", "ok")
        if kind != "presence":
            result["presence"] = self._new_presence()  # proved it: one click again from now on
        return result

    # ------------------------------------------------------------------ browser extension (see autofill.py)
    #
    # The extension talks to native_host.py, which the browser starts and which relays here. Only the extension
    # ids in native_host.ALLOWED_ORIGINS are answered, and only once the user connected that browser with one
    # click in the app (a random key the extension keeps; its hash is in data/browsers.json). Logins are matched
    # here, by registrable domain, and given out one at a time after a click in the browser.

    def _browsers(self):
        if self._browser_pairs is None:
            try:
                self._browser_pairs = json.loads(self.browsers_file.read_text()).get("paired") or {}
            except (OSError, ValueError, AttributeError):
                self._browser_pairs = {}
        return self._browser_pairs

    def _save_browsers(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.browsers_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"paired": self._browser_pairs or {}}, indent=1))
        os.replace(tmp, self.browsers_file)

    def _extension(self, op, params):
        """Who is asking: {origin, pair, key, browser} from the native host. Raises unless it is our extension and,
        except to say hello or ask to connect, a browser the user connected."""
        ext = params.pop("_ext", None)
        if not isinstance(ext, dict) or ext.get("origin") not in native_host.ALLOWED_ORIGINS:
            raise ServiceError(tr("service.this_extension_isn_secretbroker"), "forbidden")
        ext = {k: str(ext.get(k) or "")[:200] for k in ("origin", "pair", "key", "browser")}
        with self._lock:
            pair = self._browsers().get(ext["pair"]) if ext["pair"] else None
        ext["paired"] = bool(pair and hmac.compare_digest(
            hashlib.sha256(ext["key"].encode()).hexdigest(), pair.get("key_hash", "")) and pair.get("origin") == ext["origin"])
        ext["name"] = (pair or {}).get("name") or ext["browser"] or "Navegador"
        if ext["paired"]:
            self._browser_seen[ext["pair"]] = datetime.now().isoformat(timespec="seconds")
        elif op not in ("ext_hello", "ext_pair"):
            raise ServiceError(tr("service.connect_this_browser_secretbroker_from"), "not_paired")
        _ACTOR.client = {"name": f"Navegador · {ext['name']}", "folder": None}
        return ext

    def op_ext_hello(self, params):
        """The popup's first question: is SecretBroker unlocked, and is this browser connected?"""
        ext = self._extension("ext_hello", params)
        state = "unlocked" if self.vault.is_unlocked else ("locked" if self.vault.exists() else "no_vault")
        with self._lock:
            pending = next((r for r in self._browser_requests.values()
                            if r["pair"] == ext["pair"] and r["expires"] > time.monotonic()), None)
        return {"state": state, "paired": ext["paired"], "browser": ext["name"], "version": __version__,
                "pending": {"code": pending["code"]} if pending else None}

    def op_ext_pair(self, params):
        """Ask to connect this browser: the app shows the request with a code the popup shows too, and the user
        accepts with one click (browser_pair_answer)."""
        ext = self._extension("ext_pair", params)
        if ext["paired"]:
            return {"paired": True}
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", ext["pair"]) or len(ext["key"]) < 32:
            raise ServiceError(tr("service.invalid_connection_request"), "invalid")
        browser = " ".join(str(params.get("name") or ext["browser"] or "Navegador").split())[:40]
        now = time.monotonic()
        with self._lock:
            self._browser_requests = {k: v for k, v in self._browser_requests.items()
                                      if v["expires"] > now and v["pair"] != ext["pair"]}
            if len(self._browser_requests) >= 5:
                raise ServiceError(tr("service.there_are_too_many_pending"), "busy")
            request = {"id": uuid.uuid4().hex, "pair": ext["pair"], "origin": ext["origin"], "name": browser,
                       "key_hash": hashlib.sha256(ext["key"].encode()).hexdigest(),
                       "code": f"{secrets.randbelow(1000000):06d}", "expires": now + BROWSER_PAIR_SECONDS}
            self._browser_requests[request["id"]] = request
            self._revision += 1
        return {"pending": True, "code": request["code"]}

    def _browser_pending(self):
        now = time.monotonic()
        with self._lock:
            return [{"id": r["id"], "name": r["name"], "code": r["code"], "seconds": int(r["expires"] - now)}
                    for r in self._browser_requests.values() if r["expires"] > now]

    def op_browser_status(self, params):
        """For Ajustes › Navegador: the browsers connected (and when they last asked), and requests to connect."""
        with self._lock:
            paired = [{"id": k, "name": v.get("name"), "created": v.get("created"), "last_seen": self._browser_seen.get(k),
                       "firefox": v.get("origin", "").startswith("moz-extension:")} for k, v in self._browsers().items()]
        return {"paired": sorted(paired, key=lambda b: b["created"] or ""), "pending": self._browser_pending()}

    def op_browser_pair_answer(self, params):
        """The user connects (or not) a browser that asked. It can then fill this user's logins: a session unlock
        is not enough (PROVEN_OPS)."""
        accept = params.get("accept") is not False
        if accept:
            self._verify_proof("browser_pair_answer", params)
        with self._lock:
            request = self._browser_requests.pop(str(params.get("id") or ""), None)
            if not request or request["expires"] < time.monotonic():
                raise ServiceError(tr("service.connection_request_has_expired_click"), "not_found")
            if accept:
                self._browsers()[request["pair"]] = {"name": request["name"], "origin": request["origin"],
                                                     "key_hash": request["key_hash"],
                                                     "created": datetime.now().isoformat(timespec="seconds")}
                self._save_browsers()
            self._revision += 1
        self._audit("vault", "browser_pair", request["name"], "ok" if accept else "denied")
        return True

    def op_browser_forget(self, params):
        with self._lock:
            pair = self._browsers().pop(str(params.get("id") or ""), None)
            if pair:
                self._save_browsers()
                self._revision += 1
        if pair:
            self._audit("vault", "browser_forget", pair.get("name") or "", "ok")
        return True

    def _page(self, params):
        """(top, frame, target) Sites of the page asking. Refuses frames of another registrable domain."""
        try:
            top, frame = autofill.page_sites(params.get("url"), params.get("frame_url"))
        except autofill.SiteError as exc:
            raise ServiceError(str(exc), "invalid") from None
        if not autofill.frame_allowed(top, frame):
            raise ServiceError(tr("service.this_form_is_inside_another", label=frame.label, label2=top.label), "frame")
        return top, frame, frame or top

    def _fillable(self, entry):
        """None if the browser may get this login, else why not (shown in the popup)."""
        if (entry.get("shared") or {}).get("permission") == "use":
            return "use_only"
        if entry.get("draft") or not entry["fields"].get("password"):
            return "no_password"
        return None

    def op_ext_logins(self, params):
        """The logins saved for the page (names, users and the address that matched; never a password)."""
        self._extension("ext_logins", params)
        top, frame, target = self._page(params)
        logins = []
        for entry in self.vault.entries():
            matched = autofill.match_entry(entry, target)
            if not matched:
                continue
            why = self._fillable(entry)
            if why == "no_password":
                continue
            shared = entry.get("shared") or {}
            logins.append({"id": entry["id"], "name": entry.get("name") or entry["id"],
                           "username": entry["fields"].get("username", ""), "site": matched[0], "exact": matched[1] == "host",
                           "can_fill": why is None, "why": why, "totp": bool(entry["fields"].get("totp")),
                           "collection": shared.get("collection_name") or None,
                           "last_used": self._browser_used.get(entry["id"])})
        logins.sort(key=lambda l: (not l["can_fill"], not l["exact"], -(l["last_used"] or 0), l["name"].lower()))
        for login in logins:
            login.pop("last_used")
        return {"host": target.label, "domain": autofill.registrable_domain(target.host),
                "secure": target.scheme == "https" or autofill._local(target.host), "frame": bool(frame), "logins": logins}

    def op_ext_search(self, params):
        """The popup's search, over every web login: names, users and their address, to open that site. Logins are
        only ever filled on their own site (op_ext_fill), so a result for another site cannot be filled here."""
        self._extension("ext_search", params)
        words = str(params.get("query") or "").lower().split()[:5]
        if not words:
            return {"results": []}
        results = []
        for entry in self.vault.entries():
            sites = autofill.saved_sites(entry)
            if not sites or entry.get("draft"):
                continue
            text = " ".join([entry.get("name") or "", entry["fields"].get("username", ""), *(a for a, _ in sites)]).lower()
            if all(w in text for w in words):
                address, site = sites[0]
                results.append({"id": entry["id"], "name": entry.get("name") or entry["id"],
                                "username": entry["fields"].get("username", ""), "host": site.label,
                                "url": address if "://" in address else f"https://{address}"})
            if len(results) >= 20:
                break
        return {"results": results}

    def op_ext_fill(self, params):
        """One login's values for the page, after a click in the browser: `what` = login (user and password), totp
        (the current 2FA code), username or password (copied in the popup)."""
        ext = self._extension("ext_fill", params)
        top, frame, target = self._page(params)
        what = params.get("what") or "login"
        if what not in ("login", "totp", "username", "password"):
            raise ServiceError(tr("service.what_fill_in_login_totp"), "invalid")
        entry = self.vault.get(str(params.get("id") or ""))
        if not autofill.match_entry(entry, target):
            self._audit(entry["id"], "browser_fill", target.label, "denied", "La página no es la de esta credencial")
            raise ServiceError(tr("service.this_credential_isn_for", label=target.label), "mismatch")
        if self._fillable(entry) == "use_only":
            self._audit(entry["id"], "browser_fill", target.label, "denied", "Permiso en el equipo: solo uso")
            raise ServiceError(tr("service.this_team_credential_is_use_4"), "forbidden")
        self._last_activity = time.monotonic()  # a click in the browser is the user using the vault
        fields, result = entry["fields"], {}
        if what in ("login", "username"):
            result["username"] = fields.get("username", "")
        if what in ("login", "password"):
            if not fields.get("password"):
                raise ServiceError(tr("service.this_credential_has_no_password"), "not_found")
            result["password"] = fields["password"]
        if what == "totp":
            if not fields.get("totp"):
                raise ServiceError(tr("service.this_credential_has_no_2fa"), "not_found")
            try:
                code = totp.code(fields["totp"])
            except totp.TotpError as exc:
                raise ServiceError(str(exc), "invalid") from None
            result.update(totp=code["code"], remaining=code["remaining"])
        copied = params.get("copy") is True
        detail = {"login": "usuario y contraseña", "totp": "código 2FA", "username": "usuario", "password": "contraseña"}[what]
        self._audit(entry["id"], "browser_copy" if copied else "browser_fill", f"{detail} · {target.label}", "ok")
        self._browser_used[entry["id"]] = time.time()
        return result

    def _save_plan(self, params, target):
        """What saving this login would do: {action: new | update | none, id?, name}."""
        username = str(params.get("username") or "").strip()
        password = str(params.get("password") or "")
        if not username or not password or len(username) > 300 or len(password) > 4096:
            return {"action": "none"}
        same_user = [e for e in self.vault.entries() if autofill.match_entry(e, target)
                     and e["fields"].get("username", "").strip().lower() == username.lower()]
        if any(e["fields"].get("password") == password for e in same_user):
            return {"action": "none"}
        writable = [e for e in same_user if can_write_shared(e) and self._fillable(e) != "use_only"]
        if writable:
            entry = writable[0]
            return {"action": "update", "id": entry["id"], "name": entry.get("name") or entry["id"], "username": username}
        if same_user:
            return {"action": "none"}  # a team login this user may not change
        return {"action": "new", "name": autofill.registrable_domain(target.host), "username": username}

    def op_ext_save_check(self, params):
        """After a form was sent: would saving it add or change something? Nothing is stored here."""
        self._extension("ext_save_check", params)
        top, frame, target = self._page(params)
        return {**self._save_plan(params, target), "host": target.label}

    def op_ext_save(self, params):
        """Save the login the user just typed, after they clicked «Guardar» or «Actualizar» in the browser: a new
        web login for the page, or the new password of the one it matched."""
        self._extension("ext_save", params)
        top, frame, target = self._page(params)
        plan = self._save_plan(params, target)
        if plan["action"] == "none":
            return {"saved": False, **plan}
        password = str(params["password"])
        self._last_activity = time.monotonic()
        if plan["action"] == "update":
            old = self.vault.get(plan["id"])
            self._require_team_write(old)
            entry = copy.deepcopy(old)
            entry["fields"]["password"] = password
            self.vault.put(entry, replaces=old["id"])
            with self._lock:
                self._forget_grants(old["id"])
            self._audit(old["id"], "browser_save", f"contraseña nueva · {target.label}", "ok")
            return {"saved": True, "action": "update", "id": old["id"], "name": plan["name"]}
        name = " ".join(str(params.get("name") or plan["name"]).split())[:100] or plan["name"]
        existing = {e["id"] for e in self.vault.entries()}
        base = SLUG_RE.sub("-", name.lower()).strip("-")[:56] or "web"
        entry_id, n = base, 2
        while entry_id in existing:
            entry_id, n = f"{base}-{n}", n + 1
        fields = {"url": f"{target.scheme}://{target.label}", "username": plan["username"], "password": password}
        entry = {"id": entry_id, "name": name, "template": "web_login", "description": "", "fields": fields,
                 "policy": templates.default_policy("web_login", fields)}
        self.vault.put(entry)
        self._audit(entry_id, "browser_save", f"guardada desde {target.label}", "ok")
        return {"saved": True, "action": "new", "id": entry_id, "name": name}

    # ------------------------------------------------------------------ AI clients (names and times only)

    def _load_ai_clients(self):
        if self._ai_clients is None:
            try:
                data = json.loads(self.ai_clients_file.read_text(encoding="utf-8"))
                self._ai_clients = {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}
            except (OSError, ValueError):
                self._ai_clients = {}
        return self._ai_clients

    def _ai_client_seen(self, name):
        """Remember which program (Claude Code, Cursor…, from the MCP handshake) made an AI request, and when."""
        name = str(name).strip()
        if not AI_CLIENT_NAME_RE.match(name):
            return
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            clients = self._load_ai_clients()
            record = clients.get(name)
            if record is None and len(clients) >= 30:
                return  # a misbehaving local program inventing names
            record = clients.setdefault(name, {"first": now, "requests": 0})
            save = record.get("last", "")[:16] != now[:16]  # on disk at most once a minute per client
            record["last"], record["requests"] = now, record.get("requests", 0) + 1
            if save:
                try:
                    self.ai_clients_file.write_text(json.dumps(clients), encoding="utf-8")
                except OSError:
                    pass

    def op_ai_clients(self, params):
        """[{name, first, last, requests}] of the AI programs that used SecretBroker, newest first."""
        with self._lock:
            clients = copy.deepcopy(self._load_ai_clients())
        return sorted(({"name": k, **v} for k, v in clients.items()), key=lambda c: c.get("last", ""), reverse=True)

    # ------------------------------------------------------------------ backups

    def op_backup(self, params):
        """A copy of the vault file for the app to keep wherever the user wants. It is useless without
        the master password; still, only the app that unlocked gets it."""
        self._verify_proof("backup", params)
        if not self.vault.is_unlocked:
            raise VaultLocked()
        return {"vault": self.vault.file.read_text(encoding="utf-8"), "entries": len(self.vault.entries()),
                "created": datetime.now().isoformat(timespec="seconds")}

    def op_restore(self, params):
        if self.vault.exists():
            self._verify_proof("restore", params)  # replacing a vault needs its owner
        self._throttle()
        try:
            self.vault.restore(str(params.get("vault") or "").encode("utf-8"), params.get("master_password") or "")
        except WrongPassword:
            self._failures += 1
            raise ServiceError(tr("service.master_password_doesn_open_that"), "wrong_password") from None
        except ValueError:
            raise ServiceError(tr("service.that_file_isn_secretbroker_backup"), "invalid") from None
        self._failures = 0
        with self._lock:
            self._grants = {}
        self._last_activity = time.monotonic()
        self._seal_audit_log()
        self._audit("vault", "restore", f"{len(self.vault.entries())} credenciales", "ok")
        self._team_wake.set()
        return {**self.op_status({}), "exposure_session": self._new_scan_session(), "presence": self._new_presence()}

    def op_complete_draft(self, params):
        """The user pastes the secret of a credential the AI prepared."""
        self._verify_proof("complete_draft", params, ALL_PROOFS)
        entry = self.vault.get(params["id"])
        if not entry.get("draft"):
            raise ServiceError(tr("service.this_credential_already_has_its"), "invalid")
        secret_names = templates.secret_field_names(entry["template"])
        for name, value in (params.get("fields") or {}).items():
            if name in secret_names and value:
                entry["fields"][name] = value
        entry.pop("draft", None)
        self.vault.put(entry, replaces=entry["id"])
        self._audit(entry["id"], "save", "clave añadida", "ok")
        return self._summary(self.vault.get(entry["id"]))

    def op_push_github_secret(self, params):
        """Store a credential as a GitHub Actions secret. The value goes from the vault to GitHub only."""
        entry = self._get_secret(params.get("secret_id"))
        token_entry = self._get_secret(params.get("github_secret_id"))
        target = f"GitHub {params.get('repo', '')}" + (f" ({params['environment']})" if params.get("environment") else "")
        detail = f"Subir como secret {params.get('name', '')} a {target}"
        redactors = [Redactor(entry), Redactor(token_entry)]
        used = [entry] if entry["id"] == token_entry["id"] else [entry, token_entry]
        try:
            actions.check_github_secret(params)
            actions._check_destination(token_entry, {"url": actions.GITHUB_API})
            if not self._gate("github", entry, "push_github_secret", detail):
                for item in used:
                    self._authorize(item, "push_github_secret", detail)
            result = actions.push_github_secret(entry, token_entry, params)
        except ServiceError as exc:
            for item in used:
                self._audit(item["id"], "push_github_secret", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            for redact in redactors:
                message = redact(message)
            if not isinstance(exc, ActionError):
                message = f"{type(exc).__name__}: {message}"
            for item in used:
                self._audit(item["id"], "push_github_secret", detail, "error", message)
            raise ServiceError(message, "action_failed") from None
        for item in used:
            self._audit(item["id"], "push_github_secret", detail, "ok")
        self._remember_destination(entry["id"], {
            "kind": "github", "repo": params["repo"], "environment": params.get("environment") or None,
            "name": params["name"], "value": params.get("value") or "{{value}}", "token": token_entry["id"]})
        return result

    def op_release_env(self, params):
        """Hand credentials to a local program started by `sb run`, as environment variables.

        Only credentials with environment variables in their AI permissions can be released: that list
        is the user's opt-in. Each item is {name, secret_id, field}; without a name, every variable of
        the credential is released; without a field, the credential's own template for that variable
        (or {{value}}) is used."""
        command, cwd = str(params.get("command") or ""), str(params.get("cwd") or "")
        grouped = {}
        for item in params.get("vars") or []:
            if not isinstance(item, dict):
                raise ServiceError(tr("service.malformed_request"), "invalid")
            if item.get("name") and not ENV_NAME_RE.match(str(item["name"])):
                raise ServiceError(tr("service.invalid_variable_name", name=item['name']), "invalid")
            if item.get("field") and not ENV_NAME_RE.match(str(item["field"])):
                raise ServiceError(tr("service.invalid_data_name", field=item['field']), "invalid")
            grouped.setdefault(item.get("secret_id"), []).append(item)
        if not grouped:
            raise ServiceError(tr("service.no_variable_was_requested"), "invalid")

        entries = []
        for secret_id, items in grouped.items():
            entry = self._get_secret(secret_id)
            mapping = (entry["policy"].get("commands") or {}).get("env") or {}
            if not mapping:
                raise ServiceError(tr("service.has_no_environment_variables_in", id=entry['id']), "invalid")
            templates_by_name = {}
            for item in items:
                name, field = item.get("name"), item.get("field")
                if not name:
                    templates_by_name.update(mapping)
                else:
                    templates_by_name[name] = "{{%s}}" % field if field else mapping.get(name, "{{value}}")
            entries.append((entry, templates_by_name))

        env, redact = {}, {}
        for entry, templates_by_name in entries:
            detail = f"{command}\n(en {cwd})\nVariables: {', '.join(templates_by_name)}"
            try:
                if not self._gate("local_env", entry, "release_env", detail):
                    self._authorize(entry, "release_env", detail)
                values = {name: substitute(template, entry) for name, template in templates_by_name.items()}
            except (ServiceError, ActionError) as exc:
                denied = isinstance(exc, ServiceError) and exc.code == "denied"
                self._audit(entry["id"], "release_env", detail, "denied" if denied else "error", str(exc))
                raise
            self._audit(entry["id"], "release_env", detail, "ok")
            env.update(values)
            released = list(values.values())
            redact[entry["id"]] = released + [v for v in templates.secret_values(entry) if any(v in r for r in released)]
        return {"env": env, "redact": redact}

    def _authorize(self, entry, action, detail):
        mode = entry.get("policy", {}).get("approval", "session")
        if mode != "always" and self._unusual_use(entry):
            limit = self.vault.settings().get("max_uses_per_hour", 100)
            self._ask_user(entry, action, f"Uso inusual: más de {limit} usos en la última hora.\n\n{detail}",
                           allow_session=mode == "session")
            self._uses.pop(entry["id"], None)
            return
        if mode == "never":
            if self.vault.settings().get("notify_uses", True):
                self._notify(tr("service.ai_used", get=entry.get('name', entry['id'])), detail.splitlines()[0] if detail else "",
                             key=entry["id"])
            return
        if mode == "session" and entry["id"] in self._live_grants():
            return
        self._ask_user(entry, action, detail, allow_session=mode == "session")

    def op_request_access(self, params):
        """The AI asks at the start of a task for every credential it will need: one approval for all."""
        ids = params.get("secret_ids")
        if not isinstance(ids, list) or not ids or len(ids) > 20:
            raise ServiceError(tr("service.give_between_1_and_20"), "invalid")
        reason = str(params.get("reason") or "").strip()[:500]
        entries = [self._get_secret(str(i)) for i in dict.fromkeys(ids)]
        live = self._live_grants()
        mode = lambda e: (e.get("policy") or {}).get("approval", "session")
        needed = [e for e in entries if mode(e) == "session" and e["id"] not in live]
        result = {"already_allowed": [e["id"] for e in entries if e not in needed and mode(e) != "always"],
                  "asks_every_time": [e["id"] for e in entries if mode(e) == "always"], "granted": []}
        if needed:
            names = ", ".join(e.get("name", e["id"]) for e in needed)
            detail = (reason + "\n\n" if reason else "") + "Credenciales: " + names
            first = needed[0]
            batch = {**first, "id": first["id"], "name": names if len(needed) == 1 else f"{len(needed)} credenciales"}
            try:
                self._ask_user(batch, "request_access", detail, allow_session=True,
                               grant_ids=[e["id"] for e in needed], allow_once=False)
            except ServiceError as exc:
                for e in needed:
                    self._audit(e["id"], "request_access", detail, "denied" if exc.code == "denied" else "error", str(exc))
                raise
            for e in needed:
                self._audit(e["id"], "request_access", detail, "ok")
            result["granted"] = [e["id"] for e in needed]
        return result

    def _unusual_use(self, entry):
        """Count this use; True when one credential is used more than the user's hourly limit, even if
        it was approved for the day (a loop gone wrong, or something the user would want to see)."""
        limit = self.vault.settings().get("max_uses_per_hour", 100)
        now = time.monotonic()
        with self._lock:
            uses = self._uses[entry["id"]]
            while uses and now - uses[0] > 3600:
                uses.popleft()
            uses.append(now)
            return bool(limit) and len(uses) > limit

    def _ask_user(self, entry, action, detail, allow_session, grant_ids=None, allow_once=True, strong=False, changes=None):
        """Show the request in the app and wait for the user's answer. `strong`: it deletes, rotates or widens
        where a key goes, so after a Windows-session unlock approving it needs a proof once (op_approve)."""
        if time.monotonic() - self._gui_seen > GUI_SEEN_SECONDS:
            raise ServiceError(tr("service.this_action_needs_user_approval"),
                               "gui_required")
        reason = getattr(_ACTOR, "reason", None) or ""
        if reason:  # shown on its own: not twice
            detail = "\n".join(line for line in detail.split("\n") if line.strip() not in (reason, f"Motivo: {reason}")).strip("\n")
        now = datetime.now()
        request = {
            "id": uuid.uuid4().hex, "secret_id": entry["id"], "secret_name": entry.get("name", entry["id"]),
            "template": entry["template"], "action": action, "detail": detail,
            "allow_session": allow_session, "allow_once": allow_once, "secret_ids": grant_ids or [entry["id"]],
            "strong": bool(strong), **({"changes": changes} if changes else {}),
            "created": now.isoformat(timespec="seconds"),
            "expires": (now + timedelta(seconds=APPROVAL_TIMEOUT_SECONDS)).isoformat(timespec="seconds"),
            "client": getattr(_ACTOR, "client", None), "reason": reason, "host": getattr(_ACTOR, "host", None),
            **self._usage_of(entry["id"]),
            "event": threading.Event(), "answer": None,
        }
        with self._lock:
            self._approvals[request["id"]] = request
        try:
            request["event"].wait(APPROVAL_TIMEOUT_SECONDS)
        finally:
            with self._lock:
                self._approvals.pop(request["id"], None)
                if request["answer"] is None:
                    self._expired.append({"id": request["id"], "secret_name": request["secret_name"], "at": time.monotonic()})
            self._revision += 1  # approved for a while, or not: the app shows it
        if request["answer"] == "session":
            seconds = self._approval_seconds()
            with self._lock:
                for secret_id in grant_ids or [entry["id"]]:
                    self._grants[secret_id] = time.monotonic() + seconds if seconds else None
        elif request["answer"] != "once":
            reason = "El usuario ha denegado el uso de esta credencial" if request["answer"] == "deny" \
                else "Nadie aprobó la solicitud a tiempo"
            raise ServiceError(reason, "denied")

    # ------------------------------------------------------------------ teams (client logic in teams.py)
    #
    # The account password is typed once, in team_connect; afterwards the vault keeps the account keys and a
    # session token, and every change is one click (presence). Nothing here is reachable by the AI.

    def _shared_edit(self, old, entry):
        """An edit of a team credential keeps its team block. Without permission to edit it, only the local
        approval mode may change."""
        entry = {**entry, "shared": copy.deepcopy(old["shared"])}
        if not can_write_shared(old):
            if _normalized(shared_content(old)) != _normalized(shared_content(entry)):
                raise ServiceError(_team_read_only(old), "forbidden")
            approval = (entry.get("policy") or {}).get("approval", "session")
            entry = copy.deepcopy(old)
            entry["policy"] = {**(old.get("policy") or {}), "approval": approval}
            return entry
        pending = entry["shared"].get("pending_policy")
        if pending and teams.widening_changes(old, entry) + teams.widening_changes(entry, old):
            entry["shared"].pop("pending_policy")  # the user decided by hand where it may go
        elif pending and "description" in pending and (old.get("description") or "") != (entry.get("description") or ""):
            # The user wrote the description by hand: theirs is the one that goes to the team. A new rotation guide
            # still waits for review.
            pending.pop("description")
            pending["texts"] = bool(pending.get("rotation_guide"))
            pending["changes"] = [c for c in pending.get("changes") or []
                                  if not teams.is_text_change(c) or (isinstance(c, dict) and c.get("kind") == "rotation_guide")]
            if not pending["changes"]:
                entry["shared"].pop("pending_policy")
        if (entry.get("rotation_guide") or None) != (old.get("rotation_guide") or None):
            entry["shared"].pop("guide_by", None)  # written here now
        return entry

    def _require_team_write(self, entry):
        if not can_write_shared(entry):
            raise ServiceError(_team_read_only(entry), "forbidden")

    def _team_loop(self):
        """Sync while the vault is unlocked: on unlock, every 5 minutes, and soon after a local change."""
        while True:
            self._team_wake.wait(TEAM_SYNC_SECONDS)
            self._team_wake.clear()
            if self.vault.is_unlocked:
                self._team_sync()

    def _team_sync(self):
        """One sync round. Never raises: problems are reported by team_status."""
        with self._team_lock:
            try:
                if not teams.connected(self.vault.team()):
                    self._team_info = {"state": "idle"}
                    return None
                self._team_info = {**self._team_info, "state": "syncing"}
                notes = self.team.sync()
            except teams.TeamError as exc:
                print(f"team sync: {teams.detail(exc)}", file=sys.stderr)
                state = exc.code if exc.code in ("reconnect", "offline") else "error"
                self._team_state(state, teams.explain(exc))
                return None
            except VaultLocked:
                self._team_info = {**self._team_info, "state": "idle"}
                return None
            except Exception as exc:  # noqa: BLE001 - the sync thread must survive anything
                print(f"team sync: {type(exc).__name__}", file=sys.stderr)
                self._team_state("error", tr("service.couldn_sync_with_team_it"))
                return None
            self._team_info = {"state": "error" if notes["errors"] else "ok", "error": "; ".join(notes["errors"])[:500],
                               "last_sync": datetime.now().isoformat(timespec="seconds"),
                               "last": {k: len(v) for k, v in notes.items()}}
        self._team_notices(notes)
        return notes

    def _team_state(self, state, error=""):
        """The sync state the GUI shows; a session that just expired is also told in a Windows notice."""
        if state == "reconnect" and not self._team_info.get("expired"):
            self._notify(tr("service.your_team_session_has_expired"), tr("service.open_secretbroker_team_and_sign"))
        # `expired` stays until a sync round works again (it rebuilds _team_info): one notice per expiry.
        self._team_info = {**self._team_info, "state": state, "error": error,
                           "expired": bool(self._team_info.get("expired")) or state == "reconnect"}

    def _team_notices(self, notes):
        # Actividad shows who changed what: the name of whoever signed the change (2.6), not just "Equipo".
        for change in notes.get("changes", []):
            self._audit(change["id"], change["action"], change.get("detail") or "", "ok", by=change.get("by"))
        for name in notes["quarantined"]:
            self._notify(tr("service.change_review_in", name=name), tr("service.teammate_changed_where_key_can"))
        for held in notes.get("held_deletions", []):
            who = _join(held["by"]) if held["by"] else None
            self._notify(tr("service.held_waiting", count=held["count"], collection=held["collection"]),
                         (tr("service.collection_no_longer_appears_on") if held.get("gone") else
                          tr("service.deleted_them_at_once", value=who or tr("service.someone")))
                         + tr("service.nothing_has_been_deleted_on"))
            self._audit("vault", "team_held", f"{held['count']} borradas en {held['collection']}: esperan tu decisión",
                        "denied", by=who)
        if notes.get("unsigned"):
            self._notify(tr("service.team_changes_discarded"), tr("service.unsigned_discarded", names=", ".join(notes["unsigned"][:3])))
            self._audit("vault", "team_unsigned", ", ".join(notes["unsigned"][:5]), "denied")
        for item in notes.get("recovery", []):
            self._audit("vault", "team_recovery", f"{item['person']} puede recuperar «{item['collection']}»", "ok")
        for item in notes["rotate"]:
            people = item["people"]
            self._notify(tr("service.change_keys", collection=item['collection']),
                         tr("service.rotate_after_leave", count=len(people), names=_join(people)))
        for name in notes.get("trust", []):
            self._notify(tr("service.verify_security_code", name=name), tr("service.until_then_collection_keys_they"))
        for entry_id in notes["conflicts"]:
            self._notify(tr("service.sync_conflict"), tr("service.someone_changed_credential_at_same", entry_id=entry_id))
            self._audit(entry_id, "team_conflict", "tu versión, guardada aparte", "error")
        if notes["added"]:
            self._notify(tr("service.new_credentials_from_team"), ", ".join(notes["added"]))

    def _team_call(self, op, params, action, change=True):
        """Changes run one at a time with the sync (team lock). Reads (`change=False`) don't wait for it: they
        only look at the server and write the Equipo view's cache, never the team state."""
        kind = self._verify_proof(op, params) if change else "presence"
        if not self.vault.is_unlocked:
            raise VaultLocked()
        try:
            if change:
                with self._team_lock:
                    result = action()
            else:
                result = action()
        except teams.TeamError as exc:
            if exc.code in ("reconnect", "offline"):
                self._team_state(exc.code, str(exc))
            raise
        if not change and self._team_info.get("state") == "offline":
            self._team_wake.set()  # the server answers again: a sync round puts the state right
        if kind != "presence" and isinstance(result, dict):
            result = {**result, "presence": getattr(_ACTOR, "presence", None) or self._new_presence()}  # proved it: one click again from now on
        return result

    def op_team_overview(self, params):
        """What the Equipo view draws at once, from this PC (no network, no team lock)."""
        if not self.vault.is_unlocked:
            raise VaultLocked()
        if not teams.connected(self.vault.team()):
            return {"status": self.op_team_status({})}
        return {**self.team.overview(), "status": self.op_team_status({})}

    def op_team_offboarding(self, params):
        """Per person who left: credentials they could see and which are still to be changed."""
        if not self.vault.is_unlocked:
            raise VaultLocked()
        return self.team.offboarding()

    def op_team_status(self, params):
        status = self.team.status()
        info = dict(self._team_info)
        return {**status, "state": info.pop("state") if status["connected"] else "off",
                **({k: v for k, v in info.items() if k in ("error", "last", "last_sync")} if status["connected"] else {})}

    def op_team_connect(self, params):
        """Create (mode "register") or open (mode "login") the team account. Its password is only used here."""
        result = self._team_call("team_connect", params, lambda: self.team.connect(
            params.get("server_url"), params.get("email"), str(params.get("password") or ""),
            params.get("mode") or "login", params.get("name") or "", params.get("device_name") or "",
            params.get("invite_token")))
        self._team_info = {"state": "idle"}
        self._audit("vault", "team_connect", f"{result['user']['email']} en {result['server_url']}", "ok")
        self._team_wake.set()
        return result

    def op_team_verify_email(self, params):
        """The code the team server e-mailed: until then invites to this address are not shown."""
        result = self._team_call("team_verify_email", params, lambda: self.team.verify_email(params.get("code")))
        self._audit("vault", "team_verify_email", result["user"]["email"], "ok")
        self._team_wake.set()  # invites may be waiting
        return result

    def op_team_send_code(self, params):
        return self._team_call("team_send_code", params, self.team.send_code)

    def op_team_resolve_deletions(self, params):
        """Held deletions (too many at once): `apply` deletes them here too; otherwise they are kept."""
        apply = params.get("apply", True) is not False
        result = self._team_call("team_resolve_deletions", params, lambda: self.team.resolve_deletions(
            params.get("collection"), apply))
        self._audit("vault", "team_resolve", f"{result['count']} de {result['collection_name']} "
                    + ("borradas también aquí" if apply else "conservadas"), "ok")
        self._team_wake.set()  # restored ones go back to the server
        return result

    def op_team_disconnect(self, params):
        result = self._team_call("team_disconnect", params, self.team.disconnect)
        self._team_info = {"state": "idle"}
        self._audit("vault", "team_disconnect", f"{result['removed']} credenciales del equipo quitadas", "ok")
        return result

    def op_team_sync(self, params):
        if not self.vault.is_unlocked:
            raise VaultLocked()
        notes = self._team_sync()
        return {**self.op_team_status({}), "result": notes}

    def op_team_orgs(self, params):
        return self._team_call("team_orgs", params, self.team.orgs, change=False)

    def op_team_create_org(self, params):
        return self._team_call("team_create_org", params, lambda: self.team.create_org(params.get("name")))

    def op_team_invite(self, params):
        return self._team_call("team_invite", params, lambda: self.team.invite(
            params.get("org"), params.get("email"), params.get("role") or "member"))

    def op_team_renew_invite(self, params):
        """A new code for a pending or expired invite, e-mailed again if the server can."""
        return self._team_call("team_renew_invite", params, lambda: self.team.renew_invite(
            params.get("org"), params.get("email")))

    def op_team_resend_invite(self, params):
        return self._team_call("team_resend_invite", params, lambda: self.team.resend_invite(
            params.get("org"), params.get("email")))

    def op_team_drop_invite(self, params):
        return self._team_call("team_drop_invite", params, lambda: self.team.drop_invite(
            params.get("org"), params.get("email")))

    def op_team_invite_code(self, params):
        """The code of a pending invite ({org, email}), for the instructions the admin passes on. It works as a
        sign-up code for that e-mail, so the member list (no proof) never carries it: this needs one click."""
        return self._team_call("team_invite_code", params, lambda: self.team.invite_code(
            params.get("org"), params.get("email")))

    def op_team_invites(self, params):
        return self._team_call("team_invites", params, self.team.invites, change=False)

    def op_team_accept_invite(self, params):
        result = self._team_call("team_accept_invite", params, lambda: self.team.accept_invite(
            params.get("id"), params.get("fingerprint")))
        self._audit("vault", "team_join", "invitación aceptada", "ok")
        return result

    def op_team_devices(self, params):
        """This team account's devices («Tu cuenta»)."""
        return self._team_call("team_devices", params, self.team.devices, change=False)

    def op_team_revoke_device(self, params):
        result = self._team_call("team_revoke_device", params, lambda: self.team.revoke_device(params.get("id")))
        self._audit("vault", "team_device", "sesión cerrada en otro dispositivo", "ok")
        return result

    def op_team_change_password(self, params):
        """A new team account password (the current one is needed). Keys stay the same; other devices log out."""
        result = self._team_call("team_change_password", params, lambda: self.team.change_password(
            str(params.get("current") or ""), str(params.get("password") or "")))
        self._audit("vault", "team_password", "contraseña de la cuenta del equipo cambiada", "ok")
        return result

    def op_team_members(self, params):
        return self._team_call("team_members", params, lambda: self.team.members(params.get("org")), change=False)

    def op_team_confirm_member(self, params):
        result = self._team_call("team_confirm_member", params, lambda: self.team.confirm_member(
            params.get("org"), params.get("user_id"), params.get("fingerprint")))
        self._audit("vault", "team_confirm", f"miembro verificado (código de seguridad {result['fingerprint']})", "ok")
        return result

    def op_team_set_role(self, params):
        return self._team_call("team_set_role", params, lambda: self.team.set_role(
            params.get("org"), params.get("user_id"), params.get("role")))

    def op_team_remove_member(self, params):
        result = self._team_call("team_remove_member", params, lambda: self.team.remove_member(
            params.get("org"), params.get("user_id")))
        count = len(result["rekeyed"])
        self._audit("vault", "team_remove", f"{count} {'colección vuelta' if count == 1 else 'colecciones vueltas'} "
                    "a cifrar" + (f"; {len(result['failed'])} en la próxima sincronización" if result.get("failed") else ""),
                    "ok")
        if result.get("failed"):
            self._team_wake.set()
        return result

    def op_team_collections(self, params):
        return self._team_call("team_collections", params, self.team.collections, change=False)

    def op_team_create_collection(self, params):
        return self._team_call("team_create_collection", params, lambda: self.team.create_collection(
            params.get("org"), params.get("name")))

    def op_team_collection_members(self, params):
        return self._team_call("team_collection_members", params,
                               lambda: self.team.collection_members(params.get("collection")), change=False)

    def op_team_grant(self, params):
        result = self._team_call("team_grant", params, lambda: self.team.grant(
            params.get("collection"), params.get("user_id"), params.get("permission")))
        self._audit("vault", "team_grant", f"permiso «{params.get('permission')}» en una colección", "ok")
        return result

    def op_team_revoke(self, params):
        result = self._team_call("team_revoke", params, lambda: self.team.revoke(
            params.get("collection"), params.get("user_id")))
        self._audit("vault", "team_revoke", "acceso a una colección retirado; la colección se vuelve a cifrar", "ok")
        return result

    def op_team_share_entry(self, params):
        entry = self.vault.get(params.get("id"))
        result = self._team_call("team_share_entry", params, lambda: self.team.share_entry(
            entry["id"], params.get("collection")))
        self._audit(entry["id"], "share", f"Compartida en {result['collection_name']}", "ok")
        return {**result, "entry": self._summary(self.vault.get(entry["id"]))}

    def op_team_share_entries(self, params):
        """Share several credentials in one collection with one click."""
        ids = [str(i) for i in (params.get("ids") or [])][:500]
        for entry_id in ids:
            self.vault.get(entry_id)
        result = self._team_call("team_share_entries", params, lambda: self.team.share_entries(
            ids, params.get("collection")))
        for entry_id in result["shared"]:
            self._audit(entry_id, "share", f"Compartida en {result['collection_name']}", "ok")
        return result

    def op_team_share_with(self, params):
        """Share credentials with one teammate in one step (a direct share, docs/ARCHITECTURE.md 5)."""
        ids = [str(i) for i in (params.get("ids") or [])][:500]
        for entry_id in ids:
            self.vault.get(entry_id)
        result = self._team_call("team_share_with", params, lambda: self.team.share_with(
            ids, params.get("org"), params.get("user_id"), params.get("permission") or "view"))
        for entry_id in result["shared"]:
            self._audit(entry_id, "share", f"Compartida con {result['person']}", "ok")
        return result

    def op_team_unshare_with(self, params):
        """Stop sharing with that person: the direct share ends, its credentials are flagged to rotate."""
        result = self._team_call("team_unshare_with", params, lambda: self.team.unshare_with(params.get("collection")))
        for entry_id in result["ids"]:
            self._audit(entry_id, "unshare", f"Ya no compartida con {result['person']}", "ok")
        return result

    def op_team_unshare_entry(self, params):
        entry = self.vault.get(params.get("id"))
        result = self._team_call("team_unshare_entry", params, lambda: self.team.unshare_entry(entry["id"]))
        self._audit(entry["id"], "unshare", f"Ya no compartida con {result['with']}" if result.get("with")
                    else f"Ya no está en {result['collection_name']}", "ok")
        return {**result, "entry": self._summary(self.vault.get(entry["id"]))}

    def op_team_accept_change(self, params):
        """Accept (or, with edit permission, turn down) a teammate's change to where a key can go."""
        entry = self.vault.get(params.get("id"))
        accept = params.get("accept", True) is not False
        result = self._team_call("team_accept_change", params, lambda: self.team.accept_change(entry["id"], accept))
        if accept:
            self._forget_grants(entry["id"])  # approvals were given for the places it could go before
        else:
            self._team_wake.set()  # push the local version back
        self._audit(entry["id"], "team_change", ("aceptado: " if accept else "rechazado: ")
                    + "; ".join(teams.change_text(c) for c in result["changes"]), "ok")
        return {**result, "entry": self._summary(self.vault.get(entry["id"]))}

    def op_team_events(self, params):
        return self._team_call("team_events", params, lambda: self.team.events(
            params.get("org"), params.get("before")), change=False)

    # ------------------------------------------------------------------ the team server's admin («Servidor», 5.2)
    # Reads only need an unlocked vault (short timeouts, cached in team_view); changes are one click.

    def op_team_admin_overview(self, params):
        return self._team_call("team_admin_overview", params, self.team.admin_overview, change=False)

    def op_team_admin_users(self, params):
        return self._team_call("team_admin_users", params, self.team.admin_users, change=False)

    def op_team_admin_orgs(self, params):
        return self._team_call("team_admin_orgs", params, self.team.admin_orgs, change=False)

    def op_team_admin_events(self, params):
        return self._team_call("team_admin_events", params, self.team.admin_events, change=False)

    def op_team_admin_backups(self, params):
        return self._team_call("team_admin_backups", params, self.team.admin_backups, change=False)

    def op_team_admin_backup_now(self, params):
        result = self._team_call("team_admin_backup_now", params, self.team.admin_backup_now)
        self._audit("vault", "team_admin", "copia de seguridad del servidor del equipo", "ok")
        return result

    def op_team_admin_settings(self, params):
        result = self._team_call("team_admin_settings", params, lambda: self.team.admin_settings(
            params.get("signups"), params.get("auto_update")))
        self._audit("vault", "team_admin", "ajustes del servidor del equipo: " + ", ".join(
            f"{k} = {v}" for k, v in result.items()), "ok")
        return result

    def op_team_admin_disable(self, params):
        """Block an account on the team server: it leaves its teams, whose managers re-key and flag credentials."""
        result = self._team_call("team_admin_disable", params, lambda: self.team.admin_disable(params.get("user_id")))
        self._audit("vault", "team_admin", f"cuenta desactivada en el servidor: {result['person']}", "ok")
        self._team_wake.set()  # collections this user manages are re-keyed now
        return result

    def op_team_admin_enable(self, params):
        result = self._team_call("team_admin_enable", params, lambda: self.team.admin_enable(params.get("user_id")))
        self._audit("vault", "team_admin", f"cuenta reactivada en el servidor: {result['person']}", "ok")
        return result

    def op_team_admin_verify(self, params):
        result = self._team_call("team_admin_verify", params, lambda: self.team.admin_verify(params.get("user_id")))
        self._audit("vault", "team_admin", f"e-mail verificado por el administrador: {result['person']}", "ok")
        return result

    def op_team_admin_delete(self, params):
        """Delete an account on the team server; refused (with the fix) while it is the only owner or manager."""
        result = self._team_call("team_admin_delete", params, lambda: self.team.admin_delete(params.get("user_id")))
        if result["deleted"]:
            self._audit("vault", "team_admin", f"cuenta borrada en el servidor: {result['person']}", "ok")
            self._team_wake.set()
        return result

    def op_team_admin_transfer_owner(self, params):
        result = self._team_call("team_admin_transfer_owner", params, lambda: self.team.admin_transfer_owner(
            params.get("org"), params.get("user_id")))
        self._audit("vault", "team_admin", f"nuevo propietario de una organización: {result['person']}", "ok")
        return result

    def op_team_admin_signup_token(self, params):
        """A single-use code to create an account on the team server (sign-ups by invitation)."""
        result = self._team_call("team_admin_signup_token", params, lambda: self.team.admin_signup_token(params.get("days")))
        self._audit("vault", "team_admin", "código de registro creado en el servidor del equipo", "ok")
        return result

    # ------------------------------------------------------------------ audit

    def _audit(self, secret_id, action, detail, status, message="", by=None):
        """`by`: for a team change, the name of the teammate who signed it."""
        actor = "team" if action in TEAM_SYNC_EVENTS else getattr(_ACTOR, "value", None) or \
            ("team" if action.startswith("team_") else "system")
        event = {"ts": datetime.now().isoformat(timespec="seconds"), "secret": secret_id, "action": action,
                 "detail": detail.splitlines()[0][:300] if detail else "", "status": status, "actor": actor}
        if message:
            event["message"] = message[:300]
        if by:
            event["by"] = str(by)[:100]
        client = getattr(_ACTOR, "client", None)
        if client:
            event["client"] = client["name"]
        if event["actor"] != "user":
            self._revision += 1  # the app shows the AI's uses (Actividad reciente) and the team's changes
        if event["actor"] == "ai" and status == "ok" and action in AI_USE_ACTIONS and self._usage is not None:
            self._count_use(self._usage, secret_id, event["ts"])
        with self._lock:
            public_key = self.vault.audit_public_key()
            if public_key is None:
                # A vault from 0.3 or earlier that was not unlocked yet: keep it until it is.
                self._pending_audit.append(event)
                return
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with self.audit_file.open("a", encoding="utf-8") as log:
                log.write(self._seal_audit_event(public_key, event) + "\n")

    @staticmethod
    def _seal_audit_event(public_key, event):
        return json.dumps(crypto.seal_to(public_key, json.dumps(event, ensure_ascii=False).encode("utf-8"), AUDIT_AAD))

    @staticmethod
    def _open_audit_line(private_key, line):
        record = json.loads(line)
        if "epk" not in record:
            return record  # written in clear by 0.3 or earlier
        return json.loads(crypto.open_from(private_key, record, AUDIT_AAD))

    def _seal_audit_log(self):
        """Once the vault is open: encrypt events left in clear by earlier versions and those held in memory."""
        with self._lock:
            public_key = self.vault.audit_public_key()
            try:
                lines = [line for line in self.audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            except OSError:
                lines = []
            plain = [_plain_audit_event(line) for line in lines]
            if not any(plain) and not self._pending_audit:
                return
            sealed = [self._seal_audit_event(public_key, event) if event else line for line, event in zip(lines, plain)]
            sealed += [self._seal_audit_event(public_key, event) for event in self._pending_audit]
            self._pending_audit = []
            tmp = self.audit_file.with_suffix(".tmp")
            tmp.write_text("".join(line + "\n" for line in sealed), encoding="utf-8")
            os.replace(tmp, self.audit_file)


CHANGE_LABELS = {"name": "Nombre", "description": "Notas para la IA", "tags": "Etiquetas", "expires": "Caduca",
                 "rotate_every_days": "Rotar cada (días)", "rotation_guide": "Guía de rotación", "used_in": "Dónde se usa",
                 "check_every_hours": "Comprobar cada (horas)"}
def _paired_question(entry):
    """For the AI: the id a secret goes with, or a question to settle it when nobody knows."""
    paired = rotation.paired_id(entry)
    if paired and paired["value"]:
        return {"paired_id": {"label": paired["label"], "value": paired["value"]}}
    unknown = entry["template"] in ("api_key", "generic") and (rotation.info(entry) or {}).get("provider") in (None, links.OWN_SECRET)
    if not paired and not unknown:
        return {}
    what = f"un {paired['label']}" if paired else "un identificador (client id, app id, account id, key id…)"
    return {"paired_id": None, "question": f"¿Este secreto va emparejado con {what}? Si es así, guárdalo en fields.username "
            "con update_credential (pregúntaselo al usuario si no lo sabes): al rotarlo, la app preguntará si ha cambiado."}


USED_IN_QUESTION = ("¿Dónde se usa esta credencial (develop, pre, pro, el .env de un servidor, Vercel, CI, otro proyecto…)? "
                    "Apúntalo con update_credential(used_in=[...]): al rotarla, la app le pedirá al usuario que la cambie en cada sitio.")
CONTEXT_KEYS = ("name", "description", "tags", "expires", "rotate_every_days", "rotation_guide", "check_every_hours", "used_in")  # changes that don't affect where a key can go
CONTEXT_KEYS += ("test_request",)  # only to the credential's own allowed hosts, and read-only
TEST_QUESTION = ("La app no sabe cómo probar esta clave. Busca en la documentación de su API un endpoint de solo lectura "
                 "que necesite la clave y guárdalo con update_credential(test_request={\"method\": \"GET\", \"url\": \"/ruta\", "
                 "\"status\": 200}): así se comprueba que funciona y, al rotarla, se prueba la nueva.")
CHANGE_LABELS["test_request"] = "Petición de prueba"


def _setting_value(key, value):
    """A context setting as the structured change keeps it (JSON, no secrets): the page words it."""
    if value in (None, "", []):
        return None
    if key == "rotation_guide":
        return {"steps": len(value.get("create") or []), "sources": list(value.get("sources") or [])}
    if key == "test_request":
        return {k: value.get(k) for k in ("method", "url", "status")}
    if key in ("name", "description"):
        return str(value)[:300]
    return value


def _describe_changes(old, new):
    """[(key, line, change)] of what differs between two versions of an entry (no secrets). `line` is Spanish, for the
    activity log and the AI (like the service's other audit details); `change` is the same, structured
    ({kind: setting | field | allowed_hosts | programs | env_vars, …}), for the approval card, which words it in the
    app's language (change_line_text here, changeLine in the page)."""
    changes = []
    for key in CONTEXT_KEYS:
        if old.get(key) != new.get(key):
            value = ", ".join(new[key]) if key == "tags" and new.get(key) else str(new.get(key) or "—")
            if key == "rotation_guide" and new.get(key):
                value = f"{len(new[key]['create'])} {'paso' if len(new[key]['create']) == 1 else 'pasos'}; fuentes: {', '.join(new[key]['sources'])}"
            elif key == "rotate_every_days" and new.get(key) is not None:
                value = str(new[key] or "nunca")
            elif key == "used_in":
                value = "; ".join(new.get(key) or []) or "—"
            elif key == "check_every_hours" and new.get(key) is not None:
                value = {0: "nunca", CHECK_ONCE: "solo una vez"}.get(new[key], str(new[key]))
            elif key == "test_request" and new.get(key):
                value = f"{new[key]['method']} {new[key]['url']} → HTTP {new[key]['status']}"
            changes.append((key, f"{CHANGE_LABELS[key]}: «{value[:200]}»",
                            {"kind": "setting", "key": key, "value": _setting_value(key, new.get(key))}))
    labels = {s["name"]: s["label"] for s in templates.field_specs(old["template"])}
    for name in sorted(set(old["fields"]) | set(new["fields"])):
        if name in templates.SECRET_FIELDS or name in templates.secret_field_names(old["template"])                 or old["fields"].get(name) == new["fields"].get(name):
            continue
        changes.append((name, f"{labels.get(name, name)}: {old['fields'].get(name) or '—'} → {new['fields'].get(name) or '—'}",
                        {"kind": "field", "field": name, "template": old["template"],
                         "old": old["fields"].get(name) or "", "new": new["fields"].get(name) or ""}))
    old_policy, new_policy = old.get("policy") or {}, new.get("policy") or {}
    hosts = lambda p: (p.get("http") or {}).get("allowed_hosts") or []
    if hosts(old_policy) != hosts(new_policy):
        changes.append(("hosts", f"Webs permitidas: {', '.join(hosts(new_policy)) or '—'}",
                        {"kind": "allowed_hosts", "values": list(hosts(new_policy))}))
    commands = lambda p: p.get("commands") or {}
    if commands(old_policy).get("allowed", []) != commands(new_policy).get("allowed", []):
        allowed = list(commands(new_policy).get("allowed", []))
        changes.append(("commands", f"Programas: {', '.join(allowed) or '—'}", {"kind": "programs", "values": allowed}))
    if commands(old_policy).get("env", {}) != commands(new_policy).get("env", {}):
        env = [f"{k}={v}" for k, v in commands(new_policy).get("env", {}).items()]
        changes.append(("env", "Variables: " + (", ".join(env) or "—"), {"kind": "env_vars", "values": env}))
    return changes


def change_line_text(change):
    """One structured change of _describe_changes in the language of the request (for a notice)."""
    kind = change.get("kind")
    if kind == "field":
        template = change.get("template")
        specs = i18n.localize("templates", templates.field_specs(template)) if template in templates.TEMPLATES else []
        label = next((s["label"] for s in specs if s["name"] == change.get("field")), change.get("field"))
        return f"{label}: {change.get('old') or '—'} → {change.get('new') or '—'}"
    if kind in ("allowed_hosts", "programs", "env_vars"):
        return f"{tr('service.change_' + kind)}: {', '.join(change.get('values') or []) or '—'}"
    key, value = change.get("key"), change.get("value")
    if value is None:
        text = "—"
    elif key in ("tags", "used_in"):
        text = ", ".join(value)
    elif key == "rotate_every_days":
        text = tr("service.change_every_days", days=value) if value else tr("service.change_never")
    elif key == "check_every_hours":
        text = tr("service.change_never") if value == 0 else tr("service.change_once") if value == CHECK_ONCE             else tr("service.change_every_hours", count=value)
    elif key == "rotation_guide":
        text = tr("service.change_steps", count=value.get("steps", 0))
    elif key == "test_request":
        text = f"{value.get('method')} {value.get('url')} → HTTP {value.get('status')}"
    else:
        text = f"«{str(value)[:200]}»"
    return f"{tr('service.change_' + str(key))}: {text}"


def _normalized(content):
    """Entry content without empty values, so an editor that sends "" or [] for unset keys is no change."""
    if isinstance(content, dict):
        return {k: _normalized(v) for k, v in content.items() if v not in (None, "", [], {})}
    return content


def _join(names):
    """«Bob», «Bob y Carol», «Bob, Carol y Dan» (in the language of the request)."""
    names = [str(n) for n in names]
    return names[0] if len(names) == 1 else tr("service.list_and", names=", ".join(names[:-1]), last=names[-1]) if names else ""


def _team_read_only(entry):
    shared = entry.get("shared") or {}
    return (f"«{entry.get('name') or entry['id']}» es del equipo ({shared.get('collection_name') or 'colección compartida'}) "
            "y tu permiso no permite cambiarla. Pide a quien la gestiona que lo haga.")


def _set_rotation(data, entry_id, **changes):
    """Change an entry's rotation state (vault section "rotation"); None or [] removes a key."""
    item = data.setdefault("entries", {}).setdefault(entry_id, {})
    for key, value in changes.items():
        if value in (None, []):
            item.pop(key, None)
        else:
            item[key] = value
    if not item:
        data["entries"].pop(entry_id)


def rotation_password(entry):
    """A new secret made by the service: 32 letters and digits for a password (nothing to escape in a
    connection URL, SQL or a shell), 48 random bytes (URL-safe) for a secret of the user's own."""
    if entry["template"] in ("api_key", "generic"):
        return secrets.token_urlsafe(48)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _clean_test_request(entry, test):
    """{method, url, status} checked against the credential: GET or HEAD, to one of its allowed hosts
    (a path is joined to its API address). None or {} means no test. Raises ValueError."""
    if not test:
        return None
    if not isinstance(test, dict) or entry["template"] not in ("api_key", "generic"):
        raise ValueError(tr("service.only_api_keys_and_other"))
    method = str(test.get("method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        raise ValueError(tr("service.test_request_can_only_be"))
    url = str(test.get("url") or test.get("path") or "").strip()
    if url.startswith("/"):
        base = (entry["fields"].get("base_url") or entry["fields"].get("url") or "").strip().rstrip("/")
        if not base:
            raise ValueError(tr("service.type_full_address_https_credential"))
        url = (base if "://" in base else "https://" + base) + url
    # The hosts the policy names; a personal credential's own fields may stand in for them, a shared one's never
    # (exposure._check_test_request).
    hosts = ((entry.get("policy") or {}).get("http") or {}).get("allowed_hosts") or ([] if entry.get("shared") else
        templates.default_policy(entry["template"], entry["fields"]).get("http", {}).get("allowed_hosts") or [])
    try:
        actions._check_destination({"id": entry["id"], "policy": {"http": {"allowed_hosts": hosts}}}, {"url": url})
    except ActionError as exc:
        raise ValueError(tr("service.test_request_can_only_go", exc=exc)) from None
    try:
        status = int(test.get("status") or 200)
    except (TypeError, ValueError):
        raise ValueError(tr("service.expected_response_must_be_http")) from None
    if not 200 <= status <= 399:
        raise ValueError(tr("service.expected_response_must_be_code"))
    return {"method": method, "url": url, "status": status}


def _clean_client(client):
    """{name, folder} of the program asking (sent by the MCP server and sb), or None. Shown, never trusted."""
    if not isinstance(client, dict) or not str(client.get("name") or "").strip():
        return None
    folder = str(client.get("folder") or "").strip()
    return {"name": " ".join(str(client["name"]).split())[:60], "folder": folder[:260] or None}


def _target_host(action, params, entry):
    """The host a request of the AI goes to, or None."""
    if action == "http_request":
        try:
            return urlsplit(str(params.get("url") or "")).hostname
        except ValueError:
            return None
    if action.startswith("ssh_"):
        return entry["fields"].get("host")
    return None


def _plain_audit_event(line):
    """The event of an audit line written in clear, or None if it is encrypted or unreadable."""
    try:
        record = json.loads(line)
    except ValueError:
        return None
    return record if isinstance(record, dict) and "epk" not in record else None


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        service = self.server.service
        nonce = b""
        try:
            request = json.loads(self.rfile.readline(MAX_REQUEST_BYTES))
            nonce = base64.b64decode(request.get("nonce", ""))
            if not hmac.compare_digest(str(request.get("token", "")).encode(), service.token.encode()):
                response = {"ok": False, "code": "auth", "error": tr("service.invalid_service_token")}
            else:
                lang = request.get("lang")  # only the app sends it: the language it shows
                if lang:
                    i18n.set_default(lang)  # also for the AI's requests, the browser and notices from the team sync
                with i18n.using(lang):
                    response = service.handle(request.get("op"), request.get("params") or {}, request.get("client"))
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            response = {"ok": False, "code": "bad_request", "error": tr("service.malformed_request")}
        body = json.dumps(response, ensure_ascii=False)
        envelope = {"body": body, "sig": service.sign(nonce, body.encode("utf-8"))}
        self.wfile.write(json.dumps(envelope).encode("utf-8") + b"\n")


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description="SecretBroker service")
    parser.add_argument("--root", help="Carpeta de datos (por defecto según el modo)")
    parser.add_argument("--owner", help="Usuario propietario (Windows: DOMINIO\\usuario; Linux: nombre de usuario)")
    parser.add_argument("--isolated", action="store_true", help="Modo instalado con cuenta de servicio dedicada")
    args = parser.parse_args()
    owner = args.owner or platform.default_owner()
    root = Path(args.root or paths.root())
    if sys.stderr is None:  # pythonw: keep crash reports somewhere
        (root / "data").mkdir(parents=True, exist_ok=True)
        sys.stderr = open(root / "data" / "service.log", "a", encoding="utf-8", buffering=1)
    service = Service(root, owner, args.isolated)
    service.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        service.stop()


if __name__ == "__main__":
    main()
