"""SecretBroker service: owns the vault and performs actions with secrets.

In installed mode it runs as a dedicated Windows account, so processes of the desktop user
(including AI agents) can neither read its memory nor its files. Clients talk to it over
127.0.0.1; every response is signed so clients can tell it is the real service.

Sensitive operations need a *proof* the service verifies by itself:
  hello            RSA signature from the owner's Windows Hello key over a one-time challenge
  windows_password the owner's Windows account password (checked with LogonUser)
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

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import actions, crypto, exposure, links, paths, rotation, update, winsec
from .inject import ActionError, Redactor, substitute
from .vault import (
    DEFAULT_SETTINGS, Vault, VaultLocked, ValidationError, WrongPassword, agent_view,
    check_master_password, convert_legacy_entry, entry_summary,
)
from . import templates

PROTOCOL_VERSION = 2
MAX_REQUEST_BYTES = 4 * 1024 * 1024
APPROVAL_TIMEOUT_SECONDS = 120
GUI_SEEN_SECONDS = 6
CHALLENGE_TTL_SECONDS = 180
AGENT_ACTIONS = set(actions.ACTIONS)
POLL_OPS = {"status", "pending_approvals", "audit", "update_status"}
ALL_PROOFS = ("hello", "windows_password", "master_password")
APPROVAL_HOURS = (0, 8, 24)  # how long "don't ask again" lasts; 0: until the vault is locked
AUDIT_AAD = b"secretbroker/audit/v1"
SCAN_SESSION_SECONDS = 12 * 3600
CHECK_EVERY_SECONDS = 24 * 3600
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SLUG_RE = re.compile(r"[^a-z0-9]+")
PRESENCE_OPS = ("approve", "complete_draft", "resume_ai", "set_ai_permissions")  # what the app that unlocked may do with one click
# Everything the AI can ask for. "Pause the AI" refuses all of it without locking the vault.
AI_OPS = AGENT_ACTIONS | {"list_secrets", "release_env", "push_github_secret", "create_draft", "update_credential",
                          "request_access"}
# What the AI may do beyond using a credential, and how freely. The user sets each one in the app:
#   free    follows each credential's own approval      notify  the same, and the user gets a notice
#   ask     the user confirms every time                 off     refused
AI_LEVELS = ("free", "notify", "ask", "off")
AI_CAPABILITIES = {
    "create": ("free", "Preparar credenciales nuevas"),
    "edit_notes": ("free", "Cambiar el nombre y las notas"),
    "edit_config": ("ask", "Cambiar adónde puede ir una clave guardada (webs, programas, variables)"),
    "local_env": ("free", "Dar claves a tus programas locales (sb run)"),
    "github": ("free", "Subir claves a los secrets de GitHub"),
}
NOTICE_EVERY_SECONDS = 600  # at most one "the AI used X" notice per credential in this time


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
        self._presence = None  # (token, expiry): the app that unlocked may approve without a password
        self._last_activity = time.monotonic()
        self._gui_seen = 0.0
        self._failures = 0
        self._pending_audit = []
        self._scan_sessions = {}
        self._notices = collections.deque(maxlen=50)
        self._notice_id = 0
        self._noticed = {}
        self._server = None
        self.updates = update.Checker()

    # ------------------------------------------------------------------ server

    def start(self, port=0):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.public_dir.mkdir(parents=True, exist_ok=True)
        self._server = _Server(("127.0.0.1", port), _Handler)
        self._server.service = self
        threading.Thread(target=self._server.serve_forever, daemon=True, name="server").start()
        threading.Thread(target=self._auto_lock_loop, daemon=True, name="auto-lock").start()
        threading.Thread(target=self._check_loop, daemon=True, name="exposure-check").start()
        public_key = self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        info = {"port": self._server.server_address[1], "token": self.token, "pid": os.getpid(),
                "public_key": crypto.b64(public_key), "isolated": self.isolated, "protocol": PROTOCOL_VERSION}
        tmp = paths.broker_file(self.root).with_suffix(".tmp")
        tmp.write_text(json.dumps(info))
        os.replace(tmp, paths.broker_file(self.root))
        return self._server.server_address[1]

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        self._lock_vault()

    def sign(self, nonce, body):
        return crypto.b64(self.signing_key.sign(nonce + body))

    # ------------------------------------------------------------------ dispatch

    def handle(self, op, params):
        if op not in POLL_OPS:
            self._last_activity = time.monotonic()
        try:
            if op in AI_OPS and self.pause_file.exists():
                raise ServiceError("El usuario ha pausado el acceso de la IA en SecretBroker. "
                                   "No reintentes: espera a que lo reanude.", "paused")
            if op in AGENT_ACTIONS:
                return {"ok": True, "result": self._run_action(op, params)}
            handler = getattr(self, "op_" + str(op), None)
            if handler is None:
                raise ServiceError(f"Operación desconocida: {op}", "unknown_op")
            return {"ok": True, "result": handler(params)}
        except ServiceError as exc:
            return {"ok": False, "code": exc.code, "error": str(exc)}
        except VaultLocked:
            return {"ok": False, "code": "locked",
                    "error": "La bóveda de SecretBroker está bloqueada. El usuario debe desbloquearla en la app SecretBroker."}
        except (ValidationError, ActionError) as exc:
            return {"ok": False, "code": "invalid", "error": str(exc)}
        except KeyError as exc:
            return {"ok": False, "code": "not_found", "error": f"No existe: {exc.args[0] if exc.args else ''}"}

    # ------------------------------------------------------------------ proofs

    def _hello_public_key(self):
        try:
            return crypto.unb64(json.loads(self.hello_file.read_text())["public_key"])
        except (OSError, ValueError, KeyError):
            return None

    def _throttle(self):
        if self._failures >= 3:
            time.sleep(min(60, 2 ** (self._failures - 3)))

    def _verify_proof(self, op, params, allowed=ALL_PROOFS):
        proof = params.get("proof") or {}
        kind = proof.get("kind")
        if kind == "presence" and op in PRESENCE_OPS:
            with self._lock:
                presence = self._presence
            if presence and presence[1] > time.monotonic() and hmac.compare_digest(
                    str(proof.get("token", "")).encode(), presence[0].encode()):
                return kind
            raise ServiceError("La verificación ha caducado; inténtalo de nuevo", "proof_invalid")
        if kind not in allowed:
            raise ServiceError("Esta operación requiere verificar tu identidad", "proof_required")
        if kind == "hello":
            public_key = self._hello_public_key()
            if not public_key:
                raise ServiceError("Windows Hello no está configurado en SecretBroker", "proof_invalid")
            with self._lock:
                challenge = self._challenges.pop(str(proof.get("nonce")), None)
            if not challenge or challenge["expires"] < time.monotonic():
                raise ServiceError("La verificación ha caducado; inténtalo de nuevo", "proof_invalid")
            if not hmac.compare_digest(challenge["digest"], op_digest(op, params)):
                raise ServiceError("La verificación no corresponde a esta operación", "proof_invalid")
            try:
                signature = crypto.unb64(proof.get("signature", ""))
            except ValueError:
                signature = b""
            if not winsec.verify_hello_signature(public_key, challenge["message"], signature):
                raise ServiceError("Firma de Windows Hello no válida", "proof_invalid")
            return kind

        self._throttle()
        value = proof.get("value") or ""
        if kind == "windows_password":
            ok = winsec.verify_windows_password(self.owner, value)
            message = "Contraseña de Windows incorrecta"
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
            "windows_password": winsec.IS_WINDOWS,
            "legacy_vault": state == "no_vault" and any(p.exists() for p in self.legacy_files),
            "auto_lock_minutes": settings.get("auto_lock_minutes"),
            "approval_hours": settings.get("approval_hours"),
            "session_grants": len(self._live_grants()),
            "gui_connected": time.monotonic() - self._gui_seen < GUI_SEEN_SECONDS,
            "pending": len(self._approvals),
            "session_unlock": self.session_file.exists(),
            "ai_paused": self.pause_file.exists(),
            "drafts": sum(1 for e in self.vault.entries() if e.get("draft")) if self.vault.is_unlocked else 0,
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
        return self.op_status({})

    def _read_legacy(self, password):
        for path in self.legacy_files:
            if path.exists():
                try:
                    payload = crypto.decrypt_legacy_v1(password, json.loads(path.read_bytes()))
                except WrongPassword:
                    raise ServiceError("La contraseña de la bóveda anterior no es correcta", "proof_invalid") from None
                return {e["id"]: convert_legacy_entry(e) for e in payload["entries"].values()}
        raise ServiceError("No se encontró la bóveda anterior", "not_found")

    def op_unlock(self, params):
        if self.vault.is_unlocked:
            return self.op_status({})
        proof = params.get("proof") or {}
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
                raise ServiceError("Contraseña maestra incorrecta", "proof_invalid") from None
            self._failures = 0
        else:
            kind = self._verify_proof("unlock", params, ("hello", "windows_password"))
            if not self.vault.device_unlock_available():
                raise ServiceError("Este PC aún no puede desbloquear la bóveda; usa la contraseña maestra", "invalid")
            self.vault.unlock_with_device()
            proof = {"kind": kind}
        self._last_activity = time.monotonic()
        self._seal_audit_log()
        self._audit("vault", "unlock", proof.get("kind", ""), "ok")
        # Whoever unlocked may look for copies of the secrets and approve the AI's requests without
        # proving it again (see op_exposure_begin and _verify_proof), until the vault is locked.
        return {**self.op_status({}), "exposure_session": self._new_scan_session(), "presence": self._new_presence()}

    def _check_session_token(self, token):
        """The app keeps this token protected with the user's Windows login (DPAPI): whoever is
        signed in to Windows as the user can open the vault without typing anything."""
        self._throttle()
        try:
            stored = json.loads(self.session_file.read_text())["hash"]
        except (OSError, ValueError, KeyError):
            raise ServiceError("El desbloqueo con la sesión de Windows no está activado", "proof_invalid") from None
        digest = hashlib.sha256(str(token or "").encode()).hexdigest()
        if not (self.vault.device_unlock_available() and hmac.compare_digest(digest, stored)):
            self._failures += 1
            raise ServiceError("La sesión de Windows no puede desbloquear la bóveda; usa la contraseña", "proof_invalid")
        self._failures = 0

    def op_enable_session_unlock(self, params):
        self._verify_proof("enable_session_unlock", params)
        if not self.vault.is_unlocked:
            raise VaultLocked()
        if not self.vault.device_unlock_available():
            raise ServiceError("Desbloquea una vez con la contraseña maestra en este equipo y vuelve a intentarlo", "invalid")
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
        return {"capabilities": [{"id": key, "label": label, "default": default, "level": self._ai_level(key)}
                                 for key, (default, label) in AI_CAPABILITIES.items()],
                "notify_uses": settings.get("notify_uses", True)}

    def op_set_ai_permissions(self, params):
        """Making the AI's permissions stricter needs nothing; loosening them needs the user (the app
        that unlocked, or a proof)."""
        changes = params.get("permissions") or {}
        if any(key not in AI_CAPABILITIES or level not in AI_LEVELS for key, level in changes.items()):
            raise ServiceError("Permiso no válido", "invalid")
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
        detail = ", ".join(f"{AI_CAPABILITIES[k][1]}: {v}" for k, v in changes.items())
        self._audit("vault", "ai_permissions", detail, "ok")
        return self.op_ai_permissions({})

    def _gate(self, capability, entry, action, detail):
        """Apply the user's choice for one of the AI's capabilities. Returns True if the user was
        asked (and agreed), so the caller can skip the credential's own approval."""
        level = self._ai_level(capability)
        if level == "off":
            raise ServiceError(f"El usuario no permite a la IA: {AI_CAPABILITIES[capability][1].lower()}. "
                               "Pídele que lo haga en la app SecretBroker o que cambie el permiso en «Acceso de la IA».",
                               "forbidden")
        if level == "ask":
            self._ask_user(entry, action, detail, allow_session=False)
            return True
        if level == "notify":
            self._notify("La IA " + {"create": "ha preparado", "edit_notes": "ha editado", "edit_config": "ha cambiado",
                                     "local_env": "ha dado a un programa", "github": "ha subido a GitHub"}[capability]
                         + f" {entry.get('name', entry.get('id'))}", detail.splitlines()[0] if detail else "")
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

    def _new_presence(self):
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._presence = (token, time.monotonic() + 24 * 3600)
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
        self._lock_vault(forget_approvals=not windows)
        self._audit("vault", "lock", "Windows bloqueado" if windows else "manual", "ok")
        return self.op_status({})

    def _lock_vault(self, forget_approvals=False):
        """Locking by hand forgets every approval; locking after inactivity keeps the timed ones,
        so the user is not asked again for each credential after unlocking."""
        with self._lock:
            for request in self._approvals.values():
                request["answer"] = "deny"
                request["event"].set()
            self._grants = {} if forget_approvals else {k: v for k, v in self._grants.items() if v is not None}
            self._presence = None
            self._scan_sessions.clear()
        self.vault.lock()

    def _auto_lock_loop(self):
        while True:
            time.sleep(10)
            if not self.vault.is_unlocked or self._approvals or self.session_file.exists():
                continue  # with the Windows session unlock, the vault locks when Windows does
            minutes = self.vault.settings().get("auto_lock_minutes") if self.vault.is_unlocked else None
            if minutes and time.monotonic() - self._last_activity > minutes * 60:
                self._lock_vault()
                self._audit("vault", "lock", f"inactividad ({minutes} min)", "ok")

    # ------------------------------------------------------------------ management (GUI)

    def _summary(self, entry, destinations=None):
        destinations = self.vault.destinations() if destinations is None else destinations
        return {**entry_summary(entry), "rotation": rotation.info(entry), "provider": links.for_entry(entry),
                "destinations": destinations.get("entries", {}).get(entry["id"], [])}

    def op_entries(self, params):
        destinations = self.vault.destinations()
        return [self._summary(e, destinations) for e in self.vault.entries()]

    def op_save_entry(self, params):
        self._verify_proof("save_entry", params)
        entry = dict(params.get("entry") or {})
        replaces = params.get("replaces")
        fields = {k: v for k, v in (entry.get("fields") or {}).items()}
        if replaces:
            # Secret fields sent as null mean "keep the stored value".
            old = self.vault.get(replaces)
            for name in templates.secret_field_names(entry.get("template", "")):
                if name in fields and fields[name] is None and old["fields"].get(name):
                    fields[name] = old["fields"][name]
        entry["fields"] = {k: v for k, v in fields.items() if v not in (None, "")}
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
        with self._lock:
            self._forget_grants(entry["id"], replaces)
        self._audit(entry["id"], "save", "creada" if not replaces else "modificada", "ok")
        return self._summary(self.vault.get(entry["id"]))

    def op_delete_entry(self, params):
        self._verify_proof("delete_entry", params)
        self.vault.delete(params["id"])
        self._update_exposure(lambda data: data.get("entries", {}).pop(params["id"], None))
        self._update_destinations(lambda data: data.get("entries", {}).pop(params["id"], None))
        with self._lock:
            self._forget_grants(params["id"])
        self._audit(params["id"], "delete", "", "ok")
        return True

    def op_reveal(self, params):
        self._verify_proof("reveal", params)
        entry = self.vault.get(params["id"])
        field = params.get("field")
        if field not in templates.secret_field_names(entry["template"]) or not entry["fields"].get(field):
            raise ServiceError("Ese campo no existe", "not_found")
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
        entry = self.vault.get(params["id"])
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
        uploads = []
        for destination in self.vault.destinations().get("entries", {}).get(entry["id"], []):
            uploads.append(self._push_again(entry, destination))
        return {"entry": self._summary(self.vault.get(entry["id"])), "check": alive, "uploads": uploads}

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
            raise ServiceError("Tiempo de bloqueo no válido", "invalid")
        if "approval_hours" in changes and changes["approval_hours"] not in APPROVAL_HOURS:
            raise ServiceError("Duración de las aprobaciones no válida", "invalid")
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
        self._audit(secret_id or "vault", "revoke", "aprobación retirada", "ok")
        return True

    def op_audit(self, params):
        limit = min(int(params.get("limit") or 200), 1000)
        private_key = self.vault.audit_private_key()
        try:
            with self.audit_file.open(encoding="utf-8") as log:
                lines = collections.deque((line for line in log if line.strip()), maxlen=limit)
        except OSError:
            return []
        events = []
        for line in reversed(lines):
            try:
                events.append(self._open_audit_line(private_key, line))
            except Exception:
                events.append({"ts": "", "secret": "", "action": "audit", "detail": "",
                               "status": "error", "message": "Entrada del historial ilegible"})
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
            raise ServiceError("La sesión de análisis ha caducado", "session_expired")
        found = 0
        for item in params.get("items") or []:
            location, source = str(item.get("location", "")), str(item.get("source", ""))
            if not location or source not in exposure.SOURCE_LABELS:
                raise ServiceError("Elemento de análisis no válido", "invalid")
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
            raise ServiceError("La sesión de análisis ha caducado", "session_expired")
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
            self._audit(entry_id, "exposure", f"Encontrada en claro en {count} sitio(s) nuevo(s)", "error")
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

    def op_exposure_check(self, params):
        """Test the keys with their providers and the passwords against known breaches."""
        entries = [e for e in self.vault.entries()
                   if exposure.check_alive_possible(e) and (not params.get("id") or e["id"] == params["id"])]
        timestamp = exposure.now_iso()
        stored = self.vault.exposure()
        records = {e["id"]: exposure.record_for(stored, e["id"], exposure.secret_fingerprint(self.vault, e)) for e in entries}

        def run(entry):
            alive = exposure.check_entry(entry, records[entry["id"]], timestamp)
            if alive:
                self._audit(entry["id"], "check", alive["provider"], "ok" if alive["status"] == "ok" else "error",
                            alive.get("message", ""))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run, entries))

        def store(data):
            for entry_id, checked in records.items():
                record = exposure.record_for(data, entry_id, checked["fp"])
                record.update({k: checked[k] for k in ("alive", "pwned") if k in checked})
            if not params.get("id"):
                data["last_check"] = timestamp
        self._update_exposure(store)
        return self.op_exposure_report(params)

    def _update_exposure(self, change):
        with self._lock:
            data = self.vault.exposure()
            change(data)
            self.vault.set_exposure(data)

    def _check_loop(self):
        """Check the keys once a day while the vault is unlocked."""
        while True:
            time.sleep(600)
            try:
                if not self.vault.is_unlocked:
                    continue
                last = self.vault.exposure().get("last_check")
                if last and (datetime.fromisoformat(exposure.now_iso()) - datetime.fromisoformat(last)).total_seconds() < CHECK_EVERY_SECONDS:
                    continue
                self.op_exposure_check({})
            except (VaultLocked, OSError, ValueError) as exc:  # e.g. locked halfway: try again later
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
            raise ServiceError("No hay ninguna versión nueva", "not_found")
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

    def op_approve(self, params):
        kind = self._verify_proof("approve", params)
        with self._lock:
            request = self._approvals.get(params.get("id"))
            if not request:
                raise ServiceError("La solicitud ya no está pendiente", "not_found")
            scope = params.get("scope")
            if scope not in ("once", "session") or (scope == "session" and not request["allow_session"]) \
                    or (scope == "once" and not request.get("allow_once", True)):
                raise ServiceError("Tipo de aprobación no válido", "invalid")
            request["answer"] = scope
            request["event"].set()
        # After proving it with a password or Hello, the next approvals are a single click.
        return {"presence": self._new_presence()} if kind != "presence" else True

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
            raise ServiceError(f"No existe el secreto '{secret_id}'. Usa list_secrets para ver los disponibles.", "not_found") from None
        if entry.get("draft"):
            raise ServiceError(f"'{secret_id}' aún no tiene la clave. Pide al usuario que la pegue en la app SecretBroker.", "draft")
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
                raise ServiceError(f"El valor de «{name}» solo lo puede escribir el usuario en la app", "invalid")
            if name not in known:
                raise ServiceError(f"La plantilla '{template}' no tiene el campo '{name}'. Campos: "
                                   + ", ".join(sorted(known - set(secret_names))), "invalid")
            if value in (None, ""):
                entry["fields"].pop(name, None)
            else:
                entry["fields"][name] = str(value)
        for key in ("name", "description"):
            if params.get(key) is not None:
                entry[key] = str(params[key]).strip()
        policy = entry.setdefault("policy", {})
        if params.get("allowed_hosts") is not None:
            policy.setdefault("http", {"auth": {"kind": "none"}})["allowed_hosts"] = \
                [str(h).strip().lower() for h in params["allowed_hosts"] if str(h).strip()]
        if params.get("commands") is not None:
            policy.setdefault("commands", {"allowed": [], "env": {}})["allowed"] = [str(c).strip() for c in params["commands"]]
        if params.get("env_vars") is not None:
            policy.setdefault("commands", {"allowed": [], "env": {}})["env"] = {str(k): str(v) for k, v in params["env_vars"].items()}
        return entry

    def op_create_draft(self, params):
        """A credential prepared by the AI with everything but its secret, which the user pastes in the app."""
        template = params.get("template")
        if template not in templates.TEMPLATES:
            raise ServiceError(f"Plantilla desconocida: {template}. Usa una de: {', '.join(templates.TEMPLATES)}", "invalid")
        name = str(params.get("name") or "").strip()
        entry_id = params.get("id") or SLUG_RE.sub("-", name.lower()).strip("-")[:64]
        if entry_id in {e["id"] for e in self.vault.entries()}:
            raise ServiceError(f"Ya existe una credencial '{entry_id}': usa update_credential para cambiarla", "invalid")
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
        return {"credential": agent_view(self.vault.get(entry_id)),
                "next": "El usuario debe pegar la clave en la app SecretBroker; hasta entonces no se puede usar."}

    def op_update_credential(self, params):
        """Change a credential's context or configuration. Name and notes change at once; anything that
        decides where its secret can go needs the user's OK in the app once it has a secret."""
        try:
            entry = self.vault.get(params.get("secret_id"))
        except KeyError:
            raise ServiceError(f"No existe el secreto '{params.get('secret_id')}'", "not_found") from None
        updated = self._ai_changes(entry, params)
        changes = _describe_changes(entry, updated)
        if not changes:
            return {"credential": agent_view(entry), "changed": []}
        risky = [line for key, line in changes if key not in ("name", "description")]
        detail = "\n".join(line for _, line in changes)
        capability = "create" if entry.get("draft") else "edit_config" if risky else "edit_notes"
        try:
            self._gate(capability, entry, "edit", detail)
        except ServiceError as exc:
            self._audit(entry["id"], "edit", detail, "denied" if exc.code == "denied" else "error", str(exc))
            raise
        if capability == "edit_config":
            self._forget_grants(entry["id"])  # the user approved it going to the old places only
        self.vault.put(updated, replaces=entry["id"])
        self._audit(entry["id"], "edit", detail, "ok")
        return {"credential": agent_view(self.vault.get(entry["id"])), "changed": [line for _, line in changes]}

    def op_complete_draft(self, params):
        """The user pastes the secret of a credential the AI prepared."""
        self._verify_proof("complete_draft", params, ALL_PROOFS)
        entry = self.vault.get(params["id"])
        if not entry.get("draft"):
            raise ServiceError("Esta credencial ya tiene su clave", "invalid")
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
                raise ServiceError("Petición mal formada", "invalid")
            if item.get("name") and not ENV_NAME_RE.match(str(item["name"])):
                raise ServiceError(f"Nombre de variable no válido: {item['name']}", "invalid")
            if item.get("field") and not ENV_NAME_RE.match(str(item["field"])):
                raise ServiceError(f"Nombre de dato no válido: {item['field']}", "invalid")
            grouped.setdefault(item.get("secret_id"), []).append(item)
        if not grouped:
            raise ServiceError("No se ha pedido ninguna variable", "invalid")

        entries = []
        for secret_id, items in grouped.items():
            entry = self._get_secret(secret_id)
            mapping = (entry["policy"].get("commands") or {}).get("env") or {}
            if not mapping:
                raise ServiceError(f"'{entry['id']}' no tiene variables de entorno en sus permisos, así que no se puede "
                                   "entregar a programas locales. Añádelas en la app SecretBroker.", "invalid")
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
        if mode == "never":
            if self.vault.settings().get("notify_uses", True):
                self._notify(f"La IA ha usado {entry.get('name', entry['id'])}", detail.splitlines()[0] if detail else "",
                             key=entry["id"])
            return
        if mode == "session" and entry["id"] in self._live_grants():
            return
        self._ask_user(entry, action, detail, allow_session=mode == "session")

    def op_request_access(self, params):
        """The AI asks at the start of a task for every credential it will need: one approval for all."""
        ids = params.get("secret_ids")
        if not isinstance(ids, list) or not ids or len(ids) > 20:
            raise ServiceError("Indica entre 1 y 20 credenciales en secret_ids", "invalid")
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

    def _ask_user(self, entry, action, detail, allow_session, grant_ids=None, allow_once=True):
        """Show the request in the app and wait for the user's answer."""
        if time.monotonic() - self._gui_seen > GUI_SEEN_SECONDS:
            raise ServiceError("Esta acción necesita la aprobación del usuario y la app SecretBroker no está abierta.",
                               "gui_required")
        request = {
            "id": uuid.uuid4().hex, "secret_id": entry["id"], "secret_name": entry.get("name", entry["id"]),
            "template": entry["template"], "action": action, "detail": detail,
            "allow_session": allow_session, "allow_once": allow_once, "secret_ids": grant_ids or [entry["id"]],
            "created": datetime.now().isoformat(timespec="seconds"),
            "event": threading.Event(), "answer": None,
        }
        with self._lock:
            self._approvals[request["id"]] = request
        try:
            request["event"].wait(APPROVAL_TIMEOUT_SECONDS)
        finally:
            with self._lock:
                self._approvals.pop(request["id"], None)
        if request["answer"] == "session":
            seconds = self._approval_seconds()
            with self._lock:
                for secret_id in grant_ids or [entry["id"]]:
                    self._grants[secret_id] = time.monotonic() + seconds if seconds else None
        elif request["answer"] != "once":
            reason = "El usuario ha denegado el uso de esta credencial" if request["answer"] == "deny" \
                else "Nadie aprobó la solicitud a tiempo"
            raise ServiceError(reason, "denied")

    # ------------------------------------------------------------------ audit

    def _audit(self, secret_id, action, detail, status, message=""):
        event = {"ts": datetime.now().isoformat(timespec="seconds"), "secret": secret_id, "action": action,
                 "detail": detail.splitlines()[0][:300] if detail else "", "status": status}
        if message:
            event["message"] = message[:300]
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


CHANGE_LABELS = {"name": "Nombre", "description": "Notas para la IA"}


def _describe_changes(old, new):
    """[(key, human-readable line)] of what differs between two versions of an entry (no secrets)."""
    changes = []
    for key in ("name", "description"):
        if old.get(key, "") != new.get(key, ""):
            changes.append((key, f"{CHANGE_LABELS[key]}: «{new.get(key, '')[:200]}»"))
    labels = {s["name"]: s["label"] for s in templates.field_specs(old["template"])}
    for name in sorted(set(old["fields"]) | set(new["fields"])):
        if name in templates.SECRET_FIELDS or old["fields"].get(name) == new["fields"].get(name):
            continue
        changes.append((name, f"{labels.get(name, name)}: {old['fields'].get(name) or '—'} → {new['fields'].get(name) or '—'}"))
    old_policy, new_policy = old.get("policy") or {}, new.get("policy") or {}
    hosts = lambda p: (p.get("http") or {}).get("allowed_hosts") or []
    if hosts(old_policy) != hosts(new_policy):
        changes.append(("hosts", f"Webs permitidas: {', '.join(hosts(new_policy)) or '—'}"))
    commands = lambda p: p.get("commands") or {}
    if commands(old_policy).get("allowed", []) != commands(new_policy).get("allowed", []):
        changes.append(("commands", f"Programas: {', '.join(commands(new_policy).get('allowed', [])) or '—'}"))
    if commands(old_policy).get("env", {}) != commands(new_policy).get("env", {}):
        env = commands(new_policy).get("env", {})
        changes.append(("env", "Variables: " + (", ".join(f"{k}={v}" for k, v in env.items()) or "—")))
    return changes


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
                response = {"ok": False, "code": "auth", "error": "Token del servicio no válido"}
            else:
                response = service.handle(request.get("op"), request.get("params") or {})
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            response = {"ok": False, "code": "bad_request", "error": "Petición mal formada"}
        body = json.dumps(response, ensure_ascii=False)
        envelope = {"body": body, "sig": service.sign(nonce, body.encode("utf-8"))}
        self.wfile.write(json.dumps(envelope).encode("utf-8") + b"\n")


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description="SecretBroker service")
    parser.add_argument("--root", help="Carpeta de datos (por defecto según el modo)")
    parser.add_argument("--owner", help="Usuario de Windows propietario (DOMINIO\\usuario)")
    parser.add_argument("--isolated", action="store_true", help="Modo instalado con cuenta de servicio dedicada")
    args = parser.parse_args()
    owner = args.owner or f"{os.environ.get('USERDOMAIN', '.')}\\{os.environ.get('USERNAME', '')}"
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
