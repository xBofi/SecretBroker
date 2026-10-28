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
import hashlib
import hmac
import json
import os
import secrets
import socketserver
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import actions, crypto, paths, winsec
from .inject import ActionError, Redactor
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
POLL_OPS = {"status", "pending_approvals", "audit"}
ALL_PROOFS = ("hello", "windows_password", "master_password")
AUDIT_AAD = b"secretbroker/audit/v1"


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
        self.audit_file = self.data_dir / "audit.log"
        self.legacy_files = [self.data_dir / "legacy_vault.json", self.root / "vault.json"]
        actions.configure(self.data_dir / "known_hosts")

        self.token = secrets.token_urlsafe(32)
        self.signing_key = Ed25519PrivateKey.generate()
        self._lock = threading.RLock()
        self._challenges = {}
        self._approvals = {}
        self._grants = set()
        self._last_activity = time.monotonic()
        self._gui_seen = 0.0
        self._failures = 0
        self._pending_audit = []
        self._server = None

    # ------------------------------------------------------------------ server

    def start(self, port=0):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.public_dir.mkdir(parents=True, exist_ok=True)
        self._server = _Server(("127.0.0.1", port), _Handler)
        self._server.service = self
        threading.Thread(target=self._server.serve_forever, daemon=True, name="server").start()
        threading.Thread(target=self._auto_lock_loop, daemon=True, name="auto-lock").start()
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
            "session_grants": len(self._grants),
            "gui_connected": time.monotonic() - self._gui_seen < GUI_SEEN_SECONDS,
            "pending": len(self._approvals),
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
        if proof.get("kind") == "master_password":
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
        return self.op_status({})

    def op_lock(self, params):
        self._lock_vault()
        self._audit("vault", "lock", "manual", "ok")
        return self.op_status({})

    def _lock_vault(self):
        with self._lock:
            for request in self._approvals.values():
                request["answer"] = "deny"
                request["event"].set()
            self._grants.clear()
        self.vault.lock()

    def _auto_lock_loop(self):
        while True:
            time.sleep(10)
            if not self.vault.is_unlocked or self._approvals:
                continue
            minutes = self.vault.settings().get("auto_lock_minutes") if self.vault.is_unlocked else None
            if minutes and time.monotonic() - self._last_activity > minutes * 60:
                self._lock_vault()
                self._audit("vault", "lock", f"inactividad ({minutes} min)", "ok")

    # ------------------------------------------------------------------ management (GUI)

    def op_entries(self, params):
        return [entry_summary(e) for e in self.vault.entries()]

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
        self.vault.put(entry, replaces=replaces)
        with self._lock:
            self._grants = {g for g in self._grants if g[0] not in (entry["id"], replaces)}
        self._audit(entry["id"], "save", "creada" if not replaces else "modificada", "ok")
        return entry_summary(self.vault.get(entry["id"]))

    def op_delete_entry(self, params):
        self._verify_proof("delete_entry", params)
        self.vault.delete(params["id"])
        with self._lock:
            self._grants = {g for g in self._grants if g[0] != params["id"]}
        self._audit(params["id"], "delete", "", "ok")
        return True

    def op_reveal(self, params):
        self._verify_proof("reveal", params)
        entry = self.vault.get(params["id"])
        field = params.get("field")
        if field not in templates.secret_field_names(entry["template"]) or not entry["fields"].get(field):
            raise ServiceError("Ese campo no existe", "not_found")
        self._audit(entry["id"], "reveal", field, "ok")
        return entry["fields"][field]

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
        with self._lock:
            self._grants.clear()
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

    # ------------------------------------------------------------------ approvals (GUI)

    def op_pending_approvals(self, params):
        self._gui_seen = time.monotonic()
        with self._lock:
            return [{k: v for k, v in r.items() if k not in ("event", "answer")} for r in self._approvals.values()]

    def op_approve(self, params):
        self._verify_proof("approve", params)
        with self._lock:
            request = self._approvals.get(params.get("id"))
            if not request:
                raise ServiceError("La solicitud ya no está pendiente", "not_found")
            scope = params.get("scope")
            if scope not in ("once", "session") or (scope == "session" and not request["allow_session"]):
                raise ServiceError("Tipo de aprobación no válido", "invalid")
            request["answer"] = scope
            request["event"].set()
        return True

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
        secret_id = params.get("secret_id")
        try:
            entry = self.vault.get(secret_id)
        except KeyError:
            raise ServiceError(f"No existe el secreto '{secret_id}'. Usa list_secrets para ver los disponibles.", "not_found") from None
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

    def _authorize(self, entry, action, detail):
        mode = entry.get("policy", {}).get("approval", "session")
        if mode == "never":
            return
        grant = (entry["id"], action)
        with self._lock:
            if mode == "session" and grant in self._grants:
                return
        if time.monotonic() - self._gui_seen > GUI_SEEN_SECONDS:
            raise ServiceError("Esta acción necesita la aprobación del usuario y la app SecretBroker no está abierta.",
                               "gui_required")
        request = {
            "id": uuid.uuid4().hex, "secret_id": entry["id"], "secret_name": entry.get("name", entry["id"]),
            "template": entry["template"], "action": action, "detail": detail,
            "allow_session": mode == "session", "created": datetime.now().isoformat(timespec="seconds"),
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
            with self._lock:
                self._grants.add(grant)
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
