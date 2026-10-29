"""Encrypted vault. Entries only exist in memory while the vault is unlocked.

The vault payload is encrypted with a random data key. That key is stored twice:
  - wrapped with scrypt(master password) inside vault.json  -> portable, works on any PC
  - protected with DPAPI in device_key.bin                  -> unlock with Windows (Hello / password)

The audit log is encrypted to a key pair derived from the data key. Its public half is stored in
clear in vault.json, so events can be written while the vault is locked but only read unlocked.
"""

import copy
import hashlib
import hmac
import json
import os
import re
import threading
from datetime import datetime, timezone

from . import crypto, templates, winsec
from .crypto import WrongPassword  # noqa: F401  (re-exported for callers)
from .templates import PLACEHOLDER_RE

FORMAT_VERSION = 2
VAULT_AAD = b"secretbroker/vault/v2"
DEVICE_ENTROPY = b"secretbroker/device-key/v1"
AUDIT_KEY_INFO = b"secretbroker/audit-key/v1"
MAC_KEY_INFO = b"secretbroker/mac-key/v1"
APPROVAL_MODES = ("session", "always", "never")
AUTH_KINDS = ("none", "header", "query", "basic")
DEFAULT_SETTINGS = {"auto_lock_minutes": 60, "approval_hours": 24}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MIN_PASSWORD_LEN = 12


class VaultLocked(Exception):
    pass


class ValidationError(Exception):
    pass


def check_master_password(password):
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ValidationError(f"La contraseña maestra debe tener al menos {MIN_PASSWORD_LEN} caracteres")


def _check_template_string(template, available, where):
    for name in PLACEHOLDER_RE.findall(template):
        if name not in available:
            raise ValidationError(f"{where}: el dato {{{{{name}}}}} no existe en esta credencial")


def validate_entry(entry):
    if not ID_RE.match(entry.get("id", "")):
        raise ValidationError("El identificador solo admite minúsculas, números, '-', '_' y '.' (máx. 64)")
    if not entry.get("name", "").strip():
        raise ValidationError("Ponle un nombre a la credencial")
    template_id = entry.get("template")
    if template_id not in templates.TEMPLATES:
        raise ValidationError(f"Plantilla desconocida: {template_id}")
    fields = entry.get("fields", {})
    for spec in templates.active_specs(template_id, fields):
        if spec["required"] and not fields.get(spec["name"]):
            raise ValidationError(f"Falta el campo «{spec['label']}»")
        if spec["kind"] == "number" and fields.get(spec["name"]):
            value = str(fields[spec["name"]])
            if not value.isdigit() or not 0 < int(value) < 65536:
                raise ValidationError(f"«{spec['label']}» debe ser un número de puerto válido")

    available = templates.placeholder_values(entry)
    policy = entry.get("policy", {})
    if policy.get("approval", "session") not in APPROVAL_MODES:
        raise ValidationError("Modo de aprobación no válido")

    http = policy.get("http") or {}
    auth = http.get("auth") or {}
    kind = auth.get("kind", "none")
    if kind not in AUTH_KINDS:
        raise ValidationError("Tipo de autenticación HTTP no válido")
    if kind in ("header", "query"):
        if not auth.get("name"):
            raise ValidationError("Indica el nombre de la cabecera o parámetro de autenticación")
        _check_template_string(auth.get("template") or "{{value}}", available, "Autenticación HTTP")
    if kind == "basic" and not (fields.get("username") and fields.get("password")):
        raise ValidationError("HTTP Basic necesita usuario y contraseña")
    for host in http.get("allowed_hosts", []):
        if not re.match(r"^(\*\.)?[a-z0-9.-]+$|^\[?[0-9a-f:.]+\]?$", host):
            raise ValidationError(f"Dominio no válido: {host}")

    commands = policy.get("commands") or {}
    for name, template in (commands.get("env") or {}).items():
        if not ENV_NAME_RE.match(name):
            raise ValidationError(f"Nombre de variable de entorno no válido: {name}")
        _check_template_string(template, available, f"Variable {name}")
    for command in commands.get("allowed", []):
        if not re.match(r"^[A-Za-z0-9_.+-]+$", command):
            raise ValidationError(f"Nombre de comando no válido (sin rutas): {command}")


def entry_summary(entry):
    """Everything about an entry except secret values (for the GUI)."""
    secret_names = set(templates.secret_field_names(entry["template"]))
    return {
        "id": entry["id"],
        "name": entry.get("name") or entry["id"],
        "template": entry["template"],
        "description": entry.get("description", ""),
        "fields": {k: v for k, v in entry["fields"].items() if k not in secret_names},
        "secrets_set": [k for k in entry["fields"] if k in secret_names and entry["fields"][k]],
        "policy": entry.get("policy", {}),
        "updated": entry.get("updated"),
        "secret_since": entry.get("secret_since"),
    }


def agent_view(entry):
    """What the AI agent may know about an entry: context and permissions, never secret values."""
    summary = entry_summary(entry)
    policy = summary["policy"]
    view = {
        "id": entry["id"],
        "name": summary["name"],
        "kind": templates.TEMPLATES[entry["template"]]["label"],
        "description": summary["description"],
        **{k: v for k, v in summary["fields"].items()
           if k not in ("auth_method", "auth_style", "env_var") and v},
        "placeholders": ["{{%s}}" % name for name in templates.placeholder_values(entry)],
        "actions": templates.available_actions(entry),
        "approval": policy.get("approval", "session"),
    }
    http = policy.get("http") or {}
    if http.get("allowed_hosts"):
        view["http"] = {"allowed_hosts": http["allowed_hosts"], "auto_auth": (http.get("auth") or {}).get("kind", "none")}
    commands = policy.get("commands") or {}
    if commands.get("allowed"):
        view["commands"] = {"allowed": commands["allowed"], "env_vars": sorted((commands.get("env") or {}).keys())}
    return view


def convert_legacy_entry(old):
    """Version 1 entries (api_key / login / ssh) to version 2 templates."""
    fields = dict(old.get("fields", {}))
    template = {"api_key": "api_key", "login": "web_login", "ssh": "ssh"}[old["type"]]
    if template == "ssh":
        fields["auth_method"] = "key" if fields.get("private_key") else "password"
    if template == "api_key":
        auth = ((old.get("policy") or {}).get("http") or {}).get("auth") or {}
        fields["auth_style"] = "bearer" if auth.get("template") == "Bearer {{value}}" else "none"
    return {"id": old["id"], "name": old["id"], "template": template, "description": old.get("description", ""),
            "fields": fields, "policy": old.get("policy", {}), "updated": old.get("updated")}


class Vault:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.file = data_dir / "vault.json"
        self.device_file = data_dir / "device_key.bin"
        self._lock = threading.RLock()
        self._key = None
        self._payload = None
        self._master_wrap = None
        self._audit_public = None

    def exists(self):
        return self.file.exists()

    @property
    def is_unlocked(self):
        return self._payload is not None

    def device_unlock_available(self):
        return self.device_file.exists()

    # ----- lifecycle

    def create(self, master_password, entries=None):
        if self.exists():
            raise ValidationError("Ya existe una bóveda")
        check_master_password(master_password)
        with self._lock:
            self._key = os.urandom(32)
            self._master_wrap = crypto.wrap_with_password(master_password, self._key)
            self._payload = {"entries": entries or {}, "settings": dict(DEFAULT_SETTINGS)}
            self._save()
            self._store_device_key()

    def unlock_with_master(self, master_password):
        doc = self._load_doc()
        key = crypto.unwrap_with_password(master_password, doc["master"])
        self._open(doc, key)
        if not self._device_key_matches(key):
            # Missing, or written by a previous service account (e.g. after reinstalling).
            self._store_device_key()

    def unlock_with_device(self):
        doc = self._load_doc()
        try:
            key = winsec.dpapi_unprotect(self.device_file.read_bytes(), DEVICE_ENTROPY)
        except OSError:
            raise ValidationError("No se pudo usar la clave de este PC. Desbloquea con la contraseña maestra.") from None
        self._open(doc, key)

    def verify_master(self, master_password):
        try:
            crypto.unwrap_with_password(master_password, self._load_doc()["master"])
            return True
        except WrongPassword:
            return False

    def change_master(self, new_password):
        check_master_password(new_password)
        with self._lock:
            self._require_unlocked()
            self._master_wrap = crypto.wrap_with_password(new_password, self._key)
            self._save()

    def lock(self):
        # Python cannot reliably zero memory; dropping references is the best available.
        with self._lock:
            self._key = self._payload = self._master_wrap = None

    # ----- audit key

    def audit_public_key(self):
        """Raw X25519 public key to encrypt audit events, or None if the vault predates it and was not unlocked yet."""
        with self._lock:
            if self._audit_public is None and self.exists():
                try:
                    stored = self._load_doc().get("audit_public_key")
                except (OSError, ValueError, ValidationError):
                    stored = None
                self._audit_public = crypto.unb64(stored) if stored else None
            return self._audit_public

    def audit_private_key(self):
        with self._lock:
            self._require_unlocked()
            return crypto.derive_x25519(self._key, AUDIT_KEY_INFO)

    def mac(self, data):
        """Keyed fingerprint of some data: stable for this vault, meaningless without its key."""
        with self._lock:
            self._require_unlocked()
            key = hmac.new(self._key, MAC_KEY_INFO, hashlib.sha256).digest()
        return hmac.new(key, data, hashlib.sha256).hexdigest()[:32]

    # ----- exposure (see exposure.py)

    def exposure(self):
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("exposure") or {})

    def set_exposure(self, data):
        with self._lock:
            self._require_unlocked()
            self._payload["exposure"] = copy.deepcopy(data)
            self._save()

    # ----- destinations: where each secret was uploaded, to upload it again after a rotation

    def destinations(self):
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("destinations") or {})

    def set_destinations(self, data):
        with self._lock:
            self._require_unlocked()
            self._payload["destinations"] = copy.deepcopy(data)
            self._save()

    # ----- settings

    def settings(self):
        with self._lock:
            self._require_unlocked()
            return {**DEFAULT_SETTINGS, **self._payload.get("settings", {})}

    def update_settings(self, changes):
        with self._lock:
            self._require_unlocked()
            self._payload["settings"] = {**self.settings(), **changes}
            self._save()

    # ----- entries

    def entries(self):
        with self._lock:
            self._require_unlocked()
            entries = self._payload["entries"]
            return [copy.deepcopy(entries[k]) for k in sorted(entries, key=lambda k: entries[k].get("name", k).lower())]

    def get(self, entry_id):
        with self._lock:
            self._require_unlocked()
            if entry_id not in self._payload["entries"]:
                raise KeyError(entry_id)
            return copy.deepcopy(self._payload["entries"][entry_id])

    def put(self, entry, replaces=None):
        validate_entry(entry)
        with self._lock:
            self._require_unlocked()
            entries = self._payload["entries"]
            if entry["id"] != replaces and entry["id"] in entries:
                raise ValidationError(f"Ya existe una credencial con el identificador '{entry['id']}'")
            old = entries.pop(replaces, None) if replaces else None
            entry = copy.deepcopy(entry)
            entry["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            entry.pop("secret_since", None)
            if old is None or secret_fields(old) != secret_fields(entry):
                entry["secret_since"] = entry["updated"]
            elif old.get("secret_since"):
                entry["secret_since"] = old["secret_since"]  # unknown for entries saved before 0.5
            entries[entry["id"]] = entry
            self._save()

    def delete(self, entry_id):
        with self._lock:
            self._require_unlocked()
            self._payload["entries"].pop(entry_id, None)
            self._save()

    # ----- internals

    def _require_unlocked(self):
        if not self.is_unlocked:
            raise VaultLocked("La bóveda está bloqueada")

    def _load_doc(self):
        doc = json.loads(self.file.read_bytes())
        if doc.get("version") != FORMAT_VERSION:
            raise ValidationError(f"Versión de bóveda no soportada: {doc.get('version')}")
        return doc

    def _open(self, doc, key):
        try:
            payload = json.loads(crypto.open_sealed(key, doc, VAULT_AAD))
        except Exception:
            raise ValidationError("La bóveda está dañada o la clave no corresponde") from None
        with self._lock:
            self._key, self._payload, self._master_wrap = key, payload, doc["master"]
            # The stored public key is not authenticated: rewrite it if missing (vaults up to 0.3) or altered.
            expected = crypto.b64(crypto.x25519_public(crypto.derive_x25519(key, AUDIT_KEY_INFO)))
            if doc.get("audit_public_key") != expected:
                self._save()

    def _save(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._audit_public = crypto.x25519_public(crypto.derive_x25519(self._key, AUDIT_KEY_INFO))
        doc = {"version": FORMAT_VERSION, "master": self._master_wrap, "audit_public_key": crypto.b64(self._audit_public),
               **crypto.seal(self._key, json.dumps(self._payload).encode("utf-8"), VAULT_AAD)}
        _atomic_write(self.file, json.dumps(doc, indent=1).encode("utf-8"))

    def _device_key_matches(self, key):
        try:
            return winsec.dpapi_unprotect(self.device_file.read_bytes(), DEVICE_ENTROPY) == key
        except OSError:
            return False

    def _store_device_key(self):
        try:
            _atomic_write(self.device_file, winsec.dpapi_protect(self._key, DEVICE_ENTROPY))
        except OSError:
            pass  # unlock with Windows simply stays unavailable


def secret_fields(entry):
    """What identifies the secret values of an entry (a change means the secret was replaced)."""
    return entry["template"], {name: entry["fields"].get(name) for name in templates.secret_field_names(entry["template"])}


def _atomic_write(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
