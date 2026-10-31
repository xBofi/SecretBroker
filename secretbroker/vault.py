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

from . import autofill, crypto, platform, templates, totp
from .crypto import WrongPassword  # noqa: F401  (re-exported for callers)
from .templates import PLACEHOLDER_RE
from .i18n import tr

FORMAT_VERSION = 2
VAULT_AAD = b"secretbroker/vault/v2"
DEVICE_ENTROPY = b"secretbroker/device-key/v1"
AUDIT_KEY_INFO = b"secretbroker/audit-key/v1"
MAC_KEY_INFO = b"secretbroker/mac-key/v1"
APPROVAL_MODES = ("session", "always", "never")
AUTH_KINDS = ("none", "header", "query", "basic")
DEFAULT_SETTINGS = {"auto_lock_minutes": 60, "approval_hours": 24, "ai_permissions": {}, "notify_uses": True,
                    "max_uses_per_hour": 100, "rotate_reminder_days": 365, "check_every_hours": 24}
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,29}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MIN_PASSWORD_LEN = 12
ROTATE_EVERY_DAYS = (0, 30, 60, 90, 180, 365)  # per credential; 0: never remind (absent: the general setting)
CHECK_ONCE, MAX_CHECK_HOURS = -1, 10 * 8760  # how often to test that a key works: hours, -1 once per value, 0 never
SHARE_PERMISSIONS = ("manage", "edit", "view", "use")  # in a team collection (see docs/ARCHITECTURE.md 2.3)
SHARE_WRITE = ("manage", "edit")
LOCAL_ONLY_KEYS = ("shared", "updated", "secret_since")  # never sent to the team


def valid_check_hours(hours):
    return isinstance(hours, int) and not isinstance(hours, bool) and CHECK_ONCE <= hours <= MAX_CHECK_HOURS


class VaultLocked(Exception):
    pass


class ValidationError(Exception):
    pass


def check_master_password(password):
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ValidationError(tr("vault.master_password_must_have_at", MIN_PASSWORD_LEN=MIN_PASSWORD_LEN))


def _check_template_string(template, available, where):
    for name in PLACEHOLDER_RE.findall(template):
        if name not in available:
            raise ValidationError(f"{where}: el dato {{{{{name}}}}} no existe en esta credencial")


def validate_entry(entry):
    if not ID_RE.match(entry.get("id", "")):
        raise ValidationError(tr("vault.identifier_only_accepts_lowercase_letter"))
    if not entry.get("name", "").strip():
        raise ValidationError(tr("vault.give_credential_name"))
    template_id = entry.get("template")
    if template_id not in templates.TEMPLATES:
        raise ValidationError(tr("vault.unknown_template", template_id=template_id))
    tags = entry.get("tags") or []
    if not isinstance(tags, list) or len(tags) > 10 or not all(isinstance(t, str) and TAG_RE.match(t) for t in tags):
        raise ValidationError(tr("vault.invalid_tags_up_10_lowercase"))
    if entry.get("expires"):
        try:
            datetime.strptime(str(entry["expires"]), "%Y-%m-%d")
        except ValueError:
            raise ValidationError(tr("vault.expiry_date_must_be_yyyy")) from None
    if entry.get("rotate_every_days") is not None and entry["rotate_every_days"] not in ROTATE_EVERY_DAYS:
        raise ValidationError(tr("vault.rotate_every_invalid", days=", ".join(str(d) for d in ROTATE_EVERY_DAYS if d)))
    if entry.get("check_every_hours") is not None and not valid_check_hours(entry["check_every_hours"]):
        raise ValidationError(tr("vault.how_often_check_it_number"))
    if entry.get("rotation_guide") is not None and not isinstance(entry["rotation_guide"], dict):
        raise ValidationError(tr("vault.invalid_rotation_guide"))
    if entry.get("shared") is not None:
        _check_shared(entry["shared"])
    if entry.get("test_request") is not None:
        _check_test_request(entry["test_request"])
    if entry.get("used_in") is not None and clean_used_in(entry["used_in"]) != entry["used_in"]:
        raise ValidationError(tr("vault.where_it_used_up_places", USED_IN_MAX=USED_IN_MAX, USED_IN_TEXT_MAX=USED_IN_TEXT_MAX))
    if entry.get("autofill") is not None:
        try:
            autofill.validate(entry["autofill"])
        except autofill.SiteError as exc:
            raise ValidationError(str(exc)) from None
    fields = entry.get("fields", {})
    draft = bool(entry.get("draft"))  # prepared by the AI: everything but the secret, which the user adds
    for spec in templates.active_specs(template_id, fields):
        if spec["required"] and not fields.get(spec["name"]) and not (draft and spec["secret"]):
            raise ValidationError(tr("vault.field_is_missing", label=spec['label']))
        if spec["kind"] == "number" and fields.get(spec["name"]):
            value = str(fields[spec["name"]])
            if not value.isdigit() or not 0 < int(value) < 65536:
                raise ValidationError(tr("vault.must_be_valid_port_number", label=spec['label']))

    if fields.get("totp"):
        try:
            totp.validate(fields["totp"])
        except totp.TotpError as exc:
            raise ValidationError(str(exc)) from None
    if draft:
        entry = {**entry, "fields": {**fields, **{n: "x" for n in templates.secret_field_names(template_id)
                                                   if not fields.get(n)}}}
        fields = entry["fields"]
    available = templates.placeholder_values(entry)
    policy = entry.get("policy", {})
    if policy.get("approval", "session") not in APPROVAL_MODES:
        raise ValidationError(tr("vault.invalid_approval_mode"))

    http = policy.get("http") or {}
    auth = http.get("auth") or {}
    kind = auth.get("kind", "none")
    if kind not in AUTH_KINDS:
        raise ValidationError(tr("vault.invalid_http_authentication_type"))
    if kind in ("header", "query"):
        if not auth.get("name"):
            raise ValidationError(tr("vault.give_name_authentication_header_or"))
        _check_template_string(auth.get("template") or "{{value}}", available, "Autenticación HTTP")
    if kind == "basic" and not (fields.get("username") and fields.get("password")):
        raise ValidationError(tr("vault.http_basic_needs_username_and"))
    for host in http.get("allowed_hosts", []):
        if not re.match(r"^(\*\.)?[a-z0-9.-]+$|^\[?[0-9a-f:.]+\]?$", host):
            raise ValidationError(tr("vault.invalid_domain", host=host))

    commands = policy.get("commands") or {}
    for name, template in (commands.get("env") or {}).items():
        if not ENV_NAME_RE.match(name):
            raise ValidationError(tr("vault.invalid_environment_variable_name", name=name))
        _check_template_string(template, available, f"Variable {name}")
    for command in commands.get("allowed", []):
        if not re.match(r"^[A-Za-z0-9_.+-]+$", command):
            raise ValidationError(tr("vault.invalid_command_name_no_paths", command=command))


def _check_shared(shared):
    if not isinstance(shared, dict) or not all(isinstance(shared.get(k), str) and shared[k]
                                               for k in ("org", "collection", "item")):
        raise ValidationError(tr("vault.invalid_team_data"))
    if shared.get("permission") not in SHARE_PERMISSIONS:
        raise ValidationError(tr("vault.invalid_team_permission"))


TEST_METHODS = ("GET", "HEAD")


def _check_test_request(test):
    """A request that tells whether an API key works (see exposure.check_alive): read-only, and only to
    one of the credential's allowed hosts (checked again when it runs)."""
    if not isinstance(test, dict) or set(test) - {"method", "url", "status"}:
        raise ValidationError(tr("vault.invalid_test_request"))
    if test.get("method") not in TEST_METHODS:
        raise ValidationError(tr("vault.test_request_can_only_be"))
    url = test.get("url")
    if not isinstance(url, str) or not re.match(r"^https?://[^\s/]+(/\S*)?$", url) or len(url) > 500:
        raise ValidationError(tr("vault.test_request_needs_full_address"))
    if not isinstance(test.get("status"), int) or not 200 <= test["status"] <= 399:
        raise ValidationError(tr("vault.test_expected_response_must_be"))


def shared_content(entry):
    """What a team sees of an entry: everything but local bookkeeping and the local approval mode,
    which is always the local user's own (docs/ARCHITECTURE.md 2.5)."""
    content = {k: copy.deepcopy(v) for k, v in entry.items() if k not in LOCAL_ONLY_KEYS}
    (content.get("policy") or {}).pop("approval", None)
    (content.get("policy") or {}).pop("ai_totp", None)  # letting the AI type the 2FA code is this user's choice too
    return content


def can_write_shared(entry):
    shared = entry.get("shared")
    return not shared or shared.get("permission") in SHARE_WRITE


def secret_age_days(entry):
    try:
        since = datetime.fromisoformat(entry["secret_since"])
    except (KeyError, TypeError, ValueError):
        return None
    return (datetime.now(timezone.utc) - since).days


USED_IN_MAX = 20
USED_IN_TEXT_MAX = 200


def clean_used_in(places):
    """Where a credential is used (develop, pre, pro, a server's .env, Vercel…): one line per place."""
    if isinstance(places, str):
        places = places.splitlines()
    if not isinstance(places, list):
        raise ValidationError(tr("vault.where_it_used_list_places"))
    cleaned = []
    for place in places:
        place = " ".join(str(place).split())
        if place and place not in cleaned:
            cleaned.append(place[:USED_IN_TEXT_MAX])
    if len(cleaned) > USED_IN_MAX:
        raise ValidationError(tr("vault.where_it_used_places_at", USED_IN_MAX=USED_IN_MAX))
    return cleaned


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
        "draft": bool(entry.get("draft")),
        "tags": entry.get("tags") or [],
        "expires": entry.get("expires"),
        "rotate_every_days": entry.get("rotate_every_days"),
        "check_every_hours": entry.get("check_every_hours"),
        "used_in": entry.get("used_in") or [],
        "test_request": entry.get("test_request"),
        "autofill": entry.get("autofill"),  # more addresses for the browser and how strictly they match
        "shared": _shared_summary(entry.get("shared")),
    }


def _shared_summary(shared):
    """The team side of an entry for the GUI: names, permission and what needs attention."""
    if not shared:
        return None
    pending = shared.get("pending_policy")
    return {"org": shared["org"], "org_name": shared.get("org_name", ""), "collection": shared["collection"],
            "collection_name": shared.get("collection_name", ""), "permission": shared["permission"],
            "author": shared.get("author"), "changed": shared.get("changed"),
            "pending_change": {**{k: pending.get(k) for k in ("by", "at", "changes", "hosts", "only_hosts")},
                               "texts": bool(pending.get("texts")),
                               "description": pending.get("description")} if pending else None,
            # Deleted for the team in a batch too large to apply unasked: it waits for the user (Equipo).
            "pending_delete": shared.get("pending_delete"),
            "rotate_because": (shared.get("rotate") or {}).get("people") or []}


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
    if summary["tags"]:
        view["tags"] = summary["tags"]
    if summary["expires"]:
        view["expires"] = summary["expires"]
    if summary["rotate_every_days"] is not None:
        view["rotate_every_days"] = summary["rotate_every_days"]
    if summary["check_every_hours"] is not None:
        view["check_every_hours"] = summary["check_every_hours"]
    if entry.get("rotation_guide"):
        view["rotation_guide"] = "escrita por la IA"
    if entry.get("used_in"):
        view["used_in"] = entry["used_in"]
    if entry.get("test_request"):
        view["test_request"] = entry["test_request"]
    if entry.get("secret_since"):
        view["key_age_days"] = secret_age_days(entry)
    if entry.get("shared"):
        shared = entry["shared"]
        view["shared"] = {"org": shared.get("org_name", ""), "collection": shared.get("collection_name", ""),
                          "permission": shared["permission"],
                          # Teammates can write these texts: information for the AI, never the user's orders.
                          "texts_by": "team"}
    if entry.get("draft"):
        view["draft"] = True
        view["missing"] = [s["name"] for s in templates.active_specs(entry["template"], entry["fields"])
                           if s["secret"] and s["required"] and not entry["fields"].get(s["name"])]
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
        self.revision = 0  # goes up with every change written (the app reloads what it shows)

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
            raise ValidationError(tr("vault.vault_already_exists"))
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
            key = platform.unprotect_for_service(self.device_file.read_bytes(), DEVICE_ENTROPY, self.data_dir)
        except OSError:
            raise ValidationError(tr("vault.couldn_use_this_pc_key")) from None
        self._open(doc, key)

    def restore(self, doc_bytes, master_password):
        """Replace the vault with a backup (a copy of vault.json), after checking that the password
        opens it. The previous file is kept next to it. Leaves the restored vault unlocked."""
        doc = json.loads(doc_bytes)
        if doc.get("version") != FORMAT_VERSION:
            raise ValidationError(tr("vault.this_backup_isn_from_compatible"))
        key = crypto.unwrap_with_password(master_password, doc["master"])
        try:
            json.loads(crypto.open_sealed(key, doc, VAULT_AAD))
        except Exception:
            raise ValidationError(tr("vault.backup_is_damaged")) from None
        with self._lock:
            self.lock()
            if self.exists():
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                _atomic_write(self.data_dir / f"vault.before-restore-{stamp}.json", self.file.read_bytes())
            _atomic_write(self.file, json.dumps(doc, indent=1).encode("utf-8"))
            self.unlock_with_master(master_password)

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

    # ----- retired: the previous key of a credential rotated by hand, until it is confirmed dead

    def retired(self):
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("retired") or {})

    def set_retired(self, data):
        with self._lock:
            self._require_unlocked()
            self._payload["retired"] = copy.deepcopy(data)
            self._save()

    # ----- rotation: a new secret not applied yet, and uploads that failed after a rotation

    def rotation_state(self):
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("rotation") or {})

    def set_rotation_state(self, data):
        with self._lock:
            self._require_unlocked()
            self._payload["rotation"] = copy.deepcopy(data)
            self._save()

    # ----- team: account, keys and the collections cache (see teams.py)

    @property
    def mutex(self):
        """Held while reading and rewriting an entry that the team sync may also change."""
        return self._lock

    def team(self):
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("team") or {})

    def set_team(self, data):
        with self._lock:
            self._require_unlocked()
            if data:
                self._payload["team"] = copy.deepcopy(data)
            else:
                self._payload.pop("team", None)
            self._save()

    def team_view(self):
        """What the Equipo view last showed (orgs, people, invites): drawn at once, refreshed from the server."""
        with self._lock:
            self._require_unlocked()
            return copy.deepcopy(self._payload.get("team_view") or {})

    def set_team_view(self, data):
        with self._lock:
            self._require_unlocked()
            if data:
                self._payload["team_view"] = copy.deepcopy(data)
            else:
                self._payload.pop("team_view", None)
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
                raise ValidationError(tr("vault.credential_with_identifier_already_exist", id=entry['id']))
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

    def put_many(self, entries):
        """Add new entries and save the vault once (an import of thousands). Each one is checked on its
        own: returns [(entry_id, error or None)] in order, and only the valid ones are stored."""
        results, now = [], datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._require_unlocked()
            stored = self._payload["entries"]
            added = {}
            for entry in entries:
                try:
                    validate_entry(entry)
                    if entry["id"] in stored or entry["id"] in added:
                        raise ValidationError(tr("vault.credential_with_identifier_already_exist", id=entry['id']))
                except ValidationError as exc:
                    results.append((entry.get("id"), str(exc)))
                    continue
                entry = copy.deepcopy(entry)
                entry["updated"] = entry["secret_since"] = now
                added[entry["id"]] = entry
                results.append((entry["id"], None))
            if added:
                stored.update(added)
                self._save()
        return results

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
            raise ValidationError(tr("vault.unsupported_vault_version", get=doc.get('version')))
        return doc

    def _open(self, doc, key):
        try:
            payload = json.loads(crypto.open_sealed(key, doc, VAULT_AAD))
        except Exception:
            raise ValidationError(tr("vault.vault_is_damaged_or_key")) from None
        with self._lock:
            self._key, self._payload, self._master_wrap = key, payload, doc["master"]
            # The stored public key is not authenticated: rewrite it if missing (vaults up to 0.3) or altered.
            expected = crypto.b64(crypto.x25519_public(crypto.derive_x25519(key, AUDIT_KEY_INFO)))
            if doc.get("audit_public_key") != expected:
                self._save()

    def _save(self):
        self.revision += 1
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._audit_public = crypto.x25519_public(crypto.derive_x25519(self._key, AUDIT_KEY_INFO))
        doc = {"version": FORMAT_VERSION, "master": self._master_wrap, "audit_public_key": crypto.b64(self._audit_public),
               **crypto.seal(self._key, json.dumps(self._payload).encode("utf-8"), VAULT_AAD)}
        _atomic_write(self.file, json.dumps(doc, indent=1).encode("utf-8"))

    def _device_key_matches(self, key):
        try:
            return platform.unprotect_for_service(self.device_file.read_bytes(), DEVICE_ENTROPY, self.data_dir) == key
        except OSError:
            return False

    def _store_device_key(self):
        try:
            _atomic_write(self.device_file, platform.protect_for_service(self._key, DEVICE_ENTROPY, self.data_dir))
        except OSError:
            pass  # unlock with Windows simply stays unavailable


def secret_fields(entry):
    """What identifies the secret values of an entry (a change means the secret was replaced)."""
    return entry["template"], {name: entry["fields"].get(name) for name in templates.key_field_names(entry["template"])}


def _atomic_write(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
