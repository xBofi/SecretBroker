"""Exporting the vault, so nobody is locked in: an encrypted file to move to another SecretBroker,
or plain JSON / CSV for other password managers. See docs/EXPORT_FORMAT.md.

Built by the service; the app only writes the result to the file the user picks.
"""

import csv
import io
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

from . import crypto, templates

PLAIN_FORMAT = "secretbroker-export"
ENCRYPTED_FORMAT = "secretbroker-encrypted-export"
VERSION = 1
EXPORT_AAD = b"secretbroker/export/v1"
MIN_PASSWORD_LEN = 12
FORMATS = ("encrypted", "json", "csv")
# What travels with each credential. Local bookkeeping (exposure findings, approvals, where it was
# uploaded, retired keys) stays behind: it means nothing on another computer.
ENTRY_KEYS = ("id", "name", "template", "description", "fields", "policy", "tags", "expires", "rotate_every_days",
              "check_every_hours", "used_in", "rotation_guide", "secret_since", "updated", "draft")
CSV_COLUMNS = ("name", "url", "username", "password", "note")  # Chrome's columns: every manager reads them


class ExportError(ValueError):
    def __init__(self, message, code="invalid"):
        super().__init__(message)
        self.code = code


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def plain_document(entries, app_version=""):
    return {"format": PLAIN_FORMAT, "version": VERSION, "exported": _now(), "app": app_version,
            "entries": [{k: e[k] for k in ENTRY_KEYS if e.get(k) not in (None, "", [], {})} for e in entries]}


def _aad(header):
    return EXPORT_AAD + b"|" + json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(document, password):
    """scrypt(password) -> AES-256-GCM over the plain export; the header is authenticated too."""
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ExportError(f"La contraseña del archivo debe tener al menos {MIN_PASSWORD_LEN} caracteres")
    header = {"format": ENCRYPTED_FORMAT, "version": VERSION, "kdf": crypto.new_kdf()}
    key = crypto.derive_key(password, header["kdf"])
    sealed = crypto.seal(key, json.dumps(document).encode("utf-8"), _aad(header))
    return {**header, **sealed}


def decrypt(doc, password):
    if doc.get("format") != ENCRYPTED_FORMAT or doc.get("version") != VERSION:
        raise ExportError("Este archivo no es una exportación cifrada de SecretBroker compatible")
    header = {"format": doc["format"], "version": doc["version"], "kdf": doc.get("kdf") or {}}
    try:
        key = crypto.derive_key(password or "", header["kdf"])
        plaintext = crypto.open_sealed(key, doc, _aad(header))
    except InvalidTag:
        raise ExportError("La contraseña no abre este archivo", "wrong_password") from None
    except (KeyError, TypeError, ValueError):
        raise ExportError("El archivo está dañado") from None
    return json.loads(plaintext)


def main_secret(entry):
    """The value another manager would call the password: the first key field that is set."""
    for name in templates.key_field_names(entry["template"]):
        if entry["fields"].get(name):
            return str(entry["fields"][name])
    return ""


def to_csv(entries):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for entry in entries:
        fields = entry["fields"]
        url = fields.get("url") or fields.get("base_url") or ""
        if not url and fields.get("host"):
            url = fields["host"] + (f":{fields['port']}" if fields.get("port") else "")
        username = fields.get("username") or fields.get("access_key_id") or ""
        writer.writerow([entry.get("name") or entry["id"], url, username, main_secret(entry), fields.get("notes", "").strip()])
    return out.getvalue()


def build(entries, fmt, password=None, app_version=""):
    """The text of the file to write."""
    if fmt not in FORMATS:
        raise ExportError("Formato de exportación no válido")
    if fmt == "csv":
        return to_csv(entries)
    document = plain_document(entries, app_version)
    if fmt == "json":
        return json.dumps(document, indent=1, ensure_ascii=False)
    return json.dumps(encrypt(document, password), indent=1)
