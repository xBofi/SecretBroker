"""Exporting the vault, so nobody is locked in: an encrypted file to move to another SecretBroker,
or plain JSON / CSV for other password managers. See docs/EXPORT_FORMAT.md.

Built by the service; the app only writes the result to the file the user picks.
"""

import csv
import io
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

from . import crypto, i18n, templates
from .i18n import tr

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
# What a personal item gives in the CSV's `password` column: the one thing it hides that another manager would keep
# there. A note has none: its text is the `note`.
PERSONAL_MAIN = {"card": "number", "identity": "number", "wifi": "password", "bank": "iban", "license": "license_key"}


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
        raise ExportError(tr("exports.file_password_must_have_at", MIN_PASSWORD_LEN=MIN_PASSWORD_LEN))
    header = {"format": ENCRYPTED_FORMAT, "version": VERSION, "kdf": crypto.new_kdf()}
    key = crypto.derive_key(password, header["kdf"])
    sealed = crypto.seal(key, json.dumps(document).encode("utf-8"), _aad(header))
    return {**header, **sealed}


def decrypt(doc, password):
    if doc.get("format") != ENCRYPTED_FORMAT or doc.get("version") != VERSION:
        raise ExportError(tr("exports.this_file_isn_compatible_encrypted"))
    header = {"format": doc["format"], "version": doc["version"], "kdf": doc.get("kdf") or {}}
    try:
        key = crypto.derive_key(password or "", header["kdf"])
        plaintext = crypto.open_sealed(key, doc, _aad(header))
    except InvalidTag:
        raise ExportError(tr("exports.password_doesn_open_this_file"), "wrong_password") from None
    except (KeyError, TypeError, ValueError):
        raise ExportError(tr("exports.file_is_damaged")) from None
    return json.loads(plaintext)


def main_secret(entry):
    """The value another manager would call the password: the first key field that is set."""
    for name in templates.key_field_names(entry["template"]):
        if entry["fields"].get(name):
            return str(entry["fields"][name])
    return ""


def _personal_row(entry):
    """A personal item in Chrome's columns: `password` is what it hides (PERSONAL_MAIN), `username` a Wi-Fi's network
    name, and everything else it says goes to `note`, one «label: value» line each, so the file loses nothing."""
    fields, template = entry["fields"], entry["template"]
    main = PERSONAL_MAIN.get(template)
    lines = []
    for spec in templates.field_specs(template):
        name = spec["name"]
        value = entry.get("expires") if name == templates.EXPIRES else fields.get(name)
        if not value or name in (main, "text", "notes") or (template, name) == ("wifi", "ssid"):
            continue
        option = next((o["label"] for o in spec["options"] if o["value"] == value), None)
        lines.append(f"{i18n.phrase('templates', spec['label'])}: {i18n.phrase('templates', option) if option else str(value).strip()}")
    lines += [str(fields[name]).strip() for name in ("text", "notes") if fields.get(name)]
    return [entry.get("name") or entry["id"], "", fields.get("ssid", "") if template == "wifi" else "",
            str(fields.get(main) or "").strip() if main else "", "\n".join(lines)]


def to_csv(entries):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for entry in entries:
        if templates.is_personal(entry["template"]):
            writer.writerow(_personal_row(entry))
            continue
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
        raise ExportError(tr("exports.invalid_export_format"))
    if fmt == "csv":
        return to_csv(entries)
    document = plain_document(entries, app_version)
    if fmt == "json":
        return json.dumps(document, indent=1, ensure_ascii=False)
    return json.dumps(encrypt(document, password), indent=1)
