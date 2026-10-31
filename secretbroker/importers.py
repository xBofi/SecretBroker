"""Importing from other password managers and browsers.

Runs in the service: the app reads the file the user picked (the service account cannot) and sends
its text; the app only ever gets back names, usernames, sites and what will happen to each one.

Supported: Bitwarden (unencrypted .json and .csv), 1Password (.csv), KeePass / KeePassXC (.csv),
Chrome / Edge / Brave (.csv), Firefox (.csv), any CSV with name/url/username/password columns, and
SecretBroker's own exports (plain or encrypted). A project's .env goes through `sb import`.
"""

import csv
import io
import json
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from . import exports, exposure, presets, templates, totp
from .vault import ID_RE, TAG_RE

MAX_ITEMS = 5000
FORMATS = {
    "bitwarden_json": "Bitwarden (JSON)",
    "bitwarden_csv": "Bitwarden (CSV)",
    "onepassword_csv": "1Password (CSV)",
    "keepass_csv": "KeePass / KeePassXC (CSV)",
    "chrome_csv": "Chrome / Edge (CSV)",
    "firefox_csv": "Firefox (CSV)",
    "csv": "CSV",
    "secretbroker": "SecretBroker",
    "secretbroker_encrypted": "SecretBroker (cifrado)",
}
# Column names each manager uses for the same thing (lowercase).
COLUMNS = {
    "name": ("name", "title", "account", "nombre", "titulo"),
    "url": ("url", "login_uri", "website", "web site", "location", "uri", "urls", "sitio"),
    "username": ("username", "login_username", "login name", "user name", "user", "login", "email", "usuario"),
    "password": ("password", "login_password", "contrasena", "contraseña"),
    "notes": ("notes", "note", "comments", "notas", "nota"),
    "totp": ("totp", "login_totp", "otpauth", "otp", "timeotp-secret-base32"),
    "folder": ("folder", "group", "grouping", "tags", "carpeta"),
    "type": ("type",),
}
SKIPPED_TYPES = {"card": "Las tarjetas no se importan", "identity": "Las identidades no se importan"}


class ImportFileError(ValueError):
    def __init__(self, message, code="invalid"):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- reading the file


def detect(text, filename=""):
    """The format of a file, from its content (the name only helps with the message)."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except ValueError:
            raise ImportFileError("El archivo parece JSON pero no se puede leer") from None
        if doc.get("format") == exports.ENCRYPTED_FORMAT:
            return "secretbroker_encrypted"
        if doc.get("format") == exports.PLAIN_FORMAT:
            return "secretbroker"
        if isinstance(doc.get("items"), list):
            return "bitwarden_json"
        raise ImportFileError("No se reconoce este JSON. Exporta desde Bitwarden en formato .json (sin cifrar).")
    headers = {h.strip().lower() for h in next(csv.reader(io.StringIO(stripped)), [])}
    if not headers:
        raise ImportFileError("El archivo está vacío")
    if "login_password" in headers:
        return "bitwarden_csv"
    if "title" in headers and headers & {"otpauth", "archived", "website", "favorite"} and "group" not in headers:
        return "onepassword_csv"
    if ("group" in headers and "title" in headers) or {"account", "login name"} <= headers:
        return "keepass_csv"
    if headers & {"httprealm", "formactionorigin", "guid"}:
        return "firefox_csv"
    if {"name", "url", "username", "password"} <= headers:
        return "chrome_csv"
    if headers & set(COLUMNS["password"]):
        return "csv"
    if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped, re.M):
        raise ImportFileError("Parece un .env: impórtalo con «sb import» en la carpeta del proyecto.")
    raise ImportFileError("No se reconoce el formato. Exporta desde tu gestor en CSV o, en Bitwarden, en JSON sin cifrar.")


def parse(text, fmt="auto", password=None, filename=""):
    """(candidates, skipped). A candidate is an entry without id or policy; skipped: [{name, reason}]."""
    fmt = detect(text, filename) if fmt in (None, "", "auto") else fmt
    if fmt not in FORMATS:
        raise ImportFileError("Formato no válido")
    if fmt == "bitwarden_json":
        found = _bitwarden_json(json.loads(text))
    elif fmt in ("secretbroker", "secretbroker_encrypted"):
        doc = json.loads(text)
        if fmt == "secretbroker_encrypted":
            if not password:
                raise ImportFileError("Este archivo está cifrado: escribe su contraseña", "password_required")
            try:
                doc = exports.decrypt(doc, password)
            except exports.ExportError as exc:
                raise ImportFileError(str(exc), exc.code) from None
        found = _secretbroker(doc)
    else:
        found = _csv(text, fmt)
    candidates, skipped = found
    if len(candidates) > MAX_ITEMS:
        raise ImportFileError(f"Demasiadas credenciales en un archivo (máximo {MAX_ITEMS})")
    return fmt, candidates, skipped


# --------------------------------------------------------------------------- formats


def _bitwarden_json(doc):
    if doc.get("encrypted"):
        raise ImportFileError("Este archivo de Bitwarden está cifrado. Exporta de nuevo en formato «.json» (sin cifrar).")
    folders = {f.get("id"): f.get("name") for f in doc.get("folders") or [] if isinstance(f, dict)}
    candidates, skipped = [], []
    for item in doc["items"]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        kind = item.get("type")
        extra = [f"{f.get('name')}: {f.get('value')}" for f in item.get("fields") or []
                 if isinstance(f, dict) and f.get("value") not in (None, "")]
        folder = folders.get(item.get("folderId"))
        if kind == 1:
            login = item.get("login") or {}
            uris = [u.get("uri") for u in login.get("uris") or [] if isinstance(u, dict) and u.get("uri")]
            _add(candidates, skipped, name, uris[0] if uris else "", login.get("username"), login.get("password"),
                 item.get("notes"), login.get("totp"), extra + [f"Otra dirección: {u}" for u in uris[1:]], folder)
        elif kind == 2:
            _note(candidates, skipped, name, item.get("notes"), extra, folder)
        elif kind == 5 and (item.get("sshKey") or {}).get("privateKey"):
            key = item["sshKey"]["privateKey"].strip() + "\n"
            candidates.append(_candidate(name or "Clave SSH", "generic", {"value": key, "notes": _notes(item.get("notes"), None, extra)}, folder))
        else:
            skipped.append({"name": name or "(sin nombre)", "reason": {3: SKIPPED_TYPES["card"], 4: SKIPPED_TYPES["identity"]}.get(kind, "Tipo no compatible")})
    return candidates, skipped


def _csv(text, fmt):
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        raise ImportFileError("El archivo está vacío") from None
    index = {}
    for key, names in COLUMNS.items():
        index[key] = next((header.index(n) for n in names if n in header), None)
    if index["password"] is None:
        raise ImportFileError("El CSV no tiene una columna de contraseña")
    known = {i for i in index.values() if i is not None}
    candidates, skipped = [], []
    for row in reader:
        if not any(cell.strip() for cell in row):
            continue
        get = lambda key: row[index[key]].strip() if index[key] is not None and index[key] < len(row) else ""  # noqa: E731
        kind = get("type").lower()
        # Columns this importer doesn't know (1Password's or KeePass's extras) go to the private notes.
        extra = [f"{header[i]}: {cell.strip()}" for i, cell in enumerate(row)
                 if i not in known and i < len(header) and cell.strip() and header[i] in ("fields", "otpauth", "custom fields")]
        folder = get("folder").split("/")[-1].split(",")[0].strip()
        if fmt == "keepass_csv" and folder.lower() == "root":
            folder = ""  # KeePass puts every group under «Root»: it is not a folder of the user
        if kind in SKIPPED_TYPES:
            skipped.append({"name": get("name") or "(sin nombre)", "reason": SKIPPED_TYPES[kind]})
        elif kind == "note":
            _note(candidates, skipped, get("name"), get("notes"), extra, folder)
        else:
            _add(candidates, skipped, get("name"), get("url"), get("username"), get("password"), get("notes"), get("totp"),
                 extra, folder)
    return candidates, skipped


def _secretbroker(doc):
    if doc.get("format") != exports.PLAIN_FORMAT or doc.get("version") != exports.VERSION:
        raise ImportFileError("Este archivo no es una exportación de SecretBroker compatible")
    candidates = []
    for entry in doc.get("entries") or []:
        if not isinstance(entry, dict) or entry.get("template") not in templates.TEMPLATES:
            continue
        candidate = {k: entry[k] for k in exports.ENTRY_KEYS if k in entry and k not in ("secret_since", "updated")}
        candidate["fields"] = {k: str(v) for k, v in (entry.get("fields") or {}).items() if v not in (None, "")}
        candidates.append(candidate)
    return candidates, []


# --------------------------------------------------------------------------- mapping


def _notes(notes, otp, extra):
    parts = [str(notes).strip()] if notes and str(notes).strip() else []
    if otp:
        parts.append(f"Código de un solo uso (TOTP): {str(otp).strip()}")
    parts += [str(e) for e in extra or []]
    return "\n".join(parts).strip()


def _candidate(name, template, fields, folder):
    fields = {k: v for k, v in fields.items() if v}
    if fields.get("notes"):
        fields["notes"] = fields["notes"].strip() + "\n"
    tag = re.sub(r"[^a-z0-9_.-]+", "-", _ascii(str(folder or "")).lower()).strip("-")[:30]
    return {"name": name[:120], "template": template, "fields": fields, "tags": [tag] if tag and TAG_RE.match(tag) else []}


def _ascii(text):
    return unicodedata.normalize("NFD", text).encode("ascii", "ignore").decode("ascii")


def _host(url):
    try:
        return urlsplit(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:
        return ""


def _web_url(url):
    """Only web addresses become the credential's URL (it decides where the AI may send it)."""
    url = (url or "").strip()
    if re.match(r"^https?://", url, re.I) or (url and "://" not in url and re.match(r"^[\w.-]+\.[a-z]{2,}(/.*)?$", url, re.I)):
        return url
    return ""


def _key_preset(value):
    """The preset of a value that is clearly an API key of a known provider (sk-ant-…, ghp_…)."""
    for name, prefixes, *_ in exposure.PROVIDERS:
        if prefixes and value.startswith(prefixes):
            return next((pid for pid, p in presets.PRESETS.items() if p[0] == name), None)
    return None


# Addresses that are a server, not a web page: the credential becomes a database or an SSH server.
DB_SCHEMES = {"postgres": "postgresql", "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mysql",
              "mssql": "sqlserver", "sqlserver": "sqlserver", "mongodb": "mongodb", "mongodb+srv": "mongodb",
              "redis": "redis", "rediss": "redis"}


def _server(url, username, password):
    """(template, fields) of a postgres://, mysql://, ssh://… address, or None."""
    match = re.match(r"^([a-z][a-z0-9+]*)://", (url or "").strip(), re.I)
    scheme = match[1].lower() if match else ""
    if scheme not in DB_SCHEMES and scheme not in ("ssh", "sftp"):
        return None
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname or "", parts.port
    except ValueError:
        return None
    user = username or unquote(parts.username or "")
    if not host or not user:
        return None
    fields = {"host": host, "username": user, "password": password}
    if scheme in ("ssh", "sftp"):
        return "ssh", {**fields, "port": str(port or 22), "auth_method": "password"}
    fields.update(engine=DB_SCHEMES[scheme], port=str(port) if port else "", database=parts.path.strip("/"))
    return "database", fields


def _totp(value):
    """A 2FA seed the app can compute codes from (else it stays in the private notes)."""
    try:
        totp.validate(value)
        return str(value).strip()
    except totp.TotpError:
        return None


def _add(candidates, skipped, name, url, username, password, notes, otp, extra, folder):
    name, username, password = (name or "").strip(), (username or "").strip(), password or ""
    web = _web_url(url)
    server = _server(url, username, password)
    if url and not web and not server:
        extra = list(extra) + [f"Dirección: {url}"]
    name = name or _host(web) or (server[1]["host"] if server else "") or username or "Importada"
    if not password.strip():
        skipped.append({"name": name, "reason": "No tiene contraseña"})
        return
    # A login's 2FA goes to its own field (the app shows the code); anything else keeps it in the notes.
    seed = _totp(otp) if otp and username and not server else None
    private = _notes(notes, None if seed else otp, extra)
    preset = None if username else _key_preset(password.strip())
    if server:
        template, fields = server
        candidates.append(_candidate(name, template, {**fields, "notes": private}, folder))
    elif preset:
        fields, _ = presets.apply(preset, {"value": password.strip(), "notes": private}, "")
        candidates.append(_candidate(name, "api_key", fields, folder))
    elif username:
        candidates.append(_candidate(name, "web_login", {"url": web, "username": username, "password": password,
                                                          "totp": seed, "notes": private}, folder))
    else:
        candidates.append(_candidate(name, "generic", {"value": password, "url": web, "notes": private}, folder))


def _note(candidates, skipped, name, notes, extra, folder):
    text = _notes(notes, None, extra)
    if not text:
        skipped.append({"name": name or "(sin nombre)", "reason": "Nota vacía"})
        return
    candidates.append(_candidate(name or "Nota", "generic", {"value": text + "\n"}, folder))


# --------------------------------------------------------------------------- what will happen


def identity(entry):
    """What makes two credentials 'the same account': kind, site and user."""
    fields = entry.get("fields") or {}
    site = _host(fields.get("url") or fields.get("base_url") or "") or fields.get("host") or ""
    return entry.get("template"), site.lower(), (fields.get("username") or fields.get("access_key_id") or "").lower()


def _slug(text):
    slug = re.sub(r"[^a-z0-9]+", "-", _ascii(text).lower()).strip("-")[:60].strip("-")
    return slug or "importada"


def plan(candidates, existing):
    """Each candidate with its id and status: new, duplicate (identical to one already there or earlier in
    the file) or conflict (same site and user, another password). Only new ones are selected by default."""
    by_identity = {}
    for entry in existing:
        by_identity.setdefault(identity(entry), []).append(entry)
    in_vault = {e["id"] for e in existing}
    taken = set(in_vault)
    planned = []
    for key, candidate in enumerate(candidates):
        same = by_identity.get(identity(candidate), [])
        secret = exports.main_secret(candidate)
        match = next((e for e in same if exports.main_secret(e) == secret), None)
        if match:
            status, reason = "duplicate", "Ya está en la bóveda" if match["id"] in in_vault else "Repetida en el archivo"
        elif same and identity(candidate)[1:] != ("", ""):
            status, reason = "conflict", f"Ya tienes «{same[0].get('name') or same[0]['id']}» con otra contraseña"
        else:
            status, reason = "new", ""
        wanted = candidate.get("id") if ID_RE.match(str(candidate.get("id") or "")) else _slug(candidate["name"])
        entry_id, n = wanted, 2
        while entry_id in taken:
            suffix = f"-{n}"
            entry_id, n = wanted[:64 - len(suffix)] + suffix, n + 1
        taken.add(entry_id)
        entry = {**candidate, "id": entry_id}
        by_identity.setdefault(identity(entry), []).append(entry)
        planned.append({"key": key, "status": status, "reason": reason, "entry": entry})
    return planned


DEV_TEMPLATES = {"api_key", "ssh", "database", "aws"}
DEV_WORDS = re.compile(r"(^|[^a-z])(api|apikey|token|pat|secret|key|keys|ssh|sftp|pem|db|database|postgres|postgresql|"
                       r"mysql|mariadb|mongo|mongodb|redis|sql|aws|gcp|azure|s3|npm|pypi|docker|webhook|deploy|ci|"
                       r"smtp|oauth|client[_ -]?secret)([^a-z]|$)", re.I)


def is_dev(entry):
    """A development key (API key, SSH, database, cloud) rather than a personal login: the import filter."""
    if entry.get("template") in DEV_TEMPLATES:
        return True
    if entry.get("template") != "generic":
        return False
    value = str((entry.get("fields") or {}).get("value") or "").strip()
    if value.startswith(("-----BEGIN", "ssh-", "ecdsa-")):
        return True
    return bool(DEV_WORDS.search(_ascii(str(entry.get("name") or "")))) and "\n" not in value


def subtitle(entry):
    fields = entry.get("fields") or {}
    site = _host(fields.get("url") or fields.get("base_url") or "") or fields.get("host") or ""
    return " · ".join(x for x in (fields.get("username") or fields.get("access_key_id"), site) if x)


def preview(item):
    """What the app may show about a planned import: never a value."""
    entry = item["entry"]
    return {"key": item["key"], "id": entry["id"], "name": entry["name"], "template": entry["template"],
            "subtitle": subtitle(entry), "tags": entry.get("tags") or [], "status": item["status"], "reason": item["reason"],
            "notes": bool((entry.get("fields") or {}).get("notes")), "totp": bool((entry.get("fields") or {}).get("totp")),
            "dev": is_dev(entry), "selected": item["status"] == "new"}
