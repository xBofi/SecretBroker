"""Teams: account keys, signed key grants, encrypted collections and the sync engine.

The server only ever sees ciphertext, public keys and routing metadata (docs/ARCHITECTURE.md). Everything here
runs inside the service with the vault unlocked. The account password is used once, when linking the account;
afterwards only the private keys and a session token are kept, inside the encrypted vault (payload section "team").

Shared credentials are ordinary vault entries with an `entry["shared"]` block, so the broker, `sb run`, exposure
checks and rotation work on them unchanged. The team state keeps, per collection, its keys and the last content
synced for each item ("base"), which is how local edits, conflicts and quarantined changes are told apart.
"""

import copy
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import __version__, autofill, crypto, templates
from .crypto import b64, unb64
from .vault import ID_RE, SHARE_PERMISSIONS, SHARE_WRITE, ValidationError, secret_fields, shared_content
from .i18n import tr

API = "/api/v1"
AUTH_INFO = b"secretbroker/team-auth/v1"
WRAP_INFO = b"secretbroker/team-wrap/v1"
KEYS_AAD = b"secretbroker/team-keys/v1|"
GRANT_AAD = "secretbroker/grant/v1|"
NAME_AAD = b"secretbroker/collection-name/v1|"
ITEM_AAD = "secretbroker/item/v1|"
MEMBERS_SIG = b"secretbroker/members/v1|"
ITEM_SIG = b"secretbroker/item-sig/v1|"
DELETE_SIG = b"secretbroker/delete/v1|"
DATA_INFO = b"secretbroker/account-data/v1"
DATA_AAD = b"secretbroker/account-data/v1|"
# A sync that would delete more than this many credentials of a collection (or at least MASS_DELETE_MIN that are
# half of it or more) waits for the user instead (2.7): a stolen account, a broken client or the server itself.
MASS_DELETE = 5
MASS_DELETE_MIN = 3
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
# What the user is looking at (the Equipo view): answer soon, from what is known, rather than hang.
READ_TIMEOUT = httpx.Timeout(8.0, connect=5.0)
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
MIN_ACCOUNT_PASSWORD = 12
# Besides the policy, these fields decide where a secret is sent (an SSH or database server).
DESTINATION_FIELDS = ("host", "port", "engine")
SOMEONE = "alguien que ya no está"
# The oldest server protocol this app works with (GET /info `api`; servers before it was announced count by their
# version): 1 = 0.16, which keeps signed member lists and deletions. Older servers refuse them, so the app says
# the server must be updated instead of failing later on a member list.
MIN_SERVER_API = 1
VERSION_HEADER = "X-SecretBroker-Version"
VERSION_RE = re.compile(r"^\s*v?(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?")


class TeamError(Exception):
    def __init__(self, message, code="team_error", status=None, data=None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.data = data or {}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash(content):
    return hashlib.sha256(_canonical(content)).hexdigest()


# ---------------------------------------------------------------------- account keys (2.1)

def new_account_keys():
    return {"x25519": b64(X25519PrivateKey.generate().private_bytes_raw()),
            "ed25519": b64(Ed25519PrivateKey.generate().private_bytes_raw())}


def _x25519(keys):
    return X25519PrivateKey.from_private_bytes(unb64(keys["x25519"]))


def _ed25519(keys):
    return Ed25519PrivateKey.from_private_bytes(unb64(keys["ed25519"]))


def public_keys(keys):
    return {"public_key": b64(crypto.x25519_public(_x25519(keys))),
            "signing_public_key": b64(_ed25519(keys).public_key().public_bytes_raw())}


def check_kdf(kdf):
    """Only sane scrypt parameters: a hostile server must not make this PC hang or run out of memory."""
    try:
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        ok = kdf.get("name") == "scrypt" and 2**14 <= n <= 2**20 and not n & (n - 1) and 1 <= r <= 32 \
            and 1 <= p <= 16 and len(unb64(kdf["salt"])) >= 16
    except (KeyError, TypeError, ValueError):
        ok = False
    if not ok:
        raise TeamError(tr("teams.server_sent_invalid_encryption_parameter"), "bad_server")
    return kdf


def account_secrets(password, kdf):
    """(auth_key, wrap_key): the first is sent to the server as auth_hash, the second never leaves this PC."""
    master = crypto.derive_key(password, check_kdf(kdf))
    return crypto._hkdf(master, AUTH_INFO), crypto._hkdf(master, WRAP_INFO)


def seal_private_keys(wrap_key, keys, user_id):
    return crypto.seal(wrap_key, _canonical(keys), KEYS_AAD + user_id.encode("utf-8"))


def open_private_keys(wrap_key, blob, user_id):
    try:
        keys = json.loads(crypto.open_sealed(wrap_key, blob, KEYS_AAD + user_id.encode("utf-8")))
        keys = {"x25519": keys["x25519"], "ed25519": keys["ed25519"]}
        public_keys(keys)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise TeamError(tr("teams.couldn_open_account_keys_password"),
                        "invalid_credentials") from None
    return keys


def fingerprint(public_key, signing_public_key):
    """The "código de seguridad" two people compare over another channel, digits being easy to read out:
    SHA-256(x25519 || ed25519) as 40 decimal digits (133 bits) in 8 groups of 5."""
    digest = hashlib.sha256(unb64(public_key) + unb64(signing_public_key)).digest()
    digits = f"{int.from_bytes(digest, 'big') % 10**40:040d}"
    return " ".join(digits[i:i + 5] for i in range(0, 40, 5))


def _hex_fingerprint(public_key, signing_public_key):
    """How earlier versions showed it (8 groups of 4 hex chars): someone may still read that one out."""
    return hashlib.sha256(unb64(public_key) + unb64(signing_public_key)).hexdigest()[:32]


def _same_fingerprint(typed, person):
    """Whether what the user typed is that person's code (or the hex fingerprint older versions showed)."""
    clean = "".join(ch for ch in str(typed or "") if ch.isalnum()).lower()
    return bool(clean) and clean in ("".join(person["fp"].split()),
                                     _hex_fingerprint(person["public_key"], person["signing_public_key"]))


def _pinned_fp(pinned):
    """The code of a pinned key, computed from the key itself (pins made by earlier versions stored the hex one)."""
    return fingerprint(pinned["public_key"], pinned["signing_public_key"])


# ---------------------------------------------------------------------- grants, names and items (2.3)

def _grant_aad(cid, version, member_id):
    return f"{GRANT_AAD}{cid}|{version}|{member_id}".encode("utf-8")


def _grant_message(cid, version, member_id, sealed):
    return _grant_aad(cid, version, member_id) + b"|" + hashlib.sha256(_canonical(sealed)).hexdigest().encode("ascii")


def make_grant(keys, granter_id, cid, version, member_id, member_public_key, collection_key):
    sealed = crypto.seal_to(unb64(member_public_key), collection_key, _grant_aad(cid, version, member_id))
    signature = _ed25519(keys).sign(_grant_message(cid, version, member_id, sealed))
    return {"sealed": sealed, "granted_by": granter_id, "signature": b64(signature)}


def open_grant(keys, member_id, cid, version, grant, granter_signing_key):
    """The collection key, only if the grant is signed by the (pinned) key of whoever says they granted it."""
    try:
        Ed25519PublicKey.from_public_bytes(unb64(granter_signing_key)).verify(
            unb64(grant["signature"]), _grant_message(cid, version, member_id, grant["sealed"]))
        key = crypto.open_from(_x25519(keys), grant["sealed"], _grant_aad(cid, version, member_id))
    except (InvalidSignature, InvalidTag, ValueError, KeyError, TypeError):
        raise TeamError(tr("teams.collection_key_doesn_have_valid"), "bad_grant") from None
    if len(key) != 32:
        raise TeamError(tr("teams.collection_key_isn_valid"), "bad_grant")
    return key


def seal_name(key, cid, info):
    """The collection name, plus who lost access at the last re-key ({name, removed, version})."""
    return crypto.seal(key, _canonical(info), NAME_AAD + cid.encode("utf-8"))


def open_name(key, cid, blob):
    info = json.loads(crypto.open_sealed(key, blob, NAME_AAD + cid.encode("utf-8")))
    return info if isinstance(info, dict) else {"name": str(info)}


def _item_aad(cid, iid, version):
    return f"{ITEM_AAD}{cid}|{iid}|{version}".encode("utf-8")


def seal_item(key, cid, iid, version, plaintext):
    return crypto.seal(key, _canonical(plaintext), _item_aad(cid, iid, version))


def open_item(key, cid, iid, version, ciphertext):
    return json.loads(crypto.open_sealed(key, ciphertext, _item_aad(cid, iid, version)))


# ---------------------------------------------------------------------- signatures (2.6)

def sign(keys, message):
    return b64(_ed25519(keys).sign(message))


def signed_by(signing_public_key, signature, message):
    """Whether `signature` over `message` is from that key. Never raises."""
    try:
        Ed25519PublicKey.from_public_bytes(unb64(signing_public_key)).verify(unb64(signature), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def members_hash(body):
    return hashlib.sha256(_canonical(body)).hexdigest()


def make_members_record(keys, me, cid, head, members, key_version):
    """The next signed member list of a collection: who is in it with which permission, chained to `head` (the
    last one this client verified; None for the first)."""
    body = {"cid": cid, "seq": (head["seq"] + 1) if head else 1, "key_version": key_version, "by": me,
            "members": dict(sorted(members.items())), "at": now_iso()}
    if head:
        body["prev"] = head["hash"]
    return {"body": body, "signature": sign(keys, MEMBERS_SIG + _canonical(body))}


def _item_message(cid, iid, seq, entry, by, at):
    return ITEM_SIG + _canonical({"cid": cid, "iid": iid, "seq": seq, "hash": content_hash(entry), "by": by,
                                  "at": at})


def sign_item(keys, me, cid, iid, plain):
    """Sign an item's plaintext (inside the encryption): who wrote this version, which one, with what content."""
    message = _item_message(cid, iid, _seq(plain), plain["entry"], me, plain.get("updated"))
    return {**plain, "sig": {"by": me, "signature": sign(keys, message)}}


def _delete_message(cid, iid, seq, by):
    return DELETE_SIG + _canonical({"cid": cid, "iid": iid, "seq": seq, "by": by})


def make_deletion(keys, me, cid, iid, seq):
    return {"by": me, "seq": seq, "signature": sign(keys, _delete_message(cid, iid, seq, me))}


def _data_key(keys):
    """The key of the account's own data on the server: every device of the account has the private keys."""
    return crypto._hkdf(unb64(keys["x25519"]) + unb64(keys["ed25519"]), DATA_INFO)


# ---------------------------------------------------------------------- what a team member may change locally

def effective_content(entry):
    """The shared content of an entry as the server has it: a quarantined change (2.5) is already on the
    server, the entry just doesn't enforce it yet."""
    content = shared_content(entry)
    pending = (entry.get("shared") or {}).get("pending_policy")
    if not pending:
        return content
    if pending.get("entry"):
        return copy.deepcopy(pending["entry"])
    content["policy"] = copy.deepcopy(pending["policy"])
    for name, value in pending["fields"].items():
        if value in (None, ""):
            content["fields"].pop(name, None)
        else:
            content["fields"][name] = value
    if "description" in pending:
        content["description"] = pending["description"]
    if "fill" in pending:
        _set_fill_part(content, pending["fill"])
    return content


def text_changes(old, new):
    """The change to the description: the AI reads it as instructions about the credential, so a teammate's new
    text waits for review like a new destination (a prompt-injection vector otherwise)."""
    before, after = str(old.get("description") or "").strip(), str(new.get("description") or "").strip()
    if before == after or not after:
        return []  # removing the text can't instruct anything
    return [{"kind": "description", "new": after[:300] + ("…" if len(after) > 300 else "")}]


def is_text_change(change):
    """A change to the instructions the AI reads (dicts since 0.16; Spanish lines kept in older vaults)."""
    return change.get("kind") == "description" if isinstance(change, dict) else str(change).startswith("Instrucciones")


def change_text(change):
    """One change as the line Actividad has always kept (Spanish, like the rest of the service's audit details);
    the review card renders the structured form in the page's language instead."""
    if not isinstance(change, dict):
        return str(change)
    kind, values = change.get("kind"), ", ".join(change.get("values") or [])
    if kind == "field":
        template = change.get("template")
        labels = {s["name"]: s["label"] for s in templates.field_specs(template)} if template in templates.TEMPLATES else {}
        return f"{labels.get(change.get('field'), change.get('field'))}: {change.get('old') or '—'} → {change.get('new') or '—'}"
    return {
        "template": f"Tipo de credencial: {change.get('new')}",
        "hosts": f"Webs nuevas: {values}",
        "fill_sites": f"Autorrellenado del navegador en webs nuevas: {values}",
        "auth": f"Cómo se envía la clave: {change.get('new')}",
        "programs": f"Programas nuevos: {values}",
        "env": f"Variables nuevas o cambiadas: {values}",
        "description": f"Instrucciones para la IA (descripción): «{change.get('new')}»",
    }.get(kind, str(change))


def _destination(content):
    policy = copy.deepcopy(content.get("policy") or {})
    policy.pop("approval", None)
    policy.pop("ai_totp", None)
    return {"template": content.get("template"), "policy": policy,
            "fields": {name: (content.get("fields") or {}).get(name) for name in DESTINATION_FIELDS}}


def widening_changes(old, new):
    """Every way `new` sends a secret somewhere `old` did not (empty: nothing wider), as structured changes
    ({kind, field?, template?, old?, new?, values?}) that the page words in its own language."""
    sites = new_fill_sites(old, new)
    old, new = _destination(old), _destination(new)
    changes = []
    if old["template"] != new["template"]:
        changes.append({"kind": "template", "old": old["template"], "new": new["template"]})
    for name in DESTINATION_FIELDS:
        if old["fields"][name] != new["fields"][name]:
            changes.append({"kind": "field", "field": name, "template": new["template"],
                            "old": old["fields"][name] or "", "new": new["fields"][name] or ""})
    http = lambda d: d["policy"].get("http") or {}
    hosts = new_hosts(old, new)
    if hosts:
        changes.append({"kind": "hosts", "values": hosts})
    if sites:
        changes.append({"kind": "fill_sites", "values": sites})
    if (http(old).get("auth") or {"kind": "none"}) != (http(new).get("auth") or {"kind": "none"}):
        changes.append({"kind": "auth", "new": str((http(new).get("auth") or {}).get("kind", "none"))})
    commands = lambda d: d["policy"].get("commands") or {}
    programs = [c for c in commands(new).get("allowed") or [] if c not in (commands(old).get("allowed") or [])]
    if programs:
        changes.append({"kind": "programs", "values": programs})
    old_env = commands(old).get("env") or {}
    env = [k for k, v in (commands(new).get("env") or {}).items() if old_env.get(k) != v]
    if env:
        changes.append({"kind": "env", "values": env})
    return changes


def new_hosts(old, new):
    """The web hosts `new` may send the key to and `old` could not (the change review names them)."""
    http = lambda d: _destination(d)["policy"].get("http") or {}
    return [h for h in http(new).get("allowed_hosts") or [] if h not in (http(old).get("allowed_hosts") or [])]


def new_fill_sites(old, new):
    """The pages where the browser would fill the web login `new` and would not fill `old` (its address and autofill
    sites, autofill.py): a password filled on a page is handed to that page, so a teammate's (or a removed one's,
    before leaving) new address waits for review like a new web for the AI."""
    if new.get("template") != "web_login":
        return []
    new_mode = (new.get("autofill") or {}).get("match", "domain")
    if new_mode == "never":
        return []
    old_mode = (old.get("autofill") or {}).get("match", "domain")
    before = autofill.saved_sites(old) if old.get("template") == "web_login" else []
    labels = []
    for _, site in autofill.saved_sites(new):
        broad = new_mode == "domain" and autofill.has_own_domain(site.host)  # any subdomain too
        if any(autofill.site_matches(saved, site, old_mode) is None
               and (not broad or (old_mode == "domain" and autofill.has_own_domain(saved.host))) for _, saved in before):
            continue
        label = autofill.registrable_domain(site.host) + (f":{site.port}" if site.port else "") if broad else site.label
        label = ("http://" if site.scheme == "http" else "") + label
        if label not in labels:
            labels.append(label)
    return labels


def _fill_part(content):
    """What decides where the browser fills a web login: {url, autofill}."""
    return {"url": (content.get("fields") or {}).get("url"), "autofill": copy.deepcopy(content.get("autofill"))}


def _set_fill_part(entry, part):
    if part["url"] in (None, ""):
        entry["fields"].pop("url", None)
    else:
        entry["fields"]["url"] = part["url"]
    if part["autofill"] is None:
        entry.pop("autofill", None)
    else:
        entry["autofill"] = copy.deepcopy(part["autofill"])


def secret_fp(vault, entry):
    """Keyed fingerprint of an entry's secret: a 'rotate because…' flag ends when the secret changes."""
    return vault.mac(b"team/rotate\0" + _canonical(secret_fields(entry)))


def server_base(url):
    url = str(url or "").strip().rstrip("/")
    if url.endswith(API):
        url = url[:-len(API)]
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        host = None
    if not host or parts.query or parts.fragment or parts.username or parts.password:
        raise TeamError(tr("teams.server_address_isn_valid"), "invalid")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in LOCAL_HOSTS):
        raise TeamError(tr("teams.team_server_must_use_https"), "invalid")
    return url


class Client:
    """The server API. TLS certificates are always verified; plain http only to this same PC."""

    def __init__(self, base, token=None, timeout=TIMEOUT):
        self.base = server_base(base)
        self.token = token
        self._http = httpx.Client(timeout=timeout, verify=True, follow_redirects=False,
                                  headers={"User-Agent": "SecretBroker", VERSION_HEADER: __version__})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._http.close()

    def call(self, method, path, body=None, auth=True):
        headers = {"Authorization": f"Bearer {self.token}"} if auth and self.token else {}
        try:
            response = self._http.request(method, self.base + API + path, json=body, headers=headers)
        except httpx.TimeoutException:
            raise TeamError(tr("teams.team_server_isn_responding_it"), "offline") from None
        except httpx.HTTPError as exc:
            if "CERTIFICATE" in str(exc).upper():
                raise TeamError(tr("teams.team_server_certificate_isn_valid"), "offline", data={"certificate": True}) from None
            raise TeamError(tr("teams.can_reach_team_server_it"), "offline") from None
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code == 200:
            if data is None:
                raise TeamError(tr("teams.team_server_answered_something_unexpecte"), "bad_server")
            return data
        error = data if isinstance(data, dict) else {}
        message = error.get("error") if isinstance(error.get("error"), str) else \
            f"El servidor del equipo ha respondido con un error ({response.status_code})"
        code = error.get("code") if isinstance(error.get("code"), str) else "server_error"
        if response.status_code == 401 and auth:
            code, message = "reconnect", "La sesión del equipo ha caducado. Vuelve a entrar en Equipo para seguir recibiendo cambios."
        if response.status_code == 426:  # the server serves only newer apps (its min_client)
            code, message = "client_too_old", tr("teams.app_too_old")
        raise TeamError(message[:300], code, response.status_code, error)


def _version(text):
    """(major, minor, patch) of "0.17.0" or "0.17.0-beta1"; None if it is not a version."""
    match = VERSION_RE.match(str(text or ""))
    return tuple(int(n or 0) for n in match.groups()) if match else None


def server_api(info):
    """The protocol a server speaks: its `api`, or for servers that did not announce one, 1 from 0.16 on."""
    api = info.get("api")
    if isinstance(api, int) and not isinstance(api, bool):
        return api
    version = _version(info.get("version"))
    return 1 if version and version >= (0, 16, 0) else 0


def check_server(info):
    """Whether this app and the team server work together (GET /info), before anything fails halfway: one
    sentence that says which of the two to update."""
    if not isinstance(info, dict):
        raise TeamError(tr("teams.team_server_answered_something_unexpecte"), "bad_server")
    if server_api(info) < MIN_SERVER_API:
        raise TeamError(tr("teams.server_too_old"), "server_too_old")
    oldest, mine = _version(info.get("min_client")), _version(__version__)
    if oldest and mine and mine < oldest:
        raise TeamError(tr("teams.app_too_old"), "client_too_old")
    return info


# What the user reads when something about the team goes wrong: one sentence that says what to do (the
# messages teams.explain_<code>; these Spanish texts are their source). The details (codes, exception types)
# only go to the service log.
_EXPLAIN = {
    "bad_grant": "{where}la clave no la firma nadie de confianza, así que no se usa. Avisa a quien la gestiona.",
    "old_key": "{where}llegó una versión cifrada con una clave antigua y se ha descartado. No tienes que hacer nada.",
    "rollback": "{where}llegó una versión anterior a la que ya tienes y se ha descartado. No tienes que hacer nada.",
    "missing_key": "{where}falta la clave para leer una credencial. Pide a quien la gestiona que te vuelva a dar acceso.",
    "decrypt": "{where}algo no se pudo descifrar. Pide a quien la gestiona que te vuelva a dar acceso.",
    "invalid_item": "{where}una credencial que llegó no es válida y no se ha aplicado. Pide a quien la cambió que la revise.",
    "key_changed": "{where}la clave de alguien ha cambiado. Verifica su código de seguridad en Equipo › Personas.",
    "bad_members": "{where}el servidor muestra una lista de miembros que nadie que la gestiona ha firmado, así que "
                   "no se usa ni se comparte nada nuevo en ella. Avisa a quien administra el servidor.",
    "unsigned": "{where}llegó un cambio sin una firma válida de alguien que pueda editar y se ha descartado. "
                "Avisa a quien gestiona la colección.",
    "bad_server": "El servidor del equipo ha respondido algo inesperado. Se reintentará; si sigue, avisa a quien lo administra.",
    "rate_limited": "El servidor del equipo pide esperar un poco. Se reintentará solo.",
    "other": "{where}algo no se pudo sincronizar. Se reintentará; si sigue, pide a quien la gestiona que lo revise.",
}


def explain(exc, where=""):
    """The sentence for the user about a sync problem (`where`: the collection, if it is about one)."""
    code = "other"
    if isinstance(exc, TeamError):
        if exc.code in ("offline", "reconnect", "server_too_old", "client_too_old"):
            return str(exc)
        code = exc.code if exc.code in _EXPLAIN else "rate_limited" if exc.status == 429             else "bad_server" if (exc.status or 0) >= 500 else "other"
    elif isinstance(exc, ValidationError):
        code = "invalid_item"
    elif isinstance(exc, (InvalidTag, ValueError, KeyError, TypeError)):
        code = "decrypt"
    text = tr(f"teams.explain_{code}", where=tr("teams.explain_where", name=where) if where else "")
    return text[0].upper() + text[1:]


def detail(exc):
    """What goes to the log: the code and type, never a value."""
    if isinstance(exc, TeamError):
        return f"{exc.code} {exc.status or ''} {exc}".strip()
    return type(exc).__name__


def connected(state):
    return bool(state.get("token") and state.get("keys") and state.get("user"))


def _seq(plain):
    """The write counter inside an item's plaintext (0 for items written before it existed)."""
    seq = plain.get("seq", 0)
    return seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0


def _label(person):
    return (person or {}).get("name") or (person or {}).get("email") or SOMEONE


def _mass(count, total):
    """Whether deleting `count` of a collection's `total` credentials in one sync is too much to do unasked."""
    return count > MASS_DELETE or (count >= MASS_DELETE_MIN and count * 2 >= total)


class Team:
    """Team operations on one vault. The service runs them one at a time, with the vault unlocked."""

    def __init__(self, vault, on_removed=None):
        self.vault = vault
        self.on_removed = on_removed  # called with the id of each credential a sync removes from this PC
        self._freed = set()       # ids removed in this sync round: never handed to another credential
        self._removed_ids = []

    # ------------------------------------------------------------------ account

    def status(self):
        state = self.vault.team()
        if not connected(state):
            return {"connected": False}
        entries = [e for e in self.vault.entries() if e.get("shared")]
        return {"connected": True, "server_url": state["server_url"], "user": state["user"],
                "fingerprint": fingerprint(state["public_key"], state["signing_public_key"]),
                "device": state.get("device"), "last_sync": state.get("last_sync"),
                "orgs": len(state.get("orgs") or {}), "collections": len(state.get("collections") or {}),
                "shared": len(entries), "pending_changes": sum(1 for e in entries if e["shared"].get("pending_policy")),
                "needs_rekey": sum(1 for c in (state.get("collections") or {}).values() if c.get("needs_rekey")),
                # An account that has not proved its e-mail sees no invites (see verify_email).
                "verified": state["user"].get("verified", True) is not False,
                "verification": state.get("verification") or "email",
                "mail": bool(state.get("mail")),  # the server e-mails invites itself
                "held_deletions": self.held_deletions(),
                "waiting": [{k: p.get(k) for k in ("user_id", "name", "email", "fingerprint", "org", "reason")}
                            | {"collections": len(p.get("collections") or [])}
                            for p in (state.get("waiting") or {}).values()]}

    def held_deletions(self):
        """Deletions a sync did not apply because they were too many at once (2.7): one decision per collection."""
        state = self.vault.team()
        held = []
        for cid, coll in sorted((state.get("collections") or {}).items()):
            items = coll.get("held") or {}
            if not items:
                continue
            by = sorted({i.get("by") or SOMEONE for i in items.values()})
            held.append({"collection": cid, "collection_name": coll.get("name", ""), "count": len(items),
                         "by": by, "gone": bool(coll.get("gone")), "at": max(i.get("at") or "" for i in items.values()),
                         "can_restore": coll.get("permission") in SHARE_WRITE and not coll.get("gone")})
        return held

    def connect(self, server_url, email, password, mode, name="", device_name="", invite_token=None):
        """Link (mode "register") or log in to a team account. The only time the account password is used."""
        base, email = server_base(server_url), str(email or "").strip().lower()
        if mode not in ("register", "login"):
            raise TeamError(tr("teams.say_whether_you_want_create"), "invalid")
        if not email or "@" not in email:
            raise TeamError(tr("teams.type_your_e_mail"), "invalid")
        current = self.vault.team()
        if connected(current) and (current["user"]["email"] != email or current["server_url"] != base):
            raise TeamError(tr("teams.another_team_account_is_already"), "invalid")
        device_name = str(device_name or os.environ.get("COMPUTERNAME") or "PC")[:100]
        with Client(base) as api:
            info = check_server(api.call("GET", "/info", auth=False))
            if mode == "register":
                if len(password or "") < MIN_ACCOUNT_PASSWORD:
                    raise TeamError(tr("teams.account_password_must_have_at", MIN_ACCOUNT_PASSWORD=MIN_ACCOUNT_PASSWORD),
                                    "invalid")
                user_id, kdf, keys = str(uuid.uuid4()), crypto.new_kdf(), new_account_keys()
                auth_key, wrap_key = account_secrets(password, kdf)
                body = {"user_id": user_id, "email": email, "name": str(name or email.split("@")[0]).strip()[:100],
                        "kdf": kdf, "auth_hash": b64(auth_key), **public_keys(keys),
                        "private_blob": seal_private_keys(wrap_key, keys, user_id)}
                if invite_token:
                    body["invite_token"] = str(invite_token).strip()
                api.call("POST", "/accounts/register", body, auth=False)
            else:
                kdf = api.call("POST", "/accounts/prelogin", {"email": email}, auth=False)["kdf"]
                auth_key, wrap_key = account_secrets(password, kdf)
            session = api.call("POST", "/accounts/login", {"email": email, "auth_hash": b64(auth_key),
                                                            "device_name": device_name}, auth=False)
            keys = open_private_keys(wrap_key, session["private_blob"], session["user"]["id"])
            if public_keys(keys) != {"public_key": session["public_key"],
                                     "signing_public_key": session["signing_public_key"]}:
                raise TeamError(tr("teams.account_keys_don_match_server"), "bad_server")
            user = {k: session["user"].get(k) for k in ("id", "email", "name")}
            user["verified"] = session["user"].get("verified", True) is not False  # servers before 0.16: no check
            state = current if connected(current) and current["user"]["id"] == user["id"] else {}
            state.update(server_url=base, token=session["token"], user=user, keys=keys, device=device_name,
                         verification=info.get("verification", "off"), mail=info.get("mail") is True,
                         **public_keys(keys))
            for section in ("pinned", "orgs", "collections"):
                state.setdefault(section, {})
            api.token = session["token"]
            try:  # the people this account verified on its other devices are trusted here at once
                self._sync_account_data(api, state)
            except TeamError as exc:
                print(f"team account data: {detail(exc)}", file=sys.stderr)
        self.vault.set_team(state)
        return self.status()

    # ------------------------------------------------------------------ e-mail verification

    def verify_email(self, code):
        """The code the server e-mailed. Until the address is verified, invites to it are not shown or accepted."""
        state = self.vault.team()
        with self._api(state) as api:
            api.call("POST", "/accounts/verify", {"code": str(code or "").strip()[:20]})
        state["user"]["verified"] = True
        self.vault.set_team(state)
        return self.status()

    def send_code(self):
        """Ask for a new code. {sent} (False when the server has no e-mail: its admin verifies the account)."""
        state = self.vault.team()
        with self._api(state) as api:
            result = api.call("POST", "/accounts/verify/send", {})
        if result.get("verified"):
            state["user"]["verified"] = True
            self.vault.set_team(state)
        return {"sent": bool(result.get("sent")), "verified": bool(result.get("verified")),
                "verification": result.get("verification") or state.get("verification")}

    def _refresh_me(self, api, state):
        """While the e-mail is not verified, each sync asks again (the admin may have verified it meanwhile)."""
        if state["user"].get("verified", True) is not False:
            return
        me = api.call("GET", "/me")
        if (me.get("user") or {}).get("verified"):
            state["user"]["verified"] = True

    # ------------------------------------------------------------------ the account's own data (2.2)

    def _sync_account_data(self, api, state):
        """Pins (the people this account verified) live encrypted on the server for every device of the account:
        verifying someone once is enough. Merged by time (the newest pin of a person wins) and never rolled back."""
        try:
            remote = api.call("GET", "/me/data")
        except TeamError as exc:
            if exc.status in (404, 405):
                return  # a server from before 0.16: pins stay on this PC
            raise
        key, me = _data_key(state["keys"]), state["user"]["id"]
        theirs, counter = {}, int(state.get("data_counter") or 0)
        if remote.get("blob"):
            try:
                data = json.loads(crypto.open_sealed(key, remote["blob"], DATA_AAD + me.encode("utf-8")))
                if int(data.get("counter") or 0) >= counter:
                    theirs, counter = data.get("pinned") or {}, int(data.get("counter") or 0)
            except (InvalidTag, ValueError, KeyError, TypeError):
                print("team account data: unreadable, replaced", file=sys.stderr)
        merged = dict(state.get("pinned") or {})
        for uid, pin in theirs.items():
            try:
                fingerprint(pin["public_key"], pin["signing_public_key"])
            except (KeyError, TypeError, ValueError):
                continue
            if uid != me and (uid not in merged or str(pin.get("at") or "") > str(merged[uid].get("at") or "")):
                merged[uid] = pin
        state["pinned"] = merged
        if merged != theirs:
            blob = crypto.seal(key, _canonical({"pinned": merged, "counter": counter + 1}), DATA_AAD + me.encode("utf-8"))
            try:
                api.call("PUT", "/me/data", {"blob": blob, "base_revision": int(remote.get("revision") or 0)})
                counter += 1
            except TeamError as exc:
                if exc.code != "conflict":
                    raise  # another device wrote first: merged on the next sync
        state["data_counter"] = counter

    def disconnect(self):
        """Forget the account on this PC, and the team's credentials with it (they belong to the team)."""
        state = self.vault.team()
        if connected(state):
            try:
                with Client(state["server_url"], state["token"]) as api:
                    api.call("POST", "/accounts/logout")
            except TeamError:
                pass  # offline or already expired: the token is forgotten anyway
        notes = {"removed": [], "conflicts": []}
        for cid in list(state.get("collections") or {}):
            notes["removed"] += self._drop_collection(state, cid, notes)
        for entry in self.vault.entries():  # anything left without a known collection
            if entry.get("shared"):
                self._leave(entry, False, notes)
        self.vault.set_team({})
        self.vault.set_team_view({})
        self._flush_removed()
        return {"removed": len(notes["removed"]), "kept": len(notes.get("kept", [])) + len(notes["conflicts"])}

    def _api(self, state, timeout=TIMEOUT):
        if not connected(state):
            raise TeamError(tr("teams.no_team_account_is_connected"), "not_connected")
        return Client(state["server_url"], state["token"], timeout)

    def _read(self):
        """The server, for what the user is looking at: short timeouts (READ_TIMEOUT)."""
        return self._api(self.vault.team(), READ_TIMEOUT)

    def _remember(self, key, value, sub=None):
        """Keep what the server said for the Equipo view to draw next time at once. Only this cache is written
        (never the team state): reads run alongside a sync, which owns the state."""
        with self.vault.mutex:
            view = self.vault.team_view()
            target = view.setdefault(key, {}) if sub is not None else view
            name = sub if sub is not None else key
            if target.get(name) != value:
                target[name] = value
                self.vault.set_team_view(view)

    def _me(self, state):
        return {"id": state["user"]["id"], "name": _label(state["user"])}

    # ------------------------------------------------------------------ people and their keys (2.2)

    @staticmethod
    def _fetch_keys(api, uid):
        return Team._keys_of(api.call("GET", f"/users/{uid}/keys"))

    @staticmethod
    def _keys_of(data):
        return {"public_key": data["public_key"], "signing_public_key": data["signing_public_key"],
                "email": data.get("email"), "name": data.get("name"),
                "fp": fingerprint(data["public_key"], data["signing_public_key"])}

    @staticmethod
    def _fetch_many(api, uids):
        """{uid: keys} of several people in one request (servers without it: one by one). Who the server
        does not show is simply missing."""
        uids = list(dict.fromkeys(u for u in uids if u))
        found = {}
        for start in range(0, len(uids), 200):
            chunk = uids[start:start + 200]
            try:
                rows = api.call("GET", "/users/keys?ids=" + ",".join(chunk))
            except TeamError as exc:
                if exc.status not in (404, 405):
                    raise
                rows = []
                for uid in chunk:
                    try:
                        rows.append({"id": uid, **api.call("GET", f"/users/{uid}/keys")})
                    except TeamError as inner:
                        if inner.code in ("offline", "reconnect"):
                            raise
            for row in rows if isinstance(rows, list) else []:
                try:
                    found[row["id"]] = Team._keys_of(row)
                except (KeyError, TypeError, ValueError):
                    continue
        return found

    def _peer_keys(self, api, state, uid, fresh=True):
        """A person's public keys, only once this user trusts them (pinned by confirming or verifying that
        person, or by accepting their invite), and checked against that pinned fingerprint. Keys the server
        hands out are never trusted on first sight: they decide who gets collection keys (2.2)."""
        if uid == state["user"]["id"]:
            return {"public_key": state["public_key"], "signing_public_key": state["signing_public_key"],
                    "email": state["user"]["email"], "name": state["user"]["name"]}
        pinned = state["pinned"].get(uid)
        if not pinned:
            raise self._untrusted(api, uid)
        if not fresh:
            return pinned
        found = self._fetch_keys(api, uid)
        if _pinned_fp(pinned) != found["fp"]:
            raise TeamError(tr("teams.key_has_changed_since_you", _label=_label(found)),
                            "key_changed")
        return pinned

    def _untrusted(self, api, uid, org=None):
        """The error for someone whose key this user has not confirmed yet, with what the app needs to ask."""
        try:
            person = self._fetch_keys(api, uid)
        except TeamError:
            person = {}
        return TeamError(tr("teams.first_verify_security_code_in", _label=_label(person)), "untrusted",
                         data={"user_id": uid, "name": person.get("name"), "email": person.get("email"),
                               "fingerprint": person.get("fp"), "org": org})

    # ------------------------------------------------------------------ organizations

    def orgs(self):
        with self._read() as api:
            rows = api.call("GET", "/orgs")
        self._remember("orgs", rows)
        return rows

    def _refresh_orgs(self, api, state):
        """After a change (create, join): the state learns the org now, not at the next sync."""
        rows = api.call("GET", "/orgs")
        state["orgs"] = {r["id"]: {"name": r["name"], "role": r["role"], "status": r.get("status")} for r in rows}
        self._remember("orgs", rows)

    def create_org(self, name):
        state = self.vault.team()
        with self._api(state) as api:
            oid = api.call("POST", "/orgs", {"name": str(name or "").strip()})["id"]
            self._refresh_orgs(api, state)
        self.vault.set_team(state)
        return {"id": oid}

    def invite(self, oid, email, role="member"):
        """→ {id, emailed, expires?}: `emailed` when the server e-mailed the invite itself (servers before 0.17
        never do: the app gives the admin the instructions to pass on)."""
        with self._api(self.vault.team()) as api:
            result = api.call("POST", f"/orgs/{oid}/invites", {"email": str(email or "").strip(), "role": role})
        return {**result, "emailed": result.get("emailed") is True}

    def renew_invite(self, oid, invite_id):
        """A new code for a pending or expired invite (the old one stops working), e-mailed if the server can.
        → {id, emailed, expires}"""
        with self._api(self.vault.team()) as api:
            result = api.call("POST", f"/orgs/{oid}/invites/{invite_id}/renew", {})
        return {**result, "emailed": result.get("emailed") is True}

    def resend_invite(self, oid, invite_id):
        """E-mail a pending invite again. → {emailed}"""
        with self._api(self.vault.team()) as api:
            result = api.call("POST", f"/orgs/{oid}/invites/{invite_id}/send", {})
        return {"emailed": result.get("emailed") is True}

    def drop_invite(self, invite_id):
        """Withdraw an invite (org admins)."""
        with self._api(self.vault.team()) as api:
            api.call("DELETE", f"/invites/{invite_id}")
        return {}

    def invites(self):
        with self._read() as api:
            rows = api.call("GET", "/invites")
        self._remember("invites", rows)
        return rows

    def accept_invite(self, invite_id):
        """Join an organization. Whoever sent the invite is trusted from now on (their key is pinned): accepting
        it is this user saying they know that person. Anyone else is confirmed by hand (confirm_member)."""
        state = self.vault.team()
        with self._api(state) as api:
            invite = next((i for i in api.call("GET", "/invites") if i.get("id") == invite_id), None)
            api.call("POST", f"/invites/{invite_id}/accept")
            by = (invite or {}).get("invited_by")
            if by and by != state["user"]["id"] and by not in state["pinned"]:
                try:
                    state["pinned"][by] = {**self._fetch_keys(api, by), "at": now_iso()}
                except TeamError:
                    pass  # confirmed by hand later, if they grant anything
            self._refresh_orgs(api, state)
        self.vault.set_team(state)
        return {}

    def members(self, oid):
        """Members with their security codes, whether this user trusts each one (`trusted`: pinned with the
        same code) and whether a pinned key has changed since. Their keys come in one request."""
        state = self.vault.team()
        with self._api(state, READ_TIMEOUT) as api:
            rows = api.call("GET", f"/orgs/{oid}/members")
            keys = self._fetch_many(api, [r.get("user_id") for r in rows])
        for row in rows:
            row["fingerprint"], row["key_changed"], row["trusted"] = None, False, False
            if not row.get("user_id"):
                continue
            row["me"] = row["user_id"] == state["user"]["id"]
            if row["user_id"] not in keys:
                continue
            row["fingerprint"] = keys[row["user_id"]]["fp"]
            pinned = state["pinned"].get(row["user_id"])
            row["key_changed"] = bool(pinned and _pinned_fp(pinned) != row["fingerprint"])
            row["trusted"] = row["me"] or bool(pinned and not row["key_changed"])
        self._remember("members", rows, oid)
        return rows

    def confirm_member(self, oid, uid, expected_fingerprint=None):
        """Trust someone's key on this PC, and let them into the organization if they are waiting for an admin.
        With a fingerprint (typed by this user, as read out by that person) it must match. A key that changed
        since it was pinned is only re-pinned with that typed fingerprint: one click is not enough there."""
        state = self.vault.team()
        with self._api(state) as api:
            row = next((r for r in api.call("GET", f"/orgs/{oid}/members") if r.get("user_id") == uid), None)
            if row is None or row.get("status") not in ("accepted", "confirmed"):
                raise TeamError(tr("teams.that_person_isn_in_organization"), "not_found")
            found = self._fetch_keys(api, uid)
            if expected_fingerprint and not _same_fingerprint(expected_fingerprint, found):
                raise TeamError(tr("teams.security_code_doesn_match_don", _label=_label(found)), "fingerprint_mismatch")
            pinned = state["pinned"].get(uid)
            if pinned and _pinned_fp(pinned) != found["fp"] and not expected_fingerprint:
                raise TeamError(tr("teams.key_has_changed_ask_them", _label=_label(found)), "key_changed")
            if row["status"] == "accepted":
                api.call("POST", f"/orgs/{oid}/members/{uid}/confirm")
            state["pinned"][uid] = {**found, "at": now_iso()}
            state.get("waiting", {}).pop(uid, None)
            try:  # the account's other devices trust them too
                self._sync_account_data(api, state)
            except TeamError as exc:
                print(f"team account data: {detail(exc)}", file=sys.stderr)
        self.vault.set_team(state)
        return {"fingerprint": found["fp"]}

    def set_role(self, oid, uid, role):
        with self._api(self.vault.team()) as api:
            return api.call("PATCH", f"/orgs/{oid}/members/{uid}", {"role": role})

    def remove_member(self, oid, uid):
        """Take someone out of the organization, then re-key every collection they could read that this user
        manages (2.4). The others are re-keyed by their managers on their next sync.

        Once the server has let them go, nothing here raises: a collection that cannot be re-encrypted now
        (offline, someone to verify first…) stays `needs_rekey` and the next sync does it; what was done is
        always saved. Every credential they could see is flagged to rotate straight away."""
        state = self.vault.team()
        with self._api(state) as api:
            person = self._person(api, state, oid, uid)
            result = api.call("DELETE", f"/orgs/{oid}/members/{uid}")
            if uid == state["user"]["id"]:
                # Leaving on purpose: its credentials go now (a sync would hold them as a mass deletion, 2.7).
                for cid in [c for c, coll in state["collections"].items() if coll.get("org") == oid]:
                    self._drop_collection(state, cid)
                self.vault.set_team(state)
                self._flush_removed()
                return {"left": True, "rekeyed": [], "pending": result.get("needs_rekey") or [], "failed": []}
            # The server's list, plus every collection this PC knows they were in: an empty or short answer
            # must not leave them with a working key.
            known = [cid for cid, c in sorted(state["collections"].items())
                     if c.get("org") == oid and uid in (c.get("members") or {})]
            cids = list(dict.fromkeys([*(result.get("needs_rekey") or []), *known]))
            try:
                rekeyed, pending, failed = self._rekey_after(api, state, cids, [person], [uid])
            finally:
                self.vault.set_team(state)
        for cid in cids:
            if cid not in rekeyed and cid in state["collections"]:
                self._flag(cid, [person])  # re-keyed ones were flagged by _rekey
        flagged = sum(1 for e in self.vault.entries() if (e.get("shared") or {}).get("collection") in cids)
        return {"rekeyed": rekeyed, "pending": pending, "failed": [cid for cid, _ in failed],
                "offline": any(code in ("offline", "reconnect") for _, code in failed),
                "person": person, "credentials": flagged}

    def _person(self, api, state, oid, uid):
        try:
            rows = api.call("GET", f"/orgs/{oid}/members")
            row = next((r for r in rows if r.get("user_id") == uid), None)
        except TeamError:
            row = None
        return _label(row or state["pinned"].get(uid))

    def _rekey_after(self, api, state, cids, people, removed):
        """(re-keyed, left to their managers, failed here: the next sync retries them)."""
        rekeyed, pending, failed = [], [], []
        for cid in cids:
            coll = state["collections"].get(cid)
            if not (coll and coll.get("permission") == "manage"):
                pending.append(cid)
                continue
            if failed and failed[-1][1] in ("offline", "reconnect"):
                failed.append((cid, failed[-1][1]))  # no point trying the others now
                continue
            try:
                self._rekey(api, state, cid, people, removed)
            except TeamError as exc:
                if exc.code == "not_found":
                    pending.append(cid)  # gone from the server meanwhile: the next sync drops it here
                    continue
                print(f"team re-key after removal: {cid} {detail(exc)}", file=sys.stderr)
                coll["needs_rekey"] = True
                failed.append((cid, exc.code))
                continue
            rekeyed.append(cid)
        return rekeyed, pending, failed

    def events(self, oid, before=None):
        with self._read() as api:
            rows = api.call("GET", f"/orgs/{oid}/events" + (f"?before={int(before)}" if before else ""))
        if not before:
            self._remember("events", rows[:50], oid)
        return rows

    # ------------------------------------------------------------------ collections

    def collections(self):
        state = self.vault.team()
        counts = {}
        for entry in self.vault.entries():
            if entry.get("shared"):
                counts[entry["shared"]["collection"]] = counts.get(entry["shared"]["collection"], 0) + 1
        orgs = state.get("orgs") or {}

        def managers(c):
            signed = (c.get("manifest") or {}).get("members")
            listed = signed if signed is not None else {u: m.get("permission") for u, m in (c.get("members") or {}).items()}
            return sum(1 for p in listed.values() if p == "manage")
        return sorted(({"id": cid, "org": c.get("org"), "org_name": (orgs.get(c.get("org")) or {}).get("name", ""),
                        "name": c.get("name", ""), "permission": c.get("permission"),
                        "key_version": c.get("key_version"), "needs_rekey": bool(c.get("needs_rekey")),
                        "entries": counts.get(cid, 0), "managers": managers(c),
                        # Only one person can re-key it or let others in: if they go, it is stuck (2.6).
                        "single_manager": managers(c) == 1, "signed": bool(c.get("manifest")),
                        "gone": bool(c.get("gone"))}
                       for cid, c in (state.get("collections") or {}).items()),
                      key=lambda c: (c["org_name"].lower(), c["name"].lower()))

    def create_collection(self, oid, name):
        """A new collection with its first signed member list; the organization's owners get access to it at once
        (if this user verified them), so it can always be recovered (2.6)."""
        name = str(name or "").strip()
        if not name:
            raise TeamError(tr("teams.give_collection_name"), "invalid")
        state = self.vault.team()
        cid, key, me = str(uuid.uuid4()), os.urandom(32), state["user"]["id"]
        record = make_members_record(state["keys"], me, cid, None, {me: "manage"}, 1)
        with self._api(state) as api:
            grant = make_grant(state["keys"], me, cid, 1, me, state["public_key"], key)
            api.call("POST", f"/orgs/{oid}/collections",
                     {"id": cid, "encrypted_name": seal_name(key, cid, {"name": name}), "grant": grant,
                      "members_record": record})
            state["collections"][cid] = {
                "org": oid, "name": name, "keys": {"1": b64(key)}, "key_version": 1, "permission": "manage",
                "revision": 0, "needs_rekey": False, "items": {},
                "members": {me: {"name": _label(state["user"]), "permission": "manage"}},
                "manifest": self._head(record)}
            self.vault.set_team(state)
            try:
                self._recover_access(api, state, {"recovery": []}, {}, only=[cid])
            except TeamError as exc:
                print(f"team owners' access: {detail(exc)}", file=sys.stderr)  # the next sync tries again
        self.vault.set_team(state)
        return {"id": cid}

    def collection_members(self, cid):
        with self._read() as api:
            rows = api.call("GET", f"/collections/{cid}/members")
        self._remember("collection_members", rows, cid)
        return rows

    def overview(self):
        """Everything the Equipo view draws, from this PC only (no network): what the server said last time.
        The view then asks the server (short timeouts) and redraws if anything changed."""
        state, view = self.vault.team(), self.vault.team_view()
        orgs = view.get("orgs")
        if orgs is None:  # nothing cached yet: what the last sync learned
            orgs = [{"id": oid, **o} for oid, o in (state.get("orgs") or {}).items()]
        members = dict(view.get("members") or {})
        for cid, coll in (state.get("collections") or {}).items():  # until asked: who the last sync saw
            view.setdefault("collection_members", {}).setdefault(
                cid, [{"user_id": uid, "name": m.get("name"), "email": None, "permission": m.get("permission")}
                      for uid, m in (coll.get("members") or {}).items()])
        return {"status": self.status(), "orgs": orgs, "invites": view.get("invites") or [],
                "collections": self.collections(), "members": members, "events": view.get("events") or {},
                "collection_members": view.get("collection_members") or {}, "unsent": self.unsent(),
                "offboarding": self.offboarding()}

    def unsent(self):
        """{entry id: why} for shared credentials changed here and not on the server yet: "rekey" while their
        collection waits to be re-encrypted (they go out after it), "pending" otherwise (next sync)."""
        state = self.vault.team()
        found = {}
        for entry in self.vault.entries():
            shared = entry.get("shared") or {}
            coll = (state.get("collections") or {}).get(shared.get("collection"))
            if not shared or not coll:
                continue
            known = (coll.get("items") or {}).get(shared.get("item"))
            if known is None or known.get("hash") != content_hash(effective_content(entry)):
                found[entry["id"]] = "rekey" if coll.get("needs_rekey") else "pending"
        return found

    def offboarding(self):
        """Per person who left: how many credentials they could see and which still have to be changed
        (`shared.rotate`, see _flag). A credential counts as changed once its secret is not the one they saw."""
        people = {}
        for entry in self.vault.entries():
            rotate = (entry.get("shared") or {}).get("rotate")
            if not rotate:
                continue
            current = rotate.get("fp") == secret_fp(self.vault, entry)
            for name in sorted(set(rotate.get("people") or []) | set(rotate.get("seen") or [])):
                person = people.setdefault(name, {"person": name, "since": rotate.get("since"), "total": 0,
                                                  "pending": []})
                person["total"] += 1
                person["since"] = min(filter(None, (person["since"], rotate.get("since"))), default=None)
                if current and name in (rotate.get("people") or []):
                    person["pending"].append(entry["id"])
        return sorted(people.values(), key=lambda p: p["since"] or "", reverse=True)

    def _collection(self, state, cid, permissions=SHARE_PERMISSIONS):
        coll = (state.get("collections") or {}).get(cid)
        if not coll:
            raise TeamError(tr("teams.that_collection_doesn_exist_or"), "not_found")
        if coll.get("permission") not in permissions:
            raise TeamError(tr("teams.your_permission_in_this_collection"), "forbidden")
        return coll

    def grant(self, cid, uid, permission):
        """Give someone access to a collection (sealing its key to their pinned key), or change their permission."""
        if permission not in SHARE_PERMISSIONS:
            raise TeamError(tr("service.invalid_permission"), "invalid")
        state = self.vault.team()
        self._collection(state, cid, ("manage",))
        with self._api(state) as api:
            self._grant(api, state, cid, uid, permission)
        self.vault.set_team(state)
        self._refresh_entries(state, cid)
        return {}

    def _grant(self, api, state, cid, uid, permission):
        """The grant itself, with the new signed member list (2.6)."""
        coll = state["collections"][cid]
        for attempt in range(2):
            if not self._verify_members(api, state, cid, coll):
                self._rekey(api, state, cid, [])  # a collection from before 0.16: sign its member list first
            record, rows = self._next_members(api, state, cid, coll, {uid: permission})
            body = {"permission": permission, "members_record": record}
            if uid not in {r["user_id"] for r in rows}:
                peer = self._peer_keys(api, state, uid)
                body["grant"] = make_grant(state["keys"], state["user"]["id"], cid, coll["key_version"], uid,
                                           peer["public_key"], unb64(coll["keys"][str(coll["key_version"])]))
            try:
                api.call("PUT", f"/collections/{cid}/members/{uid}", body)
                break
            except TeamError as exc:
                if exc.code not in ("needs_rekey", "members_record") or attempt:
                    raise
                if exc.code == "needs_rekey":
                    self._rekey(api, state, cid, *self._gone(api, state, cid))
        coll["manifest"] = self._head(record, coll.get("manifest"))
        coll.setdefault("members", {})[uid] = {"name": _label(state["pinned"].get(uid)), "permission": permission}

    def revoke(self, cid, uid):
        """Take someone out of a collection and re-key it: they keep nothing that changes from now on."""
        state = self.vault.team()
        coll = self._collection(state, cid)
        me = state["user"]["id"]
        if uid != me and coll.get("permission") != "manage":
            raise TeamError(tr("teams.only_whoever_manages_collection_can"), "forbidden")
        with self._api(state) as api:
            person = _label((coll.get("members") or {}).get(uid) or state["pinned"].get(uid))
            body = {}
            if self._verify_members(api, state, cid, coll):
                body["members_record"] = self._next_members(api, state, cid, coll, {uid: None})[0]
            api.call("DELETE", f"/collections/{cid}/members/{uid}", body or None)
            if body:
                coll["manifest"] = self._head(body["members_record"], coll.get("manifest"))
            (coll.get("members") or {}).pop(uid, None)
            if uid == me:
                self._drop_collection(state, cid)
            else:
                self._rekey(api, state, cid, [person], [uid])
        self.vault.set_team(state)
        self._flush_removed()
        return {}

    def _gone(self, api, state, cid):
        """Who left a collection since this PC last looked: (names for the 'rotate because…' reminder, ids)."""
        coll = state["collections"][cid]
        current = {r["user_id"] for r in api.call("GET", f"/collections/{cid}/members")}
        signed = (coll.get("manifest") or {}).get("members") or {}
        known = {**{uid: {"name": None} for uid in signed}, **(coll.get("members") or {})}
        gone = {uid: m for uid, m in known.items() if uid not in current}
        return sorted({_label(m) for m in gone.values()}) or [SOMEONE], sorted(gone)

    # ------------------------------------------------------------------ signed member lists (2.6)

    def _signer(self, state, uid):
        """The keys whose signatures this user accepts: their own, and people they verified (pinned)."""
        if uid == state["user"]["id"]:
            return {"signing_public_key": state["signing_public_key"], "name": _label(state["user"])}
        return (state.get("pinned") or {}).get(uid)

    @staticmethod
    def _head(record, previous=None):
        """What this client keeps of the last verified member list. `writers`: everyone who could write items
        with the current collection key (a re-key starts it again), whose signed items are therefore accepted."""
        body = record["body"]
        writers = {u for u, p in body["members"].items() if p in SHARE_WRITE}
        if previous and previous.get("key_version") == body["key_version"]:
            writers |= set(previous.get("writers") or [])
        return {"seq": body["seq"], "hash": members_hash(body), "members": dict(body["members"]), "by": body["by"],
                "key_version": body["key_version"], "at": body.get("at"), "writers": sorted(writers)}

    def _verify_members(self, api, state, cid, coll, org=None):
        """Extend the verified member list with the server's new links, each signed by someone this user trusts
        who managed the collection before it (or who only takes themselves out). Returns the head, or None for
        a collection from before 0.16 that has no signed list yet. A broken chain raises: nothing is used."""
        head = coll.get("manifest")
        try:
            records = api.call("GET", f"/collections/{cid}/manifest?since={head['seq'] if head else 0}")["records"]
        except TeamError as exc:
            if exc.status in (404, 405) and not head:
                return None  # a server from before 0.16
            raise
        if not isinstance(records, list):
            raise TeamError(tr("teams.invalid_member_list"), "bad_members")
        me, org = state["user"]["id"], org or coll.get("org")
        start = 0
        if head is None and records:
            # First look at this list: start from the newest link signed by someone trusted here who manages it
            # (who let this user in, normally). Links after it must all check out.
            trusted = [i for i, r in enumerate(records) if isinstance(r, dict) and isinstance(r.get("body"), dict)
                       and self._signer(state, r["body"].get("by"))
                       and (r["body"].get("members") or {}).get(r["body"].get("by")) == "manage"]
            if not trusted:
                last = records[-1].get("body") if isinstance(records[-1], dict) else None
                raise self._untrusted(api, (last or {}).get("by"), org) if isinstance(last, dict) and \
                    isinstance(last.get("by"), str) else TeamError(tr("teams.invalid_member_list"), "bad_members")
            start = trusted[-1]
            legacy = coll.get("members") or {}
            body = records[start]["body"]
            if legacy and (legacy.get(body["by"]) or {}).get("permission") not in (None, "manage"):
                raise TeamError(tr("teams.member_list_signed_by_someone"), "bad_members")
        for index, record in enumerate(records[start:]):
            body = record.get("body") if isinstance(record, dict) else None
            first = head is None and index == 0
            if not isinstance(body, dict) or body.get("cid") != cid or not isinstance(body.get("members"), dict) \
                    or not all(p in SHARE_PERMISSIONS for p in body["members"].values()) \
                    or not isinstance(body.get("seq"), int) or not isinstance(body.get("key_version"), int) \
                    or (not first and (body["seq"] != head["seq"] + 1 or body.get("prev") != head["hash"]
                                       or body["key_version"] < head["key_version"])):
                raise TeamError(tr("teams.invalid_member_list"), "bad_members")
            by = body.get("by")
            signer = self._signer(state, by)
            if signer is None:
                raise self._untrusted(api, by, org)
            if not signed_by(signer["signing_public_key"], record.get("signature"), MEMBERS_SIG + _canonical(body)):
                raise TeamError(tr("teams.member_list_with_invalid_signature"), "bad_members")
            before = body["members"] if first else head["members"]
            leaving = by not in body["members"] and all(before.get(u) == p for u, p in body["members"].items())
            if before.get(by) != "manage" and not leaving:
                raise TeamError(tr("teams.member_list_signed_by_someone_2"), "bad_members")
            head = self._head(record, None if first else head)
        coll["manifest"] = head
        if head and me not in head["members"]:
            raise TeamError(tr("teams.you_re_no_longer_on"), "bad_members")
        return head

    def _signed_rows(self, coll, rows):
        """The server's member list, refused if it has anyone (or any permission) the signed list does not.
        People missing from it were taken out of the organization: the next re-key signs the list without them."""
        head = coll.get("manifest")
        if not head:
            return rows
        extra = [r for r in rows if head["members"].get(r.get("user_id")) != r.get("permission")]
        if extra:
            raise TeamError(tr("teams.server_shows_unsigned", people=", ".join(_label(r) for r in extra[:5])), "bad_members",
                            data={"people": [r.get("user_id") for r in extra]})
        return rows

    def _next_members(self, api, state, cid, coll, update):
        """(The signed list after a change, the server's current rows). The change applies to the server's
        members (checked against the verified list): {uid: permission, or None to take them out}."""
        rows = self._signed_rows(coll, api.call("GET", f"/collections/{cid}/members"))
        members = {r["user_id"]: r["permission"] for r in rows}
        for uid, permission in update.items():
            if permission is None:
                members.pop(uid, None)
            else:
                members[uid] = permission
        record = make_members_record(state["keys"], state["user"]["id"], cid, coll.get("manifest"), members,
                                     coll["key_version"])
        return record, rows

    def _recover_access(self, api, state, notes, waiting, only=None):
        """Owners of the organization get `manage` on every collection this user manages, so a collection is never
        stuck if its only manager leaves (like an organization owner in other managers, but zero knowledge: each
        owner gets a signed key grant). Only owners this user verified; the others wait to be verified."""
        me = state["user"]["id"]
        mine = {cid: c for cid, c in (state.get("collections") or {}).items()
                if (only is None or cid in only) and c.get("permission") == "manage" and c.get("manifest")
                and not c.get("gone") and not c.get("needs_rekey")}
        for oid in sorted({c.get("org") for c in mine.values()}):
            try:
                rows = api.call("GET", f"/orgs/{oid}/members")
            except TeamError as exc:
                if exc.code in ("offline", "reconnect"):
                    raise
                continue
            owners = [r for r in rows if r.get("role") == "owner" and r.get("status") == "confirmed"
                      and r.get("user_id") and r["user_id"] != me]
            for cid, coll in sorted(mine.items()):
                if coll.get("org") != oid:
                    continue
                for owner in owners:
                    uid = owner["user_id"]
                    if coll["manifest"]["members"].get(uid) == "manage":
                        continue
                    if uid not in (state.get("pinned") or {}):
                        if uid not in waiting:
                            waiting[uid] = {**self._untrusted(api, uid, oid).data, "reason": "recovery",
                                            "collections": []}
                        waiting[uid]["collections"].append(cid)
                        continue
                    try:
                        self._grant(api, state, cid, uid, "manage")
                        notes.setdefault("recovery", []).append({"collection": coll.get("name"), "person": _label(owner)})
                    except TeamError as exc:
                        if exc.code in ("offline", "reconnect"):
                            raise
                        print(f"team owners' access: {cid} {detail(exc)}", file=sys.stderr)

    def _item_signer(self, state, cid, iid, plain, head):
        """Who signed this version of an item, if the signature is valid and they could write with this key."""
        sig = plain.get("sig")
        if not isinstance(sig, dict) or not head:
            return None
        by = sig.get("by")
        signer = self._signer(state, by)
        if signer is None or by not in (head.get("writers") or []):
            return None
        message = _item_message(cid, iid, _seq(plain), plain.get("entry"), by, plain.get("updated"))
        return by if signed_by(signer["signing_public_key"], sig.get("signature"), message) else None

    def _rekey(self, api, state, cid, people, removed=()):
        """A new collection key, every live item re-encrypted and a grant per remaining member, in one atomic call,
        with the new signed member list; then every credential in it is flagged 'rotate because <people> had
        access' (2.4). Items signed by someone who can no longer write (or not at all: before 0.16) are signed
        again by this manager, who vouches for the content they already have.

        The member list comes from the server and must match the signed one, so the new key is only sealed to
        people this user trusts (_peer_keys refuses anyone not confirmed on this PC), never to someone just removed."""
        coll = state["collections"][cid]
        me = state["user"]["id"]
        for attempt in range(2):
            listed = next((c for c in api.call("GET", "/collections") if c["id"] == cid), None)
            if listed is None:
                raise TeamError(tr("teams.you_no_longer_have_access"), "not_found")
            head = self._verify_members(api, state, cid, coll, listed.get("org_id"))
            self._learn_key(api, state, coll, cid, listed)
            data = api.call("GET", f"/collections/{cid}/items?since=0")
            live = {}
            for item in data["items"]:
                if not item["deleted"]:
                    live[item["id"]] = open_item(self._key(coll, item["key_version"]), cid, item["id"],
                                                 item["key_version"], item["ciphertext"])
            members = self._signed_rows(coll, api.call("GET", f"/collections/{cid}/members"))
            if any(m["user_id"] in removed for m in members):
                raise TeamError(tr("teams.server_still_gives_access_person"),
                                "bad_server")
            version, key = listed["key_version"] + 1, os.urandom(32)
            grants = {m["user_id"]: make_grant(state["keys"], me, cid, version, m["user_id"],
                                               self._peer_keys(api, state, m["user_id"])["public_key"], key)
                      for m in members}
            record = make_members_record(state["keys"], me, cid, head, {m["user_id"]: m["permission"] for m in members},
                                         version)
            future = self._head(record)
            for iid, plain in live.items():
                if self._item_signer(state, cid, iid, plain, future) is None:
                    live[iid] = sign_item(state["keys"], me, cid, iid, plain)
            body = {"key_version": version, "grants": grants, "members_record": record,
                    "encrypted_name": seal_name(key, cid, {"name": coll.get("name", ""), "removed": people,
                                                           "version": version}),
                    "items": {iid: seal_item(key, cid, iid, version, plain) for iid, plain in live.items()}}
            try:
                api.call("POST", f"/collections/{cid}/rotate", body)
                break
            except TeamError as exc:
                if exc.code not in ("incomplete", "key_version", "members_record") or attempt:
                    raise
        coll["keys"] = {str(version): b64(key)}
        coll.update(key_version=version, needs_rekey=False, manifest=future,
                    members={m["user_id"]: {"name": _label(m), "permission": m["permission"]} for m in members})
        if people:
            self._flag(cid, people)
        return version

    def _learn_key(self, api, state, coll, cid, listed):
        """The collection's current key. A new one is only taken from a grant signed by this user or by someone
        they trust who manages the collection (by the signed member list, 2.6); anything else (a key the server
        made up, an old version served again) is refused. Older keys are dropped: nothing may be read or written
        with them again."""
        version, me = listed["key_version"], state["user"]["id"]
        if str(version) not in coll.setdefault("keys", {}):
            if version < int(coll.get("key_version") or 0):
                raise TeamError(tr("teams.server_offers_old_key_collection"), "bad_grant")
            granter_id = listed["grant"]["granted_by"]
            granter = self._peer_keys(api, state, granter_id, fresh=False) if granter_id == me else \
                state["pinned"].get(granter_id)
            if granter is None:
                raise self._untrusted(api, granter_id, listed.get("org_id"))
            head = coll.get("manifest")
            manages = head["members"].get(granter_id) == "manage" if head else any(
                m["user_id"] == granter_id and m["permission"] == "manage"
                for m in api.call("GET", f"/collections/{cid}/members"))
            if granter_id != me and not manages:
                raise TeamError(tr("teams.collection_key_is_signed_by"), "bad_grant")
            key = open_grant(state["keys"], me, cid, version, listed["grant"], granter["signing_public_key"])
            coll["keys"] = {str(version): b64(key)}
        return unb64(coll["keys"][str(version)])

    @staticmethod
    def _key(coll, version):
        try:
            return unb64(coll["keys"][str(version)])
        except KeyError:
            raise TeamError(tr("teams.key_old_version_collection_is"), "missing_key") from None

    # ------------------------------------------------------------------ sharing entries

    def share_entry(self, entry_id, cid):
        entry = self.vault.get(entry_id)
        if entry.get("shared"):
            raise TeamError(tr("teams.this_credential_is_already_shared"), "invalid")
        if entry.get("draft"):
            raise TeamError(tr("teams.add_key_before_sharing_it"), "invalid")
        state = self.vault.team()
        coll = self._collection(state, cid, SHARE_WRITE)
        with self._api(state) as api:
            if coll.get("needs_rekey"):
                if coll.get("permission") != "manage":
                    raise TeamError(tr("teams.this_collection_has_be_re"), "needs_rekey")
                self._rekey(api, state, cid, *self._gone(api, state, cid))
            iid, content = str(uuid.uuid4()), shared_content(entry)
            plain = sign_item(state["keys"], state["user"]["id"], cid, iid,
                              {"entry": content, "author": self._me(state), "updated": now_iso(), "seq": 1})
            revision = api.call("PUT", f"/collections/{cid}/items/{iid}", {
                "ciphertext": seal_item(self._key(coll, coll["key_version"]), cid, iid, coll["key_version"], plain),
                "key_version": coll["key_version"], "base_revision": 0})["revision"]
        coll["items"][iid] = {"revision": revision, "hash": content_hash(content), "content": content, "seq": 1}
        with self.vault.mutex:
            entry = self.vault.get(entry_id)
            # `own`: it was this user's before it was shared, so it stays here if the collection goes away.
            entry["shared"] = {**self._shared_block(state, cid, iid, revision, self._me(state), plain["updated"]),
                               "own": True}
            self.vault.put(entry, replaces=entry_id)
        self.vault.set_team(state)
        return {"item": iid, "collection": cid, "collection_name": coll.get("name", "")}

    def share_entries(self, entry_ids, cid):
        """Share several credentials in one go. Each one is shared or not on its own: {shared, failed}."""
        shared, failed, name, stop = [], [], "", None
        for entry_id in list(dict.fromkeys(entry_ids or [])):
            if stop is not None:  # the server or the collection is gone: the rest would fail the same way
                failed.append({"id": entry_id, "error": str(stop)})
                continue
            try:
                name = self.share_entry(entry_id, cid)["collection_name"]
                shared.append(entry_id)
            except KeyError:
                failed.append({"id": entry_id, "error": tr("teams.it_no_longer_exists")})
            except TeamError as exc:
                if exc.code in ("offline", "reconnect", "not_found", "forbidden", "needs_rekey"):
                    if not shared:
                        raise
                    stop = exc
                failed.append({"id": entry_id, "error": str(exc)})
        return {"shared": shared, "failed": failed, "collection_name": name}

    def unshare_entry(self, entry_id):
        """Take a credential out of its collection for everyone; this PC keeps it as a personal one."""
        entry = self.vault.get(entry_id)
        shared = entry.get("shared")
        if not shared:
            raise TeamError(tr("teams.this_credential_isn_shared"), "invalid")
        state = self.vault.team()
        cid = shared["collection"]
        coll = self._collection(state, cid, SHARE_WRITE)
        known = coll["items"].get(shared["item"]) or {}
        with self._api(state) as api:
            try:
                api.call("DELETE", f"/collections/{cid}/items/{shared['item']}",
                         {"base_revision": known.get("revision", shared.get("revision", 0)),
                          "deletion": make_deletion(state["keys"], state["user"]["id"], cid, shared["item"],
                                                    known.get("seq", 0) + 1)})
            except TeamError as exc:
                if exc.code != "not_found":
                    raise
        coll["items"].pop(shared["item"], None)
        with self.vault.mutex:
            entry = self.vault.get(entry_id)
            entry.pop("shared", None)
            self.vault.put(entry, replaces=entry_id)
        self.vault.set_team(state)
        return {"collection_name": coll.get("name", "")}

    def accept_change(self, entry_id, accept=True):
        """Apply (or turn down) a teammate's change to where a shared key can go (2.5)."""
        with self.vault.mutex:
            entry = self.vault.get(entry_id)
            shared = entry.get("shared") or {}
            pending = shared.get("pending_policy")
            if not pending:
                raise TeamError(tr("teams.this_credential_has_no_pending"), "not_found")
            if not accept and shared.get("permission") not in SHARE_WRITE:
                raise TeamError(tr("teams.only_someone_who_can_edit"), "forbidden")
            if accept:
                approval = (entry.get("policy") or {}).get("approval", "session")
                entry = {**effective_content(entry), "id": entry["id"], "shared": shared}
                entry["policy"] = {**(entry.get("policy") or {}), "approval": approval}
            shared.pop("pending_policy", None)
            entry["shared"] = shared
            self.vault.put(entry, replaces=entry_id)
            return {"accepted": bool(accept), "changes": pending.get("changes") or []}

    def _shared_block(self, state, cid, iid, revision, author, changed):
        coll = state["collections"][cid]
        return {"org": coll["org"], "org_name": ((state.get("orgs") or {}).get(coll["org"]) or {}).get("name", ""),
                "collection": cid, "collection_name": coll.get("name", ""), "item": iid, "revision": revision,
                "permission": coll["permission"], "author": author, "changed": changed}

    # ------------------------------------------------------------------ sync (3)

    def sync(self):
        """Pull every collection, push local changes, re-key where needed. Returns what happened."""
        notes = {"added": [], "updated": [], "removed": [], "conflicts": [], "quarantined": [], "pushed": [],
                 "rotate": [], "trust": [], "held": [], "errors": [], "unsigned": [], "held_deletions": [],
                 "recovery": [], "changes": []}
        state = self.vault.team()
        self._freed = set()
        waiting = {}
        with self._api(state) as api:
            # Each round: a server updated (or replaced by an older one) since, or an app too old for it, is
            # told plainly instead of failing on the first signed member list.
            info = check_server(api.call("GET", "/info", auth=False))
            state["mail"] = info.get("mail") is True
            self._refresh_me(api, state)
            try:
                self._sync_account_data(api, state)
            except TeamError as exc:
                if exc.code in ("offline", "reconnect"):
                    raise
                print(f"team account data: {detail(exc)}", file=sys.stderr)  # pins stay as they are here
            state["orgs"] = {r["id"]: {"name": r["name"], "role": r["role"], "status": r.get("status")}
                             for r in api.call("GET", "/orgs")}
            listed = api.call("GET", "/collections")
            for row in listed:
                try:
                    self._sync_collection(api, state, row, notes)
                except TeamError as exc:
                    if exc.code in ("reconnect", "offline"):
                        raise
                    if exc.code == "untrusted":
                        # A key or member list from (or for) someone not confirmed here: the user confirms them first.
                        person = waiting.setdefault(exc.data["user_id"], {**exc.data, "collections": []})
                        person["org"] = person.get("org") or row.get("org_id")
                        person["collections"].append(row["id"])
                        if len(person["collections"]) == 1:
                            notes["trust"].append(_label(person))
                    else:
                        self._sync_error(notes, row["id"], (state["collections"].get(row["id"]) or {}).get("name"), exc)
                except (InvalidTag, ValueError, KeyError, TypeError) as exc:
                    self._sync_error(notes, row["id"], (state["collections"].get(row["id"]) or {}).get("name"), exc)
                self.vault.set_team(state)
            for cid in [cid for cid in state["collections"] if cid not in {r["id"] for r in listed}]:
                notes["removed"] += self._collection_gone(state, cid, notes)
            self._recover_access(api, state, notes, waiting)
            for data in notes.pop("trust_later", []):
                person = waiting.setdefault(data["user_id"], {**data, "collections": []})
                person.pop("collection", None)
                person["collections"].append(data["collection"])
        state["waiting"] = waiting
        state["last_sync"] = now_iso()
        self.vault.set_team(state)
        self._flush_removed()
        return notes

    @staticmethod
    def _sync_error(notes, cid, name, exc):
        """One sentence for the user (once per kind of problem), the details for the log."""
        print(f"team sync: collection {cid}: {detail(exc)}", file=sys.stderr)
        text = explain(exc, name or "una colección")
        if text not in notes["errors"]:
            notes["errors"].append(text)

    def _sync_collection(self, api, state, row, notes):
        cid = row["id"]
        coll = state["collections"].get(cid)
        first = coll is None
        coll = copy.deepcopy(coll) if coll else {"items": {}, "revision": 0, "keys": {}, "members": {}}
        # The signed member list first (2.6): it says whose key grants and item signatures count.
        head = self._verify_members(api, state, cid, coll, row.get("org_id"))
        key = self._learn_key(api, state, coll, cid, row)
        info = open_name(key, cid, row["encrypted_name"])
        removed = info.get("removed") if not first and row["key_version"] > coll.get("key_version", 0) \
            and info.get("version") == row["key_version"] else None
        # Nobody (and no permission) the signed list does not have: checked before anything here changes.
        rows = self._signed_rows(coll, api.call("GET", f"/collections/{cid}/members"))
        if head and head["members"].get(state["user"]["id"]) != row["permission"]:
            raise TeamError(tr("teams.own_permission_that_nobody_has"), "bad_members")
        coll.update(org=row["org_id"], name=str(info.get("name") or ""), key_version=row["key_version"],
                    permission=row["permission"], needs_rekey=bool(row["needs_rekey"]))
        if coll.pop("gone", None):  # listed again: what was held because it had disappeared stays
            self._release_held(state, cid, coll)
        state["collections"][cid] = coll
        signed_gone = bool(head) and any(uid not in {r["user_id"] for r in rows} for uid in head["members"])
        rekeyed = False
        if coll["permission"] == "manage" and (coll["needs_rekey"] or signed_gone):
            # Someone left (the server says so, or the signed list has someone the server no longer lists). Safe
            # even if the server asked for it falsely: the new key only goes to people trusted here.
            self._pull(api, state, cid, notes)
            people, gone = self._gone(api, state, cid)
            self._rekey(api, state, cid, people, gone)
            notes["rotate"].append({"collection": coll["name"], "people": people})
            rekeyed = True
        elif coll["permission"] == "manage" and not head:
            # A collection from before 0.16: its manager signs the member list (and its items) with a re-key.
            # Until everyone in it is verified here it keeps working as before.
            self._pull(api, state, cid, notes)
            try:
                self._rekey(api, state, cid, [])
                rekeyed = True
            except TeamError as exc:
                if exc.code != "untrusted":
                    raise
                notes.setdefault("trust_later", []).append({**exc.data, "collection": cid})
        if not rekeyed:
            coll["members"] = {m["user_id"]: {"name": _label(m), "permission": m["permission"]} for m in rows}
        self._pull(api, state, cid, notes)
        if removed:
            people = [str(p)[:100] for p in removed if isinstance(p, str)][:20] or [SOMEONE]
            self._flag(cid, people)
            notes["rotate"].append({"collection": coll["name"], "people": people})
        if coll["permission"] in SHARE_WRITE:
            self._push(api, state, cid, notes)
        self._refresh_entries(state, cid)

    def _local_index(self, cid):
        return {e["shared"]["item"]: e["id"] for e in self.vault.entries()
                if (e.get("shared") or {}).get("collection") == cid}

    def _pull(self, api, state, cid, notes):
        """Apply what changed on the server. Deletions are checked first (signed by someone who can edit) and,
        if they are too many at once, held for the user to decide (2.7) instead of applied."""
        coll = state["collections"][cid]
        data = api.call("GET", f"/collections/{cid}/items?since={int(coll.get('revision') or 0)}")
        deletions = []
        for item in data["items"]:
            try:
                if item["deleted"]:
                    found = self._check_deletion(state, cid, item, notes)
                    if found:
                        deletions.append(found)
                else:
                    self._apply(state, cid, item, notes)
            except (TeamError, ValidationError, InvalidTag, ValueError, KeyError, TypeError) as exc:
                self._sync_error(notes, cid, coll.get("name"), exc)
        if deletions and _mass(len(deletions), len(coll["items"])):
            self._hold(state, cid, deletions, notes)
        else:
            for found in deletions:
                self._delete(state, cid, found, notes)
        coll["revision"] = max(int(coll.get("revision") or 0), int(data["revision"]))

    def _name_of(self, state, coll, uid):
        if uid and uid == state["user"]["id"]:
            return _label(state["user"])
        return _label((state.get("pinned") or {}).get(uid) or (coll.get("members") or {}).get(uid))

    def _check_deletion(self, state, cid, item, notes):
        """A tombstone for a credential this PC has: what to delete, if someone who can edit signed it with a
        newer write counter than this PC knows. Anything else is ignored (the credential stays) and reported."""
        coll, iid = state["collections"][cid], item["id"]
        known = coll["items"].get(iid)
        local_id = self._local_index(cid).get(iid)
        if local_id is None:
            coll["items"].pop(iid, None)  # never had it, or deleted here too
            return None
        if iid in (coll.get("held") or {}):
            return None
        record, head = item.get("deletion"), coll.get("manifest")
        writers = head["writers"] if head else [u for u, m in (coll.get("members") or {}).items()
                                                if m.get("permission") in SHARE_WRITE]
        by = record.get("by") if isinstance(record, dict) else None
        signer = self._signer(state, by)
        valid = bool(signer) and by in writers and isinstance(record.get("seq"), int) \
            and record["seq"] > (known or {}).get("seq", 0) \
            and signed_by(signer["signing_public_key"], record.get("signature"), _delete_message(cid, iid, record["seq"], by))
        if not valid:
            # Kept: an editor here may edit it, which writes it again for the team over the deletion.
            if known:
                known["revision"] = item["revision"]
            name = self.vault.get(local_id).get("name") or local_id
            notes.setdefault("unsigned", []).append(name)
            self._sync_error(notes, cid, coll.get("name"), TeamError(tr("teams.unsigned_deletion"), "unsigned"))
            return None
        return {"iid": iid, "revision": item["revision"], "by": self._name_of(state, coll, by), "at": item.get("updated"),
                "seq": record["seq"], "local_id": local_id}

    def _delete(self, state, cid, found, notes):
        coll = state["collections"][cid]
        known = coll["items"].pop(found["iid"], None)
        with self.vault.mutex:
            try:
                local = self.vault.get(found["local_id"])
            except KeyError:
                return
            edited = known is not None and content_hash(effective_content(local)) != known["hash"]
            self._leave(local, edited, notes)
        notes.setdefault("changes", []).append({"id": local["id"], "action": "team_delete", "by": found["by"],
                                 "detail": f"«{local.get('name') or local['id']}» borrada del equipo"})

    def _hold(self, state, cid, deletions, notes):
        """Too many deletions at once: nothing is deleted here until the user says so (resolve_deletions)."""
        coll = state["collections"][cid]
        held = coll.setdefault("held", {})
        with self.vault.mutex:
            for found in deletions:
                held[found["iid"]] = {k: found[k] for k in ("revision", "by", "at", "seq")}
                if found["iid"] in coll["items"]:
                    coll["items"][found["iid"]]["revision"] = found["revision"]
                try:
                    entry = self.vault.get(found["local_id"])
                except KeyError:
                    continue
                entry["shared"]["pending_delete"] = {"by": found["by"], "at": found["at"]}
                self.vault.put(entry, replaces=entry["id"])
        notes.setdefault("held_deletions", []).append({"collection": coll.get("name", ""), "count": len(deletions),
                                        "by": sorted({f["by"] for f in deletions})})

    def _release_held(self, state, cid, coll):
        """The held credentials stay as they are: the reason to delete them went away."""
        coll.pop("held", None)
        with self.vault.mutex:
            for entry in self.vault.entries():
                shared = entry.get("shared") or {}
                if shared.get("collection") == cid and shared.pop("pending_delete", None) is not None:
                    self.vault.put(entry, replaces=entry["id"])

    def resolve_deletions(self, cid, apply=True):
        """The user's one click on held deletions: delete them here too, or keep them. Keeping restores them for
        the whole team when this user can edit the collection (the next sync writes them again); otherwise, and
        for a collection that disappeared, they stay on this PC as personal credentials."""
        state = self.vault.team()
        coll = (state.get("collections") or {}).get(cid)
        if not coll or not coll.get("held"):
            raise TeamError(tr("teams.there_are_no_pending_deletions"), "not_found")
        held, notes = coll["held"], {"removed": [], "conflicts": []}
        if coll.get("gone"):
            self._drop_collection(state, cid, notes, keep=not apply)
        else:
            index = self._local_index(cid)
            restore = coll.get("permission") in SHARE_WRITE
            with self.vault.mutex:
                for iid, info in held.items():
                    local = self.vault.get(index[iid]) if iid in index else None
                    known = coll["items"].get(iid)
                    if apply or not restore:
                        coll["items"].pop(iid, None)
                        if local:
                            edited = known is not None and content_hash(effective_content(local)) != known["hash"]
                            self._leave(local, edited and apply, notes, keep=not apply)
                        continue
                    if known:  # written again over the deletion by the next push, with a newer counter
                        known.update(hash="", seq=max(known.get("seq", 0), info.get("seq", 0)))
                    if local and local["shared"].pop("pending_delete", None) is not None:
                        self.vault.put(local, replaces=local["id"])
            coll.pop("held", None)
        self.vault.set_team(state)
        self._flush_removed()
        return {"applied": bool(apply), "count": len(held), "collection_name": coll.get("name", "")}

    def _collection_gone(self, state, cid, notes):
        """A collection the server no longer lists (access removed, deleted, or the server hiding it). Its
        credentials leave this PC, unless they are many: then they wait for the user (2.7)."""
        coll = state["collections"][cid]
        if coll.get("gone"):
            return []  # already waiting for the user
        entries = [e for e in self.vault.entries()
                   if (e.get("shared") or {}).get("collection") == cid and not e["shared"].get("own")]
        if not _mass(len(entries), len(entries)):
            return self._drop_collection(state, cid, notes)
        coll["gone"], at = True, now_iso()
        coll["held"] = {e["shared"]["item"]: {"revision": e["shared"].get("revision"), "by": None, "at": at, "seq": 0}
                        for e in entries}
        with self.vault.mutex:
            for entry in entries:
                entry = self.vault.get(entry["id"])
                entry["shared"]["pending_delete"] = {"by": None, "at": at, "gone": True}
                self.vault.put(entry, replaces=entry["id"])
        notes.setdefault("held_deletions", []).append({"collection": coll.get("name", ""), "count": len(entries), "by": [],
                                        "gone": True})
        return []

    def _apply(self, state, cid, item, notes):
        """One incoming version of an item: a new credential, or a change to an existing one. In a collection with
        a signed member list (2.6), a new version must be signed by someone who can edit it."""
        coll, iid = state["collections"][cid], item["id"]
        known = coll["items"].get(iid)
        me = state["user"]["id"]
        with self.vault.mutex:
            local_id = self._local_index(cid).get(iid)
            local = self.vault.get(local_id) if local_id else None
            edited = local is not None and known is not None and content_hash(effective_content(local)) != known["hash"]
            if item["key_version"] < coll["key_version"]:
                # Every live item is re-encrypted at a re-key: an older key is someone who left (or the server).
                raise TeamError(tr("teams.is_encrypted_with_old_key"), "old_key")
            plain = open_item(self._key(coll, item["key_version"]), cid, iid, item["key_version"], item["ciphertext"])
            content = {k: v for k, v in dict(plain["entry"]).items() if k not in ("shared", "updated", "secret_since")}
            for local_only in ("approval", "ai_totp"):  # the user's own choices on this PC, never a teammate's
                (content.get("policy") or {}).pop(local_only, None)
            if not ID_RE.match(str(content.get("id", ""))):
                raise TeamError(tr("teams.invalid_identifier"), "invalid_item")
            digest, seq = content_hash(content), _seq(plain)
            if known and (seq < known.get("seq", 0) or (seq == known.get("seq", 0) and seq and digest != known["hash"])):
                # Each write counts up: an older version served again (a revoked key, say) is not taken back.
                raise TeamError(tr("teams.is_older_version_than_one"), "rollback")
            if (coll.get("held") or {}).pop(iid, None) is not None and local:
                local["shared"].pop("pending_delete", None)  # written again after the deletion: it stays
            if local is None and known and digest == known["hash"]:
                coll["items"][iid] = {**known, "revision": item["revision"], "seq": seq}
                return  # deleted here and not pushed yet: the tombstone goes out with the next push
            if local and known and digest == known["hash"]:
                # Unchanged on the server (our own push coming back, or a re-key): local edits stay to be pushed.
                coll["items"][iid] = {**known, "revision": item["revision"], "seq": seq}
                local["shared"].update(revision=item["revision"])
                self.vault.put(local, replaces=local["id"])
                return
            signer = self._item_signer(state, cid, iid, plain, coll.get("manifest"))
            if coll.get("manifest") and signer is None:
                notes.setdefault("unsigned", []).append(content.get("name") or content["id"])
                raise TeamError(tr("teams.version_without_valid_signature_from"), "unsigned")
            by = signer or item.get("updated_by")
            author = {"id": by, "name": self._name_of(state, coll, by), **({"verified": True} if signer else {})}
            shared = self._shared_block(state, cid, iid, item["revision"], author, item.get("updated"))
            if edited:
                notes["conflicts"].append(self._conflict_copy(local))
            entry = copy.deepcopy(content)
            if local is None:
                entry["id"] = self._unique_id(content["id"])
                entry = self._new_from_team(entry, content, shared, author, notes)
                entry["policy"] = {**(entry.get("policy") or {}), "approval": "session"}
                notes["added"].append(entry.get("name") or entry["id"])
                action = "team_add"
            else:
                entry["id"] = local["id"]
                for key in ("rotate", "own"):
                    if local["shared"].get(key):
                        shared[key] = local["shared"][key]
                # A local edit that lost was kept as a copy: the text in force is the last one synced.
                basis = {**local, "description": known["content"].get("description", "")} if edited else local
                lines = widening_changes(local, content)
                texts = text_changes(basis, content)
                if (lines or texts) and signer != me:  # this user's own other device needs no review
                    entry = self._quarantine(basis, content, shared, author, lines + texts, bool(texts))
                    notes["quarantined"].append(entry.get("name") or entry["id"])
                    action = "team_review"
                else:
                    entry["policy"] = {**(entry.get("policy") or {}),
                                       "approval": (local.get("policy") or {}).get("approval", "session"),
                                       **({"ai_totp": True} if (local.get("policy") or {}).get("ai_totp") else {})}
                    action = "team_update"
                notes["updated"].append(entry.get("name") or entry["id"])
            entry["shared"] = shared
            self.vault.put(entry, replaces=local["id"] if local else None)
            coll["items"][iid] = {"revision": item["revision"], "hash": digest, "content": content, "seq": seq}
        notes.setdefault("changes", []).append({"id": entry["id"], "action": action, "by": author["name"],
                                 "detail": f"«{entry.get('name') or entry['id']}»"})

    def _new_from_team(self, entry, content, shared, author, notes):
        """A credential new to this PC runs nothing here until the user says so: the programs and variables
        it brings (code that would run on this PC) wait as a change to review. Webs and servers apply."""
        commands = (content.get("policy") or {}).get("commands") or {}
        if not (commands.get("allowed") or commands.get("env")):
            return entry
        base = {**entry, "policy": {k: v for k, v in (content.get("policy") or {}).items() if k != "commands"}}
        entry = self._quarantine(base, content, shared, author, widening_changes(base, content))
        notes["quarantined"].append(entry.get("name") or entry["id"])
        return entry

    def _leave(self, local, edited, notes, keep=False):
        """A shared credential leaves this PC (deleted for the team, or no access any more). An unpushed edit
        is kept as a personal copy, and one that was this user's before sharing it stays as a personal one
        (any one, with `keep`: the user chose to keep held deletions)."""
        if edited and not local["shared"].get("own") and not keep:
            notes["conflicts"].append(self._conflict_copy(local))
        if local["shared"].get("own") or keep:
            self.vault.put({k: v for k, v in local.items() if k != "shared"}, replaces=local["id"])
            notes.setdefault("kept", []).append(local.get("name") or local["id"])
            return
        self.vault.delete(local["id"])
        self._freed.add(local["id"])
        self._removed_ids.append(local["id"])
        notes["removed"].append(local.get("name") or local["id"])

    def _flush_removed(self):
        """Tell the service which credentials left this PC (outside the vault lock), so it forgets their
        approvals, destinations and exposure records."""
        removed, self._removed_ids = self._removed_ids, []
        for entry_id in removed if self.on_removed else ():
            self.on_removed(entry_id)

    @staticmethod
    def _quarantine(local, content, shared, author, lines, texts=False):
        """Apply the incoming change except where the key may go and, with `texts`, the description the AI reads:
        those stay as they were until the user accepts (2.5)."""
        pending = {"by": author["name"], "at": now_iso(), "changes": lines, "hosts": new_hosts(local, content),
                   "only_hosts": all(isinstance(c, dict) and c.get("kind") == "hosts" for c in lines), "texts": texts}
        if local["template"] != content.get("template"):
            entry = {**shared_content(local), "id": local["id"]}
            pending["entry"] = copy.deepcopy(content)
        else:
            entry = copy.deepcopy(content)
            entry["id"] = local["id"]
            destination = _destination(content)
            pending.update(policy=destination["policy"], fields=destination["fields"])
            for name in DESTINATION_FIELDS:
                if local["fields"].get(name) in (None, ""):
                    entry["fields"].pop(name, None)
                else:
                    entry["fields"][name] = local["fields"][name]
            if texts:
                pending["description"] = content.get("description") or ""
                entry["description"] = local.get("description") or ""
            if new_fill_sites(local, content):  # the browser keeps filling only where it did
                pending["fill"] = _fill_part(content)
                _set_fill_part(entry, _fill_part(local))
        entry["policy"] = copy.deepcopy(local.get("policy") or {})
        shared["pending_policy"] = pending
        return entry

    def _conflict_copy(self, local):
        """Keep the local edit that lost against the server as a separate, personal credential."""
        entry = shared_content(local)
        entry["id"] = self._unique_id(local["id"][:55] + "-conflict")
        entry["name"] = f"{local.get('name') or local['id']} (conflicto)"
        entry["policy"] = copy.deepcopy(local.get("policy") or {})
        self.vault.put(entry)
        return entry["id"]

    def _unique_id(self, wanted):
        """A free local id; one that a synced deletion just freed is never reused (approvals, GitHub
        destinations and .secretbroker files still point at it)."""
        taken = {e["id"] for e in self.vault.entries()} | self._freed
        if wanted not in taken:
            return wanted
        n = 2
        while f"{wanted[:60]}-{n}" in taken:
            n += 1
        return f"{wanted[:60]}-{n}"

    def _push(self, api, state, cid, notes):
        coll = state["collections"][cid]
        version, me = coll["key_version"], self._me(state)
        if coll.get("needs_rekey"):
            # Someone who left still holds this key: edits wait here until a manager re-keys (2.4).
            held = [e.get("name") or e["id"] for e in self.vault.entries()
                    if (e.get("shared") or {}).get("collection") == cid
                    and (coll["items"].get(e["shared"]["item"]) or {}).get("hash") != content_hash(effective_content(e))]
            notes.setdefault("held", []).extend(held)
            return
        present = set()
        for entry in self.vault.entries():
            shared = entry.get("shared") or {}
            if shared.get("collection") != cid:
                continue
            iid = shared["item"]
            present.add(iid)
            known = coll["items"].get(iid)
            content = effective_content(entry)
            digest = content_hash(content)
            if known and known["hash"] == digest:
                continue
            seq = (known or {}).get("seq", 0) + 1
            plain = sign_item(state["keys"], me["id"], cid, iid,
                              {"entry": content, "author": me, "updated": now_iso(), "seq": seq})
            try:
                revision = api.call("PUT", f"/collections/{cid}/items/{iid}", {
                    "ciphertext": seal_item(self._key(coll, version), cid, iid, version, plain), "key_version": version,
                    "base_revision": known["revision"] if known else 0})["revision"]
            except TeamError as exc:
                if exc.code == "conflict":
                    self._pull(api, state, cid, notes)  # the server wins; the local edit is kept as a copy
                    continue
                if exc.code in ("key_version", "needs_rekey"):
                    notes.setdefault("held", []).append(entry.get("name") or entry["id"])  # after the re-key
                    continue
                raise
            coll["items"][iid] = {"revision": revision, "hash": digest, "content": content, "seq": seq}
            notes["pushed"].append(entry.get("name") or entry["id"])
            with self.vault.mutex:
                try:
                    current = self.vault.get(entry["id"])
                except KeyError:
                    continue
                current["shared"]["revision"] = revision
                self.vault.put(current, replaces=current["id"])
        for iid, known in list(coll["items"].items()):
            if iid in present:
                continue
            try:
                api.call("DELETE", f"/collections/{cid}/items/{iid}", {
                    "base_revision": known["revision"],
                    "deletion": make_deletion(state["keys"], me["id"], cid, iid, known.get("seq", 0) + 1)})
            except TeamError as exc:
                if exc.code == "rate_limited":
                    notes.setdefault("held", []).append(known.get("content", {}).get("name") or iid)
                    break  # the server's limit on deletions an hour: the rest go out on a later sync
                if exc.code == "conflict":
                    coll["revision"] = 0  # changed meanwhile: it comes back on the next pull
                elif exc.code != "not_found":
                    raise
            coll["items"].pop(iid, None)

    def _flag(self, cid, people):
        """'Rotate: <people> had access' on every credential of a collection, until its secret changes."""
        with self.vault.mutex:
            for entry in self.vault.entries():
                if (entry.get("shared") or {}).get("collection") != cid:
                    continue
                fp = secret_fp(self.vault, entry)
                previous = entry["shared"].get("rotate") or {}
                known = previous.get("people", []) if previous.get("fp") == fp else []
                # `seen`: everyone who ever had access, so "Bob pudo ver 3 · 2 cambiadas" survives a rotation.
                seen = sorted(set(previous.get("seen") or []) | set(previous.get("people") or []) | set(people))
                entry["shared"]["rotate"] = {"people": sorted(set(known) | set(people)), "since": now_iso(), "fp": fp,
                                             "seen": seen}
                self.vault.put(entry, replaces=entry["id"])

    def _refresh_entries(self, state, cid):
        """Keep the names and the permission each shared entry carries in step with the collection."""
        coll = state["collections"][cid]
        org_name = ((state.get("orgs") or {}).get(coll["org"]) or {}).get("name", "")
        with self.vault.mutex:
            for entry in self.vault.entries():
                shared = entry.get("shared") or {}
                if shared.get("collection") != cid:
                    continue
                wanted = {"org_name": org_name, "collection_name": coll.get("name", ""), "permission": coll["permission"]}
                if any(shared.get(k) != v for k, v in wanted.items()):
                    shared.update(wanted)
                    self.vault.put(entry, replaces=entry["id"])

    def _drop_collection(self, state, cid, notes=None, keep=False):
        """No access any more (removed, or the collection was deleted): its credentials leave this PC, except
        what was this user's own before sharing it and edits not pushed yet (kept as personal copies), or all of
        them with `keep`."""
        notes = notes if notes is not None else {"removed": [], "conflicts": []}
        before = list(notes["removed"])
        coll = state["collections"].get(cid) or {}
        with self.vault.mutex:
            for entry in self.vault.entries():
                if (entry.get("shared") or {}).get("collection") == cid:
                    known = (coll.get("items") or {}).get(entry["shared"]["item"])
                    edited = known is not None and content_hash(effective_content(entry)) != known["hash"]
                    if keep:
                        entry["shared"].pop("pending_delete", None)
                    self._leave(entry, edited, notes, keep=keep)
        state["collections"].pop(cid, None)
        added = notes["removed"][len(before):]
        del notes["removed"][len(before):]
        return added
