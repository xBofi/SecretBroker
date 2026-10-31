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
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto, templates
from .crypto import b64, unb64
from .vault import ID_RE, SHARE_PERMISSIONS, SHARE_WRITE, ValidationError, secret_fields, shared_content

API = "/api/v1"
AUTH_INFO = b"secretbroker/team-auth/v1"
WRAP_INFO = b"secretbroker/team-wrap/v1"
KEYS_AAD = b"secretbroker/team-keys/v1|"
GRANT_AAD = "secretbroker/grant/v1|"
NAME_AAD = b"secretbroker/collection-name/v1|"
ITEM_AAD = "secretbroker/item/v1|"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
MIN_ACCOUNT_PASSWORD = 12
# Besides the policy, these fields decide where a secret is sent (an SSH or database server).
DESTINATION_FIELDS = ("host", "port", "engine")
SOMEONE = "alguien que ya no está"


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
        raise TeamError("El servidor ha enviado parámetros de cifrado no válidos", "bad_server")
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
        raise TeamError("No se pudieron abrir las claves de la cuenta: la contraseña no es la de la cuenta",
                        "invalid_credentials") from None
    return keys


def fingerprint(public_key, signing_public_key):
    """What two people compare over another channel: SHA-256(x25519 || ed25519), 8 groups of 4 hex chars."""
    digest = hashlib.sha256(unb64(public_key) + unb64(signing_public_key)).hexdigest()[:32]
    return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


def _same_fingerprint(a, b):
    clean = lambda text: "".join(str(text or "").split()).lower()
    return clean(a) == clean(b)


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
        raise TeamError("La clave de una colección no tiene una firma válida: no se usará", "bad_grant") from None
    if len(key) != 32:
        raise TeamError("La clave de una colección no es válida", "bad_grant")
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
    return content


def _destination(content):
    policy = copy.deepcopy(content.get("policy") or {})
    policy.pop("approval", None)
    return {"template": content.get("template"), "policy": policy,
            "fields": {name: (content.get("fields") or {}).get(name) for name in DESTINATION_FIELDS}}


def widening_changes(old, new):
    """Human-readable lines for every way `new` sends a secret somewhere `old` did not (empty: nothing wider)."""
    old, new = _destination(old), _destination(new)
    lines = []
    if old["template"] != new["template"]:
        lines.append(f"Tipo de credencial: {new['template']}")
    labels = {s["name"]: s["label"] for s in templates.field_specs(new["template"])} \
        if new["template"] in templates.TEMPLATES else {}
    for name in DESTINATION_FIELDS:
        if old["fields"][name] != new["fields"][name]:
            lines.append(f"{labels.get(name, name)}: {old['fields'][name] or '—'} → {new['fields'][name] or '—'}")
    http = lambda d: d["policy"].get("http") or {}
    hosts = [h for h in http(new).get("allowed_hosts") or [] if h not in (http(old).get("allowed_hosts") or [])]
    if hosts:
        lines.append("Webs nuevas: " + ", ".join(hosts))
    if (http(old).get("auth") or {"kind": "none"}) != (http(new).get("auth") or {"kind": "none"}):
        lines.append("Cómo se envía la clave: " + str((http(new).get("auth") or {}).get("kind", "none")))
    commands = lambda d: d["policy"].get("commands") or {}
    programs = [c for c in commands(new).get("allowed") or [] if c not in (commands(old).get("allowed") or [])]
    if programs:
        lines.append("Programas nuevos: " + ", ".join(programs))
    old_env = commands(old).get("env") or {}
    env = [k for k, v in (commands(new).get("env") or {}).items() if old_env.get(k) != v]
    if env:
        lines.append("Variables nuevas o cambiadas: " + ", ".join(env))
    return lines


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
        raise TeamError("La dirección del servidor no es válida", "invalid")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in LOCAL_HOSTS):
        raise TeamError("El servidor de equipo debe usar https:// (http solo para pruebas en este mismo PC)", "invalid")
    return url


class Client:
    """The server API. TLS certificates are always verified; plain http only to this same PC."""

    def __init__(self, base, token=None):
        self.base = server_base(base)
        self.token = token
        self._http = httpx.Client(timeout=TIMEOUT, verify=True, follow_redirects=False,
                                  headers={"User-Agent": "SecretBroker"})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._http.close()

    def call(self, method, path, body=None, auth=True):
        headers = {"Authorization": f"Bearer {self.token}"} if auth and self.token else {}
        try:
            response = self._http.request(method, self.base + API + path, json=body, headers=headers)
        except httpx.TimeoutException:
            raise TeamError("El servidor de equipo no responde. Se reintentará más tarde.", "offline") from None
        except httpx.HTTPError as exc:
            reason = "su certificado no es válido" if "CERTIFICATE" in str(exc).upper() else "sin conexión"
            raise TeamError(f"No se pudo conectar con el servidor de equipo ({reason})", "offline") from None
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code == 200:
            if data is None:
                raise TeamError("El servidor de equipo ha respondido algo inesperado", "bad_server")
            return data
        error = data if isinstance(data, dict) else {}
        message = error.get("error") if isinstance(error.get("error"), str) else \
            f"El servidor de equipo ha respondido con un error ({response.status_code})"
        code = error.get("code") if isinstance(error.get("code"), str) else "server_error"
        if response.status_code == 401 and auth:
            code, message = "reconnect", "La sesión del equipo ha caducado: vuelve a conectar la cuenta"
        raise TeamError(message[:300], code, response.status_code, error)


def connected(state):
    return bool(state.get("token") and state.get("keys") and state.get("user"))


def _seq(plain):
    """The write counter inside an item's plaintext (0 for items written before it existed)."""
    seq = plain.get("seq", 0)
    return seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0


def _label(person):
    return (person or {}).get("name") or (person or {}).get("email") or SOMEONE


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
                "waiting": [{k: p.get(k) for k in ("user_id", "name", "email", "fingerprint", "org")}
                            | {"collections": len(p.get("collections") or [])}
                            for p in (state.get("waiting") or {}).values()]}

    def connect(self, server_url, email, password, mode, name="", device_name="", invite_token=None):
        """Link (mode "register") or log in to a team account. The only time the account password is used."""
        base, email = server_base(server_url), str(email or "").strip().lower()
        if mode not in ("register", "login"):
            raise TeamError("Indica si quieres crear la cuenta o entrar en una existente", "invalid")
        if not email or "@" not in email:
            raise TeamError("Escribe tu e-mail", "invalid")
        current = self.vault.team()
        if connected(current) and (current["user"]["email"] != email or current["server_url"] != base):
            raise TeamError("Ya hay otra cuenta de equipo conectada. Desconéctala antes.", "invalid")
        device_name = str(device_name or os.environ.get("COMPUTERNAME") or "PC")[:100]
        with Client(base) as api:
            api.call("GET", "/info", auth=False)
            if mode == "register":
                if len(password or "") < MIN_ACCOUNT_PASSWORD:
                    raise TeamError(f"La contraseña de la cuenta debe tener al menos {MIN_ACCOUNT_PASSWORD} caracteres",
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
                raise TeamError("Las claves de la cuenta no coinciden con las del servidor", "bad_server")
        user = {k: session["user"].get(k) for k in ("id", "email", "name")}
        state = current if connected(current) and current["user"]["id"] == user["id"] else {}
        state.update(server_url=base, token=session["token"], user=user, keys=keys, device=device_name,
                     **public_keys(keys))
        for section in ("pinned", "orgs", "collections"):
            state.setdefault(section, {})
        self.vault.set_team(state)
        return self.status()

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
        self._flush_removed()
        return {"removed": len(notes["removed"]), "kept": len(notes.get("kept", [])) + len(notes["conflicts"])}

    def _api(self, state):
        if not connected(state):
            raise TeamError("No hay ninguna cuenta de equipo conectada", "not_connected")
        return Client(state["server_url"], state["token"])

    def _me(self, state):
        return {"id": state["user"]["id"], "name": _label(state["user"])}

    # ------------------------------------------------------------------ people and their keys (2.2)

    @staticmethod
    def _fetch_keys(api, uid):
        data = api.call("GET", f"/users/{uid}/keys")
        return {"public_key": data["public_key"], "signing_public_key": data["signing_public_key"],
                "email": data.get("email"), "name": data.get("name"),
                "fp": fingerprint(data["public_key"], data["signing_public_key"])}

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
        if pinned["fp"] != found["fp"]:
            raise TeamError(f"La clave de {_label(found)} ha cambiado desde que la confirmaste. Compara su huella "
                            "con esa persona y vuelve a confirmarla antes de compartir nada con ella.", "key_changed")
        return pinned

    def _untrusted(self, api, uid, org=None):
        """The error for someone whose key this user has not confirmed yet, with what the app needs to ask."""
        try:
            person = self._fetch_keys(api, uid)
        except TeamError:
            person = {}
        return TeamError(f"Antes confirma la huella de {_label(person)} en Equipo › Personas: así nadie, ni el "
                         "servidor, puede colarse con otra clave.", "untrusted",
                         data={"user_id": uid, "name": person.get("name"), "email": person.get("email"),
                               "fingerprint": person.get("fp"), "org": org})

    # ------------------------------------------------------------------ organizations

    def orgs(self):
        state = self.vault.team()
        with self._api(state) as api:
            rows = api.call("GET", "/orgs")
        state["orgs"] = {r["id"]: {"name": r["name"], "role": r["role"], "status": r.get("status")} for r in rows}
        self.vault.set_team(state)
        return rows

    def create_org(self, name):
        state = self.vault.team()
        with self._api(state) as api:
            oid = api.call("POST", "/orgs", {"name": str(name or "").strip()})["id"]
        self.orgs()
        return {"id": oid}

    def invite(self, oid, email, role="member"):
        with self._api(self.vault.team()) as api:
            return api.call("POST", f"/orgs/{oid}/invites", {"email": str(email or "").strip(), "role": role})

    def invites(self):
        with self._api(self.vault.team()) as api:
            return api.call("GET", "/invites")

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
                    state["pinned"][by] = self._fetch_keys(api, by)
                except TeamError:
                    pass  # confirmed by hand later, if they grant anything
        self.vault.set_team(state)
        self.orgs()
        return {}

    def members(self, oid):
        """Members with their key fingerprints, whether this user trusts each one (`trusted`: pinned with the
        same fingerprint) and whether a pinned key has changed since."""
        state = self.vault.team()
        with self._api(state) as api:
            rows = api.call("GET", f"/orgs/{oid}/members")
            for row in rows:
                row["fingerprint"], row["key_changed"], row["trusted"] = None, False, False
                if not row.get("user_id"):
                    continue
                row["me"] = row["user_id"] == state["user"]["id"]
                try:
                    data = api.call("GET", f"/users/{row['user_id']}/keys")
                except TeamError:
                    continue
                row["fingerprint"] = fingerprint(data["public_key"], data["signing_public_key"])
                pinned = state["pinned"].get(row["user_id"])
                row["key_changed"] = bool(pinned and pinned["fp"] != row["fingerprint"])
                row["trusted"] = row["me"] or bool(pinned and not row["key_changed"])
        return rows

    def confirm_member(self, oid, uid, expected_fingerprint=None):
        """Trust someone's key on this PC, and let them into the organization if they are waiting for an admin.
        With a fingerprint (typed by this user, as read out by that person) it must match. A key that changed
        since it was pinned is only re-pinned with that typed fingerprint: one click is not enough there."""
        state = self.vault.team()
        with self._api(state) as api:
            row = next((r for r in api.call("GET", f"/orgs/{oid}/members") if r.get("user_id") == uid), None)
            if row is None or row.get("status") not in ("accepted", "confirmed"):
                raise TeamError("Esa persona no está en la organización", "not_found")
            found = self._fetch_keys(api, uid)
            if expected_fingerprint and not _same_fingerprint(expected_fingerprint, found["fp"]):
                raise TeamError(f"La huella no coincide con la de {_label(found)}. No la confirmes: alguien podría "
                                "estar haciéndose pasar por esa persona.", "fingerprint_mismatch")
            pinned = state["pinned"].get(uid)
            if pinned and pinned["fp"] != found["fp"] and not expected_fingerprint:
                raise TeamError(f"La clave de {_label(found)} ha cambiado. Pídele su huella y escríbela para "
                                "confirmarla.", "key_changed")
            if row["status"] == "accepted":
                api.call("POST", f"/orgs/{oid}/members/{uid}/confirm")
        state["pinned"][uid] = found
        state.get("waiting", {}).pop(uid, None)
        self.vault.set_team(state)
        return {"fingerprint": found["fp"]}

    def set_role(self, oid, uid, role):
        with self._api(self.vault.team()) as api:
            return api.call("PATCH", f"/orgs/{oid}/members/{uid}", {"role": role})

    def remove_member(self, oid, uid):
        """Take someone out of the organization, then re-key every collection they could read that this user
        manages (2.4). The others are re-keyed by their managers on their next sync."""
        state = self.vault.team()
        with self._api(state) as api:
            person = self._person(api, state, oid, uid)
            result = api.call("DELETE", f"/orgs/{oid}/members/{uid}")
            if uid == state["user"]["id"]:
                return {"left": True, "rekeyed": [], "pending": result.get("needs_rekey") or []}
            # The server's list, plus every collection this PC knows they were in: an empty or short answer
            # must not leave them with a working key.
            known = [cid for cid, c in sorted(state["collections"].items())
                     if c.get("org") == oid and uid in (c.get("members") or {})]
            cids = list(dict.fromkeys([*(result.get("needs_rekey") or []), *known]))
            rekeyed, pending = self._rekey_after(api, state, cids, [person], [uid])
        self.vault.set_team(state)
        return {"rekeyed": rekeyed, "pending": pending}

    def _person(self, api, state, oid, uid):
        try:
            rows = api.call("GET", f"/orgs/{oid}/members")
            row = next((r for r in rows if r.get("user_id") == uid), None)
        except TeamError:
            row = None
        return _label(row or state["pinned"].get(uid))

    def _rekey_after(self, api, state, cids, people, removed):
        rekeyed, pending = [], []
        for cid in cids:
            coll = state["collections"].get(cid)
            if coll and coll.get("permission") == "manage":
                try:
                    self._rekey(api, state, cid, people, removed)
                except TeamError as exc:
                    if exc.code != "not_found":
                        raise
                    pending.append(cid)  # gone from the server meanwhile: the next sync drops it here
                    continue
                rekeyed.append(cid)
            else:
                pending.append(cid)
        return rekeyed, pending

    def events(self, oid, before=None):
        with self._api(self.vault.team()) as api:
            return api.call("GET", f"/orgs/{oid}/events" + (f"?before={int(before)}" if before else ""))

    # ------------------------------------------------------------------ collections

    def collections(self):
        state = self.vault.team()
        counts = {}
        for entry in self.vault.entries():
            if entry.get("shared"):
                counts[entry["shared"]["collection"]] = counts.get(entry["shared"]["collection"], 0) + 1
        orgs = state.get("orgs") or {}
        return sorted(({"id": cid, "org": c.get("org"), "org_name": (orgs.get(c.get("org")) or {}).get("name", ""),
                        "name": c.get("name", ""), "permission": c.get("permission"),
                        "key_version": c.get("key_version"), "needs_rekey": bool(c.get("needs_rekey")),
                        "entries": counts.get(cid, 0)}
                       for cid, c in (state.get("collections") or {}).items()),
                      key=lambda c: (c["org_name"].lower(), c["name"].lower()))

    def create_collection(self, oid, name):
        name = str(name or "").strip()
        if not name:
            raise TeamError("Ponle un nombre a la colección", "invalid")
        state = self.vault.team()
        cid, key, me = str(uuid.uuid4()), os.urandom(32), state["user"]["id"]
        with self._api(state) as api:
            grant = make_grant(state["keys"], me, cid, 1, me, state["public_key"], key)
            api.call("POST", f"/orgs/{oid}/collections",
                     {"id": cid, "encrypted_name": seal_name(key, cid, {"name": name}), "grant": grant})
        state["collections"][cid] = {"org": oid, "name": name, "keys": {"1": b64(key)}, "key_version": 1,
                                     "permission": "manage", "revision": 0, "needs_rekey": False, "items": {},
                                     "members": {me: {"name": _label(state["user"]), "permission": "manage"}}}
        self.vault.set_team(state)
        return {"id": cid}

    def collection_members(self, cid):
        with self._api(self.vault.team()) as api:
            return api.call("GET", f"/collections/{cid}/members")

    def _collection(self, state, cid, permissions=SHARE_PERMISSIONS):
        coll = (state.get("collections") or {}).get(cid)
        if not coll:
            raise TeamError("Esa colección no existe o aún no se ha sincronizado", "not_found")
        if coll.get("permission") not in permissions:
            raise TeamError("Tu permiso en esta colección no permite hacer esto", "forbidden")
        return coll

    def grant(self, cid, uid, permission):
        """Give someone access to a collection (sealing its key to their pinned key), or change their permission."""
        if permission not in SHARE_PERMISSIONS:
            raise TeamError("Permiso no válido", "invalid")
        state = self.vault.team()
        coll = self._collection(state, cid, ("manage",))
        with self._api(state) as api:
            current = {r["user_id"] for r in api.call("GET", f"/collections/{cid}/members")}
            for attempt in range(2):
                body = {"permission": permission}
                if uid not in current:
                    peer = self._peer_keys(api, state, uid)
                    body["grant"] = make_grant(state["keys"], state["user"]["id"], cid, coll["key_version"], uid,
                                               peer["public_key"], unb64(coll["keys"][str(coll["key_version"])]))
                try:
                    api.call("PUT", f"/collections/{cid}/members/{uid}", body)
                    break
                except TeamError as exc:
                    if exc.code != "needs_rekey" or attempt:
                        raise
                    self._rekey(api, state, cid, *self._gone(api, state, cid))
            coll.setdefault("members", {})[uid] = {"name": _label(state["pinned"].get(uid)), "permission": permission}
        self.vault.set_team(state)
        self._refresh_entries(state, cid)
        return {}

    def revoke(self, cid, uid):
        """Take someone out of a collection and re-key it: they keep nothing that changes from now on."""
        state = self.vault.team()
        coll = self._collection(state, cid)
        me = state["user"]["id"]
        if uid != me and coll.get("permission") != "manage":
            raise TeamError("Solo quien gestiona la colección puede quitar a otros", "forbidden")
        with self._api(state) as api:
            person = _label((coll.get("members") or {}).get(uid) or state["pinned"].get(uid))
            api.call("DELETE", f"/collections/{cid}/members/{uid}")
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
        gone = {uid: m for uid, m in (coll.get("members") or {}).items() if uid not in current}
        return sorted({_label(m) for m in gone.values()}) or [SOMEONE], sorted(gone)

    def _rekey(self, api, state, cid, people, removed=()):
        """A new collection key, every live item re-encrypted and a grant per remaining member, in one atomic call;
        then every credential in it is flagged 'rotate because <people> had access' (2.4).

        The member list comes from the server, so the new key is only sealed to people this user trusts
        (_peer_keys refuses anyone not confirmed on this PC) and never to someone just removed."""
        coll = state["collections"][cid]
        for attempt in range(2):
            listed = next((c for c in api.call("GET", "/collections") if c["id"] == cid), None)
            if listed is None:
                raise TeamError("Ya no tienes acceso a esa colección", "not_found")
            self._learn_key(api, state, coll, cid, listed)
            data = api.call("GET", f"/collections/{cid}/items?since=0")
            live = {}
            for item in data["items"]:
                if not item["deleted"]:
                    live[item["id"]] = open_item(self._key(coll, item["key_version"]), cid, item["id"],
                                                 item["key_version"], item["ciphertext"])
            members = api.call("GET", f"/collections/{cid}/members")
            if any(m["user_id"] in removed for m in members):
                raise TeamError("El servidor sigue dando acceso a quien acabas de quitar: no se cambia la clave",
                                "bad_server")
            version, key = listed["key_version"] + 1, os.urandom(32)
            grants = {m["user_id"]: make_grant(state["keys"], state["user"]["id"], cid, version, m["user_id"],
                                               self._peer_keys(api, state, m["user_id"])["public_key"], key)
                      for m in members}
            body = {"key_version": version, "grants": grants,
                    "encrypted_name": seal_name(key, cid, {"name": coll.get("name", ""), "removed": people,
                                                           "version": version}),
                    "items": {iid: seal_item(key, cid, iid, version, plain) for iid, plain in live.items()}}
            try:
                api.call("POST", f"/collections/{cid}/rotate", body)
                break
            except TeamError as exc:
                if exc.code not in ("incomplete", "key_version") or attempt:
                    raise
        coll["keys"] = {str(version): b64(key)}
        coll.update(key_version=version, needs_rekey=False,
                    members={m["user_id"]: {"name": _label(m), "permission": m["permission"]} for m in members})
        self._flag(cid, people)
        return version

    def _learn_key(self, api, state, coll, cid, listed):
        """The collection's current key. A new one is only taken from a grant signed by this user or by someone
        they trust who manages the collection; anything else (a key the server made up, an old version
        served again) is refused. Older keys are dropped: nothing may be read or written with them again."""
        version, me = listed["key_version"], state["user"]["id"]
        if str(version) not in coll.setdefault("keys", {}):
            if version < int(coll.get("key_version") or 0):
                raise TeamError("El servidor ofrece una clave antigua de la colección: no se usará", "bad_grant")
            granter_id = listed["grant"]["granted_by"]
            granter = self._peer_keys(api, state, granter_id, fresh=False) if granter_id == me else \
                state["pinned"].get(granter_id)
            if granter is None:
                raise self._untrusted(api, granter_id, listed.get("org_id"))
            if granter_id != me and not any(m["user_id"] == granter_id and m["permission"] == "manage"
                                            for m in api.call("GET", f"/collections/{cid}/members")):
                raise TeamError("La clave de una colección la firma alguien que no la gestiona: no se usará", "bad_grant")
            key = open_grant(state["keys"], me, cid, version, listed["grant"], granter["signing_public_key"])
            coll["keys"] = {str(version): b64(key)}
        return unb64(coll["keys"][str(version)])

    @staticmethod
    def _key(coll, version):
        try:
            return unb64(coll["keys"][str(version)])
        except KeyError:
            raise TeamError("Falta la clave de una versión antigua de la colección", "missing_key") from None

    # ------------------------------------------------------------------ sharing entries

    def share_entry(self, entry_id, cid):
        entry = self.vault.get(entry_id)
        if entry.get("shared"):
            raise TeamError("Esta credencial ya está compartida", "invalid")
        if entry.get("draft"):
            raise TeamError("Añade la clave antes de compartirla", "invalid")
        state = self.vault.team()
        coll = self._collection(state, cid, SHARE_WRITE)
        with self._api(state) as api:
            if coll.get("needs_rekey"):
                if coll.get("permission") != "manage":
                    raise TeamError("Esta colección está pendiente de cambiar de clave (alguien salió de ella). "
                                    "Espera a que quien la gestiona sincronice.", "needs_rekey")
                self._rekey(api, state, cid, *self._gone(api, state, cid))
            iid, content = str(uuid.uuid4()), shared_content(entry)
            plain = {"entry": content, "author": self._me(state), "updated": now_iso(), "seq": 1}
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

    def unshare_entry(self, entry_id):
        """Take a credential out of its collection for everyone; this PC keeps it as a personal one."""
        entry = self.vault.get(entry_id)
        shared = entry.get("shared")
        if not shared:
            raise TeamError("Esta credencial no está compartida", "invalid")
        state = self.vault.team()
        cid = shared["collection"]
        coll = self._collection(state, cid, SHARE_WRITE)
        known = coll["items"].get(shared["item"]) or {}
        with self._api(state) as api:
            try:
                api.call("DELETE", f"/collections/{cid}/items/{shared['item']}",
                         {"base_revision": known.get("revision", shared.get("revision", 0))})
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
                raise TeamError("Esta credencial no tiene cambios pendientes", "not_found")
            if not accept and shared.get("permission") not in SHARE_WRITE:
                raise TeamError("Solo quien puede editar la credencial puede rechazar el cambio. Mientras tanto se "
                                "sigue usando como estaba.", "forbidden")
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
                 "rotate": [], "trust": [], "held": [], "errors": []}
        state = self.vault.team()
        self._freed = set()
        waiting = {}
        with self._api(state) as api:
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
                        # A key from (or for) someone not confirmed on this PC: the user confirms them first.
                        person = waiting.setdefault(exc.data["user_id"], {**exc.data, "collections": []})
                        person["org"] = person.get("org") or row.get("org_id")
                        person["collections"].append(row["id"])
                        if len(person["collections"]) == 1:
                            notes["trust"].append(_label(person))
                    else:
                        notes["errors"].append(f"{(state['collections'].get(row['id']) or {}).get('name') or 'Colección'}: {exc}")
                except (InvalidTag, ValueError, KeyError, TypeError):
                    notes["errors"].append("Una colección no se pudo descifrar")
                self.vault.set_team(state)
            for cid in [cid for cid in state["collections"] if cid not in {r["id"] for r in listed}]:
                notes["removed"] += self._drop_collection(state, cid, notes)
        state["waiting"] = waiting
        state["last_sync"] = now_iso()
        self.vault.set_team(state)
        self._flush_removed()
        return notes

    def _sync_collection(self, api, state, row, notes):
        cid = row["id"]
        coll = state["collections"].get(cid)
        first = coll is None
        coll = coll or {"items": {}, "revision": 0, "keys": {}, "members": {}}
        key = self._learn_key(api, state, coll, cid, row)
        info = open_name(key, cid, row["encrypted_name"])
        removed = info.get("removed") if not first and row["key_version"] > coll.get("key_version", 0) \
            and info.get("version") == row["key_version"] else None
        coll.update(org=row["org_id"], name=str(info.get("name") or ""), key_version=row["key_version"],
                    permission=row["permission"], needs_rekey=bool(row["needs_rekey"]))
        state["collections"][cid] = coll
        if coll["needs_rekey"] and coll["permission"] == "manage":
            # Safe even if the server asked for it falsely: the new key only goes to people trusted here.
            self._pull(api, state, cid, notes)
            people, gone = self._gone(api, state, cid)
            self._rekey(api, state, cid, people, gone)
            notes["rotate"].append({"collection": coll["name"], "people": people})
        else:
            coll["members"] = {m["user_id"]: {"name": _label(m), "permission": m["permission"]}
                               for m in api.call("GET", f"/collections/{cid}/members")}
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
        coll = state["collections"][cid]
        data = api.call("GET", f"/collections/{cid}/items?since={int(coll.get('revision') or 0)}")
        members = coll.get("members") or {}
        for item in data["items"]:
            try:
                self._apply(state, cid, item, members, notes)
            except (TeamError, ValidationError, InvalidTag, ValueError, KeyError, TypeError) as exc:
                notes["errors"].append(f"{coll.get('name') or 'Colección'}: un elemento no se pudo aplicar "
                                       f"({exc if isinstance(exc, (TeamError, ValidationError)) else type(exc).__name__})")
        coll["revision"] = max(int(coll.get("revision") or 0), int(data["revision"]))

    def _apply(self, state, cid, item, members, notes):
        """One incoming item: tombstone, new credential, or a change to an existing one."""
        coll, iid = state["collections"][cid], item["id"]
        known = coll["items"].get(iid)
        with self.vault.mutex:
            local_id = self._local_index(cid).get(iid)
            local = self.vault.get(local_id) if local_id else None
            edited = local is not None and known is not None and content_hash(effective_content(local)) != known["hash"]
            if item["deleted"]:
                coll["items"].pop(iid, None)
                if local:
                    self._leave(local, edited, notes)
                return
            if item["key_version"] < coll["key_version"]:
                # Every live item is re-encrypted at a re-key: an older key is someone who left (or the server).
                raise TeamError("está cifrado con una clave antigua de la colección", "old_key")
            plain = open_item(self._key(coll, item["key_version"]), cid, iid, item["key_version"], item["ciphertext"])
            content = {k: v for k, v in dict(plain["entry"]).items() if k not in ("shared", "updated", "secret_since")}
            (content.get("policy") or {}).pop("approval", None)
            if not ID_RE.match(str(content.get("id", ""))):
                raise TeamError("identificador no válido", "invalid")
            digest, seq = content_hash(content), _seq(plain)
            if known and (seq < known.get("seq", 0) or (seq == known.get("seq", 0) and seq and digest != known["hash"])):
                # Each write counts up: an older version served again (a revoked key, say) is not taken back.
                raise TeamError("es una versión anterior a la que ya tienes", "rollback")
            author = {"id": item.get("updated_by"),
                      "name": _label(members.get(item.get("updated_by")) or state["pinned"].get(item.get("updated_by"))
                                     or (state["user"] if item.get("updated_by") == state["user"]["id"] else None))}
            shared = self._shared_block(state, cid, iid, item["revision"], author, item.get("updated"))
            if local is None and known and digest == known["hash"]:
                coll["items"][iid] = {**known, "revision": item["revision"], "seq": seq}
                return  # deleted here and not pushed yet: the tombstone goes out with the next push
            if local and known and digest == known["hash"]:
                # Unchanged on the server (our own push coming back, or a re-key): local edits stay to be pushed.
                coll["items"][iid] = {**known, "revision": item["revision"], "seq": seq}
                local["shared"].update(revision=item["revision"])
                self.vault.put(local, replaces=local["id"])
                return
            if edited:
                notes["conflicts"].append(self._conflict_copy(local))
            entry = copy.deepcopy(content)
            if local is None:
                entry["id"] = self._unique_id(content["id"])
                entry = self._new_from_team(entry, content, shared, author, notes)
                entry["policy"] = {**(entry.get("policy") or {}), "approval": "session"}
                notes["added"].append(entry.get("name") or entry["id"])
            else:
                entry["id"] = local["id"]
                for key in ("rotate", "own"):
                    if local["shared"].get(key):
                        shared[key] = local["shared"][key]
                lines = widening_changes(local, content)
                if lines:
                    entry = self._quarantine(local, content, shared, author, lines)
                    notes["quarantined"].append(entry.get("name") or entry["id"])
                else:
                    entry["policy"] = {**(entry.get("policy") or {}),
                                       "approval": (local.get("policy") or {}).get("approval", "session")}
                notes["updated"].append(entry.get("name") or entry["id"])
            entry["shared"] = shared
            self.vault.put(entry, replaces=local["id"] if local else None)
            coll["items"][iid] = {"revision": item["revision"], "hash": digest, "content": content, "seq": seq}

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

    def _leave(self, local, edited, notes):
        """A shared credential leaves this PC (deleted for the team, or no access any more). An unpushed edit
        is kept as a personal copy, and one that was this user's before sharing it stays as a personal one."""
        if edited and not local["shared"].get("own"):
            notes["conflicts"].append(self._conflict_copy(local))
        if local["shared"].get("own"):
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
    def _quarantine(local, content, shared, author, lines):
        """Apply the incoming change except where the key may go: that stays as it was until the user accepts."""
        pending = {"by": author["name"], "at": now_iso(), "changes": lines}
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
            plain = {"entry": content, "author": me, "updated": now_iso(), "seq": seq}
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
                api.call("DELETE", f"/collections/{cid}/items/{iid}", {"base_revision": known["revision"]})
            except TeamError as exc:
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
                entry["shared"]["rotate"] = {"people": sorted(set(known) | set(people)), "since": now_iso(), "fp": fp}
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

    def _drop_collection(self, state, cid, notes=None):
        """No access any more (removed, or the collection was deleted): its credentials leave this PC, except
        what was this user's own before sharing it and edits not pushed yet (kept as personal copies)."""
        notes = notes if notes is not None else {"removed": [], "conflicts": []}
        before = list(notes["removed"])
        coll = state["collections"].get(cid) or {}
        with self.vault.mutex:
            for entry in self.vault.entries():
                if (entry.get("shared") or {}).get("collection") == cid:
                    known = (coll.get("items") or {}).get(entry["shared"]["item"])
                    edited = known is not None and content_hash(effective_content(entry)) != known["hash"]
                    self._leave(entry, edited, notes)
        state["collections"].pop(cid, None)
        added = notes["removed"][len(before):]
        del notes["removed"][len(before):]
        return added
