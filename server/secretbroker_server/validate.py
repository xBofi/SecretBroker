"""Strict validation of request bodies: exact fields, types, lengths and encodings.

Every validator takes the raw JSON value and returns the cleaned value or raises ApiError (400).
Messages are Spanish because the desktop app shows them to the user.
"""

import base64
import binascii
import json
import re
import uuid

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
ROLES = ("owner", "admin", "member")
PERMISSIONS = ("manage", "edit", "view", "use")
SEALED_FIELDS = ("epk", "nonce", "ciphertext")


class ApiError(Exception):
    def __init__(self, status, code, message, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra

    def body(self):
        return {"error": self.message, "code": self.code, **self.extra}


def invalid(message):
    return ApiError(400, "invalid", message)


def body(data, required, optional=None):
    """Check that `data` is an object with exactly these fields, and validate each one."""
    optional = optional or {}
    if not isinstance(data, dict):
        raise invalid("La petición debe ser un objeto JSON.")
    unknown = set(data) - set(required) - set(optional)
    if unknown:
        raise invalid(f"Campo no admitido: {sorted(unknown)[0]}")
    out = {}
    for name, check in required.items():
        if name not in data:
            raise invalid(f"Falta el campo {name}.")
        out[name] = _field(name, check, data[name])
    for name, check in optional.items():
        out[name] = _field(name, check, data[name]) if data.get(name) is not None else None
    return out


def _field(name, check, value):
    try:
        return check(value)
    except ApiError as exc:
        raise invalid(f"{name}: {exc.message}") from None


def uuid_id(value):
    if not isinstance(value, str) or len(value) != 36:
        raise invalid("debe ser un UUID.")
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise invalid("debe ser un UUID.") from None


def path_id(value):
    """Ids in URLs: a malformed one is simply not found."""
    try:
        return uuid_id(value)
    except ApiError:
        raise ApiError(404, "not_found", "No existe.") from None


def email(value):
    if not isinstance(value, str):
        raise invalid("debe ser un e-mail.")
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise invalid("debe ser un e-mail.")
    return value


def text(max_len, min_len=1):
    def check(value):
        if not isinstance(value, str):
            raise invalid("debe ser texto.")
        value = value.strip()
        if not min_len <= len(value) <= max_len or any(ord(c) < 32 for c in value):
            raise invalid(f"debe tener entre {min_len} y {max_len} caracteres.")
        return value
    return check


def integer(low, high):
    def check(value):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise invalid(f"debe ser un número entre {low} y {high}.")
        return value
    return check


def one_of(*choices):
    def check(value):
        if value not in choices:
            raise invalid(f"debe ser uno de: {', '.join(choices)}.")
        return value
    return check


def b64(min_bytes, max_bytes=None):
    max_bytes = min_bytes if max_bytes is None else max_bytes

    def check(value):
        if not isinstance(value, str) or len(value) > (max_bytes + 2) // 3 * 4:
            raise invalid("debe ser base64.")
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise invalid("debe ser base64.") from None
        if not min_bytes <= len(raw) <= max_bytes:
            raise invalid("tiene un tamaño incorrecto.")
        return value
    return check


def kdf(value):
    """Only scrypt with sane parameters, so a client cannot make other devices hang."""
    if not isinstance(value, dict) or set(value) != {"name", "n", "r", "p", "salt"} or value["name"] != "scrypt":
        raise invalid("debe ser {name: scrypt, n, r, p, salt}.")
    n = integer(2**14, 2**20)(value["n"])
    if n & (n - 1):
        raise invalid("n debe ser potencia de 2.")
    return {"name": "scrypt", "n": n, "r": integer(1, 32)(value["r"]), "p": integer(1, 16)(value["p"]),
            "salt": b64(16, 64)(value["salt"])}


def sealed(max_bytes, sealed_to=False):
    """An AES-GCM box as produced by secretbroker.crypto: {nonce, ciphertext} (+ epk when sealed to a key)."""
    fields = {"epk", "nonce", "ciphertext"} if sealed_to else {"nonce", "ciphertext"}

    def check(value):
        if not isinstance(value, dict) or set(value) != fields:
            raise invalid(f"debe ser un objeto con {', '.join(sorted(fields))}.")
        out = {"nonce": b64(12)(value["nonce"]), "ciphertext": b64(16, max_bytes)(value["ciphertext"])}
        if sealed_to:
            out["epk"] = b64(32)(value["epk"])
        return out
    return check


def grant(value):
    if not isinstance(value, dict):
        raise invalid("debe ser {sealed, granted_by, signature}.")
    try:
        return body(value, {"sealed": sealed(64, sealed_to=True), "granted_by": uuid_id, "signature": b64(64)})
    except ApiError as exc:
        raise invalid(exc.message) from None


def mapping(key_check, value_check, max_items):
    def check(value):
        if not isinstance(value, dict) or len(value) > max_items:
            raise invalid(f"debe ser un objeto de como mucho {max_items} elementos.")
        out = {}
        for key, item in value.items():
            out[key_check(key)] = value_check(item)
        if len(out) != len(value):
            raise invalid("tiene ids repetidos.")
        return out
    return check


def dump(value):
    """Canonical JSON for storing opaque client blobs."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def query_int(query, name, default):
    """A non-negative integer from the query string."""
    value = query.get(name, "")
    if not value:
        return default
    if not (value.isascii() and value.isdigit() and len(value) <= 15):
        raise invalid(f"{name} debe ser un número.")
    return int(value)
