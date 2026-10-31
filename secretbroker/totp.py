"""Time-based one-time passwords (RFC 6238, on HOTP from RFC 4226).

A web login may keep its 2FA seed in `fields.totp`: an otpauth:// URI (what a QR code holds and what
Bitwarden, 1Password and KeePassXC export) or a bare base32 seed. Only the service computes codes.
"""

import base64
import hashlib
import hmac
import re
import struct
import time
from urllib.parse import parse_qs, unquote, urlsplit

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
DEFAULTS = {"algorithm": "SHA1", "digits": 6, "period": 30}


class TotpError(ValueError):
    pass


def _seed(text):
    cleaned = re.sub(r"[\s-]+", "", str(text or "")).upper().rstrip("=")
    if not cleaned or not re.fullmatch(r"[A-Z2-7]+", cleaned):
        raise TotpError("El código 2FA no es válido: pega la URI otpauth:// o la clave en base32 que te dio la web")
    try:
        key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except ValueError:
        raise TotpError("El código 2FA no es válido: la clave en base32 está incompleta") from None
    if len(key) < 5:
        raise TotpError("El código 2FA es demasiado corto")
    return key


def parse(value):
    """{key, algorithm, digits, period, issuer, account} of an otpauth:// URI or a base32 seed."""
    text = str(value or "").strip()
    if not text.lower().startswith("otpauth://"):
        return {**DEFAULTS, "key": _seed(text), "issuer": "", "account": ""}
    parts = urlsplit(text)
    if parts.netloc.lower() != "totp":
        raise TotpError("Solo se admiten códigos por tiempo (TOTP); este es de otro tipo")
    query = {k.lower(): v[-1] for k, v in parse_qs(parts.query).items()}
    label = unquote(parts.path.lstrip("/"))
    issuer, _, account = label.rpartition(":")
    algorithm = (query.get("algorithm") or "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise TotpError(f"Algoritmo de 2FA no compatible: {algorithm}")
    try:
        digits = int(query.get("digits") or 6)
        period = int(query.get("period") or 30)
    except ValueError:
        raise TotpError("El código 2FA tiene parámetros no válidos") from None
    if digits not in (6, 7, 8) or not 10 <= period <= 300:
        raise TotpError("El código 2FA tiene parámetros no válidos")
    return {"key": _seed(query.get("secret")), "algorithm": algorithm, "digits": digits, "period": period,
            "issuer": query.get("issuer") or issuer.strip(), "account": account.strip()}


def validate(value):
    parse(value)


def hotp(key, counter, digits=6, algorithm="SHA1"):
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


def code(value, now=None):
    """{code, period, remaining, digits} for the moment `now` (seconds since the epoch)."""
    params = parse(value)
    now = time.time() if now is None else now
    counter = int(now // params["period"])
    return {"code": hotp(params["key"], counter, params["digits"], params["algorithm"]), "period": params["period"],
            "remaining": params["period"] - int(now) % params["period"], "digits": params["digits"]}
