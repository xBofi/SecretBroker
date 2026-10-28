"""Vault cryptography: AES-256-GCM data key, wrapped by scrypt(master password)."""

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ~128 MiB of memory per derivation: slow enough to make offline brute force expensive.
SCRYPT_PARAMS = {"n": 2**17, "r": 8, "p": 1}


class WrongPassword(Exception):
    pass


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text)


def new_kdf():
    return {"name": "scrypt", **SCRYPT_PARAMS, "salt": b64(os.urandom(16))}


def derive_key(password, kdf):
    if kdf.get("name") != "scrypt":
        raise ValueError(f"KDF no soportado: {kdf.get('name')}")
    return hashlib.scrypt(
        password.encode("utf-8"), salt=unb64(kdf["salt"]),
        n=kdf["n"], r=kdf["r"], p=kdf["p"], maxmem=512 * 1024 * 1024, dklen=32,
    )


def seal(key, plaintext, aad):
    nonce = os.urandom(12)
    return {"nonce": b64(nonce), "ciphertext": b64(AESGCM(key).encrypt(nonce, plaintext, aad))}


def open_sealed(key, sealed, aad):
    return AESGCM(key).decrypt(unb64(sealed["nonce"]), unb64(sealed["ciphertext"]), aad)


def _kdf_aad(kdf):
    return json.dumps(kdf, sort_keys=True).encode("utf-8")


def wrap_with_password(password, data_key):
    kdf = new_kdf()
    return {"kdf": kdf, **seal(derive_key(password, kdf), data_key, _kdf_aad(kdf))}


def unwrap_with_password(password, wrap):
    try:
        return open_sealed(derive_key(password, wrap["kdf"]), wrap, _kdf_aad(wrap["kdf"]))
    except InvalidTag:
        raise WrongPassword("Contraseña maestra incorrecta") from None


def decrypt_legacy_v1(password, doc):
    """Version 1 vaults encrypted the payload directly with scrypt(master password)."""
    if doc.get("version") != 1:
        raise ValueError("No es una bóveda de la versión 1")
    header = {"version": doc["version"], "kdf": doc["kdf"]}
    try:
        plaintext = open_sealed(derive_key(password, doc["kdf"]), doc,
                                json.dumps(header, sort_keys=True).encode("utf-8"))
    except InvalidTag:
        raise WrongPassword("Contraseña maestra incorrecta") from None
    return json.loads(plaintext)
