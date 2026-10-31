"""Windows security primitives used by the service: DPAPI, Windows password check, Hello (and Touch ID) signatures."""

import ctypes
import sys

from .i18n import tr

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi32.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]

CRYPTPROTECT_UI_FORBIDDEN = 0x1
LOGON32_LOGON_INTERACTIVE = 2
LOGON32_PROVIDER_DEFAULT = 0


def _blob(data):
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _dpapi(function, data, entropy, *extra):
    if not IS_WINDOWS:
        raise OSError(tr("winsec.dpapi_is_only_available_on"))
    data_blob, _keep1 = _blob(data)
    entropy_blob, _keep2 = _blob(entropy)
    out = _DataBlob()
    if not function(ctypes.byref(data_blob), *extra, ctypes.byref(entropy_blob), None, None,
                    CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _kernel32.LocalFree(out.pbData)


def dpapi_protect(data, entropy):
    """Encrypt so that only this Windows account (on this PC) can decrypt."""
    return _dpapi(_crypt32.CryptProtectData, data, entropy, "SecretBroker")


def dpapi_unprotect(data, entropy):
    return _dpapi(_crypt32.CryptUnprotectData, data, entropy, None)


def verify_windows_password(owner, password):
    """Check the owner's Windows account password (not the PIN) with LogonUser."""
    if not IS_WINDOWS or not password:
        return False
    domain, _, user = owner.rpartition("\\")
    token = wintypes.HANDLE()
    ok = _advapi32.LogonUserW(user, domain or ".", password, LOGON32_LOGON_INTERACTIVE,
                              LOGON32_PROVIDER_DEFAULT, ctypes.byref(token))
    if ok:
        _kernel32.CloseHandle(token)
    return bool(ok)


def load_hello_public_key(der):
    """Windows Hello keys are RSA (2048 bits or more); Touch ID keys (macOS, secretbroker/touchid.py) are
    Secure Enclave EC P-256 keys."""
    key = load_der_public_key(der)
    if isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048:
        return key
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return key
    raise ValueError(tr("winsec.invalid_windows_hello_public_key"))


def verify_hello_signature(public_key_der, message, signature):
    """Windows Hello (KeyCredential) keys sign with PKCS#1 v1.5 + SHA-256; Touch ID keys with ECDSA + SHA-256."""
    try:
        key = load_hello_public_key(public_key_der)
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
