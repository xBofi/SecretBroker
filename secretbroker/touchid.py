"""Touch ID for the desktop app on macOS: a Secure Enclave key that only signs after the user's fingerprint.

The same interface as hello.py (Windows Hello), so the service treats both alike: create_key() returns the public
key (DER, EC P-256), sign() an ECDSA-SHA256 signature that service.py checks with winsec.verify_hello_signature.

The private key never leaves the Secure Enclave and is bound to the fingerprints enrolled when it was created
(kSecAccessControlBiometryCurrentSet): adding a finger in System Settings invalidates it, and the user activates
Touch ID again. Keeping a Secure Enclave key needs the data protection keychain, which macOS only grants to a
signed app with a keychain-access-groups entitlement (docs/RELEASING.md). An unsigned build gets
errSecMissingEntitlement: is_supported() is False there and the app uses password proofs, as on a Mac without
Touch ID.

pyobjc is imported only when asked, on macOS: importing this module on Windows or Linux loads nothing.
"""

import sys
import threading
import time

from .hello import HelloCancelled, HelloError  # noqa: F401  (the app catches these for every system)
from .i18n import tr

LABEL = "Touch ID"
KEY_TAG = b"com.secretbroker.touchid"
SUPPORTED_CACHE_SECONDS = 30

ERR_ITEM_NOT_FOUND = -25300
ERR_USER_CANCELED = -128
ERR_MISSING_ENTITLEMENT = -34018
LA_CANCELLED = (-2, -3, -4, -9)  # userCancel, userFallback, systemCancel, appCancel
LA_LOCKOUT = -8

_supported = {"at": 0.0, "value": False}
_guard = threading.Lock()


def _frameworks():
    if sys.platform != "darwin":
        raise HelloError(tr("touchid.only_exists_on_macos"))
    import LocalAuthentication
    import Security
    return Security, LocalAuthentication


def _code(error):
    try:
        return int(error.code())
    except Exception:
        return 0


def _fail(error, doing_key):
    code = _code(error)
    if code == ERR_USER_CANCELED or code in LA_CANCELLED:
        raise HelloCancelled(tr("app.verification_cancelled"))
    if code == LA_LOCKOUT:
        raise HelloError(tr("touchid.locked_out"))
    if code == ERR_MISSING_ENTITLEMENT:
        raise HelloError(tr("touchid.app_not_signed"))
    raise HelloError(tr(doing_key, code=code))


def _key_query(Security, context=None, ref=True):
    query = {Security.kSecClass: Security.kSecClassKey,
             Security.kSecAttrKeyType: Security.kSecAttrKeyTypeECSECPrimeRandom,
             Security.kSecAttrApplicationTag: KEY_TAG,
             Security.kSecUseDataProtectionKeychain: True}
    if ref:
        query[Security.kSecReturnRef] = True
    if context is not None:
        query[Security.kSecUseAuthenticationContext] = context
    return query


def _probe():
    Security, LocalAuthentication = _frameworks()
    context = LocalAuthentication.LAContext.alloc().init()
    can, _error = context.canEvaluatePolicy_error_(LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics, None)
    if not can:
        return False
    # Without the entitlement, the data protection keychain answers errSecMissingEntitlement to any query.
    context.setInteractionNotAllowed_(True)
    status, _found = Security.SecItemCopyMatching(_key_query(Security, context, ref=False), None)
    return status in (0, ERR_ITEM_NOT_FOUND)


def is_supported():
    """This Mac has Touch ID with a finger enrolled, and this build may keep a Secure Enclave key."""
    with _guard:
        if time.monotonic() - _supported["at"] > SUPPORTED_CACHE_SECONDS:
            try:
                _supported["value"] = bool(_probe())
            except Exception:
                _supported["value"] = False
            _supported["at"] = time.monotonic()
        return _supported["value"]


def _public_der(Security, private_key):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    point, error = Security.SecKeyCopyExternalRepresentation(Security.SecKeyCopyPublicKey(private_key), None)
    if point is None:
        _fail(error, "touchid.error_reading_key")
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(point))  # X9.63: 04 || X || Y
    return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def create_key():
    """Create (or replace) the Touch ID key in the Secure Enclave. Returns the public key (DER).

    Creating it asks for nothing: the fingerprint is asked for on every signature, and enrolling in the service
    signs nothing (the user proved who they are with a password first, see service.op_enroll_hello)."""
    Security, _ = _frameworks()
    delete_key()
    access, error = Security.SecAccessControlCreateWithFlags(
        None, Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        Security.kSecAccessControlPrivateKeyUsage | Security.kSecAccessControlBiometryCurrentSet, None)
    if access is None:
        _fail(error, "touchid.error_preparing_key")
    attributes = {
        Security.kSecAttrKeyType: Security.kSecAttrKeyTypeECSECPrimeRandom,
        Security.kSecAttrKeySizeInBits: 256,
        Security.kSecAttrTokenID: Security.kSecAttrTokenIDSecureEnclave,
        Security.kSecUseDataProtectionKeychain: True,
        Security.kSecPrivateKeyAttrs: {
            Security.kSecAttrIsPermanent: True,
            Security.kSecAttrApplicationTag: KEY_TAG,
            Security.kSecAttrLabel: "SecretBroker (Touch ID)",
            Security.kSecAttrAccessControl: access,
        },
    }
    key, error = Security.SecKeyCreateRandomKey(attributes, None)
    if key is None:
        _fail(error, "touchid.error_creating_key")
    _supported["at"] = 0.0
    return _public_der(Security, key)


def sign(message):
    """Sign with the Touch ID key. macOS shows its fingerprint sheet every time."""
    Security, LocalAuthentication = _frameworks()
    context = LocalAuthentication.LAContext.alloc().init()
    context.setLocalizedReason_(tr("touchid.reason"))  # macOS shows it under «SecretBroker wants to…»
    status, key = Security.SecItemCopyMatching(_key_query(Security, context), None)
    if status == ERR_ITEM_NOT_FOUND:
        raise HelloError(tr("touchid.isn_set_up"))
    if status != 0 or key is None:
        raise HelloError(tr("touchid.error_finding_key", status=status))
    signature, error = Security.SecKeyCreateSignature(
        key, Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256, bytes(message), None)
    if signature is None:
        _fail(error, "touchid.error_signing")
    return bytes(signature)


def delete_key():
    try:
        Security, _ = _frameworks()
        Security.SecItemDelete(_key_query(Security, ref=False))
    except Exception:
        pass
