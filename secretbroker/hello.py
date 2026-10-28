"""Windows Hello for the desktop app: a TPM-backed key that only signs after PIN / fingerprint / face."""

import asyncio

KEY_NAME = "SecretBroker"


class HelloError(Exception):
    pass


class HelloCancelled(HelloError):
    pass


def _winrt():
    from winrt.windows.security.credentials import (
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    )
    from winrt.windows.security.cryptography import CryptographicBuffer
    from winrt.windows.security.cryptography.core import CryptographicPublicKeyBlobType
    return KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus, CryptographicBuffer, CryptographicPublicKeyBlobType


def _check(status, statuses):
    if status == statuses.SUCCESS:
        return
    if status in (statuses.USER_CANCELED, statuses.USER_PREFERS_PASSWORD):
        raise HelloCancelled("Verificación cancelada")
    if status == statuses.NOT_FOUND:
        raise HelloError("Windows Hello no está configurado para SecretBroker en este usuario")
    if status == statuses.SECURITY_DEVICE_LOCKED:
        raise HelloError("El dispositivo de seguridad está bloqueado; inténtalo más tarde")
    raise HelloError(f"Windows Hello devolvió un error ({status})")


def is_supported():
    try:
        _, manager, *_ = _winrt()
        return bool(asyncio.run(manager.is_supported_async()))
    except Exception:
        return False


def create_key():
    """Create (or replace) the Hello key. Shows the Windows Hello prompt. Returns the public key (DER)."""
    option, manager, statuses, _, blob_type = _winrt()

    async def run():
        result = await manager.request_create_async(KEY_NAME, option.REPLACE_EXISTING)
        _check(result.status, statuses)
        return bytes(result.credential.retrieve_public_key(blob_type.X509_SUBJECT_PUBLIC_KEY_INFO))

    return asyncio.run(run())


def sign(message):
    """Sign with the Hello key. Shows the Windows Hello prompt every time."""
    _, manager, statuses, buffers, _ = _winrt()

    async def run():
        opened = await manager.open_async(KEY_NAME)
        _check(opened.status, statuses)
        signed = await opened.credential.request_sign_async(buffers.create_from_byte_array(message))
        _check(signed.status, statuses)
        return bytes(signed.result)

    return asyncio.run(run())


def delete_key():
    _, manager, *_ = _winrt()
    try:
        asyncio.run(manager.delete_async(KEY_NAME))
    except Exception:
        pass
