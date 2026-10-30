"""Password verifiers, session tokens, fake prelogin salts and login throttling."""

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

# The client already ran scrypt(2**17) on the password; this second scrypt makes a stolen database useless for
# logging in (the server never stores auth_hash itself).
VERIFIER_PARAMS = {"n": 2**14, "r": 8, "p": 1}
# What a new client uses (secretbroker/crypto.py SCRYPT_PARAMS); unknown e-mails get the same shape.
DEFAULT_KDF = {"name": "scrypt", "n": 2**17, "r": 8, "p": 1}


def b64(data):
    return base64.b64encode(data).decode("ascii")


def new_salt():
    return b64(os.urandom(16))


def verifier(auth_hash_b64, salt_b64):
    return b64(hashlib.scrypt(base64.b64decode(auth_hash_b64), salt=base64.b64decode(salt_b64),
                              **VERIFIER_PARAMS, dklen=32))


def verify(auth_hash_b64, salt_b64, expected_b64):
    return hmac.compare_digest(verifier(auth_hash_b64, salt_b64), expected_b64)


def fake_kdf(secret, email):
    """A deterministic kdf for e-mails without an account, indistinguishable from a real one."""
    salt = hmac.new(secret, b"secretbroker/prelogin/v1|" + email.encode("utf-8"), hashlib.sha256).digest()[:16]
    return {**DEFAULT_KDF, "salt": b64(salt)}


def new_token():
    return secrets.token_urlsafe(32)


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Throttle:
    """Counts failures per key; after `free` failures each new one doubles the wait, up to `max_delay` seconds.

    Kept in memory: a restart forgets it, which only gives an attacker a few extra guesses.
    """

    def __init__(self, free, max_delay=900, forget_after=3600):
        self.free, self.max_delay, self.forget_after = free, max_delay, forget_after
        self._state = {}
        self._lock = threading.Lock()

    def retry_after(self, key):
        """Seconds the caller must wait before trying again (0 = go ahead)."""
        with self._lock:
            failures, last = self._state.get(key, (0, 0.0))
        now = time.monotonic()
        if failures < self.free or now - last > self.forget_after:
            return 0
        wait = last + min(2 ** (failures - self.free), self.max_delay) - now
        return max(0, int(wait + 0.999))

    def fail(self, key):
        now = time.monotonic()
        with self._lock:
            failures, last = self._state.get(key, (0, 0.0))
            if now - last > self.forget_after:
                failures = 0
            self._state[key] = (failures + 1, now)
            if len(self._state) > 50_000:
                self._prune(now)

    def reset(self, key):
        with self._lock:
            self._state.pop(key, None)

    def _prune(self, now):
        for key in [k for k, (_, last) in self._state.items() if now - last > self.forget_after]:
            del self._state[key]
