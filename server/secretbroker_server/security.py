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


def fake_kdf(secret, email, purpose="prelogin"):
    """A deterministic kdf for e-mails without an account (or, for `purpose` "recovery", without a recovery code),
    indistinguishable from a real one."""
    salt = hmac.new(secret, f"secretbroker/{purpose}/v1|".encode("ascii") + email.encode("utf-8"),
                    hashlib.sha256).digest()[:16]
    return {**DEFAULT_KDF, "salt": b64(salt)}


def signed_by(public_key_b64, signature_b64, message):
    """Whether `signature_b64` is an Ed25519 signature of `message` by that public key. Never raises."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64)).verify(
            base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


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


class Window:
    """At most `limit` events per key in any `seconds`-long window. In memory, like Throttle."""

    def __init__(self, limit, seconds):
        self.limit, self.seconds = limit, seconds
        self._times = {}
        self._lock = threading.Lock()

    def hit(self, key):
        """Count one event; returns 0 if allowed, else the seconds to wait (the event is not counted)."""
        now = time.monotonic()
        with self._lock:
            times = [t for t in self._times.get(key, []) if now - t < self.seconds]
            if len(times) >= self.limit:
                self._times[key] = times
                return max(1, int(times[0] + self.seconds - now + 0.999))
            times.append(now)
            self._times[key] = times
            if len(self._times) > 50_000:
                self._times = {k: v for k, v in self._times.items() if v and now - v[-1] < self.seconds}
            return 0


class Challenges:
    """Single-use challenges an account's device signs with the account's Ed25519 key to prove it holds the private
    keys (a password reset from a connected device, setting a recovery code, finishing a recovery). One live
    challenge per account and purpose (a new one replaces it), each valid for `seconds`. In memory, like Throttle:
    a restart only means asking for a new one."""

    def __init__(self, seconds=300):
        self.seconds = seconds
        self._items = {}
        self._lock = threading.Lock()

    def issue(self, user_id, purpose):
        challenge, now = secrets.token_urlsafe(32), time.monotonic()
        with self._lock:
            self._items[(user_id, purpose)] = (challenge, now + self.seconds)
            if len(self._items) > 50_000:
                self._items = {k: v for k, v in self._items.items() if v[1] > now}
        return challenge

    def take(self, user_id, purpose, challenge):
        """True once for the live challenge of that account and purpose; it can't be used again."""
        with self._lock:
            item = self._items.get((user_id, purpose))
            if item is None or not hmac.compare_digest(item[0].encode(), str(challenge).encode()):
                return False
            del self._items[(user_id, purpose)]
        return item[1] > time.monotonic()
