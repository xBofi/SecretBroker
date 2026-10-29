"""Updates from GitHub Releases, accepted only when signed with the release key.

Every release carries SecretBroker-Setup-<version>.exe and a .sig file: an Ed25519 signature over
SIGNED_PREFIX + version + NUL + SHA-256(installer). The public key below lives in Program Files with
the rest of the code, so only an administrator can change which key is trusted. Binding the version
stops an old (vulnerable) signed release from being offered as a new one.

The service downloads and verifies the installer into its public folder, which the desktop user can
read and run but not modify, so nothing can swap the file between verification and installation.
"""

import base64
import hashlib
import re
import time
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import __version__

REPO = "xBofi/SecretBroker"
RELEASES_URL = f"https://github.com/{REPO}/releases"
LATEST_API = f"https://api.github.com/repos/{REPO}/releases/latest"
PUBLIC_KEY = "Y54EWQu13b79ilylP/cAvqFDvzxjkwiYkEq/puedHos="  # base64 raw Ed25519; the private half is the UPDATE_SIGNING_KEY secret
SIGNED_PREFIX = b"SecretBroker release\0"
INSTALLER_RE = re.compile(r"^SecretBroker-Setup-(\d+\.\d+\.\d+)\.exe$")
CHECK_EVERY_SECONDS = 6 * 3600
TIMEOUT = 30
MAX_INSTALLER_BYTES = 200 * 1024 * 1024


class UpdateError(Exception):
    pass


def parse_version(text):
    try:
        return tuple(int(part) for part in str(text).lstrip("v").split("."))
    except ValueError:
        return ()


def signed_message(version, digest):
    return SIGNED_PREFIX + version.encode() + b"\0" + digest


def sign(private_key_b64, version, data):
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(key.sign(signed_message(version, hashlib.sha256(data).digest()))).decode()


def verify(version, data, signature_b64, public_key_b64=None):
    public_key_b64 = public_key_b64 or PUBLIC_KEY
    if not public_key_b64:
        raise UpdateError("Esta versión no tiene clave de firma: no puede actualizarse sola")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64)).verify(
            base64.b64decode(signature_b64.strip()), signed_message(version, hashlib.sha256(data).digest()))
    except (InvalidSignature, ValueError):
        raise UpdateError("La firma del instalador no es válida: no se instalará") from None


def _get(client, url, **kwargs):
    response = client.get(url, **kwargs)
    if response.status_code != 200:
        raise UpdateError(f"GitHub respondió HTTP {response.status_code}")
    return response


def fetch_latest():
    """The newest release: {"version", "notes", "url", "installer", "signature"}, or None without installer."""
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        release = _get(client, LATEST_API, headers={"Accept": "application/vnd.github+json"}).json()
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    for name, url in assets.items():
        match = INSTALLER_RE.match(name)
        if match and name + ".sig" in assets:
            return {"version": match[1], "notes": (release.get("body") or "")[:4000], "url": release.get("html_url"),
                    "installer": {"name": name, "url": url}, "signature": assets[name + ".sig"]}
    return None


def _allowed_download(url):
    host = httpx.URL(url).host
    return url.startswith("https://") and (host == "github.com" or host.endswith(".githubusercontent.com"))


def _download(client, url):
    # GitHub answers asset downloads with a redirect to its storage host: follow it only there.
    for _ in range(3):
        if not _allowed_download(url):
            raise UpdateError("Descarga desde un sitio no permitido")
        response = client.get(url)
        if response.is_redirect:
            url = response.headers["location"]
            continue
        if response.status_code != 200:
            raise UpdateError(f"La descarga respondió HTTP {response.status_code}")
        if len(response.content) > MAX_INSTALLER_BYTES:
            raise UpdateError("El instalador es demasiado grande")
        return response.content
    raise UpdateError("Demasiadas redirecciones")


def download(latest, folder):
    """Download and verify the installer of `latest` into `folder`. Returns its path."""
    if parse_version(latest["version"]) <= parse_version(__version__):
        raise UpdateError("No hay ninguna versión más nueva")
    with httpx.Client(timeout=TIMEOUT * 4, follow_redirects=False) as client:
        signature = _download(client, latest["signature"]).decode("ascii", errors="replace")
        data = _download(client, latest["installer"]["url"])
    verify(latest["version"], data, signature)
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob("SecretBroker-Setup-*.exe"):
        old.unlink(missing_ok=True)
    path = folder / latest["installer"]["name"]
    tmp = path.with_suffix(".part")
    tmp.write_bytes(data)
    tmp.replace(path)
    return path


class Checker:
    """Caches the latest release so the app can ask often without hitting GitHub each time."""

    def __init__(self):
        self._latest = None
        self._checked = 0.0
        self._error = None

    def status(self, force=False):
        if force or time.monotonic() - self._checked > CHECK_EVERY_SECONDS:
            try:
                self._latest, self._error = fetch_latest(), None
            except (httpx.HTTPError, UpdateError, ValueError, KeyError) as exc:
                self._error = str(exc) or type(exc).__name__
            self._checked = time.monotonic()
        latest = self._latest
        available = bool(latest and PUBLIC_KEY and parse_version(latest["version"]) > parse_version(__version__))
        return {"current": __version__, "latest": latest["version"] if latest else None, "available": available,
                "notes": latest["notes"] if available else "", "url": latest["url"] if latest else RELEASES_URL,
                "error": self._error}

    def latest(self):
        return self._latest
