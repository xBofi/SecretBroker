"""The platform layer: every system module offers the whole interface, and what this system offers works.

Run with:  python tests/test_platform.py   (any system; no service, no GUI)
"""

import ast
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SECRETBROKER_HOME"] = tempfile.mkdtemp(prefix="sb-platform-")

from secretbroker import platform  # noqa: E402
from secretbroker.platform import _common  # noqa: E402

failures = []


def check(condition, label):
    print(("ok   " if condition else "FAIL ") + label)
    if not condition:
        failures.append(label)


def defined_names(module_file):
    """Top-level names of a module, read from its source (the other systems' modules cannot be imported here)."""
    tree = ast.parse(module_file.read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in node.names}
    return names


for name in ("windows", "linux", "macos"):
    missing = sorted(set(_common.INTERFACE) - defined_names(ROOT / "secretbroker" / "platform" / f"{name}.py"))
    check(not missing, f"{name}.py implements the whole interface" + (f" (missing {missing})" if missing else ""))

check(all(hasattr(platform, n) for n in _common.INTERFACE), f"secretbroker.platform exports everything ({platform.NAME})")
check(platform.NAME == {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux"), "the right module is chosen")

# Keys protected for the service account open again, and only with the same entropy.
folder = Path(tempfile.mkdtemp(prefix="sb-key-"))
blob = platform.protect_for_service(b"k" * 32, b"entropy/v1", folder)
check(platform.unprotect_for_service(blob, b"entropy/v1", folder) == b"k" * 32, "service key: round trip")
try:
    platform.unprotect_for_service(blob, b"other", folder)
    check(False, "service key: another entropy is refused")
except OSError:
    check(True, "service key: another entropy is refused")

import time  # noqa: E402

started = time.monotonic()
blob = platform.protect_for_user(b"session-token", b"session/v1")
check(platform.unprotect_for_user(blob, b"session/v1") == b"session-token", "user key: round trip")
check(time.monotonic() - started < 15, "user key: never waits for a prompt")
if platform.NAME != "windows":
    kept = {b"s": "the Secret Service keyring", b"k": "the login Keychain", b"f": "a 0600 file"}
    print(f"     (kept in {kept.get(blob[:1], 'an unknown place')})")

if platform.NAME == "linux":
    import stat
    key = folder / "machine.key"
    check(stat.S_IMODE(key.stat().st_mode) == 0o600, "Linux: the service key file is 0600")
    public = folder / "broker.json"
    platform.write_public_file(public, "{}", isolated=True)
    check(stat.S_IMODE(public.stat().st_mode) == 0o640, "Linux: broker.json of the isolated service is 0640 (owner's group)")
    platform.write_public_file(public, "{}", isolated=False)
    check(stat.S_IMODE(public.stat().st_mode) == 0o600, "Linux: broker.json in development is 0600")
    env = folder / "environment"
    env.write_text('# comment\nPATH="/usr/bin"\nexport API_TOKEN=abc\nBROKEN LINE\n')
    check(_common.parse_env_file(env) == {"PATH": "/usr/bin", "API_TOKEN": "abc"}, "Linux: /etc/environment is parsed")
    check(platform.verify_os_password(platform.default_owner(), "certainly-not-the-password-123") is False,
          "Linux: a wrong account password is refused by PAM")
    check(isinstance(platform.session_locked(), bool), "Linux: the lock screen state can be asked")
    check(platform.single_instance() and not platform.single_instance(), "Linux: a second app finds the first")

if platform.NAME == "macos":
    import stat
    check(stat.S_IMODE((folder / "machine.key").stat().st_mode) == 0o600, "macOS: the service key file is 0600")
    check(isinstance(platform.session_locked(), bool), "macOS: the lock screen state can be asked")
    check(platform.single_instance() and not platform.single_instance(), "macOS: a second app finds the first")
    check(platform.verify_os_password(platform.default_owner(), "certainly-not-the-password-123") is False,
          "macOS: a wrong account password is refused by Open Directory")
    check(isinstance(platform.biometric.is_supported(), bool), "macOS: asking for Touch ID never fails")
    print(f"     (Touch ID usable here: {platform.biometric.is_supported()}; Open Directory: {platform.os_password_available()})")

# The service accepts Touch ID's proofs (Secure Enclave P-256, ECDSA-SHA256) as it accepts Windows Hello's (RSA).
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402

from secretbroker import winsec  # noqa: E402


def _der(private):
    return private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


touch = ec.generate_private_key(ec.SECP256R1())
signature = touch.sign(b"challenge", ec.ECDSA(hashes.SHA256()))
check(winsec.verify_hello_signature(_der(touch), b"challenge", signature), "Touch ID: a P-256 signature is accepted")
check(not winsec.verify_hello_signature(_der(touch), b"other", signature), "Touch ID: a signature of another challenge is refused")
other = ec.generate_private_key(ec.SECP384R1())
try:
    winsec.load_hello_public_key(_der(other))
    check(False, "Touch ID: keys on other curves are refused")
except ValueError:
    check(True, "Touch ID: keys on other curves are refused")
hello_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
check(winsec.verify_hello_signature(_der(hello_key), b"challenge", hello_key.sign(b"challenge", padding.PKCS1v15(), hashes.SHA256())),
      "Windows Hello: an RSA signature is still accepted")
weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
check(not winsec.verify_hello_signature(_der(weak), b"challenge", weak.sign(b"challenge", padding.PKCS1v15(), hashes.SHA256())),
      "Windows Hello: RSA keys under 2048 bits are still refused")

# The updater picks this system's installer from a release that carries all of them (and only with its signature).
from secretbroker import update  # noqa: E402

machine = os.uname().machine if hasattr(os, "uname") else ""
mine = {"windows": "SecretBroker-Setup-1.2.3.exe", "linux": "secretbroker_1.2.3_amd64.deb",
        "macos": f"SecretBroker-1.2.3-macos-{'arm64' if machine == 'arm64' else 'x86_64'}.pkg"}[platform.NAME]
names = ["SecretBroker-Setup-1.2.3.exe", "secretbroker_1.2.3_amd64.deb", "SecretBroker-1.2.3-macos-arm64.pkg",
         "SecretBroker-1.2.3-macos-x86_64.pkg"]
check([n for n in names if update.INSTALLER_RE.match(n)] == [mine], f"updater: only {mine} is this system's installer")


class _Release:
    def __init__(self, assets):
        self.assets = assets

    def json(self):
        return {"html_url": "https://github.com/x/y/releases/tag/v1.2.3", "body": "notes",
                "assets": [{"name": n, "browser_download_url": f"https://github.com/x/y/releases/download/v1.2.3/{n}"}
                           for n in self.assets]}


_real_get = update._get
try:
    update._get = lambda client, url, **kw: _Release(names + [n + ".sig" for n in names])
    latest = update.fetch_latest()
    check(latest and latest["installer"]["name"] == mine and latest["signature"].endswith(mine + ".sig")
          and latest["version"] == "1.2.3", "updater: the release's asset and signature for this system are chosen")
    update._get = lambda client, url, **kw: _Release(names + [n + ".sig" for n in names if n != mine])
    check(update.fetch_latest() is None, "updater: an installer without its signature is never offered")
finally:
    update._get = _real_get

print()
if failures:
    print(f"{len(failures)} FAILED")
    sys.exit(1)
print("all platform checks passed")
