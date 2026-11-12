"""Sign the built installers for the in-app updater, or check their signatures (run by the release workflow).

    UPDATE_SIGNING_KEY=<base64 Ed25519 private key> python tools/sign_release.py <installer>...
    python tools/sign_release.py --verify <installer>...
    python tools/sign_release.py --public-key <base64> ...   # release.yml's dry runs: a throwaway key

Signing writes <installer>.sig next to each installer (dist/SecretBroker-Setup-<version>.exe,
dist/secretbroker_<version>_amd64.deb, dist/SecretBroker-<version>-macos-<arch>.pkg, and the team server's
dist/secretbroker-server-<version>-linux-x86_64.tar.gz and dist/install-server.sh) and checks it against the
public key built into secretbroker/update.py, so a release can never ship with a mismatched key. --verify checks
existing .sig files against that key, as the updater will.

The job that holds the key runs this with nothing installed but cryptography (requirements/sign.txt): it imports no
SecretBroker code and no other package, and reads the public key and the signed prefix out of update.py as text.
The signed message is the one update.signed_message builds: SIGNED_PREFIX + version + NUL + SHA-256(installer)
(tests/test_e2e.py checks that a signature made here verifies with update.verify).
"""

import argparse
import ast
import base64
import hashlib
import os
import sys
import tomllib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent


def update_constants():
    """PUBLIC_KEY and SIGNED_PREFIX from secretbroker/update.py, parsed (not imported)."""
    tree = ast.parse((ROOT / "secretbroker" / "update.py").read_text(encoding="utf-8"))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("PUBLIC_KEY", "SIGNED_PREFIX"):
                found[node.targets[0].id] = ast.literal_eval(node.value)
    return found["PUBLIC_KEY"], found["SIGNED_PREFIX"]


def project_version():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def signed_message(prefix, version, data):
    return prefix + version.encode() + b"\0" + hashlib.sha256(data).digest()


def sign(private_key_b64, version, data, prefix):
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(key.sign(signed_message(prefix, version, data))).decode()


def verify(public_key_b64, version, data, signature_b64, prefix):
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64)).verify(
        base64.b64decode(signature_b64.strip()), signed_message(prefix, version, data))


def main():
    parser = argparse.ArgumentParser(description="Sign installers for the updater, or verify their signatures.")
    parser.add_argument("--verify", action="store_true", help="check <installer>.sig instead of writing it")
    parser.add_argument("--public-key", help="check against this key instead of update.py's (dry runs only)")
    parser.add_argument("installers", nargs="*", type=Path)
    options = parser.parse_args()

    public_key, prefix = update_constants()
    public_key = options.public_key or public_key
    if not public_key:
        sys.exit("secretbroker/update.py no tiene PUBLIC_KEY")
    version = project_version()
    installers = options.installers or [ROOT / "dist" / f"SecretBroker-Setup-{version}.exe"]
    key = None
    if not options.verify:
        key = os.environ.get("UPDATE_SIGNING_KEY", "").strip()
        if not key:
            sys.exit("Falta UPDATE_SIGNING_KEY")

    for installer in installers:
        # install-server.sh has no version in its name; its signature still binds the release's version.
        if version not in installer.name and installer.name != "install-server.sh":
            sys.exit(f"{installer.name} no es de la versión {version}")
        data = installer.read_bytes()
        sig_path = installer.with_name(installer.name + ".sig")
        if options.verify:
            signature = sig_path.read_text(encoding="ascii")
        else:
            signature = sign(key, version, data, prefix)
        try:
            verify(public_key, version, data, signature, prefix)  # the key in update.py must match
        except (InvalidSignature, ValueError):
            sys.exit(f"La firma de {installer.name} no es válida con la clave de secretbroker/update.py")
        if options.verify:
            print(f"ok {installer.name}")
        else:
            sig_path.write_text(signature + "\n", encoding="ascii")
            print(f"Firmado {installer.name}")


if __name__ == "__main__":
    main()
