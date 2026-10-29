"""Sign the built installer for the in-app updater (run by the release workflow).

    UPDATE_SIGNING_KEY=<base64 Ed25519 private key> python tools/sign_release.py

Writes dist/SecretBroker-Setup-<version>.exe.sig next to the installer and checks it against the
public key built into secretbroker/update.py, so a release can never ship with a mismatched key.
"""

import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secretbroker import update  # noqa: E402


def main():
    key = os.environ.get("UPDATE_SIGNING_KEY", "").strip()
    if not key:
        sys.exit("Falta UPDATE_SIGNING_KEY")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    installer = ROOT / "dist" / f"SecretBroker-Setup-{version}.exe"
    data = installer.read_bytes()
    signature = update.sign(key, version, data)
    update.verify(version, data, signature)  # the key in update.py must match
    installer.with_name(installer.name + ".sig").write_text(signature + "\n", encoding="ascii")
    print(f"Firmado {installer.name}")


if __name__ == "__main__":
    main()
