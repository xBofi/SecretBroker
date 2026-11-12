"""Test releases for the installer and updater checks in CI (.github/workflows/ci.yml, job server-install). Never
used for real releases, which tools/sign_release.py signs with UPDATE_SIGNING_KEY.

    python fake_release.py keygen                              -> {"private": ..., "public": ...} (a throwaway key)
    TEST_SIGNING_KEY=<private> python fake_release.py sign FILE VERSION       -> FILE.sig
    python fake_release.py repack ARTIFACT OUTDIR VERSION [--broken]
        a copy of a built server artifact that says it is VERSION (VERSION file and __version__); --broken makes
        its server exit at once, so its health check fails (the updater must roll back)
"""

import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from pathlib import Path

PREFIX = b"SecretBroker release\0"


def keygen():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(json.dumps({"private": base64.b64encode(raw).decode(), "public": base64.b64encode(pub).decode()}))


def sign(path, version):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ["TEST_SIGNING_KEY"]))
    data = Path(path).read_bytes()
    signature = key.sign(PREFIX + version.encode() + b"\0" + hashlib.sha256(data).digest())
    Path(path + ".sig").write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")


def repack(artifact, outdir, version, broken=False):
    name = re.sub(r"-\d+\.\d+\.\d+-linux-", f"-{version}-linux-", Path(artifact).name)
    out = Path(outdir) / name
    Path(outdir).mkdir(parents=True, exist_ok=True)
    with tarfile.open(artifact, "r:gz") as src, tarfile.open(out, "w:gz") as dst:
        for member in src.getmembers():
            path = member.name.lstrip("./")
            if re.search(r"secretbroker_server/__pycache__/(__init__|__main__)\.", path):
                continue  # compiled with the old text; the edited source is used instead
            data = src.extractfile(member).read() if member.isfile() else None
            if path == "VERSION":
                data = f"{version}\n".encode()
            elif path.endswith("site-packages/secretbroker_server/__init__.py"):
                data = re.sub(rb'__version__ = "[^"]+"', f'__version__ = "{version}"'.encode(), data)
            elif broken and path.endswith("site-packages/secretbroker_server/__main__.py"):
                data = b"import sys\nsys.exit('this test version never starts')\n"
            if data is not None:
                member.size = len(data)
                dst.addfile(member, io.BytesIO(data))
            else:
                dst.addfile(member)
    print(out)


if __name__ == "__main__":
    command, args = sys.argv[1], sys.argv[2:]
    if command == "keygen":
        keygen()
    elif command == "sign":
        sign(*args)
    elif command == "repack":
        repack(args[0], args[1], args[2], "--broken" in args)
    else:
        sys.exit(__doc__)
