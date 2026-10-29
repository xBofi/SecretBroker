r"""Create the release signing key without anybody seeing it.

    python tools/new_signing_key.py <repo public key id> <repo public key (base64)>

Generates an Ed25519 key pair and prints, as JSON, only:
  public_key       to paste into secretbroker/update.py (PUBLIC_KEY)
  key_id           \ the body for PUT /repos/{repo}/actions/secrets/UPDATE_SIGNING_KEY: the private
  encrypted_value  / key sealed with the repository's key, readable only by GitHub Actions
The private key itself is never printed or written to disk.
"""

import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PublicKey, SealedBox


def main():
    key_id, repo_key = sys.argv[1], sys.argv[2]
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sealed = SealedBox(PublicKey(base64.b64decode(repo_key))).encrypt(base64.b64encode(raw_private))
    print(json.dumps({"public_key": base64.b64encode(raw_public).decode(), "key_id": key_id,
                      "encrypted_value": base64.b64encode(sealed).decode()}))


if __name__ == "__main__":
    main()
