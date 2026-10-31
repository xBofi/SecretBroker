# SecretBroker export formats

SecretBroker never locks your data in. Settings → *Importar y exportar* → *Exportar* writes one of three files.
All of them are built by the service (`secretbroker/exports.py`); the desktop app only writes the result to the file
you pick. Exporting needs the one-click presence proof of the app that unlocked the vault (or Hello / a password if
that app was restarted), never the AI: `export_vault` is not in `AI_OPS`.

## 1. Encrypted export (`.sbexport`, recommended)

A JSON document:

```json
{
  "format": "secretbroker-encrypted-export",
  "version": 1,
  "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<16 random bytes, base64>"},
  "nonce": "<12 random bytes, base64>",
  "ciphertext": "<AES-256-GCM ciphertext + 16-byte tag, base64>"
}
```

* `key = scrypt(password_utf8, salt, n, r, p, dklen=32)` — the same parameters as the vault (about 128 MiB of
  memory per guess). The file password is chosen when exporting (at least 12 characters) and is independent of
  the master password.
* `aad = b"secretbroker/export/v1|" + JSON({"format", "version", "kdf"}, keys sorted, separators "," and ":")`, so
  the header (including the KDF parameters) cannot be changed without the decryption failing.
* `plaintext = AES-256-GCM-decrypt(key, nonce, ciphertext, aad)` is the UTF-8 JSON of a plain export (section 2).
* Nothing else is stored in clear: not the number of credentials, not their names.

To read it without SecretBroker (Python, `cryptography` package):

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

doc = json.load(open("SecretBroker-exportacion.sbexport", encoding="utf-8"))
kdf = doc["kdf"]
key = hashlib.scrypt(password.encode(), salt=base64.b64decode(kdf["salt"]), n=kdf["n"], r=kdf["r"], p=kdf["p"],
                     maxmem=512 * 1024 * 1024, dklen=32)
header = {"format": doc["format"], "version": doc["version"], "kdf": kdf}
aad = b"secretbroker/export/v1|" + json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
plain = json.loads(AESGCM(key).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["ciphertext"]), aad))
```

Importing it back (Settings → *Importar*, or the same button on an empty vault) asks for the file password,
shows the list of names and skips the credentials you already have.

## 2. Plain JSON (`.json`, unencrypted)

```json
{
  "format": "secretbroker-export",
  "version": 1,
  "exported": "2026-10-31T10:00:00+00:00",
  "app": "0.15.0",
  "entries": [
    {
      "id": "github", "name": "GitHub", "template": "api_key", "description": "Notes the AI reads",
      "fields": {"value": "…", "base_url": "https://api.github.com", "auth_style": "bearer", "notes": "…"},
      "policy": {"approval": "session", "http": {"allowed_hosts": ["api.github.com"], "auth": {"kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}}},
      "tags": ["work"], "expires": "2027-01-01", "rotate_every_days": 90, "check_every_hours": 24,
      "used_in": ["pro: Vercel"], "rotation_guide": {"create": ["…"], "sources": ["https://…"]},
      "secret_since": "2026-01-01T00:00:00+00:00", "updated": "2026-01-01T00:00:00+00:00"
    }
  ]
}
```

Each entry is the vault entry as stored (see `secretbroker/templates.py` for the fields of each template; `notes` is
the private-notes field the AI never sees). Empty keys are left out. Local bookkeeping is not exported: exposure
findings, approvals, where a key was uploaded (GitHub secrets) and keys retired by a rotation.

## 3. Plain CSV (`.csv`, unencrypted)

Chrome's columns, which Bitwarden, 1Password, KeePassXC, Firefox and Chrome/Edge all import:

```
name,url,username,password,note
```

* `url`: the credential's URL, API URL, or `host:port` for servers and databases.
* `username`: the user, or the AWS access key id.
* `password`: the main secret (password, API key, secret access key or private key).
* `note`: the private notes.

It is lossy (AI notes, permissions, tags and dates are dropped); use the encrypted export to move between
SecretBroker installs.

## Importing from other managers

`secretbroker/importers.py` reads Bitwarden (unencrypted `.json` and `.csv`), 1Password (`.csv`), KeePass 2 and
KeePassXC (`.csv`), Chrome / Edge / Brave (`.csv`), Firefox (`.csv`), any CSV with name/url/username/password
columns, and the two SecretBroker exports above. The service maps each item to a template (web login, API key
when the value is obviously one, e.g. `ghp_…`, or a generic secret), puts notes, TOTP seeds and custom fields into
the private notes, turns folders into tags, and compares every item with the vault (same site and user and same
password: already there; another password: conflict). The app only receives names, users, sites and statuses.
Cards and identities are skipped. A project's `.env` goes through `sb import`.
