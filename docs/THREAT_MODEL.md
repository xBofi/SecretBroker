# SecretBroker threat model

This document says what SecretBroker protects, from whom, how, and where the protection ends. It is based on the
security model in [README.es.md](../README.es.md#modelo-de-seguridad) and on sections 2-4 of
[ARCHITECTURE.md](ARCHITECTURE.md). If you find a gap that is not listed under "limits", please report it as described
in [SECURITY.md](../SECURITY.md).

## 1. Assets

| Asset | Where it lives |
|---|---|
| Secret values (API keys, passwords, SSH keys, connection strings) | Encrypted vault, service memory while unlocked, the target process during `run_command` / `sb run` |
| Vault data key and master password | Data key wrapped by scrypt(master password) and by DPAPI; master password only typed in the app |
| Credential metadata (names, notes, tags, policies, `used_in`) | Encrypted vault; shared items encrypted with their collection key |
| Credential policies (allowed hosts, programs, env variables) | Encrypted vault; they decide where a key can go |
| Approvals and presence | Service memory; Windows Hello key in the TPM |
| Activity history | Encrypted with an X25519 public key derived from the vault (write-only while locked) |
| Team account keys (X25519, Ed25519) | Vault; on the server only as `private_blob` wrapped by a key derived from the account password |
| Collection keys | Sealed to each member's X25519 key, grants signed by the granter's Ed25519 key |
| Release signing key | GitHub Actions secret (maintainers only); public key pinned in `secretbroker/update.py` |

## 2. Trust boundaries

1. **The user's Windows session**: the app window, the AI agent, the user's other programs.
2. **The SecretBroker service**: a separate, non-interactive Windows account, code in Program Files run with `python -I`.
   Only it can read the vault files.
3. **Remote endpoints**: providers and servers that receive the injected key.
4. **The team server**: stores ciphertext, public keys and routing metadata. Untrusted for confidentiality.
5. **The update channel**: GitHub Releases. Untrusted; every installer is signature-checked.

## 3. Actors

### 3.1 Curious or malicious AI agent

The agent is assumed to be capable, possibly prompt-injected, and to run with the user's privileges.

**Mitigations**
- No AI operation returns a secret value. Output from HTTP, SSH and commands is redacted (literal, base64, URL-encoded,
  JSON-escaped and connection-string forms).
- Per-credential allow-lists: HTTPS only to listed hosts, no redirects followed, SSH host taken from the vault, only
  listed programs and environment variables.
- Approvals need the user's presence: a Windows Hello signature (or Windows/master password where Hello is missing)
  over a single-use challenge bound to that operation. The agent cannot approve itself.
- AI changes that widen where a key can go wait for the user's approval; the AI cannot change approval modes or secret
  values. Per-action levels (free, notify, ask, never), unusual-use limits and a "pause the AI" kill switch.
- The MCP endpoint listens on `127.0.0.1`, requires a token and checks `Host` and `Origin`, so web pages cannot drive it.
- The exposure scanner only answers "is this text in the vault?" inside a session granted at unlock, so it cannot be
  used as a guessing oracle.

**Limits**
- A program allowed in `run_command` or started with `sb run` receives the key in clear. An agent that can write and run
  code in such a program (for example `node -e`, `python`) can exfiltrate it. Allow only the programs you need.
- Redaction is best effort against transformations it knows. An allowed endpoint that echoes data back in an unusual
  encoding, or an allowed host the agent controls, can leak a key. Keep allow-lists tight.
- An approved "allow today" credential can be used for any allowed operation during that window.
- Approval prompts show what is being asked; a user who approves without reading can be socially engineered.

### 3.2 Malware in the user's session

A program running as the user, without administrator rights.

**Mitigations**
- The vault, the service memory and its code belong to another Windows account; reading or patching them needs
  administrator elevation.
- The service ignores user environment variables and user site-packages (`python -I`).
- Service responses are signed (Ed25519) with a key only the real service has, so a fake service cannot impersonate it
  to the app.
- Registering a new Windows Hello key requires the master or Windows password.
- Clipboard copies are cleared after 30 s and excluded from clipboard history.

**Limits**
- Anything shown or typed on the desktop is exposed: keyloggers can capture the master password, screen capture and
  clipboard snooping can capture revealed or copied secrets, and fake windows can trick the user. This applies to every
  password manager.
- With "open with my Windows session" enabled, anyone who can use the unlocked session can use the vault through the
  app.
- Malware with administrator rights (or a user who runs the AI agent as administrator) defeats the account isolation.

### 3.3 Malicious teammate

A member of an organization, with some permission on a collection.

**Mitigations**
- A member only receives keys for collections they were granted; the server cannot add itself or others because grants
  are signed and fingerprints are pinned.
- Synced changes to anything that decides where a key can go (policy hosts, commands, env) are quarantined locally until
  the user accepts them. The local approval mode is never taken from the server.
- `use` permission: the app does not reveal or copy the credential; the AI and `sb run` can still use it.
- The server keeps an audit log of metadata events (grants, removals, item writes) readable by admins.

**Limits**
- `use` is enforced by the member's client. A teammate running a modified client can decrypt anything they can use.
  Treat `use` as "will not see it by accident", not as a cryptographic barrier.
- A member with `edit` can change names, notes and secret values of shared items (these apply immediately). Notes are
  read by your AI, so a malicious note is a prompt-injection vector; policies still bound where keys can go.
- A member with `manage` can grant access to others in the organization.

### 3.4 Removed teammate

**Mitigations**
- Removal marks every collection they could read `needs_rekey`; a member with `manage` re-keys it atomically (new key,
  items re-encrypted, new grants), and the server refuses grants with the old key version.
- The server stops serving those collections to them as soon as they are removed.
- Every credential they could see is flagged "rotate: <person> had access" in reminders and the guided rotation wizard.

**Limits**
- Re-keying protects future changes only. Anything they saw, copied or used while they were a member must be rotated
  at the provider; SecretBroker reminds you, it cannot do it for every provider.
- Copies already synced to their devices stay readable by them until the underlying keys are rotated.

### 3.5 Compromised or malicious team server

**Mitigations**
- Zero knowledge: the server never sees secrets, credential names or collection names. Items, names and keys are
  encrypted client side (AES-256-GCM, X25519 sealing) with associated data binding each ciphertext to its collection,
  item and key version, so ciphertexts cannot be swapped between items.
- The account password never leaves the client: the server gets an HKDF-derived `auth_hash` (stored hashed with scrypt)
  and an opaque `private_blob`.
- Key grants are Ed25519-signed by the granter and verified against pinned keys, so the server cannot inject its own
  collection keys or substitute a member's public key without a fingerprint change the user must confirm.
- Quarantine of policy-widening changes (3.3) also covers changes forged by the server.

**Limits**
- Metadata is visible: e-mail addresses, organization names, membership graph, permissions, item counts, sizes and
  timestamps.
- The server can deny service, delete data, withhold updates or roll an item back to an older ciphertext it has seen.
- An attacker who controls the server can try offline guessing of weak account passwords from `private_blob` and the
  scrypt parameters. Use a strong account password.
- First contact with a new member is trust on first use: if the server lies about a key the first time you see a user,
  only comparing fingerprints out of band detects it.

### 3.6 Network attacker

**Mitigations**
- Provider calls are HTTPS only, with certificate validation and no redirects.
- The team server refuses a non-HTTPS public URL (except an explicit local-testing switch), and its payloads are
  end-to-end encrypted anyway.
- Updates are only installed when their Ed25519 signature matches the pinned release key, regardless of the transport.
- The MCP endpoint is loopback-only.

**Limits**
- SSH host keys are remembered on first use and checked afterwards; the very first connection to a host is trust on
  first use.
- Metadata of team traffic (timing, sizes) is visible to the network path.

### 3.7 Stolen disk or backup

**Mitigations**
- The vault is AES-256-GCM under a random data key wrapped by scrypt (128 MiB) of the master password; on the PC the
  copy is additionally wrapped with DPAPI.
- Backups are the encrypted vault; restoring needs the master password the backup had.
- Online guessing through the app is slowed with increasing delays after each failure.

**Limits**
- A weak master password can be brute-forced offline from a stolen backup, slowly. Choose a long passphrase.
- Windows Hello and Windows-password recovery work only on the original PC; they do not help an attacker with a backup,
  but they also mean the backup alone is only as strong as the master password.

## 4. Out of scope

- Compromise of the provider or server that legitimately receives a key.
- Physical attacks on an unlocked, unattended PC.
- An attacker with administrator or SYSTEM rights on the user's PC.
- Supply-chain compromise of Python dependencies before they are bundled into a signed release (mitigated only by
  review and pinned release signing).
