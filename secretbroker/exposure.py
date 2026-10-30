"""Exposure: is each secret still only inside the vault?

Three signals, all computed by the service, which alone knows the values:
  copies    the desktop app streams the user's files (AI conversations, shell history, program
            settings, projects, git history) and the service looks for the secrets in them
  liveness  a harmless read-only call to the provider; a key that suddenly stops working was most
            likely revoked by the provider after finding it leaked (e.g. in a public repository)
  breaches  passwords are checked against Have I Been Pwned with k-anonymity: only the first
            5 characters of their SHA-1 hash leave this computer

Findings stay attached to the value they were found for: once a secret changes (it was rotated),
its exposure history starts again.
"""

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import paramiko

from . import actions, templates
from .inject import ActionError, encodings
from .vault import secret_fields

MIN_NEEDLE = 8          # shorter values would match everywhere
MAX_NEEDLE = 1024       # longer values are matched by their last bytes (the app overlaps its reads by this much)
STALE_DAYS = 365
CHECK_TIMEOUT = 15
SOURCE_LABELS = {
    "ai": ("conversación con IA", "conversaciones con IA"),
    "history": ("historial de terminal", "historiales de terminal"),
    "config": ("configuración de programa", "configuraciones de programas"),
    "env": ("variable de entorno", "variables de entorno"),
    "project": ("archivo de proyecto", "archivos de proyectos"),
    "git": ("historial de git", "historiales de git"),
}


def _bearer(key):
    return {"Authorization": f"Bearer {key}"}


# Providers whose keys can be tested with a cheap authenticated GET that changes nothing.
# A key is matched by the host of its API URL or, failing that, by an unambiguous prefix:
# a key is never sent to a provider it may not belong to.
PROVIDERS = [
    ("Anthropic", ("sk-ant-",), "api.anthropic.com", "https://api.anthropic.com/v1/models",
     lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01"}),
    ("OpenRouter", ("sk-or-",), "openrouter.ai", "https://openrouter.ai/api/v1/key", _bearer),
    ("OpenAI", ("sk-proj-", "sk-svcacct-", "sk-admin-"), "api.openai.com", "https://api.openai.com/v1/models", _bearer),
    ("GitHub", ("ghp_", "gho_", "ghu_", "ghs_", "github_pat_"), "api.github.com", "https://api.github.com/user", _bearer),
    ("GitLab", ("glpat-",), "gitlab.com", "https://gitlab.com/api/v4/user", lambda k: {"PRIVATE-TOKEN": k}),
    ("Stripe", ("sk_live_", "sk_test_", "rk_live_", "rk_test_"), "api.stripe.com", "https://api.stripe.com/v1/balance", _bearer),
    ("Groq", ("gsk_",), "api.groq.com", "https://api.groq.com/openai/v1/models", _bearer),
    ("Hugging Face", ("hf_",), "huggingface.co", "https://huggingface.co/api/whoami-v2", _bearer),
    ("AssemblyAI", (), "api.eu.assemblyai.com", "https://api.eu.assemblyai.com/v2/transcript?limit=1", lambda k: {"Authorization": k}),
    ("AssemblyAI", (), "api.assemblyai.com", "https://api.assemblyai.com/v2/transcript?limit=1", lambda k: {"Authorization": k}),
    ("Mistral", (), "api.mistral.ai", "https://api.mistral.ai/v1/models", _bearer),
    ("ElevenLabs", (), "api.elevenlabs.io", "https://api.elevenlabs.io/v1/user", lambda k: {"xi-api-key": k}),
    ("Deepgram", (), "api.deepgram.com", "https://api.deepgram.com/v1/projects", lambda k: {"Authorization": f"Token {k}"}),
    ("Cloudflare", (), "api.cloudflare.com", "https://api.cloudflare.com/client/v4/user/tokens/verify", _bearer),
]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- copies


def needles(entry):
    """Byte strings whose presence in a file means one of the entry's secrets is there in clear."""
    found = set()
    for secret in templates.secret_values(entry):
        secret = secret.strip()
        if len(secret) < MIN_NEEDLE:
            continue
        # Multi-line values (private keys) are matched whole, with either line ending: their
        # individual lines are not distinctive (every OpenSSH key starts the same way).
        forms = [secret, secret.replace("\n", "\r\n")] if "\n" in secret else [secret]
        for form in forms:
            for value in encodings(form):
                data = value.encode("utf-8")
                if len(data) >= MIN_NEEDLE:
                    found.add(data[-MAX_NEEDLE:])
    return found


def secret_fingerprint(vault, entry):
    return vault.mac(b"exposure/secret\0" + json.dumps(secret_fields(entry), sort_keys=True).encode("utf-8"))


def record_for(data, entry_id, fingerprint):
    """The exposure record of an entry, reset if its secret changed since it was written."""
    record = data.setdefault("entries", {}).get(entry_id)
    if not record or record.get("fp") != fingerprint:
        record = {"fp": fingerprint, "findings": {}, "revealed": 0}
        data["entries"][entry_id] = record
    return record


def merge_scan(record, matches, scanned, unchanged, timestamp):
    """Update an entry's findings with a finished scan. Returns how many new places were found."""
    findings = record["findings"]
    for location, finding in findings.items():
        if location in scanned:
            finding["present"] = location in matches
        elif location not in unchanged:
            finding["present"] = False  # the file no longer exists or is no longer scanned
        if finding["present"]:
            finding["last_seen"] = timestamp
    new = 0
    for location, source in matches.items():
        if location not in findings:
            findings[location] = {"source": source, "first_seen": timestamp, "last_seen": timestamp, "present": True}
            new += 1
    record["scanned"] = timestamp
    return new


# --------------------------------------------------------------------------- liveness & breaches


def _host(url):
    if not url:
        return None
    try:
        return urlsplit(url if "://" in url else "https://" + url).hostname
    except ValueError:
        return None


def provider_for(entry):
    if entry["template"] not in ("api_key", "generic"):
        return None
    key = (entry["fields"].get("value") or "").strip()
    host = _host(entry["fields"].get("base_url") or entry["fields"].get("url"))
    if not key:
        return None
    for provider in PROVIDERS:
        if host and (host == provider[2] or host.endswith("." + provider[2])):
            return provider
    if host:
        return None  # an API of its own: its key must not be sent anywhere else
    return next((p for p in PROVIDERS if p[1] and key.startswith(p[1])), None)


def check_alive(entry):
    """{"status": ok | invalid | unknown, "provider", "message"}, or None if it cannot be tested."""
    if entry["template"] == "ssh":
        try:
            client, _ = actions._connect(entry)
            client.close()
            return {"status": "ok", "provider": "SSH"}
        except paramiko.AuthenticationException:
            return {"status": "invalid", "provider": "SSH", "message": "El servidor rechaza la credencial"}
        except (ActionError, paramiko.SSHException, OSError) as exc:
            return {"status": "unknown", "provider": "SSH", "message": f"No se pudo conectar: {type(exc).__name__}"}
    provider = provider_for(entry)
    if not provider:
        return None
    name, _, _, url, headers = provider
    try:
        response = httpx.get(url, headers=headers(entry["fields"]["value"].strip()), timeout=CHECK_TIMEOUT,
                             follow_redirects=False)
    except httpx.HTTPError as exc:
        return {"status": "unknown", "provider": name, "message": f"Sin respuesta: {type(exc).__name__}"}
    if response.status_code in (401, 403):
        return {"status": "invalid", "provider": name, "message": f"{name} rechaza la clave (HTTP {response.status_code})"}
    if response.is_success or response.status_code == 429:  # rate limited means the key was recognised
        return {"status": "ok", "provider": name}
    return {"status": "unknown", "provider": name, "http": response.status_code,
            "message": f"Respuesta inesperada (HTTP {response.status_code}){_said(response)}"}


def _said(response):
    """What the provider says about an unexpected answer, briefly (it may explain a revoked key)."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        said = body.get("error") or body.get("message") or body.get("detail")
        if isinstance(said, dict):
            said = said.get("message")
        if isinstance(said, str) and said.strip():
            return ": " + said.strip()[:160]
    return ""


def password_of(entry):
    if entry["template"] in ("web_login", "database") or \
            (entry["template"] == "ssh" and entry["fields"].get("auth_method") != "key"):
        return entry["fields"].get("password") or None
    return None


def pwned_count(password):
    """Times the password appears in known breaches (Have I Been Pwned, k-anonymity)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    response = httpx.get(f"https://api.pwnedpasswords.com/range/{digest[:5]}", timeout=CHECK_TIMEOUT,
                         headers={"Add-Padding": "true", "User-Agent": "SecretBroker"})
    response.raise_for_status()
    for line in response.text.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix == digest[5:]:
            return int(count or 0)
    return 0


def check_entry(entry, record, timestamp):
    """Run the liveness and breach checks of one entry and store them in its record."""
    alive = check_alive(entry)
    if alive:
        previous = record.get("alive") or {}
        alive["checked"] = timestamp
        # Whether this value ever worked: a working key that stops working was revoked, not mistyped.
        alive["was_ok"] = alive["status"] == "ok" or previous.get("status") == "ok" or bool(previous.get("was_ok"))
        record["alive"] = alive
    password = password_of(entry)
    if password:
        try:
            record["pwned"] = {"count": pwned_count(password), "checked": timestamp}
        except httpx.HTTPError:
            pass
    record["checked"] = timestamp
    return alive


def last_checked(record):
    """When the entry's current value was last tested, or None if never."""
    record = record or {}
    return record.get("checked") or (record.get("alive") or {}).get("checked") or (record.get("pwned") or {}).get("checked")


# --------------------------------------------------------------------------- assessment


def _plural(count, source):
    singular, plural = SOURCE_LABELS.get(source, (source, source))
    return f"{count} {singular if count == 1 else plural}"


def _places(findings):
    by_source = {}
    for finding in findings:
        by_source[finding["source"]] = by_source.get(finding["source"], 0) + 1
    order = list(SOURCE_LABELS)
    parts = [_plural(n, s) for s, n in sorted(by_source.items(), key=lambda i: order.index(i[0]) if i[0] in order else 99)]
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " y " + parts[-1]


def _age_days(entry, timestamp):
    since = entry.get("secret_since")
    if not since:
        return None
    try:
        return (datetime.fromisoformat(timestamp) - datetime.fromisoformat(since)).days
    except ValueError:
        return None


def assess(entry, record, timestamp, details):
    """Level (exposed, warning, ok, unknown) and the reasons, for the app."""
    record = record or {}
    reasons = []
    findings = [dict(f, location=loc) for loc, f in (record.get("findings") or {}).items()]
    present = [f for f in findings if f["present"]]
    gone = [f for f in findings if not f["present"]]
    if present:
        text = f"Está en claro en {_places(present)}."
        if any(f["source"] == "ai" for f in present):
            text += " Una IA la ha visto: se envió a su proveedor."
        reasons.append(("exposed", text))
    if gone:
        reasons.append(("warning", f"Estuvo en claro en {_places(gone)}. Aunque ya no esté, conviene rotarla."))

    alive = record.get("alive") or {}
    if alive.get("status") == "invalid":
        if alive.get("was_ok"):
            reasons.append(("exposed", f"Ha dejado de funcionar: {alive.get('message', '')}. Si no la has revocado tú, "
                                       "es probable que el proveedor la haya detectado filtrada."))
        else:
            reasons.append(("warning", f"No funciona: {alive.get('message', '')}."))
    pwned = (record.get("pwned") or {}).get("count")
    if pwned:
        reasons.append(("exposed", f"Esta contraseña aparece {pwned:,} veces en filtraciones públicas.".replace(",", ".")))

    age = _age_days(entry, timestamp)
    if age is not None and age > STALE_DAYS:
        reasons.append(("warning", f"No se ha cambiado en {age // 30} meses."))

    levels = [level for level, _ in reasons]
    if "exposed" in levels:
        level = "exposed"
    elif "warning" in levels:
        level = "warning"
    elif record.get("scanned"):
        level = "ok"
    else:
        level = "unknown"
        reasons.append(("unknown", "Aún no se ha buscado en tus archivos."))

    result = {
        "id": entry["id"], "level": level,
        "reasons": [{"level": lvl, "text": text} for lvl, text in reasons],
        "found": len(present), "found_before": len(gone),
        "scanned": record.get("scanned"), "alive": alive or None, "pwned": record.get("pwned"),
        "revealed": record.get("revealed", 0), "secret_since": entry.get("secret_since"), "age_days": age,
        "checkable": bool(check_alive_possible(entry)),
    }
    if details:
        result["findings"] = sorted(findings, key=lambda f: (not f["present"], f["source"], f["location"]))
    return result


def check_alive_possible(entry):
    return entry["template"] == "ssh" or provider_for(entry) is not None or password_of(entry) is not None
