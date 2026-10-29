"""Rotation: ask the provider for a new key and retire the old one, without anybody seeing either.

Only providers whose API can issue a replacement key are rotatable. For the rest the app shows the
button disabled with the reason, so it never pretends to do what the provider does not allow.

Some providers (Cloudflare, GitLab) revoke the old key in the same call that returns the new one:
the service stores the new value before doing anything else, so a later failure (re-uploading it
to GitHub, say) never leaves the user without a working key.
"""

from datetime import date, timedelta

import httpx

from . import exposure, links
from .inject import ActionError

TIMEOUT = 30
GITLAB_LIFETIME_DAYS = 364  # gitlab.com caps token lifetime at a year

CLOUDFLARE_NOT_ROTATABLE = {
    "account_token": "Los tokens de cuenta de Cloudflare todavía no se pueden rotar desde aquí.",
    "global_key": "Cloudflare solo permite cambiar la Global API Key desde su panel.",
    "access_secret": "Los service tokens de Access no se rotan con la API de tokens.",
    "r2": "Las credenciales de R2 salen de un token de API: rota ese token y genera unas nuevas.",
}
NOT_ROTATABLE = {
    "OpenAI": "OpenAI solo permite crear claves por API con una Admin key de la organización. Todavía no está soportado.",
    "Anthropic": "Anthropic no permite crear claves por API: solo desde la Console.",
    "GitHub": "GitHub no permite crear tokens personales por API.",
    "AssemblyAI": "AssemblyAI no permite crear claves por API: solo desde su dashboard.",
}


def _key(entry):
    return (entry["fields"].get("value") or "").strip()


def _fail(provider, response):
    if response.status_code in (401, 403):
        raise ActionError(f"{provider} no deja rotar esta clave (HTTP {response.status_code}): "
                          "le falta el permiso para gestionar tokens")
    raise ActionError(f"{provider} respondió HTTP {response.status_code}")


def _rotate_cloudflare(entry):
    headers = {"Authorization": f"Bearer {_key(entry)}"}
    with httpx.Client(base_url="https://api.cloudflare.com/client/v4", headers=headers, timeout=TIMEOUT,
                      follow_redirects=False) as client:
        verify = client.get("/user/tokens/verify")
        if verify.status_code in (401, 403):
            raise ActionError("Cloudflare no reconoce este token como token de usuario. "
                              "Los tokens de cuenta todavía no se pueden rotar desde aquí.")
        if not verify.is_success:
            _fail("Cloudflare", verify)
        token_id = verify.json()["result"]["id"]
        rolled = client.put(f"/user/tokens/{token_id}/value", json={})
        if not rolled.is_success:
            _fail("Cloudflare", rolled)
        return rolled.json()["result"]


def _rotate_gitlab(entry):
    expires = (date.today() + timedelta(days=GITLAB_LIFETIME_DAYS)).isoformat()
    response = httpx.post("https://gitlab.com/api/v4/personal_access_tokens/self/rotate",
                          headers={"PRIVATE-TOKEN": _key(entry)}, json={"expires_at": expires},
                          timeout=TIMEOUT, follow_redirects=False)
    if not response.is_success:
        _fail("GitLab", response)
    return response.json()["token"]


ROTATORS = {
    "Cloudflare": _rotate_cloudflare,
    "GitLab": _rotate_gitlab,
}


def info(entry):
    """{"provider", "supported", "reason"} for API keys of a known provider, None otherwise."""
    if entry["template"] not in ("api_key", "generic"):
        return None
    cloudflare = links.cloudflare_kind(entry)
    if cloudflare:
        kind = next((k for prefix, k in links.CF_PREFIXES if _key(entry).startswith(prefix)), cloudflare[0])
        if kind in CLOUDFLARE_NOT_ROTATABLE:
            return {"provider": "Cloudflare", "supported": False, "reason": CLOUDFLARE_NOT_ROTATABLE[kind]}
        return {"provider": "Cloudflare", "supported": True, "reason": ""}
    provider = exposure.provider_for(entry)
    if not provider:
        return {"provider": None, "supported": False,
                "reason": "No se reconoce el proveedor de esta clave, así que no se puede rotar automáticamente."}
    name = provider[0]
    if name in ROTATORS:
        return {"provider": name, "supported": True, "reason": ""}
    return {"provider": name, "supported": False,
            "reason": NOT_ROTATABLE.get(name, f"{name} no permite rotar claves por API.")}


def rotate(entry):
    """Ask the provider for a new key. Returns the new value; the old one is no longer valid."""
    details = info(entry)
    if not details or not details["supported"]:
        raise ActionError(details["reason"] if details else "Esta credencial no se puede rotar")
    try:
        value = ROTATORS[details["provider"]](entry)
    except httpx.HTTPError as exc:
        raise ActionError(f"Sin respuesta de {details['provider']}: {type(exc).__name__}") from None
    if not isinstance(value, str) or not value.strip():
        raise ActionError(f"{details['provider']} no devolvió una clave nueva")
    return value.strip()
