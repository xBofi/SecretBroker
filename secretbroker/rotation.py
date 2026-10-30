"""Rotation: ask the provider for a new key and retire the old one, without anybody seeing either.

Only providers whose API can issue a replacement key are rotatable. For the rest the app shows the
button disabled with the reason, so it never pretends to do what the provider does not allow.

Some providers (Cloudflare, GitLab) revoke the old key in the same call that returns the new one:
the service stores the new value before doing anything else, so a later failure (re-uploading it
to GitHub, say) never leaves the user without a working key.

The rest are rotated by hand with a guide: where to create the new key and where to delete the old
one. The guides of known providers come from their own documentation; for other providers the AI
can research one and store it with the credential (marked as written by the AI).
"""

import re
from datetime import date, timedelta

import httpx

from . import exposure, links, templates
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
    "Google Cloud": "Las claves de cuentas de servicio se crean en la consola de Google Cloud.",
    "Google OAuth": "Los secretos de clientes OAuth se crean en la consola de Google Cloud.",
    "Microsoft Entra": "Los secretos de las apps se crean en el portal de Azure (Microsoft Entra).",
    "Secreto propio": "Es un secreto tuyo, no de un proveedor: se rota generando uno nuevo.",
}


GUIDES = {
    "OpenAI": {
        "create": ["Abre «API keys» y pulsa «Create new secret key».",
                   "Elige el mismo proyecto y los mismos permisos que tenía la clave actual."],
        "revoke": "En «API keys», borra la clave anterior con el icono de la papelera.",
        "link": "API keys",
    },
    "Anthropic": {
        "create": ["Abre «API keys» en la Console y pulsa «Create Key».",
                   "Elige el mismo workspace que tenía la clave actual."],
        "revoke": "En «API keys», abre el menú «…» de la clave anterior y bórrala.",
        "link": "API keys",
    },
    "GitHub": {
        "create": ["Abre tus tokens y entra en el token actual.",
                   "Pulsa «Regenerate token»: conserva los repositorios y permisos y solo cambia el valor."],
        "revoke": "Al regenerarlo, el valor anterior deja de funcionar solo. Si creaste un token nuevo, borra el viejo en la misma página.",
        "link": "Crear token fine-grained",
    },
    "GitLab": {
        "create": ["Abre «Tokens personales» y pulsa «Add new token» con los mismos scopes que el actual."],
        "revoke": "En la misma página, pulsa «Revoke» en el token anterior.",
        "link": "Tokens personales",
    },
    "AssemblyAI": {
        "create": ["Abre el dashboard y entra en «API Keys» del proyecto que usa la clave.",
                   "Pulsa «Create new API key»."],
        "revoke": "En «API Keys», borra la clave anterior.",
        "link": "Dashboard",
    },
    "OpenRouter": {
        "create": ["Abre «API keys» y pulsa «Create API Key». Si la actual tenía un límite de crédito, ponle el mismo."],
        "revoke": "En «API keys», borra la clave anterior desde su menú.",
        "link": "API keys",
    },
    "Stripe": {
        "create": ["Abre «API keys» (en el modo, pruebas o producción, de la clave actual).",
                   "En la clave actual, pulsa «…» › «Roll key». Stripe deja elegir cuánto tiempo sigue funcionando la anterior."],
        "revoke": "Si elegiste «ahora» al rotarla, la anterior ya no funciona; si no, caduca sola en el plazo que elegiste.",
        "link": "API keys",
    },
    "Groq": {
        "create": ["Abre «API Keys» en la consola y pulsa «Create API Key»."],
        "revoke": "En la misma página, borra la clave anterior.",
        "link": "API keys",
    },
    "Hugging Face": {
        "create": ["Abre «Access Tokens», entra en el token actual y pulsa «Invalidate and refresh»: "
                   "conserva los permisos y cambia el valor."],
        "revoke": "Al refrescarlo, el valor anterior deja de funcionar solo.",
        "link": "Tokens",
    },
    "Mistral": {
        "create": ["Abre «API keys» del workspace que usa la clave y pulsa «Create new key»."],
        "revoke": "En la misma página, borra la clave anterior.",
        "link": "API keys",
    },
    "ElevenLabs": {
        "create": ["Abre «API keys» y pulsa «Create API key» con los mismos permisos que la actual."],
        "revoke": "En la misma página, borra la clave anterior.",
        "link": "API keys",
    },
    "Deepgram": {
        "create": ["Abre la consola, elige el proyecto y entra en «Settings» › «API Keys».",
                   "Pulsa «Create a New API Key» con el mismo rol que la actual."],
        "revoke": "En la misma página, borra la clave anterior.",
        "link": "Consola",
    },
    "Google Cloud": {
        "create": ["Abre las claves de la cuenta de servicio y pulsa «Add key» › «Create new key» › JSON.",
                   "Se descarga un archivo .json: abre el archivo, copia todo su contenido y pégalo en el paso 2. "
                   "Después borra el archivo de Descargas."],
        "revoke": "En la misma pestaña «Keys», borra la clave anterior con la papelera (su ID es el «private_key_id» del JSON viejo).",
        "link": None,
    },
    "Google OAuth": {
        "warning": "No borres el cliente OAuth ni crees otro: el secreto se rota dentro del mismo cliente. "
                   "Si creas otro, cambia el ID de cliente y tendrás que cambiarlo también en tu app. "
                   "Tampoco hace falta crear una «API key»: es otra cosa.",
        "create": ["Abre el cliente OAuth y pulsa «Add secret»: Google permite tener dos secretos a la vez, así que no se corta nada.",
                   "Copia el secreto nuevo."],
        "revoke": "Cuando tu app ya use el nuevo, en el mismo cliente desactiva el secreto anterior («Disable») y luego bórralo.",
        "link": None,
    },
    "Microsoft Entra": {
        "warning": "No borres la app ni registres otra: el secreto se rota dentro de la misma app. "
                   "Si registras otra, cambia el Application (client) ID y tendrás que cambiarlo también en tu app.",
        "create": ["Abre los secretos de la app (Certificates & secrets) y pulsa «New client secret».",
                   "Elige la caducidad y copia el «Value» (no el «Secret ID»): solo se muestra una vez."],
        "revoke": "Cuando tu app ya use el nuevo, borra el secreto anterior en la misma página.",
        "link": None,
    },
    "Secreto propio": {
        "create": ["Si es un secreto que generas tú (de sesión, de firma…), pulsa «Generar uno aleatorio» en el paso 2.",
                   "Si viene de un servicio, añade su dirección web a la credencial (Editar) y la app te llevará a su página."],
        "revoke": "No hay nada que borrar fuera: en cuanto tu app use el nuevo, el anterior deja de valer "
                  "(por ejemplo, las sesiones abiertas con un secreto de sesión se cierran).",
        "link": None,
    },
    "Cloudflare": {
        "create": ["Abre la página de tokens y, en el token actual, pulsa «…» › «Roll»: conserva los permisos y cambia el valor."],
        "revoke": "Al hacer «Roll», el valor anterior deja de funcionar solo.",
        "link": None,
    },
}
GENERIC_GUIDE = {
    "create": ["Entra en la web del servicio y busca la sección de API keys o tokens (suele estar en Settings, "
               "Developer o API).",
               "Crea una clave nueva con los mismos permisos que la actual."],
    "revoke": "En la misma sección, borra o revoca la clave anterior.",
}
GUIDE_STEPS_MAX = 8
GUIDE_TEXT_MAX = 300

# The identifier a secret goes with (an OAuth client id, an app id…). Rotating the secret inside the
# same client keeps it; creating a new client changes it, and a new secret with the old id fails.
PAIRED_IDS = {
    "Google OAuth": ("ID de cliente", links.GOOGLE_CLIENT_RE, "123456789-abc.apps.googleusercontent.com"),
    "Microsoft Entra": ("Application (client) ID", links.UUID_RE, "00000000-0000-0000-0000-000000000000"),
}
PAIRED_ID_MAX = 300
PAIRED_ID_RE = re.compile(r"^\S+$")


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
    """{"provider", "supported", "reason"} for API keys of a known provider and databases, None otherwise."""
    if entry["template"] == "database":
        return {"provider": _database(entry)[0], "supported": False,
                "reason": "La contraseña de una base de datos se cambia en la propia base de datos o en el panel de su proveedor."}
    if entry["template"] not in ("api_key", "generic"):
        return None
    cloudflare = links.cloudflare_kind(entry)
    if cloudflare:
        kind = next((k for prefix, k in links.CF_PREFIXES if _key(entry).startswith(prefix)), cloudflare[0])
        if kind in CLOUDFLARE_NOT_ROTATABLE:
            return {"provider": "Cloudflare", "supported": False, "reason": CLOUDFLARE_NOT_ROTATABLE[kind]}
        return {"provider": "Cloudflare", "supported": True, "reason": ""}
    console = links.console_kind(entry)
    if console:
        return {"provider": console[0], "supported": False, "reason": NOT_ROTATABLE[console[0]]}
    provider = exposure.provider_for(entry)
    if not provider:
        return {"provider": None, "supported": False,
                "reason": "No se reconoce el proveedor de esta clave, así que no se puede rotar automáticamente."}
    name = provider[0]
    if name in ROTATORS:
        return {"provider": name, "supported": True, "reason": ""}
    return {"provider": name, "supported": False,
            "reason": NOT_ROTATABLE.get(name, f"{name} no permite rotar claves por API.")}


def paired_id(entry):
    """{"label", "value", "hint"} of the identifier this secret goes with, or None if it has none.
    Credentials that are not API keys keep their user apart (a password changes alone)."""
    if entry["template"] not in ("api_key", "generic"):
        return None
    provider = (info(entry) or {}).get("provider")
    current = (entry["fields"].get("username") or "").strip()
    if provider in PAIRED_IDS:
        label, _, hint = PAIRED_IDS[provider]
        return {"label": label, "value": current, "hint": hint}
    if current:
        return {"label": "ID asociado", "value": current, "hint": ""}
    return None


def clean_paired_id(entry, value):
    """A new paired id, checked against the provider's format; raises ValueError."""
    value = str(value or "").strip()
    provider = (info(entry) or {}).get("provider")
    label, pattern, hint = PAIRED_IDS.get(provider, ("ID asociado", PAIRED_ID_RE, ""))
    if not value or len(value) > PAIRED_ID_MAX or not pattern.match(value):
        raise ValueError(f"El {label} nuevo no es válido" + (f" (tiene esta forma: {hint})" if hint else ""))
    return value


# ----------------------------------------------------------------------------- databases
#
# Nothing connects to the database from here: the app generates the password and gives the exact
# command (or the panel of a managed database). The old password stops working at once, so every
# place that uses it has to get the new one.

DB_COMMANDS = {
    "postgresql": """ALTER ROLE "{user}" WITH PASSWORD '{password}';""",
    "mysql": """ALTER USER '{user}'@'%' IDENTIFIED BY '{password}';""",
    "sqlserver": """ALTER LOGIN [{user}] WITH PASSWORD = '{password}';""",
    "mongodb": """db.getSiblingDB("{database}").changeUserPassword("{user}", "{password}")""",
    "redis": """ACL SETUSER {user} resetpass >{password}""",
}
DB_COMMAND_NOTES = {
    "mysql": "Si el usuario no es de cualquier host ('%'), pon el suyo (lo ves con SELECT user, host FROM mysql.user).",
    "redis": "Si no usa usuarios (solo requirepass): CONFIG SET requirepass y cámbiala también en redis.conf.",
}
SUPABASE_HOST_RE = re.compile(r"^db\.(?P<ref>[a-z0-9]{20})\.supabase\.co$")
SUPABASE_USER_RE = re.compile(r"^postgres\.(?P<ref>[a-z0-9]{20})$")


def _database(entry):
    """(name, links, panel_only) of a database: its engine, or the managed service it runs on."""
    fields = entry["fields"]
    host = (fields.get("host") or "").strip().lower()
    engine = templates.DB_ENGINES.get(fields.get("engine") or "postgresql", templates.DB_ENGINES["other"])["label"]
    supabase = SUPABASE_HOST_RE.match(host) or (host.endswith(".pooler.supabase.com") and SUPABASE_USER_RE.match(fields.get("username") or ""))
    if supabase:
        return "Supabase", [links._link("Contraseña de la base de datos", f"https://supabase.com/dashboard/project/{supabase['ref']}/settings/database",
                                        "«Reset database password»: pega la generada o copia la que te dé.")], False
    if host.endswith(".supabase.co") or host.endswith(".supabase.com"):
        return "Supabase", [links._link("Proyectos de Supabase", "https://supabase.com/dashboard/projects",
                                        "Abre el proyecto › Database › Settings › «Reset database password».")], False
    if host.endswith(".neon.tech"):
        return "Neon", [links._link("Proyectos de Neon", "https://console.neon.tech/app/projects",
                                    "Abre el proyecto › Roles › «Reset password»: Neon genera la nueva; cópiala.")], True
    if host.endswith(".rds.amazonaws.com"):
        return f"{engine} en AWS RDS", [links._link("Bases de datos de RDS", "https://console.aws.amazon.com/rds/home#databases:",
                                                    "Para el usuario maestro: «Modify» › «New master password». Para otros, el comando.")], False
    if host.endswith(".database.azure.com") or host.endswith(".database.windows.net"):
        return f"{engine} en Azure", [links._link("Bases de datos de Azure", "https://portal.azure.com/#browse/resourcegroups",
                                                  "Para el administrador: «Reset password» en el servidor. Para otros, el comando.")], False
    return engine, [], False


def _database_guide(entry):
    fields = entry["fields"]
    name, found, panel_only = _database(entry)
    engine = fields.get("engine") or "postgresql"
    command = None if panel_only else DB_COMMANDS.get(engine)
    if command:
        command = command.replace("{user}", fields.get("username") or "usuario").replace("{database}", fields.get("database") or "admin")
    where = f"{fields.get('host') or 'el servidor'}" + (f" (base de datos {fields['database']})" if fields.get("database") else "")
    steps = (["Abre el panel (enlace de abajo) y cambia la contraseña del usuario "
              f"{fields.get('username') or ''} con la que te da el panel; pégala en el paso siguiente."] if panel_only else
             ["Genera la contraseña nueva aquí abajo (o escribe la tuya).",
              f"Conéctate a {where} con la contraseña actual (la puedes copiar en la credencial) "
              + ("y ejecuta el comando, o cámbiala en el panel (enlace de abajo)." if found and command else
                 "y ejecuta el comando." if command else "y cámbiala como se haga en esa base de datos."),
              "Cuando esté cambiada, pulsa «Ya la he cambiado: guardar»."])
    return {"provider": name, "source": "builtin", "kind": "database", "create": steps, "revoke": "",
            "warning": "En cuanto la cambies, la actual deja de funcionar: todo lo que la usa (develop, pre, pro…) "
                       "fallará hasta que le pongas la nueva. Hazlo cuando puedas actualizar todos esos sitios seguidos.",
            "links": found, "sources": [], "generate": not panel_only, "paired": None, "testable": False,
            "command": command, "command_note": DB_COMMAND_NOTES.get(engine, "") if command else ""}


def guide(entry):
    """How to rotate an API key or a database password by hand: {"provider", "source": builtin | ai |
    generic, "create": [steps], "revoke", "links", "sources"}, or None for other credentials."""
    if entry["template"] == "database":
        return _database_guide(entry)
    if entry["template"] not in ("api_key", "generic"):
        return None
    details = info(entry) or {}
    provider = details.get("provider")
    testable = exposure.provider_for(entry) is not None
    if provider in GUIDES:
        known = GUIDES[provider]
        provider_links = (links.for_entry(entry) or {}).get("links") or []
        first = [link for link in provider_links if link["label"] == known["link"]] or provider_links[:1]
        return {"provider": provider, "source": "builtin", "create": known["create"], "revoke": known["revoke"],
                "warning": known.get("warning", ""), "links": first + [link for link in provider_links if link not in first],
                "sources": [], "generate": provider == links.OWN_SECRET, "paired": paired_id(entry), "testable": testable}
    written = entry.get("rotation_guide")
    if written:
        return {"provider": provider, "source": "ai", "create": written.get("create") or [],
                "revoke": written.get("revoke") or "", "warning": written.get("warning") or "",
                "links": written.get("links") or [], "sources": written.get("sources") or [],
                "written": written.get("written"), "paired": paired_id(entry), "testable": testable}
    return {"provider": provider, "source": "generic", **GENERIC_GUIDE, "warning": "",
            "links": [links.search_link(entry)], "sources": [], "paired": paired_id(entry), "testable": testable}


def clean_guide(guide):
    """A rotation guide written by the AI, checked and trimmed; raises ValueError if malformed."""
    if not isinstance(guide, dict):
        raise ValueError("rotation_guide debe ser un objeto con create, revoke, links y sources")
    steps = guide.get("create") or []
    if isinstance(steps, str):
        steps = [steps]
    steps = [str(s).strip()[:GUIDE_TEXT_MAX] for s in steps if str(s).strip()][:GUIDE_STEPS_MAX]
    if not steps:
        raise ValueError("rotation_guide.create necesita al menos un paso")
    found = []
    for link in (guide.get("links") or [])[:GUIDE_STEPS_MAX]:
        if isinstance(link, str):
            link = {"label": link, "url": link}
        url = str((link or {}).get("url") or "").strip()
        if not url.startswith("https://") or len(url) > 500 or any(c.isspace() for c in url):
            raise ValueError(f"Enlace no válido (solo https://): {url[:80]}")
        found.append({"label": str(link.get("label") or url).strip()[:80], "url": url, "hint": str(link.get("hint") or "").strip()[:GUIDE_TEXT_MAX]})
    sources = []
    for url in (guide.get("sources") or [])[:GUIDE_STEPS_MAX]:
        url = str(url).strip()
        if not url.startswith("https://") or len(url) > 500 or any(c.isspace() for c in url):
            raise ValueError(f"Fuente no válida (solo https://): {url[:80]}")
        sources.append(url)
    if not sources:
        raise ValueError("rotation_guide.sources: indica las páginas de documentación donde lo has comprobado")
    return {"create": steps, "revoke": str(guide.get("revoke") or "").strip()[:GUIDE_TEXT_MAX],
            "warning": str(guide.get("warning") or "").strip()[:GUIDE_TEXT_MAX], "links": found, "sources": sources}


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
