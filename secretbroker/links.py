"""Links to each provider's dashboard: where its keys are listed and created, and billing.

Only links found in the providers' own documentation are listed: a guessed URL that 404s is worse
than none. Cloudflare has several kinds of credentials, so its keys are also classified, and an
AI Gateway URL (gateway.ai.cloudflare.com/v1/<account>/<gateway>/...) links to that account.
"""

import json
import re
from urllib.parse import quote, urlsplit

from . import exposure


def _link(label, url, hint=""):
    return {"label": label, "url": url, "hint": hint}


LINKS = {
    "OpenAI": [
        _link("API keys", "https://platform.openai.com/settings/organization/api-keys",
              "Las claves de todos los proyectos de la organización."),
        _link("Admin keys", "https://platform.openai.com/settings/organization/admin-keys",
              "Claves para gestionar la organización por API."),
        _link("Uso", "https://platform.openai.com/usage"),
        _link("Límites de gasto", "https://platform.openai.com/settings/organization/limits"),
    ],
    "Anthropic": [
        _link("API keys", "https://platform.claude.com/settings/keys", "Aquí se crean las claves nuevas."),
        _link("Workspaces", "https://platform.claude.com/settings/workspaces", "Cada clave puede limitarse a un workspace."),
        _link("Admin keys", "https://platform.claude.com/settings/admin-keys"),
        _link("Facturación", "https://platform.claude.com/settings/billing"),
        _link("Uso", "https://platform.claude.com/usage"),
        _link("Coste", "https://platform.claude.com/cost"),
    ],
    "GitHub": [
        _link("Crear token fine-grained", "https://github.com/settings/personal-access-tokens/new",
              "Recomendado: acceso solo a los repositorios y permisos que elijas."),
        _link("Tokens classic", "https://github.com/settings/tokens"),
        _link("GitHub Apps", "https://github.com/settings/apps", "Alternativa sin claves fijas: tokens de 1 hora."),
    ],
    "GitLab": [
        _link("Tokens personales", "https://gitlab.com/-/user_settings/personal_access_tokens",
              "Aquí se ven y se crean los tokens."),
    ],
    "AssemblyAI": [
        _link("Dashboard", "https://www.assemblyai.com/dashboard/home",
              "Las claves están en Workspace › Manage › API Keys, una por proyecto."),
    ],
    "OpenRouter": [
        _link("API keys", "https://openrouter.ai/settings/keys"),
        _link("Management keys", "https://openrouter.ai/settings/management-keys", "Claves para gestionar claves por API."),
        _link("Créditos", "https://openrouter.ai/settings/credits"),
        _link("Actividad", "https://openrouter.ai/activity"),
    ],
    "Stripe": [
        _link("API keys", "https://dashboard.stripe.com/apikeys", "Cambia entre pruebas y producción con el selector de la página."),
        _link("Webhooks", "https://dashboard.stripe.com/webhooks", "Secretos de firma de los webhooks."),
        _link("Políticas de acceso", "https://dashboard.stripe.com/api-access-policies"),
    ],
    "Groq": [
        _link("API keys", "https://console.groq.com/keys"),
        _link("Facturación", "https://console.groq.com/settings/billing"),
        _link("Uso", "https://console.groq.com/dashboard/usage"),
    ],
    "Hugging Face": [
        _link("Tokens", "https://huggingface.co/settings/tokens"),
        _link("Facturación", "https://huggingface.co/settings/billing"),
    ],
    "Mistral": [
        _link("API keys", "https://console.mistral.ai/api-keys", "Cada workspace tiene sus propias claves."),
        _link("Workspaces", "https://admin.mistral.ai/organization/workspaces"),
        _link("Facturación y límites", "https://admin.mistral.ai/organization/billing"),
    ],
    "ElevenLabs": [
        _link("API keys", "https://elevenlabs.io/app/settings/api-keys"),
    ],
    "Deepgram": [
        _link("Consola", "https://console.deepgram.com", "Las claves están en cada proyecto: Settings › API Keys."),
    ],
}

# ----------------------------------------------------------------------------- Cloudflare

CF_DASH = "https://dash.cloudflare.com/?to=/:account"
CF_KINDS = {
    "user_token": ("Token de API de usuario",
                   "Ligado a tu usuario, con los permisos que elegiste al crearlo."),
    "account_token": ("Token de API de cuenta",
                      "Pertenece a la cuenta, no a una persona: el adecuado para servicios y CI."),
    "global_key": ("Global API Key",
                   "Clave antigua con acceso total a tu usuario. Cloudflare recomienda cambiarla por tokens."),
    "access_secret": ("Secreto de service token de Access",
                      "Para que una máquina entre en aplicaciones protegidas con Cloudflare Access."),
    "ai_gateway": ("Token de AI Gateway",
                   "Un token con permiso «AI Gateway Run» sirve para todos los gateways de la cuenta, "
                   "también los que guardan claves de proveedores."),
    "r2": ("Credenciales de R2 (S3)", "Access Key ID y Secret Access Key generados a partir de un token de API."),
}
CF_PREFIXES = [("cfut_", "user_token"), ("cfat_", "account_token"), ("cfk_", "global_key"), ("cfast_", "access_secret")]
GATEWAY_PATH_RE = re.compile(r"^/v1/(?P<account>[0-9a-f]{32})/(?P<gateway>[^/]+)")


def _host(entry):
    url = entry["fields"].get("base_url") or entry["fields"].get("url") or ""
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
        return (parts.hostname or "").lower(), parts.path
    except ValueError:
        return "", ""


def cloudflare_kind(entry):
    """(kind, account_id, gateway) for a Cloudflare credential, or None if it is not one."""
    host, path = _host(entry)
    key = (entry["fields"].get("value") or "").strip()
    if host == "gateway.ai.cloudflare.com":
        match = GATEWAY_PATH_RE.match(path)
        return ("ai_gateway", match["account"], match["gateway"]) if match else ("ai_gateway", None, None)
    if host.endswith(".r2.cloudflarestorage.com"):
        return ("r2", host.split(".")[0], None)
    for prefix, kind in CF_PREFIXES:
        if key.startswith(prefix):
            return (kind, None, None)
    if host == "cloudflare.com" or host.endswith(".cloudflare.com"):
        return (None, None, None)
    return None


def _cloudflare_links(kind, account, gateway):
    dash = f"https://dash.cloudflare.com/{account}" if account else CF_DASH
    gateway_link = _link("AI Gateway", f"{dash}/ai/ai-gateway",
                         (f"Abre el gateway «{gateway}» › Settings para crear tokens, " if gateway else
                          "Dentro de cada gateway: Settings para crear tokens, ")
                         + "y Provider Keys para guardar ahí las claves de OpenAI, Anthropic…")
    user_tokens = _link("Tokens de usuario y Global API Key", "https://dash.cloudflare.com/profile/api-tokens/",
                        "Tokens ligados a tu usuario. La Global API Key está en la misma página, en «API Keys».")
    account_tokens = _link("Tokens de cuenta", "https://dash.cloudflare.com/",
                           "Elige la cuenta › Manage account › Account API tokens.")
    others = [
        _link("Workers AI", f"{dash}/ai/workers-ai", "«Use REST API» › Create a Workers AI API Token."),
        _link("R2", f"{dash}/r2/overview", "Account Details › API Tokens › Manage, para claves S3."),
        _link("Service tokens de Access", "https://one.dash.cloudflare.com/?to=/:account/access/service-auth/service-tokens"),
        _link("Turnstile", f"{dash}/turnstile"),
    ]
    billing = _link("Facturación", f"{dash}/billing")
    first = {
        "ai_gateway": [gateway_link, user_tokens, account_tokens],
        "account_token": [account_tokens, gateway_link, user_tokens],
        "r2": [others[1], user_tokens, account_tokens],
        "access_secret": [others[2], user_tokens, account_tokens],
    }.get(kind, [user_tokens, account_tokens, gateway_link])
    return first + [link for link in [gateway_link, *others] if link not in first] + [billing]


# ----------------------------------------------------------------------------- consoles
#
# Secrets that are not API keys of a provider's API but are recognised by their own data: a Google
# service account key (its JSON), an OAuth client secret (its client id) or a secret of your own.
# Their links go straight to that account, project or app.

GOOGLE_CONSOLE = "https://console.cloud.google.com"
GOOGLE_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
GOOGLE_CLIENT_RE = re.compile(r"^(?P<number>\d+)-[a-z0-9]+\.apps\.googleusercontent\.com$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
OWN_SECRET = "Secreto propio"


def _service_account(entry):
    try:
        data = json.loads((entry["fields"].get("value") or "").strip())
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("type") == "service_account" else None


def console_kind(entry):
    """(provider, links) for secrets recognised by their data rather than by an API host, or None."""
    fields = entry["fields"]
    host, _ = _host(entry)
    client_id = (fields.get("username") or "").strip()
    account = _service_account(entry)
    if account:
        project, unique = str(account.get("project_id") or ""), str(account.get("client_id") or "")
        email = str(account.get("client_email") or "")
        if GOOGLE_PROJECT_RE.match(project) and unique.isdigit():
            keys = _link("Claves de esta cuenta de servicio", f"{GOOGLE_CONSOLE}/iam-admin/serviceaccounts/details/{unique}/keys?project={project}",
                         f"{email}: «Add key» crea la nueva; la papelera borra la anterior.")
        else:
            keys = _link("Cuentas de servicio", f"{GOOGLE_CONSOLE}/iam-admin/serviceaccounts", f"Abre {email or 'la cuenta'} › Keys.")
        return "Google Cloud", [keys]
    google_client = GOOGLE_CLIENT_RE.match(client_id)
    if google_client or host in ("oauth2.googleapis.com", "accounts.google.com"):
        found = [_link("Clientes OAuth", f"{GOOGLE_CONSOLE}/auth/clients", "Elige el proyecto y abre el cliente"
                       + (f" {client_id}." if client_id else "."))]
        if google_client:
            found.insert(0, _link("Este cliente OAuth", f"{GOOGLE_CONSOLE}/auth/clients/{client_id}?project={google_client['number']}",
                                  "«Add secret» crea el nuevo; después desactiva y borra el anterior."))
        return "Google OAuth", found
    if host == "login.microsoftonline.com" or host.endswith(".microsoftonline.com"):
        found = [_link("Registros de aplicaciones", "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
                       "Abre la app" + (f" {client_id}" if client_id else "") + " › Certificates & secrets.")]
        if UUID_RE.match(client_id):
            found.insert(0, _link("Secretos de esta app", "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/"
                                  f"ApplicationMenuBlade/~/Credentials/appId/{client_id}",
                                  "Certificates & secrets › «New client secret»; después borra el anterior."))
        return "Microsoft Entra", found
    if entry["template"] == "generic" and not host and not client_id:
        return OWN_SECRET, []
    return None


def search_link(entry):
    """A web search for how to rotate a key nobody has a guide for."""
    host, _ = _host(entry)
    query = f"{host or entry.get('name') or ''} rotate API key".strip()
    return _link("Buscar en la web cómo rotarla", "https://www.google.com/search?q=" + quote(query),
                 "O pide a la IA que busque la guía en la documentación oficial y la guarde aquí.")


def for_entry(entry):
    """{"provider", "kind": {"label", "help"} | None, "links": [...]} for API keys of a known provider."""
    if entry["template"] not in ("api_key", "generic"):
        return None
    console = console_kind(entry)
    if console:
        return {"provider": console[0], "kind": None, "links": console[1]} if console[1] else None
    cloudflare = cloudflare_kind(entry)
    if cloudflare:
        kind, account, gateway = cloudflare
        label, help_text = CF_KINDS.get(kind, (None, None))
        if kind == "ai_gateway" and gateway:
            label = f"{label} · gateway «{gateway}»"
        return {"provider": "Cloudflare", "kind": {"label": label, "help": help_text} if label else None,
                "links": _cloudflare_links(kind, account, gateway)}
    provider = exposure.provider_for(entry)
    if not provider or provider[0] not in LINKS:
        return None
    return {"provider": provider[0], "kind": None, "links": LINKS[provider[0]]}


def catalog():
    """Every provider with its links, for the "where do I get the key?" list of the new-key form."""
    providers = [{"provider": name, "links": items} for name, items in LINKS.items()]
    providers.append({"provider": "Cloudflare", "links": _cloudflare_links(None, None, None)})
    providers.append({"provider": "Cloudflare AI Gateway", "links": _cloudflare_links("ai_gateway", None, None),
                      "help": CF_KINDS["ai_gateway"][1]})
    return sorted(providers, key=lambda p: p["provider"].lower())
