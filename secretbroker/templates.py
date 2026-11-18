"""Credential templates: which fields each kind of credential has, and its default AI policy."""

import re
from urllib.parse import quote, urlsplit

from . import i18n, totp

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def _field(name, label, kind="text", required=False, secret=False, hint="", help="",
           options=None, default="", show_if=None, substitutable=True, note=False, optional=None):
    return {
        "name": name, "label": label, "kind": kind, "required": required, "secret": secret,
        "hint": hint, "help": help, "options": options or [], "default": default,
        "show_if": show_if, "substitutable": substitutable, "note": note,
        # What the form marks «opcional»: all that isn't required, unless the template says otherwise (a card's
        # holder is not asked for, but nobody thinks of it as optional).
        "optional": not required if optional is None else optional,
    }


def _notes():
    # Kept like a secret (hidden, shown or copied after verifying) but it is not a key: it is never
    # given to programs, looked for in files or redacted, and changing it doesn't make the key "new".
    return _field("notes", "Notas privadas (opcional)", "multiline", secret=True, substitutable=False, note=True,
                  hint="Códigos de recuperación, preguntas de seguridad…", help="Solo para ti: la IA no las ve.")


EXPIRES = "expires"


def _expires(label, kind="date", hint=""):
    # Not one of the entry's `fields`: its own expiry date (`expires`, the one behind «caduca pronto»), placed among
    # them in the form and in the detail. `month`: typed as on a card, MM/AA, kept as the last day of that month.
    return _field(EXPIRES, label, kind, hint=hint, substitutable=False, optional=False)


DB_ENGINES = {
    "postgresql": {
        "label": "PostgreSQL", "port": "5432", "scheme": "postgresql",
        "commands": ["psql", "pg_dump", "pg_restore"],
        "env": {"PGHOST": "{{host}}", "PGPORT": "{{port}}", "PGUSER": "{{username}}",
                "PGPASSWORD": "{{password}}", "PGDATABASE": "{{database}}"},
    },
    "mysql": {
        "label": "MySQL / MariaDB", "port": "3306", "scheme": "mysql",
        "commands": ["mysql", "mysqldump"],
        "env": {"MYSQL_HOST": "{{host}}", "MYSQL_TCP_PORT": "{{port}}", "MYSQL_PWD": "{{password}}"},
    },
    "sqlserver": {
        "label": "SQL Server", "port": "1433", "scheme": "mssql",
        "commands": ["sqlcmd"],
        "env": {"SQLCMDSERVER": "{{host}},{{port}}", "SQLCMDUSER": "{{username}}",
                "SQLCMDPASSWORD": "{{password}}", "SQLCMDDBNAME": "{{database}}"},
    },
    "mongodb": {"label": "MongoDB", "port": "27017", "scheme": "mongodb", "commands": [], "env": {}},
    "redis": {
        "label": "Redis", "port": "6379", "scheme": "redis",
        "commands": ["redis-cli"], "env": {"REDISCLI_AUTH": "{{password}}"},
    },
    "other": {"label": "Otro", "port": "", "scheme": "", "commands": [], "env": {}},
}

API_AUTH_STYLES = {
    "bearer": ("Cabecera Authorization: Bearer <token>", {"kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}),
    "x_api_key": ("Cabecera X-API-Key", {"kind": "header", "name": "X-API-Key", "template": "{{value}}"}),
    "query": ("Parámetro api_key en la URL", {"kind": "query", "name": "api_key", "template": "{{value}}"}),
    "none": ("No añadirla automáticamente", {"kind": "none"}),
}

TEMPLATES = {
    "web_login": {
        "label": "Web o servicio",
        "icon": "globe",
        "summary": "Usuario y contraseña de una web, panel o aplicación",
        "fields": [
            _field("url", "Dirección web", hint="https://panel.ejemplo.com",
                   help="La IA solo podrá usar esta credencial con esta web."),
            _field("username", "Usuario o e-mail", required=True),
            _field("password", "Contraseña", "secret", required=True, secret=True),
            # The 2FA seed: kept like the private notes (not a key, never given to the AI as such). The
            # service computes the current code; the AI gets it only as {{totp_code}} if the user allows it.
            _field("totp", "Código 2FA (TOTP) (opcional)", "secret", secret=True, substitutable=False, note=True,
                   hint="otpauth://totp/… o la clave en base32",
                   help="La clave que da la web al activar la verificación en dos pasos (debajo del QR). "
                        "SecretBroker te muestra el código de 6 cifras; la IA no lo ve."),
        ],
    },
    # Personal items (`personal`): the user's own things, for the user alone. They are kept, shown, copied, shared and
    # exported like the rest, but they don't exist for the AI, `sb run` or the browser (service._for_ai), and what
    # they hide is not a key: nothing to give to a program, redact, rotate, test or look for in files.
    "card": {
        "label": "Tarjeta de pago",
        "icon": "card",
        "summary": "Tarjeta de crédito o débito",
        "personal": True,
        "fields": [
            _field("holder", "Titular de la tarjeta", hint="Como aparece en la tarjeta", optional=False),
            _field("number", "Número de la tarjeta", "secret", required=True, secret=True),
            _expires("Caducidad", "month", hint="MM/AA"),
            _field("cvv", "CVV", "secret", secret=True, optional=False),
            _field("pin", "PIN", "secret", secret=True),
            _field("brand", "Banco o marca", hint="Visa, Mastercard, tu banco…"),
        ],
    },
    "note": {
        "label": "Nota segura",
        "icon": "note",
        "summary": "Un texto que quieres guardar a salvo",
        "personal": True,
        "fields": [
            _field("text", "Nota", "multiline", required=True, secret=True, hint="Escribe aquí lo que quieras guardar"),
        ],
    },
    "identity": {
        "label": "Documento de identidad",
        "icon": "idcard",
        "summary": "DNI, pasaporte, carné de conducir…",
        "personal": True,
        "fields": [
            _field("doc_type", "Tipo de documento", "select", default="id_card",
                   options=[{"value": "id_card", "label": "DNI o NIE"}, {"value": "passport", "label": "Pasaporte"},
                            {"value": "driving", "label": "Carné de conducir"},
                            {"value": "social_security", "label": "Seguridad social"},
                            {"value": "other", "label": "Otro documento"}]),
            _field("number", "Número del documento", "secret", required=True, secret=True),
            _field("full_name", "Nombre completo", optional=False),
            _field("country", "País", optional=False),
            _field("issued", "Fecha de expedición", "date", optional=False),
            _expires("Válido hasta"),
        ],
    },
    "wifi": {
        "label": "Red Wi-Fi",
        "icon": "wifi",
        "summary": "Nombre de la red y su contraseña",
        "personal": True,
        "fields": [
            _field("ssid", "Nombre de la red", required=True, hint="El que aparece al conectarte (SSID)"),
            _field("security", "Seguridad", "select", default="wpa",
                   options=[{"value": "wpa", "label": "WPA / WPA2 / WPA3"}, {"value": "wep", "label": "WEP"},
                            {"value": "open", "label": "Abierta (sin contraseña)"}]),
            _field("password", "Contraseña", "secret", secret=True, optional=False),
        ],
    },
    "bank": {
        "label": "Cuenta bancaria",
        "icon": "bank",
        "summary": "IBAN y datos de tu cuenta",
        "personal": True,
        "fields": [
            _field("bank", "Banco", optional=False),
            _field("holder", "Titular de la cuenta", optional=False),
            _field("iban", "IBAN", "secret", required=True, secret=True),
            _field("bic", "BIC / SWIFT"),
        ],
    },
    "license": {
        "label": "Licencia de software",
        "icon": "badge",
        "summary": "Clave de un programa o juego que compraste",
        "personal": True,
        "fields": [
            _field("product", "Producto", hint="Un programa, un juego, una suscripción…", optional=False),
            _field("license_key", "Clave de licencia", "multiline", required=True, secret=True),
            _field("registered_to", "A nombre de", hint="Nombre o e-mail con el que la registraste"),
            _field("purchased", "Fecha de compra", "date"),
        ],
    },
    # For developers (`dev`): the second group of the «Nueva» picker.
    "api_key": {
        "label": "API key o token",
        "icon": "key",
        "summary": "Clave de API de un servicio (OpenAI, Stripe, GitHub…)",
        "dev": True,
        "fields": [
            _field("value", "API key o token", "secret", required=True, secret=True),
            _field("username", "ID asociado (opcional)", hint="client id, app id, account id…",
                   help="Si la clave va emparejada con un identificador. Al rotarla se pregunta si ha cambiado."),
            _field("base_url", "URL de la API", hint="https://api.ejemplo.com",
                   help="La IA solo podrá enviar la clave a este dominio."),
            _field("auth_style", "Cómo se envía la clave", "select", default="bearer", substitutable=False,
                   options=[{"value": k, "label": v[0]} for k, v in API_AUTH_STYLES.items()]),
            _field("env_var", "Variable de entorno (opcional)", hint="OPENAI_API_KEY", substitutable=False,
                   help="Para usarla con herramientas de línea de comandos."),
        ],
    },
    "ssh": {
        "label": "Servidor SSH",
        "icon": "server",
        "summary": "Acceso a un servidor por SSH y SFTP",
        "dev": True,
        "fields": [
            _field("host", "Servidor (IP o dominio)", required=True, hint="203.0.113.10"),
            _field("port", "Puerto", "number", default="22"),
            _field("username", "Usuario", required=True, hint="root"),
            _field("auth_method", "Autenticación", "select", default="password", substitutable=False,
                   options=[{"value": "password", "label": "Contraseña"}, {"value": "key", "label": "Clave privada"}]),
            _field("password", "Contraseña", "secret", secret=True, required=True,
                   show_if={"auth_method": "password"}, help="También se usa para sudo."),
            _field("private_key", "Clave privada", "multiline", secret=True, required=True, substitutable=False,
                   show_if={"auth_method": "key"}, hint="-----BEGIN OPENSSH PRIVATE KEY-----"),
            _field("passphrase", "Passphrase de la clave (si tiene)", "secret", secret=True, substitutable=False,
                   show_if={"auth_method": "key"}),
        ],
    },
    "database": {
        "label": "Base de datos",
        "icon": "database",
        "summary": "PostgreSQL, MySQL, SQL Server, MongoDB, Redis…",
        "dev": True,
        "fields": [
            _field("engine", "Motor", "select", default="postgresql", substitutable=False,
                   options=[{"value": k, "label": v["label"]} for k, v in DB_ENGINES.items()]),
            _field("host", "Servidor", required=True, hint="db.ejemplo.com"),
            _field("port", "Puerto", "number"),
            _field("database", "Base de datos", hint="app_production"),
            _field("username", "Usuario", required=True),
            _field("password", "Contraseña", "secret", required=True, secret=True),
        ],
    },
    "aws": {
        "label": "Nube (AWS)",
        "icon": "cloud",
        "summary": "Claves de acceso de AWS para la CLI",
        "dev": True,
        "fields": [
            _field("access_key_id", "Access key ID", required=True, hint="AKIA…"),
            _field("secret_access_key", "Secret access key", "secret", required=True, secret=True),
            _field("region", "Región", default="eu-west-1"),
        ],
    },
    # Not a secret: IDs and settings a program needs (a public app's client ID, a tenant, an account id). Kept here so
    # `.secretbroker` and `sb run` give it like the rest, but it has no key: nothing to find in files, rotate or redact,
    # the AI sees its values, and `sb run` gives them without asking.
    "config": {
        "label": "Configuración (no secreta)",
        "icon": "settings",
        "summary": "IDs y datos públicos: client ID, tenant, ID de cuenta…",
        "public": True,
        "dev": True,
        "fields": [
            _field("username", "Identificador", hint="client id, app id, tenant id…",
                   help="No es secreto: la IA lo ve y los programas lo reciben sin pedirte permiso."),
            _field("value", "Valor (opcional)", hint="Un dato de configuración"),
            _field("url", "Dirección web (opcional)", hint="https://…"),
        ],
    },
    "generic": {
        "label": "Otro secreto",
        "icon": "lock",
        "summary": "Cualquier otro dato secreto",
        "dev": True,
        "fields": [
            _field("value", "Secreto", "secret", required=True, secret=True),
            _field("username", "Usuario (opcional)"),
            _field("url", "Dirección web (opcional)", hint="https://…"),
        ],
    },
}

for _id, _template in TEMPLATES.items():
    if _id != "note":  # a note is its text: private notes of its own would be a second one
        _template["fields"].append(_notes())

SECRET_FIELDS = sorted({f["name"] for t in TEMPLATES.values() if not t.get("personal")
                        for f in t["fields"] if f["secret"] and not f["note"]})
COMPUTED_SECRETS = ("connection_url", "totp_code")


def field_specs(template_id):
    return TEMPLATES[template_id]["fields"]


def active_specs(template_id, fields):
    """Field specs that apply given the current values (e.g. SSH key fields only for key auth)."""
    specs = field_specs(template_id)
    defaults = {s["name"]: s["default"] for s in specs}
    resolved = {**defaults, **{k: v for k, v in fields.items() if v not in (None, "")}}
    return [s for s in specs if not s["show_if"] or all(resolved.get(k) == v for k, v in s["show_if"].items())]


def is_public(template_id):
    """A template for data that is not secret (configuration): no key to protect, find, rotate or redact."""
    return bool((TEMPLATES.get(template_id) or {}).get("public"))


PUBLIC_FIELDS = ("username", "value", "url")  # what a configuration entry may hold besides its notes


def is_personal(template_id):
    """A template for the user's own things (a card, a document, a note…): only the user sees and copies them. They
    don't exist for the AI, `sb run` or the browser, and they have no key to give out, rotate, test or look for."""
    return bool((TEMPLATES.get(template_id) or {}).get("personal"))


def secret_field_names(template_id):
    return [s["name"] for s in field_specs(template_id) if s["secret"]]


def key_field_names(template_id):
    """The secret fields that are keys, not private notes. A personal item has none: what it hides (a card's number,
    a document's) is shown and copied like a secret, but never given to a program, redacted, rotated or scanned for."""
    if is_personal(template_id):
        return []
    return [s["name"] for s in field_specs(template_id) if s["secret"] and not s["note"]]


def totp_for_ai(entry):
    """The user let the AI type this login's current 2FA code ({{totp_code}}). Off unless they chose it."""
    return bool(entry["fields"].get("totp") and (entry.get("policy") or {}).get("ai_totp"))


def computed_values(entry):
    fields = entry["fields"]
    if totp_for_ai(entry):
        try:
            return {"totp_code": totp.code(fields["totp"])["code"]}
        except totp.TotpError:
            return {}
    if entry["template"] == "database" and fields.get("host"):
        engine = DB_ENGINES.get(fields.get("engine") or "postgresql", DB_ENGINES["other"])
        if engine["scheme"]:
            credentials = quote(fields.get("username", ""), safe="")
            if fields.get("password"):
                credentials += ":" + quote(fields["password"], safe="")
            port = quote(str(fields.get("port") or engine["port"] or ""), safe="")
            # Every field quoted: a database name like «app?host=evil.example» must stay a name, not become
            # options (libpq reads host= from the query) that send the password elsewhere. IPv6 keeps [ : ].
            host = quote(str(fields["host"]), safe="[]:")
            return {"connection_url": f"{engine['scheme']}://{credentials}@{host}"
                                      f"{':' + port if port else ''}/{quote(str(fields.get('database') or ''), safe='')}"}
    return {}


def placeholder_values(entry):
    """Values the agent may reference as {{name}}; the broker substitutes them server-side."""
    if is_personal(entry["template"]):
        return {}  # nothing of a personal item is ever put in a request, a command or a variable
    fields = entry["fields"]
    values = {s["name"]: str(fields[s["name"]]) for s in active_specs(entry["template"], fields)
              if s["substitutable"] and fields.get(s["name"])}
    if entry["template"] == "database" and not values.get("port"):
        port = DB_ENGINES.get(fields.get("engine") or "postgresql", DB_ENGINES["other"])["port"]
        if port:
            values["port"] = port
    values.update(computed_values(entry))
    return values


def secret_values(entry):
    fields = entry["fields"]
    # The entry's own keys: «value» is a key in an API key but plain data in a configuration entry.
    values = [str(fields[name]) for name in key_field_names(entry["template"]) if fields.get(name)]
    values += [v for k, v in computed_values(entry).items() if k in COMPUTED_SECRETS]
    if fields.get("username") and fields.get("password"):
        values.append(f"{fields['username']}:{fields['password']}")
    return values


def _host_of(url):
    if not url:
        return None
    if "://" not in url:
        url = "https://" + url
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def default_policy(template_id, fields):
    """Sensible AI permissions derived from the template fields. The user can override them."""
    http = {"allowed_hosts": [], "auth": {"kind": "none"}}
    commands = {"allowed": [], "env": {}}
    if is_public(template_id):
        return {"approval": "never"}  # nothing to approve: `sb run` and the AI get its data freely
    if is_personal(template_id):
        return {"approval": "always"}  # no permissions at all: the AI never gets to it (service._for_ai)
    if template_id in ("web_login", "generic"):
        host = _host_of(fields.get("url"))
        http["allowed_hosts"] = [host] if host else []
    elif template_id == "api_key":
        host = _host_of(fields.get("base_url"))
        http["allowed_hosts"] = [host] if host else []
        http["auth"] = dict(API_AUTH_STYLES.get(fields.get("auth_style") or "bearer", API_AUTH_STYLES["none"])[1])
        if fields.get("env_var"):
            commands["env"] = {fields["env_var"].strip(): "{{value}}"}
    elif template_id == "database":
        engine = DB_ENGINES.get(fields.get("engine") or "postgresql", DB_ENGINES["other"])
        entry = {"template": "database", "fields": {**fields, "password": fields.get("password") or "x"}}
        available = placeholder_values(entry)
        commands["allowed"] = list(engine["commands"])
        commands["env"] = {
            name: template for name, template in engine["env"].items()
            if all(p in available for p in PLACEHOLDER_RE.findall(template))
        }
        if engine["scheme"]:
            commands["env"]["DATABASE_URL"] = "{{connection_url}}"
    elif template_id == "aws":
        commands["allowed"] = ["aws"]
        commands["env"] = {"AWS_ACCESS_KEY_ID": "{{access_key_id}}", "AWS_SECRET_ACCESS_KEY": "{{secret_access_key}}"}
        if fields.get("region"):
            commands["env"]["AWS_DEFAULT_REGION"] = "{{region}}"
    policy = {"approval": "session"}
    if template_id != "ssh":
        policy["http"] = http
    if commands["allowed"] or commands["env"]:
        policy["commands"] = commands
    return policy


def available_actions(entry):
    policy = entry.get("policy") or {}
    actions = []
    if (policy.get("http") or {}).get("allowed_hosts"):
        actions.append("http_request")
    if entry["template"] == "ssh":
        actions += ["ssh_exec", "ssh_upload", "ssh_download"]
    if (policy.get("commands") or {}).get("allowed"):
        actions.append("run_command")
    return actions


def export():
    """Template definitions for the GUI, in the language of the request (messages templates.*)."""
    return i18n.localize("templates", {
        "templates": [{"id": k, **v} for k, v in TEMPLATES.items()],
        "db_engines": {k: {"label": v["label"], "port": v["port"]} for k, v in DB_ENGINES.items()},
    })
