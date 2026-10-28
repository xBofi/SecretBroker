"""Credential templates: which fields each kind of credential has, and its default AI policy."""

import re
from urllib.parse import quote, urlsplit

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def _field(name, label, kind="text", required=False, secret=False, hint="", help="",
           options=None, default="", show_if=None, substitutable=True):
    return {
        "name": name, "label": label, "kind": kind, "required": required, "secret": secret,
        "hint": hint, "help": help, "options": options or [], "default": default,
        "show_if": show_if, "substitutable": substitutable,
    }


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
            _field("username", "Usuario o email", required=True),
            _field("password", "Contraseña", "secret", required=True, secret=True),
        ],
    },
    "api_key": {
        "label": "API key o token",
        "icon": "key",
        "summary": "Clave de API de un servicio (OpenAI, Stripe, GitHub…)",
        "fields": [
            _field("value", "API key o token", "secret", required=True, secret=True),
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
        "fields": [
            _field("access_key_id", "Access key ID", required=True, hint="AKIA…"),
            _field("secret_access_key", "Secret access key", "secret", required=True, secret=True),
            _field("region", "Región", default="eu-west-1"),
        ],
    },
    "generic": {
        "label": "Otro secreto",
        "icon": "lock",
        "summary": "Cualquier otro dato secreto",
        "fields": [
            _field("value", "Secreto", "secret", required=True, secret=True),
            _field("username", "Usuario (opcional)"),
            _field("url", "Dirección web (opcional)", hint="https://…"),
        ],
    },
}

SECRET_FIELDS = sorted({f["name"] for t in TEMPLATES.values() for f in t["fields"] if f["secret"]})
COMPUTED_SECRETS = ("connection_url",)


def field_specs(template_id):
    return TEMPLATES[template_id]["fields"]


def active_specs(template_id, fields):
    """Field specs that apply given the current values (e.g. SSH key fields only for key auth)."""
    specs = field_specs(template_id)
    defaults = {s["name"]: s["default"] for s in specs}
    resolved = {**defaults, **{k: v for k, v in fields.items() if v not in (None, "")}}
    return [s for s in specs if not s["show_if"] or all(resolved.get(k) == v for k, v in s["show_if"].items())]


def secret_field_names(template_id):
    return [s["name"] for s in field_specs(template_id) if s["secret"]]


def computed_values(entry):
    fields = entry["fields"]
    if entry["template"] == "database" and fields.get("host"):
        engine = DB_ENGINES.get(fields.get("engine") or "postgresql", DB_ENGINES["other"])
        if engine["scheme"]:
            credentials = quote(fields.get("username", ""), safe="")
            if fields.get("password"):
                credentials += ":" + quote(fields["password"], safe="")
            port = fields.get("port") or engine["port"]
            return {"connection_url": f"{engine['scheme']}://{credentials}@{fields['host']}"
                                      f"{':' + port if port else ''}/{fields.get('database', '')}"}
    return {}


def placeholder_values(entry):
    """Values the agent may reference as {{name}}; the broker substitutes them server-side."""
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
    values = [str(fields[name]) for name in SECRET_FIELDS if fields.get(name)]
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
    """Template definitions for the GUI."""
    return {
        "templates": [{"id": k, **v} for k, v in TEMPLATES.items()],
        "db_engines": {k: {"label": v["label"], "port": v["port"]} for k, v in DB_ENGINES.items()},
    }
