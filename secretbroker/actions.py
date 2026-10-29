"""Actions the broker performs on behalf of the agent. None of them return secret values."""

import base64
import io
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import httpx
import paramiko
from nacl.public import PublicKey, SealedBox

from .inject import ActionError, Redactor, substitute

MAX_OUTPUT_CHARS = 100_000
KNOWN_HOSTS = None  # set by the service: SSH host keys remembered on first use


def configure(known_hosts):
    global KNOWN_HOSTS
    KNOWN_HOSTS = known_hosts
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
TEXT_CONTENT_HINTS = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "yaml", "csv")
CMD_METACHARS = set('&|<>^%!"\r\n')


def _truncate(text):
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n[... truncado, {len(text) - MAX_OUTPUT_CHARS} caracteres más]"


def _require(params, *names):
    missing = [name for name in names if params.get(name) in (None, "")]
    if missing:
        raise ActionError("Faltan parámetros: " + ", ".join(missing))


# --------------------------------------------------------------------------- HTTP


def host_allowed(host, patterns):
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.strip().lower()
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):
                return True
        elif host == pattern.strip("[]"):
            return True
    return False


def _check_destination(entry, params):
    """Validate the destination before any secret is substituted into the request."""
    _require(params, "url")
    allowed = (entry["policy"].get("http") or {}).get("allowed_hosts") or []
    if not allowed:
        raise ActionError(f"'{entry['id']}' no tiene webs permitidas")
    try:
        url = httpx.URL(params["url"])
    except Exception:
        raise ActionError("URL no válida") from None
    if not url.host or not host_allowed(url.host, allowed):
        raise ActionError(f"Host '{url.host}' no permitido para '{entry['id']}'. Permitidos: {', '.join(allowed)}")
    if url.scheme != "https" and not (url.scheme == "http" and url.host in LOOPBACK_HOSTS):
        raise ActionError("Solo se permite HTTPS (HTTP únicamente hacia localhost)")
    return url


def http_request(entry, params):
    http = entry["policy"].get("http") or {}
    url = _check_destination(entry, params)
    raw_url = params["url"]

    final_url = httpx.URL(substitute(raw_url, entry, escape=lambda v: quote(v, safe="")))
    if (final_url.scheme, final_url.host, final_url.port) != (url.scheme, url.host, url.port):
        raise ActionError("Los placeholders no pueden modificar el destino de la petición")

    headers = {str(k): substitute(str(v), entry) for k, v in (params.get("headers") or {}).items()}
    content = None
    if params.get("json_body") is not None:
        content = substitute(json.dumps(params["json_body"]), entry, escape=lambda v: json.dumps(v)[1:-1])
        headers.setdefault("Content-Type", "application/json")
    elif params.get("body") is not None:
        content = substitute(str(params["body"]), entry)

    auth = None
    if params.get("inject_auth", True):
        auth_cfg = http.get("auth") or {}
        kind = auth_cfg.get("kind", "none")
        template = auth_cfg.get("template") or "{{value}}"
        if kind == "header":
            headers[auth_cfg["name"]] = substitute(template, entry)
        elif kind == "query":
            final_url = final_url.copy_merge_params({auth_cfg["name"]: substitute(template, entry)})
        elif kind == "basic":
            auth = (entry["fields"]["username"], entry["fields"]["password"])

    timeout = float(params.get("timeout") or 60)
    # Redirects are not followed so credentials never travel to a host outside the allowlist.
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        response = client.request(
            params.get("method", "GET").upper(),
            final_url,
            headers=headers,
            content=content.encode("utf-8") if content is not None else None,
            auth=auth,
        )

    redact = Redactor(entry)
    content_type = response.headers.get("content-type", "")
    if not content_type or any(hint in content_type for hint in TEXT_CONTENT_HINTS):
        body = _truncate(redact(response.content.decode(response.encoding or "utf-8", errors="replace")))
    else:
        body = f"[contenido binario: {content_type}, {len(response.content)} bytes]"
    return {
        "status": response.status_code,
        "headers": {k: redact(v) for k, v in response.headers.items()},
        "body": body,
    }


# --------------------------------------------------------------------------- SSH


def load_private_key(text, passphrase=None):
    last_error = None
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise ActionError("La clave privada está cifrada y requiere passphrase") from None
        except (paramiko.SSHException, ValueError) as exc:
            last_error = exc
    raise ActionError(f"No se pudo leer la clave privada: {last_error}")


class _TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
    """Accept and remember unknown host keys; paramiko itself rejects changed keys."""

    def __init__(self):
        self.added = None

    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        self.added = f"{hostname} {key.get_name()} {getattr(key, 'fingerprint', key.get_base64()[:32])}"


def _connect(entry):
    fields = entry["fields"]
    if entry.get("template") != "ssh":
        raise ActionError(f"'{entry['id']}' no es un servidor SSH")
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    KNOWN_HOSTS.touch(exist_ok=True)
    client = paramiko.SSHClient()
    client.load_host_keys(str(KNOWN_HOSTS))
    policy = _TrustOnFirstUse()
    client.set_missing_host_key_policy(policy)
    use_key = fields.get("auth_method") == "key"
    pkey = load_private_key(fields["private_key"], fields.get("passphrase")) if use_key else None
    client.connect(
        fields["host"],
        port=int(fields.get("port") or 22),
        username=fields["username"],
        password=None if use_key else fields.get("password"),
        pkey=pkey,
        timeout=15,
        allow_agent=False,
        look_for_keys=False,
    )
    if policy.added:
        client.save_host_keys(str(KNOWN_HOSTS))
    return client, policy.added


def ssh_exec(entry, params):
    _require(params, "command")
    command = params["command"]
    sudo = bool(params.get("sudo"))
    password = entry["fields"].get("password") if entry["fields"].get("auth_method") != "key" else None
    if sudo:
        if not password:
            raise ActionError("sudo requiere que la credencial use autenticación por contraseña")
        # -k forces sudo to ask, so the password line is always consumed by sudo, not the command.
        command = "sudo -k -S -p '' sh -c " + shlex.quote(command)
    timeout = float(params.get("timeout") or 120)

    client, new_host_key = _connect(entry)
    try:
        channel = client.get_transport().open_session()
        channel.exec_command(command)
        if sudo:
            channel.sendall((password + "\n").encode())
        channel.shutdown_write()
        stdout, stderr = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        timed_out = False
        while True:
            if channel.recv_ready():
                stdout += channel.recv(65536)
            elif channel.recv_stderr_ready():
                stderr += channel.recv_stderr(65536)
            elif channel.exit_status_ready():
                break
            elif time.monotonic() > deadline:
                timed_out = True
                break
            else:
                time.sleep(0.05)
        exit_code = None if timed_out else channel.recv_exit_status()
        channel.close()
    finally:
        client.close()

    redact = Redactor(entry)
    result = {
        "exit_code": exit_code,
        "stdout": _truncate(redact(stdout.decode("utf-8", errors="replace"))),
        "stderr": _truncate(redact(stderr.decode("utf-8", errors="replace"))),
    }
    if timed_out:
        result["timed_out"] = True
    if new_host_key:
        result["note"] = f"Nueva clave de host registrada (TOFU): {new_host_key}"
    return result


def ssh_upload(entry, params):
    _require(params, "local_path", "remote_path")
    local = Path(params["local_path"]).expanduser().resolve()
    if not local.is_file():
        raise ActionError(f"No existe el archivo local: {local}")
    client, new_host_key = _connect(entry)
    try:
        with client.open_sftp() as sftp:
            sftp.put(str(local), params["remote_path"])
    finally:
        client.close()
    return {"uploaded": str(local), "remote_path": params["remote_path"], "bytes": local.stat().st_size,
            **({"note": f"Nueva clave de host registrada: {new_host_key}"} if new_host_key else {})}


def ssh_download(entry, params):
    _require(params, "remote_path", "local_path")
    local = Path(params["local_path"]).expanduser().resolve()
    if local.exists() and not params.get("overwrite"):
        raise ActionError(f"El archivo local ya existe: {local} (usa overwrite=true)")
    if not local.parent.is_dir():
        raise ActionError(f"No existe la carpeta local: {local.parent}")
    client, new_host_key = _connect(entry)
    try:
        with client.open_sftp() as sftp:
            sftp.get(params["remote_path"], str(local))
    finally:
        client.close()
    return {"downloaded": params["remote_path"], "local_path": str(local), "bytes": local.stat().st_size,
            **({"note": f"Nueva clave de host registrada: {new_host_key}"} if new_host_key else {})}


# --------------------------------------------------------------------------- local commands


def _resolve_executable(name):
    """Look the command up on PATH only (never the current directory or a given path)."""
    if any(sep in name for sep in ("/", "\\", ":")):
        raise ActionError("argv[0] debe ser un nombre de comando, no una ruta")
    if sys.platform == "win32":
        exts = [e.lower() for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
        candidates = [name] if Path(name).suffix.lower() in exts else [name + ext for ext in exts]
    else:
        candidates = [name]
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or not os.path.isabs(directory):
            continue
        for candidate in candidates:
            path = os.path.join(directory, candidate)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    raise ActionError(f"Comando no encontrado en PATH: {name}")


def _command_name(name):
    stem, ext = os.path.splitext(name)
    return (stem if ext.lower() in (".exe", ".cmd", ".bat", ".com") else name).lower()


def _check_command(entry, params):
    argv = params.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ActionError("argv debe ser una lista de strings no vacía")
    if any(sep in argv[0] for sep in ("/", "\\", ":")):
        raise ActionError("argv[0] debe ser un nombre de comando, no una ruta")
    allowed = {c.lower() for c in (entry["policy"].get("commands") or {}).get("allowed", [])}
    if _command_name(argv[0]) not in allowed:
        raise ActionError(f"'{argv[0]}' no está en los comandos permitidos de '{entry['id']}': {', '.join(sorted(allowed)) or '(ninguno)'}")
    return argv


def run_command(entry, params):
    argv = _check_command(entry, params)
    commands = entry["policy"].get("commands") or {}
    executable = _resolve_executable(argv[0])
    if Path(executable).suffix.lower() in (".bat", ".cmd") and any(CMD_METACHARS & set(a) for a in argv[1:]):
        # .bat/.cmd go through cmd.exe, which would interpret these characters.
        raise ActionError("Argumentos con caracteres especiales de cmd.exe no permitidos para scripts .bat/.cmd")

    env = dict(os.environ)
    for name, template in (commands.get("env") or {}).items():
        env[name] = substitute(template, entry)
    cwd = params.get("cwd") or None
    if cwd and not Path(cwd).is_dir():
        raise ActionError(f"No existe el directorio: {cwd}")

    timeout = float(params.get("timeout") or 300)
    try:
        completed = subprocess.run(
            [executable, *argv[1:]], env=env, cwd=cwd, capture_output=True,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ActionError(f"El comando superó el tiempo límite de {timeout:.0f} s") from None

    redact = Redactor(entry)
    return {
        "exit_code": completed.returncode,
        "stdout": _truncate(redact(completed.stdout.decode("utf-8", errors="replace"))),
        "stderr": _truncate(redact(completed.stderr.decode("utf-8", errors="replace"))),
    }


# --------------------------------------------------------------------------- GitHub

GITHUB_API = "https://api.github.com"
GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def check_github_secret(params):
    _require(params, "repo", "name")
    repo = str(params["repo"])
    if not GITHUB_REPO_RE.match(repo) or any(part.strip(".") == "" for part in repo.split("/")):
        raise ActionError("repo debe tener la forma propietario/repositorio")
    name = str(params["name"])
    if not SECRET_NAME_RE.match(name) or name.upper().startswith("GITHUB_"):
        raise ActionError("Nombre de secret no válido: solo letras, números y _, sin empezar por número ni por GITHUB_")


def _github_secrets_url(params):
    base = f"{GITHUB_API}/repos/{params['repo']}"
    if params.get("environment"):
        base += f"/environments/{quote(str(params['environment']), safe='')}"
    return base + "/actions/secrets"


def _github(token_entry, method, url, json_body=None):
    params = {"method": method, "url": url, "headers": {
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}}
    if json_body is not None:
        params["json_body"] = json_body
    response = http_request(token_entry, params)
    if response["status"] >= 300:
        raise ActionError(f"GitHub respondió {response['status']}: {response['body'][:500]}")
    return response


def push_github_secret(value_entry, token_entry, params):
    """Store a value from the vault as a GitHub Actions secret, encrypted with the repository's public key."""
    check_github_secret(params)
    value = substitute(params.get("value") or "{{value}}", value_entry)
    base = _github_secrets_url(params)
    key = json.loads(_github(token_entry, "GET", base + "/public-key")["body"])
    sealed = SealedBox(PublicKey(base64.b64decode(key["key"]))).encrypt(value.encode("utf-8"))
    response = _github(token_entry, "PUT", f"{base}/{params['name']}",
                       {"encrypted_value": base64.b64encode(sealed).decode(), "key_id": key["key_id"]})
    return {"repo": params["repo"], "environment": params.get("environment"), "name": params["name"],
            "status": "created" if response["status"] == 201 else "updated"}


# --------------------------------------------------------------------------- registry


ACTIONS = {
    "http_request": http_request,
    "ssh_exec": ssh_exec,
    "ssh_upload": ssh_upload,
    "ssh_download": ssh_download,
    "run_command": run_command,
}


def precheck(action, entry, params):
    """Reject requests that can never succeed before asking the user to approve them."""
    if action.startswith("ssh_") and entry.get("template") != "ssh":
        raise ActionError(f"'{entry['id']}' no es un servidor SSH")
    if action == "http_request":
        _check_destination(entry, params)
    elif action == "run_command":
        _check_command(entry, params)


def describe(action, params, entry):
    """Human-readable summary for approval prompts and the audit log (placeholders unexpanded)."""
    fields = entry["fields"]
    target = f"{fields.get('username')}@{fields.get('host')}"
    if action == "http_request":
        text = f"{str(params.get('method', 'GET')).upper()} {params.get('url', '')}"
        body = params.get("json_body")
        body = json.dumps(body, ensure_ascii=False) if body is not None else params.get("body")
        return text + (f"\n\nCuerpo:\n{str(body)[:1500]}" if body else "")
    if action == "ssh_exec":
        return f"{target}$ {'sudo ' if params.get('sudo') else ''}{params.get('command', '')}"
    if action == "ssh_upload":
        return f"Subir {params.get('local_path')} → {target}:{params.get('remote_path')}"
    if action == "ssh_download":
        return f"Descargar {target}:{params.get('remote_path')} → {params.get('local_path')}"
    if action == "run_command":
        argv = params.get("argv") if isinstance(params.get("argv"), list) else []
        return subprocess.list2cmdline([str(a) for a in argv]) + (f"\n(en {params['cwd']})" if params.get("cwd") else "")
    return action
