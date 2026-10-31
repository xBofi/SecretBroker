"""Connect SecretBroker's MCP server to the user's AI apps (Claude Code, Claude Desktop, Cursor, VS Code,
Windsurf, Codex), and per-user UI preferences."""

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from . import paths, platform

SERVER_NAME = "secret-broker"
PREFS_FILE = paths.user_dir() / "prefs.json"
CREATE_NO_WINDOW = platform.NO_WINDOW
# the desktop app serves the tools here for Claude Code (see resident.serve_mcp)
MCP_PORT = int(os.environ.get("SECRETBROKER_MCP_PORT") or 47821)


def mcp_command():
    return platform.python_console(), ["-I", "-m", "secretbroker.mcp_server"]


# ----------------------------------------------------------------- preferences


def load_prefs():
    try:
        return json.loads(PREFS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def set_pref(key, value):
    prefs = load_prefs()
    prefs[key] = value
    PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PREFS_FILE.write_text(json.dumps(prefs), encoding="utf-8")


def mcp_endpoint():
    """(url, token) of the MCP server the desktop app serves. The token keeps other local programs
    (and web pages, which can reach 127.0.0.1) out; Claude Code sends it as a header."""
    token = load_prefs().get("mcp_token")
    if not token:
        token = secrets.token_urlsafe(32)
        set_pref("mcp_token", token)
    return f"http://127.0.0.1:{MCP_PORT}/mcp", token


# ----------------------------------------------------------------- Claude Code
#
# Claude Code connects to the app over HTTP: after an update it reconnects by itself, while a stdio
# server killed by the installer stayed dead until the user ran /mcp. Claude Desktop only supports stdio.


def _claude_cli():
    return shutil.which("claude")


def _claude_code_entry():
    try:
        config = json.loads((Path.home() / ".claude.json").read_text(encoding="utf-8"))
        return config.get("mcpServers", {}).get(SERVER_NAME)
    except (OSError, ValueError, AttributeError):
        return None


def claude_code_status():
    if not _claude_cli():
        return "missing"
    entry = _claude_code_entry() or {}
    url, token = mcp_endpoint()
    connected = entry.get("url") == url and (entry.get("headers") or {}).get("Authorization") == f"Bearer {token}"
    return "connected" if connected else "disconnected"


def connect_claude_code():
    cli = _claude_cli()
    if not cli:
        raise RuntimeError("Claude Code no está instalado en este usuario")
    url, token = mcp_endpoint()
    run = lambda *a: subprocess.run([cli, "mcp", *a], capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
    run("remove", SERVER_NAME, "--scope", "user")
    result = run("add", "--transport", "http", "--scope", "user", SERVER_NAME, url,
                 "--header", f"Authorization: Bearer {token}")
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "No se pudo registrar en Claude Code").strip())


def upgrade_claude_code():
    """Move a Claude Code connection made by an older version (stdio) to the app's HTTP server."""
    if paths.instance_suffix():
        return  # a test instance must not repoint the user's Claude Code
    if _claude_cli() and _claude_code_entry() and claude_code_status() == "disconnected":
        connect_claude_code()


# ----------------------------------------------------------------- Claude Desktop


def _desktop_config_dirs():
    yield from platform.claude_desktop_config_dirs(Path.home())


def _desktop_config_files():
    return [d / "claude_desktop_config.json" for d in _desktop_config_dirs() if d.is_dir()]


def claude_desktop_status():
    files = _desktop_config_files()
    if not files:
        return "missing"
    for file in files:
        try:
            if SERVER_NAME in json.loads(file.read_text(encoding="utf-8")).get("mcpServers", {}):
                return "connected"
        except (OSError, ValueError):
            pass
    return "disconnected"


def connect_claude_desktop():
    files = _desktop_config_files()
    if not files:
        raise RuntimeError("Claude Desktop no está instalado en este usuario")
    python, args = mcp_command()
    for file in files:
        try:
            config = json.loads(file.read_text(encoding="utf-8")) if file.exists() else {}
        except ValueError:
            raise RuntimeError(f"No se pudo leer {file}: el JSON no es válido") from None
        config.setdefault("mcpServers", {})[SERVER_NAME] = {"command": python, "args": args}
        file.write_text(json.dumps(config, indent=2), encoding="utf-8")


# ----------------------------------------------------------------- other AI apps
#
# Each reads its MCP servers from a file in the user's profile; SecretBroker adds its own entry and keeps
# the rest of the file as it was. Editors connect to the app's HTTP server (it reconnects after an update),
# Codex starts the stdio server like Claude Desktop.
#   Cursor    ~/.cursor/mcp.json                        {"mcpServers": {name: {"url", "headers"}}}
#   VS Code   %APPDATA%/Code/User/mcp.json (Copilot)    {"servers": {name: {"type": "http", "url", "headers"}}}
#             (Linux: ~/.config/Code/User/mcp.json)
#   Windsurf  ~/.codeium/windsurf/mcp_config.json       {"mcpServers": {name: {"serverUrl", "headers"}}}
#   Codex     ~/.codex/config.toml (or CODEX_HOME)      [mcp_servers.<name>] command / args


def _strip_json_comments(text):
    """VS Code's mcp.json is JSON with comments and trailing commas: plain JSON, keeping strings intact."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            i = text.find("\n", i) if "\n" in text[i:] else n
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _read_json(file):
    if not file.exists():
        return {}
    try:
        text = file.read_text(encoding="utf-8-sig")
        return json.loads(_strip_json_comments(text)) if text.strip() else {}
    except (OSError, ValueError):
        raise RuntimeError(f"No se pudo leer {file}: el archivo no es JSON válido. Corrígelo o bórralo y vuelve a intentarlo.") from None


def _http_entry(kind):
    url, token = mcp_endpoint()
    headers = {"Authorization": f"Bearer {token}"}
    if kind == "vscode":
        return {"type": "http", "url": url, "headers": headers}
    if kind == "windsurf":
        return {"serverUrl": url, "headers": headers}
    return {"url": url, "headers": headers}


def _home():
    """The user's profile; a test instance (SECRETBROKER_HOME) uses a fake one and never edits the real apps."""
    if paths.instance_suffix():
        return Path(os.environ.get("SECRETBROKER_PROFILE") or paths.root() / "profile")
    return Path.home()


def _appdata(name):
    """APPDATA: where programs keep settings; LOCALAPPDATA: where they install per user (see platform)."""
    if paths.instance_suffix():
        if platform.NAME == "windows":
            return _home() / "AppData" / ("Roaming" if name == "APPDATA" else "Local")
        return (platform.roaming_dir if name == "APPDATA" else platform.local_dir)(_home())
    if platform.NAME == "windows":
        return Path(os.environ.get(name) or _home())
    return (platform.roaming_dir if name == "APPDATA" else platform.local_dir)(_home())


JSON_CLIENTS = {
    # id: (installed?, config file, key holding the servers)
    "cursor": (lambda: (_home() / ".cursor").is_dir() or (_appdata("LOCALAPPDATA") / "Programs" / "cursor").is_dir(),
               lambda: _home() / ".cursor" / "mcp.json", "mcpServers"),
    "vscode": (lambda: (_appdata("APPDATA") / "Code" / "User").is_dir(),
               lambda: _appdata("APPDATA") / "Code" / "User" / "mcp.json", "servers"),
    "windsurf": (lambda: (_home() / ".codeium" / "windsurf").is_dir() or (_appdata("LOCALAPPDATA") / "Programs" / "Windsurf").is_dir(),
                 lambda: _home() / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"),
}


def json_client_status(kind):
    installed, path, key = JSON_CLIENTS[kind]
    if not installed():
        return "missing"
    try:
        entry = (_read_json(path()).get(key) or {}).get(SERVER_NAME)
    except (RuntimeError, AttributeError):
        return "disconnected"
    return "connected" if entry == _http_entry(kind) else "disconnected"


def connect_json_client(kind):
    installed, path, key = JSON_CLIENTS[kind]
    if not installed():
        raise RuntimeError(f"{CLIENT_LABELS[kind]} no está instalado en este usuario")
    file = path()
    config = _read_json(file)
    if not isinstance(config.get(key, {}), dict):
        raise RuntimeError(f"No se pudo leer {file}: «{key}» no tiene el formato esperado")
    config.setdefault(key, {})[SERVER_NAME] = _http_entry(kind)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def _codex_file():
    codex_home = None if paths.instance_suffix() else os.environ.get("CODEX_HOME")
    return Path(codex_home or _home() / ".codex") / "config.toml"


_CODEX_HEADER = re.compile(r"^\s*\[\s*mcp_servers\s*\.\s*(?:\"secret-broker\"|'secret-broker'|secret-broker)\s*(\]|\.)")


def _codex_without_us(text):
    """config.toml without our [mcp_servers.secret-broker] table (and its sub-tables)."""
    kept, skipping = [], False
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("["):
            skipping = bool(_CODEX_HEADER.match(line))
        if not skipping:
            kept.append(line)
    return "".join(kept)


def _codex_block():
    python, args = mcp_command()
    quote = lambda s: "'" + s + "'" if "'" not in s else json.dumps(s)  # noqa: E731  (TOML literal string: no escapes)
    return f"[mcp_servers.{SERVER_NAME}]\ncommand = {quote(python)}\nargs = [{', '.join(quote(a) for a in args)}]\n"


def codex_status():
    file = _codex_file()
    if not (file.parent.is_dir() or shutil.which("codex")):
        return "missing"
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return "disconnected"
    return "connected" if _codex_block() in text else "disconnected"


def connect_codex():
    file = _codex_file()
    if not (file.parent.is_dir() or shutil.which("codex")):
        raise RuntimeError("Codex no está instalado en este usuario")
    try:
        text = file.read_text(encoding="utf-8") if file.exists() else ""
    except OSError as exc:
        raise RuntimeError(f"No se pudo leer {file}: {exc.strerror or exc}") from None
    text = _codex_without_us(text).rstrip()
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text((text + "\n\n" if text else "") + _codex_block(), encoding="utf-8")


def _remove_codex():
    file = _codex_file()
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return False
    cleaned = _codex_without_us(text)
    if cleaned == text:
        return False
    file.write_text(cleaned.rstrip() + "\n" if cleaned.strip() else "", encoding="utf-8")
    return True


# Every AI app the app can connect, in the order it shows them. `mcp` are the names each one sends in the
# MCP handshake (clientInfo.name), lowercase, to tell which of them made a request.
CLIENT_LABELS = {"claude_code": "Claude Code", "claude_desktop": "Claude Desktop", "cursor": "Cursor",
                 "vscode": "VS Code (Copilot)", "windsurf": "Windsurf", "codex": "Codex"}
CLIENT_MCP_NAMES = {"claude_code": ("claude-code",), "claude_desktop": ("claude-ai", "claude desktop", "claude"),
                    "cursor": ("cursor", "cursor-vscode"), "vscode": ("visual studio code", "vscode", "visual studio code - insiders"),
                    "windsurf": ("windsurf", "windsurf-client", "codeium"), "codex": ("codex", "codex-mcp-client", "codex_cli_rs")}
CONNECTORS = {"claude_code": (claude_code_status, connect_claude_code),
              "claude_desktop": (claude_desktop_status, connect_claude_desktop),
              "cursor": (lambda: json_client_status("cursor"), lambda: connect_json_client("cursor")),
              "vscode": (lambda: json_client_status("vscode"), lambda: connect_json_client("vscode")),
              "windsurf": (lambda: json_client_status("windsurf"), lambda: connect_json_client("windsurf")),
              "codex": (codex_status, connect_codex)}


def client_of(mcp_name):
    """The id (claude_code, cursor…) of a name sent in the MCP handshake, or None for one the app doesn't know."""
    name = str(mcp_name or "").strip().lower()
    for client_id, names in CLIENT_MCP_NAMES.items():
        if name in names or any(name.startswith(n + " ") or name.startswith(n + "-") for n in names if n != "claude"):
            return client_id
    return None


def connect(client_id):
    if client_id not in CONNECTORS:
        raise RuntimeError("Aplicación desconocida")
    if paths.instance_suffix() and client_id in ("claude_code", "claude_desktop"):
        raise RuntimeError("Una instancia de prueba no conecta las apps de Claude de este usuario")
    CONNECTORS[client_id][1]()


def clients():
    """[{id, label, status: connected | disconnected | missing}] of every AI app the app can connect."""
    result = []
    for client_id, (current, _) in CONNECTORS.items():
        try:
            # A test instance only sees its fake profile; the Claude apps are this user's real ones.
            state = "missing" if paths.instance_suffix() and client_id in ("claude_code", "claude_desktop") else current()
        except Exception:  # a broken config file must not hide the others
            state = "disconnected"
        result.append({"id": client_id, "label": CLIENT_LABELS[client_id], "status": state})
    return result


# ----------------------------------------------------------------- uninstall


def _remove_server(file, key="mcpServers"):
    try:
        config = json.loads(_strip_json_comments(file.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError):
        return False
    if SERVER_NAME not in (config.get(key) or {}):
        return False
    del config[key][SERVER_NAME]
    file.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    return True


def remove_all():
    """Called by the uninstaller: unregister the MCP server from Claude Code and Claude Desktop and delete preferences.

    It edits the config files directly instead of using the `claude` CLI, because it runs elevated with
    USERPROFILE / APPDATA / LOCALAPPDATA pointing at the owner's profile.
    """
    files = [(Path.home() / ".claude.json", "mcpServers"), *((f, "mcpServers") for f in _desktop_config_files()),
             *((path(), key) for _, path, key in JSON_CLIENTS.values())]
    for file, key in files:
        try:
            if _remove_server(file, key):
                print(f"Quitado de {file}")
        except OSError as exc:
            print(f"No se pudo modificar {file}: {exc}", file=sys.stderr)
    try:
        if _remove_codex():
            print(f"Quitado de {_codex_file()}")
    except OSError as exc:
        print(f"No se pudo modificar {_codex_file()}: {exc}", file=sys.stderr)
    shutil.rmtree(PREFS_FILE.parent, ignore_errors=True)
    platform.remove_autostart()  # start with the session (see resident.set_start_with_windows)



def status():
    return {"claude_code": claude_code_status(), "claude_desktop": claude_desktop_status()}


def auto_connect():
    """Called by the setup program (as the desktop user): connect whatever Claude apps are installed."""
    for current, connect in ((claude_code_status, connect_claude_code), (claude_desktop_status, connect_claude_desktop)):
        if current() == "disconnected":
            try:
                connect()
            except Exception as exc:
                print(f"{connect.__name__}: {exc}", file=sys.stderr)
