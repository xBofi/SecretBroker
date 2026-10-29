"""Connect SecretBroker's MCP server to Claude Code and Claude Desktop, and per-user UI preferences."""

import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from . import paths

SERVER_NAME = "secret-broker"
PREFS_FILE = paths.user_dir() / "prefs.json"
CREATE_NO_WINDOW = 0x08000000
# the desktop app serves the tools here for Claude Code (see resident.serve_mcp)
MCP_PORT = int(os.environ.get("SECRETBROKER_MCP_PORT") or 47821)


def mcp_command():
    python = Path(sys.executable).with_name("python.exe")
    return str(python if python.exists() else sys.executable), ["-I", "-m", "secretbroker.mcp_server"]


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
    yield Path(os.environ.get("APPDATA", "")) / "Claude"
    packages = Path(os.environ.get("LOCALAPPDATA", "")) / "Packages"
    if packages.is_dir():
        for package in packages.glob("Claude_*"):
            yield package / "LocalCache" / "Roaming" / "Claude"


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


# ----------------------------------------------------------------- uninstall


def _remove_server(file):
    try:
        config = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if SERVER_NAME not in (config.get("mcpServers") or {}):
        return False
    del config["mcpServers"][SERVER_NAME]
    file.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    return True


def remove_all():
    """Called by the uninstaller: unregister the MCP server from Claude Code and Claude Desktop and delete preferences.

    It edits the config files directly instead of using the `claude` CLI, because it runs elevated with
    USERPROFILE / APPDATA / LOCALAPPDATA pointing at the owner's profile.
    """
    for file in [Path.home() / ".claude.json", *_desktop_config_files()]:
        try:
            if _remove_server(file):
                print(f"Quitado de {file}")
        except OSError as exc:
            print(f"No se pudo modificar {file}: {exc}", file=sys.stderr)
    shutil.rmtree(PREFS_FILE.parent, ignore_errors=True)
    if sys.platform == "win32":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "SecretBroker")  # start with Windows (see resident.set_start_with_windows)
        except OSError:
            pass


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
