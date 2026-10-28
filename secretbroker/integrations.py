"""Connect SecretBroker's MCP server to Claude Code and Claude Desktop, and per-user UI preferences."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SERVER_NAME = "secret-broker"
PREFS_FILE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretBroker" / "prefs.json"
CREATE_NO_WINDOW = 0x08000000


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


# ----------------------------------------------------------------- Claude Code


def _claude_cli():
    return shutil.which("claude")


def claude_code_status():
    if not _claude_cli():
        return "missing"
    try:
        config = json.loads((Path.home() / ".claude.json").read_text(encoding="utf-8"))
        command = config.get("mcpServers", {}).get(SERVER_NAME, {}).get("command", "")
    except (OSError, ValueError):
        command = ""
    return "connected" if command and Path(command) == Path(mcp_command()[0]) else "disconnected"


def connect_claude_code():
    cli = _claude_cli()
    if not cli:
        raise RuntimeError("Claude Code no está instalado en este usuario")
    python, args = mcp_command()
    run = lambda *a: subprocess.run([cli, "mcp", *a], capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
    run("remove", SERVER_NAME, "--scope", "user")
    result = run("add", "--scope", "user", SERVER_NAME, "--", python, *args)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "No se pudo registrar en Claude Code").strip())


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
