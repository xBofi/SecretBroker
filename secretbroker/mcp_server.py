"""MCP server for AI agents: a thin client of the SecretBroker service. It never holds secrets."""

import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import client
from .client import BrokerError, BrokerUnavailable

UNLOCK_WAIT_SECONDS = 120
APP_START_WAIT_SECONDS = 20

mcp = MCPServer(
    "secret-broker",
    instructions=(
        "Use stored credentials (API keys, logins, SSH servers, databases, cloud keys) without ever seeing "
        "their values. Call list_secrets first to discover what exists and what each credential is for "
        "(read its description: it contains the user's instructions). Reference secret values only through "
        "placeholders such as {{value}}, {{username}} or {{password}}; the broker substitutes them and "
        "redacts them from any output. Never ask the user to paste a secret into the chat. Calls may wait "
        "while the user approves them with Windows Hello in the SecretBroker app."
    ),
)


def _wait(condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if condition(client.request("status", timeout=10)):
                return True
        except (BrokerError, BrokerUnavailable):
            pass
        time.sleep(1)
    return False


def _call(op, params=None):
    """Call the service; if the vault is locked or an approval needs the app, open it and retry once."""
    if not client.ensure_service():
        raise ToolError("El servicio SecretBroker no está en marcha. Pide al usuario que lo revise.")
    for attempt in (1, 2):
        try:
            return client.request(op, params or {})
        except BrokerUnavailable as exc:
            raise ToolError(str(exc)) from None
        except BrokerError as exc:
            if attempt == 2 or exc.code not in ("locked", "gui_required"):
                raise ToolError(str(exc)) from None
            client.launch_app()
            if exc.code == "locked":
                if not _wait(lambda s: s["state"] == "unlocked", UNLOCK_WAIT_SECONDS):
                    raise ToolError("La bóveda sigue bloqueada. Se ha abierto SecretBroker para que el usuario la desbloquee; "
                                    "reintenta cuando lo haya hecho.") from None
            elif not _wait(lambda s: s.get("gui_connected"), APP_START_WAIT_SECONDS):
                raise ToolError("Hace falta la aprobación del usuario, pero la app SecretBroker no se ha abierto.") from None


def _drop_none(**params):
    return {k: v for k, v in params.items() if v is not None}


@mcp.tool()
def list_secrets() -> list[dict]:
    """List the stored credentials with their context: name, kind, description (user instructions),
    host, username, allowed web hosts, allowed commands, available placeholders and actions.
    Secret values are never included."""
    return _call("list_secrets")


@mcp.tool()
def http_request(
    secret_id: str,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    json_body: Any = None,
    inject_auth: bool = True,
    timeout: int = 60,
) -> dict:
    """Make an HTTPS request using a stored credential. Only the credential's allowed hosts work.

    If the credential has automatic auth (header, query parameter or HTTP Basic) it is added unless
    inject_auth is false. You can also place placeholders like {{value}}, {{username}} or {{password}}
    anywhere in url, headers, body or json_body (e.g. a login form) and the broker substitutes them.
    Redirects are not followed. The response comes back with any secret redacted."""
    return _call("http_request", _drop_none(
        secret_id=secret_id, url=url, method=method, headers=headers, body=body,
        json_body=json_body, inject_auth=inject_auth, timeout=timeout,
    ))


@mcp.tool()
def ssh_exec(secret_id: str, command: str, sudo: bool = False, timeout: int = 120) -> dict:
    """Run a shell command on the SSH server of a stored credential (host and user come from the vault).
    With sudo=true the command runs through `sudo` and the stored password is fed to it automatically."""
    return _call("ssh_exec", dict(secret_id=secret_id, command=command, sudo=sudo, timeout=timeout))


@mcp.tool()
def ssh_upload(secret_id: str, local_path: str, remote_path: str) -> dict:
    """Upload a local file to the SSH server of a stored credential via SFTP."""
    return _call("ssh_upload", dict(secret_id=secret_id, local_path=local_path, remote_path=remote_path))


@mcp.tool()
def ssh_download(secret_id: str, remote_path: str, local_path: str, overwrite: bool = False) -> dict:
    """Download a file from the SSH server of a stored credential via SFTP."""
    return _call("ssh_download", dict(
        secret_id=secret_id, remote_path=remote_path, local_path=local_path, overwrite=overwrite,
    ))


@mcp.tool()
def run_command(secret_id: str, argv: list[str], cwd: str | None = None, timeout: int = 300) -> dict:
    """Run a local CLI (e.g. gh, aws, psql) with the credential injected as environment variables.
    argv[0] must be one of the credential's allowed commands (a bare name, resolved on PATH).
    No shell is used. Output is returned with any secret redacted."""
    return _call("run_command", _drop_none(secret_id=secret_id, argv=argv, cwd=cwd, timeout=timeout))


def main():
    mcp.run()


if __name__ == "__main__":
    main()
