"""MCP server for AI agents: a thin client of the SecretBroker service. It never holds secrets."""

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import client
from .client import BrokerError, BrokerUnavailable

mcp = MCPServer(
    "secret-broker",
    instructions=(
        "Use stored credentials (API keys, logins, SSH servers, databases, cloud keys) without ever seeing "
        "their values. Call list_secrets first to discover what exists and what each credential is for "
        "(read its description: it contains the user's instructions). Reference secret values only through "
        "placeholders such as {{value}}, {{username}} or {{password}}; the broker substitutes them and "
        "redacts them from any output. Never ask the user to paste a secret into the chat. Calls may wait "
        "while the user approves them in the SecretBroker app; at the start of a task that needs several "
        "credentials, call request_access once. To set up a project's local secrets: write a .secretbroker "
        "file (VARIABLE = credential-id lines, no values; it can be committed), prepare missing credentials "
        "with create_credential, move keys out of a .env with the shell command `sb import .env --delete` "
        "(it never prints values; the user confirms in the app), check with `sb check`, run the app with "
        "`sb run -- <command>`, and store production secrets with push_github_secret. When you prepare a "
        "credential for a provider that is not a known preset, look up in its official documentation how "
        "its keys are rotated and pass rotation_guide, so the app can guide the user when it is time. If a "
        "secret goes with an identifier (OAuth client id, app id, account id, key id), store that id in "
        "fields.username; when create_credential or check_credential returns a question about it and you "
        "don't know the answer, ask the user."
    ),
)


# Replaced by the desktop app when it serves the tools itself: it shows its own window instead.
open_app = client.launch_app


def _call(op, params=None):
    try:
        return client.call(op, params, open_app=open_app)
    except (BrokerError, BrokerUnavailable) as exc:
        raise ToolError(str(exc)) from None


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


@mcp.tool()
def request_access(secret_ids: list[str], reason: str) -> dict:
    """At the start of a task, ask once for every credential it will need (by id, from list_secrets),
    explaining the task in `reason`. The user approves them all with one click instead of one prompt
    per credential. Credentials set to ask every time still ask on each use."""
    return _call("request_access", dict(secret_ids=secret_ids, reason=reason))


@mcp.tool()
def create_credential(
    name: str,
    description: str,
    template: str | None = None,
    provider: str | None = None,
    fields: dict[str, str] | None = None,
    id: str | None = None,
    allowed_hosts: list[str] | None = None,
    env_vars: dict[str, str] | None = None,
    commands: list[str] | None = None,
    tags: list[str] | None = None,
    expires: str | None = None,
    rotate_every_days: int | None = None,
    rotation_guide: dict[str, Any] | None = None,
    check_every_hours: int | None = None,
) -> dict:
    """Prepare a new credential with everything except its secret; the user then only pastes the
    key in the SecretBroker app (it can't be used until then). Never ask for the secret in the chat.

    provider fills in a known API's URL, auth and environment variable (template api_key): openai,
    anthropic, openrouter, github, gitlab, stripe, groq, huggingface, mistral, cloudflare, assemblyai,
    elevenlabs, deepgram. Otherwise give a template and its non-secret fields:
      api_key   base_url (API URL; its host becomes the only allowed host), auth_style
                (bearer | x_api_key | query | none), env_var (e.g. OPENAI_API_KEY)
      web_login url, username
      ssh       host, port, username, auth_method (password | key)
      database  engine (postgresql | mysql | sqlserver | mongodb | redis | other), host, port, database, username
      aws       access_key_id, region
      generic   username, url
    api_key and generic: if the secret goes with an identifier (an OAuth client id, app id, account id,
    key id), put it in username, so rotating it asks whether that id changed too.
    description: what it is, which project uses it and how to use it (you'll read it later).
    Permissions are derived from the fields; override them with allowed_hosts, env_vars
    ({"OPENAI_API_KEY": "{{value}}"}, used by `sb run` and run_command) and commands (CLIs allowed in
    run_command). tags group credentials (e.g. the project name); expires is YYYY-MM-DD if the key
    has an expiry date. The id defaults to a slug of the name.
    rotation_guide is for providers without a preset: how the user replaces the key by hand, found in
    the provider's official documentation (search the web; never guess URLs). {"create": ["step", ...]
    (where to click to create the new key), "revoke": "how to delete the old one", "links": [{"label",
    "url"}] (the exact https pages), "sources": ["https://..."] (the docs you read), optional "warning":
    "what not to do" (e.g. deleting the app changes its client id)}. The app shows it
    as written by the AI. rotate_every_days (30, 60, 90, 180, 365, or 0 for never) sets how often the
    app reminds the user to rotate this key; check_every_hours how often it tests that the key still
    works (hours; -1 once per key, 0 never; leave it unset to follow the user's general setting)."""
    return _call("create_draft", _drop_none(
        template=template, provider=provider, name=name, description=description, fields=fields, id=id,
        allowed_hosts=allowed_hosts, env_vars=env_vars, commands=commands, tags=tags, expires=expires,
        rotate_every_days=rotate_every_days, rotation_guide=rotation_guide, check_every_hours=check_every_hours,
    ))


@mcp.tool()
def update_credential(
    secret_id: str,
    name: str | None = None,
    description: str | None = None,
    fields: dict[str, str] | None = None,
    allowed_hosts: list[str] | None = None,
    env_vars: dict[str, str] | None = None,
    commands: list[str] | None = None,
    tags: list[str] | None = None,
    expires: str | None = None,
    rotate_every_days: int | None = None,
    rotation_guide: dict[str, Any] | None = None,
    check_every_hours: int | None = None,
) -> dict:
    """Change a credential's name, notes, tags, expiry date (YYYY-MM-DD), non-secret fields or permissions (only what you pass;
    an empty string clears a field). Name and description change at once. Changes that affect where
    its secret can go (fields, allowed_hosts, env_vars, commands) wait for the user's OK in the app
    when the credential already has its secret. Secret values and the approval mode can't be changed.
    rotation_guide is for providers without a preset: how the user replaces the key by hand, found in
    the provider's official documentation (search the web; never guess URLs). {"create": ["step", ...]
    (where to click to create the new key), "revoke": "how to delete the old one", "links": [{"label",
    "url"}] (the exact https pages), "sources": ["https://..."] (the docs you read), optional "warning":
    "what not to do" (e.g. deleting the app changes its client id)}. The app shows it
    as written by the AI. rotate_every_days (30, 60, 90, 180, 365, or 0 for never) sets how often the
    app reminds the user to rotate this key; check_every_hours how often it tests that the key still
    works (hours; -1 once per key, 0 never; leave it unset to follow the user's general setting).
    An empty rotation_guide ({}) removes it."""
    return _call("update_credential", _drop_none(
        secret_id=secret_id, name=name, description=description, fields=fields,
        allowed_hosts=allowed_hosts, env_vars=env_vars, commands=commands, tags=tags, expires=expires,
        rotate_every_days=rotate_every_days, rotation_guide=rotation_guide, check_every_hours=check_every_hours,
    ))


@mcp.tool()
def check_credential(secret_id: str) -> dict:
    """Test whether a credential still works (a harmless read-only call to its provider, or an SSH
    login), and see its key's age, expiry date, whether it can be rotated by API and which rotation
    guide the app has for it (builtin, ai or generic: generic means you could research one and store it
    with update_credential's rotation_guide)."""
    return _call("ai_check", dict(secret_id=secret_id))


@mcp.tool()
def rotate_credential(secret_id: str, reason: str) -> dict:
    """Replace an API key with a new one issued by its provider (only providers that allow it, see
    check_credential; for the rest, tell the user to use «Rotar con ayuda» in the app). The old key stops working at once; GitHub secrets it was pushed to are updated.
    The user usually confirms it in the app. You never see the new key."""
    return _call("ai_rotate", dict(secret_id=secret_id, reason=reason))


@mcp.tool()
def credential_activity(secret_id: str | None = None, limit: int = 50) -> list[dict]:
    """Recent activity (uses, approvals, denials, errors, edits), newest first, optionally of one
    credential. No secret values."""
    return _call("ai_activity", _drop_none(secret_id=secret_id, limit=limit))


@mcp.tool()
def delete_credential(secret_id: str, reason: str) -> dict:
    """Propose deleting a credential that is no longer needed. The user always confirms it in the app."""
    return _call("ai_delete", dict(secret_id=secret_id, reason=reason))


@mcp.tool()
def push_github_secret(
    secret_id: str,
    github_secret_id: str,
    repo: str,
    name: str,
    value: str = "{{value}}",
    environment: str | None = None,
) -> dict:
    """Store a credential as a GitHub Actions secret (repository secret, or environment secret if
    `environment` is given) without seeing it. The broker reads the value from the vault, encrypts it
    with the repository's public key and uploads it using the GitHub token stored as `github_secret_id`.

    `value` is a placeholder template for what to store, e.g. "{{value}}" for an API key or
    "{{connection_url}}" for a database. Creating or updating works the same way, so use it again
    after the user rotates a key."""
    return _call("push_github_secret", _drop_none(
        secret_id=secret_id, github_secret_id=github_secret_id, repo=repo, name=name,
        value=value, environment=environment,
    ))


def main():
    mcp.run()


if __name__ == "__main__":
    main()
