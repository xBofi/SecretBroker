"""End-to-end checks of the service, proofs, approvals, actions and the MCP server (no GUI).

Windows Hello is simulated with a software RSA key: the service-side verification is the real one.
Run with:  .venv\\Scripts\\python.exe tests\\test_e2e.py
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="secretbroker-test-"))
os.environ["SECRETBROKER_HOME"] = str(HOME)  # must be set before importing secretbroker

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

from nacl.public import PrivateKey, SealedBox  # noqa: E402

from secretbroker import actions, cli, client, crypto, exposure, links, rotation  # noqa: E402
from secretbroker.client import BrokerError, BrokerUnavailable  # noqa: E402
from secretbroker.service import Service  # noqa: E402

MASTER = "correct horse battery staple"
API_KEY = "sk-test-SUPERSECRET-1234567890"
DB_PASSWORD = 'db p@ss "quoted"&'
failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


def expect_error(fn, code, label):
    try:
        fn()
        check(False, f"{label} (no error)")
    except BrokerError as exc:
        check(exc.code == code, f"{label} [{exc.code}] {exc}")


class EchoHandler(BaseHTTPRequestHandler):
    def _echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = {"path": self.path, "headers": dict(self.headers),
                   "body": self.rfile.read(length).decode() if length else ""}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _echo

    def log_message(self, *args):
        pass


class FakeGitHub(BaseHTTPRequestHandler):
    key = PrivateKey.generate()
    received = []

    def _reply(self, status, payload=None):
        data = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.endswith("/actions/secrets/public-key"):
            self._reply(200, {"key_id": "k1", "key": base64.b64encode(bytes(self.key.public_key)).decode()})
        else:
            self._reply(404, {"message": "Not Found"})

    def do_PUT(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.received.append({"path": self.path, "auth": self.headers.get("Authorization"), **body})
        self._reply(201 if len(self.received) == 1 else 204)

    def log_message(self, *args):
        pass


# --- simulated Windows Hello ------------------------------------------------------------
HELLO_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def hello_proof(op, params):
    challenge = client.request("challenge", {"op": op, "params": params})
    signature = HELLO_KEY.sign(base64.b64decode(challenge["message"]), padding.PKCS1v15(), hashes.SHA256())
    return {"kind": "hello", "nonce": challenge["nonce"], "signature": base64.b64encode(signature).decode()}


def call(op, params, proof=None):
    params = dict(params)
    if proof == "hello":
        proof = hello_proof(op, params)
    if proof:
        params["proof"] = proof
    return client.request(op, params)


def write_legacy_vault():
    """A version 1 vault as written by SecretBroker 0.1."""
    kdf = {"name": "scrypt", "n": 2**14, "r": 8, "p": 1, "salt": crypto.b64(os.urandom(16))}
    header = {"version": 1, "kdf": kdf}
    payload = {"entries": {"old-ssh": {"id": "old-ssh", "type": "ssh", "description": "Servidor antiguo",
                                       "fields": {"host": "10.0.0.9", "username": "root", "password": "legacy-pass"},
                                       "policy": {"approval": "session"}}}}
    sealed = crypto.seal(crypto.derive_key(MASTER, kdf), json.dumps(payload).encode(),
                         json.dumps(header, sort_keys=True).encode())
    (HOME / "vault.json").write_text(json.dumps({**header, **sealed}))


def main():
    server = HTTPServer(("127.0.0.1", 0), EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    write_legacy_vault()
    (HOME / "data").mkdir(parents=True, exist_ok=True)
    (HOME / "data" / "audit.log").write_text(json.dumps({"ts": "2026-01-01T00:00:00", "secret": "vault",
                                                         "action": "legacy-event", "detail": "", "status": "ok"}) + "\n")
    service = Service(HOME, owner=f"{os.environ.get('USERDOMAIN')}\\{os.environ.get('USERNAME')}", isolated=False)
    service.start()

    print("Vault creation and legacy import")
    status = client.request("status")
    check(status["state"] == "no_vault" and status["legacy_vault"], "detects missing vault and legacy vault")
    expect_error(lambda: client.request("create_vault", {"master_password": "short"}), "invalid", "rejects short master password")
    client.request("create_vault", {"master_password": MASTER, "import_legacy": True})
    entries = client.request("entries")
    check([e["id"] for e in entries] == ["old-ssh"] and entries[0]["template"] == "ssh", "legacy entry imported as SSH template")
    check("password" not in entries[0]["fields"] and entries[0]["secrets_set"] == ["password"], "entries never include secret values")
    raw = (HOME / "data" / "vault.json").read_text()
    check("legacy-pass" not in raw, "vault file on disk has no plaintext")
    check((HOME / "data" / "device_key.bin").exists(), "device (DPAPI) key created")

    print("Proofs")
    entry = {"id": "echo-api", "name": "Echo API", "template": "api_key", "description": "API de prueba",
             "fields": {"value": API_KEY, "base_url": base, "auth_style": "bearer", "env_var": "MY_TOKEN"},
             "policy": {"approval": "session",
                        "http": {"allowed_hosts": ["127.0.0.1"], "auth": {"kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}},
                        "commands": {"allowed": ["python"], "env": {"MY_TOKEN": "{{value}}"}}}}
    expect_error(lambda: call("save_entry", {"entry": entry}), "proof_required", "save without proof is refused")
    expect_error(lambda: call("save_entry", {"entry": entry}, {"kind": "master_password", "value": "nope nope nope"}),
                 "proof_invalid", "wrong master password proof refused")
    expect_error(lambda: call("save_entry", {"entry": entry}, {"kind": "windows_password", "value": "definitely-wrong"}),
                 "proof_invalid", "wrong Windows password refused")
    call("save_entry", {"entry": entry}, {"kind": "master_password", "value": MASTER})
    check(any(e["id"] == "echo-api" for e in client.request("entries")), "save with master password proof")

    public_der = HELLO_KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    enroll = {"public_key": base64.b64encode(public_der).decode()}
    expect_error(lambda: call("enroll_hello", enroll), "proof_required", "Hello enrollment needs a password proof")
    call("enroll_hello", enroll, {"kind": "master_password", "value": MASTER})
    check(client.request("status")["hello_enrolled"], "Hello key enrolled")

    db = {"id": "shop-db", "name": "Tienda", "template": "database", "description": "",
          "fields": {"engine": "postgresql", "host": "db.local", "database": "shop", "username": "app", "password": DB_PASSWORD},
          "policy": {"approval": "never", "commands": {"allowed": ["python"], "env": {"DATABASE_URL": "{{connection_url}}", "PGPASSWORD": "{{password}}"}}}}
    call("save_entry", {"entry": db}, "hello")
    check(any(e["id"] == "shop-db" for e in client.request("entries")), "save with Hello signature")

    proof = hello_proof("delete_entry", {"id": "shop-db"})
    expect_error(lambda: call("delete_entry", {"id": "echo-api"}, proof), "proof_invalid", "Hello proof bound to another operation refused")
    proof = hello_proof("reveal", {"id": "echo-api", "field": "value"})
    check(call("reveal", {"id": "echo-api", "field": "value"}, proof) == API_KEY, "reveal with Hello proof")
    expect_error(lambda: call("reveal", {"id": "echo-api", "field": "value"}, proof), "proof_invalid", "Hello proof cannot be replayed")
    forged = dict(hello_proof("reveal", {"id": "echo-api", "field": "value"}), signature=base64.b64encode(b"x" * 256).decode())
    expect_error(lambda: call("reveal", {"id": "echo-api", "field": "value"}, forged), "proof_invalid", "forged signature refused")

    updated = json.loads(json.dumps(entry))
    updated["fields"]["value"] = None
    updated["description"] = "API de prueba (editada)"
    call("save_entry", {"entry": updated, "replaces": "echo-api"}, "hello")
    check(call("reveal", {"id": "echo-api", "field": "value"}, "hello") == API_KEY, "editing with secret = null keeps stored secret")

    print("Lock / unlock")
    client.request("lock")
    expect_error(lambda: client.request("entries"), "locked", "locked vault refuses requests")
    expect_error(lambda: call("unlock", {}, {"kind": "master_password", "value": "wrong wrong wrong"}), "proof_invalid", "wrong master password")
    call("unlock", {}, "hello")
    check(client.request("status")["state"] == "unlocked", "unlock with Windows Hello (device key)")

    print("Recovery: reset master password with Windows Hello")
    call("change_master_password", {"new_password": "a brand new master pass"}, "hello")
    client.request("lock")
    call("unlock", {}, {"kind": "master_password", "value": "a brand new master pass"})
    check(client.request("status")["state"] == "unlocked", "unlock with the new master password")

    print("Agent: list and approvals")
    listing = client.request("list_secrets")
    dumped = json.dumps(listing)
    check(API_KEY not in dumped and "legacy-pass" not in dumped and DB_PASSWORD not in dumped, "list_secrets has no secret values")
    echo_view = next(v for v in listing if v["id"] == "echo-api")
    check("http_request" in echo_view["actions"] and "{{value}}" in echo_view["placeholders"], "agent view lists actions and placeholders")

    expect_error(lambda: client.request("http_request", {"secret_id": "echo-api", "url": base + "/x"}), "gui_required",
                 "approval needed while app closed -> gui_required")

    decisions = []

    def fake_gui(decision):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pending = client.request("pending_approvals")
            if pending:
                request = pending[0]
                if decision == "deny":
                    client.request("deny", {"id": request["id"]})
                else:
                    call("approve", {"id": request["id"], "scope": decision}, "hello")
                decisions.append((request["action"], request["detail"]))
                return
            time.sleep(0.1)

    client.request("pending_approvals")  # the app announces itself
    gui = threading.Thread(target=fake_gui, args=("deny",))
    gui.start()
    expect_error(lambda: client.request("http_request", {"secret_id": "echo-api", "url": base + "/denied"}), "denied", "user denies")
    gui.join()

    gui = threading.Thread(target=fake_gui, args=("session",))
    gui.start()
    result = client.request("http_request", {"secret_id": "echo-api", "url": base + "/v1/items"})
    gui.join()
    echoed = json.loads(result["body"])
    check(result["status"] == 200 and echoed["headers"]["Authorization"] == "Bearer [REDACTED:echo-api]",
          "approved request carries injected key, redacted in response")
    check(decisions[-1][1].startswith("GET " + base), "approval shows the exact request")
    client.request("pending_approvals")
    result = client.request("http_request", {"secret_id": "echo-api", "url": base + "/again"})
    check(result["status"] == 200, "session grant: no second approval")

    print("Agent: commands")
    script = "import os;print(os.environ['DATABASE_URL']);print(os.environ['PGPASSWORD'])"
    result = client.request("run_command", {"secret_id": "shop-db", "argv": ["python", "-c", script]})
    check(result["exit_code"] == 0 and DB_PASSWORD not in result["stdout"] and result["stdout"].count("[REDACTED:shop-db]") == 2,
          f"database URL and password redacted: {result['stdout'].strip()!r}")
    expect_error(lambda: client.request("ssh_exec", {"secret_id": "echo-api", "command": "id"}), "action_failed", "SSH refused for non-SSH credential")

    print("Local programs: sb run")
    check(cli.parse_config("# app\nDATABASE_URL = shop-db\nPW=shop-db:password  # comment\naws-prod\n") == [
        {"secret_id": "shop-db", "name": "DATABASE_URL"}, {"secret_id": "shop-db", "name": "PW", "field": "password"},
        {"secret_id": "aws-prod"}], "parses .secretbroker lines")
    try:
        cli.parse_config("OPENAI_API_KEY = sk-123 456")
        check(False, "rejects a line that is not a credential reference")
    except cli.ConfigError:
        check(True, "rejects a line that is not a credential reference")
    released = client.request("release_env", {"vars": [{"secret_id": "shop-db"}], "command": "x", "cwd": "."})
    check(set(released["env"]) == {"DATABASE_URL", "PGPASSWORD"} and released["env"]["PGPASSWORD"] == DB_PASSWORD,
          "a bare credential releases all its variables")
    expect_error(lambda: client.request("release_env", {"vars": [{"secret_id": "old-ssh"}]}), "invalid",
                 "credentials without environment variables are never released")
    expect_error(lambda: client.request("release_env", {"vars": [{"secret_id": "shop-db", "name": "A B"}]}), "invalid",
                 "invalid variable names refused")

    project = HOME / "project" / "sub"
    project.mkdir(parents=True)
    (HOME / "project" / ".secretbroker").write_text("DATABASE_URL = shop-db\nPW = shop-db:password\n")
    script = "import os;print(os.environ['PW']);print(os.environ['DATABASE_URL']);print(os.environ['PW'] == os.environ['EXPECTED'])"
    completed = subprocess.run([sys.executable, "-m", "secretbroker.cli", "run", "--", "python", "-c", script],
                               cwd=project, capture_output=True, text=True, env={**os.environ, "EXPECTED": DB_PASSWORD})
    lines = completed.stdout.splitlines()
    check(completed.returncode == 0 and lines[2] == "True", f"the program receives the real values ({completed.stderr.strip()})")
    check(DB_PASSWORD not in completed.stdout and lines[0] == "[REDACTED:shop-db]" and "[REDACTED:shop-db]" in lines[1],
          f"piped output is redacted: {lines[:2]}")
    completed = subprocess.run([sys.executable, "-m", "secretbroker.cli", "run", "--", "python", "-c", "raise SystemExit(7)"],
                               cwd=project, capture_output=True, text=True)
    check(completed.returncode == 7, "sb run returns the program's exit code")
    check(any(e["action"] == "release_env" and "python -c" in e["detail"] for e in client.request("audit", {"limit": 20})),
          "releases are audited with the command")

    print("GitHub secrets")
    github = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=github.serve_forever, daemon=True).start()
    actions.GITHUB_API = f"http://127.0.0.1:{github.server_address[1]}"
    token = {"id": "gh-token", "name": "GitHub", "template": "api_key", "description": "",
             "fields": {"value": "ghp_FAKE_TOKEN_1234567890", "base_url": actions.GITHUB_API, "auth_style": "bearer"},
             "policy": {"approval": "never", "http": {"allowed_hosts": ["127.0.0.1"], "auth": {
                 "kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}}}}
    call("save_entry", {"entry": token}, "hello")
    push = {"secret_id": "shop-db", "github_secret_id": "gh-token", "repo": "me/app", "name": "DB_PASSWORD", "value": "{{password}}"}
    result = client.request("push_github_secret", push)
    sent = FakeGitHub.received[-1]
    check(result["status"] == "created" and DB_PASSWORD not in json.dumps(result), "push returns no value")
    check(sent["path"] == "/repos/me/app/actions/secrets/DB_PASSWORD" and sent["key_id"] == "k1"
          and sent["auth"] == "Bearer ghp_FAKE_TOKEN_1234567890", "uploads with the repository key and the stored token")
    check(SealedBox(FakeGitHub.key).decrypt(base64.b64decode(sent["encrypted_value"])).decode() == DB_PASSWORD,
          "GitHub receives the value encrypted for the repository")
    result = client.request("push_github_secret", dict(push, environment="prod"))
    check(result["status"] == "updated" and FakeGitHub.received[-1]["path"] == "/repos/me/app/environments/prod/actions/secrets/DB_PASSWORD",
          "environment secrets")
    expect_error(lambda: client.request("push_github_secret", dict(push, name="GITHUB_TOKEN")), "action_failed", "reserved names refused")
    expect_error(lambda: client.request("push_github_secret", dict(push, repo="../x")), "action_failed", "malformed repo refused")
    expect_error(lambda: client.request("push_github_secret", dict(push, github_secret_id="old-ssh")), "action_failed",
                 "token credential must allow the GitHub API host")

    print("Rotation")
    rotated = []
    rotation.ROTATORS["Cloudflare"] = lambda entry: rotated.append(entry["fields"]["value"]) or "cf-NEW-TOKEN-0987654321"
    exposure.check_alive = lambda entry: {"status": "ok", "provider": "Cloudflare"}
    cf = {"id": "cloudflare", "name": "Cloudflare", "template": "api_key", "description": "",
          "fields": {"value": "cf-OLD-TOKEN-1234567890", "base_url": "https://api.cloudflare.com/client/v4", "auth_style": "bearer",
                     "env_var": "CLOUDFLARE_API_TOKEN"},
          "policy": {"approval": "never", "http": {"allowed_hosts": ["api.cloudflare.com"], "auth": {"kind": "none"}},
                     "commands": {"allowed": [], "env": {"CLOUDFLARE_API_TOKEN": "{{value}}"}}}}
    anthropic = {"id": "claude", "name": "Claude", "template": "api_key", "description": "",
                 "fields": {"value": "sk-ant-api03-FAKEFAKEFAKE"}, "policy": {"approval": "never"}}
    call("save_entry", {"entry": cf}, "hello")
    call("save_entry", {"entry": anthropic}, "hello")
    listed = {e["id"]: e for e in client.request("entries")}
    check(listed["cloudflare"]["rotation"] == {"provider": "Cloudflare", "supported": True, "reason": ""}, "Cloudflare keys are rotatable")
    check(listed["claude"]["rotation"]["provider"] == "Anthropic" and not listed["claude"]["rotation"]["supported"]
          and "Console" in listed["claude"]["rotation"]["reason"], "Anthropic keys are not, with the reason")
    check(not listed["echo-api"]["rotation"]["supported"] and listed["shop-db"]["rotation"] is None,
          "unknown providers are not rotatable; non-API credentials have no rotation")
    check(listed["shop-db"]["destinations"][0]["repo"] == "me/app", "uploads to GitHub are remembered")
    expect_error(lambda: call("rotate", {"id": "claude"}, "hello"), "invalid", "rotating an unsupported provider is refused")
    expect_error(lambda: client.request("rotate", {"id": "cloudflare"}), "proof_required", "rotation needs a proof")

    client.request("push_github_secret", {"secret_id": "cloudflare", "github_secret_id": "gh-token", "repo": "me/app", "name": "CF_TOKEN"})
    uploads_before = len(FakeGitHub.received)
    result = call("rotate", {"id": "cloudflare"}, "hello")
    check(rotated == ["cf-OLD-TOKEN-1234567890"], "the provider is asked with the old key")
    check(call("reveal", {"id": "cloudflare", "field": "value"}, "hello") == "cf-NEW-TOKEN-0987654321", "the new key is stored")
    check("cf-NEW-TOKEN" not in json.dumps(result), "rotation returns no value")
    check(len(FakeGitHub.received) == uploads_before + 1 and result["uploads"][0]["ok"]
          and SealedBox(FakeGitHub.key).decrypt(base64.b64decode(FakeGitHub.received[-1]["encrypted_value"])).decode() == "cf-NEW-TOKEN-0987654321",
          "the new key is uploaded again to GitHub")

    print("Provider links")
    gateway = {"id": "aig", "name": "Gateway", "template": "api_key", "description": "",
               "fields": {"value": "cfat_" + "A" * 40, "auth_style": "bearer",
                          "base_url": "https://gateway.ai.cloudflare.com/v1/" + "0123456789abcdef" * 2 + "/team-gw/openai"},
               "policy": {"approval": "never"}}
    call("save_entry", {"entry": gateway}, "hello")
    listed = {e["id"]: e for e in client.request("entries")}
    aig = listed["aig"]["provider"]
    check(aig["provider"] == "Cloudflare" and "«team-gw»" in aig["kind"]["label"] and "todos los gateways" in aig["kind"]["help"],
          "AI Gateway tokens are identified, with their gateway and reach")
    check(aig["links"][0]["url"] == "https://dash.cloudflare.com/" + "0123456789abcdef" * 2 + "/ai/ai-gateway",
          "the first link opens AI Gateway in that account")
    check(not listed["aig"]["rotation"]["supported"] and "cuenta" in listed["aig"]["rotation"]["reason"],
          "account tokens are not rotatable yet")
    check(listed["cloudflare"]["provider"]["links"][0]["url"] == "https://dash.cloudflare.com/profile/api-tokens/"
          and listed["cloudflare"]["provider"]["links"][-1]["label"] == "Facturación", "Cloudflare API tokens link to their page and billing")
    check(listed["claude"]["provider"]["links"][0]["url"] == "https://platform.claude.com/settings/keys", "Anthropic keys page")
    check(listed["echo-api"]["provider"] is None and listed["shop-db"]["provider"] is None, "no links for unknown providers")
    check(all(link["url"].startswith("https://") for e in listed.values() if e["provider"] for link in e["provider"]["links"]),
          "every link is HTTPS")
    catalog = {p["provider"]: p for p in links.catalog()}
    check(catalog["Cloudflare AI Gateway"]["links"][0]["label"] == "AI Gateway" and "OpenAI" in catalog
          and all(link["url"].startswith("https://") for p in catalog.values() for link in p["links"]),
          "the new-key form lists every provider, AI Gateway first for gateways")
    github.shutdown()

    print("Service authenticity")
    info_file = HOME / "public" / "broker.json"
    original = info_file.read_text()
    info = json.loads(original)
    info["public_key"] = crypto.b64(os.urandom(32))
    info_file.write_text(json.dumps(info))
    try:
        client.request("status")
        check(False, "client rejects responses not signed by the service")
    except BrokerUnavailable:
        check(True, "client rejects responses not signed by the service")
    info_file.write_text(original)

    print("MCP over stdio")
    asyncio.run(check_stdio())

    print("Audit")
    events = client.request("audit", {"limit": 50})
    check(any(e["action"] == "http_request" and e["status"] == "denied" for e in events), "audit log records denials")
    check(API_KEY not in json.dumps(events), "audit log has no secrets")
    check(any(e["action"] == "legacy-event" for e in events), "events written in clear by 0.3 are kept")
    raw = (HOME / "data" / "audit.log").read_text()
    check(all(word not in raw for word in ("legacy-event", "http_request", "/denied", "echo-api")), "audit log on disk is encrypted")
    client.request("lock")
    expect_error(lambda: call("unlock", {}, {"kind": "master_password", "value": "wrong wrong wrong"}), "proof_invalid", "failed unlock while locked")
    expect_error(lambda: client.request("audit"), "locked", "audit log unreadable while locked")
    call("unlock", {}, "hello")
    events = client.request("audit", {"limit": 3})
    check([e["action"] for e in events][:2] == ["unlock", "unlock"] and events[1]["status"] == "error",
          "events written while locked are readable after unlocking")

    service.stop()
    server.shutdown()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (home: {HOME})")
    sys.exit(1 if failures else 0)


async def check_stdio():
    from mcp import ClientSession, StdioServerParameters, stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "secretbroker.mcp_server"], env={**os.environ})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = sorted(t.name for t in (await session.list_tools()).tools)
            check(tools == ["http_request", "list_secrets", "push_github_secret", "run_command", "ssh_download", "ssh_exec", "ssh_upload"], f"MCP tools: {tools}")
            result = await session.call_tool("list_secrets", {})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("echo-api" in text and API_KEY not in text, "MCP list_secrets works through the service")
            result = await session.call_tool("http_request", {"secret_id": "echo-api", "url": "https://evil.example.com/"})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("no permitido" in text, "MCP surfaces service errors to the agent")


if __name__ == "__main__":
    main()
