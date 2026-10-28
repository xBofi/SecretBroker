"""End-to-end checks of the service, proofs, approvals, actions and the MCP server (no GUI).

Windows Hello is simulated with a software RSA key: the service-side verification is the real one.
Run with:  .venv\\Scripts\\python.exe tests\\test_e2e.py
"""

import asyncio
import base64
import json
import os
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

from secretbroker import client, crypto  # noqa: E402
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
            check(tools == ["http_request", "list_secrets", "run_command", "ssh_download", "ssh_exec", "ssh_upload"], f"MCP tools: {tools}")
            result = await session.call_tool("list_secrets", {})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("echo-api" in text and API_KEY not in text, "MCP list_secrets works through the service")
            result = await session.call_tool("http_request", {"secret_id": "echo-api", "url": "https://evil.example.com/"})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("no permitido" in text, "MCP surfaces service errors to the agent")


if __name__ == "__main__":
    main()
