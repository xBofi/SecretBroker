"""End-to-end checks of the service, proofs, approvals, actions and the MCP server (no GUI).

Windows Hello is simulated with a software RSA key: the service-side verification is the real one.
Run with:  .venv\\Scripts\\python.exe tests\\test_e2e.py
"""

import asyncio
import base64
import json
import socket
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from nacl.public import PrivateKey, SealedBox  # noqa: E402

from secretbroker import actions, cli, client, crypto, exposure, links, rotation, update  # noqa: E402
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
    fresh_presence = []  # approving with Hello hands the app a new one-click token

    def fake_gui(decision):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pending = client.request("pending_approvals")
            if pending:
                request = pending[0]
                if decision == "deny":
                    client.request("deny", {"id": request["id"]})
                else:
                    answer = call("approve", {"id": request["id"], "scope": decision}, "hello")
                    if isinstance(answer, dict) and answer.get("presence"):
                        fresh_presence.append(answer["presence"])
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

    print("Agent: approvals without retyping the password")
    service._lock_vault()  # what the inactivity timer does
    unlocked = call("unlock", {}, "hello")
    presence = unlocked.get("presence")
    check(bool(presence), "unlocking hands the app a token to approve requests")
    client.request("pending_approvals")
    result = client.request("http_request", {"secret_id": "echo-api", "url": base + "/after-auto-lock"})
    check(result["status"] == 200, "approvals survive the automatic lock")
    client.request("lock")
    call("unlock", {}, "hello")
    expect_error(lambda: call("approve", {"id": "x", "scope": "once"}, {"kind": "presence", "token": presence}),
                 "proof_invalid", "a token from before a lock is refused")
    presence = client.request("lock") and call("unlock", {}, "hello")["presence"]
    expect_error(lambda: call("reveal", {"id": "echo-api", "field": "value"}, {"kind": "presence", "token": presence}),
                 "proof_required", "the token only approves, it cannot reveal")

    def click_approve():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pending = client.request("pending_approvals")
            if pending:
                call("approve", {"id": pending[0]["id"], "scope": "session"}, {"kind": "presence", "token": presence})
                return
            time.sleep(0.1)

    gui = threading.Thread(target=click_approve)
    gui.start()
    result = client.request("http_request", {"secret_id": "echo-api", "url": base + "/one-click"})
    gui.join()
    check(result["status"] == 200, "approving with the token: one click, no password")
    check(client.request("run_command", {"secret_id": "echo-api", "argv": ["python", "-c", "print(1)"]})["exit_code"] == 0,
          "one approval covers every use of that credential")
    client.request("pending_approvals")

    print("The AI's access: approvals, withdrawing them, pausing")
    grants = client.request("grants")
    check(any(g["secret_id"] == "echo-api" and g["kind"] == "approved" and g["until"] for g in grants),
          "running approvals are listed with their expiry")
    saved_grants = dict(service._grants)
    client.request("revoke_sessions", {"secret_id": "echo-api"})
    check(not any(g["secret_id"] == "echo-api" for g in client.request("grants")), "one approval can be withdrawn")
    service._grants.update(saved_grants)
    client.request("pause_ai")
    check(client.request("status")["ai_paused"], "the AI can be paused")
    expect_error(lambda: client.request("list_secrets"), "paused", "a paused AI can't even list the credentials")
    expect_error(lambda: client.request("http_request", {"secret_id": "echo-api", "url": base + "/x"}), "paused",
                 "a paused AI can't use an approved credential")
    expect_error(lambda: client.request("create_draft", {"template": "api_key", "name": "Paused"}), "paused",
                 "a paused AI can't create credentials")
    check(len(client.request("entries")) > 0, "the user keeps using the vault")
    expect_error(lambda: call("resume_ai", {}), "proof_required", "resuming needs the user")
    call("resume_ai", {}, {"kind": "presence", "token": presence})
    check(not client.request("status")["ai_paused"], "the app resumes the AI with one click")

    print("Open with the Windows session")
    expect_error(lambda: call("enable_session_unlock", {}), "proof_required", "turning it on needs the user")
    token = call("enable_session_unlock", {}, "hello")["token"]
    check(client.request("status")["session_unlock"], "session unlock turned on")
    client.request("lock", {"reason": "windows"})
    check(client.request("status")["state"] == "locked", "locking Windows locks the vault")
    expect_error(lambda: call("unlock", {}, {"kind": "session", "token": "not the token"}), "proof_invalid",
                 "a wrong session token is refused")
    unlocked = call("unlock", {}, {"kind": "session", "token": token})
    check(unlocked["state"] == "unlocked" and unlocked.get("presence"), "the Windows session opens the vault, no password")
    presence = unlocked["presence"]
    check(any(g["secret_id"] == "echo-api" for g in client.request("grants")), "approvals survive locking Windows")
    client.request("disable_session_unlock")
    client.request("lock")
    expect_error(lambda: call("unlock", {}, {"kind": "session", "token": token}), "proof_invalid",
                 "once turned off the token is useless")
    presence = call("unlock", {}, "hello")["presence"]
    client.request("pending_approvals")

    print("What the AI may do")
    perms = {c["id"]: c["level"] for c in client.request("ai_permissions")["capabilities"]}
    check(perms["create"] == "free" and perms["edit_config"] == "ask", "sensible defaults")
    client.request("set_ai_permissions", {"permissions": {"edit_notes": "off"}})
    check({c["id"]: c["level"] for c in client.request("ai_permissions")["capabilities"]}["edit_notes"] == "off",
          "making the AI stricter needs no password")
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "description": "x"}), "forbidden",
                 "a forbidden capability is refused")
    expect_error(lambda: client.request("set_ai_permissions", {"permissions": {"edit_notes": "notify"}}), "proof_required",
                 "loosening it needs the user")
    call("set_ai_permissions", {"permissions": {"edit_notes": "notify"}}, {"kind": "presence", "token": presence})
    last = (client.request("notices") or [{"id": 0}])[-1]["id"]
    client.request("update_credential", {"secret_id": "echo-api", "description": "API de prueba (avisada)"})
    notices = client.request("notices", {"after": last})
    check(len(notices) == 1 and "echo-api" not in notices[0]["text"] and "editado" in notices[0]["title"],
          "'notify' tells the user what the AI did")
    client.request("set_ai_permissions", {"permissions": {"create": "ask"}})
    gui = threading.Thread(target=fake_gui, args=("deny",))
    gui.start()
    expect_error(lambda: client.request("create_draft", {"template": "api_key", "name": "Asked"}), "denied",
                 "'ask' waits for the user")
    gui.join()
    call("set_ai_permissions", {"permissions": {"create": "free", "edit_notes": "free"}}, {"kind": "presence", "token": presence})

    print("One approval for a whole task")
    session_ids = [e["id"] for e in client.request("entries")
                   if e["policy"].get("approval", "session") == "session" and not e.get("draft")][:2]
    saved_grants = dict(service._grants)
    client.request("revoke_sessions")
    gui = threading.Thread(target=fake_gui, args=("session",))
    gui.start()
    granted = client.request("request_access", {"secret_ids": session_ids, "reason": "Desplegar el proyecto X"})
    gui.join()
    check(sorted(granted["granted"]) == sorted(session_ids) and decisions[-1][0] == "request_access"
          and "Desplegar el proyecto X" in decisions[-1][1], f"one click grants {len(session_ids)} credentials")
    live = {g["secret_id"] for g in client.request("grants")}
    check(set(session_ids) <= live, "they are all usable without asking again")
    check(client.request("request_access", {"secret_ids": session_ids, "reason": "otra vez"})["granted"] == [],
          "asking again for approved credentials doesn't bother the user")
    client.request("lock")  # approving with Hello above handed out a new one-click token
    presence = call("unlock", {}, "hello")["presence"]
    service._grants.update(saved_grants)
    client.request("pending_approvals")

    print("Agent: credentials prepared and edited by the AI")
    draft = client.request("create_draft", {
        "template": "api_key", "name": "Mailer API", "description": "Envío de correos del proyecto X",
        "fields": {"base_url": base + "/mail", "env_var": "MAILER_KEY"}})
    view = draft["credential"]
    check(view["id"] == "mailer-api" and view["draft"] and view["missing"] == ["value"], "the AI prepares a credential without its key")
    check(view["http"]["allowed_hosts"] == ["127.0.0.1"] and view["approval"] == "session", "permissions derived from its fields")
    listed = {e["id"]: e for e in client.request("entries")}
    check(listed["mailer-api"]["draft"] and client.request("status")["drafts"] == 1, "the app sees it as waiting for its key")
    expect_error(lambda: client.request("http_request", {"secret_id": "mailer-api", "url": base + "/mail"}), "draft",
                 "a credential without its key can't be used")
    expect_error(lambda: client.request("create_draft", {"template": "api_key", "name": "X", "fields": {"value": "sk-123"}}),
                 "invalid", "the AI can't write secret values")
    expect_error(lambda: client.request("create_draft", {"template": "api_key", "name": "Mailer API"}), "invalid",
                 "it can't overwrite an existing credential")
    result = client.request("update_credential", {"secret_id": "mailer-api", "allowed_hosts": ["127.0.0.1", "api.mailer.test"]})
    check(result["credential"]["http"]["allowed_hosts"] == ["127.0.0.1", "api.mailer.test"], "drafts are edited without asking")
    expect_error(lambda: call("complete_draft", {"id": "mailer-api", "fields": {"value": "mk-1"}}), "proof_required",
                 "adding the key needs the app")
    summary = call("complete_draft", {"id": "mailer-api", "fields": {"value": "mk-SECRET-123456"}}, {"kind": "presence", "token": presence})
    check(not summary["draft"] and summary["secrets_set"] == ["value"], "the user pastes the key with one click")
    check(call("reveal", {"id": "mailer-api", "field": "value"}, "hello") == "mk-SECRET-123456", "the key is stored")

    result = client.request("update_credential", {"secret_id": "echo-api", "description": "API de prueba, revisada por la IA"})
    check(result["changed"] and next(e for e in client.request("entries") if e["id"] == "echo-api")["description"].endswith("por la IA"),
          "notes change at once")
    decisions.clear()
    gui = threading.Thread(target=fake_gui, args=("deny",))
    gui.start()
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "allowed_hosts": ["evil.example.com"]}),
                 "denied", "widening where a stored key may go needs the user's OK")
    gui.join()
    check(decisions and decisions[-1][0] == "edit" and "evil.example.com" in decisions[-1][1], "the request shows the change")
    check(next(e for e in client.request("entries") if e["id"] == "echo-api")["policy"]["http"]["allowed_hosts"] == ["127.0.0.1"],
          "a denied change is not applied")
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "fields": {"value": "x"}}), "invalid",
                 "secret values can't be edited by the AI")
    client.request("pending_approvals")

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

    print("Projects: sb check and sb import")
    (HOME / "project" / ".secretbroker").write_text("DATABASE_URL = shop-db\nX = nothing-here\nY = old-ssh\n")
    completed = subprocess.run([sys.executable, "-m", "secretbroker.cli", "check"], cwd=project, capture_output=True, text=True)
    out = completed.stdout
    check(completed.returncode == 1 and "OK  DATABASE_URL = shop-db" in out and "no existe" in out and "variables de entorno" in out,
          f"sb check says what is missing: {out.strip()!r}")
    app_dir = HOME / "shop-app"
    app_dir.mkdir()
    env_file = app_dir / ".env"
    env_file.write_text("# keys\nexport OPENAI_API_KEY=\"sk-proj-IMPORTED-1234567890\"\nPORT=3000\n"
                        "STRIPE_SECRET_KEY=sk_test_IMPORTED_abcdef\nPAYMENTS_SECRET='whsec-IMPORTED-zzz'\nPAYMENTS_ID=pay_app_42\n")
    gui = threading.Thread(target=fake_gui, args=("once",))
    gui.start()
    completed = subprocess.run([sys.executable, "-m", "secretbroker.cli", "import", "--delete"], cwd=app_dir,
                               capture_output=True, text=True)
    gui.join()
    out = completed.stdout + completed.stderr
    check(completed.returncode == 0 and "IMPORTED" not in out, f"sb import never prints values ({out.strip()[:200]!r})")
    check(decisions[-1][0] == "import_env" and "OPENAI_API_KEY" in decisions[-1][1] and "IMPORTED" not in decisions[-1][1],
          "the user confirms the list of names")
    openai_entry = next(e for e in client.request("entries") if e["id"] == "shop-app-openai-api-key")
    check(openai_entry["fields"]["base_url"] == "https://api.openai.com/v1" and openai_entry["policy"]["commands"]["env"] == {"OPENAI_API_KEY": "{{value}}"},
          "known keys get their provider's settings")
    check(call("reveal", {"id": "shop-app-payments-secret", "field": "value"}, "hello") == "whsec-IMPORTED-zzz",
          "values are stored as they were (quotes removed)")
    check(env_file.read_text().strip().splitlines() == ["# keys", "PORT=3000", "PAYMENTS_ID=pay_app_42"], "--delete leaves only what isn't a key")
    payments = next(e for e in client.request("entries") if e["id"] == "shop-app-payments-secret")
    check(payments["fields"].get("username") == "pay_app_42" and "con PAYMENTS_ID" in decisions[-1][1]
          and "con su ID, PAYMENTS_ID" in out, "a secret's id from the same .env is stored with it")
    config = (app_dir / ".secretbroker").read_text()
    check("OPENAI_API_KEY = shop-app-openai-api-key" in config and "STRIPE_SECRET_KEY = shop-app-stripe-secret-key" in config,
          ".secretbroker is written for sb run")
    completed = subprocess.run([sys.executable, "-m", "secretbroker.cli", "check"], cwd=app_dir, capture_output=True, text=True)
    check(completed.returncode == 0, f"and sb check is happy: {completed.stdout.strip()!r}")

    print("Provider presets")
    view = client.request("create_draft", {"provider": "anthropic", "description": "Para el bot"})["credential"]
    check(view["id"] == "anthropic" and view["http"]["allowed_hosts"] == ["api.anthropic.com"]
          and "anthropic-version" in view["description"], "provider=anthropic fills URL, host and how to call it")
    expect_error(lambda: client.request("create_draft", {"provider": "nope", "name": "x"}), "invalid", "unknown providers are refused")

    print("Backups")
    presence = fresh_presence[-1]
    backup = call("backup", {}, {"kind": "presence", "token": presence})
    expect_error(lambda: client.request("backup"), "proof_required", "only the app gets a backup")
    client.request("create_draft", {"template": "generic", "name": "After the backup"})
    expect_error(lambda: call("restore", {"vault": backup["vault"], "master_password": "wrong wrong wrong"},
                              {"kind": "presence", "token": presence}), "wrong_password", "a wrong master password is refused")
    restored = call("restore", {"vault": backup["vault"], "master_password": "a brand new master pass"},
                    {"kind": "presence", "token": presence})
    ids = {e["id"] for e in client.request("entries")}
    check(restored["state"] == "unlocked" and "after-the-backup" not in ids and "shop-app-openai-api-key" in ids,
          "restoring brings the vault back to the copy")
    check(any(f.name.startswith("vault.before-restore-") for f in (HOME / "data").iterdir()), "the replaced vault is kept aside")
    presence = restored["presence"]
    client.request("pending_approvals")

    print("More for the AI: check, rotate, activity, delete")
    checked = client.request("ai_check", {"secret_id": "echo-api"})
    check(checked["check"]["status"] in ("ok", "invalid", "unknown") and isinstance(checked["key_age_days"], int),
          "the AI can check a key and see its age")
    expect_error(lambda: client.request("ai_rotate", {"secret_id": "echo-api", "reason": "x"}), "invalid",
                 "keys of providers without rotation API are refused with the reason")
    activity = client.request("ai_activity", {"limit": 20})
    check(len(activity) == 20 and API_KEY not in json.dumps(activity), "the AI sees recent activity, without values")
    check(all(e["secret"] == "echo-api" for e in client.request("ai_activity", {"secret_id": "echo-api"})),
          "activity of one credential")
    gui = threading.Thread(target=fake_gui, args=("deny",))
    gui.start()
    expect_error(lambda: client.request("ai_delete", {"secret_id": "shop-app-payments-secret", "reason": "no se usa"}),
                 "denied", "deleting needs the user's OK")
    gui.join()
    check(decisions[-1][0] == "delete" and "no se usa" in decisions[-1][1], "the request says why")
    gui = threading.Thread(target=fake_gui, args=("once",))
    gui.start()
    client.request("ai_delete", {"secret_id": "shop-app-payments-secret", "reason": "no se usa"})
    gui.join()
    check("shop-app-payments-secret" not in {e["id"] for e in client.request("entries")}, "deleted once the user agrees")

    print("Tags, expiry and reminders")
    client.request("update_credential", {"secret_id": "echo-api", "tags": ["Tienda", "pruebas"], "expires": "2020-01-31"})
    view = next(v for v in client.request("list_secrets") if v["id"] == "echo-api")
    check(view["tags"] == ["pruebas", "tienda"] and view["expires"] == "2020-01-31", "the AI can tag a credential and set its expiry")
    reminders = {r["id"]: r for r in client.request("reminders")}
    check(reminders.get("echo-api", {}).get("kind") == "expired" and client.request("status")["reminders"] >= 1,
          "expired keys are flagged")
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "expires": "31/01/2020"}), "invalid",
                 "dates are checked")
    client.request("update_credential", {"secret_id": "echo-api", "expires": ""})
    check("echo-api" not in {r["id"] for r in client.request("reminders")}, "removing the date clears the reminder")
    check("shop-app" in next(e for e in client.request("entries") if e["id"] == "shop-app-openai-api-key")["tags"],
          "imported keys are tagged with their project")

    print("Unusual use asks again")
    call("set_settings", {"settings": {"max_uses_per_hour": 50}}, "hello")
    gui = threading.Thread(target=fake_gui, args=("session",))
    gui.start()
    client.request("http_request", {"secret_id": "echo-api", "url": base + "/grant"})
    gui.join()
    service._uses.clear()  # earlier sections used echo-api in this same hour
    for i in range(50):
        client.request("http_request", {"secret_id": "echo-api", "url": base + f"/n{i}"})
    asked = len(decisions)
    client.request("pending_approvals")  # the app announces itself
    gui = threading.Thread(target=fake_gui, args=("session",))
    gui.start()
    result = client.request("http_request", {"secret_id": "echo-api", "url": base + "/one-too-many"})
    gui.join()
    check(result["status"] == 200 and len(decisions) == asked + 1 and decisions[-1][1].startswith("Uso inusual"),
          "past the hourly limit, an approved credential asks again")
    client.request("http_request", {"secret_id": "echo-api", "url": base + "/after"})
    check(len(decisions) == asked + 1, "and then the count starts again")
    call("set_settings", {"settings": {"max_uses_per_hour": 0}}, "hello")
    presence = fresh_presence[-1]

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

    print("Rotation by hand")
    working = {"sk-ant-api03-FAKEFAKEFAKE", "sk-ant-api03-NEWNEWNEW1234"}
    deleted_409 = set()

    def fake_alive(entry):
        if not exposure.provider_for(entry):
            return None
        if entry["fields"]["value"] in deleted_409:  # how AssemblyAI answers a deleted key
            return {"status": "unknown", "provider": "Anthropic", "http": 409, "message": "Respuesta inesperada (HTTP 409)"}
        ok = entry["fields"]["value"] in working
        return {"status": "ok" if ok else "invalid", "provider": "Anthropic", "message": "" if ok else "Anthropic rechaza la clave (HTTP 401)"}
    exposure.check_alive = fake_alive
    claude = listed["claude"]
    check(claude["guide"]["source"] == "builtin" and claude["guide"]["create"]
          and claude["guide"]["links"][0]["url"] == "https://platform.claude.com/settings/keys",
          "Anthropic has a built-in guide that starts at its keys page")
    check(listed["echo-api"]["guide"]["source"] == "generic" and listed["shop-db"]["guide"] is None,
          "unknown providers get the generic guide; non-API credentials none")
    expect_error(lambda: client.request("replace_key", {"id": "claude", "value": "sk-ant-api03-NEWNEWNEW1234"}), "proof_required",
                 "replacing a key needs the user")
    expect_error(lambda: call("replace_key", {"id": "claude", "value": "sk-ant-api03-REJECTED99"}, "hello"), "invalid",
                 "a new key the provider rejects is refused")
    expect_error(lambda: call("replace_key", {"id": "claude", "value": "sk-ant-api03-FAKEFAKEFAKE"}, "hello"), "invalid",
                 "the same key is refused")
    check(call("reveal", {"id": "claude", "field": "value"}, "hello") == "sk-ant-api03-FAKEFAKEFAKE", "and nothing changed")
    result = call("replace_key", {"id": "claude", "value": "sk-ant-api03-NEWNEWNEW1234"}, "hello")
    check(call("reveal", {"id": "claude", "field": "value"}, "hello") == "sk-ant-api03-NEWNEWNEW1234", "the new key is stored")
    check(result["check"]["status"] == "ok" and result["entry"]["retired"]["status"] == "pending"
          and result["entry"]["retired"]["checkable"], "it was tested, and the old one is kept to check it later")
    check("FAKEFAKE" not in json.dumps(client.request("entries")) and "NEWNEW" not in json.dumps(result),
          "neither key is shown")
    check(client.request("check_retired", {"id": "claude"})["status"] == "alive", "the old key still works")
    check(any(r["id"] == "claude" and r["kind"] == "old_alive" for r in client.request("reminders")),
          "a working old key is a reminder")
    working.discard("sk-ant-api03-FAKEFAKEFAKE")
    check(client.request("check_retired", {"id": "claude"})["status"] == "done", "once deleted at the provider, it is detected")
    check(next(e for e in client.request("entries") if e["id"] == "claude")["retired"] is None
          and not any(r["id"] == "claude" for r in client.request("reminders")), "and forgotten")
    working.add("sk-ant-api03-THIRD0000000")
    call("replace_key", {"id": "claude", "value": "sk-ant-api03-THIRD0000000"}, "hello")
    deleted_409.add("sk-ant-api03-NEWNEWNEW1234")
    check(client.request("check_retired", {"id": "claude"})["status"] == "done",
          "an old key refused with an unusual 4xx (AssemblyAI's 409) counts as deleted while the new one works")
    working.add("sk-ant-api03-FOURTH000000")
    call("replace_key", {"id": "claude", "value": "sk-ant-api03-FOURTH000000"}, "hello")
    client.request("forget_retired", {"id": "claude"})
    check(next(e for e in client.request("entries") if e["id"] == "claude")["retired"] is None, "the user can say it is deleted")

    print("Direct links for consoles and regional APIs")
    account = json.dumps({"type": "service_account", "project_id": "fincall-prod", "client_id": "123456789012345678901",
                          "client_email": "vertex@fincall-prod.iam.gserviceaccount.com", "private_key": "-----BEGIN PRIVATE KEY-----\nX"})
    consoles = [
        {"id": "eu-stt", "name": "STT", "template": "api_key", "fields": {"value": "eu-key-1234567890", "base_url": "https://api.eu.assemblyai.com"}},
        {"id": "vertex", "name": "Vertex", "template": "generic", "fields": {"value": account}},
        {"id": "g-oauth", "name": "Google", "template": "generic", "fields": {
            "value": "GOCSPX-secret-123456", "username": "619577974052-r6av55onin7fvn11.apps.googleusercontent.com", "url": "https://oauth2.googleapis.com"}},
        {"id": "ms-oauth", "name": "Microsoft", "template": "generic", "fields": {
            "value": "ms~secret~1234567890", "username": "f86bf497-4993-46b9-bccd-628b3721b715", "url": "https://login.microsoftonline.com"}},
        {"id": "own", "name": "Sesión", "template": "generic", "fields": {"value": "my-own-session-secret-123"}},
        {"id": "unknown-api", "name": "Otra", "template": "api_key", "fields": {"value": "zz-key-1234567890", "base_url": "https://api.unknown.example"}},
    ]
    for item in consoles:
        call("save_entry", {"entry": {**item, "description": "", "policy": {"approval": "never"}}}, "hello")
    listed = {e["id"]: e for e in client.request("entries")}
    first = lambda i: listed[i]["guide"]["links"][0]["url"]
    check(listed["eu-stt"]["guide"]["provider"] == "AssemblyAI" and listed["eu-stt"]["guide"]["source"] == "builtin"
          and first("eu-stt").startswith("https://www.assemblyai.com/"), "the EU AssemblyAI endpoint is recognised, with its links")
    check(exposure.provider_for(service.vault.get("eu-stt"))[3].startswith("https://api.eu.assemblyai.com/"),
          "and its key is only tested against the EU endpoint")
    check(first("vertex") == "https://console.cloud.google.com/iam-admin/serviceaccounts/details/123456789012345678901/keys?project=fincall-prod",
          "a service account key links to that account's keys")
    check(first("g-oauth") == "https://console.cloud.google.com/auth/clients/619577974052-r6av55onin7fvn11.apps.googleusercontent.com?project=619577974052",
          "an OAuth client secret links to that client")
    check(first("ms-oauth").endswith("/Credentials/appId/f86bf497-4993-46b9-bccd-628b3721b715"), "a Microsoft app secret links to that app's secrets")
    check(listed["own"]["guide"]["generate"] and listed["own"]["provider"] is None, "a secret of your own offers to generate one")
    check(listed["unknown-api"]["guide"]["source"] == "generic" and "api.unknown.example" in first("unknown-api"),
          "an unknown provider gets at least a web search")
    check("BEGIN PRIVATE" not in json.dumps(listed) and "GOCSPX" not in json.dumps(listed), "no secret leaks into the links")

    print("Secrets that go with an id")
    old_client = "619577974052-r6av55onin7fvn11.apps.googleusercontent.com"
    new_client = "619577974052-newclient42.apps.googleusercontent.com"
    call("save_entry", {"entry": {"id": "g-client-id", "name": "GOOGLE_CLIENT_ID", "template": "generic", "description": "",
                                  "fields": {"value": old_client}, "policy": {"approval": "never"}}}, "hello")
    g = listed["g-oauth"]["guide"]
    check(g["paired"] == {"label": "ID de cliente", "value": old_client, "hint": "123456789-abc.apps.googleusercontent.com"}
          and "No borres el cliente" in g["warning"] and "API key" in g["warning"], "the Google guide warns not to delete the client")
    check("No borres la app" in listed["ms-oauth"]["guide"]["warning"], "and the Microsoft one, the app")
    check(listed["own"]["guide"]["paired"] is None and listed["eu-stt"]["guide"]["paired"] is None, "keys without an id don't ask")
    check(listed["eu-stt"]["guide"]["testable"] and not g["testable"], "the wizard only promises a test when the key can be tested")
    expect_error(lambda: call("replace_key", {"id": "g-oauth", "value": "GOCSPX-new-654321"}, "hello"), "id_unconfirmed",
                 "rotating it without saying whether the client id changed is refused")
    expect_error(lambda: call("replace_key", {"id": "g-oauth", "value": "GOCSPX-new-654321", "paired_id": "not an id"}, "hello"),
                 "invalid", "a new client id must look like one")
    check(call("reveal", {"id": "g-oauth", "field": "value"}, "hello") == "GOCSPX-secret-123456", "and nothing changed")
    result = call("replace_key", {"id": "g-oauth", "value": "GOCSPX-new-654321", "paired_id": new_client}, "hello")
    check(result["id_changed"] and result["entry"]["fields"]["username"] == new_client
          and call("reveal", {"id": "g-oauth", "field": "value"}, "hello") == "GOCSPX-new-654321", "a new client: secret and id change together")
    check([o["id"] for o in result["also_updated"]] == ["g-client-id"]
          and call("reveal", {"id": "g-client-id", "field": "value"}, "hello") == new_client, "the id stored on its own is updated too")
    check(service.vault.retired()["entries"]["g-oauth"]["old_id"] == old_client
          and any(new_client in e["detail"] for e in client.request("audit", {"limit": 10})), "the old id is kept to delete that client, and audited")
    result = call("replace_key", {"id": "ms-oauth", "value": "ms~secret~NEW0987654", "paired_id": "f86bf497-4993-46b9-bccd-628b3721b715"}, "hello")
    check(not result["id_changed"] and result["entry"]["fields"]["username"] == "f86bf497-4993-46b9-bccd-628b3721b715",
          "same app: only the secret changes")
    check(not call("replace_key", {"id": "own", "value": "my-new-session-secret-456"}, "hello")["id_changed"], "a secret without an id rotates as before")
    check(client.request("ai_check", {"secret_id": "unknown-api"})["question"].startswith("¿Este secreto va emparejado")
          and client.request("ai_check", {"secret_id": "g-oauth"})["paired_id"]["value"] == new_client,
          "the AI is told the id, or asked to find out")
    drafted = client.request("create_draft", {"template": "generic", "name": "Webhook X", "description": ""})
    check(drafted["paired_id"] is None and "fields.username" in drafted["question"], "a new secret of unknown origin asks the AI about its id")
    call("delete_entry", {"id": "g-client-id"}, "hello")
    call("delete_entry", {"id": "webhook-x"}, "hello")
    for item in consoles:
        call("delete_entry", {"id": item["id"]}, "hello")

    print("Rotation guides by the AI and reminders per credential")
    guide = {"create": ["Abre Settings › API", "Pulsa «New key»"], "revoke": "Borra la anterior en la misma página",
             "links": [{"label": "API keys", "url": "https://echo.example.com/settings/api"}],
             "sources": ["https://docs.echo.example.com/keys"]}
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "rotation_guide": dict(
        guide, links=[{"label": "x", "url": "http://echo.example.com"}])}), "invalid", "guide links must be HTTPS")
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "rotation_guide": dict(guide, sources=[])}),
                 "invalid", "a guide must say where it comes from")
    expect_error(lambda: client.request("update_credential", {"secret_id": "echo-api", "rotate_every_days": 7}), "invalid",
                 "only the listed intervals")
    changed = client.request("update_credential", {"secret_id": "echo-api", "rotation_guide": guide, "rotate_every_days": 90})
    check(any("Guía de rotación" in c and "docs.echo.example.com" in c for c in changed["changed"]), "the change says where the guide comes from")
    echo = next(e for e in client.request("entries") if e["id"] == "echo-api")
    check(echo["guide"]["source"] == "ai" and echo["guide"]["links"][0]["url"] == "https://echo.example.com/settings/api"
          and echo["guide"]["written"] and echo["rotate_every_days"] == 90, "the app shows the AI's guide, marked as such")
    view = next(v for v in client.request("list_secrets") if v["id"] == "echo-api")
    check(view["rotate_every_days"] == 90 and view["rotation_guide"] == "escrita por la IA", "the AI sees it too")
    check(client.request("ai_check", {"secret_id": "echo-api"})["rotation_guide"] == "ai", "check_credential says which guide there is")
    saved = dict(echo, fields={**echo["fields"], "value": None})
    saved = {k: saved[k] for k in ("id", "name", "template", "description", "fields", "policy", "tags", "rotate_every_days")}
    call("save_entry", {"entry": saved, "replaces": "echo-api"}, "hello")
    check(next(e for e in client.request("entries") if e["id"] == "echo-api")["guide"]["source"] == "ai",
          "editing it in the app keeps the AI's guide")
    with service.vault._lock:
        service.vault._payload["entries"]["echo-api"]["secret_since"] = "2026-01-01T00:00:00+00:00"
    old_reminder = next((r for r in client.request("reminders") if r["id"] == "echo-api"), None)
    check(service.vault.settings()["rotate_reminder_days"] in (0, 365) and old_reminder and old_reminder["kind"] == "old",
          "its own interval (90 days) applies instead of the general one")
    client.request("update_credential", {"secret_id": "echo-api", "rotate_every_days": 0})
    check(not any(r["id"] == "echo-api" for r in client.request("reminders")), "0 means never remind")

    print("How often keys are tested")
    check(client.request("status")["check_every_hours"] == 24, "by default, every day")
    expect_error(lambda: call("set_settings", {"settings": {"check_every_hours": -5}}, "hello"), "invalid", "nonsense intervals are refused")
    expect_error(lambda: client.request("update_credential", {"secret_id": "claude", "check_every_hours": "a"}), "invalid",
                 "the interval is a number")
    service.op_exposure_check({})
    check(not service._due_checks(), "right after a check, nothing is due")
    stored = service.vault.exposure()
    for record in stored["entries"].values():
        record["checked"] = "2026-01-01T00:00:00+00:00"
        record.pop("alive", None)
    service.vault.set_exposure(stored)
    due = set(service._due_checks())
    check({"claude", "shop-db"} <= due, "a day later, every key is due again")
    client.request("update_credential", {"secret_id": "claude", "check_every_hours": 0})
    check("claude" not in service._due_checks(), "a credential set to never is not tested")
    client.request("update_credential", {"secret_id": "claude", "check_every_hours": -1})
    check("claude" not in service._due_checks(), "«only once»: a key tested once is not tested again")
    client.request("update_credential", {"secret_id": "claude", "check_every_hours": 87600})
    check("claude" not in service._due_checks(), "a custom number of hours is respected")
    view = next(v for v in client.request("list_secrets") if v["id"] == "claude")
    check(view["check_every_hours"] == 87600, "the AI sees the interval")
    call("set_settings", {"settings": {"check_every_hours": 0}}, "hello")
    check(not service._due_checks() and client.request("status")["check_every_hours"] == 0, "the general setting can turn it off")
    client.request("update_credential", {"secret_id": "claude", "check_every_hours": 1})
    check(service._due_checks() == ["claude"], "and one credential can still be tested on its own schedule")
    call("set_settings", {"settings": {"check_every_hours": 24}}, "hello")
    working.add("sk-ant-api03-FOURTH000000")
    service.op_exposure_check({"ids": ["claude"]})
    check("claude" not in service._due_checks(), "after its check it waits for its next turn")

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

    print("Updates")
    signing = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(signing.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                         serialization.NoEncryption())).decode()
    update.PUBLIC_KEY = base64.b64encode(signing.public_key().public_bytes(serialization.Encoding.Raw,
                                                                           serialization.PublicFormat.Raw)).decode()
    installer = b"MZ fake installer " * 1000
    signature = update.sign(private_b64, "99.0.0", installer)
    update.verify("99.0.0", installer, signature)
    check(True, "a signed installer verifies")
    for label, args in [("another version's signature is refused", ("99.0.1", installer, signature)),
                        ("a modified installer is refused", ("99.0.0", installer + b"x", signature)),
                        ("a signature from another key is refused", ("99.0.0", installer, update.sign(
                            base64.b64encode(os.urandom(32)).decode(), "99.0.0", installer)))]:
        try:
            update.verify(*args)
            check(False, label)
        except update.UpdateError:
            check(True, label)
    served = {"https://github.com/x/sig": signature.encode(), "https://github.com/x/exe": installer}
    update._download = lambda client, url: served[url]
    latest = {"version": "99.0.0", "notes": "", "url": "", "signature": "https://github.com/x/sig",
              "installer": {"name": "SecretBroker-Setup-99.0.0.exe", "url": "https://github.com/x/exe"}}
    service.updates._latest = latest
    service.updates._checked = time.monotonic()
    status = client.request("update_status")
    check(status["available"] and status["latest"] == "99.0.0", "a newer signed release is offered")
    path = Path(client.request("update_download")["path"])
    check(path.read_bytes() == installer and path.parent == HOME / "public" / "updates", "the service downloads it into its public folder")
    served["https://github.com/x/exe"] = installer + b"tampered"
    expect_error(lambda: client.request("update_download"), "update_failed", "a tampered download is not installed")
    check(not update._allowed_download("https://evil.example.com/SecretBroker-Setup-99.0.0.exe"), "downloads only from GitHub")

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

    print("MCP over HTTP (served by the desktop app)")
    asyncio.run(check_http())

    print("Following the Windows session (Win+L simulated)")
    from secretbroker import resident
    session_token = call("enable_session_unlock", {}, "hello")["token"]

    class FakeApp:
        presence = None
        shown = 0

        def has_session_unlock(self):
            return True

        def has_presence(self):
            return self.presence is not None

        def session_unlock(self):
            self.presence = call("unlock", {}, {"kind": "session", "token": session_token})["presence"]
            return True

        def show(self):
            self.shown += 1

        def backup_due(self):
            return False

    fake = FakeApp()
    watcher = resident.Watcher(fake)
    screen = {"locked": False}
    original_locked = resident.workstation_locked
    resident.workstation_locked = lambda: screen["locked"]
    try:
        watcher._step()
        check(fake.presence, "an app opened while the vault is already open gets its one-click token from the session")
        screen["locked"] = True
        watcher._step()
        check(client.request("status")["state"] == "locked", "Win+L locks the vault")
        fake.presence = None
        screen["locked"] = False
        watcher._step()
        check(client.request("status")["state"] == "unlocked" and fake.presence, "unlocking Windows opens it again, no password")
        client.request("lock")
        watcher._step()
        check(client.request("status")["state"] == "locked", "after locking by hand it stays locked")
    finally:
        resident.workstation_locked = original_locked
        client.request("disable_session_unlock")
    call("unlock", {}, "hello")
    expect_error(lambda: call("unlock", {}, {"kind": "master_password", "value": "wrong wrong wrong"}), "proof_invalid",
                 "an open vault still checks the password before handing out a token")
    check(not client.request("unlock").get("presence"), "and without proof it hands out nothing")

    print("Audit")
    events = client.request("audit", {"limit": 1000})
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


async def check_http():
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from secretbroker import integrations, resident

    integrations.PREFS_FILE = HOME / "prefs.json"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        integrations.MCP_PORT = probe.getsockname()[1]
    shown = []
    server = resident.serve_mcp(lambda: shown.append(1))
    url, token = integrations.mcp_endpoint()
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.1)
    async with httpx.AsyncClient() as plain:
        response = await plain.post(url, json={})
        check(response.status_code == 401, "the HTTP endpoint refuses callers without the token")
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                check(len(tools) == 14, "Claude Code gets the same tools over HTTP")
                result = await session.call_tool("list_secrets", {})
                text = " ".join(getattr(c, "text", "") for c in result.content)
                check("echo-api" in text and API_KEY not in text, "MCP over HTTP works through the service")
    server.should_exit = True


async def check_stdio():
    from mcp import ClientSession, StdioServerParameters, stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "secretbroker.mcp_server"], env={**os.environ})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = sorted(t.name for t in (await session.list_tools()).tools)
            check(tools == ["check_credential", "create_credential", "credential_activity", "delete_credential", "http_request", "list_secrets", "push_github_secret", "request_access", "rotate_credential", "run_command", "ssh_download", "ssh_exec", "ssh_upload", "update_credential"], f"MCP tools: {tools}")
            result = await session.call_tool("list_secrets", {})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("echo-api" in text and API_KEY not in text, "MCP list_secrets works through the service")
            result = await session.call_tool("http_request", {"secret_id": "echo-api", "url": "https://evil.example.com/"})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            check("no permitido" in text, "MCP surfaces service errors to the agent")


if __name__ == "__main__":
    main()
