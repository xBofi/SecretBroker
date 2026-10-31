"""Teams end to end: a real SecretBroker Server and three isolated desktop services (Alice on two PCs, Bob, Carol).

Covers accounts and key recovery on a second device, invites with fingerprints, collections, sharing, sync,
'use' permission, conflicts, quarantine of policy changes, member removal with re-keying and rotate reminders,
and that the server database holds no secret or credential name. Only fake secrets are used.
Run with:  .venv\\Scripts\\python.exe tests\\test_teams.py
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="secretbroker-teams-test-"))
os.environ["SECRETBROKER_HOME"] = str(HOME / "default")  # must be set before importing secretbroker
os.environ.update(SB_ALLOW_HTTP="1", SB_PUBLIC_URL="http://127.0.0.1", SB_SIGNUPS="open",
                  SB_DATA_DIR=str(HOME / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

import uvicorn  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402

from secretbroker import teams  # noqa: E402
from secretbroker.service import AI_OPS, Service  # noqa: E402
from secretbroker_server import config  # noqa: E402
from secretbroker_server.web import create_app  # noqa: E402

MASTER = "correct horse battery staple"
ACCOUNT = "team account passphrase 42"
API_KEY = "sk-team-FAKESECRET-0123456789"
NEW_KEY = "sk-team-ROTATEDFAKE-9876543210"
NAME = "Pasarela Zafiro"        # credential name: must never reach the server in clear
COLLECTION = "Producción Ámbar"  # collection name: same
failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


class Echo(BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        Echo.received.append(self.headers.get("Authorization"))
        data = json.dumps({"path": self.path, "auth": self.headers.get("Authorization")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def start_server():
    settings = config.from_env()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)

    def stop():
        server.should_exit = True
        thread.join(10)
    return f"http://127.0.0.1:{port}", stop, settings


class Person:
    """One desktop: its own service and vault, driven like the app does (presence token = one click)."""

    def __init__(self, label):
        self.service = Service(HOME / label, owner=f"{os.environ.get('USERDOMAIN')}\\{os.environ.get('USERNAME')}",
                               isolated=False)
        self.presence = self.ok("create_vault", master_password=MASTER)["presence"]

    def call(self, op, **params):
        return self.service.handle(op, params)

    def ok(self, op, **params):
        response = self.call(op, **params)
        if not response["ok"]:
            raise AssertionError(f"{op}: [{response['code']}] {response['error']}")
        return response["result"]

    def act(self, op, **params):
        return self.ok(op, proof={"kind": "presence", "token": self.presence}, **params)

    def save(self, entry, replaces=None):
        return self.ok("save_entry", entry=entry, replaces=replaces, proof={"kind": "master_password", "value": MASTER})

    def entry(self, entry_id):
        return self.service.vault.get(entry_id)

    def summary(self, entry_id):
        return next(e for e in self.ok("entries") if e["id"] == entry_id)

    def sync(self):
        return self.ok("team_sync")

    def edit(self, entry_id, **changes):
        """An edit from the editor: secrets are sent as null (keep)."""
        entry = self.entry(entry_id)
        entry.pop("shared", None)
        for name in ("value", "password"):
            if name in entry["fields"]:
                entry["fields"][name] = None
        entry.update(changes)
        return self.call("save_entry", entry=entry, replaces=entry_id,
                         proof={"kind": "master_password", "value": MASTER})


def main():
    base, stop, settings = start_server()
    echo = HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    echo_url = f"http://127.0.0.1:{echo.server_address[1]}"

    print("Accounts")
    alice, bob, carol = Person("alice"), Person("bob"), Person("carol")
    check(alice.ok("team_status")["connected"] is False, "not connected at first")
    response = alice.call("team_connect", server_url=base, email="alice@example.com", password=ACCOUNT, mode="register")
    check(response["code"] == "proof_required", "linking an account needs the user (one click)")
    response = alice.call("team_connect", server_url="http://example.com", email="alice@example.com", password=ACCOUNT,
                          mode="register", proof={"kind": "presence", "token": alice.presence})
    check(not response["ok"] and response["code"] == "invalid" and "https" in response["error"],
          "plain http is refused except to this PC")
    response = alice.call("team_connect", server_url=base, email="alice@example.com", password="short",
                          mode="register", proof={"kind": "presence", "token": alice.presence})
    check(response["code"] == "invalid", "short account password refused")
    status = alice.act("team_connect", server_url=base, email="alice@example.com", password=ACCOUNT, mode="register",
                       name="Alice")
    check(status["connected"] and len(status["fingerprint"].split()) == 8, "Alice registers and gets a fingerprint")
    bob_status = bob.act("team_connect", server_url=base, email="bob@example.com", password=ACCOUNT, mode="register",
                         name="Bob")
    carol.act("team_connect", server_url=base, email="carol@example.com", password=ACCOUNT, mode="register", name="Carol")
    raw = (HOME / "alice" / "data" / "vault.json").read_text()
    check(alice.service.vault.team()["token"] not in raw and "x25519" not in raw, "team keys and token live encrypted in the vault")

    laptop = Person("alice-laptop")
    response = laptop.call("team_connect", server_url=base, email="alice@example.com", password="wrong password 123",
                           mode="login", proof={"kind": "presence", "token": laptop.presence})
    check(response["code"] == "invalid_credentials", f"wrong account password refused: {response.get('error')}")
    second = laptop.act("team_connect", server_url=base, email="alice@example.com", password=ACCOUNT, mode="login")
    check(second["fingerprint"] == status["fingerprint"] and second["user"]["id"] == status["user"]["id"],
          "a second device logs in and recovers the same keys")
    check(not any(op.startswith("team_") for op in AI_OPS), "no team operation is reachable by the AI")

    print("Organization, invites and fingerprints")
    oid = alice.act("team_create_org", name="Acme")["id"]
    alice.act("team_invite", org=oid, email="bob@example.com", role="member")
    alice.act("team_invite", org=oid, email="carol@example.com", role="member")
    invite = bob.ok("team_invites")[0]
    check(invite["org_name"] == "Acme", "Bob sees the invite")
    bob.act("team_accept_invite", id=invite["id"])
    carol.act("team_accept_invite", id=carol.ok("team_invites")[0]["id"])
    members = {m["email"]: m for m in alice.ok("team_members", org=oid)}
    check(members["bob@example.com"]["status"] == "accepted"
          and members["bob@example.com"]["fingerprint"] == bob_status["fingerprint"], "admin sees Bob's fingerprint")
    bob_id, carol_id = members["bob@example.com"]["user_id"], members["carol@example.com"]["user_id"]
    response = alice.call("team_confirm_member", org=oid, user_id=carol_id, fingerprint="0000 1111 2222 3333 4444 5555 6666 7777",
                          proof={"kind": "presence", "token": alice.presence})
    check(response["code"] == "fingerprint_mismatch", "a wrong fingerprint is refused")
    response = alice.call("team_confirm_member", org=oid, user_id=bob_id, fingerprint=bob_status["fingerprint"])
    check(response["code"] == "proof_required", "confirming needs the user (one click)")
    alice.act("team_confirm_member", org=oid, user_id=bob_id, fingerprint=bob_status["fingerprint"].replace(" ", ""))
    alice.act("team_confirm_member", org=oid, user_id=carol_id)
    check(bob_id in alice.service.vault.team()["pinned"], "Bob's key is pinned")

    print("Collections and sharing")
    cid = alice.act("team_create_collection", org=oid, name=COLLECTION)["id"]
    alice.act("team_grant", collection=cid, user_id=bob_id, permission="edit")
    alice.act("team_grant", collection=cid, user_id=carol_id, permission="use")
    alice.save({"id": "echo-api", "name": NAME, "template": "api_key", "description": "API compartida",
                "fields": {"value": API_KEY, "base_url": echo_url, "auth_style": "bearer"},
                "policy": {"approval": "never", "http": {"allowed_hosts": ["127.0.0.1"], "auth": {
                    "kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}}}})
    shared = alice.act("team_share_entry", id="echo-api", collection=cid)
    check(shared["entry"]["shared"]["collection_name"] == COLLECTION and shared["entry"]["shared"]["permission"] == "manage",
          "Alice shares a credential")
    collections = alice.ok("team_collections")
    check(collections[0]["name"] == COLLECTION and collections[0]["entries"] == 1, "collection list with names and counts")

    result = bob.sync()
    check(result["state"] == "ok" and result["result"]["added"] == [NAME], f"Bob syncs the new credential ({result.get('error')})")
    bob_entry = bob.entry("echo-api")
    check(bob_entry["fields"]["value"] == API_KEY and bob_entry["policy"]["approval"] == "session",
          "Bob has the secret, with his own approval mode (never taken from the server)")
    view = next(v for v in bob.ok("list_secrets") if v["id"] == "echo-api")
    check(view["shared"] == {"org": "Acme", "collection": COLLECTION, "permission": "edit"} and "key" not in json.dumps(view["shared"]),
          "the AI sees org, collection and permission, no keys")
    check("{{value}}" in view["placeholders"], "placeholders resolve for the shared credential")

    carol.sync()
    response = carol.call("reveal", id="echo-api", field="value", proof={"kind": "master_password", "value": MASTER})
    check(not response["ok"] and response["code"] == "forbidden", "'use' permission blocks reveal and copy")
    response = carol.edit("echo-api", name="Otro nombre")
    check(not response["ok"] and response["code"] == "forbidden", "'use' permission cannot edit the credential")
    response = carol.edit("echo-api", policy={**carol.entry("echo-api")["policy"], "approval": "never"})
    check(response["ok"] and carol.entry("echo-api")["policy"]["approval"] == "never", "but may set its own approval mode")
    result = carol.ok("http_request", secret_id="echo-api", url=echo_url + "/carol")
    check(result["status"] == 200 and Echo.received[-1] == f"Bearer {API_KEY}" and API_KEY not in json.dumps(result),
          "Carol's AI uses the shared key without seeing it")
    laptop.sync()
    check(laptop.entry("echo-api")["fields"]["value"] == API_KEY, "Alice's second device gets it too")

    print("Edits and conflicts")
    bob.edit("echo-api", description="Notas de Bob")
    check(bob.sync()["result"]["pushed"] == [NAME], "Bob's edit is pushed")
    alice.sync()
    check(alice.entry("echo-api")["description"] == "Notas de Bob" and alice.entry("echo-api")["policy"]["approval"] == "never",
          "Alice gets Bob's edit and keeps her approval mode")
    alice.edit("echo-api", description="Versión de Alice")
    bob.edit("echo-api", description="Versión de Bob")
    bob.sync()
    state = alice.service.vault.team()
    notes = {k: [] for k in ("added", "updated", "removed", "conflicts", "quarantined", "pushed", "rotate", "errors")}
    with teams.Client(state["server_url"], state["token"]) as api:
        alice.service.team._push(api, state, cid, notes)  # push before pulling: the server answers 409
    alice.service.vault.set_team(state)
    check(notes["conflicts"] == ["echo-api-conflict"], "409: the server version wins")
    check(alice.entry("echo-api")["description"] == "Versión de Bob"
          and alice.entry("echo-api-conflict")["description"] == "Versión de Alice"
          and not alice.entry("echo-api-conflict").get("shared"), "the local edit is kept as a personal '<id>-conflict'")
    alice.ok("delete_entry", id="echo-api-conflict", proof={"kind": "master_password", "value": MASTER})

    print("Changes to where a key can go")
    bob_policy = bob.entry("echo-api")["policy"]
    bob.edit("echo-api", name=NAME + " v2", policy={**bob_policy, "http": {**bob_policy["http"],
                                                    "allowed_hosts": ["127.0.0.1", "evil.example.com"]}})
    bob.sync()
    result = alice.sync()["result"]
    entry = alice.entry("echo-api")
    check(entry["name"] == NAME + " v2", "names apply at once")
    check(entry["policy"]["http"]["allowed_hosts"] == ["127.0.0.1"] and entry["shared"].get("pending_policy")
          and result["quarantined"] == [NAME + " v2"], "a new host is quarantined: the old policy stays")
    pending = alice.summary("echo-api")["shared"]["pending_change"]
    check(pending["by"] == "Bob" and any("evil.example.com" in line for line in pending["changes"]),
          "the change to review says who and what")
    check(any(n["title"].startswith("Cambio por revisar") for n in alice.ok("notices")), "Alice gets a notice")
    alice.sync()
    bob.sync()
    check("evil.example.com" in bob.entry("echo-api")["policy"]["http"]["allowed_hosts"],
          "a quarantined change is not pushed back as a revert")
    response = alice.call("team_accept_change", id="echo-api")
    check(response["code"] == "proof_required", "accepting needs one click")
    accepted = alice.act("team_accept_change", id="echo-api")
    entry = alice.entry("echo-api")
    check(accepted["accepted"] and "evil.example.com" in entry["policy"]["http"]["allowed_hosts"]
          and entry["policy"]["approval"] == "never" and not entry["shared"].get("pending_policy"),
          "accepted with one click, keeping the local approval mode")
    bob_policy = bob.entry("echo-api")["policy"]
    bob.edit("echo-api", policy={**bob_policy, "http": {**bob_policy["http"], "allowed_hosts": ["127.0.0.1"]}})
    bob.sync()
    alice.sync()
    check(alice.entry("echo-api")["policy"]["http"]["allowed_hosts"] == ["127.0.0.1"]
          and not alice.entry("echo-api")["shared"].get("pending_policy"), "narrowing applies at once")

    print("Session expiry")
    state = laptop.service.vault.team()
    with teams.Client(state["server_url"], state["token"]) as api:
        api.call("POST", "/accounts/logout")
    status = laptop.sync()
    check(status["state"] == "reconnect", "an expired session shows 'reconnect', no exception")
    status = laptop.act("team_connect", server_url=base, email="alice@example.com", password=ACCOUNT, mode="login")
    check(laptop.sync()["state"] == "ok" and laptop.entry("echo-api")["fields"]["value"] == API_KEY,
          "reconnecting keeps the collections")

    print("Removing a member")
    old_key = bob.service.vault.team()["collections"][cid]["keys"]["1"]
    removed = alice.act("team_remove_member", org=oid, user_id=bob_id)
    check(removed["rekeyed"] == [cid], "Alice re-keys the collection Bob could read")
    reminder = next((r for r in alice.ok("reminders") if r["id"] == "echo-api"), {})
    check(reminder.get("kind") == "team_access" and reminder.get("people") == ["Bob"] and reminder.get("can_rotate"),
          "every credential in it gets 'rotate: Bob had access'")
    carol.sync()
    reminder = next((r for r in carol.ok("reminders") if r["id"] == "echo-api"), {})
    check(reminder.get("kind") == "team_access" and reminder.get("people") == ["Bob"] and not reminder.get("can_rotate"),
          "other members see the reminder too")
    check(carol.ok("status")["reminders"] >= 1, "it counts in the reminders badge")
    rotated = alice.act("replace_key", id="echo-api", value=NEW_KEY)
    check(rotated["entry"]["id"] == "echo-api" and not any(r["id"] == "echo-api" for r in alice.ok("reminders")),
          "the guided rotation clears the reminder")
    alice.sync()
    carol.sync()
    check(carol.entry("echo-api")["fields"]["value"] == NEW_KEY and not any(r["id"] == "echo-api" for r in carol.ok("reminders")),
          "the rotated key reaches the team and clears their reminder")
    bob.sync()
    check(not any(e.get("shared") for e in bob.service.vault.entries()) and not bob.service.vault.team()["collections"],
          "Bob's copies are gone after his next sync")
    state = alice.service.vault.team()
    with teams.Client(state["server_url"], state["token"]) as api:
        item = api.call("GET", f"/collections/{cid}/items?since=0")["items"][0]
    try:
        teams.open_item(teams.unb64(old_key), cid, item["id"], 1, item["ciphertext"])
        check(False, "the removed member cannot decrypt new items")
    except InvalidTag:
        check(item["key_version"] == 2, "the removed member cannot decrypt new items")

    print("Unsharing, backups and offline")
    backup = alice.act("backup")
    alice.presence = alice.act("restore", vault=backup["vault"], master_password=MASTER)["presence"]
    check(alice.ok("team_status")["connected"] and alice.entry("echo-api").get("shared"), "backup and restore keep the team")
    alice.act("team_unshare_entry", id="echo-api")
    carol.sync()
    check(not any(e["id"] == "echo-api" for e in carol.service.vault.entries()), "unsharing removes it from the others")
    check(not alice.entry("echo-api").get("shared") and alice.entry("echo-api")["fields"]["value"] == NEW_KEY,
          "the sharer keeps it as a personal credential")
    alice.act("team_share_entry", id="echo-api", collection=cid)
    carol.sync()

    print("Background sync and leaving")
    threading.Thread(target=carol.service._team_loop, daemon=True).start()
    carol.ok("lock")
    carol.service._team_info.pop("last_sync", None)
    before = None
    started = time.monotonic()
    carol.presence = carol.ok("unlock", proof={"kind": "master_password", "value": MASTER})["presence"]
    check(time.monotonic() - started < 5, "unlocking does not wait for the network")
    for _ in range(100):
        if carol.service._team_info.get("last_sync") not in (None, before) and carol.service._team_info["state"] == "ok":
            break
        time.sleep(0.1)
    check(carol.service._team_info.get("last_sync") != before, "unlocking starts a sync in the background")
    carol.act("team_revoke", collection=cid, user_id=carol_id)
    check(not any(e["id"] == "echo-api" for e in carol.service.vault.entries()), "leaving a collection removes its credentials")
    result = alice.sync()["result"]
    check(result["rotate"] == [{"collection": COLLECTION, "people": ["Carol"]}]
          and alice.service.vault.team()["collections"][cid]["key_version"] == 3, "the manager re-keys on sync after someone left")
    reminder = next((r for r in alice.ok("reminders") if r["id"] == "echo-api"), {})
    check(reminder.get("people") == ["Carol"], "and gets 'rotate: Carol had access'")

    db = b"".join(p.read_bytes() for p in Path(settings.data_dir).glob("secretbroker.db*"))
    leaks = [w for w in (API_KEY, NEW_KEY, NAME, COLLECTION, "echo-api", "API compartida", "Notas de Bob")
             if w.encode("utf-8") in db or json.dumps(w).encode() in db]
    check(not leaks, f"the server database has no secret, credential or collection name {leaks or ''}")

    alice.ok("lock")
    check(alice.call("team_collections")["code"] == "locked", "team operations need an unlocked vault")
    disconnected = laptop.act("team_disconnect")
    check(disconnected["removed"] == 1 and not laptop.ok("team_status")["connected"], "disconnecting removes the team's credentials")
    stop()
    status = carol.sync()
    check(status["state"] == "offline" and status["connected"], "server down: reported in team_status, nothing raised")

    print()
    print("ALL PASSED" if failures == 0 else f"{failures} FAILURE(S)")
    return failures == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
