"""SecretBroker Server API checks against a real uvicorn on a random port, with a throwaway data folder.

Only fake key material is used: the server never decrypts anything, so random bytes of the right size will do.
Run with:  .venv\\Scripts\\python.exe server\\tests\\test_server.py
"""

import base64
import os
import socket
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

from secretbroker_server import config  # noqa: E402
from secretbroker_server.web import create_app  # noqa: E402

failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


def rand(size):
    return base64.b64encode(os.urandom(size)).decode("ascii")


def box(size=48):
    return {"nonce": rand(12), "ciphertext": rand(size)}


def kdf():
    return {"name": "scrypt", "n": 2**17, "r": 8, "p": 1, "salt": rand(16)}


class Api:
    """A tiny client: one per person, keeping that person's token."""

    def __init__(self, base):
        self.http = httpx.Client(base_url=base + "/api/v1", timeout=30)
        self.token = None
        self.id = None
        self.auth_hash = None
        self.email = None

    def call(self, method, path, json=None, token=None):
        token = token or self.token
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.http.request(method, path, json=json, headers=headers)

    def ok(self, method, path, json=None):
        response = self.call(method, path, json)
        if response.status_code != 200:
            raise AssertionError(f"{method} {path} -> {response.status_code} {response.text}")
        return response.json()

    def register(self, email, invite_token=None):
        self.id, self.email, self.auth_hash = str(uuid.uuid4()), email, rand(32)
        body = {"user_id": self.id, "email": email, "name": email.split("@")[0].title(), "kdf": kdf(),
                "auth_hash": self.auth_hash, "public_key": rand(32), "signing_public_key": rand(32),
                "private_blob": box(200)}
        if invite_token:
            body["invite_token"] = invite_token
        return self.call("POST", "/accounts/register", body)

    def login(self, device="PC de prueba", auth_hash=None, email=None):
        return self.call("POST", "/accounts/login", {"email": email or self.email,
                                                     "auth_hash": auth_hash or self.auth_hash, "device_name": device})

    def signup(self, email):
        assert self.register(email).status_code == 200
        self.token = self.login().json()["token"]
        return self

    def grant(self, cid=None):
        return {"sealed": {"epk": rand(32), "nonce": rand(12), "ciphertext": rand(48)}, "granted_by": self.id,
                "signature": rand(64)}


def start(**overrides):
    """Run a server in a background thread; returns (base url, stop function)."""
    data = Path(tempfile.mkdtemp(prefix="sb-server-test-"))
    settings = config.Settings(data_dir=data, public_url="http://127.0.0.1", allow_http=True, signups="open")
    for key, value in overrides.items():
        setattr(settings, key, value)
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


def test_config():
    print("Configuration")
    try:
        config.Settings(data_dir=Path("."), public_url="http://example.com").check()
        check(False, "plain http public URL is refused")
    except config.ConfigError:
        check(True, "plain http public URL is refused")
    check(config.Settings(data_dir=Path("."), public_url="https://example.com").check().https, "https URL is accepted")
    try:
        config.Settings(data_dir=Path("."), public_url="https://example.com", signups="maybe").check()
        check(False, "unknown signup mode is refused")
    except config.ConfigError:
        check(True, "unknown signup mode is refused")


def test_accounts(base):
    print("Accounts and sessions")
    anon = Api(base)
    info = anon.ok("GET", "/info")
    check(info["signups"] == "open" and info["version"] and info["name"], "info answers without auth")
    headers = anon.http.get("/info").headers
    check(headers.get("x-content-type-options") == "nosniff" and headers.get("cache-control") == "no-store"
          and "default-src 'none'" in headers.get("content-security-policy", ""), "security headers are set")
    missing = anon.http.get("/nope")
    check(missing.status_code == 404 and missing.json()["code"] == "not_found", "unknown route is a JSON 404")

    alice = Api(base)
    check(alice.register("Alice@Example.com").status_code == 200, "alice registers")
    check(Api(base).register("alice@example.com").status_code == 409, "same e-mail cannot register twice")
    alice.email = "alice@example.com"
    real = anon.ok("POST", "/accounts/prelogin", {"email": "alice@example.com"})["kdf"]
    fake1 = anon.ok("POST", "/accounts/prelogin", {"email": "ghost@example.com"})["kdf"]
    fake2 = anon.ok("POST", "/accounts/prelogin", {"email": "ghost@example.com"})["kdf"]
    other = anon.ok("POST", "/accounts/prelogin", {"email": "ghost2@example.com"})["kdf"]
    check(set(real) == set(fake1) and real["n"] == fake1["n"] and len(base64.b64decode(fake1["salt"])) == 16,
          "prelogin for an unknown e-mail looks like a real one")
    check(fake1 == fake2 and fake1["salt"] != other["salt"], "fake prelogin salt is stable per e-mail")

    wrong = alice.login(auth_hash=rand(32))
    unknown = alice.login(email="ghost@example.com")
    check(wrong.status_code == 401 and unknown.status_code == 401
          and wrong.json() == unknown.json(), "wrong password and unknown e-mail give the same 401")
    response = alice.login()
    check(response.status_code == 200, "alice logs in")
    data = response.json()
    alice.token = data["token"]
    check(data["user"]["admin"] is True and data["private_blob"]["nonce"] and data["kdf"]["n"] == 2**17,
          "login returns keys, kdf, and the first user is server admin")
    me = alice.ok("GET", "/me")
    check(len(me["devices"]) == 1 and me["devices"][0]["current"], "me lists this device")

    bad = [
        alice.call("POST", "/accounts/register", {"email": "x@example.com"}),
        Api(base).call("POST", "/accounts/prelogin", {"email": "x@example.com", "extra": 1}),
        Api(base).call("POST", "/accounts/prelogin", {"email": "not-an-email"}),
    ]
    check(all(r.status_code == 400 and r.json()["code"] == "invalid" for r in bad), "malformed bodies are 400")
    check(alice.call("GET", "/me", token="bogus").status_code == 401, "bogus token is 401")
    big = alice.http.post("/accounts/prelogin", content=b"{" + b" " * (9 * 1024 * 1024) + b"}",
                          headers={"content-type": "application/json"})
    check(big.status_code == 413, "oversized request is refused")

    # Second device, revoke it, password change revokes the rest.
    laptop = alice.login("Portátil").json()["token"]
    devices = alice.ok("GET", "/me")["devices"]
    other_id = next(d["id"] for d in devices if not d["current"])
    check(len(devices) == 2, "second login adds a device")
    alice.ok("DELETE", f"/me/devices/{other_id}")
    check(alice.call("GET", "/me", token=laptop).status_code == 401, "revoked device token stops working")
    tablet = alice.login("Tablet").json()["token"]
    new_hash = rand(32)
    alice.ok("POST", "/accounts/password", {"kdf": kdf(), "auth_hash": new_hash, "private_blob": box(200)})
    check(alice.call("GET", "/me", token=tablet).status_code == 401, "password change signs out other devices")
    check(alice.call("GET", "/me").status_code == 200, "password change keeps this device")
    check(alice.login().status_code == 401, "old password no longer works")
    alice.auth_hash = new_hash
    old_token = alice.token
    alice.token = alice.login().json()["token"]
    alice.ok("POST", "/accounts/logout", {})
    check(alice.call("GET", "/me").status_code == 401, "logout revokes the token")
    alice.token = old_token
    return alice


def test_rate_limit(base):
    print("Login rate limiting")
    victim = Api(base).signup("victim@example.com")
    codes = [victim.login(auth_hash=rand(32)).status_code for _ in range(5)]
    blocked = victim.login(auth_hash=rand(32))
    check(codes == [401] * 5 and blocked.status_code == 429 and blocked.headers.get("retry-after"),
          "sixth wrong password in a row is 429 with Retry-After")
    check(victim.login().status_code == 429, "even the right password waits while blocked")
    time.sleep(1.2)
    check(victim.login().status_code == 200, "after the wait the right password works again")


def test_orgs_and_items(base, alice):
    print("Organizations, collections and items")
    bob, carol, dave = Api(base).signup("bob@example.com"), Api(base).signup("carol@example.com"), \
        Api(base).signup("dave@example.com")
    oid = alice.ok("POST", "/orgs", {"name": "Equipo"})["id"]
    check(alice.ok("GET", "/orgs")[0]["role"] == "owner", "creator is owner")
    for person in (bob, carol, dave):
        alice.ok("POST", f"/orgs/{oid}/invites", {"email": person.email, "role": "member"})
    check(alice.call("POST", f"/orgs/{oid}/invites", {"email": bob.email, "role": "member"}).status_code == 409,
          "duplicate invite is 409")
    check(alice.call("POST", f"/orgs/{oid}/invites", {"email": "e@example.com", "role": "owner"}).status_code == 400,
          "cannot invite straight to owner")
    invites = bob.ok("GET", "/invites")
    check(len(invites) == 1 and invites[0]["org_name"] == "Equipo" and invites[0]["invited_by"] == alice.id,
          "bob sees his invite")
    check(carol.call("POST", f"/invites/{invites[0]['id']}/accept").status_code == 404,
          "someone else cannot accept bob's invite")
    bob.ok("POST", f"/invites/{invites[0]['id']}/accept")
    carol.ok("POST", f"/invites/{carol.ok('GET', '/invites')[0]['id']}/accept")
    dave.ok("POST", f"/invites/{dave.ok('GET', '/invites')[0]['id']}/accept")
    statuses = {m["email"]: m["status"] for m in alice.ok("GET", f"/orgs/{oid}/members")}
    check(statuses == {alice.email: "confirmed", bob.email: "accepted", carol.email: "accepted",
                       dave.email: "accepted"}, "accepted members wait for confirmation")
    check(bob.call("POST", f"/orgs/{oid}/members/{bob.id}/confirm").status_code in (403, 404),
          "a member cannot confirm himself")
    keys = alice.ok("GET", f"/users/{bob.id}/keys")
    check(keys["public_key"] and keys["signing_public_key"], "admin reads the keys of someone who accepted")
    outsider = Api(base).signup("eve@example.com")
    check(outsider.call("GET", f"/users/{alice.id}/keys").status_code == 404, "strangers cannot read keys")
    check(outsider.call("GET", f"/orgs/{oid}/members").status_code == 404, "non-member cannot see the org")
    for person in (bob, carol, dave):
        alice.ok("POST", f"/orgs/{oid}/members/{person.id}/confirm", {})
    check(bob.call("POST", f"/orgs/{oid}/invites", {"email": "f@example.com", "role": "member"}).status_code == 403,
          "plain member cannot invite")

    cid = str(uuid.uuid4())
    check(bob.call("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(),
                                                        "grant": bob.grant()}).status_code == 403,
          "plain member cannot create collections")
    check(alice.call("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(),
                                                          "grant": bob.grant()}).status_code == 400,
          "grant must be signed in the caller's name")
    alice.ok("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(), "grant": alice.grant()})
    cols = alice.ok("GET", "/collections")
    check(len(cols) == 1 and cols[0]["permission"] == "manage" and cols[0]["key_version"] == 1, "creator manages it")
    alice.ok("PUT", f"/collections/{cid}/members/{bob.id}", {"permission": "edit", "grant": alice.grant()})
    alice.ok("PUT", f"/collections/{cid}/members/{carol.id}", {"permission": "view", "grant": alice.grant()})
    alice.ok("PUT", f"/collections/{cid}/members/{dave.id}", {"permission": "use", "grant": alice.grant()})
    check(alice.call("PUT", f"/collections/{cid}/members/{outsider.id}",
                     {"permission": "view", "grant": alice.grant()}).status_code == 400,
          "only confirmed org members can be granted")
    check(bob.call("PUT", f"/collections/{cid}/members/{outsider.id}",
                   {"permission": "view", "grant": bob.grant()}).status_code == 403, "edit cannot grant")
    check(len(carol.ok("GET", f"/collections/{cid}/members")) == 4, "members list the collection's people")
    check(outsider.call("GET", f"/collections/{cid}/items").status_code == 404, "non-member gets 404 on items")

    item, item2 = str(uuid.uuid4()), str(uuid.uuid4())
    path = f"/collections/{cid}/items/{item}"
    r1 = alice.ok("PUT", path, {"ciphertext": box(300), "key_version": 1, "base_revision": 0})["revision"]
    stale = bob.call("PUT", path, {"ciphertext": box(300), "key_version": 1, "base_revision": 0})
    check(r1 == 1 and stale.status_code == 409 and stale.json()["revision"] == 1, "stale base_revision is 409")
    r2 = bob.ok("PUT", path, {"ciphertext": box(300), "key_version": 1, "base_revision": 1})["revision"]
    check(r2 == 2, "edit member updates with the right base_revision")
    for person, label in ((carol, "view"), (dave, "use")):
        response = person.call("PUT", path, {"ciphertext": box(300), "key_version": 1, "base_revision": 2})
        check(response.status_code == 403, f"'{label}' member cannot write")
    check(carol.call("DELETE", path, {"base_revision": 2}).status_code == 403, "'view' member cannot delete")
    listing = dave.ok("GET", f"/collections/{cid}/items?since=0")
    check(listing["revision"] == 2 and [i["revision"] for i in listing["items"]] == [2]
          and listing["items"][0]["updated_by"] == bob.id, "'use' member reads the ciphertext")
    check(dave.ok("GET", f"/collections/{cid}/items?since=2")["items"] == [], "since skips what was seen")
    check(bob.call("PUT", path, {"ciphertext": box(), "key_version": 2, "base_revision": 2}).json()["code"]
          == "key_version", "wrong key_version is refused")
    check(bob.call("PUT", path, {"ciphertext": {"nonce": "!!", "ciphertext": "x"}, "key_version": 1,
                                 "base_revision": 2}).status_code == 400, "bad base64 is 400")
    check(bob.call("PUT", f"/collections/{cid}/items/not-a-uuid",
                   {"ciphertext": box(), "key_version": 1, "base_revision": 0}).status_code == 404, "bad id is 404")
    check(bob.call("DELETE", path, {"base_revision": 1}).status_code == 409, "delete with stale base is 409")
    r3 = bob.ok("DELETE", path, {"base_revision": 2})["revision"]
    tomb = carol.ok("GET", f"/collections/{cid}/items?since=2")["items"]
    check(r3 == 3 and tomb[0]["deleted"] and tomb[0]["ciphertext"] is None, "delete leaves a tombstone")
    r4 = alice.ok("PUT", f"/collections/{cid}/items/{item2}",
                  {"ciphertext": box(), "key_version": 1, "base_revision": 0})["revision"]
    check(r4 == 4, "revisions are collection-wide")

    # Offboarding: carol leaves the org; the collection needs a new key before anyone else gets it.
    removed = alice.ok("DELETE", f"/orgs/{oid}/members/{carol.id}")
    check(removed["needs_rekey"] == [cid], "removing a member reports the collections to re-key")
    check(carol.call("GET", f"/collections/{cid}/items").status_code == 404, "removed member loses access")
    check(carol.ok("GET", "/collections") == [], "removed member sees no collections")
    check(alice.ok("GET", "/collections")[0]["needs_rekey"], "collection is marked needs_rekey")
    blocked = alice.call("PUT", f"/collections/{cid}/members/{outsider.id}",
                         {"permission": "view", "grant": alice.grant()})
    check(blocked.status_code == 409 and blocked.json()["code"] == "needs_rekey", "no new grants until re-keyed")

    grants = {uid: alice.grant() for uid in (alice.id, bob.id, dave.id)}
    rot = f"/collections/{cid}/rotate"
    full = {"key_version": 2, "encrypted_name": box(), "grants": grants, "items": {item2: box()}}
    attempts = [
        ({**full, "grants": {alice.id: grants[alice.id], bob.id: grants[bob.id]}}, 400, "a member left out"),
        ({**full, "grants": {**grants, carol.id: alice.grant()}}, 400, "a removed member included"),
        ({**full, "items": {}}, 400, "an item left out"),
        ({**full, "items": {item2: box(), item: box()}}, 400, "a deleted item included"),
        ({**full, "key_version": 3}, 409, "a skipped key version"),
    ]
    for body, status, label in attempts:
        check(alice.call("POST", rot, body).status_code == status, f"rotate refuses {label}")
    check(bob.call("POST", rot, {**full, "grants": {u: bob.grant() for u in grants}}).status_code == 403,
          "'edit' member cannot rotate")
    check(alice.ok("GET", "/collections")[0]["key_version"] == 1, "failed rotations change nothing")
    r5 = alice.ok("POST", rot, full)["revision"]
    col = bob.ok("GET", "/collections")[0]
    check(r5 == 5 and col["key_version"] == 2 and not col["needs_rekey"] and col["grant"] == grants[bob.id],
          "rotate bumps key_version, clears needs_rekey and hands out new grants")
    changed = bob.ok("GET", f"/collections/{cid}/items?since=4")["items"]
    check([(i["id"], i["key_version"], i["revision"]) for i in changed] == [(item2, 2, 5)],
          "rotated items come back with the new key version")
    check(bob.call("PUT", f"/collections/{cid}/items/{item2}",
                   {"ciphertext": box(), "key_version": 1, "base_revision": 5}).status_code == 409,
          "writes with the old key are refused")
    alice.ok("DELETE", f"/collections/{cid}/members/{dave.id}")
    check(dave.call("GET", f"/collections/{cid}/items").status_code == 404, "revoked collection member loses access")
    check(alice.ok("GET", "/collections")[0]["needs_rekey"], "revoking a collection member also needs a re-key")
    check(alice.call("DELETE", f"/collections/{cid}/members/{alice.id}").json().get("code") == "last_manager",
          "the last manager cannot leave")

    print("Roles and events")
    check(bob.call("PATCH", f"/orgs/{oid}/members/{dave.id}", {"role": "admin"}).status_code == 403,
          "member cannot change roles")
    alice.ok("PATCH", f"/orgs/{oid}/members/{bob.id}", {"role": "admin"})
    check(bob.call("PATCH", f"/orgs/{oid}/members/{alice.id}", {"role": "member"}).status_code == 403,
          "admin cannot demote an owner")
    check(alice.call("PATCH", f"/orgs/{oid}/members/{alice.id}", {"role": "admin"}).json().get("code")
          == "last_owner", "the last owner stays owner")
    check(alice.call("DELETE", f"/orgs/{oid}/members/{alice.id}").json().get("code") == "last_owner",
          "the last owner cannot leave")
    check(dave.call("GET", f"/orgs/{oid}/events").status_code == 403, "members cannot read events")
    events = alice.ok("GET", f"/orgs/{oid}/events")
    actions = {e["action"] for e in events}
    wanted = {"org.create", "invite", "join", "member.confirm", "collection.create", "grant", "item.put",
              "item.delete", "member.remove", "rotate", "revoke", "member.role"}
    check(wanted <= actions, "events record the metadata of every change")
    check(all(set(e) == {"id", "time", "actor", "action", "target"} for e in events), "events carry no contents")
    older = alice.ok("GET", f"/orgs/{oid}/events?before={events[2]['id']}")
    check(older and all(e["id"] < events[2]["id"] for e in older), "events page with before")
    check(bob.call("DELETE", f"/collections/{cid}").status_code == 403, "only manage deletes a collection")
    alice.ok("DELETE", f"/collections/{cid}")
    check(bob.ok("GET", "/collections") == [], "deleted collection is gone")


def test_invite_signups():
    print("Invite-only signups")
    base, stop, settings = start(signups="invite", admin_emails=frozenset({"root@example.com"}))
    try:
        stranger = Api(base)
        response = stranger.register("stranger@example.com")
        check(response.status_code == 403 and response.json()["code"] == "invite_required", "no invite, no account")
        root = Api(base).signup("root@example.com")
        token = root.ok("POST", "/admin/invites", {"days": 2})["token"]
        check(stranger.register("stranger@example.com", token).status_code == 200, "a signup token lets you in")
        check(Api(base).register("again@example.com", token).status_code == 403, "signup tokens are single use")
        stranger.token = stranger.login().json()["token"]
        check(stranger.call("POST", "/admin/invites", {}).status_code == 403, "only server admins make tokens")
        oid = root.ok("POST", "/orgs", {"name": "Org"})["id"]
        invite_id = root.ok("POST", f"/orgs/{oid}/invites", {"email": "new@example.com", "role": "member"})["id"]
        check(Api(base).register("other@example.com", invite_id).status_code == 403,
              "an org invite only works for its e-mail")
        check(Api(base).register("new@example.com", invite_id).status_code == 200, "an org invite lets its e-mail in")

        print("Rate limiting per IP")
        codes = [stranger.login(email=f"probe{i}@example.com").status_code for i in range(20)]
        check(codes == [401] * 20 and stranger.login(email="probe@example.com").status_code == 429,
              "many failures from one address are throttled")
    finally:
        stop()
    base, stop, _ = start(signups="closed")
    try:
        check(Api(base).register("x@example.com").json()["code"] == "signups_closed", "closed server refuses signups")
    finally:
        stop()


def main():
    test_config()
    base, stop, settings = start()
    try:
        alice = test_accounts(base)
        test_rate_limit(base)
        test_orgs_and_items(base, alice)
        secret_file = settings.data_dir / "server_secret"
        check(secret_file.exists() and len(secret_file.read_text().strip()) == 64, "server secret is persisted")
    finally:
        stop()
    test_invite_signups()
    print("\nAll good." if not failures else f"\n{failures} check(s) failed.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
