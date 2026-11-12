"""SecretBroker Server API checks against a real uvicorn on a random port, with a throwaway data folder.

Only fake key material is used: the server never decrypts anything, so random bytes of the right size will do.
Run with:  .venv\\Scripts\\python.exe server\\tests\\test_server.py
"""

import base64
import os
import re
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

from secretbroker_server import config, mail  # noqa: E402
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
    # Verification is tested on its own (test_email_verification); elsewhere it is off, as a self-hoster may set.
    settings = config.Settings(data_dir=data, public_url="http://127.0.0.1", allow_http=True, signups="open",
                               email_verification="off")
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
    stolen = alice.call("POST", "/accounts/password", {"current_auth_hash": rand(32), "kdf": kdf(),
                                                       "auth_hash": rand(32), "private_blob": box(200)})
    check(stolen.status_code == 403 and stolen.json()["code"] == "invalid_credentials"
          and alice.call("GET", "/me", token=tablet).status_code == 200,
          "a session alone cannot change the password: the current one is required")
    check(alice.call("POST", "/accounts/password", {"kdf": kdf(), "auth_hash": rand(32),
                                                    "private_blob": box(200)}).status_code == 400,
          "the current password is a required field")
    alice.ok("POST", "/accounts/password", {"current_auth_hash": alice.auth_hash, "kdf": kdf(), "auth_hash": new_hash,
                                            "private_blob": box(200)})
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


def test_direct_collections(base, alice):
    print("Sharing with one person (direct collections)")
    frank, gina, hugo = (Api(base).signup(f"{n}@direct.example") for n in ("frank", "gina", "hugo"))
    oid = alice.ok("POST", "/orgs", {"name": "Directo"})["id"]
    for person in (frank, gina, hugo):
        alice.ok("POST", f"/orgs/{oid}/invites", {"email": person.email, "role": "member"})
        person.ok("POST", f"/invites/{person.ok('GET', '/invites')[0]['id']}/accept")
        alice.ok("POST", f"/orgs/{oid}/members/{person.id}/confirm", {})
    cid = str(uuid.uuid4())
    body = {"id": cid, "encrypted_name": box(), "grant": frank.grant()}
    check(frank.call("POST", f"/orgs/{oid}/collections", body).status_code == 403,
          "a plain member still cannot create a team collection")
    check(frank.call("POST", f"/orgs/{oid}/collections", {**body, "direct": "yes"}).status_code == 400,
          "direct must be a boolean")
    frank.ok("POST", f"/orgs/{oid}/collections", {**body, "direct": True})
    listed = next(c for c in frank.ok("GET", "/collections") if c["id"] == cid)
    check(listed["direct"] and listed["permission"] == "manage", "but may share with one person: a direct collection")
    frank.ok("PUT", f"/collections/{cid}/members/{gina.id}", {"permission": "view", "grant": frank.grant()})
    refused = frank.call("PUT", f"/collections/{cid}/members/{hugo.id}", {"permission": "view", "grant": frank.grant()})
    check(refused.status_code == 400 and refused.json()["code"] == "direct_full", "it never has more than two members")
    team = str(uuid.uuid4())
    alice.ok("POST", f"/orgs/{oid}/collections", {"id": team, "encrypted_name": box(), "grant": alice.grant()})
    check(not next(c for c in alice.ok("GET", "/collections") if c["id"] == team)["direct"],
          "team collections are not direct")
    removed = alice.ok("DELETE", f"/orgs/{oid}/members/{frank.id}")
    check(removed.get("deleted") == [cid] and cid not in removed["needs_rekey"]
          and not any(c["id"] == cid for c in gina.ok("GET", "/collections")),
          "removing the person who shared deletes what they shared directly (nobody else could manage it)")
    cid2 = str(uuid.uuid4())
    gina.ok("POST", f"/orgs/{oid}/collections", {"id": cid2, "encrypted_name": box(), "grant": gina.grant(),
                                                 "direct": True})
    gina.ok("PUT", f"/collections/{cid2}/members/{hugo.id}", {"permission": "edit", "grant": gina.grant()})
    removed = alice.ok("DELETE", f"/orgs/{oid}/members/{hugo.id}")
    check(removed["needs_rekey"] == [cid2] and not removed.get("deleted")
          and next(c for c in gina.ok("GET", "/collections") if c["id"] == cid2)["needs_rekey"],
          "removing the person it was shared with leaves it to its manager to re-key (or end)")


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
    batch = alice.ok("GET", f"/users/keys?ids={bob.id},{carol.id},{outsider.id},{bob.id}")
    check(sorted(k["id"] for k in batch) == sorted([bob.id, carol.id]) and all(k["public_key"] for k in batch),
          "keys of several people in one request, strangers left out")
    check(outsider.ok("GET", f"/users/keys?ids={alice.id},{bob.id}") == [], "a stranger gets nobody's keys in a batch")
    check(alice.call("GET", "/users/keys?ids=nope").status_code == 400
          and alice.call("GET", "/users/keys?ids=" + ",".join(str(uuid.uuid4()) for _ in range(201))).status_code == 400,
          "batch ids are checked and limited")
    check(outsider.call("GET", f"/orgs/{oid}/members").status_code == 404, "non-member cannot see the org")
    for person in (bob, carol, dave):
        alice.ok("POST", f"/orgs/{oid}/members/{person.id}/confirm", {})
    check(bob.call("POST", f"/orgs/{oid}/invites", {"email": "f@example.com", "role": "member"}).status_code == 403,
          "plain member cannot invite")
    alice.ok("POST", f"/orgs/{oid}/invites", {"email": "later@example.com", "role": "member"})
    seen = lambda person: next(m for m in person.ok("GET", f"/orgs/{oid}/members") if m["email"] == "later@example.com")
    check("invite_id" not in seen(bob) and seen(alice)["invite_id"],
          "only admins see invite ids (they work as signup tokens for that e-mail)")

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

    # A collection whose only manager is removed from the org could never be re-keyed again.
    solo = str(uuid.uuid4())
    alice.ok("PATCH", f"/orgs/{oid}/members/{dave.id}", {"role": "admin"})
    dave.ok("POST", f"/orgs/{oid}/collections", {"id": solo, "encrypted_name": box(), "grant": dave.grant()})
    refused = alice.call("DELETE", f"/orgs/{oid}/members/{dave.id}")
    check(refused.status_code == 400 and refused.json()["code"] == "last_manager"
          and refused.json()["collections"] == [solo] and dave.ok("GET", f"/collections/{solo}/members"),
          "removing a collection's only manager from the org is refused")
    dave.ok("DELETE", f"/collections/{solo}")
    alice.ok("PATCH", f"/orgs/{oid}/members/{dave.id}", {"role": "member"})

    # Offboarding: carol leaves the org; the collection needs a new key before anyone else gets it.
    removed = alice.ok("DELETE", f"/orgs/{oid}/members/{carol.id}")
    check(removed["needs_rekey"] == [cid], "removing a member reports the collections to re-key")
    check(carol.call("GET", f"/collections/{cid}/items").status_code == 404, "removed member loses access")
    check(carol.ok("GET", "/collections") == [], "removed member sees no collections")
    check(alice.ok("GET", "/collections")[0]["needs_rekey"], "collection is marked needs_rekey")
    blocked = alice.call("PUT", f"/collections/{cid}/members/{outsider.id}",
                         {"permission": "view", "grant": alice.grant()})
    check(blocked.status_code == 409 and blocked.json()["code"] == "needs_rekey", "no new grants until re-keyed")
    stale_write = bob.call("PUT", f"/collections/{cid}/items/{item2}", {"ciphertext": box(), "key_version": 1,
                                                                         "base_revision": 4})
    check(stale_write.status_code == 409 and stale_write.json()["code"] == "needs_rekey",
          "no item is written with the key the removed member holds")

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


def cli_token(settings):
    """What `secretbroker-server create-invite` prints."""
    from secretbroker_server.accounts import create_token
    from secretbroker_server.db import Database
    db = Database(settings.db_path)
    with db.tx(write=True) as conn:
        token, _ = create_token(conn, None, 1)
    db.close()
    return token


def test_quota():
    print("Collection size")
    base, stop, _ = start(max_body=64 * 1024)
    try:
        owner = Api(base).signup("owner@example.com")
        oid = owner.ok("POST", "/orgs", {"name": "Q"})["id"]
        cid = str(uuid.uuid4())
        owner.ok("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(), "grant": owner.grant()})
        put = lambda: owner.call("PUT", f"/collections/{cid}/items/{uuid.uuid4()}",
                                 {"ciphertext": box(6 * 1024), "key_version": 1, "base_revision": 0})
        codes = [put().status_code for _ in range(3)]
        full = put()
        check(codes == [200] * 3 and full.status_code == 413 and full.json()["code"] == "collection_full",
              "a collection never grows past what one rotate request can carry")
    finally:
        stop()


def test_invite_signups():
    print("Invite-only signups")
    base, stop, settings = start(signups="invite", admin_emails=frozenset({"root@example.com"}))
    try:
        stranger = Api(base)
        response = stranger.register("stranger@example.com")
        check(response.status_code == 403 and response.json()["code"] == "invite_required", "no invite, no account")
        check(Api(base).register("root@example.com").status_code == 403,
              "an SB_ADMIN_EMAILS address cannot be taken without a token from the server's command line")
        root = Api(base)
        check(root.register("root@example.com", cli_token(settings)).status_code == 200, "with it, it can")
        root.token = root.login().json()["token"]
        check(root.ok("GET", "/me")["user"]["admin"], "and is server admin")
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
    base, stop, settings = start(signups="closed", admin_emails=frozenset({"ops@example.com"}))
    try:
        check(Api(base).register("x@example.com").json()["code"] == "signups_closed", "closed server refuses signups")
        check(Api(base).register("ops@example.com").status_code == 403, "even an admin e-mail needs a token")
        check(Api(base).register("ops@example.com", cli_token(settings)).status_code == 200,
              "the operator registers the admin e-mail with a command-line token")
    finally:
        stop()


class Outbox:
    """What the server would e-mail: secretbroker_server.mail.deliver replaced while a test runs."""

    def __init__(self):
        self.sent = []
        self._real = mail.deliver

    def __enter__(self):
        mail.deliver = lambda settings, msg: self.sent.append(msg)
        return self

    def __exit__(self, *exc):
        mail.deliver = self._real

    def code(self, to):
        for _ in range(100):  # sent from a background thread
            found = [m for m in self.sent if m["To"] == to]
            if found:
                return re.search(r"\b(\d{8})\b", found[-1].get_content()).group(1)
            time.sleep(0.05)
        raise AssertionError(f"no e-mail to {to}")


def test_email_verification():
    print("E-mail verification")
    try:
        config.Settings(data_dir=Path("."), public_url="https://x.example", smtp_host="smtp.example").check()
        check(False, "SMTP without a sender address is refused")
    except config.ConfigError:
        check(True, "SMTP without a sender address is refused")
    with Outbox() as outbox:
        base, stop, settings = start(email_verification="required", smtp_host="smtp.example",
                                     smtp_from="secrets@example.com")
        try:
            check(Api(base).ok("GET", "/info")["verification"] == "email", "info says codes are e-mailed")
            alice = Api(base)
            check(alice.register("alice@example.com").json()["verified"] is False, "a new account starts unverified")
            alice.token = alice.login().json()["token"]
            check(alice.ok("GET", "/me")["user"]["verified"] is False, "and says so")
            # Mallory registers Victor's address first, hoping to receive the invites sent to it.
            mallory = Api(base)
            mallory.register("victor@example.com")
            mallory.token = mallory.login().json()["token"]
            alice.ok("POST", "/accounts/verify", {"code": outbox.code("alice@example.com")})
            check(alice.ok("GET", "/me")["user"]["verified"], "the e-mailed code verifies the account")
            oid = alice.ok("POST", "/orgs", {"name": "Org"})["id"]
            invite_id = alice.ok("POST", f"/orgs/{oid}/invites", {"email": "victor@example.com", "role": "member"})["id"]
            check(mallory.ok("GET", "/invites") == [], "an unverified account sees no invites to its address")
            refused = mallory.call("POST", f"/invites/{invite_id}/accept")
            check(refused.status_code == 403 and refused.json()["code"] == "email_unverified",
                  "and cannot accept one even knowing its id")
            row = next(m for m in alice.ok("GET", f"/orgs/{oid}/members") if m["email"] == "victor@example.com")
            check(row["user_id"] is None and alice.call("GET", f"/users/{mallory.id}/keys").status_code == 404,
                  "the inviter is not shown the unverified account, nor its keys")
            for left in (4, 3):
                wrong = mallory.call("POST", "/accounts/verify", {"code": "00000000"})
                check(wrong.status_code == 400 and wrong.json()["code"] == "invalid_code"
                      and f"{left} intentos" in wrong.json()["error"], f"a wrong code is refused ({left} tries left)")
            for _ in range(3):
                mallory.call("POST", "/accounts/verify", {"code": "00000000"})
            outbox_code = outbox.code("victor@example.com")
            late = mallory.call("POST", "/accounts/verify", {"code": outbox_code})
            check(late.status_code == 400 and late.json()["code"] == "code_expired",
                  "after 5 wrong tries even the right code needs a new one")
            again = mallory.call("POST", "/accounts/verify/send", {})
            check(again.status_code == 429 and again.headers.get("retry-after"), "one new code a minute at most")
            check(mallory.ok("GET", "/me")["user"]["verified"] is False, "the address stays unverified")
            # The real owner can still get in: the admin verifies the right account from the command line.
            victim = Api(base)
            check(victim.register("bob@example.com", invite_token=None).json()["verified"] is False, "bob registers")
            bob_invite = alice.ok("POST", f"/orgs/{oid}/invites", {"email": "carol@example.com", "role": "member"})["id"]
            carol = Api(base)
            joined = carol.register("carol@example.com", bob_invite).json()
            check(joined["verified"] is False and joined["invited_to"] == oid,
                  "registering with an organization invite code (from its admin) proves the address to that org")
            carol.token = carol.login().json()["token"]
            check([i["id"] for i in carol.ok("GET", "/invites")] == [bob_invite], "and the invite is there")
            check(any(m["user_id"] == carol.id for m in alice.ok("GET", f"/orgs/{oid}/members"))
                  and alice.call("GET", f"/users/{carol.id}/keys").status_code == 200,
                  "the inviting org sees the account and its keys")
            # But any account can make an org and invite any address: its own invite code must not verify the
            # address for everybody else's invites (Mallory takes Dave's address with an invite she wrote).
            mallory_org = mallory.ok("POST", "/orgs", {"name": "Mallory"})["id"]
            own_code = mallory.ok("POST", f"/orgs/{mallory_org}/invites", {"email": "dave@example.com", "role": "member"})["id"]
            fake = Api(base)
            check(fake.register("dave@example.com", own_code).json()["verified"] is False,
                  "an invite code a stranger wrote does not verify the address")
            fake.token = fake.login().json()["token"]
            real = alice.ok("POST", f"/orgs/{oid}/invites", {"email": "dave@example.com", "role": "member"})["id"]
            check([i["org_id"] for i in fake.ok("GET", "/invites")] == [mallory_org],
                  "it sees only the invite of the org that handed out the code")
            refused = fake.call("POST", f"/invites/{real}/accept")
            check(refused.status_code == 403 and refused.json()["code"] == "email_unverified",
                  "and cannot accept another org's invite to that address")
            row = next(m for m in alice.ok("GET", f"/orgs/{oid}/members") if m["email"] == "dave@example.com")
            check(row["user_id"] is None and alice.call("GET", f"/users/{fake.id}/keys").status_code == 404,
                  "nor is it shown to that org as Dave, nor its keys")
            run_cli(settings, ["verify-email", "bob@example.com"])
            victim.token = victim.login().json()["token"]
            check(victim.ok("GET", "/me")["user"]["verified"], "the server admin verifies an account from the CLI")
            events = [e["action"] for e in alice.ok("GET", f"/orgs/{oid}/events")]
            check("invite" in events, "events still record invites")
        finally:
            stop()
    base, stop, settings = start(email_verification="required")
    try:
        check(Api(base).ok("GET", "/info")["verification"] == "admin", "without SMTP the admin verifies accounts")
        person = Api(base).signup("dan@example.com")
        answer = person.ok("POST", "/accounts/verify/send", {})
        check(answer["sent"] is False and answer["verification"] == "admin", "no e-mail is promised without SMTP")
    finally:
        stop()


def run_cli(settings, argv):
    """`secretbroker-server <argv>` against this test server's data folder."""
    from secretbroker_server import cli
    saved = dict(os.environ)
    os.environ.update(SB_DATA_DIR=str(settings.data_dir), SB_PUBLIC_URL="http://127.0.0.1", SB_ALLOW_HTTP="1")
    try:
        cli.main(argv)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def record(person, cid, seq, members, key_version=1, prev=None):
    """A signed member list as a client sends it (the signature is random: only clients check it)."""
    body = {"cid": cid, "seq": seq, "key_version": key_version, "by": person.id, "members": members,
            "at": "2026-10-31T10:00:00+00:00"}
    if prev:
        body["prev"] = prev
    return {"body": body, "signature": rand(64)}


def body_hash(body):
    import hashlib
    import json as _json
    return hashlib.sha256(_json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def test_signed_lists_and_deletions():
    print("Signed member lists, signed deletions and the deletion limit")
    base, stop, _ = start(max_deletes_per_hour=3)
    try:
        alice, bob = Api(base).signup("alice@example.com"), Api(base).signup("bob@example.com")
        oid = alice.ok("POST", "/orgs", {"name": "Org"})["id"]
        bob.ok("POST", f"/invites/{alice.ok('POST', f'/orgs/{oid}/invites', {'email': bob.email, 'role': 'member'})['id']}/accept")
        alice.ok("POST", f"/orgs/{oid}/members/{bob.id}/confirm", {})
        cid = str(uuid.uuid4())
        first = record(alice, cid, 1, {alice.id: "manage"})
        alice.ok("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(), "grant": alice.grant(),
                                                      "members_record": first})
        grant = {"permission": "edit", "grant": alice.grant()}
        missing = alice.call("PUT", f"/collections/{cid}/members/{bob.id}", grant)
        check(missing.status_code == 400 and missing.json()["code"] == "members_record",
              "once a collection has a signed member list, a change without the next one is refused")
        wrong = alice.call("PUT", f"/collections/{cid}/members/{bob.id}", {**grant, "members_record": record(
            alice, cid, 2, {alice.id: "manage", bob.id: "view"}, prev=body_hash(first["body"]))})
        check(wrong.status_code == 400 and "miembros" in wrong.json()["error"],
              "a signed list that does not describe the change is refused")
        broken = alice.call("PUT", f"/collections/{cid}/members/{bob.id}", {**grant, "members_record": record(
            alice, cid, 2, {alice.id: "manage", bob.id: "edit"}, prev="0" * 64)})
        check(broken.status_code == 400, "a list that does not follow the previous one is refused")
        second = record(alice, cid, 2, {alice.id: "manage", bob.id: "edit"}, prev=body_hash(first["body"]))
        forged = {**second, "body": {**second["body"], "by": bob.id}}
        check(alice.call("PUT", f"/collections/{cid}/members/{bob.id}",
                         {**grant, "members_record": forged}).status_code == 400, "a list signed in someone else's name is refused")
        alice.ok("PUT", f"/collections/{cid}/members/{bob.id}", {**grant, "members_record": second})
        chain = bob.ok("GET", f"/collections/{cid}/manifest?since=0")["records"]
        check(chain == [first, second], "members read the whole chain exactly as it was signed")
        check(bob.ok("GET", f"/collections/{cid}/manifest?since=1")["records"] == [second], "or what is new")

        items = [str(uuid.uuid4()) for _ in range(5)]
        for iid in items:
            alice.ok("PUT", f"/collections/{cid}/items/{iid}", {"ciphertext": box(), "key_version": 1, "base_revision": 0})
        listing = {i["id"]: i["revision"] for i in bob.ok("GET", f"/collections/{cid}/items")["items"]}
        signature = {"by": bob.id, "seq": 2, "signature": rand(64)}
        check(bob.call("DELETE", f"/collections/{cid}/items/{items[0]}",
                       {"base_revision": listing[items[0]], "deletion": {**signature, "by": alice.id}}).status_code == 400,
              "a deletion signed in someone else's name is refused")
        for iid in items[:3]:
            bob.ok("DELETE", f"/collections/{cid}/items/{iid}", {"base_revision": listing[iid], "deletion": signature})
        tomb = next(i for i in alice.ok("GET", f"/collections/{cid}/items")["items"] if i["id"] == items[0])
        check(tomb["deleted"] and tomb["deletion"] == signature, "the deleter's signature travels with the tombstone")
        limited = bob.call("DELETE", f"/collections/{cid}/items/{items[3]}",
                           {"base_revision": listing[items[3]], "deletion": signature})
        check(limited.status_code == 429 and limited.json()["code"] == "rate_limited" and limited.headers.get("retry-after"),
              "one account cannot delete more than SB_MAX_DELETES_PER_HOUR items an hour")
        alice.ok("DELETE", f"/collections/{cid}/items/{items[3]}", {"base_revision": listing[items[3]]})
        check(True, "the limit is per account")
        alice.ok("PUT", f"/collections/{cid}/items/{items[0]}",
                 {"ciphertext": box(), "key_version": 1, "base_revision": tomb["revision"]})
        revived = next(i for i in bob.ok("GET", f"/collections/{cid}/items")["items"] if i["id"] == items[0])
        check(not revived["deleted"] and "deletion" not in revived, "writing a deleted item again clears its tombstone")

        third = record(alice, cid, 3, {alice.id: "manage"}, prev=body_hash(second["body"]))
        alice.ok("DELETE", f"/collections/{cid}/members/{bob.id}", {"members_record": third})
        live = [i["id"] for i in alice.ok("GET", f"/collections/{cid}/items")["items"] if not i["deleted"]]
        rot = {"key_version": 2, "encrypted_name": box(), "grants": {alice.id: alice.grant()},
               "items": {iid: box() for iid in live}}
        check(alice.call("POST", f"/collections/{cid}/rotate", rot).json()["code"] == "members_record",
              "a re-key needs the next signed list too")
        stale = record(alice, cid, 4, {alice.id: "manage"}, prev=body_hash(third["body"]))
        check(alice.call("POST", f"/collections/{cid}/rotate", {**rot, "members_record": stale}).status_code == 400,
              "with the new key version in it")
        alice.ok("POST", f"/collections/{cid}/rotate", {**rot, "members_record": record(
            alice, cid, 4, {alice.id: "manage"}, key_version=2, prev=body_hash(third["body"]))})
        check(len(alice.ok("GET", f"/collections/{cid}/manifest")["records"]) == 4, "and it is appended")
        alice.ok("DELETE", f"/collections/{cid}")
        check(alice.call("GET", f"/collections/{cid}/manifest").status_code == 404, "deleting a collection deletes its lists")
    finally:
        stop()


def test_account_data():
    print("The account's own encrypted data")
    base, stop, _ = start()
    try:
        alice = Api(base).signup("alice@example.com")
        check(alice.ok("GET", "/me/data") == {"blob": None, "revision": 0}, "empty at first")
        blob = box(500)
        check(alice.ok("PUT", "/me/data", {"blob": blob, "base_revision": 0})["revision"] == 1, "a device stores it")
        stale = alice.call("PUT", "/me/data", {"blob": box(), "base_revision": 0})
        check(stale.status_code == 409 and stale.json()["revision"] == 1, "another device must start from the latest")
        check(alice.ok("GET", "/me/data") == {"blob": blob, "revision": 1}, "every device reads the same")
        other = Api(base).signup("bob@example.com")
        check(other.ok("GET", "/me/data")["blob"] is None, "each account has its own")
    finally:
        stop()


def test_migration():
    print("Upgrading a database from 0.15")
    import sqlite3
    from secretbroker_server.db import Database
    data = Path(tempfile.mkdtemp(prefix="sb-server-old-"))
    conn = sqlite3.connect(data / "secretbroker.db")
    conn.executescript("""
        CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kdf TEXT NOT NULL,
            auth_salt TEXT NOT NULL, auth_verifier TEXT NOT NULL, public_key TEXT NOT NULL,
            signing_public_key TEXT NOT NULL, private_blob TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL);
        CREATE TABLE items (collection_id TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
            key_version INTEGER NOT NULL, ciphertext TEXT, deleted INTEGER NOT NULL DEFAULT 0, updated_by TEXT NOT NULL,
            updated TEXT NOT NULL, PRIMARY KEY (collection_id, id));
        INSERT INTO users VALUES ('u1', 'old@example.com', 'Old', '{}', 's', 'v', 'p', 'sp', '{}', 0, '');""")
    conn.commit()
    conn.close()
    db = Database(data / "secretbroker.db")
    row = db.conn().execute("SELECT verified FROM users WHERE id = 'u1'").fetchone()
    columns = {r[1] for r in db.conn().execute("PRAGMA table_info(items)").fetchall()}
    check(row["verified"] == 1 and "deletion" in columns, "accounts that existed count as verified; tombstones get signatures")
    columns = {r[1] for r in db.conn().execute("PRAGMA table_info(collections)").fetchall()}
    check("direct" in columns, "collections can be direct shares")
    db.close()


def main():
    test_config()
    base, stop, settings = start()
    try:
        alice = test_accounts(base)
        test_rate_limit(base)
        test_orgs_and_items(base, alice)
        test_direct_collections(base, alice)
        secret_file = settings.data_dir / "server_secret"
        check(secret_file.exists() and len(secret_file.read_text().strip()) == 64, "server secret is persisted")
    finally:
        stop()
    test_invite_signups()
    test_quota()
    test_email_verification()
    test_signed_lists_and_deletions()
    test_account_data()
    test_migration()
    print("\nAll good." if not failures else f"\n{failures} check(s) failed.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
