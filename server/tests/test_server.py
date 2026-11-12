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
    twice = Api(base)
    again = twice.register("alice@example.com")
    check(again.status_code == 200 and set(again.json()) == {"user_id", "verified"},
          "registering a taken e-mail answers like a new account (it tells nobody the address has one)")
    check(twice.login().status_code == 401, "but nothing was created: that login fails")
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
    check(invites[0]["invited_by_public_key"] and invites[0]["invited_by_signing_public_key"],
          "with the inviter's public keys, so the app can show their security code before accepting")
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
            found = [m for m in self.sent if m["To"] == to and "código" in m["Subject"]]
            if found:
                return re.search(r"\b(\d{8})\b", found[-1].get_content()).group(1)
            time.sleep(0.05)
        raise AssertionError(f"no e-mail to {to}")

    def invites(self, to):
        return [m for m in self.sent if m["To"] == to and "invita" in m["Subject"]]


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
            unverified_invite = mallory.ok("POST", f"/orgs/{mallory_org}/invites", {"email": "dave@example.com", "role": "member"})
            own_code = unverified_invite["id"]
            check(unverified_invite["emailed"] is False and not outbox.invites("dave@example.com"),
                  "an account that has not verified its e-mail can invite, but the server e-mails nothing for it")
            check(mallory.ok("POST", f"/orgs/{mallory_org}/invites/{own_code}/send", {}) == {"emailed": False},
                  "nor when re-sending")
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


def server_db(settings, sql, args=()):
    """Change the server's database behind its back (time passing, for instance)."""
    import sqlite3
    conn = sqlite3.connect(settings.db_path)
    try:
        rows = conn.execute(sql, args).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def cli_out(settings, argv):
    """`secretbroker-server <argv>`: (exit code, everything it printed)."""
    import contextlib
    import io
    out = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            run_cli(settings, argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            if not isinstance(exc.code, int) and exc.code:
                print(exc.code)
    return code, out.getvalue()


def test_invite_lifecycle():
    print("Invites by e-mail, expiry, renewal and re-sending")
    with Outbox() as outbox:
        base, stop, settings = start(smtp_host="smtp.example", smtp_from="secrets@example.com", max_invites_per_hour=6,
                                     public_url="https://secrets.example.com", allow_http=True)
        try:
            check(Api(base).ok("GET", "/info")["mail"] is True, "info says the server sends e-mail")
            alice = Api(base).signup("alice@example.com")
            oid = alice.ok("POST", "/orgs", {"name": "Acme"})["id"]
            answer = alice.ok("POST", f"/orgs/{oid}/invites", {"email": "bob@example.com", "role": "member"})
            sent = outbox.invites("bob@example.com")
            check(answer["emailed"] is True and answer["expires"] and len(sent) == 1, "the invite is e-mailed")
            text = sent[0].get_content()
            link = f"secretbroker://join?server=https%3A%2F%2Fsecrets.example.com&email=bob%40example.com&code={answer['id']}"
            check(link in text and "https://github.com/xBofi/SecretBroker/releases/latest" in text
                  and "Acme" in text and "Alice (alice@example.com)" in text,
                  "with the join link, where to download SecretBroker and who invites")
            check(alice.token not in text and alice.auth_hash not in text and "Nadie te pedirá nunca tu contraseña" in text,
                  "and nothing secret (it says nobody will ask for a password)")
            row = next(m for m in alice.ok("GET", f"/orgs/{oid}/members") if m["email"] == "bob@example.com")
            check(row["emailed"] is True and row["expired"] is False and row["expires"] == answer["expires"],
                  "the admin sees it was e-mailed and when it expires")
            from datetime import datetime
            days = (datetime.fromisoformat(answer["expires"]).timestamp() - time.time()) / 86400
            check(13.9 < days < 14.1, "invites last 14 days by default")
            again = alice.call("POST", f"/orgs/{oid}/invites/{answer['id']}/send", {})
            check(again.status_code == 429 and again.headers.get("retry-after"), "re-sending at once is refused")
            server_db(settings, "UPDATE invites SET sent = sent - 3600")
            check(alice.ok("POST", f"/orgs/{oid}/invites/{answer['id']}/send", {})["emailed"]
                  and len(outbox.invites("bob@example.com")) == 2, "a pending invite can be re-sent")
            bob = Api(base).signup("bob@example.com")
            check(len(bob.ok("GET", "/invites")) == 1, "bob sees it")
            server_db(settings, "UPDATE invites SET expires = ?", (int(time.time()) - 1,))
            row = next(m for m in alice.ok("GET", f"/orgs/{oid}/members") if m["email"] == "bob@example.com")
            check(row["expired"] is True and row["status"] == "invited", "an expired invite shows as expired")
            check(bob.ok("GET", "/invites") == [], "the invitee no longer sees it")
            gone = bob.call("POST", f"/invites/{answer['id']}/accept")
            check(gone.status_code == 410 and gone.json()["code"] == "invite_expired", "nor can accept it")
            check(alice.call("POST", f"/orgs/{oid}/invites/{answer['id']}/send", {}).status_code == 410,
                  "an expired invite is renewed, not re-sent")
            renewed = alice.ok("POST", f"/orgs/{oid}/invites/{answer['id']}/renew", {})
            check(renewed["id"] != answer["id"] and renewed["emailed"] and len(outbox.invites("bob@example.com")) == 3
                  and renewed["id"] in outbox.invites("bob@example.com")[-1].get_content(),
                  "renewing makes a new code and e-mails it")
            check(bob.call("POST", f"/invites/{answer['id']}/accept").status_code == 404, "the old code stops working")
            check(bob.ok("GET", "/invites")[0]["id"] == renewed["id"], "the new one is there")
            check(alice.call("POST", f"/orgs/{oid}/invites", {"email": "bob@example.com", "role": "member"}).status_code == 409,
                  "a pending invite is not duplicated")
            server_db(settings, "UPDATE invites SET expires = ?", (int(time.time()) - 1,))
            check(alice.ok("POST", f"/orgs/{oid}/invites", {"email": "bob@example.com", "role": "admin"})["emailed"],
                  "inviting again replaces an expired invite")
            check(bob.call("POST", f"/orgs/{oid}/invites/{renewed['id']}/renew", {}).status_code in (403, 404),
                  "only org admins renew")
            events = [(e["action"], e["target"]) for e in alice.ok("GET", f"/orgs/{oid}/events")]
            check(("invite.renew", "bob@example.com") in events and ("invite.send", "bob@example.com") in events,
                  "renewals and re-sends are in the audit log")
            limited = None
            for n in range(10):
                limited = alice.call("POST", f"/orgs/{oid}/invites", {"email": f"p{n}@example.com", "role": "member"})
                if limited.status_code != 200:
                    break
            check(limited.status_code == 429 and limited.headers.get("retry-after") and n == 2,
                  f"at most SB_MAX_INVITES_PER_HOUR invites an hour per organization (stopped after {n})")
            check(not any("código" in m["Subject"] for m in outbox.sent if m["To"].startswith("p")),
                  "no verification code went to people only invited")
        finally:
            stop()
    base, stop, settings = start()
    try:
        alice = Api(base).signup("alice@example.com")
        oid = alice.ok("POST", "/orgs", {"name": "Sin correo"})["id"]
        answer = alice.ok("POST", f"/orgs/{oid}/invites", {"email": "bob@example.com", "role": "member"})
        check(answer["emailed"] is False and Api(base).ok("GET", "/info")["mail"] is False,
              "without SMTP nothing is e-mailed, and the answer says so")
        check(alice.ok("POST", f"/orgs/{oid}/invites/{answer['id']}/send", {}) == {"emailed": False},
              "re-sending without SMTP says it was not e-mailed")
    finally:
        stop()


def test_mail_texts():
    print("Names in e-mails")
    with Outbox() as outbox:
        base, stop, settings = start(smtp_host="smtp.example", smtp_from="secrets@example.com",
                                     public_url="https://secrets.example.com", allow_http=True)
        try:
            alice = Api(base).signup("alice@example.com")
            for name in ("Acme\u2028Bcc: x@evil.example", "Acme\x85x", "Acme\u202egnp.exe", "Acme\x7f"):
                response = alice.call("POST", "/orgs", {"name": name})
                check(response.status_code == 400, f"an organization name with a control or separator character is refused ({name!r})")
            weird = Api(base)
            weird.id, weird.email, weird.auth_hash = str(uuid.uuid4()), "weird@example.com", rand(32)
            response = weird.call("POST", "/accounts/register", {
                "user_id": weird.id, "email": weird.email, "name": "Eve\u2029Subject: hi", "kdf": kdf(),
                "auth_hash": weird.auth_hash, "public_key": rand(32), "signing_public_key": rand(32), "private_blob": box(200)})
            check(response.status_code == 400, "so is a person's name")
            check(alice.call("POST", "/orgs", {"name": "Acme éè \U0001F468\u200d\U0001F4BB"}).status_code == 200,
                  "accents and emoji are fine")
            oid = alice.ok("POST", "/orgs", {"name": "Acme"})["id"]
            alice.ok("POST", f"/orgs/{oid}/invites", {"email": "bob@example.com", "role": "member"})
            subject = outbox.invites("bob@example.com")[-1]["Subject"]
            check("Acme" not in subject and "Alice" not in subject and "alice" not in subject,
                  f"the subject has no free text (the organization and inviter only go in the body): {subject}")
            server_db(settings, "UPDATE orgs SET name = ? WHERE id = ?", ("Vieja\u2028org", oid))  # from before the check
            response = alice.call("POST", f"/orgs/{oid}/invites", {"email": "carol@example.com", "role": "member"})
            check(response.status_code == 200 and response.json()["emailed"] is True
                  and "Vieja org" in outbox.invites("carol@example.com")[-1].get_content(),
                  "a name saved before the check is written as plain text in the e-mail")
            real = mail.invite_message
            mail.invite_message = lambda *args: (_ for _ in ()).throw(ValueError("Header values may not contain linefeed"))
            try:
                response = alice.call("POST", f"/orgs/{oid}/invites", {"email": "dan@example.com", "role": "member"})
            finally:
                mail.invite_message = real
            check(response.status_code == 200 and response.json()["emailed"] is False
                  and any(m["email"] == "dan@example.com" for m in alice.ok("GET", f"/orgs/{oid}/members")),
                  "an e-mail that can't be written is not sent, and the invite answers normally (no error after saving it)")
        finally:
            stop()


def test_versions_and_health():
    print("Version compatibility and health")
    from secretbroker_server.accounts import health
    base, stop, settings = start()
    try:
        anon = Api(base)
        info = anon.ok("GET", "/info")
        check(info["api"] == config.API_VERSION and info["min_client"] == config.MIN_CLIENT, "info has api and min_client")
        alice = Api(base).signup("alice@example.com")
        old = alice.http.get("/me", headers={"Authorization": f"Bearer {alice.token}", "X-SecretBroker-Version": "0.15.3"})
        check(old.status_code == 426 and old.json()["code"] == "client_too_old"
              and old.json()["min_client"] == config.MIN_CLIENT, "an app older than min_client gets 426 client_too_old")
        for header, label in (({}, "no version header (0.16 apps)"), ({"X-SecretBroker-Version": "0.17.0"}, "a current app"),
                              ({"X-SecretBroker-Version": "nonsense"}, "an unreadable version")):
            answer = alice.http.get("/me", headers={"Authorization": f"Bearer {alice.token}", **header})
            check(answer.status_code == 200, f"{label} is served")
        check(anon.http.get("/info", headers={"X-SecretBroker-Version": "0.1.0"}).status_code == 200,
              "info answers any app, so it can tell its user to update")
        health_answer = anon.http.get("/health", headers={"X-SecretBroker-Version": "0.1.0"})
        check(health_answer.status_code == 200 and health_answer.json() == {"status": "ok"},
              "health answers without auth and says nothing else")
    finally:
        stop()
    base, stop, settings = start(min_client="0.99.0")
    try:
        check(Api(base).ok("GET", "/info")["min_client"] == "0.99.0", "SB_MIN_CLIENT raises the minimum")
        person = Api(base).signup("bob@example.com")
        check(person.http.get("/me", headers={"Authorization": f"Bearer {person.token}",
                                              "X-SecretBroker-Version": "0.17.0"}).status_code == 426,
              "and apps below it are told to update")
    finally:
        stop()
    try:
        config.Settings(data_dir=Path("."), public_url="https://x.example", min_client="latest").check()
        check(False, "SB_MIN_CLIENT must be a version")
    except config.ConfigError:
        check(True, "SB_MIN_CLIENT must be a version")

    class Broken:
        def conn(self):
            import sqlite3
            raise sqlite3.OperationalError("disk I/O error")

    class Ctx:
        db = Broken()
    check(health(Ctx()) == (503, {"status": "unavailable"}), "health is 503 when the database does not answer")


def test_admin_cli():
    print("Server admin: users, disable-user, enable-user, delete-user")
    base, stop, settings = start()
    try:
        alice, bob = Api(base).signup("alice@example.com"), Api(base).signup("bob@example.com")
        carol, dave = Api(base).signup("carol@example.com"), Api(base).signup("dave@example.com")
        oid = alice.ok("POST", "/orgs", {"name": "Acme"})["id"]
        for person, role in ((bob, "member"), (carol, "admin")):
            alice.ok("POST", f"/orgs/{oid}/invites", {"email": person.email, "role": role})
            person.ok("POST", f"/invites/{person.ok('GET', '/invites')[0]['id']}/accept")
            alice.ok("POST", f"/orgs/{oid}/members/{person.id}/confirm", {})
        cid, solo = str(uuid.uuid4()), str(uuid.uuid4())
        alice.ok("POST", f"/orgs/{oid}/collections", {"id": cid, "encrypted_name": box(), "grant": alice.grant()})
        alice.ok("PUT", f"/collections/{cid}/members/{bob.id}", {"permission": "edit", "grant": alice.grant()})
        carol.ok("POST", f"/orgs/{oid}/collections", {"id": solo, "encrypted_name": box(), "grant": carol.grant()})
        dave.ok("POST", "/orgs", {"name": "Solo de Dave"})
        keys = alice.ok("GET", f"/users/{bob.id}/keys")

        code, out = cli_out(settings, ["users"])
        check(code == 0 and all(p.email in out for p in (alice, bob, carol, dave)) and "Acme (owner)" in out
              and "last seen 20" in out, "users lists e-mails, organizations with roles and last seen")
        check(keys["public_key"] not in out and "verifier" not in out and bob.auth_hash not in out,
              "and never keys or verifiers")

        code, out = cli_out(settings, ["disable-user", "bob@example.com"])
        check(code == 0 and "is disabled" in out and "left «Acme»: 1 collection(s) will be re-keyed" in out,
              "disable-user says what happens")
        check(bob.call("GET", "/me").status_code == 401, "its sessions are revoked")
        refused = bob.login()
        check(refused.status_code == 403 and refused.json()["code"] == "account_disabled", "it can't sign in")
        wrong = bob.login(auth_hash=rand(32))
        check(wrong.status_code == 401 and wrong.json()["code"] == "invalid_credentials",
              "a wrong password is not told the account is disabled")
        listed = next(c for c in alice.ok("GET", "/collections") if c["id"] == cid)
        check(listed["needs_rekey"] and bob.id not in [m["user_id"] for m in alice.ok("GET", f"/collections/{cid}/members")],
              "it leaves its collections, which wait for a re-key")
        check(bob.id not in [m["user_id"] for m in alice.ok("GET", f"/orgs/{oid}/members")], "and the organization")
        events = [(e["action"], e["target"], e["actor"]) for e in alice.ok("GET", f"/orgs/{oid}/events")]
        check(("member.disable", "bob@example.com", None) in events, "the org audit log says the server admin did it")
        check("DISABLED" in cli_out(settings, ["users"])[1], "users marks it")
        code, out = cli_out(settings, ["enable-user", "bob@example.com"])
        check(code == 0 and bob.login().status_code == 200 and "invite it again" in out,
              "enable-user lets it sign in again (not back into its organizations)")

        code, out = cli_out(settings, ["delete-user", "carol@example.com", "--yes"])
        check(code != 0 and "only manager of 1 collection(s) of «Acme»" in out and carol.login().status_code == 200,
              "delete-user refuses the only manager of a collection, says what to do, changes nothing")
        code, out = cli_out(settings, ["delete-user", "dave@example.com", "--yes"])
        check(code != 0 and "only owner of «Solo de Dave»" in out and "secretbroker-server transfer-owner" in out,
              "and the last owner of an organization, naming transfer-owner")
        code, out = cli_out(settings, ["transfer-owner", "Solo de Dave", "alice@example.com"])
        check(code != 0 and "not a confirmed member" in out, "transfer-owner needs a confirmed member")
        check(cli_out(settings, ["transfer-owner", "Nadie", "alice@example.com"])[0] != 0, "and an existing organization")
        code, out = cli_out(settings, ["transfer-owner", "Acme", "carol@example.com"])
        role = next(m["role"] for m in alice.ok("GET", f"/orgs/{oid}/members") if m["user_id"] == carol.id)
        events = [(e["action"], e["target"], e["actor"]) for e in alice.ok("GET", f"/orgs/{oid}/events")]
        check(code == 0 and "is now an owner of «Acme»" in out and role == "owner"
              and ("member.role", f"{carol.id}:owner", None) in events,
              "transfer-owner makes a confirmed member owner (by name or id), in Actividad")
        check("was already" in cli_out(settings, ["transfer-owner", oid, "carol@example.com"])[1], "by id too")
        code, out = cli_out(settings, ["delete-user", "bob@example.com"])
        check(code != 0 and "--yes" in out and bob.login().status_code == 200, "it asks for --yes")
        code, out = cli_out(settings, ["delete-user", "bob@example.com", "--yes"])
        gone = bob.login()
        check(code == 0 and gone.status_code == 401 and "bob@example.com" not in cli_out(settings, ["users"])[1],
              "delete-user deletes the account")
        check(server_db(settings, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (bob.id,))[0][0] == 0
              and server_db(settings, "SELECT COUNT(*) FROM events WHERE action = 'user.delete' AND target = ?",
                            (bob.id,))[0][0] == 1, "with its sessions; the server log keeps that it happened")
        code, out = cli_out(settings, ["disable-user", "carol@example.com"])
        check(code == 0 and "stays a member" in out and carol.login().status_code == 403
              and carol.id in [m["user_id"] for m in alice.ok("GET", f"/orgs/{oid}/members")],
              "disabling a collection's only manager blocks the account and keeps it there until handed over")
        check(cli_out(settings, ["disable-user", "nobody@example.com"])[0] != 0, "an unknown e-mail is an error")
    finally:
        stop()


def test_backup_restore():
    print("Backups and restore")
    import zipfile
    from secretbroker_server.backup import release_lock, take_lock
    base, stop, settings = start()
    backups = Path(tempfile.mkdtemp(prefix="sb-backups-"))
    try:
        alice = Api(base).signup("alice@example.com")
        alice.ok("POST", "/orgs", {"name": "Antes"})
        for _ in range(3):
            code, out = cli_out(settings, ["backup", "--dir", str(backups), "--keep", "2"])
        files = sorted(backups.glob("secretbroker-backup-*.zip"))
        check(code == 0 and len(files) == 2 and "deleted" in out, "backups are timestamped and the oldest pruned")
        with zipfile.ZipFile(files[-1]) as archive:
            check(sorted(archive.namelist()) == ["secretbroker.db", "server_secret"], "a backup has the database and the secret")
        alice.ok("POST", "/orgs", {"name": "Después"})
        lock = take_lock(settings.data_dir)  # what `secretbroker-server serve` holds while it runs
        try:
            code, out = cli_out(settings, ["restore", str(files[-1])])
            check(code != 0 and "stop it first" in out, "restore refuses while a server runs on the data folder")
        finally:
            release_lock(lock)
    finally:
        stop()
    code, out = cli_out(settings, ["restore", str(files[-1])])
    aside = list(settings.data_dir.glob("before-restore-*"))
    check(code == 0 and aside and (aside[-1] / "secretbroker.db").exists(), "restore keeps the previous files aside")
    base, stop, _ = start(data_dir=settings.data_dir)
    try:
        alice.http = httpx.Client(base_url=base + "/api/v1", timeout=30)
        alice.token = alice.login().json()["token"]
        names = [o["name"] for o in alice.ok("GET", "/orgs")]
        check(names == ["Antes"], f"the restored server has the data of the backup ({names})")
    finally:
        stop()
    bogus = backups / "nope.zip"
    bogus.write_bytes(b"not a zip")
    check(cli_out(settings, ["restore", str(bogus)])[0] != 0, "a file that is not a backup is refused")


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


# What the first SecretBroker Server (schema 1, before 0.16) created: no e-mail verification, no signed lists or
# deletions, no account data, invites that never expire, no disabled accounts.
SCHEMA_1 = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kdf TEXT NOT NULL,
    auth_salt TEXT NOT NULL, auth_verifier TEXT NOT NULL, public_key TEXT NOT NULL, signing_public_key TEXT NOT NULL,
    private_blob TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL, created TEXT NOT NULL, last_seen TEXT NOT NULL, touched INTEGER NOT NULL,
    expires INTEGER NOT NULL);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE signup_tokens (token_hash TEXT PRIMARY KEY, created TEXT NOT NULL, created_by TEXT,
    expires INTEGER NOT NULL, used_by TEXT);
CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE org_members (org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (org_id, user_id));
CREATE TABLE invites (id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id), email TEXT NOT NULL,
    role TEXT NOT NULL, invited_by TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE collections (id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id), encrypted_name TEXT NOT NULL,
    key_version INTEGER NOT NULL, revision INTEGER NOT NULL, needs_rekey INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL);
CREATE TABLE collection_members (collection_id TEXT NOT NULL REFERENCES collections(id),
    user_id TEXT NOT NULL REFERENCES users(id), permission TEXT NOT NULL, grant_json TEXT NOT NULL,
    key_version INTEGER NOT NULL, PRIMARY KEY (collection_id, user_id));
CREATE TABLE items (collection_id TEXT NOT NULL REFERENCES collections(id), id TEXT NOT NULL,
    revision INTEGER NOT NULL, key_version INTEGER NOT NULL, ciphertext TEXT, deleted INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY (collection_id, id));
CREATE TABLE events (id INTEGER PRIMARY KEY, org_id TEXT, time TEXT NOT NULL, actor TEXT, action TEXT NOT NULL,
    target TEXT);
INSERT INTO meta VALUES ('schema_version', '1');
"""


def test_schema_1_upgrade():
    print("Upgrading a schema-1 database (the first server) and using it")
    import json as _json
    import sqlite3
    from secretbroker_server import security
    data = Path(tempfile.mkdtemp(prefix="sb-server-schema1-"))
    auth_hash, salt = rand(32), security.new_salt()
    uid, oid, cid, iid, invite_id = (str(uuid.uuid4()) for _ in range(5))
    conn = sqlite3.connect(data / "secretbroker.db")
    conn.executescript(SCHEMA_1)
    conn.execute("INSERT INTO users VALUES (?, 'old@example.com', 'Old', ?, ?, ?, ?, ?, ?, 1, '2025-01-01T00:00:00+00:00')",
                 (uid, _json.dumps(kdf()), salt, security.verifier(auth_hash, salt), rand(32), rand(32),
                  _json.dumps(box(200))))
    conn.execute("INSERT INTO orgs VALUES (?, 'Vieja', '2025-01-01T00:00:00+00:00')", (oid,))
    conn.execute("INSERT INTO org_members VALUES (?, ?, 'owner', 'confirmed', '2025-01-01T00:00:00+00:00')", (oid, uid))
    conn.execute("INSERT INTO invites VALUES (?, ?, 'new@example.com', 'member', ?, '2025-01-02T00:00:00+00:00')",
                 (invite_id, oid, uid))
    conn.execute("INSERT INTO collections VALUES (?, ?, ?, 1, 1, 0, '2025-01-01T00:00:00+00:00')",
                 (cid, oid, _json.dumps(box())))
    grant = {"sealed": {"epk": rand(32), "nonce": rand(12), "ciphertext": rand(48)}, "granted_by": uid,
             "signature": rand(64)}
    conn.execute("INSERT INTO collection_members VALUES (?, ?, 'manage', ?, 1)", (cid, uid, _json.dumps(grant)))
    conn.execute("INSERT INTO items VALUES (?, ?, 1, 1, ?, 0, ?, '2025-01-03T00:00:00+00:00')",
                 (cid, iid, _json.dumps(box()), uid))
    conn.commit()
    conn.close()
    base, stop, settings = start(data_dir=data)
    try:
        old = Api(base)
        old.id, old.email, old.auth_hash = uid, "old@example.com", auth_hash
        login = old.login()
        check(login.status_code == 200 and login.json()["user"]["verified"] and login.json()["user"]["admin"],
              "its accounts sign in, verified, with their admin flag")
        old.token = login.json()["token"]
        check([o["name"] for o in old.ok("GET", "/orgs")] == ["Vieja"], "organizations are there")
        invite = next(m for m in old.ok("GET", f"/orgs/{oid}/members") if m["status"] == "invited")
        check(invite["invite_id"] == invite_id and invite["expired"] is False and invite["expires"],
              "pending invites get an expiry from the upgrade on")
        items = old.ok("GET", f"/collections/{cid}/items?since=0")
        check([i["id"] for i in items["items"]] == [iid], "collections and items are there")
        put = old.ok("PUT", f"/collections/{cid}/items/{iid}", {"ciphertext": box(), "key_version": 1, "base_revision": 1})
        check(put["revision"] == 2, "and can be written")
        check(old.ok("POST", f"/orgs/{oid}/invites", {"email": "other@example.com", "role": "member"})["id"],
              "new invites work")
        version = server_db(settings, "SELECT value FROM meta WHERE key = 'schema_version'")[0][0]
        check(version == "4", f"the schema is now 4 ({version})")
        replaces = [r for r in server_db(settings, "PRAGMA table_info(invites)") if r[1] == "replaces"]
        recovery = server_db(settings, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'recovery'")
        check(replaces and recovery, "with recovery codes and invites that replace an account whose owner lost access")
        check(cli_out(settings, ["users"])[1].count("old@example.com") == 1, "the admin commands work on it")
    finally:
        stop()


class Keyed(Api):
    """An account with a real Ed25519 signing key, to prove it holds its keys (recovery, password reset)."""

    def __init__(self, base):
        super().__init__(base)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.signing = Ed25519PrivateKey.generate()

    def register(self, email, invite_token=None):
        self.id, self.email, self.auth_hash = str(uuid.uuid4()), email, rand(32)
        public = base64.b64encode(self.signing.public_key().public_bytes_raw()).decode("ascii")
        body = {"user_id": self.id, "email": email, "name": email.split("@")[0].title(), "kdf": kdf(),
                "auth_hash": self.auth_hash, "public_key": rand(32), "signing_public_key": public,
                "private_blob": box(200)}
        if invite_token:
            body["invite_token"] = invite_token
        return self.call("POST", "/accounts/register", body)

    def sign(self, purpose, challenge, fields, key=None, user_id=None):
        from secretbroker_server.accounts import proof_message
        message = proof_message(purpose, user_id or self.id, challenge, fields)
        return base64.b64encode((key or self.signing).sign(message)).decode("ascii")

    def challenge(self, purpose):
        return self.ok("POST", "/accounts/challenge", {"purpose": purpose})["challenge"]

    def recovery_body(self, recovery_auth, challenge=None, key=None, n=2**17):
        fields = {"kdf": {**kdf(), "n": n}, "recovery_auth_hash": recovery_auth, "recovery_blob": box(200)}
        challenge = challenge or self.challenge("recovery")
        return {**fields, "challenge": challenge, "signature": self.sign("recovery", challenge, fields, key)}

    def password_body(self, purpose, challenge, key=None):
        fields = {"kdf": kdf(), "auth_hash": rand(32), "private_blob": box(200)}
        return {**fields, "challenge": challenge, "signature": self.sign(purpose, challenge, fields, key)}


def _events(person, oid):
    return [e["action"] for e in person.ok("GET", f"/orgs/{oid}/events")]


def test_recovery():
    print("Recovery codes and a new password from a device with the keys")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    stranger_key = Ed25519PrivateKey.generate()
    base, stop, settings = start()
    try:
        alice = Keyed(base).signup("alice@example.com")
        other_device = alice.login("Portátil").json()["token"]
        oid = alice.ok("POST", "/orgs", {"name": "Acme"})["id"]
        check(alice.ok("GET", "/me")["recovery"] is None, "no recovery code at first")
        check(Api(base).ok("GET", "/info").get("recovery") is True, "/info says the server has recovery codes")

        # Setting the code: only a device that signs a fresh challenge with the account's key.
        recovery_auth = rand(32)
        forged = alice.recovery_body(recovery_auth, challenge="made-up")
        refused = alice.call("POST", "/accounts/recovery", forged)
        check(refused.status_code == 403 and refused.json()["code"] == "invalid_proof",
              "a challenge the server did not give is refused")
        challenge = alice.challenge("recovery")
        wrong = alice.call("POST", "/accounts/recovery", alice.recovery_body(recovery_auth, challenge, stranger_key))
        check(wrong.status_code == 403 and wrong.json()["code"] == "invalid_proof",
              "a signature by another key is refused (a stolen session alone can't set a code)")
        again = alice.call("POST", "/accounts/recovery", alice.recovery_body(recovery_auth, challenge))
        check(again.status_code == 403, "that challenge can't be used again, even with the right signature")
        weak = alice.call("POST", "/accounts/recovery", alice.recovery_body(recovery_auth, n=2**14))
        check(weak.status_code == 400, "a recovery code derived with less than 2^17 scrypt work is refused")
        good = alice.recovery_body(recovery_auth)
        check(alice.call("POST", "/accounts/recovery", good).status_code == 200, "the account's device sets it")
        replay = alice.call("POST", "/accounts/recovery", good)
        check(replay.status_code == 403 and replay.json()["code"] == "invalid_proof", "the same request replayed is refused")
        check(alice.ok("GET", "/me")["recovery"]["created"], "/me says when the code was made")
        wrong_purpose = alice.challenge("reset")
        mixed = alice.call("POST", "/accounts/recovery", alice.recovery_body(rand(32), wrong_purpose))
        check(mixed.status_code == 403, "a challenge given for something else is refused")

        # Uniform answers: unknown e-mail, account without a code, wrong code.
        anon = Api(base)
        bob = Keyed(base).signup("bob@example.com")
        pre = anon.ok("POST", "/accounts/recover/prelogin", {"email": "alice@example.com"})["kdf"]
        check(pre == good["kdf"], "recover/prelogin gives the code's scrypt parameters")
        fake = anon.ok("POST", "/accounts/recover/prelogin", {"email": "nobody@example.com"})["kdf"]
        fake2 = anon.ok("POST", "/accounts/recover/prelogin", {"email": "nobody@example.com"})["kdf"]
        no_code = anon.ok("POST", "/accounts/recover/prelogin", {"email": "bob@example.com"})["kdf"]
        check(set(fake) == set(pre) == set(no_code) and fake == fake2 and fake["n"] == pre["n"]
              and fake["salt"] != no_code["salt"], "unknown e-mails and accounts without a code look the same, every time")
        answers = [anon.call("POST", "/accounts/recover/start", {"email": address, "recovery_auth_hash": rand(32)})
                   for address in ("alice@example.com", "nobody@example.com", "bob@example.com")]
        check([a.status_code for a in answers] == [401] * 3 and len({a.text for a in answers}) == 1,
              "a wrong code, an unknown e-mail and an account without a code get the same answer")

        # Recovering on a new device: the keys wrapped by the code, a challenge to sign once they are open.
        start_body = {"email": "alice@example.com", "recovery_auth_hash": recovery_auth}
        started = anon.ok("POST", "/accounts/recover/start", start_body)
        check(started["recovery_blob"] == good["recovery_blob"] and started["user_id"] == alice.id
              and started["signing_public_key"], "the right code gets the keys wrapped by it and a challenge")
        new_password = alice.password_body("recover", started["challenge"], stranger_key)
        forged = anon.call("POST", "/accounts/recover", {**start_body, **new_password})
        check(forged.status_code == 403 and forged.json()["code"] == "invalid_proof",
              "without the account's key (the code alone, keys not opened) no new password is set")
        started = anon.ok("POST", "/accounts/recover/start", start_body)
        new_password = alice.password_body("recover", started["challenge"])
        wrong_code = anon.call("POST", "/accounts/recover", {**start_body, "recovery_auth_hash": rand(32),
                                                              **{k: v for k, v in new_password.items()}})
        check(wrong_code.status_code == 401, "finishing needs the right code too")
        done = anon.call("POST", "/accounts/recover", {**start_body, **new_password})
        check(done.status_code == 200, "the code and the opened keys set a new password")
        replayed = anon.call("POST", "/accounts/recover", {**start_body, **new_password})
        check(replayed.status_code == 403, "the same recovery can't be replayed")
        check(alice.call("GET", "/me").status_code == 401 and alice.call("GET", "/me", token=other_device).status_code == 401,
              "every session of the account ends")
        old = alice.login()
        check(old.status_code == 401, "the old password no longer works")
        session = alice.login(auth_hash=new_password["auth_hash"])
        check(session.status_code == 200 and session.json()["private_blob"] == new_password["private_blob"],
              "the new password logs in and gives the keys wrapped again")
        alice.token = session.json()["token"]
        alice.auth_hash = new_password["auth_hash"]
        check("account.recover" in _events(alice, oid), "the organization sees that the account was recovered")
        check(anon.call("POST", "/accounts/recover/start", start_body).status_code == 200,
              "the code keeps working until a new one is made")

        # A new code: the old one stops working.
        second = rand(32)
        check(alice.call("POST", "/accounts/recovery", alice.recovery_body(second)).status_code == 200,
              "a new code replaces the old one")
        check(anon.call("POST", "/accounts/recover/start", start_body).status_code == 401, "the old code is refused")
        check(anon.call("POST", "/accounts/recover/start", {"email": "alice@example.com", "recovery_auth_hash": second})
              .status_code == 200, "the new one works")

        # A connected device sets a new password without the old one by proving it has the keys.
        laptop = alice.login("Portátil").json()["token"]
        challenge = alice.challenge("reset")
        bad = alice.call("POST", "/accounts/password/reset", alice.password_body("reset", challenge, stranger_key))
        check(bad.status_code == 403 and bad.json()["code"] == "invalid_proof", "a bad signature is refused")
        replayed = alice.call("POST", "/accounts/password/reset", alice.password_body("reset", challenge))
        check(replayed.status_code == 403, "a challenge already tried is refused (no replay)")
        recovery_challenge = alice.challenge("recovery")
        crossed = alice.call("POST", "/accounts/password/reset", alice.password_body("reset", recovery_challenge))
        check(crossed.status_code == 403, "a challenge given for a recovery code can't reset the password")
        weak = alice.password_body("reset", alice.challenge("reset"))
        weak_fields = {**weak, "kdf": {**weak["kdf"], "n": 2**14}}
        check(alice.call("POST", "/accounts/password/reset", weak_fields).status_code == 400,
              "a new password with less than 2^17 scrypt work is refused")
        reset = alice.password_body("reset", alice.challenge("reset"))
        check(alice.call("POST", "/accounts/password/reset", reset).status_code == 200,
              "the device with the keys sets a new password without the old one")
        check(alice.call("GET", "/me").status_code == 200, "this device stays signed in")
        check(alice.call("GET", "/me", token=laptop).status_code == 401, "the account's other devices are logged out")
        check(alice.login(auth_hash=reset["auth_hash"]).status_code == 200
              and alice.login().status_code == 401, "only the new password works")
        check("password.reset" in _events(alice, oid), "the organization sees the reset")
        check(bob.call("POST", "/accounts/password/reset", alice.password_body("reset", bob.challenge("reset")))
              .status_code == 403, "someone else's key can't reset this account")
    finally:
        stop()

    print("Recovery codes: wrong codes are throttled like logins")
    base, stop, _ = start()
    try:
        carol = Keyed(base).signup("carol@example.com")
        carol.ok("POST", "/accounts/recovery", carol.recovery_body(rand(32)))
        anon = Api(base)
        codes = [anon.call("POST", "/accounts/recover/start", {"email": "carol@example.com",
                                                               "recovery_auth_hash": rand(32)}).status_code
                 for _ in range(5)]
        blocked = anon.call("POST", "/accounts/recover/start", {"email": "carol@example.com",
                                                               "recovery_auth_hash": rand(32)})
        check(codes == [401] * 5 and blocked.status_code == 429 and blocked.headers.get("retry-after"),
              "the sixth wrong code in a row waits (429 with Retry-After)")
        unknown = [anon.call("POST", "/accounts/recover/start", {"email": "ghost@example.com",
                                                                 "recovery_auth_hash": rand(32)}).status_code
                   for _ in range(6)]
        check(unknown == [401] * 5 + [429], "an unknown e-mail is throttled the same way")
    finally:
        stop()


def test_replace_account():
    print("An account whose owner lost access is replaced only once the new sign-up proves the e-mail")
    with Outbox() as outbox:
        base, stop, settings = start(email_verification="required", smtp_host="smtp.example",
                                     smtp_from="secrets@example.com")
        try:
            admin = Keyed(base).signup("admin@example.com")
            server_db(settings, "UPDATE users SET verified = 1")
            oid = admin.ok("POST", "/orgs", {"name": "Acme"})["id"]
            other_oid = admin.ok("POST", "/orgs", {"name": "Otra"})["id"]

            def join(person, org, address):
                invite = admin.ok("POST", f"/orgs/{org}/invites", {"email": address, "role": "member"})
                if person.token is None:
                    assert person.register(address, invite_token=invite["id"]).status_code == 200
                    person.token = person.login().json()["token"]
                person.ok("POST", f"/invites/{invite['id']}/accept")
                admin.ok("POST", f"/orgs/{org}/members/{person.id}/confirm")

            carol = Keyed(base)
            join(carol, oid, "carol@example.com")
            old_id = carol.id
            early = admin.call("POST", f"/orgs/{oid}/invites", {"email": "carol@example.com", "role": "member",
                                                                 "replaces": old_id})
            check(early.status_code == 409, "while still a member, no new invite")
            admin.ok("DELETE", f"/orgs/{oid}/members/{old_id}")
            wrong = admin.call("POST", f"/orgs/{oid}/invites", {"email": "carol@example.com", "role": "member",
                                                                 "replaces": admin.id})
            check(wrong.status_code == 400, "`replaces` must be the account of that e-mail")
            invite = admin.ok("POST", f"/orgs/{oid}/invites", {"email": "carol@example.com", "role": "member",
                                                                "replaces": old_id})
            check("invite.replace" in _events(admin, oid), "Actividad says it was a new invite after lost access")

            imposter = Keyed(base)
            imposter.register("carol@example.com")
            check(imposter.login().status_code == 401, "signing up without that invite does nothing")

            # The org admin knows the invite code: signing up with it alone must never take the address.
            hostile = Keyed(base)
            answer = hostile.register("carol@example.com", invite_token=invite["id"]).json()
            check(answer.get("replacing") is True and answer["verified"] is False,
                  "a sign-up with the invite waits: it has to prove the e-mail first")
            check(hostile.login().status_code == 401, "until then it can't sign in")
            check(carol.call("GET", "/me").status_code == 200 and carol.login().status_code == 200,
                  "and the old account keeps its sessions and its password")
            guesses = [Api(base).call("POST", "/accounts/replace/verify", {"email": "carol@example.com",
                                                                           "code": "12345678"}).status_code
                       for _ in range(3)]
            check(guesses == [400] * 3 and carol.login().status_code == 200,
                  "without the e-mailed code nothing changes (wrong codes are refused)")
            unknown = Api(base).call("POST", "/accounts/replace/verify", {"email": "nobody@example.com", "code": "1"})
            check(unknown.status_code == 400 and unknown.json()["code"] == "code_expired",
                  "an e-mail with nothing waiting gets the answer of an expired code")

            fresh = Keyed(base)
            answer = fresh.register("carol@example.com", invite_token=invite["id"]).json()
            check(answer.get("replacing") and answer.get("mail") is True, "the person signs up too: the code is e-mailed")
            code = outbox.code("carol@example.com")
            check(Api(base).call("POST", "/accounts/replace/verify", {"email": "carol@example.com", "code": code})
                  .status_code == 200, "the code from the e-mail proves the address")
            session = fresh.login()
            check(session.status_code == 200 and session.json()["user"]["id"] == fresh.id != old_id
                  and session.json()["user"]["verified"], "the new account takes the e-mail (new id, new keys, verified)")
            check(hostile.login().status_code == 401, "the earlier sign-up that never proved it is gone")
            check(carol.call("GET", "/me").status_code == 401, "the old account's sessions are gone")
            fresh.token = session.json()["token"]
            check([i["org_id"] for i in fresh.ok("GET", "/invites")] == [oid], "the new account sees the invite")
            fresh.ok("POST", f"/invites/{invite['id']}/accept")
            admin.ok("POST", f"/orgs/{oid}/members/{fresh.id}/confirm")
            check(any(m["user_id"] == fresh.id for m in admin.ok("GET", f"/orgs/{oid}/members")), "and is back in")

            # Someone also in another organization is not replaced until every organization let them go.
            dave = Keyed(base)
            join(dave, oid, "dave@example.com")
            server_db(settings, "UPDATE users SET verified = 1 WHERE replacing_email IS NULL")
            join(dave, other_oid, "dave@example.com")
            admin.ok("DELETE", f"/orgs/{oid}/members/{dave.id}")
            invite = admin.ok("POST", f"/orgs/{oid}/invites", {"email": "dave@example.com", "role": "member",
                                                                "replaces": dave.id})
            again = Keyed(base)
            answer = again.register("dave@example.com", invite_token=invite["id"]).json()
            check(not answer.get("replacing") and again.login().status_code == 401
                  and dave.call("GET", "/me").status_code == 200, "an account still in another organization is not replaced")
            plain = admin.ok("POST", f"/orgs/{other_oid}/invites", {"email": "erin@example.com", "role": "member"})
            erin = Keyed(base)
            erin.register("erin@example.com", invite_token=plain["id"])
            erin_again = Keyed(base)
            erin_again.register("erin@example.com", invite_token=plain["id"])
            check(erin_again.login().status_code == 401 and erin.login().status_code == 200,
                  "an ordinary invite never replaces an account")
        finally:
            stop()

    print("Without e-mail, the server admin verifies the new account before it replaces the old one")
    base, stop, settings = start(email_verification="required")
    try:
        admin = Keyed(base).signup("admin@example.com")
        server_db(settings, "UPDATE users SET verified = 1")
        oid = admin.ok("POST", "/orgs", {"name": "Acme"})["id"]
        frank = Keyed(base)
        invite = admin.ok("POST", f"/orgs/{oid}/invites", {"email": "frank@example.com", "role": "member"})
        frank.register("frank@example.com", invite_token=invite["id"])
        frank.token = frank.login().json()["token"]
        frank.ok("POST", f"/invites/{invite['id']}/accept")
        admin.ok("DELETE", f"/orgs/{oid}/members/{frank.id}")
        invite = admin.ok("POST", f"/orgs/{oid}/invites", {"email": "frank@example.com", "role": "member",
                                                            "replaces": frank.id})
        fresh = Keyed(base)
        answer = fresh.register("frank@example.com", invite_token=invite["id"]).json()
        check(answer.get("replacing") and answer.get("mail") is False and fresh.login().status_code == 401
              and frank.call("GET", "/me").status_code == 200, "it waits, and the old account carries on")
        code, listed = cli_out(settings, ["unverified"])
        check("frank@example.com" in listed and "lost access" in listed, "`unverified` lists it as a replacement")
        code, said = cli_out(settings, ["verify-email", "frank@example.com"])
        check(code == 0 and "took the place" in said, f"`verify-email` completes it ({said.strip()})")
        check(fresh.login().status_code == 200 and frank.call("GET", "/me").status_code == 401,
              "then the new account signs in and the old one is gone")
    finally:
        stop()


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
    test_schema_1_upgrade()
    test_invite_lifecycle()
    test_mail_texts()
    test_versions_and_health()
    test_admin_cli()
    test_backup_restore()
    test_recovery()
    test_replace_account()
    print("\nAll good." if not failures else f"\n{failures} check(s) failed.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
