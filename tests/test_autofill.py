"""Browser autofill: domain matching (anti-phishing), the native messaging host and the service's extension ops.

The host is started as the browser would start it (a separate process speaking 4-byte length + JSON on stdin and
stdout) and drives a real service. All values are fake.
Run with:  .venv\\Scripts\\python.exe tests\\test_autofill.py
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="secretbroker-autofill-"))
os.environ["SECRETBROKER_HOME"] = str(HOME)  # must be set before importing secretbroker
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secretbroker import autofill, client, native_host, service as service_module, teams  # noqa: E402
from secretbroker.client import BrokerError  # noqa: E402
from secretbroker.service import Service  # noqa: E402

MASTER = "correct horse battery staple"
PROOF = {"kind": "master_password", "value": MASTER}
CHROME = f"chrome-extension://{native_host.CHROME_EXTENSION_IDS[0]}/"
failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


# --------------------------------------------------------------------------------------------- domain matching

def matches(saved, page, mode="domain"):
    return autofill.site_matches(autofill.parse(saved), autofill.parse(page, page=True), mode) is None


def check_domains():
    print("Registrable domains (public suffix list)")
    for host, domain in [("www.shop.example.co.uk", "example.co.uk"), ("accounts.google.com", "google.com"),
                         ("alice.github.io", "alice.github.io"), ("a.b.kawasaki.jp", "a.b.kawasaki.jp"),
                         ("city.kawasaki.jp", "city.kawasaki.jp"), ("www.ck", "www.ck"), ("foo.bar.ck", "foo.bar.ck"),
                         ("example.com.evil.net", "evil.net"), ("münchen.de", "xn--mnchen-3ya.de"),
                         ("login.EXAMPLE.com.", "example.com"), ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
                         ("intranet", "intranet"), ("localhost", "localhost"), ("10.0.0.1", "10.0.0.1"),
                         ("co.uk", "co.uk"), ("unknown-tld.zzzz", "unknown-tld.zzzz")]:
        check(autofill.registrable_domain(host) == domain, f"{host} -> {domain}")

    print("Matching: same site")
    check(matches("https://example.com", "https://example.com/login"), "same host")
    check(matches("example.com", "https://accounts.example.com/signin"), "a subdomain (domain mode)")
    check(matches("https://login.example.com", "https://www.example.com"), "sibling subdomains of the same domain")
    check(matches("https://shop.example.co.uk", "https://example.co.uk"), "under a two-label public suffix")
    check(matches("https://xn--mnchen-3ya.de", "https://münchen.de/"), "IDN written either way")
    check(matches("https://EXAMPLE.com", "https://example.COM./x"), "case and the trailing dot")

    print("Matching: lookalikes and phishing, never")
    for page in ["https://example.com.evil.net/login", "https://examp1e.com", "https://example-login.com",
                 "https://exаmple.com", "https://evil.net/example.com", "https://example.co", "https://myexample.com",
                 "https://example.com@evil.net/", "https://evil.net/?u=https://example.com"]:
        check(not matches("https://example.com", page), f"example.com is not filled on {page}")
    check(not matches("https://alice.github.io", "https://bob.github.io"), "another tenant of a shared suffix (github.io)")
    check(not matches("https://myshop.myshopify.com", "https://evil.myshopify.com"), "another tenant of myshopify.com")
    check(not matches("https://a.blogspot.com", "https://b.blogspot.com"), "another tenant of blogspot.com")
    check(not matches("https://example.co.uk", "https://evil.co.uk"), "another domain under co.uk")

    print("Matching: per-credential rules")
    check(not matches("https://login.example.com", "https://www.example.com", "host"), "host mode: another subdomain is refused")
    check(matches("https://login.example.com", "https://login.example.com/x", "host"), "host mode: the exact host")
    check(not matches("https://example.com", "https://example.com", "never"), "never mode: not even the same host")
    reason = autofill.site_matches(autofill.parse("https://example.com"), autofill.parse("https://evil.net", page=True))
    check(reason == "domain", f"why not: domain [{reason}]")

    print("Matching: schemes, IP addresses, localhost and ports")
    check(not matches("https://example.com", "http://example.com"), "an https login is not filled on http")
    check(matches("http://example.com", "http://example.com"), "an http login on its http page")
    check(matches("example.com", "https://example.com"), "an address without scheme means https")
    check(matches("http://localhost:3000", "http://localhost:3000/login"), "localhost with its port")
    check(not matches("http://localhost:3000", "http://localhost:8080"), "localhost on another port")
    check(not matches("http://localhost", "http://127.0.0.1"), "localhost is not 127.0.0.1")
    check(matches("https://localhost:8443", "http://localhost:8443"), "https saved, http page on localhost (dev servers)")
    check(matches("https://192.168.1.10", "https://192.168.1.10/admin"), "an IP address: the same one")
    check(not matches("https://192.168.1.10", "https://192.168.1.11"), "an IP address: never a neighbour")
    check(not matches("https://10.0.0.1", "https://10.0.0.1:8443"), "an IP address on another port")
    check(matches("https://[::1]:9000", "https://[::1]:9000/"), "an IPv6 address with port")
    check(not matches("https://intranet", "https://intranet2"), "single-label hosts match only themselves")
    check(not matches("https://example.com:8443", "https://example.com"), "a saved port must be the page's")
    check(matches("https://example.com:443", "https://example.com"), "the default port written out")
    check(not matches("https://co.uk", "https://evil.co.uk"), "a public suffix saved as a site matches only itself")
    for bad in ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.com", "chrome://settings", "about:blank"]:
        try:
            autofill.parse(bad, page=True)
            check(False, f"refuses the page {bad}")
        except autofill.SiteError:
            check(True, f"refuses the page {bad}")

    print("Frames")
    top = autofill.parse("https://example.com", page=True)
    check(autofill.frame_allowed(top, None), "the page itself")
    check(autofill.frame_allowed(top, autofill.parse("https://login.example.com", page=True)), "a frame of the same domain")
    check(not autofill.frame_allowed(top, autofill.parse("https://ads.evil.net", page=True)), "never a third-party frame")
    check(not autofill.frame_allowed(top, autofill.parse("http://login.example.com", page=True)), "never an http frame in an https page")

    print("Saved sites")
    try:
        autofill.validate({"sites": ["https://example.com", "login.example.org"], "match": "host"})
        check(True, "valid autofill settings")
    except autofill.SiteError:
        check(False, "valid autofill settings")
    for bad in [{"sites": ["not a url !"]}, {"match": "sometimes"}, {"sites": ["x.com"] * 2}, {"other": 1},
                {"sites": [f"s{i}.example.com" for i in range(25)]}]:
        try:
            autofill.validate(bad)
            check(False, f"refuses {str(bad)[:50]}")
        except autofill.SiteError:
            check(True, f"refuses {str(bad)[:50]}")


# --------------------------------------------------------------------------------------------- native host

class Host:
    """The native host as the browser starts it."""

    def __init__(self, *argv):
        env = {**os.environ, "SECRETBROKER_HOME": str(HOME), "PYTHONIOENCODING": "utf-8"}
        self.process = subprocess.Popen([sys.executable, "-m", "secretbroker.native_host", *argv], cwd=ROOT, env=env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.next = 0

    def ask(self, op, params=None, pair=None, raw=None):
        self.next += 1
        message = raw if raw is not None else {"id": self.next, "op": op, "params": params or {}, "pair": pair, "browser": "Chrome"}
        body = json.dumps(message).encode("utf-8")
        self.process.stdin.write(struct.pack("<I", len(body)) + body)
        self.process.stdin.flush()
        header = self.process.stdout.read(4)
        if len(header) < 4:
            raise RuntimeError("the host closed: " + self.process.stderr.read().decode("utf-8", "replace"))
        reply = json.loads(self.process.stdout.read(struct.unpack("<I", header)[0]).decode("utf-8"))
        if raw is None:
            assert reply["id"] == self.next
        return reply

    def close(self):
        self.process.stdin.close()
        code = self.process.wait(10)
        self.process.stdout.close()
        self.process.stderr.close()
        return code


def entry(entry_id, name, url, username, password, **extra):
    return {"id": entry_id, "name": name, "template": "web_login", "description": "",
            "fields": {"url": url, "username": username, "password": password, **extra.pop("fields", {})},
            "policy": {"approval": "session"}, **extra}


def check_team_review():
    """A password filled on a page is handed to that page: a teammate's new address for a shared web login waits
    for review like a new web for the AI (else someone about to be removed could add their own site, and get the
    password the team sets after rotating it, the day someone fills it there)."""
    print("Team changes to where the browser fills")
    base = entry("bank", "Banco", "https://bank.example.com", "ana", "s3cret")
    wider = lambda **change: teams.new_fill_sites(base, {**base, **change})
    check(wider() == [], "nothing new")
    check(wider(fields={**base["fields"], "url": "https://login.bank.example.com/x"}) == [],
          "another page of the same domain is not new")
    check(wider(fields={**base["fields"], "url": "https://bank-example.evil.net"}) == ["evil.net"], "a new domain is")
    check(wider(autofill={"sites": ["examp1e.com"]}) == ["examp1e.com"], "so is an extra autofill site")
    check(wider(fields={**base["fields"], "url": "http://bank.example.com"}) == ["http://example.com"],
          "and plain http where it was https")
    narrow = {**base, "autofill": {"match": "host"}}
    check(teams.new_fill_sites(narrow, base) == ["example.com"], "and widening exact-host matching to the domain")
    check(teams.new_fill_sites(base, {**base, "autofill": {"match": "never"}}) == [], "never filling is not wider")
    lines = teams.widening_changes(base, {**base, "autofill": {"sites": ["evil.net"]}})
    check(any("evil.net" in line for line in lines), "the change to review names it")

    content = {**base, "name": "Banco nuevo", "autofill": {"sites": ["evil.net"]},
               "fields": {**base["fields"], "url": "https://evil.net/login"}}
    shared = {"permission": "edit"}
    held = teams.Team._quarantine(base, content, shared, {"name": "Bob"}, teams.widening_changes(base, content))
    check(held["name"] == "Banco nuevo" and held["fields"]["url"] == "https://bank.example.com"
          and not held.get("autofill"), "quarantined: the name applies, the browser keeps filling only the old site")
    page = autofill.parse("https://evil.net/login", page=True)
    check(not autofill.match_entry(held, page), "so evil.net gets nothing until the user accepts")
    accepted = teams.effective_content({**held, "shared": shared})
    check(accepted["fields"]["url"] == "https://evil.net/login" and accepted["autofill"] == {"sites": ["evil.net"]},
          "accepting applies it (and it is what the server already has, so nothing is pushed back)")


def check_host():
    print("Native host and the service")
    check(not set(service_module.EXTENSION_OPS) & service_module.AI_OPS, "no extension op is for the AI")
    service = Service(HOME, owner=f"{os.environ.get('USERDOMAIN')}\\{os.environ.get('USERNAME')}", isolated=False)
    service.start()
    host = Host(CHROME, "--parent-window=0")
    try:
        client.request("create_vault", {"master_password": MASTER})
        presence = client.request("unlock", {"proof": PROOF})["presence"]
        one_click = {"kind": "presence", "token": presence}
        vault = service.vault
        vault.put(entry("example", "Example", "https://example.com", "ana@example.com", "fake-pass-1",
                        fields={"totp": "JBSWY3DPEHPK3PXP"}))
        vault.put(entry("example-admin", "Example admin", "https://admin.example.com", "root", "fake-pass-2",
                        autofill={"sites": [], "match": "host"}))
        vault.put(entry("shop", "Tienda", "https://shop.example.org", "ana", "fake-pass-3",
                        autofill={"sites": ["https://checkout.example.net"], "match": "domain"}))
        vault.put(entry("team-use", "Panel del equipo", "https://example.com", "equipo", "fake-pass-4",
                        shared={"org": "o1", "collection": "c1", "item": "i1", "permission": "use", "collection_name": "Ops"}))
        vault.put(entry("github-pages", "Pages", "https://alice.github.io", "alice", "fake-pass-5"))

        reply = Host("chrome-extension://abcdefghijklmnopabcdefghijklmnop/").ask("hello")
        check(not reply["ok"] and reply["code"] == "forbidden", f"another extension is refused [{reply.get('code')}]")
        reply = host.ask("hello")
        check(reply["ok"] and reply["result"]["state"] == "unlocked" and reply["result"]["paired"] is False,
              "hello: unlocked, this browser not connected yet")
        pair = {"id": "pair-chrome-0123456789", "key": "k" * 43}
        reply = host.ask("logins", {"url": "https://example.com"}, pair)
        check(not reply["ok"] and reply["code"] == "not_paired", f"no logins before connecting [{reply.get('code')}]")
        reply = host.ask("pair", {"name": "Chrome"}, pair)
        check(reply["ok"] and reply["result"]["pending"] and len(reply["result"]["code"]) == 6, "asks to connect: a code to compare")
        status = client.request("status")
        check(len(status["browser_pairing"]) == 1 and status["browser_pairing"][0]["code"] == reply["result"]["code"],
              "the app sees the request with the same code")
        request_id = status["browser_pairing"][0]["id"]
        try:
            client.request("browser_pair_answer", {"id": request_id})
            check(False, "connecting needs the app that unlocked (no error)")
        except BrokerError as exc:
            check(exc.code == "proof_required", f"connecting needs the app that unlocked [{exc.code}]")
        client.request("browser_pair_answer", {"id": request_id, "proof": one_click})
        check(host.ask("hello", pair=pair)["result"]["paired"], "connected with one click")
        check((HOME / "data" / "browsers.json").exists() and "k" * 43 not in (HOME / "data" / "browsers.json").read_text(),
              "only the key's hash is kept")
        stolen = {"id": pair["id"], "key": "x" * 43}
        reply = host.ask("logins", {"url": "https://example.com"}, stolen)
        check(not reply["ok"] and reply["code"] == "not_paired", "a wrong key for a connected browser is refused")
        reply = host.ask("logins", {"url": "https://example.com", "_ext": {"origin": CHROME, "pair": pair["id"], "key": pair["key"]}}, stolen)
        check(not reply["ok"] and reply["code"] == "not_paired", "the extension cannot set who it is (the host does)")
        try:
            client.request("ext_logins", {"url": "https://example.com", "_ext": {"origin": "chrome-extension://evil/", **pair}})
            check(False, "an origin not on the list is refused (no error)")
        except BrokerError as exc:
            check(exc.code == "forbidden", f"an origin not on the list is refused [{exc.code}]")
        try:
            client.request("entries", {"_ext": {"origin": CHROME, **pair}})
            check(False, "the browser cannot call other ops (no error)")
        except BrokerError as exc:
            check(exc.code == "forbidden", f"the browser cannot call other ops [{exc.code}]")

        print("Which logins a page gets")
        def ids(url, frame=None):
            params = {"url": url, **({"frame_url": frame} if frame else {})}
            reply = host.ask("logins", params, pair)
            return reply["result"] if reply["ok"] else reply
        page = ids("https://accounts.example.com/signin")
        check([l["id"] for l in page["logins"]] == ["example", "team-use"] and page["domain"] == "example.com",
              f"accounts.example.com: example and the team one, not admin (host only) {[l['id'] for l in page['logins']]}")
        check("fake-pass" not in json.dumps(page), "listing logins gives no password")
        use_only = next(l for l in page["logins"] if l["id"] == "team-use")
        check(not use_only["can_fill"] and use_only["why"] == "use_only" and use_only["collection"] == "Ops",
              "a use-only team login is listed as not fillable")
        check([l["id"] for l in ids("https://admin.example.com")["logins"]] == ["example-admin", "example", "team-use"],
              "admin.example.com: its exact login first")
        check(ids("https://example.com.evil.net/login")["logins"] == [], "a lookalike gets nothing")
        check(ids("http://example.com")["logins"] == [], "http instead of https gets nothing")
        check([l["id"] for l in ids("https://pay.checkout.example.net")["logins"]] == ["shop"], "an extra site of a login")
        check(ids("https://bob.github.io")["logins"] == [], "another github.io tenant gets nothing")
        reply = ids("https://example.com", "https://widget.evil.net/frame")
        check(reply.get("code") == "frame", "a third-party frame gets nothing")
        check([l["id"] for l in ids("https://www.example.com", "https://login.example.com/frame")["logins"]] == ["example", "team-use"],
              "a frame of the same domain")

        print("Filling (one login, after a click)")
        reply = host.ask("fill", {"url": "https://accounts.example.com", "id": "example"}, pair)
        check(reply["ok"] and reply["result"] == {"username": "ana@example.com", "password": "fake-pass-1"}, "user and password")
        reply = host.ask("fill", {"url": "https://example.com.evil.net", "id": "example"}, pair)
        check(not reply["ok"] and reply["code"] == "mismatch", "never on another site, even if asked for that id")
        reply = host.ask("fill", {"url": "https://example.com", "frame_url": "https://ads.evil.net", "id": "example"}, pair)
        check(not reply["ok"] and reply["code"] == "frame", "never into a third-party frame")
        reply = host.ask("fill", {"url": "https://example.com", "id": "team-use"}, pair)
        check(not reply["ok"] and reply["code"] == "forbidden" and "solo uso" in reply["error"], "never a use-only team login")
        reply = host.ask("fill", {"url": "https://example.com", "id": "example", "what": "totp"}, pair)
        check(reply["ok"] and reply["result"]["totp"].isdigit() and len(reply["result"]["totp"]) == 6 and "password" not in reply["result"],
              "the current 2FA code, without the password")
        reply = host.ask("fill", {"url": "https://example.com", "id": "example", "what": "password", "copy": True}, pair)
        check(reply["ok"] and reply["result"] == {"password": "fake-pass-1"}, "copying only the password")
        events = client.request("audit", {"limit": 30})
        fills = [e for e in events if e["action"] in ("browser_fill", "browser_copy")]
        check(fills and all(e["actor"] == "browser" and e.get("client", "").startswith("Navegador") for e in fills),
              "every fill is in Actividad as «Navegador»")
        check(any(e["action"] == "browser_fill" and e["status"] == "denied" and e["secret"] == "team-use" for e in events),
              "the refused use-only fill is in Actividad too")
        check(any(e["action"] == "browser_copy" and "contraseña" in e["detail"] for e in fills), "a copy says what was copied")

        print("Search")
        reply = host.ask("search", {"query": "tienda"}, pair)
        check(reply["ok"] and [r["id"] for r in reply["result"]["results"]] == ["shop"]
              and reply["result"]["results"][0]["url"] == "https://shop.example.org", "finds by name, with its site to open")
        check("fake-pass" not in json.dumps(reply), "search gives no password")

        print("Saving what the user typed (after a click)")
        reply = host.ask("save_check", {"url": "https://example.com/login", "username": "ana@example.com", "password": "fake-pass-1"}, pair)
        check(reply["ok"] and reply["result"]["action"] == "none", "the same password: nothing to offer")
        reply = host.ask("save_check", {"url": "https://example.com/login", "username": "ANA@example.com", "password": "fake-new-1"}, pair)
        check(reply["ok"] and reply["result"]["action"] == "update" and reply["result"]["id"] == "example", "a new password: update")
        check(vault.get("example")["fields"]["password"] == "fake-pass-1", "checking stores nothing")
        reply = host.ask("save", {"url": "https://example.com/login", "username": "ana@example.com", "password": "fake-new-1"}, pair)
        check(reply["ok"] and reply["result"]["saved"] and vault.get("example")["fields"]["password"] == "fake-new-1"
              and vault.get("example")["fields"]["totp"] == "JBSWY3DPEHPK3PXP", "updated: the new password, the rest kept")
        reply = host.ask("save_check", {"url": "https://new.example.io/signin", "username": "bea", "password": "fake-pass-6"}, pair)
        check(reply["ok"] and reply["result"]["action"] == "new" and reply["result"]["name"] == "example.io", "a new site: save as new")
        reply = host.ask("save", {"url": "https://new.example.io/signin", "username": "bea", "password": "fake-pass-6", "name": "Example IO"}, pair)
        saved = vault.get(reply["result"]["id"]) if reply["ok"] else {}
        check(saved.get("template") == "web_login" and saved["fields"] == {"url": "https://new.example.io", "username": "bea", "password": "fake-pass-6"}
              and saved["name"] == "Example IO", "saved as a web login with the page's address")
        check(saved.get("policy", {}).get("http", {}).get("allowed_hosts") == ["new.example.io"], "with the template's AI permissions")
        check([l["id"] for l in ids("https://new.example.io")["logins"]] == [saved.get("id")], "and offered there next time")
        reply = host.ask("save_check", {"url": "https://example.com", "username": "equipo", "password": "fake-other"}, pair)
        check(reply["ok"] and reply["result"]["action"] == "none", "a use-only team login is never changed from the browser")
        reply = host.ask("save", {"url": "https://example.com", "username": "", "password": "fake"}, pair)
        check(reply["ok"] and not reply["result"]["saved"], "nothing without a user name")

        print("Locked, forgotten and other browsers")
        client.request("lock")
        reply = host.ask("logins", {"url": "https://example.com"}, pair)
        check(not reply["ok"] and reply["code"] == "locked", "locked: nothing")
        hello = host.ask("hello", pair=pair)["result"]
        check(hello["state"] == "locked" and hello["paired"], "hello: locked, and still connected")
        client.request("unlock", {"proof": PROOF})
        firefox = Host(str(HOME / "firefox.json"), native_host.FIREFOX_EXTENSION_IDS[0])
        reply = firefox.ask("hello", pair={"id": "pair-firefox-0123456789", "key": "f" * 43})
        check(reply["ok"] and reply["result"]["paired"] is False, "Firefox's extension id is accepted, but needs connecting too")
        reply = firefox.ask("logins", {"url": "https://example.com"}, pair)
        check(not reply["ok"] and reply["code"] == "not_paired", "Chrome's key does not work from another extension")
        firefox.close()
        reply = host.ask(None, raw={"id": 99, "op": "entries"})
        check(not reply["ok"] and reply["code"] == "unknown_op", "the host relays only its own ops")
        browsers = client.request("browser_status")
        check([b["name"] for b in browsers["paired"]] == ["Chrome"] and browsers["paired"][0]["last_seen"], "Ajustes lists the browser")
        client.request("browser_forget", {"id": browsers["paired"][0]["id"]})
        reply = host.ask("logins", {"url": "https://example.com"}, pair)
        check(not reply["ok"] and reply["code"] == "not_paired", "disconnected from the app: refused")
        check(host.close() == 0, "the host ends when the browser closes its input")
    finally:
        service.stop()


# The content script with just enough of a page around it to answer the background's messages (Node, no browser).
CONTENT_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const node = () => ({ style: {}, append() {}, appendChild() {}, remove() {}, querySelector: () => node(),
  querySelectorAll: () => [], attachShadow: () => node(), addEventListener() {}, setAttribute() {}, classList: { toggle() {} } });
let listener = null;
const page = {
  location: { origin: 'https://evil.example.net', href: 'https://evil.example.net/' },
  document: { ...node(), documentElement: node(), createElement: node, activeElement: null, addEventListener() {} },
  innerWidth: 800, innerHeight: 600, addEventListener() {}, getComputedStyle: () => ({}),
  MutationObserver: class { observe() {} }, HTMLInputElement: class {}, HTMLElement: class {}, Event: class {},
  chrome: { i18n: { getMessage: (key) => key }, runtime: { id: 'us', sendMessage: () => Promise.resolve(null),
    onMessage: { addListener: (f) => { listener = f; } } } },
};
page.window = page; page.top = page;
Object.defineProperty(page.HTMLInputElement.prototype, 'value', { set() {}, configurable: true });
vm.createContext(page);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), page);
const ask = (origin) => { let answer; listener({ type: 'apply', what: 'login', values: { username: 'u', password: 'p' },
  origin }, { id: 'us' }, (a) => { answer = a; }); return answer; };
console.log(JSON.stringify({ other: ask('https://bank.example.com'), same: ask('https://evil.example.net') }));
"""


def check_content_script():
    print("Content script")
    import shutil
    node = shutil.which("node")
    if not node:
        print("  (skipped: no Node.js)")
        return
    script = Path(tempfile.mkdtemp(prefix="sb-content-")) / "harness.js"
    script.write_text(CONTENT_HARNESS, encoding="utf-8")
    result = subprocess.run([node, str(script), str(ROOT / "extension" / "content.js")], capture_output=True, text=True,
                            encoding="utf-8", timeout=60)
    try:
        answers = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        check(False, "the content script runs: " + (result.stderr or result.stdout)[-300:])
        return
    check(answers["other"] == {"ok": False, "error": "page_has_changed_try_again"},
          "values for another origin (the frame navigated since the service matched it) are never filled")
    check(answers["same"]["ok"] is False and answers["same"]["error"] != "page_has_changed_try_again",
          "the page that was matched is filled (here: it has no form)")


def check_registration():
    print("Registration")
    launcher = Path(tempfile.mkdtemp(prefix="sb-host-")) / "secretbroker-host"
    for system in ("linux", "darwin"):
        home = Path(tempfile.mkdtemp(prefix=f"sb-{system}-"))
        written = native_host.install_manifests(launcher, home=home, system=system)
        check(len(written) == 5 and all(p.is_file() for p in written), f"{system}: a manifest per browser")
        firefox = next(p for p in written if "ozilla" in str(p))
        chrome = next(p for p in written if "google-chrome" in str(p) or "Google/Chrome" in str(p).replace("\\", "/"))
        data = json.loads(chrome.read_text())
        check(data["name"] == native_host.HOST_NAME and data["type"] == "stdio" and data["path"] == str(launcher)
              and data["allowed_origins"] == [CHROME], f"{system}: Chrome's manifest allows only our extension")
        check(json.loads(firefox.read_text())["allowed_extensions"] == list(native_host.FIREFOX_EXTENSION_IDS),
              f"{system}: Firefox's lists our extension id")
        native_host.remove_manifests(home=home, system=system)
        check(not any(p.exists() for p in written), f"{system}: removed")
    check(native_host.origin_from(["chrome-extension://abc/", "--parent-window=1"]) == "chrome-extension://abc/", "Chromium's origin argument")
    check(native_host.origin_from(["C:\\x\\host.json", "autofill@secretbroker"]) == "moz-extension:autofill@secretbroker", "Firefox's arguments")
    check(native_host.extension_dir() is not None and (native_host.extension_dir() / "manifest.json").is_file(), "the extension folder is found")
    manifest = json.loads((ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
    import base64
    import hashlib
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).hexdigest()[:32]
    check("".join(chr(ord("a") + int(c, 16)) for c in digest) == native_host.CHROME_EXTENSION_IDS[0],
          "the key in manifest.json gives the extension id the host allows")
    check(manifest["browser_specific_settings"]["gecko"]["id"] in native_host.FIREFOX_EXTENSION_IDS, "and Firefox's id")
    if sys.platform == "win32":
        name = "com.secretbroker.test_" + os.urandom(4).hex()
        folder = Path(tempfile.mkdtemp(prefix="sb-win-"))
        result = native_host.register(host_name=name, folder=folder)
        state = native_host.registered(host_name=name)
        check(all(state.values()) and set(state) == set(native_host.WINDOWS_KEYS), "Windows: registered for Chrome, Chromium, Edge, Brave and Firefox (HKCU)")
        check(Path(result["launcher"]).read_text().startswith("@echo off"), "Windows: a launcher next to the manifests")
        native_host.unregister(host_name=name, folder=folder)
        check(not any(native_host.registered(host_name=name).values()), "Windows: unregistered")


def main():
    check_domains()
    check_team_review()
    check_host()
    check_content_script()
    check_registration()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (home: {HOME})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
