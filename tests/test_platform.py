"""The platform layer: every system module offers the whole interface, and what this system offers works.

Run with:  python tests/test_platform.py   (any system; no service, no GUI)
"""

import ast
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SECRETBROKER_HOME"] = tempfile.mkdtemp(prefix="sb-platform-")

from secretbroker import platform  # noqa: E402
from secretbroker.platform import _common  # noqa: E402

failures = []


def check(condition, label):
    print(("ok   " if condition else "FAIL ") + label)
    if not condition:
        failures.append(label)


def defined_names(module_file):
    """Top-level names of a module, read from its source (the other systems' modules cannot be imported here)."""
    tree = ast.parse(module_file.read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in node.names}
    return names


for name in ("windows", "linux", "macos"):
    missing = sorted(set(_common.INTERFACE) - defined_names(ROOT / "secretbroker" / "platform" / f"{name}.py"))
    check(not missing, f"{name}.py implements the whole interface" + (f" (missing {missing})" if missing else ""))

check(all(hasattr(platform, n) for n in _common.INTERFACE), f"secretbroker.platform exports everything ({platform.NAME})")
check(platform.NAME == {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux"), "the right module is chosen")

# Keys protected for the service account open again, and only with the same entropy.
folder = Path(tempfile.mkdtemp(prefix="sb-key-"))
blob = platform.protect_for_service(b"k" * 32, b"entropy/v1", folder)
check(platform.unprotect_for_service(blob, b"entropy/v1", folder) == b"k" * 32, "service key: round trip")
try:
    platform.unprotect_for_service(blob, b"other", folder)
    check(False, "service key: another entropy is refused")
except OSError:
    check(True, "service key: another entropy is refused")

import time  # noqa: E402

started = time.monotonic()
blob = platform.protect_for_user(b"session-token", b"session/v1")
check(platform.unprotect_for_user(blob, b"session/v1") == b"session-token", "user key: round trip")
check(time.monotonic() - started < 15, "user key: never waits for a prompt")
if platform.NAME != "windows":
    kept = {b"s": "the Secret Service keyring", b"k": "the login Keychain", b"f": "a 0600 file"}
    print(f"     (kept in {kept.get(blob[:1], 'an unknown place')})")

if platform.NAME == "linux":
    import stat
    key = folder / "machine.key"
    check(stat.S_IMODE(key.stat().st_mode) == 0o600, "Linux: the service key file is 0600")
    public = folder / "broker.json"
    platform.write_public_file(public, "{}", isolated=True)
    check(stat.S_IMODE(public.stat().st_mode) == 0o640, "Linux: broker.json of the isolated service is 0640 (owner's group)")
    platform.write_public_file(public, "{}", isolated=False)
    check(stat.S_IMODE(public.stat().st_mode) == 0o600, "Linux: broker.json in development is 0600")
    env = folder / "environment"
    env.write_text('# comment\nPATH="/usr/bin"\nexport API_TOKEN=abc\nBROKEN LINE\n')
    check(_common.parse_env_file(env) == {"PATH": "/usr/bin", "API_TOKEN": "abc"}, "Linux: /etc/environment is parsed")
    check(platform.verify_os_password(platform.default_owner(), "certainly-not-the-password-123") is False,
          "Linux: a wrong account password is refused by PAM")
    check(isinstance(platform.session_locked(), bool), "Linux: the lock screen state can be asked")
    check(platform.single_instance() and not platform.single_instance(), "Linux: a second app finds the first")

if platform.NAME == "macos":
    import stat
    check(stat.S_IMODE((folder / "machine.key").stat().st_mode) == 0o600, "macOS: the service key file is 0600")
    check(isinstance(platform.session_locked(), bool), "macOS: the lock screen state can be asked")
    check(platform.single_instance() and not platform.single_instance(), "macOS: a second app finds the first")
    check(platform.verify_os_password(platform.default_owner(), "certainly-not-the-password-123") is False,
          "macOS: a wrong account password is refused by Open Directory")
    check(isinstance(platform.biometric.is_supported(), bool), "macOS: asking for Touch ID never fails")
    print(f"     (Touch ID usable here: {platform.biometric.is_supported()}; Open Directory: {platform.os_password_available()})")

# The service accepts Touch ID's proofs (Secure Enclave P-256, ECDSA-SHA256) as it accepts Windows Hello's (RSA).
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402

from secretbroker import winsec  # noqa: E402


def _der(private):
    return private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


touch = ec.generate_private_key(ec.SECP256R1())
signature = touch.sign(b"challenge", ec.ECDSA(hashes.SHA256()))
check(winsec.verify_hello_signature(_der(touch), b"challenge", signature), "Touch ID: a P-256 signature is accepted")
check(not winsec.verify_hello_signature(_der(touch), b"other", signature), "Touch ID: a signature of another challenge is refused")
other = ec.generate_private_key(ec.SECP384R1())
try:
    winsec.load_hello_public_key(_der(other))
    check(False, "Touch ID: keys on other curves are refused")
except ValueError:
    check(True, "Touch ID: keys on other curves are refused")
hello_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
check(winsec.verify_hello_signature(_der(hello_key), b"challenge", hello_key.sign(b"challenge", padding.PKCS1v15(), hashes.SHA256())),
      "Windows Hello: an RSA signature is still accepted")
weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
check(not winsec.verify_hello_signature(_der(weak), b"challenge", weak.sign(b"challenge", padding.PKCS1v15(), hashes.SHA256())),
      "Windows Hello: RSA keys under 2048 bits are still refused")

# The updater picks this system's installer from a release that carries all of them (and only with its signature).
from secretbroker import update  # noqa: E402

machine = os.uname().machine if hasattr(os, "uname") else ""
mine = {"windows": "SecretBroker-Setup-1.2.3.exe", "linux": "secretbroker_1.2.3_amd64.deb",
        "macos": f"SecretBroker-1.2.3-macos-{'arm64' if machine == 'arm64' else 'x86_64'}.pkg"}[platform.NAME]
names = ["SecretBroker-Setup-1.2.3.exe", "secretbroker_1.2.3_amd64.deb", "SecretBroker-1.2.3-macos-arm64.pkg",
         "SecretBroker-1.2.3-macos-x86_64.pkg"]
check([n for n in names if update.INSTALLER_RE.match(n)] == [mine], f"updater: only {mine} is this system's installer")


class _Release:
    def __init__(self, assets):
        self.assets = assets

    def json(self):
        return {"html_url": "https://github.com/x/y/releases/tag/v1.2.3", "body": "notes",
                "assets": [{"name": n, "browser_download_url": f"https://github.com/x/y/releases/download/v1.2.3/{n}"}
                           for n in self.assets]}


_real_get = update._get
try:
    update._get = lambda client, url, **kw: _Release(names + [n + ".sig" for n in names])
    latest = update.fetch_latest()
    check(latest and latest["installer"]["name"] == mine and latest["signature"].endswith(mine + ".sig")
          and latest["version"] == "1.2.3", "updater: the release's asset and signature for this system are chosen")
    update._get = lambda client, url, **kw: _Release(names + [n + ".sig" for n in names if n != mine])
    check(update.fetch_latest() is None, "updater: an installer without its signature is never offered")
finally:
    update._get = _real_get

# On a Mac the app says «Mac» for this computer and «ordenador» / "computer" for any other, in every language.
import json  # noqa: E402
import re  # noqa: E402

from secretbroker import i18n  # noqa: E402

OTHER_MAC = re.compile(r"\b(otro|otra|another|other|autre|anderen|anderer|altro|outro|noutro|altre|alt|celălalt|cada|each|"
                       r"chaque|jedem|ogni|fiecare|hver|kull|propriul|own|eigenen|proprio|seu|su|son|sin|their)\s+Mac\b", re.I)
leftover, others, same = [], [], True
for folder in (i18n.WEB_LOCALES, i18n.LOCALES):
    for code in i18n.available():
        raw = json.loads((folder / f"{code}.json").read_text(encoding="utf-8"))
        same = same and i18n.for_system(raw, code, "windows") == raw and i18n.for_system(raw, code, "linux") == raw
        mac = i18n.for_system(raw, code, "macos")
        for key, value in mac.items():
            for text in (value.values() if isinstance(value, dict) else [value]):
                if re.search(r"\bPC\b", text, re.I):  # «PC», «pc» (Dutch, Danish), «Pc»
                    leftover.append(f"{code}:{key}")
                if OTHER_MAC.search(text):
                    others.append(f"{code}:{key}: {text[:80]}")
check(same, "Windows and Linux keep «PC»")
check(not leftover, "macOS: no «PC» left in any language" + (f" ({leftover[:5]})" if leftover else ""))
check(not others, "macOS: another computer is never «otro Mac»" + (f" ({others[:3]})" if others else ""))
web = lambda code, key: i18n.for_system(json.loads((i18n.WEB_LOCALES / f"{code}.json").read_text(encoding="utf-8")), code, "macos")[key]
check(web("es", "setup.encrypted_on_this_pc") == "Cifrado en este Mac. " and web("es", "import_source.on_other_pc") == "En el otro ordenador: "
      and web("en", "setup.encrypted_on_this_pc") == "Encrypted on this Mac. " and web("en", "import_source.on_other_pc") == "On the other computer: "
      and web("de", "setup.encrypted_on_this_pc") == "Verschlüsselt auf diesem Mac. " and web("fr", "import_source.on_other_pc") == "Sur l’autre ordinateur : "
      and web("ru", "setup.encrypted_on_this_pc") == "Шифруется на этом Mac. ",
      "macOS: «Cifrado en este Mac», «En el otro ordenador» (and in other languages)")
mac_text = lambda code, text: i18n.for_system({"k": text}, code, "macos")["k"]
check(mac_text("nl", "Programma op deze pc") == "Programma op deze Mac" and mac_text("nl", "Van pc wisselen") == "Van computer wisselen"
      and mac_text("nl", "Op een andere pc") == "Op een andere computer"
      and mac_text("da", "på denne pc.") == "på denne Mac." and mac_text("da", "genstart din pc") == "genstart din Mac"
      and mac_text("da", "forlader de pc'en") == "forlader de computeren" and mac_text("da", "en anden pc") == "en anden computer",
      "macOS: Dutch and Danish write «pc»: «deze Mac», «andere computer», «denne Mac», «pc'en» → «computeren»")
check(mac_text("es", "Pc nuevo") == "Ordenador nuevo" and mac_text("es", "otro pc") == "otro ordenador"
      and mac_text("es", "este pc") == "este Mac" and mac_text("es", "otro PC") == "otro ordenador"
      and mac_text("de", "Ein anderer PC") == "Ein anderer Computer" and mac_text("en", "your pc") == "your Mac"
      and mac_text("fr", "un autre pc") == "un autre ordinateur",
      "macOS: the word put in keeps the case style of the «PC» it replaces («pc» → «ordenador», «Pc» → «Ordenador»)")
check(mac_text("hu", "pcsős") == "pcsős" and mac_text("pl", "pcze") == "pcze", "and only the word PC, nothing that contains it")

# The window's page may call the app only while it shows the app's own page: a link or file dropped on the window
# (or anything that navigates it) gets pywebview's bridge too, and must not reveal, export or approve anything.
import inspect  # noqa: E402

from secretbroker import app  # noqa: E402


class _Gui:
    url = None

    def get_current_url(self, uid):
        return self.url


class _Window:
    uid, real_url, gui = "master", "http://127.0.0.1:43123/index.html", _Gui()


inner, window = app.Api(), _Window()
page = app.page_api(inner, window)
exposed = [n for n in dir(inner) if not n.startswith("_") and callable(getattr(inner, n))]
check(exposed and all(inspect.getfullargspec(getattr(page, n)).args == inspect.getfullargspec(getattr(inner, n)).args
                      for n in exposed), "the page gets every method of the app, with the same arguments")
check(not [n for n in dir(page) if not n.startswith("_") and n not in exposed], "and nothing else")
calls = []
inner.has_presence = lambda: calls.append(1) or True
results = []
for url in ("http://127.0.0.1:43123/index.html", "http://127.0.0.1:43123/index.html#top", "http://evil.example/index.html",
            "file:///C:/Users/x/Downloads/evil.html", "http://127.0.0.1:43123/other.html", "http://127.0.0.1:9999/index.html",
            None, "about:blank"):
    window.gui.url = url
    try:
        results.append(page.has_presence())
    except PermissionError:
        results.append("refused")
check(results == [True, True] + ["refused"] * 6 and len(calls) == 2,
      f"only the app's own page may call it; any other page, or none, is refused ({results})")

# pywebview's page server: room for every file the page asks for at once (its default queue of 5 refused one).
import socketserver  # noqa: E402
app._roomy_page_server()
check(socketserver.TCPServer.request_queue_size >= 32, f"the page server queues every request ({socketserver.TCPServer.request_queue_size})")
window.gui.get_current_url = lambda uid: (_ for _ in ()).throw(RuntimeError("closing"))
try:
    page.has_presence()
    check(False, "if the address can't be read, the call is refused")
except PermissionError:
    check(True, "if the address can't be read, the call is refused")

# The preferences are read by the page (info(): the language of the welcome) while the app writes them at start
# (the MCP token): a reader must never catch the file half written, and two writers must not drop each other's key.
import threading  # noqa: E402
import time  # noqa: E402

from secretbroker import integrations  # noqa: E402

integrations.set_pref("language", "es")
seen, stop = [], threading.Event()


def _read_prefs():
    while not stop.is_set():
        seen.append(integrations.load_prefs().get("language"))
        time.sleep(0.001)


readers = [threading.Thread(target=_read_prefs) for _ in range(2)]
writers = [threading.Thread(target=lambda n=n: [integrations.set_pref(f"key{n}", i) for i in range(100)]) for n in range(3)]
for t in readers + writers:
    t.start()
for t in writers:
    t.join()
stop.set()
for t in readers:
    t.join()
prefs = integrations.load_prefs()
check(seen and all(v == "es" for v in seen), f"the preferences are never read half written ({len(seen)} reads, "
      f"{sum(v != 'es' for v in seen)} without the language)")
check(all(prefs.get(f"key{n}") == 99 for n in range(3)) and prefs.get("language") == "es",
      "writers at once keep every key")
check(len({integrations.mcp_endpoint()[1] for _ in range(3)}) == 1, "the MCP token is made once")

# A scan renews the exposure session as it begins; a report that went out with the old one and answers late must
# not clear the new one (the page would ask who you are again, and «Borrar de este archivo» would be refused).
api = app.Api()
api._scan_session = "old"


def _late_report(op, params, proof=None):
    api._scan_session = "new"  # the scan's exposure_begin answered while this report was on its way
    return {"ok": True, "result": {"details": False}}


api.call = _late_report
api.exposure_report(background=True)
check(api._scan_session == "new", "a late report without details keeps the session a scan has just renewed")
api.call = lambda op, params, proof=None: {"ok": True, "result": {"details": False}}
api.exposure_report(background=True)
check(api._scan_session is None, "and a report without details for the current session forgets it")

print()
if failures:
    print(f"{len(failures)} FAILED")
    sys.exit(1)
print("all platform checks passed")
