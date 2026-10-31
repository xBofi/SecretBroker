"""The browser extension in a real browser: Microsoft Edge (or Chrome for Testing / Chromium) with the unpacked
extension/, its native messaging host registered for this user, the desktop app and a throwaway vault, against local
test sites. Saves screenshots to look at.

    python tests/test_browser.py            (needs: pip install websocket-client)

    SB_BROWSER=edge | chrome                which browser (default: the first one that loads the extension)
    SB_CHROME=C:\\path\\to\\chrome.exe        a Chrome for Testing or Chromium build (stable Chrome ignores
                                            --load-extension since version 137)

What it covers: connecting the browser from the extension and the app (Ajustes › Navegador), the popup showing the
login of the site, filling user + password (in-page menu and popup) and the 2FA code, nothing for a lookalike domain
or for 127.0.0.1 instead of the saved host, nothing in a frame of another site, «Save this login?» after a form is
sent (stored only after the click), team logins marked «use only» refused, the locked vault, the site's own icon,
light and dark. The browser is driven through the DevTools protocol; clicks and typing are real input events
(trusted), so the extension's isTrusted checks apply. The keyboard shortcut is a browser command that DevTools cannot
press: its handler is called from the extension's worker instead.

Skips (exit 0) when not on Windows or no browser that loads unpacked extensions is installed. The native host is
registered in HKCU for the test and the previous registration is restored at the end (the installed SecretBroker
writes its own again at every start anyway). Firefox, Brave and the stores are not covered: see extension/README.md.
"""

import base64
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOME = Path(tempfile.mkdtemp(prefix="secretbroker-browser-"))
os.environ["SECRETBROKER_HOME"] = str(HOME)  # before importing secretbroker
sys.path.insert(0, str(ROOT))
SHOTS = HOME / "screenshots"
EXTENSION = ROOT / "extension"
MASTER = "una contraseña de prueba larga"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
failures = 0

BROWSERS = {
    "edge": [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"],
    "chrome": [os.environ.get("SB_CHROME") or "", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")],
}


def check(condition, message):
    global failures
    print(f"  {'OK  ' if condition else 'FAIL'} {message}", flush=True)
    if not condition:
        failures += 1
    return condition


def wait_for(condition, seconds=15, step=0.2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = condition()
            if value:
                return value
        except Exception:
            pass
        time.sleep(step)
    return None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ----------------------------------------------------------------------------------------- the test sites


def png(color, size=32):
    """A plain square PNG: the test site's favicon."""
    row = b"\x00" + bytes(color) * size
    raw = zlib.compress(row * size)
    chunk = lambda kind, data: struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


FAVICON = png((214, 64, 52))
STYLE = """<style>body { font: 15px system-ui, sans-serif; margin: 40px; color: #222 }
form { display: grid; gap: 10px; width: 320px } input { font: inherit; padding: 8px 10px; border: 1px solid #aaa; border-radius: 6px }
button { font: inherit; padding: 8px 12px } iframe { border: 1px solid #aaa; width: 420px; height: 260px }</style>"""


def page(title, body):
    return f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{title}</title>{STYLE}</head><body><h1>{title}</h1>{body}</body></html>"


LOGIN_FORM = """<form id='login' action='/welcome' method='post'>
<label>Email <input id='user' name='email' type='email' autocomplete='username'></label>
<label>Password <input id='pass' name='password' type='password' autocomplete='current-password'></label>
<button id='go' type='submit'>Sign in</button></form>"""
OTP_FORM = """<form id='otp-form' action='/welcome' method='post'>
<label>Code from your authenticator app <input id='otp' name='otp' inputmode='numeric' autocomplete='one-time-code' maxlength='6'></label>
<button type='submit'>Verify</button></form>"""
SIGNUP_FORM = """<form id='signup' action='/welcome' method='post'>
<label>Email <input id='user' name='email' type='email' autocomplete='username'></label>
<label>New password <input id='pass' name='password' type='password' autocomplete='new-password'></label>
<button id='go' type='submit'>Create account</button></form>"""


class Sites(BaseHTTPRequestHandler):
    """Every host name (shop.localhost, shop-login.localhost, 127.0.0.1…) gets the same pages: the browser and
    SecretBroker tell the sites apart by the address only, as they would on the internet."""
    port = 0

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/favicon.ico":
            return self.reply(FAVICON, "image/png")
        if path == "/login":
            return self.reply(page("Shop · Sign in", LOGIN_FORM))
        if path == "/2fa":
            return self.reply(page("Shop · Two-step verification", OTP_FORM))
        if path == "/signup":
            return self.reply(page("Forum · Create your account", SIGNUP_FORM))
        if path == "/framed":  # a page that shows another site's login form in a frame
            src = self.path.split("src=", 1)[1] if "src=" in self.path else ""
            return self.reply(page("Shop · Partner offers", f"<p>Sign in to see the offers:</p><iframe id='frame' src='{src}'></iframe>"))
        self.reply(page("Not found", "<p>Nothing here.</p>"), status=404)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.reply(page("Welcome", "<p id='done'>Signed in.</p>"))

    def reply(self, body, kind="text/html; charset=utf-8", status=200):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class DualStackServer(ThreadingHTTPServer):
    """*.localhost may resolve to ::1 or 127.0.0.1: listen on both."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def handle_error(self, request, client_address):
        pass  # the browser drops idle keep-alive connections


# ----------------------------------------------------------------------------------------- DevTools protocol


class Cdp:
    """One browser-level DevTools connection; targets are driven through flat sessions."""

    def __init__(self, port):
        import websocket
        version = wait_for(lambda: json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)), 40)
        if not version:
            raise RuntimeError("the browser did not open its DevTools port")
        self.version = version.get("Browser", "")
        self.ws = websocket.create_connection(version["webSocketDebuggerUrl"], timeout=60, suppress_origin=True)
        self._id = 0
        self.errors = []

    def send(self, method, session=None, timeout=60, **params):
        self._id += 1
        message = {"id": self._id, "method": method, "params": params}
        if session:
            message["sessionId"] = session
        self.ws.settimeout(timeout)
        self.ws.send(json.dumps(message))
        while True:
            reply = json.loads(self.ws.recv())
            if reply.get("method") == "Runtime.exceptionThrown":
                self.errors.append(reply["params"]["exceptionDetails"].get("exception", {}).get("description", "?"))
            if reply.get("id") == self._id:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error'].get('message')}")
                return reply.get("result", {})

    def targets(self):
        return self.send("Target.getTargets")["targetInfos"]

    def target(self, condition, seconds=15):
        return wait_for(lambda: next((t for t in self.targets() if condition(t)), None), seconds)


class Target:
    """A page, a frame, the popup or the extension's worker."""

    def __init__(self, cdp, info):
        self.cdp, self.info = cdp, info
        self.id = info["targetId"]
        self.session = cdp.send("Target.attachToTarget", targetId=self.id, flatten=True)["sessionId"]
        if info["type"] in ("page", "iframe"):
            self.send("Page.enable")
            self.send("Runtime.enable")
            # The browser window is not the foreground window while a test runs: let the page behave as focused,
            # so a click focuses the field (focusin) like it does for a user.
            self.send("Emulation.setFocusEmulationEnabled", enabled=True)

    def send(self, method, **params):
        return self.cdp.send(method, session=self.session, **params)

    def js(self, expression):
        result = self.send("Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True, userGesture=False)
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"].get("exception", {}).get("description", result["exceptionDetails"]))
        return result["result"].get("value")

    def goto(self, url):
        self.send("Page.navigate", url=url)
        wait_for(lambda: self.js("location.href") == url and self.js("document.readyState") == "complete", 15)
        time.sleep(0.6)  # the content script runs at document_idle and reports the form after 400 ms

    def theme(self, scheme):
        self.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": scheme}])

    def shot(self, name):
        SHOTS.mkdir(exist_ok=True)
        time.sleep(0.3)
        data = self.send("Page.captureScreenshot", format="png")["data"]
        (SHOTS / f"{name}.png").write_bytes(base64.b64decode(data))

    # Real (trusted) input.
    def click_at(self, x, y):
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            self.send("Input.dispatchMouseEvent", type=kind, x=x, y=y, button="left", buttons=1 if kind == "mousePressed" else 0,
                      clickCount=0 if kind == "mouseMoved" else 1)

    def rect(self, selector):
        return self.js(f"""(() => {{ const n = document.querySelector({json.dumps(selector)}); if (!n) return null;
          n.scrollIntoView({{ block: 'center' }}); const r = n.getBoundingClientRect(); return [r.left, r.top, r.width, r.height]; }})()""")

    def click(self, selector, at="center"):
        box = self.rect(selector)
        if not box:
            return False
        x = box[0] + (box[2] - 30 if at == "right" else box[2] / 2)
        self.click_at(x, box[1] + box[3] / 2)
        return True

    def type(self, text):
        self.send("Input.insertText", text=text)

    def enter(self):
        for kind in ("rawKeyDown", "char", "keyUp"):
            self.send("Input.dispatchKeyEvent", type=kind, key="Enter", code="Enter", windowsVirtualKeyCode=13,
                      **({"text": "\r"} if kind == "char" else {}))

    # What the content script draws lives in a closed shadow root: DevTools sees through it (pierce).
    def ui_nodes(self):
        root = self.send("DOM.getDocument", depth=-1, pierce=True)["root"]
        found = []

        def walk(node, inside):
            inside = inside or node.get("nodeName", "").lower() == "secretbroker-ui"
            if inside and node.get("nodeType") == 1:
                attrs = node.get("attributes") or []
                found.append({"node": node, "class": dict(zip(attrs[::2], attrs[1::2])).get("class", ""),
                              "attrs": dict(zip(attrs[::2], attrs[1::2]))})
            for child in (node.get("children") or []) + (node.get("shadowRoots") or []):
                walk(child, inside)

        walk(root, False)
        return found

    @staticmethod
    def text_of(node):
        if node.get("nodeType") == 3:
            return node.get("nodeValue", "")
        return "".join(Target.text_of(c) for c in (node.get("children") or []) + (node.get("shadowRoots") or [])
                       if c.get("nodeName", "").lower() != "style")

    def ui(self, cls):
        """The elements of our UI with this class: [{class, text, attrs, node}]."""
        return [dict(n, text=self.text_of(n["node"])) for n in self.ui_nodes() if cls in n["class"].split()]

    def ui_text(self):
        nodes = self.ui_nodes()
        return " ".join(self.text_of(n["node"]) for n in nodes if n["node"].get("nodeName", "").lower() == "div" and "sb" in n["class"].split())

    def click_ui(self, cls, text=None, offset=(0, 0)):
        matches = [n for n in self.ui(cls) if text is None or text in n["text"]]
        if not matches:
            return False
        quad = self.send("DOM.getBoxModel", backendNodeId=matches[0]["node"]["backendNodeId"])["model"]["border"]
        x, y = sum(quad[0::2]) / 4 + offset[0], sum(quad[1::2]) / 4 + offset[1]
        self.click_at(x, y)
        return True


# ----------------------------------------------------------------------------------------- the browser


def native_host_keys():
    """The current registration of our native host for each browser (to put back at the end)."""
    import winreg
    from secretbroker import native_host
    saved = {}
    for browser, key in native_host.WINDOWS_KEYS.items():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key + "\\" + native_host.HOST_NAME) as handle:
                saved[key] = winreg.QueryValueEx(handle, "")[0]
        except OSError:
            saved[key] = None
    return saved


def restore_native_host_keys(saved):
    import winreg
    from secretbroker import native_host
    for key, value in saved.items():
        path = key + "\\" + native_host.HOST_NAME
        if value is None:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
        else:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as handle:
                winreg.SetValueEx(handle, "", 0, winreg.REG_SZ, value)


def start_browser(kind, executable, env):
    port = free_port()
    profile = HOME / f"{kind}-profile"
    args = [executable, f"--user-data-dir={profile}", f"--remote-debugging-port={port}", "--no-first-run",
            "--no-default-browser-check", "--disable-sync", "--lang=en-US", "--window-size=1280,900",
            "--disable-features=msImplicitSignin,msEdgeSidebarV2,DisableLoadExtensionCommandLineSwitch",
            "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
            f"--load-extension={EXTENSION}", f"--disable-extensions-except={EXTENSION}", "about:blank"]
    process = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cdp = Cdp(port)
    worker = cdp.target(lambda t: t["type"] == "service_worker" and t["url"].startswith(f"chrome-extension://{EXTENSION_ID}/"), 15)
    return process, cdp, worker


def bring_to_front(pid):
    """Make the browser's window the foreground one, as a click on it would (Chrome only opens its popup over an
    active window; the test process may not have the focus to hand it over: an Alt press lifts that restriction)."""
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd) and user32.GetWindowTextLengthW(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    for hwnd in found[:1]:
        user32.keybd_event(0x12, 0, 0, 0)  # Alt down
        user32.keybd_event(0x12, 0, 2, 0)  # Alt up
        user32.SetForegroundWindow(hwnd)
    return bool(found)


def stop_browser(process, kind):
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
    # Browsers relaunch helpers; anything left with our profile goes too.
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*" + str(HOME / f"{kind}-profile").replace("'", "''")
                    + "*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"], capture_output=True)


# ----------------------------------------------------------------------------------------- the app


def start_app(env):
    devtools = free_port()
    app_env = {**env, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={devtools} --disable-background-timer-throttling "
               "--disable-renderer-backgrounding --disable-backgrounding-occluded-windows --disable-features=CalculateNativeWinOcclusion"}
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    process = subprocess.Popen([str(pythonw), "-m", "secretbroker.app"], cwd=ROOT, env=app_env)
    cdp = Cdp(devtools)
    info = cdp.target(lambda t: t["type"] == "page", 40)
    return process, Target(cdp, info)


def app_click(app, label, scope=""):
    return app.js(f"""(() => {{ const b = [...document.querySelectorAll({json.dumps((scope + ' button').strip())})]
      .find((n) => n.innerText.trim() === {json.dumps(label)} && n.offsetParent !== null); if (!b) return false; b.click(); return true; }})()""")


# ----------------------------------------------------------------------------------------- the popup


BROWSER_PID = [0]


def open_popup(cdp, worker, tab, scheme="light", attempts=3):
    """The toolbar popup, opened as the toolbar button would (chrome.action.openPopup) over `tab`. A popup closes when
    its window loses the focus (a tab that just closed hands it back late): then it is opened again."""
    for attempt in range(attempts):
        try:
            return _open_popup(cdp, worker, tab, scheme, last=attempt == attempts - 1)
        except RuntimeError as exc:
            if "Session" not in str(exc) and "No target" not in str(exc):
                raise
            time.sleep(1)
    return None


def _open_popup(cdp, worker, tab, scheme, last):
    for t in cdp.targets():
        if t["url"].endswith("/popup.html"):
            try:
                cdp.send("Target.closeTarget", targetId=t["targetId"])
            except RuntimeError:
                pass
    wait_for(lambda: not any(t["url"].endswith("/popup.html") for t in cdp.targets()), 5)
    cdp.send("Target.activateTarget", targetId=tab.id)
    tab.send("Page.bringToFront")
    error = None
    for _ in range(5):  # the window the popup belongs to must be the browser's focused one
        try:
            # (openPopup may also never answer when another window has the focus: give up after 5 s and try again)
            worker.js("Promise.race([chrome.windows.getLastFocused().then((w) => chrome.windows.update(w.id, { focused: true }))"
                      ".then((w) => chrome.action.openPopup({ windowId: w.id })).then(() => true),"
                      " new Promise((_, no) => setTimeout(() => no(new Error('openPopup did not answer')), 5000))])")
            error = None
            break
        except RuntimeError as exc:
            error = exc
            bring_to_front(BROWSER_PID[0])
            time.sleep(0.5)
    if error:
        if not last:
            raise RuntimeError(f"No target: {error}")
        check(False, f"chrome.action.openPopup: {error}")
        return None
    info = cdp.target(lambda t: t["type"] == "page" and t["url"].endswith("/popup.html"), 10)
    if not info:
        return None
    popup = Target(cdp, info)
    popup.theme(scheme)
    wait_for(lambda: popup.js("!document.querySelector('.spinner')"), 15)
    time.sleep(0.4)
    return popup


def popup_text(popup):
    """The popup's text ("" if there is none, or the browser closed it)."""
    try:
        return (popup and popup.js("document.body.innerText")) or ""
    except RuntimeError:
        return ""


def spanish_in(text):
    """Spanish messages of the extension (that English does not share) found in `text`."""
    es = json.loads((EXTENSION / "_locales" / "es" / "messages.json").read_text(encoding="utf-8"))
    en = json.loads((EXTENSION / "_locales" / "en" / "messages.json").read_text(encoding="utf-8"))
    english = " ".join(m["message"] for m in en.values())
    pieces = {p.strip(" .,:;·()«»") for m in es.values() for p in re.split(r"\$\w+\$", m["message"])}
    return sorted(p for p in pieces if len(p) >= 12 and p in text and p not in english)


EXTENSION_ID = None


def main():
    if sys.platform != "win32":
        print("SKIP: the browser test runs on Windows (the native host is registered in HKCU there).")
        return 0
    try:
        import websocket  # noqa: F401
    except ImportError:
        print("SKIP: pip install websocket-client")
        return 0
    from secretbroker import native_host
    global EXTENSION_ID
    EXTENSION_ID = native_host.CHROME_EXTENSION_IDS[0]
    wanted = [os.environ["SB_BROWSER"]] if os.environ.get("SB_BROWSER") else list(BROWSERS)
    candidates = [(kind, path) for kind in wanted for path in BROWSERS.get(kind, []) if path and Path(path).is_file()]
    if not candidates:
        print(f"SKIP: no supported browser installed ({', '.join(wanted)})")
        return 0

    print(f"Test home: {HOME}")
    sites = DualStackServer(("::", 0), Sites)
    port = sites.server_address[1]
    threading.Thread(target=sites.serve_forever, daemon=True).start()

    from secretbroker import client
    from secretbroker.service import Service
    (HOME / "user").mkdir(parents=True, exist_ok=True)
    (HOME / "user" / "prefs.json").write_text(json.dumps({"auto_scan": False, "language": "en"}), encoding="utf-8")
    service = Service(HOME, owner=f"{os.environ.get('USERDOMAIN')}\\{os.environ.get('USERNAME')}", isolated=False)
    service.start()
    client.request("create_vault", {"master_password": MASTER})
    client.request("lock")
    env = {**os.environ, "SECRETBROKER_HOME": str(HOME), "SECRETBROKER_PROFILE": str(HOME / "profile")}

    saved_keys = native_host_keys()
    app = browser = None
    try:
        registered = native_host.register(folder=HOME / "native-host")
        check(native_host.registered().get("edge") and native_host.registered().get("chrome"),
              f"the native host is registered for this user ({registered['launcher']})")
        app, page = start_app(env)
        for kind, path in candidates:
            process, cdp, worker = start_browser(kind, path, env)
            if worker:
                browser = (kind, process, cdp, worker)
                break
            print(f"  ...  {kind} ({path}) did not load the unpacked extension"
                  + (" (stable Chrome ignores --load-extension since 137: set SB_CHROME to a Chrome for Testing build)" if kind == "chrome" else ""))
            stop_browser(process, kind)
        if not browser:
            print("SKIP: no installed browser loads the unpacked extension")
            return 0
        kind, process, cdp, worker = browser
        BROWSER_PID[0] = process.pid
        print(f"Browser: {cdp.version} with the unpacked extension")
        run(cdp, Target(cdp, worker), page, service, client, port, kind)
    finally:
        if browser:
            stop_browser(browser[1], browser[0])
        if app and app.poll() is None:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(app.pid)], capture_output=True)
        restore_native_host_keys(saved_keys)
        service.stop()
        sites.shutdown()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (screenshots: {SHOTS})")
    return 1 if failures else 0


def web_login(entry_id, name, url, username, password, **extra):
    return {"id": entry_id, "name": name, "template": "web_login", "description": "",
            "fields": {"url": url, "username": username, "password": password, **extra.pop("fields", {})},
            "policy": {"approval": "session"}, **extra}


def run(cdp, worker, app, service, client, port, kind):
    from secretbroker import totp
    shop = f"http://shop.localhost:{port}"
    lookalike = f"http://shop-login.localhost:{port}"
    by_ip = f"http://127.0.0.1:{port}"
    forum = f"http://forum.localhost:{port}"
    # Edge, Chrome, or Chromium for Chrome for Testing and Linux builds (once the worker has run its script).
    Browser = wait_for(lambda: worker.js("typeof browserName === 'function' && browserName()"), 15)
    check(Browser in ("Edge", "Chrome", "Chromium"), f"the extension knows which browser it is in ({Browser})")

    print("The app, unlocked once with the master password")
    check(wait_for(lambda: "SecretBroker is locked" in app.js("document.body.innerText"), 30), "the app opens on its lock screen (in English)")
    app.js(f"""(() => {{ const i = document.querySelector('.auth input[type=password], input[type=password]'); i.value = {json.dumps(MASTER)};
      i.dispatchEvent(new KeyboardEvent('keydown', {{ key: 'Enter' }})); }})()""")
    check(wait_for(lambda: client.request("status")["state"] == "unlocked", 15), "unlocked")
    vault = service.vault
    vault.put(web_login("shop", "Shop", shop, "ana@shop.test", "Shop-fake-pass-1", fields={"totp": TOTP_SECRET}))
    vault.put(web_login("shop-team", "Shop admin (team)", shop, "admin@shop.test", "Team-fake-pass-2",
                        shared={"org": "o1", "collection": "c1", "item": "i1", "permission": "use", "collection_name": "Ops"}))
    app.js("loadEntries().then(renderMain)")

    tab = Target(cdp, cdp.target(lambda t: t["type"] == "page" and t["url"] == "about:blank"))
    tab.theme("light")

    print("Connecting the browser (extension › Connect, app › Connect)")
    tab.goto(f"{shop}/login")
    popup = open_popup(cdp, worker, tab)
    if not check(popup is not None, "the toolbar popup opens"):
        return
    text = popup_text(popup)
    check("Connect this browser" in text and f"Connect {Browser}" in text, f"an unconnected browser is asked to connect ({text[:120]!r})")
    popup.shot(f"{kind}-01-popup-connect")
    popup.click("button.btn.primary")
    code = wait_for(lambda: (popup.js("(document.querySelector('.code') || {}).textContent") or "").replace(" ", ""), 10)
    check(code and len(code) == 6, f"the popup shows a 6-digit code ({code})")
    popup.shot(f"{kind}-02-popup-code")
    asked = wait_for(lambda: app.js("(document.querySelector('.modal .pair-code .code') || {}).textContent"), 15)
    check(asked and asked.replace(" ", "") == code, f"the app asks to connect {Browser} with the same code ({asked})")
    check(f"Connect {Browser}?" in (app.js("document.querySelector('.modal').innerText") or ""), "titled «Connect <browser>?»")
    app.shot(f"{kind}-03-app-pair")
    # «Connect» brings the app forward; when Windows lets it take the focus, the browser closes its popup (as for a
    # user). Opened again, the popup shows the same code until the app answers.
    reopened = lambda: open_popup(cdp, worker, tab)
    again = wait_for(lambda: (reopened().js("(document.querySelector('.code') || {}).textContent") or "").replace(" ", ""), 20, 1)
    check(again == code, f"the popup opened again still shows the code to compare ({again})")
    app_click(app, "Connect", ".modal-foot")
    check(wait_for(lambda: "ana@shop.test" in popup_text(reopened()), 20, 1), "one click in the app, and the popup lists the site's login")
    app.js("state.view = 'settings'; renderMain()")
    wait_for(lambda: "Browser extension" in app.js("document.body.innerText"), 10)
    app.js("[...document.querySelectorAll('.settings-group')].find((g) => /Browser/.test((g.querySelector('h3') || {}).textContent || '')).scrollIntoView()")
    check(wait_for(lambda: Browser in app.js("document.body.innerText") and "Disconnect" in app.js("document.body.innerText"), 10),
          f"Settings › Browser lists {Browser} as connected")
    app.shot(f"{kind}-04-app-settings-browser")

    print("The popup on the login page")
    popup = open_popup(cdp, worker, tab)
    text = popup_text(popup)
    rows = popup.js("[...document.querySelectorAll('.row')].map((r) => r.innerText.replace(/\\s+/g, ' ').trim())")
    check(len(rows) == 2 and rows[0].startswith("Shop") and "ana@shop.test" in rows[0], f"the site's login first ({rows})")
    check("Use only" in rows[1] and popup.js("document.querySelectorAll('.row')[1].querySelectorAll('button').length") == 0,
          "the team login marked «use only» is listed without fill or copy buttons")
    check("shop.localhost" in text and "No HTTPS" not in text, f"it says which site ({text[:80]!r})")
    check(wait_for(lambda: popup.js("!!document.querySelector('.row .avatar.has-icon img')"), 8), "the site's own icon (its favicon)")
    check(not spanish_in(text), f"no Spanish in the popup ({spanish_in(text)[:4]})")
    popup.shot(f"{kind}-05-popup-logins-light")
    popup.theme("dark")
    popup.shot(f"{kind}-06-popup-logins-dark")
    popup.theme("light")
    popup.click(".row .icon-btn[aria-label='Copy password']")
    copied = wait_for(lambda: subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"], capture_output=True,
                                             text=True).stdout.strip() == "Shop-fake-pass-1", 5)
    check(copied and "Password copied" in popup_text(popup), "«Copy password» puts it on the clipboard, and says so")
    subprocess.run(["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value ' '"], capture_output=True)
    popup.click(".row .btn.primary")
    check(wait_for(lambda: tab.js("document.getElementById('pass').value") == "Shop-fake-pass-1", 10)
          and tab.js("document.getElementById('user').value") == "ana@shop.test", "«Fill in» fills user and password")
    check(wait_for(lambda: not any(t["url"].endswith("/popup.html") for t in cdp.targets()), 5), "and the popup closes")
    tab.shot(f"{kind}-07-page-filled")

    print("The SecretBroker button in the field")
    tab.goto(f"{shop}/login")
    tab.click("#user")
    check(wait_for(lambda: tab.ui("button"), 5), "focusing the user field shows the SecretBroker button")
    tab.click_ui("button")
    check(wait_for(lambda: "ana@shop.test" in " ".join(n["text"] for n in tab.ui("item")), 10), "its menu lists the site's login")
    items = tab.ui("item")
    check(len(items) == 2 and "disabled" in items[1]["attrs"] and "Use only" in items[1]["text"], "the «use only» login is there, disabled")
    check(wait_for(lambda: tab.ui("has-icon"), 8), "with the site's icon")
    check(not spanish_in(tab.ui_text()), f"no Spanish in the menu ({spanish_in(tab.ui_text())[:4]})")
    tab.shot(f"{kind}-08-menu-light")
    tab.click_ui("item", "Use only")
    time.sleep(0.8)
    check(tab.js("document.getElementById('pass').value") == "", "clicking the «use only» login fills nothing")
    tab.click_ui("item", "ana@shop.test")
    check(wait_for(lambda: tab.js("document.getElementById('pass').value") == "Shop-fake-pass-1", 10), "a click on the login fills it")
    tab.theme("dark")
    tab.goto(f"{shop}/login")
    tab.theme("dark")
    tab.click("#pass")
    wait_for(lambda: tab.ui("button"), 5)
    tab.click_ui("button")
    wait_for(lambda: tab.ui("has-icon"), 8)
    tab.shot(f"{kind}-09-menu-dark")
    tab.theme("light")
    reply = worker.js(f"native('fill', {{ url: {json.dumps(shop + '/login')}, id: 'shop-team', what: 'login' }})")
    check(not reply["ok"] and reply["code"] == "forbidden" and "password" not in (reply.get("result") or {}),
          f"the service refuses the «use only» login even if asked directly [{reply.get('code')}]")

    print("The keyboard shortcut (its handler, called from the worker)")
    tab.goto(f"{shop}/login")
    worker.js("fillFromShortcut().then(() => true)")
    check(wait_for(lambda: tab.js("document.getElementById('pass').value") == "Shop-fake-pass-1", 10), "the fill shortcut fills the first login")
    shortcut = worker.js("fillShortcut()")
    popup = open_popup(cdp, worker, tab)
    hint = lambda: popup.js("[...document.querySelectorAll('.hint')].map((h) => h.innerText.replace(/\\s+/g, ' ')).join(' | ')")
    # Chrome and Edge 156 do not give Ctrl+Shift+L to extensions any more: the suggested key is Alt+Shift+L.
    check(shortcut == "Alt+Shift+L" and "Alt+Shift+L" in hint(), f"the browser gives the fill shortcut, and the popup names it ({shortcut!r}, {hint()!r})")
    popup.js("fillShortcut = ''; render().then(() => true)")  # as when another extension already has the key
    check(wait_for(lambda: "Choose a shortcut" in hint() and "Alt+Shift+L" not in hint(), 5),
          f"without one, the popup offers to choose a shortcut instead of naming a key that does nothing ({hint()!r})")
    popup.shot(f"{kind}-21-popup-no-shortcut")
    popup.click(".hint .link")
    check(cdp.target(lambda t: t["type"] == "page" and "extensions/shortcuts" in t["url"], 10),
          "«Choose a shortcut» opens the browser's extension shortcuts page")
    for t in cdp.targets():
        if "extensions/shortcuts" in t["url"]:
            cdp.send("Target.closeTarget", targetId=t["targetId"])
    cdp.send("Target.activateTarget", targetId=tab.id)

    print("2FA code")
    tab.goto(f"{shop}/2fa")
    tab.click("#otp")
    wait_for(lambda: tab.ui("button"), 5)
    tab.click_ui("button")
    check(wait_for(lambda: "2FA code" in " ".join(n["text"] for n in tab.ui("item")), 10), "the menu offers the login's 2FA code")
    tab.shot(f"{kind}-10-menu-2fa")
    tab.click_ui("item", "Shop")
    filled = wait_for(lambda: tab.js("document.getElementById('otp').value"), 10)
    expected = {totp.code(TOTP_SECRET, time.time() + d)["code"] for d in (-30, 0)}  # the code of now, or of the 30 s before
    check(filled and filled in expected, f"the current code is filled ({filled})")

    print("Lookalike sites get nothing")
    for url, why in ((f"{lookalike}/login", "another domain (shop-login.localhost)"), (f"{by_ip}/login", "127.0.0.1 instead of shop.localhost")):
        tab.goto(url)
        tab.click("#user")
        wait_for(lambda: tab.ui("button"), 5)
        tab.click_ui("button")
        note = wait_for(lambda: " ".join(n["text"] for n in tab.ui("note")) if tab.ui("note") and "Searching" not in tab.ui_text() else None, 10) or ""
        check("Nothing saved" in note and not tab.ui("item"), f"{why}: the menu has nothing to fill ({note[:80]!r})")
        popup = open_popup(cdp, worker, tab)
        check(popup and "Nothing saved" in popup_text(popup) and not popup.js("document.querySelectorAll('.row').length"),
              f"{why}: the popup has nothing either")
        check(popup and not popup.js("document.querySelectorAll('.hint').length"), f"{why}: and no hint about filling")
        reply = worker.js(f"native('fill', {{ url: {json.dumps(url)}, id: 'shop', what: 'login' }})")
        check(not reply["ok"] and reply["code"] == "mismatch", f"{why}: the service refuses to hand over the login [{reply.get('code')}]")
    tab.shot(f"{kind}-11-lookalike")
    if popup:
        popup.shot(f"{kind}-12-popup-lookalike")

    print("A frame of another site")
    tab.goto(f"{shop}/framed?src={lookalike}/login")
    frame_info = cdp.target(lambda t: t["type"] == "iframe" and t["url"].startswith(lookalike), 10)
    box = tab.rect("#frame")
    if frame_info:
        frame = Target(cdp, frame_info)
        inner = frame.rect("#user")
        tab.click_at(box[0] + 1 + inner[0] + inner[2] / 2, box[1] + 1 + inner[1] + inner[3] / 2)
        check(wait_for(lambda: frame.ui("button"), 5), "the button shows in the frame's field too")
        frame.click_ui("button")
        note = wait_for(lambda: " ".join(n["text"] for n in frame.ui("note")) if frame.ui("note") and "Searching" not in frame.ui_text() else None, 10) or ""
        check(not frame.ui("item") and ("inside" in note or "Nothing saved" in note), f"the frame's menu offers nothing ({note[:100]!r})")
    else:
        frame = None
        check(wait_for(lambda: tab.js("document.getElementById('frame').contentDocument === null"), 5), "the frame is cross-origin")
    popup = open_popup(cdp, worker, tab)
    text = popup_text(popup) if popup else ""
    check(popup and not popup.js("document.querySelectorAll('.row .btn.primary').length"), f"the popup fills nothing in it ({text[:100]!r})")
    reply = worker.js(f"native('fill', {{ url: {json.dumps(shop + '/framed')}, frame_url: {json.dumps(lookalike + '/login')}, id: 'shop', what: 'login' }})")
    check(not reply["ok"] and reply["code"] == "frame", f"the service refuses a frame of another site [{reply.get('code')}]")
    if frame:
        check(frame.js("document.getElementById('pass').value") == "", "and nothing was filled in it")
    tab.shot(f"{kind}-13-frame")
    if popup:
        popup.shot(f"{kind}-14-popup-frame")

    print("«Save this login?» after a form is sent")
    tab.goto(f"{forum}/signup")
    before = {e["id"] for e in vault.entries()}
    tab.click("#user")
    tab.type("bea@forum.test")
    tab.click("#pass")
    tab.type("Forum-fake-pass-3")
    tab.click("#go")
    check(wait_for(lambda: tab.ui("bar"), 10), "sending the form offers to save the login")
    bar = " ".join(n["text"] for n in tab.ui("bar"))
    check("Save this password in SecretBroker?" in bar and "bea@forum.test" in bar and "forum.localhost" in bar,
          f"with the user and the site ({bar[:120]!r})")
    check({e["id"] for e in vault.entries()} == before, "nothing is stored before the click")
    tab.shot(f"{kind}-15-save-bar-light")
    tab.theme("dark")
    tab.shot(f"{kind}-16-save-bar-dark")
    tab.theme("light")
    time.sleep(1)
    tab.click_ui("btn", "Save")
    saved = wait_for(lambda: [e for e in vault.entries() if e["id"] not in before], 10)
    check(saved and saved[0]["fields"]["username"] == "bea@forum.test" and saved[0]["fields"]["password"] == "Forum-fake-pass-3"
          and saved[0]["fields"]["url"] == forum, f"«Save» stores it for the site ({saved and saved[0]['fields']['url']})")
    check(wait_for(lambda: "Saved in SecretBroker" in " ".join(n["text"] for n in tab.ui("toast")), 5), "and says so")
    tab.shot(f"{kind}-17-saved")
    tab.goto(f"{forum}/signup")
    tab.click("#user")
    tab.type("bea@forum.test")
    tab.click("#pass")
    tab.type("Forum-fake-pass-3")
    tab.enter()
    time.sleep(2.5)
    check(not tab.ui("bar"), "the same login again is not offered twice")
    tab.goto(f"{forum}/signup")
    tab.click("#user")
    tab.type("bea@forum.test")
    tab.click("#pass")
    tab.type("Forum-new-pass-4")
    tab.click("#go")
    check(wait_for(lambda: "Update the password" in " ".join(n["text"] for n in tab.ui("bar")) or "Update" in " ".join(n["text"] for n in tab.ui("bar")), 10),
          f"a new password for a saved login offers to update it ({' '.join(n['text'] for n in tab.ui('bar'))[:100]!r})")
    tab.shot(f"{kind}-22-update-bar")
    time.sleep(1)  # the bar is drawn twice (the offer, then the page asking for it once loaded): click the one that stays
    tab.click_ui("btn", "Update")
    said = wait_for(lambda: " ".join(n["text"] for n in tab.ui("toast")), 6) or ""
    updated = wait_for(lambda: vault.get(saved[0]["id"])["fields"]["password"] == "Forum-new-pass-4", 10)
    check(updated and len(vault.entries()) == len(before) + 1, "«Update» changes the password of that login (no duplicate)"
          + ("" if updated else f" [{said!r}]"))

    print("A locked vault")
    client.request("lock")
    tab.goto(f"{shop}/login")
    tab.click("#user")
    wait_for(lambda: tab.ui("button"), 5)
    tab.click_ui("button")
    note = wait_for(lambda: tab.ui_text() if "locked" in tab.ui_text() else None, 10) or ""
    check("SecretBroker is locked" in note and not tab.ui("item"), f"the menu says it is locked, and lists nothing ({note[:80]!r})")
    tab.shot(f"{kind}-18-menu-locked")
    popup = open_popup(cdp, worker, tab)
    text = popup_text(popup) if popup else ""
    check("SecretBroker is locked" in text and "Unlock" in text and "ana@shop.test" not in text, f"the popup too ({text[:80]!r})")
    popup.shot(f"{kind}-19-popup-locked-light")
    popup.theme("dark")
    popup.shot(f"{kind}-20-popup-locked-dark")
    reply = worker.js(f"native('fill', {{ url: {json.dumps(shop + '/login')}, id: 'shop', what: 'login' }})")
    check(not reply["ok"] and reply["code"] == "locked", f"and nothing can be filled while it is locked [{reply.get('code')}]")
    popup.click("button.btn.primary")  # «Unlock»: brings the app forward
    check(wait_for(lambda: "SecretBroker is locked" in app.js("document.body.innerText"), 10), "«Unlock» shows the app's lock screen")
    app.js(f"""(() => {{ const i = document.querySelector('input[type=password]'); i.value = {json.dumps(MASTER)};
      i.dispatchEvent(new KeyboardEvent('keydown', {{ key: 'Enter' }})); }})()""")
    check(wait_for(lambda: client.request("status")["state"] == "unlocked", 15), "unlocked in the app")
    popup = open_popup(cdp, worker, tab)
    check(popup and "ana@shop.test" in popup_text(popup), "and the popup works again")

    print("Disconnecting the browser in the app")
    app.js("state.view = 'settings'; renderMain()")
    wait_for(lambda: "Disconnect" in app.js("document.body.innerText"), 10)
    app_click(app, "Disconnect")
    wait_for(lambda: app.js("!!document.querySelector('.modal')"), 3) and app.js(
        "(() => { const b = [...document.querySelectorAll('.modal-foot button')].pop(); if (b) b.click(); return !!b; })()")
    check(wait_for(lambda: not client.request("browser_status")["paired"], 10), "Disconnect forgets it")
    popup = open_popup(cdp, worker, tab)
    check(popup and "Connect this browser" in popup_text(popup), "and the popup asks to connect again")
    errors = [e for e in cdp.errors if "secretbroker" in e.lower() or "chrome-extension" in e.lower()]
    check(not errors, f"no errors in the extension's pages ({errors[:3]})")


if __name__ == "__main__":
    sys.exit(main())
