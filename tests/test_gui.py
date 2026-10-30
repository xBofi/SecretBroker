"""Drive the real desktop app (window, WebView2 page, icon next to the clock, MCP over HTTP) against a
throwaway vault, and save screenshots to look at.

    python tests/test_gui.py            (needs: pip install websocket-client)

Runs as a separate instance (its own SECRETBROKER_HOME, window, settings, ports): the installed
SecretBroker and the user's vault are never touched. The page is driven through WebView2's
remote debugging protocol, enabled only for this test.
"""

import base64
import ctypes
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

import websocket

ROOT = Path(__file__).resolve().parents[1]
HOME = Path(tempfile.mkdtemp(prefix="secretbroker-gui-"))
SHOTS = HOME / "screenshots"
MASTER = "una contraseña de prueba larga"
failures = 0


def check(condition, message):
    global failures
    print(f"  {'OK  ' if condition else 'FAIL'} {message}", flush=True)
    if not condition:
        failures += 1


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(condition, seconds=20, step=0.2):
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


# ----------------------------------------------------------------- the window (Win32)

user32 = ctypes.windll.user32


def app_window(pid):
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        title = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title, 256)
        if owner.value == pid and title.value == "SecretBroker":
            found.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


def real_pid(pid):
    """A venv's pythonw.exe starts the real interpreter as a child process."""
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          f"(Get-CimInstance Win32_Process -Filter 'ParentProcessId={pid}').ProcessId"],
                         capture_output=True, text=True).stdout.split()
    return int(out[0]) if out else pid


def visible(hwnd):
    return bool(user32.IsWindowVisible(hwnd)) and not user32.IsIconic(hwnd)


# ----------------------------------------------------------------- the page (Chrome DevTools Protocol)


class Page:
    def __init__(self, port):
        targets = wait_for(lambda: json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json")), 40)
        target = next(t for t in targets if t["type"] == "page")
        self.ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=60)
        self._id = 0
        self.errors = []
        self.send("Runtime.enable")
        self.send("Page.enable")

    def send(self, method, **params):
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("method") == "Runtime.exceptionThrown":
                self.errors.append(message["params"]["exceptionDetails"].get("exception", {}).get("description", "?"))
            elif message.get("method") == "Runtime.consoleAPICalled" and message["params"]["type"] == "error":
                self.errors.append(" ".join(str(a.get("value", a.get("description", ""))) for a in message["params"]["args"]))
            if message.get("id") == self._id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]

    def js(self, expression):
        result = self.send("Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"].get("exception", {}).get("description", result["exceptionDetails"]))
        return result["result"].get("value")

    def text(self):
        return self.js("document.body.innerText")

    def click(self, label, selector="button"):
        """Click the first visible element whose text is `label`."""
        return self.js(f"""(() => {{
            const el = [...document.querySelectorAll({json.dumps(selector)})]
              .find((b) => b.innerText.trim() === {json.dumps(label)} && b.offsetParent !== null);
            if (!el) return false; el.click(); return true; }})()""")

    def shot(self, name):
        SHOTS.mkdir(exist_ok=True)
        data = self.send("Page.captureScreenshot", format="png")["data"]
        (SHOTS / f"{name}.png").write_bytes(base64.b64decode(data))


# ----------------------------------------------------------------- a local API to call


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "auth": self.headers.get("Authorization")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    print(f"Test home: {HOME}")
    api_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=api_server.serve_forever, daemon=True).start()
    api_port = api_server.server_address[1]

    devtools, mcp_port = free_port(), free_port()
    env = {**os.environ, "SECRETBROKER_HOME": str(HOME), "SECRETBROKER_MCP_PORT": str(mcp_port),
           "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={devtools} --disable-background-timer-throttling "
           "--disable-renderer-backgrounding --disable-backgrounding-occluded-windows --disable-features=CalculateNativeWinOcclusion"}
    os.environ.update({k: env[k] for k in ("SECRETBROKER_HOME", "SECRETBROKER_MCP_PORT")})
    sys.path.insert(0, str(ROOT))
    from secretbroker import client, integrations

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    app = subprocess.Popen([str(pythonw), "-m", "secretbroker.app"], cwd=ROOT, env=env)
    try:
        run(app, env, devtools, api_port, client, integrations)
    finally:
        if app.poll() is None:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(app.pid)], capture_output=True)
        service_pid = wait_for(lambda: json.loads((HOME / "public" / "broker.json").read_text())["pid"], 2)
        if service_pid:
            subprocess.run(["taskkill", "/F", "/PID", str(service_pid)], capture_output=True)
        api_server.shutdown()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (screenshots: {SHOTS})")
    sys.exit(1 if failures else 0)


def run(app, env, devtools, api_port, client, integrations):
    print("Window")
    page = Page(devtools)
    pid = real_pid(app.pid)
    hwnd = wait_for(lambda: app_window(pid))
    check(hwnd and visible(hwnd), "the window opens")
    check(wait_for(lambda: "Tus claves, usadas sin ser vistas" in page.text()), "first screen: create a vault")
    page.shot("01-welcome")

    print("Create the vault and a credential")
    page.js(f"api().call('create_vault', {{ master_password: {json.dumps(MASTER)} }})")
    page.js("state.setupActive = false; state.screen = null; refreshStatus()")
    page.js(f"api().call('unlock', {{}}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    check(wait_for(lambda: "Credenciales" in page.text()), "main screen after unlocking")
    entry = {"id": "echo-api", "name": "Echo API", "template": "api_key", "description": "API local de prueba",
             "fields": {"value": "sk-gui-test-SECRET-123", "base_url": f"http://127.0.0.1:{api_port}", "auth_style": "bearer"},
             "policy": {"approval": "session", "http": {"allowed_hosts": ["127.0.0.1"],
                        "auth": {"kind": "header", "name": "Authorization", "template": "Bearer {{value}}"}}},
             "tags": ["pruebas"]}
    saved = page.js(f"api().call('save_entry', {{ entry: {json.dumps(entry)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    check(saved and saved["ok"], f"credential saved {'' if saved and saved['ok'] else saved}")
    page.js("loadEntries().then(renderMain)")
    check(wait_for(lambda: "Echo API" in page.text() and "pruebas" in page.text()), "it shows in the list, with its tag")
    page.shot("02-credentials")

    print("Screens")
    for view, expected, name in (("access", "Qué puede hacer la IA", "03-access"), ("settings", "Abrir con mi sesión de Windows", "04-settings"),
                                 ("activity", "Actividad", "05-activity"), ("exposure", "Exposición", "06-exposure")):
        page.js(f"state.view = '{view}'; renderMain()")
        check(wait_for(lambda: expected in page.text(), 10), f"{view} renders")
        time.sleep(0.5)
        page.shot(name)
    check("Copia diaria automática" in page.js("state.view = 'settings'; renderMain(); new Promise(r => setTimeout(() => r(document.body.innerText), 800))"),
          "settings show backups")

    print("Rotation with a guide")
    other = {"id": "other-api", "name": "Otra API", "template": "api_key", "description": "",
             "fields": {"value": "other-OLD-key-1234567", "base_url": "https://api.other.example.com", "auth_style": "bearer"},
             "policy": {"approval": "session"}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(other)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'other-api'; loadEntries().then(renderMain)")
    check(wait_for(lambda: "Rotar con ayuda" in page.text() and "Te recuerda rotarla" in page.text(), 10),
          "a key without a rotation API offers the guided rotation and says when it will remind")
    page.click("Rotar con ayuda")
    check(wait_for(lambda: "1 · Dónde se usa" in page.text() and "Todavía no hay ningún sitio apuntado" in page.text(), 10),
          "step 1: where it is used")
    for place in ("develop: .env local", "pro: servidor api.other.example.com"):
        page.js(f"""(() => {{ const i = document.querySelector('.modal input.input:not([type])'); i.value = {json.dumps(place)}; }})()""")
        page.click("Añadir")
    check(wait_for(lambda: "pro: servidor api.other.example.com" in page.text() and "develop: .env local" in page.text(), 5), "places are added")
    page.shot("07-rotate-where")
    page.click("Siguiente")
    check(wait_for(lambda: "2 · Crea la clave nueva" in page.text() and "other-api-" in page.text(), 10), "step 2: how to create the new key")
    page.shot("07-rotate-guide")
    page.click("Ya la tengo")
    check(wait_for(lambda: "3 · Pega la clave nueva" in page.text(), 10), "step 3: paste it")
    page.js("""(() => { const i = document.querySelector('.modal input[type=password]'); i.value = 'other-NEW-key-7654321'; })()""")
    page.click("Probar y guardar")
    check(wait_for(lambda: "4 · Ponla en cada sitio" in page.text() and "Faltan 2" in page.text(), 15),
          "step 4: saved with one click, and a list of places to update")
    next_disabled = "[...document.querySelectorAll('.modal button')].find((b) => b.innerText.trim() === 'Siguiente').disabled"
    check(page.js(next_disabled), "the old key can't be deleted before every place has the new one")
    page.js("document.querySelectorAll('.modal input[type=checkbox]').forEach((c) => { c.click(); })")
    page.shot("08-rotate-done")
    check(wait_for(lambda: not page.js(next_disabled), 5), "once all are ticked, it goes on")
    page.click("Siguiente")
    check(wait_for(lambda: "5 · Borra la clave anterior" in page.text(), 10), "step 5: delete the old one")
    page.click("Más tarde")
    check(wait_for(lambda: "Falta borrar la clave anterior" in page.text(), 10), "until then the credential says so")
    page.shot("09-rotate-pending")
    page.click("Ya la he borrado")
    check(wait_for(lambda: "Falta borrar la clave anterior" not in page.text(), 10), "and it is done when the user says so")
    check(wait_for(lambda: "Se usa en:" in page.text() and "pro: servidor api.other.example.com" in page.text(), 10),
          "the places are kept with the credential")

    print("Rotation of a database password")
    db = {"id": "shop-db", "name": "BD tienda", "template": "database", "description": "",
          "fields": {"engine": "postgresql", "host": "db.example.com", "database": "shop", "username": "shop_app", "password": "OLD-db-pass"},
          "used_in": ["develop: .env local", "pre: servidor pre", "pro: servidor pro"], "policy": {"approval": "session"}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(db)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'shop-db'; loadEntries().then(renderMain)")
    check(wait_for(lambda: "Rotar con ayuda" in page.text() and "pre: servidor pre" in page.text(), 10),
          "a database offers the guided rotation and lists where it is used")
    page.click("Rotar con ayuda")
    check(wait_for(lambda: "1 · Dónde se usa" in page.text() and "pro: servidor pro" in page.text(), 10), "step 1 has the places already")
    page.click("Siguiente")
    check(wait_for(lambda: "2 · Cambia la contraseña" in page.text() and "deja de funcionar" in page.text(), 10),
          "step 2 warns that everything using it stops working")
    page.click("Generar una")
    check(wait_for(lambda: 'ALTER ROLE "shop_app" WITH PASSWORD' in page.text() and "CONTRASEÑA_NUEVA" not in page.text(), 5),
          "it generates one and gives the exact command, the password hidden")
    page.shot("09-rotate-database")
    page.click("Ya la he cambiado: guardar")
    check(wait_for(lambda: "3 · Ponla en cada sitio" in page.text() and "Faltan 3" in page.text(), 15), "step 3: put it in every place")
    page.js("document.querySelectorAll('.modal input[type=checkbox]').forEach((c) => { c.click(); })")
    page.click("Terminar")
    check(wait_for(lambda: page.js("!document.querySelector('.modal')"), 5), "and it is done")
    check(wait_for(lambda: any(e["secret"] == "shop-db" and e["action"] == "rotate" for e in client.request("audit", {"limit": 10})), 5),
          "the rotation is in the activity")

    print("Rotation of a secret that goes with an id")
    oauth = {"id": "g-oauth", "name": "Google OAuth", "template": "generic", "description": "",
             "fields": {"value": "GOCSPX-old-123456", "username": "619577974052-oldclient.apps.googleusercontent.com",
                        "url": "https://oauth2.googleapis.com"}, "policy": {"approval": "session"}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(oauth)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'g-oauth'; loadEntries().then(renderMain)")
    check(wait_for(lambda: "Rotar con ayuda" in page.text(), 10), "an OAuth client secret offers the guided rotation")
    page.click("Rotar con ayuda")
    page.click("Siguiente")
    check(wait_for(lambda: "No borres el cliente OAuth" in page.text(), 10), "step 2 warns not to delete the client")
    page.click("Ya la tengo")
    check(wait_for(lambda: "¿Y el ID de cliente?" in page.text(), 10), "step 3 asks whether the client id changed")
    page.js("""(() => { const i = document.querySelector('.modal input[type=password]'); i.value = 'GOCSPX-new-654321'; })()""")
    page.click("Probar y guardar")
    check(wait_for(lambda: "Indica si el ID de cliente es el mismo o ha cambiado" in page.text(), 10), "it can't be saved without answering")
    page.js("document.querySelector('.modal input[type=radio][value=new]').click()")
    page.js("""(() => { const i = document.querySelector('.modal input.mono'); i.value = '619577974052-newclient.apps.googleusercontent.com'; })()""")
    page.shot("10-rotate-new-client")
    page.click("Probar y guardar")
    check(wait_for(lambda: "ID de cliente nuevo guardado" in page.text(), 15), "a new client: the new id is saved with the secret")
    page.click("Siguiente")
    check(wait_for(lambda: "borra el anterior (619577974052-oldclient" in page.text(), 10), "step 4 says to delete the old client")
    page.click("Ya la he borrado")
    page.js("loadEntries()")
    check(wait_for(lambda: page.js("(state.entries.find((e) => e.id === 'g-oauth') || {fields: {}}).fields.username")
                   == "619577974052-newclient.apps.googleusercontent.com", 10), "the credential has the new client id")

    print("How often keys are tested")
    page.js("state.view = 'settings'; renderMain()")
    check(wait_for(lambda: "Comprobar que las claves funcionan" in page.text(), 10), "the general setting is in Ajustes")
    page.js("state.view = 'credentials'; state.selected = 'other-api'; renderMain()")
    page.click("Editar")
    check(wait_for(lambda: "Comprobar que funciona" in page.text(), 10), "each credential has its own")
    page.js("""(() => { const s = [...document.querySelectorAll('.modal select')].find((x) => [...x.options].some((o) => o.value === 'custom'));
      s.value = 'custom'; s.dispatchEvent(new Event('change'));
      const n = document.querySelector('.modal input[type=number]'); n.value = '48'; })()""")
    page.shot("11-check-every")
    page.click("Guardar")
    if wait_for(lambda: "Confirma que eres tú" in page.text(), 5):  # saving a credential asks who you are
        page.click("Contraseña maestra")
        page.js(f"""(() => {{ const i = [...document.querySelectorAll('.modal input[type=password]')].pop(); i.value = {json.dumps(MASTER)}; }})()""")
        page.click("Confirmar")
    check(wait_for(lambda: page.js("(state.entries.find((e) => e.id === 'other-api') || {}).check_every_hours") == 48, 15),
          "a custom number of hours is saved")
    page.click("Editar")
    check(wait_for(lambda: page.js("(document.querySelector('.modal input[type=number]') || {}).value") == "48", 10),
          "reopening it shows the 48 hours")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")

    print("Claude Code over HTTP, and approving with one click")
    url, token = integrations.mcp_endpoint()
    result = {}

    def ask():
        import asyncio
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async def go():
            async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60) as http:
                async with streamable_http_client(url, http_client=http) as (read, write, *_):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result["tools"] = len((await session.list_tools()).tools)
                        call = await session.call_tool("http_request", {"secret_id": "echo-api", "url": f"http://127.0.0.1:{api_port}/hola"})
                        result["text"] = " ".join(getattr(c, "text", "") for c in call.content)
        asyncio.run(go())

    caller = threading.Thread(target=ask)
    caller.start()
    check(wait_for(lambda: "La IA quiere usar una credencial" in page.text(), 20), "the request pops up in the app")
    time.sleep(0.5)
    page.shot("07-approval")
    check(page.click("Permitir hoy"), "one click: «Permitir hoy»")
    caller.join(30)
    check("Confirma que eres tú" not in page.text(), "no password asked")
    check(result.get("tools") == 14, f"Claude Code sees the tools ({result.get('tools')})")
    check("Bearer [REDACTED:echo-api]" in result.get("text", "") and "SECRET" not in result.get("text", ""),
          f"the request carried the key and the AI saw it redacted ({result.get('text', '')[:200]!r})")

    print("Pause the AI")
    page.js("state.view = 'access'; renderMain()")
    wait_for(lambda: "Pausar la IA" in page.text(), 5)
    page.click("Pausar la IA")
    check(wait_for(lambda: client.request("status")["ai_paused"], 5), "the pause button pauses the AI")
    check(wait_for(lambda: "La IA está en pausa" in page.text(), 5), "and the page says so")
    page.shot("08-paused")
    page.click("Reanudar")
    check(wait_for(lambda: not client.request("status")["ai_paused"], 5), "resuming is one click")

    print("Close, reopen, quit")
    # The X button. (A plain WM_CLOSE from another program, like the installer or Task Manager, quits.)
    user32.PostMessageW(hwnd, 0x0112, 0xF060, 0)  # WM_SYSCOMMAND SC_CLOSE
    check(wait_for(lambda: not user32.IsWindowVisible(hwnd), 5) and app.poll() is None, "closing hides the window, the app keeps running")
    check(wait_for(lambda: client.request("status")["gui_connected"], 5), "hidden, it still answers the AI")
    subprocess.Popen([str(Path(sys.executable).with_name("pythonw.exe")), "-m", "secretbroker.app"], cwd=ROOT, env=env).wait(20)
    check(wait_for(lambda: visible(hwnd), 5), "starting it again shows the running window")

    print("Open with the Windows session")
    enabled = page.js(f"api().enable_session_unlock({{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    check(enabled and enabled["ok"] and (HOME / "user" / "session.bin").exists(), "turned on; the token is kept for this Windows user")
    page.js("lockNow()")
    check(wait_for(lambda: "Abrir con mi sesión de Windows" in page.text(), 5), "the lock screen offers one click")
    page.shot("09-lock-session")
    page.click("Abrir con mi sesión de Windows")
    check(wait_for(lambda: client.request("status")["state"] == "unlocked", 10), "one click opens it, no password")

    print("Backups")
    folder = HOME / "backups"
    made = page.js(f"api().set_backup_folder({json.dumps(str(folder))})")
    copies = list(folder.glob("*.sbbackup"))
    check(made and made["ok"] and len(copies) == 1 and "SECRET" not in copies[0].read_text(), "a backup is written, encrypted")

    print("Errors in the page")
    check(not page.errors, f"no JavaScript errors {page.errors[:3]}")
    log = (HOME / "user" / "app.log").read_text(encoding="utf-8") if (HOME / "user" / "app.log").exists() else ""
    check("tray icon: ok" in log and "MCP over HTTP: ok" in log and "ERROR" not in log, f"app log clean: {log[-400:]!r}")

    try:
        page.js("api().quit()")
    except websocket.WebSocketException:
        pass  # the page goes away with the app
    check(wait_for(lambda: app.poll() is not None, 10), "«Salir» quits the app")


if __name__ == "__main__":
    main()
