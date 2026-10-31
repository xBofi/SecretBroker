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
ACCOUNT = "cuenta del equipo de prueba 42"
failures = 0
# A local SecretBroker Server for the teams flow (plain http only because it is on this PC).
os.environ.update(SB_ALLOW_HTTP="1", SB_PUBLIC_URL="http://127.0.0.1", SB_SIGNUPS="open", SB_DATA_DIR=str(HOME / "server"))
sys.path.insert(0, str(ROOT / "server"))


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


PROFILE = HOME / "profile"
LEAKED = "sk-gui-test-SECRET-123"
CONVERSATION = PROFILE / ".claude" / "projects" / "demo" / "s1.jsonl"
FAKE_PSQL = '''import os, sys
from pathlib import Path
state = Path(__file__).with_name("db_password.txt")
sql = sys.stdin.read()
if os.environ.get("PGPASSWORD") != state.read_text(encoding="utf-8"):
    print('psql: FATAL: password authentication failed for user "pg_app"', file=sys.stderr)
    sys.exit(2)
if "ALTER ROLE" in sql:
    state.write_text(sql.split("PASSWORD '")[1].split("';")[0].replace("''", "'"), encoding="utf-8")
'''


def fake_profile():
    """A Claude Code conversation where the AI saw a key."""
    CONVERSATION.parent.mkdir(parents=True)
    (HOME / "user").mkdir(parents=True, exist_ok=True)
    (HOME / "user" / "prefs.json").write_text(json.dumps({"auto_scan": False}), encoding="utf-8")  # searched when the test says
    CONVERSATION.write_text(json.dumps({"message": f"usa la clave {LEAKED} para probar"}) + "\n", encoding="utf-8")


def fake_psql():
    """A psql that keeps the database password in a file: what the service runs to apply a new one."""
    folder = HOME / "bin"
    folder.mkdir()
    (folder / "fake_psql.py").write_text(FAKE_PSQL, encoding="utf-8")
    (folder / "psql.cmd").write_text(f'@"{sys.executable}" "%~dp0fake_psql.py" %*\r\n', encoding="utf-8")
    (folder / "db_password.txt").write_text("OLD-pg-pass-1", encoding="utf-8")
    return folder


def start_team_server():
    import uvicorn
    from secretbroker_server import config
    from secretbroker_server.web import create_app

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(config.from_env()), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    wait_for(lambda: server.started, 10, 0.05)
    return f"http://127.0.0.1:{port}", server


def main():
    print(f"Test home: {HOME}")
    api_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=api_server.serve_forever, daemon=True).start()
    api_port = api_server.server_address[1]
    global TEAM_URL
    TEAM_URL, team_server = start_team_server()

    devtools, mcp_port = free_port(), free_port()
    # A user profile of its own (the search for copies reads it) and a psql of its own (the service runs it).
    fake_profile()
    env = {**os.environ, "SECRETBROKER_HOME": str(HOME), "SECRETBROKER_MCP_PORT": str(mcp_port),
           "SECRETBROKER_PROFILE": str(PROFILE), "PATH": f"{fake_psql()}{os.pathsep}{os.environ.get('PATH', '')}",
           "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={devtools} --disable-background-timer-throttling "
           "--disable-renderer-backgrounding --disable-backgrounding-occluded-windows --disable-features=CalculateNativeWinOcclusion"}
    os.environ.update({k: env[k] for k in ("SECRETBROKER_HOME", "SECRETBROKER_MCP_PORT")})
    sys.path.insert(0, str(ROOT))
    from secretbroker import client, integrations

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    # The app starts the service with -I, which would import the installed (editable) package: start the
    # service of this checkout first, so the test drives the code next to it.
    subprocess.Popen([str(pythonw), "-m", "secretbroker.service"], cwd=ROOT, env=env)
    wait_for(lambda: client.request("status", timeout=2), 20)
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
        team_server.should_exit = True
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (screenshots: {SHOTS})")
    sys.exit(1 if failures else 0)


def run(app, env, devtools, api_port, client, integrations):
    print("Window")
    page = Page(devtools)
    pid = real_pid(app.pid)
    hwnd = wait_for(lambda: app_window(pid))
    check(hwnd and visible(hwnd), "the window opens")
    check(wait_for(lambda: "Tus claves, usadas sin ser vistas" in page.text()), "first screen: create a vault")
    welcome = page.text()
    check("Apruebas con un clic, una vez o para todo el día" in welcome and "este equipo" not in welcome
          and "Restaurar una copia" in welcome and "Importar de otro gestor" in welcome,
          "the welcome says approvals are one click, and offers restoring or importing")
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
                                 ("activity", "Actividad", "05-activity"), ("exposure", "Copias encontradas", "06-exposure")):
        page.js(f"state.view = '{view}'; renderMain()")
        check(wait_for(lambda: expected in page.text(), 10), f"{view} renders")
        time.sleep(0.5)
        page.shot(name)
    check("Copia diaria automática" in page.js("state.view = 'settings'; renderMain(); new Promise(r => setTimeout(() => r(document.body.innerText), 800))"),
          "settings show backups")
    check("Importar de otro gestor" in page.text() and "Exportar" in page.text(), "settings offer import and export")
    shell_checks(page)

    print("Generator and health")
    page.js("openGenerator()")
    check(wait_for(lambda: len(page.js("(document.querySelector('.modal .gen-output') || {}).textContent || ''")) == 20, 10),
          "the generator opens with a 20-character password")
    page.click("Frase de palabras")
    check(wait_for(lambda: "-" in page.js("document.querySelector('.modal .gen-output').textContent"), 10), "and makes passphrases")
    page.shot("07-generator")
    page.click("Aleatoria")  # leave the saved options as they were
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    page.js("state.view = 'exposure'; renderMain()")
    check(wait_for(lambda: page.js("(document.querySelector('.health-score') || {}).textContent") == "—", 10)
          and "Sin datos aún" in page.text(), "before searching for copies and testing the keys, Salud claims nothing")
    review = "[...document.querySelectorAll('.content-header button')].find((b) => b.innerText.trim() === 'Revisar ahora')"
    check(page.js(f"{review}.classList.contains('primary')") and "Buscar copias al desbloquear" not in page.text(),
          "one primary action: «Revisar ahora»")
    page.click("Revisar ahora")
    check(wait_for(lambda: "Expuesta" in page.text() and "búsqueda: hoy" in page.text() and "proveedores: hoy" in page.text(), 60),
          "it searches for copies and tests the keys: the key the AI saw is found, and Salud says when it looked")
    check("Una IA la ha visto" in page.text() and page.click("Rotar con ayuda", ".exposure-card button") is not None,
          "the exposed credential's card says an AI saw it")
    page.js("document.querySelector('.modal') && document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    page.click("Descartar")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.finding button')].some((b) => b.innerText.trim() === 'Borrar de este archivo')"), 10),
          "an AI conversation offers «Borrar de este archivo» and «Ignorar»")
    calm_shot(page, "06-health-exposed")
    page.click("Borrar de este archivo", ".finding button")
    check(wait_for(lambda: "Se guarda una copia del archivo" in page.text(), 5), "it asks first, and says a copy is kept")
    page.click("Borrar de este archivo", ".modal-foot button")
    check(wait_for(lambda: "[REDACTED:echo-api]" in CONVERSATION.read_text(encoding="utf-8")
                   and LEAKED not in CONVERSATION.read_text(encoding="utf-8"), 15), "the key is removed from the conversation, in place")
    check(wait_for(lambda: "borrada de aquí" in page.text(), 10), "and the place shows it")
    check(CONVERSATION.with_name("s1.jsonl.secretbroker.bak").exists(), "a copy of the file is left next to it")
    check(LEAKED not in page.text() and LEAKED not in json.dumps(page.js("state")), "the page never had the key")
    calm_shot(page, "06-health-redacted")

    print("Rotation with a guide")
    other = {"id": "other-api", "name": "Otra API", "template": "api_key", "description": "",
             "fields": {"value": "other-OLD-key-1234567", "base_url": "https://api.other.example.com", "auth_style": "bearer"},
             "policy": {"approval": "session"}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(other)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'other-api'; loadEntries().then(renderMain)")
    check(wait_for(lambda: "Rotar con ayuda" in page.text() and page.js("!!document.querySelector('.status-strip')"), 10),
          "a key without a rotation API offers the guided rotation, under a status strip")
    strip = page.js("[...document.querySelectorAll('.status-chip')].map((c) => c.innerText.trim())")
    check(any(c.startswith("Rotar en") for c in strip) and "Sin sitios apuntados" in strip and "No se puede probar" in strip,
          f"the strip says when to rotate it, where it is used and that it can't be tested ({strip})")
    check("se prueba" not in page.js("document.querySelector('.detail').innerText"), "nothing promises a test it can't do")
    calm_shot(page, "07-detail-strip")
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
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: "¿Descartar?" in page.text(), 5) and page.js("document.querySelectorAll('.modal').length") == 2,
          "Esc does not close the wizard without asking")
    page.click("Seguir")
    check(wait_for(lambda: "2 · Crea la clave nueva" in page.text() and "¿Descartar?" not in page.text(), 5), "«Seguir» goes back to it")
    page.click("Ya la tengo")
    check(wait_for(lambda: "3 · Pega la clave nueva" in page.text(), 10), "step 3: paste it")
    page.js("""(() => { const i = document.querySelector('.modal input[type=password]'); i.value = 'other-NEW-key-7654321'; })()""")
    page.click("Guardar")
    check(wait_for(lambda: "4 · Ponla en cada sitio" in page.text() and "Faltan 2" in page.text(), 15),
          "step 4: saved with one click, and a list of places to update")
    check(wait_for(lambda: "Usada en 2 sitios" in page.text() and "Falta anular la anterior" in page.text(), 10),
          "the credential behind the wizard already shows the new state")
    next_disabled = "[...document.querySelectorAll('.modal button')].find((b) => b.innerText.trim() === 'Siguiente').disabled"
    check(page.js(next_disabled), "the old key can't be revoked before every place has the new one")
    page.js("document.querySelectorAll('.modal input[type=checkbox]').forEach((c) => { c.click(); })")
    page.shot("08-rotate-done")
    check(wait_for(lambda: not page.js(next_disabled), 5), "once all are ticked, it goes on")
    page.click("Siguiente")
    check(wait_for(lambda: "5 · Anula la clave anterior" in page.text(), 10), "step 5: revoke the old one")
    page.click("Más tarde")
    check(wait_for(lambda: "Clave nueva activa · falta anular la anterior" in page.text(), 10),
          "until then it is not «complete»: the credential says the old one is still to revoke")
    calm_shot(page, "09-rotate-pending")
    page.click("Ya la he anulado")
    check(wait_for(lambda: "falta anular la anterior" not in page.text(), 10), "and it is done when the user says so")
    check(wait_for(lambda: "Usada en 2 sitios" in page.text(), 10), "the places are kept with the credential")

    print("Testing a key of an unknown provider")
    page.click("Cómo probarla")
    check(wait_for(lambda: "Cómo probar Otra API" in page.text(), 10), "a key the app can't test asks how")
    page.js("""(() => { const i = document.querySelector('.modal input.mono'); i.value = '/v1/me'; })()""")
    calm_shot(page, "09-test-request")
    page.click("Guardar y probar")
    check(wait_for(lambda: page.js("JSON.stringify((state.entries.find((e) => e.id === 'other-api') || {}).test_request)")
                   == json.dumps({"method": "GET", "url": "https://api.other.example.com/v1/me", "status": 200}, separators=(",", ":")), 20),
          "it is saved (a path of its API) and tried")
    check(wait_for(lambda: "Cambiar la prueba" in page.text() and "No se puede probar" not in page.text(), 10), "from then on it can be tested")

    print("Rotation of a database password")
    db = {"id": "shop-db", "name": "BD tienda", "template": "database", "description": "",
          "fields": {"engine": "postgresql", "host": "db.example.com", "database": "shop", "username": "shop_app", "password": "OLD-db-pass"},
          "used_in": ["develop: .env local", "pre: servidor pre", "pro: servidor pro"], "policy": {"approval": "session"}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(db)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'shop-db'; loadEntries().then(renderMain)")
    check(wait_for(lambda: "Rotar con ayuda" in page.text() and "Usada en 3 sitios" in page.text(), 10),
          "a database offers the guided rotation and says where it is used")
    page.click("Rotar con ayuda")
    check(wait_for(lambda: "1 · Dónde se usa" in page.text() and "pro: servidor pro" in page.text(), 10), "step 1 has the places already")
    page.click("Siguiente")
    check(wait_for(lambda: "2 · Cambia la contraseña" in page.text() and "deja de funcionar" in page.text()
                   and 'ALTER ROLE "shop_app" WITH PASSWORD' in page.text(), 10),
          "step 2 warns that everything using it stops working, and gives the exact command")
    new = client.request("rotation_secret", {"id": "shop-db", "what": "value", "proof": {"kind": "master_password", "value": MASTER}})
    check(len(new) == 32 and new not in page.text() and new not in json.dumps(page.js("state")),
          "the service made the new one and keeps it as pending: the page never has it")
    check("«psql»" in page.text(), "it says why the app can't apply it here (psql not allowed)")
    page.js("document.querySelectorAll('.modal .prop .btn.icon-only')[1].click()")
    clipboard = wait_for(lambda: (lambda c: c if new in c else None)(subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-Clipboard"], capture_output=True, text=True).stdout), 10)
    check(clipboard and clipboard.strip() == f"""ALTER ROLE "shop_app" WITH PASSWORD '{new}';""", "«Copiar» puts the command with it in the clipboard")
    page.shot("09-rotate-database")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: "queda guardada aquí como pendiente" in page.text(), 5), "closing asks first, and says the new one is kept")
    page.click("Descartar")
    page.js("lockNow()")
    check(wait_for(lambda: client.request("status")["state"] == "locked", 10), "even locking the vault…")
    page.js(f"api().call('unlock', {{}}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'shop-db'")
    check(wait_for(lambda: "Rotación a medias" in page.text(), 15), "…keeps it: the credential shows a rotation left halfway")
    page.click("Rotar con ayuda")
    check(wait_for(lambda: "Rotación a medias: ¿ya la cambiaste?" in page.text(), 10), "reopening asks whether it was changed")
    calm_shot(page, "09-rotate-resume")
    page.click("Sí, ya la cambié: guardar")
    check(wait_for(lambda: "3 · Ponla en cada sitio" in page.text() and "Faltan 3" in page.text(), 15), "and saves the one it kept")
    page.js("document.querySelectorAll('.modal input[type=checkbox]').forEach((c) => { c.click(); })")
    page.click("Terminar")
    check(wait_for(lambda: page.js("!document.querySelector('.modal')"), 5), "and it is done")
    check(wait_for(lambda: any(e["secret"] == "shop-db" and e["action"] == "rotate" for e in client.request("audit", {"limit": 10})), 5),
          "the rotation is in the activity")
    page.click("Rotar con ayuda")
    wait_for(lambda: "1 · Dónde se usa" in page.text(), 10)
    page.click("Siguiente")
    wait_for(lambda: "Guardar y que la aplique la IA" in page.text(), 10)
    page.click("Guardar y que la aplique la IA")
    check(wait_for(lambda: "la base de datos aún tiene la anterior" in page.text()
                   and "Aplica en la base de datos la contraseña nueva de «BD tienda» (shop-db)" in page.text(), 15),
          "or it is saved first, with a request for the AI to apply it")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    page.click("Descartar")

    print("A database password applied by the service")
    pg = {"id": "pg-api", "name": "Postgres API", "template": "database", "description": "",
          "fields": {"engine": "postgresql", "host": "db.internal", "database": "api", "username": "pg_app", "password": "OLD-pg-pass-1"},
          "used_in": ["pro: servidor api"], "policy": {"approval": "session", "commands": {"allowed": ["psql"], "env": {}}}}
    page.js(f"api().call('save_entry', {{ entry: {json.dumps(pg)} }}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("state.view = 'credentials'; state.selected = 'pg-api'; loadEntries().then(renderMain)")
    wait_for(lambda: "Postgres API" in page.text() and "Rotar con ayuda" in page.text(), 10)
    page.click("Rotar con ayuda")
    wait_for(lambda: "1 · Dónde se usa" in page.text(), 10)
    page.click("Siguiente")
    check(wait_for(lambda: "Aplicar ahora" in page.text() and "Lo hago yo" in page.text() and "con psql" in page.text(), 15),
          "with psql installed and allowed: «Aplicar ahora», and «Lo hago yo» as the alternative")
    calm_shot(page, "09-rotate-apply")
    page.click("Aplicar ahora")
    check(wait_for(lambda: "Cambiada en la base de datos con psql y comprobada" in page.text(), 30),
          "one click: the service changes it with the current one and logs in with the new one")
    applied = (HOME / "bin" / "db_password.txt").read_text(encoding="utf-8")
    check(applied != "OLD-pg-pass-1" and applied == client.request("reveal", {"id": "pg-api", "field": "password",
                                                                              "proof": {"kind": "master_password", "value": MASTER}}),
          "the database and the vault have the same new password")
    page.js("document.querySelectorAll('.modal input[type=checkbox]').forEach((c) => { c.click(); })")
    page.click("Terminar")
    check(wait_for(lambda: page.js("!document.querySelector('.modal')"), 5), "and it is done")

    print("Suggesting a database password in the editor")
    page.js("state.view = 'credentials'; state.selected = 'shop-db'; renderMain()")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)
    page.click("Editar")
    check(wait_for(lambda: "Generar" in page.text(), 10), "the password field has «Generar»")
    page.click("Generar")
    generated = wait_for(lambda: page.js("[...document.querySelectorAll('.modal input[type=password]')].pop().value"), 5)
    check(isinstance(generated, str) and len(generated) == 32 and generated.isalnum(),
          "it fills in 32 random letters and digits (nothing to escape in a connection URL)")
    check("no cambia la contraseña en el servidor" in page.text(), "and says that saving it doesn't change it on the server")
    page.shot("10-editor-generate")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

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
    page.click("Guardar")
    check(wait_for(lambda: "Indica si el ID de cliente es el mismo o ha cambiado" in page.text(), 10), "it can't be saved without answering")
    page.js("document.querySelector('.modal input[type=radio][value=new]').click()")
    page.js("""(() => { const i = document.querySelector('.modal input.mono'); i.value = '619577974052-newclient.apps.googleusercontent.com'; })()""")
    page.shot("10-rotate-new-client")
    page.click("Guardar")
    check(wait_for(lambda: "ID de cliente nuevo guardado" in page.text(), 15), "a new client: the new id is saved with the secret")
    page.click("Siguiente")
    check(wait_for(lambda: "borra el anterior (619577974052-oldclient" in page.text(), 10), "step 4 says to delete the old client")
    page.click("Ya la he anulado")
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
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

    teams_flow(page)

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
    check(page.js("document.querySelector('.auth .btn.primary').innerText.trim()") == "Abrir con mi sesión de Windows"
          and "Contraseña maestra" not in page.js("document.querySelector('.auth').innerText")
          and page.js("document.activeElement === document.querySelector('.auth .btn.primary')"),
          "one primary way, focused; the password is folded under «Otras formas de desbloquear»")
    page.shot("09-lock-session")
    page.js("document.querySelector('details.other-unlock').open = true")
    check(wait_for(lambda: page.js("!!document.querySelector('details.other-unlock input[type=password]').offsetParent"), 5),
          "the other ways are one click away")
    page.shot("09-lock-other-ways")
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


def fill(page, label, value, scope=""):
    """Type into the input of the field labelled `label` (or, without a label, the input with that placeholder)."""
    page.js(f"""(() => {{
      const scope = {json.dumps(scope)};
      const field = [...document.querySelectorAll(scope + ' .field')].find((f) => f.offsetParent !== null
        && f.querySelector('label') && f.querySelector('label').innerText.trim().startsWith({json.dumps(label)}));
      const input = field ? field.querySelector('input')
        : [...document.querySelectorAll(scope + ' input')].find((i) => i.placeholder === {json.dumps(label)} && i.offsetParent !== null);
      input.value = {json.dumps(value)}; input.dispatchEvent(new Event('input')); }})()""")


def calm_shot(page, name):
    """A screenshot without the toasts of earlier steps, once animations are over."""
    page.js("document.getElementById('toasts').replaceChildren()")
    time.sleep(0.4)
    page.shot(name)


def shell_checks(page):
    """The app shell: status dot, toasts, dialogs, the AI's access, Ajustes, Actividad, both themes."""
    print("App shell")
    page.js("state.view = 'credentials'; renderMain()")
    check(wait_for(lambda: page.js("!!document.querySelector('#sidebar-state .dot')"), 5)
          and page.js("document.querySelector('#sidebar-state .dot').className.trim()") == "dot",
          "unlocked with nothing to do: the status dot is not amber")

    page.js("['Guardado', 'Guardado', 'Guardado', 'Uno', 'Dos', 'Tres'].forEach((m) => toast(m)); toast('Falló', 'error')")
    toasts = page.js("[...document.querySelectorAll('#toasts .toast')].map((t) => t.innerText.trim())")
    check(len(toasts) == 3 and toasts[-1] == "Falló", f"at most three toasts, the newest last ({toasts})")
    page.js("document.getElementById('toasts').replaceChildren(); toast('Guardado'); toast('Guardado'); toast('Guardado')")
    check(page.js("document.querySelectorAll('#toasts .toast').length") == 1
          and "×3" in page.js("document.querySelector('#toasts .toast').innerText"), "the same message merges into one (×3)")
    box = page.js("(() => { const r = document.querySelector('#toasts .toast').getBoundingClientRect(); return [r.right, r.bottom, innerWidth, innerHeight]; })()")
    check(box[2] - box[0] < 40 and box[3] - box[1] < 40, f"toasts sit bottom right ({box})")
    check(page.js("getComputedStyle(document.getElementById('toasts')).pointerEvents") == "none"
          and page.js("!!document.querySelector('#toasts .toast .close') && !!document.querySelector('#toasts .toast .icon')"),
          "only the toasts take clicks; each has an icon and a close button")
    page.js("document.querySelectorAll('.nav button')[4].click()")
    check(wait_for(lambda: page.js("!document.querySelector('#toasts .toast')"), 3), "changing view clears the toasts")

    print("Dialogs")
    page.js("""(() => { const a = openModal({ title: 'Paso 1', body: el('p', {}, 'uno') }); a.close();
      openModal({ title: 'Un título muy largo que no cabe en la cabecera del diálogo y tiene que acabar con puntos suspensivos', body: el('p', {}, 'dos') }); })()""")
    check(page.js("document.querySelectorAll('#modal-root > *').length") == 1 and page.js("!!document.querySelector('.overlay.continued')"),
          "a step that replaces a dialog keeps the same scrim (no flash)")
    title = page.js("(() => { const h = document.querySelector('.modal-head h2'); return [h.scrollWidth > h.clientWidth, getComputedStyle(h).textOverflow]; })()")
    check(title == [True, "ellipsis"], f"a long dialog title ends in an ellipsis ({title})")
    page.shot("03-dialog-dark")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: page.js("!document.querySelector('#modal-root > *')"), 3), "and the scrim goes once the last one closes")

    print("The AI's access")
    page.js("state.view = 'access'; renderMain()")
    check(wait_for(lambda: page.js("document.querySelectorAll('.ai-row').length") >= 6, 10), "one row per capability")
    text = page.text()
    check("Valor recomendado" not in text and all(g in text for g in ("Usar", "Modificar", "Publicar")),
          "grouped (Usar · Modificar · Publicar), without a subtitle on rows left as recommended")
    check(page.js("[...document.querySelectorAll('.ai-grid-head span[title]')].length") == 4,
          "the levels are explained once, as column tooltips")
    check(page.js("document.querySelectorAll('.ai-row input[type=radio]:checked').length") == page.js("document.querySelectorAll('.ai-row').length"),
          "each row has its level checked")

    print("Ajustes")
    page.js("state.view = 'settings'; renderMain()")
    wait_for(lambda: "Bloqueo automático" in page.text(), 10)
    widths = page.js("[...document.querySelectorAll('.setting > .control > select, .setting > .control > span > select')].map((s) => s.offsetWidth)")
    check(len(widths) >= 4 and len(set(widths)) == 1, f"the selects in Ajustes have one width ({widths})")
    rights = page.js("[...document.querySelectorAll('.settings-group:first-of-type .setting > .control')].map((c) => Math.round(c.getBoundingClientRect().right))")
    check(len(set(rights)) == 1, f"and the controls line up on the right ({rights})")

    print("Actividad")
    page.js("state.view = 'activity'; renderMain()")
    check(wait_for(lambda: page.js("!!document.querySelector('.event')"), 10), "the activity lists events")
    check(page.js("document.querySelector('.day-head').innerText.trim()") == "Hoy", "grouped by day")
    check(page.js("[...document.querySelectorAll('.event .actor')].every((a) => a.innerText.trim() === 'Tú')"), "who did it: you")
    check(page.js("!document.querySelector('.event .chip')"), "nothing failed: no result column noise")
    page.click("IA", ".activity-filters .tag")
    check(wait_for(lambda: "Nada así" in page.text(), 5), "the IA filter leaves out what you did")
    page.click("Todo", ".activity-filters .tag")
    page.shot("05-activity")

    # The light theme, like Windows set to light.
    page.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "light"}])
    page.js("state.view = 'credentials'; renderMain()")
    time.sleep(0.4)
    page.shot("02-credentials-light")
    page.js("openModal({ title: 'Diálogo', body: el('p', {}, 'En el tema claro'), footer: [el('button', { class: 'btn' }, 'Cancelar'), el('button', { class: 'btn primary' }, 'Aceptar')] })")
    time.sleep(0.3)
    page.shot("03-dialog-light")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(page.js("getComputedStyle(document.querySelector('.nav button.active .icon')).color")
          != page.js("getComputedStyle(document.body).color"), "the current view is marked in the interactive colour, not the text colour")
    page.send("Emulation.setEmulatedMedia", features=[])
    wait_for(lambda: page.js("!document.querySelector('#modal-root > *')"), 3)


def teams_flow(page):
    from secretbroker.service import Service

    print("Teams")
    page.js("state.view = 'team'; renderMain()")
    check(wait_for(lambda: "Comparte credenciales con tu equipo" in page.text() and "el servidor no la conoce" in page.text(), 10),
          "not connected: what is shared, that the server sees nothing, and the password asked once")
    check(page.js("[...document.querySelectorAll('.team-form input')].every((i) => !i.value)"), "nothing is prefilled")
    calm_shot(page, "12-team-connect")
    fill(page, "Servidor", TEAM_URL, ".team-form")
    fill(page, "Tu nombre", "Alicia", ".team-form")
    fill(page, "E-mail", "alicia@example.com", ".team-form")
    fill(page, "Contraseña de la cuenta", ACCOUNT, ".team-form")
    fill(page, "Repítela", ACCOUNT, ".team-form")
    page.click("Crear cuenta", ".team-form .btn.primary")
    check(wait_for(lambda: "Crear organización" in page.text() and "Tu huella" in page.text(), 20), "account created: account, sync and fingerprint")
    check("Confirma que eres tú" not in page.text(), "linking the account asked no other password")
    check(wait_for(lambda: "Sincronizado" in page.text() or "Sin sincronizar" in page.text(), 10), "the sync state shows")

    fill(page, "Nombre del equipo o la empresa", "Acme")
    page.click("Crear organización")
    check(wait_for(lambda: "Colecciones" in page.text() and "Personas" in page.text() and "Acme" in page.text(), 15), "organization created")
    fill(page, "Nombre, p. ej. Producción", "Producción")
    page.click("Crear colección")
    check(wait_for(lambda: "Tu permiso: Gestionar" in page.text(), 15), "collection created, managed by its creator")

    print("Inviting and confirming a teammate")
    bob = Service(HOME / "bob", owner="test\\bob", isolated=False)
    presence = bob.handle("create_vault", {"master_password": MASTER})["result"]["presence"]
    act = lambda op, **params: bob.handle(op, {**params, "proof": {"kind": "presence", "token": presence}})
    bob_status = act("team_connect", server_url=TEAM_URL, email="bob@example.com", password=ACCOUNT, mode="register", name="Bob")["result"]
    fill(page, "e-mail de la persona", "bob@example.com")
    page.click("Invitar")
    check(wait_for(lambda: "Invitación enviada" in page.text(), 15), "invited by e-mail")
    invite = bob.handle("team_invites", {})["result"][0]
    act("team_accept_invite", id=invite["id"])
    page.js("renderView()")
    check(wait_for(lambda: "Pendiente de confirmar" in page.text() and bob_status["fingerprint"] in page.text(), 15),
          "Bob accepted: pending, with his fingerprint to compare")
    page.js("document.querySelector('.fingerprint-box').scrollIntoView({ block: 'center' })")
    calm_shot(page, "13-team-confirm")
    page.click("Confirmar")
    check(wait_for(lambda: "Bob confirmado" in page.text() or "Pendiente de confirmar" not in page.text(), 15), "one click confirms him")
    check(wait_for(lambda: page.js("!!document.querySelector('.collection-members select')"), 15), "he can be added to the collection")
    page.js("""(() => { const s = document.querySelectorAll('.collection-members .inline-form select'); s[1].value = 'edit'; })()""")
    page.click("Añadir")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.collection-members .access-row select')].some((s) => s.value === 'edit')"), 15),
          "Bob is in the collection with «Editar»")
    check("la IA y sb run pueden usarla; la app no la muestra ni la copia" in page.text(), "the permissions are explained")
    calm_shot(page, "14-team")
    page.js("document.querySelector('.content-body').scrollTop = 1e6")
    calm_shot(page, "14-team-people")

    print("Sharing a credential")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    check(wait_for(lambda: page.click("Compartir"), 10), "the credential offers «Compartir»")
    check(wait_for(lambda: "Les llegará cifrada" in page.text(), 10), "choose the collection")
    calm_shot(page, "15-share")
    page.click("Compartir", ".modal-foot button")
    check(wait_for(lambda: "Producción · Gestionar" in page.js("(document.querySelector('.head-sub') || {}).innerText || ''"), 15),
          "shared: badge with collection and permission")
    check(page.js("!!document.querySelector('.row.selected .shared-mark') && !!document.querySelector('.tag.team-tag')"),
          "the list marks it and filters by collection")
    check("Dejar de compartir" in page.text(), "it can be unshared")
    calm_shot(page, "15-shared")
    added = bob.handle("team_sync", {})["result"]["result"]["added"]
    check(added == ["Echo API"], f"Bob receives it ({added})")
    server_files = b"".join(f.read_bytes() for f in (HOME / "server").glob("*") if f.is_file())
    check(b"sk-gui-test-SECRET-123" not in server_files and b"Echo API" not in server_files and "Producción".encode() not in server_files,
          "the server holds neither the key, its name nor the collection name")

    print("A teammate widens where the key can go")
    mine = bob.vault.get("echo-api")
    mine.pop("shared")
    mine["fields"]["value"] = None
    mine["policy"]["http"]["allowed_hosts"].append("api.evil.example")
    saved = bob.handle("save_entry", {"entry": mine, "replaces": "echo-api", "proof": {"kind": "master_password", "value": MASTER}})
    check(saved["ok"], f"Bob edits it ({saved.get('error')})")
    bob.handle("team_sync", {})
    page.js("api().call('team_sync').then(() => loadEntries()).then(renderMain)")
    check(wait_for(lambda: "Cambio por revisar" in page.text() and "api.evil.example" in page.text(), 15),
          "the change waits for review, with what changed")
    check("Revisar cambio" in page.text(), "the list says so")
    calm_shot(page, "16-team-change")
    page.click("Mantener la actual")
    check(wait_for(lambda: "Cambio por revisar" not in page.text(), 15), "one click keeps the current one")
    hosts = page.js("state.entries.find((e) => e.id === 'echo-api').policy.http.allowed_hosts")
    check(hosts == ["127.0.0.1"], f"and the key still only goes where it went ({hosts})")

    print("Removing a teammate")
    page.js("state.view = 'team'; renderMain()")
    check(wait_for(lambda: page.js("!!document.querySelector('button[title=\"Quitar de la organización\"]')"), 15), "admins can remove people")
    page.js("document.querySelector('button[title=\"Quitar de la organización\"]').click()")
    check(wait_for(lambda: "cambiarán de clave" in page.text() and "marcadas para rotar" in page.text(), 5),
          "removing warns: re-keyed collections, credentials to rotate")
    calm_shot(page, "17-team-remove")
    page.click("Quitar", ".modal-foot button")
    check(wait_for(lambda: "Por revisar" in page.text() and "Bob tenía acceso" in page.text(), 15),
          "the credentials he could see are listed to rotate")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    check(wait_for(lambda: "tenía acceso a esta credencial del equipo" in page.text(), 10), "the credential says who had access")
    calm_shot(page, "18-team-rotate")
    page.click("Rotar con ayuda", ".warning button")
    check(wait_for(lambda: "1 · Dónde se usa" in page.text(), 10), "and links to the guided rotation")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)


if __name__ == "__main__":
    main()
