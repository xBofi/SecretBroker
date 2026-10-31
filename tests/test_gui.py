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
os.environ.update(SB_ALLOW_HTTP="1", SB_PUBLIC_URL="http://127.0.0.1", SB_SIGNUPS="open", SB_DATA_DIR=str(HOME / "server"),
                  SB_EMAIL_VERIFICATION="required", SB_SMTP_HOST="smtp.example", SB_SMTP_FROM="secrets@example.com")
sys.path.insert(0, str(ROOT / "server"))
OUTBOX = []  # what the team server would e-mail (verification codes)


def email_code(address):
    import re
    found = wait_for(lambda: [m for m in OUTBOX if m["To"] == address], 10, 0.05)
    return re.search(r"\b(\d{8})\b", found[-1].get_content()).group(1) if found else ""


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
    from secretbroker_server import config, mail
    from secretbroker_server.web import create_app

    mail.deliver = lambda settings, msg: OUTBOX.append(msg)

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
    global TEAM_URL, TEAM_SERVER
    TEAM_URL, team_server = start_team_server()
    TEAM_SERVER = team_server

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
    page.click("Empezar")
    check(wait_for(lambda: "Elige una contraseña maestra" in page.text(), 5), "step 2: the master password")
    page.js(f"""document.querySelectorAll('.auth input[type=password]').forEach((i) => {{ i.value = {json.dumps(MASTER)}; }})""")
    page.click("Crear bóveda")
    check(wait_for(lambda: "¿Cómo quieres abrirla cada día?" in page.text(), 15)
          and "Escribirás la contraseña maestra solo para restaurar copias o en otro PC." in page.text(),
          "step 3: how it opens day to day, so the master password is only for backups and other PCs")
    hello = page.js("!!state.info.hello_supported")
    first = page.js("document.querySelector('.choice input:checked').value")
    check(first == ("hello" if hello else "session") and "Recomendado" in page.js("document.querySelector('.choice.active').innerText"),
          f"preselected: {'Windows Hello' if hello else 'Abrir con mi sesión de Windows'} ({first})")
    check("no de alguien que use tu sesión de Windows" in page.text(), "the session unlock is explained honestly")
    page.shot("01-setup-unlock")
    page.js("document.querySelector('.choice input[value=master]').click()")  # this test types the password on purpose
    page.click("Continuar")
    check(wait_for(lambda: "Conecta tu IA" in page.text(), 15), "then the last step: connect your AI")
    page.click("Ahora no")
    check(wait_for(lambda: "Credenciales" in page.text(), 15), "and the vault is open")
    page.js(f"api().call('unlock', {{}}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    check(wait_for(lambda: "Credenciales" in page.text()), "main screen after unlocking")
    check(wait_for(lambda: "Conectar tu IA" in page.text(), 10)
          and all(t in page.text() for t in ("Añadir una credencial", "Importar de otro gestor", "Importar un .env de un proyecto")),
          "an empty vault offers three ways to start, and connecting the AI while none is connected")
    calm_shot(page, "01-empty-vault")
    page.click("Importar un .env de un proyecto", ".start-card .title")
    check(wait_for(lambda: "sb import .env --delete" in page.text() and "sb run -- npm run dev" in page.text(), 5), "the .env start explains sb import")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)
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
    browser_flow(page, client)
    friction_flow(page, client)

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
    page.js("document.querySelector('.overlay').dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))")
    check(page.js("document.querySelectorAll('.modal').length") == 1, "a click outside the editor doesn't close it")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: "¿Descartar cambios?" in page.text(), 5), "Esc with changes asks «¿Descartar cambios?»")
    page.click("Descartar")
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
    page.click("Ya la he anulado", ".modal button")  # the wizard's, not the same button in the detail behind it
    check(wait_for(lambda: page.js("!document.querySelector('.modal')"), 10), "and the wizard closes: nothing left open behind")
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

    list_flow(page, client)
    teams_flow(page, env)

    print("Claude Code over HTTP, and approving with one click")
    url, token = integrations.mcp_endpoint()
    result = {}

    def ask():
        import asyncio
        import httpx
        from mcp import ClientSession, types
        from mcp.client.streamable_http import streamable_http_client

        async def go():
            async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60) as http:
                async with streamable_http_client(url, http_client=http) as (read, write, *_):
                    async with ClientSession(read, write, client_info=types.Implementation(name="claude-code", version="2.0")) as session:
                        await session.initialize()
                        result["tools"] = len((await session.list_tools()).tools)
                        call = await session.call_tool("http_request", {"secret_id": "echo-api", "url": f"http://127.0.0.1:{api_port}/hola",
                                                                        "reason": "Comprobar que la API local responde"})
                        result["text"] = " ".join(getattr(c, "text", "") for c in call.content)
        asyncio.run(go())

    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    page.js("api().call('revoke_sessions', {})")
    caller = threading.Thread(target=ask)
    caller.start()
    check(wait_for(lambda: "quiere usar una credencial" in page.text(), 20), "the request pops up in the app")
    text = page.js("document.querySelector('.modal.approval').innerText")
    check("Comprobar que la API local responde" in text and "Echo API" in text, "it says why (the AI's reason) and which credential")
    check(page.js("(document.querySelector('.modal.approval mark.host') || {}).textContent") == "127.0.0.1",
          "the exact request, with the host it goes to marked")
    check("Caduca en" in text and ("veces hoy" in text or "vez hoy" in text or "aún no la ha usado" in text or "Último uso" in text),
          "a countdown, and when the AI last used it")
    buttons = page.js("[...document.querySelectorAll('.modal.approval .modal-foot .btn')].map((b) => [b.innerText.trim(), b.className])")
    labels = [b[0] for b in buttons]
    check("Solo esta vez" in labels and "Permitir 24 horas" in labels and "Decidir luego" in text,
          f"«Solo esta vez» and «Permitir 24 horas», and «Decidir luego» instead of an X ({labels})")
    check(len({b[1] for b in buttons if b[0] in ("Solo esta vez", "Permitir 24 horas")}) == 1, "both ways to allow weigh the same")
    check("sin volver a preguntarte durante 24 horas" in text, "one sentence says what the timed grant does")
    time.sleep(0.5)
    page.shot("07-approval")
    page.click("Decidir luego")
    check(wait_for(lambda: page.js("!!document.getElementById('approval-banner') && !document.querySelector('.modal.approval')"), 5),
          "«Decidir luego» folds it into a banner")
    time.sleep(2.5)
    check(page.js("!document.querySelector('.modal.approval')"), "and it doesn't pop up again by itself")
    calm_shot(page, "07-approval-banner")
    page.click("Revisar", "#approval-banner button")
    check(wait_for(lambda: page.js("!!document.querySelector('.modal.approval')"), 5), "«Revisar» opens it again")
    check(page.click("Permitir 24 horas"), "one click: «Permitir 24 horas»")
    caller.join(30)
    check("Confirma que eres tú" not in page.text(), "no password asked")
    check(result.get("tools") == 14, f"Claude Code sees the tools ({result.get('tools')})")
    check("Bearer [REDACTED:echo-api]" in result.get("text", "") and "SECRET" not in result.get("text", ""),
          f"the request carried the key and the AI saw it redacted ({result.get('text', '')[:200]!r})")
    check(wait_for(lambda: "Actividad reciente" in page.text() and "127.0.0.1" in page.js(
        "(document.querySelector('.recent-list') || {}).innerText || ''"), 10),
          "the credential's «Actividad reciente» shows the use, by method and host, without reloading by hand")
    page.js("document.querySelector('.detail .recent').scrollIntoView({ block: 'end' })")
    calm_shot(page, "07-detail-recent")

    print("Several requests from the same AI")
    page.js("api().call('revoke_sessions', {})")
    callers = [threading.Thread(target=lambda: client.request("http_request", {
        "secret_id": "echo-api", "url": f"http://127.0.0.1:{api_port}/{n}", "_client": {"name": "Claude Code", "folder": str(ROOT)}}))
        for n in ("uno", "dos")]
    for c in callers:
        c.start()
        time.sleep(0.4)
    check(wait_for(lambda: "1 de 2" in page.text() and "Permitir las 2 para esta tarea" in page.text(), 15),
          "a queue: «1 de 2», and «Permitir las 2 para esta tarea»")
    check("Claude Code quiere usar una credencial" in page.text() and str(ROOT) in page.text(), "who asks, and from which folder")
    page.shot("07-approval-queue")
    page.click("Permitir las 2 para esta tarea")
    for c in callers:
        c.join(30)
    check(wait_for(lambda: page.js("!document.querySelector('.modal.approval')") and client.request("status")["pending"] == 0, 10),
          "one click answers both")

    print("Pause the AI")
    page.js("state.view = 'access'; renderMain()")
    wait_for(lambda: "Pausar la IA" in page.text(), 5)
    page.click("Pausar la IA")
    check(wait_for(lambda: client.request("status")["ai_paused"], 5), "the pause button pauses the AI")
    check(wait_for(lambda: "La IA está en pausa" in page.text(), 5), "and the page says so")
    page.shot("08-paused")
    page.click("Reanudar")
    check(wait_for(lambda: not client.request("status")["ai_paused"], 5), "resuming is one click")

    connect_ai_flow(page, client)
    import_flow(page, client)

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


def mcp_call(name, tool="list_secrets", arguments=None):
    """One MCP request over HTTP from a client that calls itself `name` in the handshake (like Cursor does)."""
    import asyncio
    import httpx
    from mcp import ClientSession, types
    from mcp.client.streamable_http import streamable_http_client
    from secretbroker import integrations

    url, token = integrations.mcp_endpoint()

    async def go():
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60) as http:
            async with streamable_http_client(url, http_client=http) as (read, write, *_):
                async with ClientSession(read, write, client_info=types.Implementation(name=name, version="1.0")) as session:
                    await session.initialize()
                    return await session.call_tool(tool, arguments or {})
    return asyncio.run(go())


def connect_ai_flow(page, client):
    """The last step of the first run: connect an AI app with one click and see its first request arrive."""
    print("Connect your AI")
    (PROFILE / ".cursor").mkdir(parents=True, exist_ok=True)  # Cursor and VS Code are «installed» in the fake profile
    vscode = PROFILE / "AppData" / "Roaming" / "Code" / "User" / "mcp.json"
    vscode.parent.mkdir(parents=True, exist_ok=True)
    vscode.write_text('{\n  // mine\n  "servers": {"other": {"type": "stdio", "command": "x"},},\n}\n', encoding="utf-8")
    wait_for(lambda: page.js("state.paused === state.status.ai_paused"), 5)  # the pause test's last redraw is over
    time.sleep(1.6)
    page.js("""(() => { state.setupActive = true; state.screen = 'setup'; const box = el('div', { class: 'auth wide' });
      $app().replaceChildren(el('div', { class: 'center-screen' }, box));
      renderConnectAi(box, () => { state.setupActive = false; state.screen = null; state.view = 'access'; refreshStatus(); }); })()""")
    check(wait_for(lambda: "Conecta tu IA" in page.text() and page.js("document.querySelectorAll('.ai-client').length") >= 2, 10),
          "the last setup step lists the AI apps on this PC")
    text = page.text()
    check("Esperando la primera petición" in text and "list_secrets" in text and "No instalados:" in text and "Windsurf" in text,
          "with a test prompt to copy, a live wait for the first request, and the apps not installed folded")
    calm_shot(page, "12-connect-ai")
    page.js("document.querySelector('.ai-client[data-client=cursor] .btn').click()")
    cursor = PROFILE / ".cursor" / "mcp.json"
    check(wait_for(lambda: json.loads(cursor.read_text(encoding="utf-8"))["mcpServers"]["secret-broker"]["url"].startswith("http://127.0.0.1:"), 10),
          "«Conectar» writes Cursor's mcp.json (url and token header)")
    check(wait_for(lambda: page.js("!!document.querySelector('.ai-client[data-client=cursor] .level.is-ok')"), 10), "and the row says Conectado")
    page.js("document.querySelector('.ai-client[data-client=vscode] .btn').click()")
    saved = wait_for(lambda: json.loads(vscode.read_text(encoding="utf-8")) if "secret-broker" in vscode.read_text(encoding="utf-8") else None, 10)
    check(saved and saved["servers"]["secret-broker"]["type"] == "http" and saved["servers"]["other"]["command"] == "x",
          "VS Code's mcp.json (with comments) gets a «servers» entry and keeps the user's own")
    mcp_call("Cursor")
    check(wait_for(lambda: "Recibida de Cursor" in page.text(), 10), "the first request arrives: «Recibida de Cursor»")
    calm_shot(page, "12-connect-ai-received")
    page.click("Empezar a usar SecretBroker")
    check(wait_for(lambda: "Clientes conectados" in page.text() and "Cursor" in page.text() and "Última petición hoy" in page.text(), 10),
          "Acceso de la IA starts with the connected clients and when each made its last request")
    calm_shot(page, "03-access-clients")


IMPORT_CSV = ('"Group","Title","Username","Password","URL","Notes","TOTP"\n'
              '"Root","Correo","ana","fake-Mail-pass-31","https://mail.example.com","","otpauth://totp/Mail:ana?secret=JBSWY3DPEHPK3PXP&issuer=Mail"\n'
              '"Root/Dev","BD pedidos","app","fake-Db-pass-32","postgres://db.example.com:6543/orders","",""\n'
              '"Root/Dev","Bastión","deploy","fake-Ssh-pass-33","ssh://bastion.example.com:2222","",""\n'
              '"Root/Dev","Token de despliegue","","fake-deploy-token-34","","",""\n'
              + "".join(f'"Root","Web {n}","user{n}","fake-Web-pass-{n:03}","https://web{n}.example.com","",""\n' for n in range(140)))


def import_flow(page, client):
    """Import from another manager: the menu, how to export, the development-keys filter, progress, summary, 2FA."""
    print("Import from another manager")
    page.js("state.view = 'credentials'; renderMain()")
    wait_for(lambda: page.js("!!document.querySelector('.content-header [aria-label=\"Más acciones\"]')"), 10)
    check(not page.js("!!document.querySelector('.content-header .btn.icon-only[title=\"Importar de otro gestor\"]')"),
          "no unlabelled import arrow next to «Nueva»")
    page.js("document.querySelector('.content-header [aria-label=\"Más acciones\"]').click()")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.menu-item')].map((b) => b.innerText.trim()).join('|')") == "Importar…|Exportar…", 5),
          "«…» next to «Nueva» has «Importar…» and «Exportar…»")
    calm_shot(page, "13-menu")
    page.click("Importar…", ".menu-item")
    check(wait_for(lambda: "Herramientas → Exportar caja fuerte" in page.text(), 5), "Bitwarden: the exact menu path")
    for source, path in (("1Password", "Archivo → Exportar"), ("KeePassXC / KeePass", "Base de datos → Exportar → Exportar a CSV…"),
                         ("Chrome / Edge", "Exportar contraseñas"), ("Firefox", "about:logins")):
        page.click(source, ".source-tabs button")
        check(wait_for(lambda: path in page.text(), 5), f"{source}: {path}")
    page.click("KeePassXC / KeePass", ".source-tabs button")
    calm_shot(page, "13-import-sources")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

    export = HOME / "keepassxc-export.csv"
    export.write_text(IMPORT_CSV, encoding="utf-8")
    before = len(client.request("entries"))
    page.js(f"previewImport({json.dumps(str(export))}, null)")
    check(wait_for(lambda: "144 credenciales en el archivo" in page.text(), 15), "the preview lists the 144 (names only)")
    check("fake-" not in page.text() and "JBSWY3DP" not in json.dumps(page.js("state")), "without any value")
    check("con código 2FA" in page.text(), "a login with 2FA says so")
    page.js("document.querySelector('.dev-filter input').click()")
    check(wait_for(lambda: page.js("document.querySelectorAll('.import-row').length") == 3 and "Importar 3" in page.text(), 5),
          "«Solo claves de desarrollo»: the database, the SSH server and the token")
    calm_shot(page, "13-import-preview-dev")
    page.js("document.querySelector('.dev-filter input').click()")
    check(wait_for(lambda: "Importar 144" in page.text(), 5), "turning it off selects them all again")
    page.click("Importar 144")
    check(wait_for(lambda: page.js("(document.querySelector('.import-count') || {}).textContent || ''").endswith("de 144"), 10),
          "progress: «N de 144»")
    check(wait_for(lambda: "144 credenciales importadas" in page.text(), 30), "then a summary")
    stats = page.js("[...document.querySelectorAll('.import-stat')].map((s) => s.innerText.replace(/\\s+/g, ' ').trim())")
    check(stats == ["144 creadas", "0 saltadas", "0 con errores"], f"created, skipped and failed, counted ({stats})")
    calm_shot(page, "13-import-done")
    check(len(client.request("entries")) == before + 144, "all in the vault")
    entries = {e["name"]: e for e in client.request("entries")}
    check(entries["BD pedidos"]["template"] == "database" and entries["Bastión"]["template"] == "ssh"
          and "totp" in entries["Correo"]["secrets_set"], "a database, an SSH server and a login with its 2FA")
    page.click("Lo borraré yo")

    print("2FA codes")
    page.js(f"state.view = 'credentials'; state.selected = {json.dumps(entries['Correo']['id'])}; renderMain()")
    check(wait_for(lambda: page.js("(document.querySelector('.totp-code') || {}).textContent || ''").replace(" ", "").isdigit(), 10),
          "the detail shows the current 6-digit code, one click away after unlocking (no prompt)")
    shown = page.js("document.querySelector('.totp-code').textContent").replace(" ", "")
    check(len(shown) == 6 and page.js("+document.querySelector('.totp-seconds').textContent") > 0, "with the seconds left in a ring")
    calm_shot(page, "14-totp")
    page.js("document.querySelectorAll('.totp-prop .actions .btn')[1].click()")
    check(wait_for(lambda: "Código 2FA copiado" in page.text(), 5), "«Copiar» copies it")
    listing = json.dumps(client.request("list_secrets"))
    check("JBSWY3DP" not in listing and "totp_code" not in listing, "the AI sees neither the seed nor the code")
    page.click("Editar")
    check(wait_for(lambda: "Código 2FA (TOTP)" in page.text(), 10), "the editor has the 2FA field")
    labels = page.js("[...document.querySelectorAll('.modal label')].map((l) => l.innerText)")
    check(any(l.startswith("Código 2FA") for l in labels) and sum("Notas privadas" in l for l in labels) == 1,
          f"its label is its own; only the notes are «Notas privadas» {labels}")
    page.js("document.querySelector('.modal details.advanced').open = true")
    check(wait_for(lambda: "Dejar que la IA escriba el código 2FA" in page.text(), 5)
          and page.js("![...document.querySelectorAll('.modal .check-row input')].pop().checked"),
          "letting the AI type the code is a choice in its permissions, off by default")
    page.js("document.querySelector('.modal details.advanced').scrollIntoView({ block: 'end' })")
    calm_shot(page, "14-totp-editor")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)
    for entry in client.request("entries"):
        if entry["description"].startswith("Importada de"):
            client.request("delete_entry", {"id": entry["id"], "proof": {"kind": "master_password", "value": MASTER}})


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


def browser_flow(page, client):
    """Ajustes › Navegador: installing the extension, a browser asking to connect, the editor's sites and
    Actividad's «Navegador» (the extension itself is driven through the service, as its native host would)."""
    from secretbroker import native_host
    print("Browser extension")
    page.js("state.view = 'settings'; renderMain()")
    check(wait_for(lambda: "Extensión del navegador" in page.text() and "Instalar la extensión" in page.text(), 10),
          "Ajustes has a Navegador section offering to install the extension")
    page.js("[...document.querySelectorAll('.settings-group')].find((g) => (g.querySelector('h3') || {}).textContent === 'Navegador').scrollIntoView()")
    time.sleep(0.3)
    page.shot("17-settings-browser")
    page.click("Instalar la extensión")
    check(wait_for(lambda: page.js("!!document.querySelector('.install-steps')"), 5), "the install steps open")
    steps = page.js("[...document.querySelectorAll('.install-steps li')].map((l) => l.innerText)")
    folder = page.js("(document.querySelector('.install-folder code') || {}).innerText || ''")
    check(len(steps) >= 3 and any("Cargar" in s for s in steps) and any("Conectar" in s for s in steps),
          f"steps: open the extensions page, load the folder, press «Conectar» ({len(steps)})")
    check(folder.rstrip("\\/").endswith("extension") and "Copiar ruta" in page.text() and "Mostrar" in page.text(),
          f"the extension folder, to copy or show, no terminal ({folder})")
    check("tienda" in page.text() or "addons.mozilla.org" in page.text(), "says the stores will make it one click")
    calm_shot(page, "17-browser-install")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

    ext = {"origin": native_host.ALLOWED_ORIGINS[0], "pair": "gui-test-pair-0123456789", "key": "g" * 43}
    asked = client.request("ext_pair", {"name": "Chrome", "_ext": ext})
    check(wait_for(lambda: "¿Conectar Chrome?" in page.text(), 10), "a browser asking to connect shows up in the app")
    check(f"{asked['code'][:3]} {asked['code'][3:]}" in page.text(), "with the code the extension shows")
    calm_shot(page, "17-browser-pair")
    page.click("Conectar", ".modal-foot button")
    check(wait_for(lambda: client.request("ext_hello", {"_ext": ext})["paired"], 10), "one click connects it")
    check(wait_for(lambda: "Conectada" in page.text() and "Desconectar" in page.text(), 10), "Ajustes says it is connected")

    login = {"id": "web-gui", "name": "Web de prueba", "template": "web_login", "description": "",
             "fields": {"url": "https://login.example.com", "username": "ana", "password": "gui-fake-pass"},
             "policy": {"approval": "session"}, "autofill": {"sites": ["https://example.org"], "match": "host"}}
    saved = page.js(f"api().call('save_entry', {{ entry: {json.dumps(login)} }})")
    check(saved and saved["ok"], f"a web login with autofill sites {'' if saved and saved['ok'] else saved}")
    page.js("loadEntries().then(() => { state.view = 'credentials'; state.selected = 'web-gui'; renderMain(); })")
    wait_for(lambda: "Web de prueba" in page.text(), 5)
    page.click("Editar")
    check(wait_for(lambda: page.js("!!document.querySelector('.modal details.advanced')"), 5)
          and page.js("[...document.querySelectorAll('.modal details summary')].some((s) => s.innerText.includes('Navegador'))"),
          "the editor of a web login has a «Navegador» section")
    check(page.js("[...document.querySelectorAll('.modal textarea')].some((t) => t.value === 'https://example.org')")
          and page.js("[...document.querySelectorAll('.modal select')].some((s) => s.value === 'host')"),
          "with its sites and how strictly they match")
    page.js("[...document.querySelectorAll('.modal details summary')].find((s) => s.innerText.includes('Navegador')).scrollIntoView({ block: 'center' })")
    calm_shot(page, "17-editor-autofill")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

    filled = client.request("ext_fill", {"url": "https://example.org/login", "id": "web-gui", "_ext": ext})
    check(filled.get("password") == "gui-fake-pass", "the browser fills it on its site")
    page.js("state.view = 'activity'; renderMain()")
    check(wait_for(lambda: "Rellenada en el navegador" in page.text(), 10), "Actividad shows the fill")
    page.click("Navegador", ".activity-filters .tag")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.event .actor')].map((a) => a.innerText.trim())") == ["Navegador"], 5),
          "the Navegador filter shows only the browser, labelled «Navegador»")
    page.click("Todo", ".activity-filters .tag")
    client.request("browser_forget", {"id": ext["pair"]})
    page.js("api().call('delete_entry', { id: 'web-gui' }).then(() => loadEntries())")
    page.js("state.view = 'credentials'; renderMain()")


def type_proof(page, value):
    """Answer «Confirma que eres tú» with the master password."""
    page.click("Contraseña maestra", ".modal .segmented button")
    page.js(f"""(() => {{ const i = [...document.querySelectorAll('.modal input[type=password]')].pop(); i.value = {json.dumps(value)}; }})()""")
    page.click("Confirmar")


def friction_flow(page, client):
    """The password is typed once a session: unlocking. Without Windows Hello, editing, revealing, copying
    and changing a setting are one click. Opening with the Windows session asks for a proof once."""
    print("One password a session (without Windows Hello)")
    page.js("state.info.hello_supported_real = state.info.hello_supported; state.info.hello_supported = false")
    page.js("""window.__prompts = 0; if (!window.__askProof) { window.__askProof = askProof;
      askProof = (...args) => { window.__prompts++; return window.__askProof(...args); }; }""")
    page.js("lockNow()")
    check(wait_for(lambda: "SecretBroker está bloqueado" in page.text(), 10), "locked")
    page.js("document.querySelector('details.other-unlock') && (document.querySelector('details.other-unlock').open = true)")
    page.js(f"""(() => {{ const i = document.querySelector('.auth input[type=password]'); i.value = {json.dumps(MASTER)}; }})()""")
    page.click("Desbloquear")
    check(wait_for(lambda: "Credenciales" in page.text() and client.request("status")["state"] == "unlocked", 15),
          "the master password, typed once on the lock screen")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    wait_for(lambda: "Echo API" in page.text(), 5)

    page.click("Editar")
    wait_for(lambda: page.js("!!document.querySelector('.modal textarea')"), 5)
    labels = page.js("[...document.querySelectorAll('.modal label')].map((l) => l.innerText.trim())")
    check(any(l.startswith("Instrucciones para la IA") and "la IA las lee" in l for l in labels)
          and any(l.startswith("Notas privadas") and "solo tú, cifradas" in l for l in labels)
          and any(l.startswith("Identificador de la app (p. ej. ID de cliente)") for l in labels),
          f"the editor says who reads what: instructions for the AI, private notes, the app's id ({labels})")
    calm_shot(page, "10-editor-labels")
    page.js("""(() => { const t = [...document.querySelectorAll('.modal .field')].find((f) => f.innerText.startsWith('Instrucciones para la IA')).querySelector('textarea');
      t.value = 'API local de prueba. Solo lectura.'; t.dispatchEvent(new Event('input', { bubbles: true })); })()""")
    page.click("Guardar")
    check(wait_for(lambda: page.js("(state.entries.find((e) => e.id === 'echo-api') || {}).description") == "API local de prueba. Solo lectura.", 10),
          "editing a credential: saved")
    page.js("document.querySelector('.detail .prop button[title=Mostrar]').click()")
    check(wait_for(lambda: page.js("!!document.querySelector('.detail .v.revealed')"), 10), "revealing a key")
    page.js("document.querySelector('.detail .prop button[title=Ocultar]').click()")
    page.js("[...document.querySelectorAll('.detail .prop')].find((p) => p.querySelector('button[title=Mostrar]')).querySelector('button[title=Copiar]').click()")
    check(wait_for(lambda: "se borra en" in page.text(), 10), "copying a key")
    page.js("state.view = 'settings'; renderMain()")
    approvals = "[...document.querySelectorAll('select')].find((s) => [...s.options].some((o) => o.textContent === 'Hasta que bloquee'))"
    wait_for(lambda: page.js(f"!!{approvals}"), 5)
    page.js(f"(() => {{ const s = {approvals}; s.value = '8'; s.dispatchEvent(new Event('change')); }})()")
    check(wait_for(lambda: client.request("status")["approval_hours"] == 8, 10), "changing a setting")
    page.js(f"(() => {{ const s = {approvals}; s.value = '24'; s.dispatchEvent(new Event('change')); }})()")
    wait_for(lambda: client.request("status")["approval_hours"] == 24, 10)
    check(page.js("window.__prompts") == 0 and "Confirma que eres tú" not in page.text(),
          f"1 password over the session: unlock, edit, reveal, copy, settings ({page.js('window.__prompts')} more asked)")

    print("Opened with the Windows session: a proof once")
    enabled = page.js("api().enable_session_unlock(null)")
    check(enabled and enabled["ok"] and page.js("window.__prompts") == 0, "turning on the session unlock is one click too")
    page.js("lockNow()")
    wait_for(lambda: "SecretBroker está bloqueado" in page.text(), 10)
    page.js("document.querySelector('details.other-unlock') && (document.querySelector('details.other-unlock').open = true)")
    page.click("Abrir con mi sesión de Windows")
    check(wait_for(lambda: client.request("status")["state"] == "unlocked" and "Credenciales" in page.text(), 10), "opened without a password")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    wait_for(lambda: page.js("!!document.querySelector('.detail .prop button[title=Mostrar]')"), 5)
    page.js("document.querySelector('.detail .prop button[title=Mostrar]').click()")
    check(wait_for(lambda: "Confirma que eres tú" in page.text(), 10) and "Confirma una vez que eres tú" in page.text(),
          "revealing asks who you are, once: anything running as you could have opened it")
    calm_shot(page, "11-proof-once")
    type_proof(page, MASTER)
    check(wait_for(lambda: page.js("!!document.querySelector('.detail .v.revealed')"), 10), "then it shows")
    page.js("document.querySelector('.detail .prop button[title=Ocultar]').click()")
    page.js("[...document.querySelectorAll('.detail .prop')].find((p) => p.querySelector('button[title=Mostrar]')).querySelector('button[title=Copiar]').click()")
    check(wait_for(lambda: "se borra en" in page.text(), 10) and page.js("window.__prompts") == 1,
          "and from then on it is one click (one proof in all)")

    print("Locked for inactivity, with the Windows session")
    page.js("api().call('set_settings', { settings: { auto_lock_minutes: 1 } })")
    check(wait_for(lambda: (lambda s: s["state"] == "locked" and s.get("lock_reason") == "idle")(client.request("status")), 100, 1),
          "after a minute without use it locks")
    check(wait_for(lambda: "Se bloqueó por inactividad" in page.text(), 10), "the lock screen says it will open by itself")
    calm_shot(page, "11-idle-lock")
    page.js("window.dispatchEvent(new Event('pointerdown'))")
    check(wait_for(lambda: client.request("status")["state"] == "unlocked" and "Credenciales" in page.text(), 10),
          "coming back to the window opens it, without a password")
    client.request("lock")
    check(any(v["id"] == "echo-api" for v in client.call("list_secrets")), "the AI's next request opens it too: it doesn't wait for anyone")
    check(page.js("window.__prompts") == 1, "still one proof in all")
    # Back to how the rest of the test expects it: the app with a token from a password, no session unlock.
    wait_for(lambda: "Credenciales" in page.text() and page.js("api().has_presence()"), 10)
    page.js(f"api().call('unlock', {{}}, {{ kind: 'master_password', value: {json.dumps(MASTER)} }})")
    page.js("api().disable_session_unlock()")
    page.js("api().call('set_settings', { settings: { auto_lock_minutes: 0 } })")
    check(wait_for(lambda: client.request("status")["auto_lock_minutes"] == 0, 5), "(the inactivity lock off again for the rest of the test)")
    page.js("askProof = window.__askProof; delete window.__askProof; state.info.hello_supported = state.info.hello_supported_real ?? state.info.hello_supported")


def list_flow(page, client):
    print("The list: search, keyboard, order")
    page.js("state.view = 'credentials'; state.search = ''; state.tag = null; state.collection = null; state.selected = 'echo-api'; renderMain()")
    wait_for(lambda: page.js("!!document.querySelector('.list .row')"), 5)
    total = page.js("state.entries.length")
    check(page.js("document.querySelector('.list-count').textContent") == f"{total} credenciales", "the list says how many there are")
    page.js("(() => { const s = document.querySelector('.search .input'); s.value = 'otra'; s.dispatchEvent(new Event('input')); })()")
    check(wait_for(lambda: page.js("state.selected") == "other-api", 5), "searching selects the first match")
    check(page.js("document.querySelector('.list-count').textContent") == f"1 de {total}", f"«1 de {total}»")
    page.js("(() => { const s = document.querySelector('.search .input'); s.value = ''; s.dispatchEvent(new Event('input')); })()")
    order = page.js("[...document.querySelectorAll('.list .row')].map((r) => r.dataset.id)")
    page.js("document.querySelector('.list').focus()")
    page.js("document.querySelector('.list').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))")
    following = order[order.index("other-api") + 1] if order.index("other-api") + 1 < len(order) else "other-api"
    check(wait_for(lambda: page.js("state.selected") == following, 5)
          and page.js("document.activeElement.dataset.id") == following, "the down arrow selects and focuses the next one")
    page.js("document.querySelector('.list').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))")
    check(wait_for(lambda: page.js("!!document.querySelector('.modal')"), 5), "Enter opens it")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)
    options = page.js("[...document.querySelector('.list-tools select').options].map((o) => o.textContent)")
    check(options == ["Nombre", "Usadas recientemente", "Cambiadas recientemente", "Necesitan atención"], f"orders ({options})")
    page.js("(() => { const s = document.querySelector('.list-tools select'); s.value = 'changed'; s.dispatchEvent(new Event('change')); })()")
    newest = max(page.js("state.entries.map((e) => e.updated || '')"))
    check(page.js("(state.entries.find((e) => e.id === document.querySelector('.list .row').dataset.id) || {}).updated") == newest,
          "«Cambiadas recientemente» puts the last one changed first")
    calm_shot(page, "02-list-sorted")
    page.js("(() => { const s = document.querySelector('.list-tools select'); s.value = 'name'; s.dispatchEvent(new Event('change')); })()")

    print("Changes made elsewhere show in place")
    page.js("state.selected = 'other-api'; renderMain()")
    wait_for(lambda: "Otra API" in page.js("document.querySelector('.detail h2').textContent"), 5)
    page.js("document.querySelector('.list').dataset.mark = 'same'; document.querySelector('.detail').scrollTop = 40")
    client.request("update_credential", {"secret_id": "other-api", "description": "Escrito por la IA desde fuera"})
    check(wait_for(lambda: "Escrito por la IA desde fuera" in page.js("document.querySelector('.detail').innerText"), 10),
          "an edit by the AI shows by itself")
    check(page.js("document.querySelector('.list').dataset.mark") == "same" and page.js("state.selected") == "other-api",
          "redrawn in place: the same list, the same selection")

    print("Editing while something else changes it")
    page.click("Editar")
    wait_for(lambda: page.js("!!document.querySelector('.modal input.input')"), 5)
    page.js("""(() => { const i = document.querySelector('.modal .field input.input'); i.value = 'Otra API (mía)'; i.dispatchEvent(new Event('input', { bubbles: true })); })()""")
    client.request("update_credential", {"secret_id": "other-api", "name": "Otra API (IA)", "tags": ["ia"]})
    page.click("Guardar")
    check(wait_for(lambda: "Cambió mientras editabas" in page.text(), 10), "saving says it changed meanwhile")
    check("Nombre" in page.js("document.querySelector('.conflict').innerText") and "Etiquetas" in page.js("document.querySelector('.conflict').innerText"),
          "and what: «Nombre», «Etiquetas»")
    check(page.js("[...document.querySelectorAll('.conflict button')].map((b) => b.innerText.trim()).join('|')") == "Recargar|Sobrescribir",
          "«Recargar» or «Sobrescribir»")
    calm_shot(page, "10-editor-conflict")
    page.click("Sobrescribir")
    check(wait_for(lambda: page.js("(state.entries.find((e) => e.id === 'other-api') || {}).name") == "Otra API (mía)", 10),
          "«Sobrescribir» keeps the user's version")
    page.click("Editar")
    wait_for(lambda: page.js("!!document.querySelector('.modal')"), 5)
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: page.js("!document.querySelector('.modal')"), 5), "Esc without changes closes at once")
    client.request("update_credential", {"secret_id": "other-api", "name": "Otra API", "tags": []})  # as the team test expects it
    wait_for(lambda: page.js("(state.entries.find((e) => e.id === 'other-api') || {}).name") == "Otra API", 10)

    print("Messages in the user's words")
    page.js("openEditor(null)")
    page.click("API key o token", ".template-option .title")
    wait_for(lambda: page.js("!!document.querySelector('.modal .field input.input')"), 5)
    page.js("""(() => { const f = [...document.querySelectorAll('.modal .field input.input')];
      f[0].value = 'Otra API (mía)'; f[0].dispatchEvent(new Event('input', { bubbles: true }));
      const key = document.querySelector('.modal input[type=password]'); key.value = 'sk-test-12345678901234'; key.dispatchEvent(new Event('input', { bubbles: true }));
      document.querySelector('.modal details.advanced').open = true;
      const auth = [...document.querySelectorAll('.modal select')].find((s) => [...s.options].some((o) => o.value === 'header'));
      auth.value = 'header'; auth.dispatchEvent(new Event('input', { bubbles: true }));
      const value = [...document.querySelectorAll('.modal input.mono')].find((i) => i.placeholder === 'Bearer {{value}}');
      value.value = 'Bearer {{password}}'; value.dispatchEvent(new Event('input', { bubbles: true }));
      const name = [...document.querySelectorAll('.modal input.mono')].find((i) => i.placeholder === 'Authorization');
      name.value = 'Authorization'; name.dispatchEvent(new Event('input', { bubbles: true })); })()""")
    page.click("Guardar")
    error = wait_for(lambda: page.js("(document.querySelector('.modal .error-text') || {}).textContent"), 10) or ""
    check(error and "{{" not in error and "other-api" not in error and "«password»" in error,
          f"no {{{{placeholders}}}} or internal ids in the message ({error})")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    page.click("Descartar")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)


def tab(page, name):
    """Open a tab of the Equipo view (its label, without the count)."""
    return page.js(f"""(() => {{ const b = [...document.querySelectorAll('.team-tabs button')]
      .find((x) => x.firstChild && x.firstChild.textContent.trim() === {json.dumps(name)});
      if (!b) return false; b.click(); return true; }})()""")


def teams_flow(page, env):
    from secretbroker.service import Service

    print("Teams")
    page.js("state.view = 'team'; renderMain()")
    check(wait_for(lambda: "Comparte credenciales con tu equipo" in page.text() and "el servidor no la conoce" in page.text(), 10),
          "not connected: what is shared, that the server sees nothing, and the password asked once")
    check(page.js("[...document.querySelectorAll('.team-form input')].every((i) => !i.value)"), "nothing is prefilled")
    check("uno alojado" not in page.text(), "no promise of a hosted server that doesn't exist")
    calm_shot(page, "12-team-connect")

    print("An invite link")
    link = f"secretbroker://join?server={TEAM_URL}&email=alicia%40example.com&code=ABC-123"
    page.js(f"""(() => {{ const i = document.querySelector('.team-form input'); i.value = {json.dumps(link)};
      i.dispatchEvent(new Event('input')); }})()""")
    filled = page.js("[...document.querySelectorAll('.team-form input')].map((i) => i.value)")
    check(TEAM_URL in filled and "alicia@example.com" in filled and "ABC-123" in filled,
          "pasting an invite link fills in server, e-mail and code")
    check("Invitación para alicia@example.com" in page.text(), "and says it came from an invitation, to check the server")
    calm_shot(page, "12-team-invite-link")
    page.js("renderView()")
    wait_for(lambda: page.js("[...document.querySelectorAll('.team-form input')].every((i) => !i.value)"), 5)
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    subprocess.Popen([str(pythonw), "-m", "secretbroker.app", link], cwd=ROOT, env=env).wait(20)
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.team-form input')].some((i) => i.value === 'ABC-123')"), 10),
          "opening the app with secretbroker://join… fills in the form of the running app")
    log = (HOME / "user" / "app.log").read_text(encoding="utf-8")
    check("ABC-123" not in log, "the invite code is not written to the app log")
    page.js("renderView()")
    wait_for(lambda: page.js("[...document.querySelectorAll('.team-form input')].every((i) => !i.value)"), 5)

    fill(page, "Servidor", TEAM_URL, ".team-form")
    fill(page, "Tu nombre", "Alicia", ".team-form")
    fill(page, "E-mail", "alicia@example.com", ".team-form")
    fill(page, "Contraseña de la cuenta", ACCOUNT, ".team-form")
    fill(page, "Repítela", ACCOUNT, ".team-form")
    page.click("Crear cuenta", ".team-form .btn.primary")
    check(wait_for(lambda: "Crear organización" in page.text() and "Tu código de seguridad" in page.text(), 20),
          "account created: create an organization, and the account with its security code")
    code = page.js("state.team.fingerprint")
    check(len(code.split()) == 8 and code.replace(" ", "").isdigit() and code in page.text(), f"the code is groups of digits ({code})")
    check("Confirma que eres tú" not in page.text(), "linking the account asked no other password")
    check(wait_for(lambda: "Sincronizado" in page.text() or "Sin sincronizar" in page.text(), 10), "the sync state shows")
    check(wait_for(lambda: "Verifica tu e-mail" in page.text() and "alicia@example.com" in page.text(), 10),
          "a new account is asked to verify its e-mail (invites only reach verified addresses)")
    calm_shot(page, "12-team-verify")
    fill(page, "12345678", email_code("alicia@example.com"))
    page.click("Verificar")
    check(wait_for(lambda: "E-mail verificado" in page.text() and "Verifica tu e-mail" not in page.text(), 15),
          "typing the code from the e-mail verifies it, once")
    calm_shot(page, "12-team-no-org")

    fill(page, "Nombre del equipo o la empresa", "Acme")
    page.click("Crear organización")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.team-tabs button')].map((b) => b.firstChild.textContent).join('|')")
                   == "Colecciones|Personas|Actividad|Tu cuenta", 15), "organization created: tabs Colecciones · Personas · Actividad · Tu cuenta")
    check(page.js("document.querySelector('.org-picker').selectedOptions[0].textContent") == "Acme", "the organization in the header")
    fill(page, "Nombre, p. ej. Producción", "Producción")
    page.click("Crear colección")
    check(wait_for(lambda: "Tu permiso: Gestor" in page.text(), 15), "collection created, its creator is «Gestor»")

    print("Inviting and confirming a teammate")
    bob = Service(HOME / "bob", owner="test\\bob", isolated=False)
    presence = bob.handle("create_vault", {"master_password": MASTER})["result"]["presence"]
    act = lambda op, **params: bob.handle(op, {**params, "proof": {"kind": "presence", "token": presence}})
    bob_status = act("team_connect", server_url=TEAM_URL, email="bob@example.com", password=ACCOUNT, mode="register", name="Bob")["result"]
    act("team_verify_email", code=email_code("bob@example.com"))
    check(tab(page, "Personas"), "the Personas tab")
    check(wait_for(lambda: "SecretBroker no envía las invitaciones por e-mail" in page.text(), 10), "inviting says honestly that no e-mail is sent")
    fill(page, "e-mail de la persona", "bob@example.com")
    page.click("Invitar")
    check(wait_for(lambda: "Invitación creada para bob@example.com" in page.text() and "secretbroker://join?server=" in page.text(), 15),
          "invited: instructions with a link to pass on")
    instructions = page.js("document.querySelector('.instructions').textContent")
    check("bob%40example.com" in instructions and TEAM_URL in instructions and "Código de invitación" in instructions,
          "the instructions carry the server, the e-mail and the sign-up code")
    calm_shot(page, "13-team-invite")
    page.click("Copiar instrucciones", ".modal button")
    check(wait_for(lambda: "Instrucciones copiadas" in page.text(), 5), "one click copies them")
    page.js("document.querySelector('.overlay').dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: "Invitada · aún no ha entrado" in page.text(), 10), "the person shows as invited, not in yet")
    invite = bob.handle("team_invites", {})["result"][0]
    act("team_accept_invite", id=invite["id"])
    page.js("renderView()")
    check(wait_for(lambda: "Por verificar (1)" in page.text() and "Pendiente de confirmar" in page.text()
                   and bob_status["fingerprint"] in page.text() and "Código de Bob" in page.text(), 15),
          "Bob accepted: «Por verificar (1)» at the top, with his security code to compare")
    calm_shot(page, "13-team-confirm")
    page.click("Confirmar")
    check(wait_for(lambda: "Bob confirmado" in page.text() and "Por verificar" not in page.text(), 15), "one click confirms him")
    tab(page, "Colecciones")
    check(wait_for(lambda: page.js("!!document.querySelector('.collection-members select')"), 15), "he can be added to the collection")
    page.js("""(() => { const s = document.querySelectorAll('.collection-members .inline-form select'); s[1].value = 'edit'; })()""")
    page.click("Añadir")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('.collection-members .access-row select')].some((s) => s.value === 'edit')"), 15),
          "Bob is in the collection as «Editor»")
    options = page.js("[...document.querySelector('.collection-members .access-row select').options].map((o) => o.textContent).join('|')")
    check(options == "Gestor|Editor|Lector|Solo uso", f"permissions are nouns ({options})")
    check("Solo uso: la IA y tus programas" not in page.text(), "no legend floating under the list")
    page.js("document.querySelector('.help-btn').click()")
    check(wait_for(lambda: "la IA y tus programas pueden usarla; tú no puedes verla ni copiarla" in page.text(), 5),
          "the «?» explains the permissions")
    calm_shot(page, "14-team")
    page.js("document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))")
    check(wait_for(lambda: "tú no puedes verla ni copiarla" not in page.text(), 5), "and closes when clicking elsewhere")
    tab(page, "Personas")
    wait_for(lambda: "Invitar" in page.text(), 5)
    calm_shot(page, "14-team-people")
    tab(page, "Tu cuenta")
    check(wait_for(lambda: "Tu código de seguridad" in page.text() and "Desconectar" in page.text(), 5), "Tu cuenta: code and disconnect")
    tab(page, "Actividad")
    check(wait_for(lambda: "Creó la colección Producción" in page.text(), 10), "Actividad: what the server recorded")

    print("Sharing a credential")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    check(wait_for(lambda: page.click("Compartir"), 10), "the credential offers «Compartir»")
    check(wait_for(lambda: "Les llegará cifrada" in page.text() and "Nueva colección…" in page.text(), 10),
          "choose the collection, or a new one")
    calm_shot(page, "15-share")
    page.click("Compartir", ".modal-foot button")
    check(wait_for(lambda: "Compartida · Producción" in page.js("(document.querySelector('.head-sub') || {}).innerText || ''"), 15),
          "shared: «Compartida · Producción»")
    check("Gestor" in page.js("document.querySelector('.head-sub .shared-badge').title"), "the permission is in its tooltip")
    check(page.js("!!document.querySelector('.row.selected .shared-mark') && !!document.querySelector('.tag.team-tag')"),
          "the list marks it and filters by collection")
    check("Dejar de compartir" in page.text() and "Tu permiso: Gestor" in page.text(), "the detail says the permission, and it can be unshared")
    calm_shot(page, "15-shared")
    added = bob.handle("team_sync", {})["result"]["result"]["added"]
    check(added == ["Echo API"], f"Bob receives it ({added})")
    server_files = b"".join(f.read_bytes() for f in (HOME / "server").glob("*") if f.is_file())
    check(b"sk-gui-test-SECRET-123" not in server_files and b"Echo API" not in server_files and "Producción".encode() not in server_files,
          "the server holds neither the key, its name nor the collection name")

    print("Sharing several at once")
    for name in ("Otra API", "BD tienda"):
        page.js(f"""(() => {{ const row = [...document.querySelectorAll('.row')].find((r) => r.querySelector('.title').firstChild.textContent === {json.dumps(name)});
          row.querySelector('.pick').click(); }})()""")
    check(wait_for(lambda: "2 seleccionadas" in page.text() and "Compartir 2 en…" in page.text(), 5),
          "ticking two credentials offers «Compartir 2 en…»")
    calm_shot(page, "15-share-several")
    page.click("Compartir 2 en…")
    check(wait_for(lambda: "Compartir 2 credenciales" in page.text(), 10), "one dialog for both")
    page.js("document.querySelector('.modal input[type=radio][value=new]').click()")
    fill(page, "Nombre, p. ej. Producción", "Pruebas", ".modal")
    page.click("Compartir 2", ".modal-foot button")
    check(wait_for(lambda: page.js("['other-api', 'shop-db'].every((id) => ((state.entries.find((e) => e.id === id) || {}).shared || {}).collection_name === 'Pruebas')"), 20),
          "a new collection made in the dialog, and both shared in it")
    check(page.js("state.picked.size") == 0 and page.js("document.querySelector('.bulk-bar').classList.contains('hidden')"),
          "the selection is cleared")

    print("A teammate widens where the key can go")
    mine = bob.vault.get("echo-api")
    mine.pop("shared")
    mine["fields"]["value"] = None
    mine["policy"]["http"]["allowed_hosts"].append("api.evil.example")
    saved = bob.handle("save_entry", {"entry": mine, "replaces": "echo-api", "proof": {"kind": "master_password", "value": MASTER}})
    check(saved["ok"], f"Bob edits it ({saved.get('error')})")
    bob.handle("team_sync", {})
    page.js("state.selected = 'echo-api'; api().call('team_sync').then(() => loadEntries()).then(renderMain)")
    check(wait_for(lambda: "Bob quiere que la IA pueda enviar esta clave a:" in page.text() and "api.evil.example" in page.text(), 15),
          "the change waits for review: who wants the key to go where")
    check("Rechazar y mantener como estaba" in page.text() and "Permitir api.evil.example" in page.text()
          and "deshace el cambio para todo el equipo" in page.text() and "la IA no puede usar los destinos nuevos" in page.text(),
          "rejecting is the main choice, and both are explained")
    check("Revisar cambio" in page.text(), "the list says so")
    calm_shot(page, "16-team-change")
    page.click("Rechazar y mantener como estaba")
    check(wait_for(lambda: "quiere que la IA pueda enviar" not in page.text(), 15), "one click keeps it as it was")
    hosts = page.js("state.entries.find((e) => e.id === 'echo-api').policy.http.allowed_hosts")
    check(hosts == ["127.0.0.1"], f"and the key still only goes where it went ({hosts})")

    print("An edit that waits")
    page.js("""(() => { const e = state.entries.find((x) => x.id === 'echo-api'); e.shared.unsent = 'rekey'; renderMain(); })()""")
    check(wait_for(lambda: "Sin enviar" in page.text(), 5)
          and "se tiene que volver a cifrar" in page.js("[...document.querySelectorAll('.draft-badge')].map((b) => b.title).join(' ')"),
          "an edit held for a re-encryption is marked «Sin enviar», with why")
    page.js("loadEntries().then(renderMain)")

    print("Removing a teammate")
    page.js("state.view = 'team'; state.teamTab = 'people'; renderMain()")
    check(wait_for(lambda: page.js("!!document.querySelector('button[title=\"Quitar de la organización\"]')"), 15), "admins can remove people")
    page.js("document.querySelector('button[title=\"Quitar de la organización\"]').click()")
    check(wait_for(lambda: "se volverán a cifrar" in page.text() and "cambiar las claves que pudo ver" in page.text(), 5),
          "removing warns: collections re-encrypted, keys to change")
    calm_shot(page, "17-team-remove")
    page.click("Quitar", ".modal-foot button")
    check(wait_for(lambda: "Cambiar lo que pudo ver Bob" in page.text() and "0 de 1 cambiada" in page.text(), 15),
          "then the list of what he could see opens, to change it one after the other")
    calm_shot(page, "17-team-offboarding")
    page.click("Más tarde")
    check(wait_for(lambda: "Bob pudo ver 1 credencial · 0 cambiadas" in page.text(), 10), "Equipo keeps it at the top")
    check(page.js("(document.querySelector('.nav button[data-view=\"team\"] .count') || {}).textContent") == "1",
          "and the sidebar counts it")
    calm_shot(page, "18-team-offboarding-banner")
    page.js("state.view = 'exposure'; renderMain()")
    check(wait_for(lambda: "Bob ya no está: 1 credencial por cambiar" in page.text(), 10), "Salud shows it too")
    calm_shot(page, "18-salud-offboarding")
    page.js("state.view = 'credentials'; state.selected = 'echo-api'; renderMain()")
    check(wait_for(lambda: "Bob tenía acceso a esta credencial del equipo y ya no está" in page.text() and "Cámbiala por si la vio" in page.text(), 10),
          "the credential says who had access")
    check("Cambiar: salió Bob" in page.text(), "the list badge says it as a noun")
    calm_shot(page, "18-team-rotate")
    page.js("state.view = 'team'; renderMain()")
    wait_for(lambda: "Bob pudo ver" in page.text(), 10)
    page.click("Empezar", ".offboard-card button")
    check(wait_for(lambda: "Cambiar lo que pudo ver Bob" in page.text(), 10), "the queue opens from Equipo")
    wait_for(lambda: page.click("Empezar", ".modal-foot button"), 10)
    check(wait_for(lambda: "1 · Dónde se usa" in page.text(), 10), "and runs the guided rotation")
    calm_shot(page, "18-team-offboarding-wizard")
    page.js("[...document.querySelectorAll('.overlay')].pop().dispatchEvent(new Event('dismiss'))")
    check(wait_for(lambda: "Saltada" in page.text() or "Seguir con" in page.text(), 10), "closing it leaves the queue to go on or skip")
    page.js("document.querySelectorAll('.overlay').forEach((o) => o.dispatchEvent(new Event('dismiss')))")
    wait_for(lambda: page.js("!document.querySelector('.modal')"), 5)

    print("Offline")
    TEAM_SERVER.should_exit = True
    wait_for(lambda: not TEAM_SERVER.started or TEAM_SERVER.should_exit, 5)
    time.sleep(1)
    page.js("api().call('team_sync')")
    check(wait_for(lambda: page.js("(document.querySelector('.nav button[data-view=\"team\"] .count') || {}).textContent") == "!", 15),
          "the sidebar warns when the team server can't be reached")
    page.js("state.view = 'team'; state.teamTab = 'people'; renderMain()")
    check(wait_for(lambda: "Sin conexión" in page.text() and "Alicia" in page.text(), 10), "Equipo still shows what it knew, and says it is offline")
    check(wait_for(lambda: page.js("[...document.querySelectorAll('button')].find((b) => b.innerText.trim() === 'Invitar').disabled"), 10),
          "changes are disabled while offline")
    check("Exception" not in page.text() and "Error:" not in page.text(), "no technical error names")
    calm_shot(page, "19-team-offline")


if __name__ == "__main__":
    main()
