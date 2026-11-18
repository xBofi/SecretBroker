"""Screenshots of the real app with a demo vault, for the README, the website and the extension stores.

Starts a separate instance (its own SECRETBROKER_HOME, like tests/test_gui.py: the installed app and its vault are
never touched), creates a vault, saves a handful of made-up items a real person could have, and photographs the
main screens in the dark and the light theme through the DevTools Protocol.

    python tools/make_screenshots.py                 # Spanish and English, into docs/img/<language>/
    python tools/make_screenshots.py --lang es --out site/img

Needs a desktop session (Windows, or Linux with an X display) and the dev dependencies. Every value is fake.
"""

import argparse
import base64
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))

import gui_desktop as desktop  # noqa: E402
import test_gui as gui  # noqa: E402  (its Page drives the window; nothing of the suite runs on import)

MASTER = "una frase larga solo para las capturas"
SCALE = 2  # device pixels per CSS pixel: sharp on a website
SIZE = (1200, 760)

TEXT = {
    "es": {
        "mail": "marta@ejemplo.com", "tags": ("personal", "trabajo", "tienda"),
        "bank": "Banco", "router": "Wi-Fi de casa", "server": "Servidor de la tienda", "database": "Base de datos de la tienda",
        "card": "Visa de Marta", "passport": "Pasaporte", "note": "Alarma de casa", "license": "Affinity Designer",
        "openai": "Para el asistente de la tienda. Solo el proyecto «tienda».",
        "github": "Token de solo lectura de los repositorios de la tienda.",
        "stripe": "Clave restringida: solo leer pagos y clientes.",
        "ask": "Listar los pagos de esta semana",
    },
    "en": {
        "mail": "martha@example.com", "tags": ("personal", "work", "shop"),
        "bank": "Bank", "router": "Home Wi-Fi", "server": "Shop server", "database": "Shop database",
        "card": "Martha's Visa", "passport": "Passport", "note": "Home alarm", "license": "Affinity Designer",
        "openai": "For the shop's assistant. Only the “shop” project.",
        "github": "Read-only token for the shop's repositories.",
        "stripe": "Restricted key: read payments and customers only.",
        "ask": "List this week's payments",
    },
}


def demo_entries(text):
    """What the demo vault holds. Types the app doesn't have (an older checkout) are skipped."""
    personal, work, shop = text["tags"]
    mail = text["mail"]

    def login(ident, name, url, tags, totp=""):
        return {"id": ident, "name": name, "template": "web_login", "tags": tags,
                "fields": {"url": url, "username": mail, "password": f"demo-{ident}-Xk7!pQ2v", "totp": totp}}

    def api(ident, name, preset, description, key):
        from secretbroker import presets
        fields, description = presets.apply(preset, {"value": key}, description)
        host = fields["base_url"].split("/")[2]
        return {"id": ident, "name": name, "template": "api_key", "tags": [shop], "description": description, "fields": fields,
                "policy": {"approval": "session", "http": {"allowed_hosts": [host]}}}

    return [
        login("gmail", "Gmail", "https://mail.google.com", [personal], "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
        login("netflix", "Netflix", "https://www.netflix.com", [personal]),
        login("amazon", "Amazon", "https://www.amazon.es", [personal]),
        login("banco", text["bank"], "https://www.banco-ejemplo.es", [personal], "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"),
        login("figma", "Figma", "https://www.figma.com", [work]),
        login("canva", "Canva", "https://www.canva.com", [work]),
        login("shopify", "Shopify", "https://admin.shopify.com", [shop]),
        api("openai", "OpenAI", "openai", text["openai"], "clave-de-demostracion-openai"),
        api("github", "GitHub", "github", text["github"], "clave-de-demostracion-github"),
        api("stripe", "Stripe", "stripe", text["stripe"], "clave-de-demostracion-stripe"),
        {"id": "servidor", "name": text["server"], "template": "ssh", "tags": [shop],
         "fields": {"host": "203.0.113.10", "port": "22", "username": "deploy", "auth_method": "password", "password": "demo-ssh-9Lm!x2Qa"}},
        {"id": "postgres", "name": text["database"], "template": "database", "tags": [shop],
         "fields": {"engine": "postgresql", "host": "db.ejemplo.com", "port": "5432", "database": "tienda", "username": "tienda",
                    "password": "demo-pg-4Rt!z8Wc"}},
        {"id": "wifi", "name": text["router"], "template": "wifi", "tags": [personal],
         "fields": {"ssid": "Casa-5G", "password": "demo-wifi-violeta-42", "security": "wpa"}},
        {"id": "visa", "name": text["card"], "template": "card", "tags": [personal],
         "fields": {"holder": "MARTA GARCIA", "number": "4242424242424242", "expiry": "08/29", "cvv": "123", "brand": "Visa"}},
        {"id": "pasaporte", "name": text["passport"], "template": "identity", "tags": [personal],
         "fields": {"kind": "passport", "number": "XAB123456", "full_name": "Marta García", "country": "España", "expiry": "2031-05-14"}},
        {"id": "alarma", "name": text["note"], "template": "note", "tags": [personal], "fields": {"value": "Código 0000 (cámbialo)."}},
        {"id": "affinity", "name": text["license"], "template": "license", "tags": [work],
         "fields": {"product": "Affinity Designer 2", "key": "DEMO-0000-0000-0000", "registered_to": mail}},
    ]


class Shots:
    def __init__(self, page, folder):
        self.page, self.folder = page, folder
        folder.mkdir(parents=True, exist_ok=True)

    def take(self, name):
        """`name`-dark.png and `name`-light.png of what the window shows now."""
        for theme in ("dark", "light"):
            self.page.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": theme}])
            self.page.js("document.getElementById('toasts').replaceChildren()")
            self.page.settled()
            time.sleep(0.3)
            data = self.page.send("Page.captureScreenshot", format="png")["data"]
            (self.folder / f"{name}-{theme}.png").write_bytes(base64.b64decode(data))
        self.page.send("Emulation.setEmulatedMedia", features=[])
        print(f"  {name}", flush=True)


def close_dialogs(page):
    page.js("[...document.querySelectorAll('.overlay')].forEach((o) => o.dispatchEvent(new Event('dismiss')))")
    gui.wait_for(lambda: page.js("!document.querySelector('#modal-root > *')"), 3)


def photograph(lang, out):
    text = TEXT[lang]
    home = Path(tempfile.mkdtemp(prefix="secretbroker-shots-"))
    profile = home / "profile"
    profile.mkdir()
    (home / "user").mkdir()
    # Spanish while the vault is created (the setup is driven by its labels); the pictures switch language after.
    (home / "user" / "prefs.json").write_text(json.dumps({"auto_scan": False, "language": "es"}), encoding="utf-8")
    devtools, mcp_port = gui.free_port(), gui.free_port()
    env = {**os.environ, "SECRETBROKER_HOME": str(home), "SECRETBROKER_MCP_PORT": str(mcp_port),
           "SECRETBROKER_PROFILE": str(profile), **desktop.browser_env(devtools)}
    os.environ.update({k: env[k] for k in ("SECRETBROKER_HOME", "SECRETBROKER_MCP_PORT")})
    from secretbroker import client

    service = desktop.start(["-m", "secretbroker.service"], ROOT, env)
    app = None
    try:
        if not gui.wait_for(lambda: client.request("status", timeout=2), 30):
            raise SystemExit("the service did not start")
        app = desktop.start(["-m", "secretbroker.app"], ROOT, env)
        page = gui.Page(devtools)
        page.send("Emulation.setDeviceMetricsOverride", width=SIZE[0], height=SIZE[1], deviceScaleFactor=SCALE, mobile=False)
        shots = Shots(page, out / lang)
        print(f"{lang}: {out / lang}", flush=True)
        proof = json.dumps({"kind": "master_password", "value": MASTER})

        gui.wait_for(lambda: "Empezar" in page.text(), 30)
        page.js(f"applyLanguage({json.dumps(lang)}).then(() => renderSetup())")
        gui.wait_for(lambda: page.js("document.documentElement.lang") == lang, 10)
        shots.take("welcome")
        page.js("applyLanguage('es').then(() => renderSetup())")
        gui.wait_for(lambda: "Empezar" in page.text(), 10)

        page.click("Empezar")
        gui.wait_for(lambda: "Elige una contraseña maestra" in page.text(), 10)
        page.js(f"document.querySelectorAll('.auth input[type=password]').forEach((i) => {{ i.value = {json.dumps(MASTER)}; }})")
        page.click("Crear bóveda")
        gui.wait_for(lambda: "¿Cómo quieres abrirla cada día?" in page.text(), 20)
        page.js("document.querySelector('.choice input[value=master]').click()")
        page.click("Continuar")
        gui.wait_for(lambda: "Conecta tu IA" in page.text(), 20)
        page.click("Ahora no")
        gui.wait_for(lambda: "Credenciales" in page.text(), 20)
        page.js(f"api().call('unlock', {{}}, {proof})")

        saved = []
        for entry in demo_entries(text):
            result = page.js(f"api().call('save_entry', {{ entry: {json.dumps(entry)} }}, {proof})")
            if result and result.get("ok"):
                saved.append(entry["id"])
            else:
                print(f"  (not saved: {entry['id']}: {(result or {}).get('error')})", flush=True)
        page.js(f"applyLanguage({json.dumps(lang)}).then(() => loadEntries()).then(renderMain)")
        gui.wait_for(lambda: page.js("document.documentElement.lang") == lang and "Gmail" in page.text(), 15)

        def show(view, selected=None):
            page.js(f"state.view = {json.dumps(view)}; state.selected = {json.dumps(selected)}; renderMain()")
            time.sleep(0.6)

        show("credentials", "gmail")
        shots.take("vault")
        show("credentials", "openai")
        shots.take("api-key")
        for ident in ("visa", "wifi"):
            if ident in saved:
                show("credentials", ident)
                shots.take(ident)
                break

        page.js("openEditor()")
        gui.wait_for(lambda: page.js("!!document.querySelector('.modal')"), 5)
        shots.take("new-item")
        close_dialogs(page)

        page.js("openGenerator()")
        gui.wait_for(lambda: page.js("!!document.querySelector('.modal .gen-output')"), 5)
        shots.take("generator")
        close_dialogs(page)

        # The AI asks to use a key: the one-click approval. Denied afterwards, so nothing leaves this PC.
        request = threading.Thread(daemon=True, target=lambda: gui.mcp_call("Claude Code", "http_request", {
            "secret_id": "stripe", "url": "https://api.stripe.com/v1/charges?limit=10", "reason": text["ask"]}))
        show("credentials", "stripe")
        request.start()
        if gui.wait_for(lambda: page.js("!!document.querySelector('.modal .approval-explain, .modal .countdown')"), 20):
            shots.take("approval")
            page.click(page.js("t('show_approval.deny')"))
            request.join(20)
        else:
            print("  (no approval dialog)", flush=True)
        close_dialogs(page)

        show("credentials", "openai")
        if page.click(page.js("t('common.rotate_with_help')")):
            gui.wait_for(lambda: page.js("!!document.querySelector('.modal')"), 5)
            time.sleep(0.5)
            shots.take("rotate")
            close_dialogs(page)

        for view, name in (("access", "ai-access"), ("settings", "settings")):
            show(view)
            shots.take(name)
    finally:
        for process in (app, service):
            if process is not None and process.poll() is None:
                desktop.stop_tree(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lang", action="append", choices=sorted(TEXT), help="language (default: every one)")
    parser.add_argument("--out", default=str(ROOT / "docs" / "img"), help="folder (a subfolder per language)")
    args = parser.parse_args()
    languages = args.lang or sorted(TEXT)
    if len(languages) == 1:
        photograph(languages[0], Path(args.out).resolve())
        return
    # One process per language: each is an instance of its own (the app's paths are read once per process).
    import subprocess
    for lang in languages:
        subprocess.run([sys.executable, __file__, "--lang", lang, "--out", args.out], check=True)


if __name__ == "__main__":
    main()
