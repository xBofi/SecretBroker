"""Personal vault features: password generator, health, import from other managers and export.

Pure checks of the modules first, then the same through the service (no GUI). All values are fake.
Run with:  .venv\\Scripts\\python.exe tests\\test_personal.py
"""

import json
import math
import os
import re
import sys
import tempfile
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="secretbroker-personal-"))
os.environ["SECRETBROKER_HOME"] = str(HOME)  # must be set before importing secretbroker
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secretbroker import client, exports, generator, health, importers, platform, totp, service as service_module  # noqa: E402
from secretbroker.client import BrokerError  # noqa: E402
from secretbroker.service import Service  # noqa: E402

FIXTURES = Path(__file__).with_name("fixtures")
MASTER = "correct horse battery staple"
PROOF = {"kind": "master_password", "value": MASTER}
failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


def expect_error(fn, code, label):
    try:
        fn()
        check(False, f"{label} (no error)")
    except BrokerError as exc:
        check(exc.code == code, f"{label} [{exc.code}]")


def call(op, params, proof=None):
    return client.request(op, dict(params, proof=proof) if proof else params)


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def check_generator():
    print("Generator")
    for length in (12, 20, 64, 128):
        value = generator.generate({"length": length})["value"]
        check(len(value) == length and re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)
              and re.search(r"\d", value) and any(c in generator.SYMBOLS for c in value),
              f"random of {length}: every class present")
    values = {generator.generate()["value"] for _ in range(200)}
    check(len(values) == 200, "200 passwords, no repeats")
    safe = generator.generate({"preset": "url_safe"})
    check(len(safe["value"]) == 32 and safe["value"].isalnum() and safe["bits"] >= 180, "url_safe: 32 letters and digits (database default)")
    clear = "".join(generator.generate({"length": 128, "avoid_ambiguous": True})["value"] for _ in range(20))
    check(not set(clear) & generator.AMBIGUOUS, "avoid_ambiguous leaves out Il1O0o")
    digits = generator.generate({"length": 16, "lower": False, "upper": False, "symbols": False})
    check(digits["value"].isdigit() and digits["bits"] == round(16 * math.log2(10)), "only digits, with honest bits")
    for bad in ({"length": 8}, {"length": 200}, {"lower": False, "upper": False, "digits": False, "symbols": False},
                {"mode": "passphrase", "words": 2}, {"separator": "x"}):
        try:
            generator.generate(bad)
            check(False, f"refuses {bad}")
        except generator.GeneratorError:
            check(True, f"refuses {bad}")
    phrase = generator.generate({"mode": "passphrase", "words": 6, "separator": ".", "capitalize": True, "number": True})
    words = phrase["value"].split(".")
    check(len(words) == 6 and all(w[0].isupper() for w in words) and sum(c.isdigit() for c in phrase["value"]) == 1,
          "passphrase: 6 capitalised words, one digit")
    check(all(re.sub(r"\d", "", w).lower() in generator.WORDS for w in words), "passphrase words come from the list")
    check(len(generator.WORDS) >= 800 and all(w.isascii() and w.isalpha() for w in generator.WORDS), "word list: 800+ ASCII words")
    plain = generator.generate({"mode": "passphrase", "words": 4, "separator": " ", "capitalize": False, "number": False})
    check(plain["value"] == plain["value"].lower() and len(plain["value"].split(" ")) == 4, "passphrase options are honoured")

    print("Strength")
    for weak in ("password", "P@ssw0rd", "Summer2024!", "qwerty123", "aaaaaaaaaaaaaaaa", "Barcelona1992", "123456"):
        check(generator.is_weak(weak), f"weak: {weak}")
    for strong in ("kR7#pQ2!vZ9mXw", generator.generate()["value"], generator.generate({"mode": "passphrase"})["value"]):
        check(not generator.is_weak(strong), "strong: a generated or random password")


def check_totp():
    print("TOTP (RFC 6238)")
    import base64
    # Appendix B of RFC 6238: the seed is "12345678901234567890" repeated to the hash's size, 8 digits.
    seeds = {"SHA1": b"1234567890" * 2, "SHA256": b"1234567890" * 3 + b"12", "SHA512": b"1234567890" * 6 + b"1234"}
    vectors = [(59, "94287082", "46119246", "90693936"), (1111111109, "07081804", "68084774", "25091201"),
               (1111111111, "14050471", "67062674", "99943326"), (1234567890, "89005924", "91819424", "93441116"),
               (2000000000, "69279037", "90698825", "38618901"), (20000000000, "65353130", "77737706", "47863826")]
    for moment, *codes in vectors:
        got = [totp.code(f"otpauth://totp/RFC:test?secret={base64.b32encode(seeds[a]).decode()}&algorithm={a}&digits=8", moment)["code"]
               for a in ("SHA1", "SHA256", "SHA512")]
        check(got == codes, f"T={moment}: {got}")
    plain = totp.code("jbsw y3dp ehpk 3pxp", 59)
    check(plain["digits"] == 6 and len(plain["code"]) == 6 and plain["period"] == 30 and plain["remaining"] == 1,
          "a bare base32 seed (spaces, lowercase): 6 digits every 30 s, and the seconds left")
    check(totp.parse("otpauth://totp/GitHub:ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")["account"] == "ana@example.com",
          "an otpauth URI's issuer and account")
    for bad in ("", "not base32!", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"):
        try:
            totp.parse(bad)
            check(False, f"refuses {bad!r}")
        except totp.TotpError:
            check(True, f"refuses {bad!r}")


def check_importers():
    print("Importers")
    expected = {"bitwarden.json": "bitwarden_json", "bitwarden.csv": "bitwarden_csv", "onepassword.csv": "onepassword_csv",
                "keepassxc.csv": "keepass_csv", "keepass2.csv": "keepass_csv", "chrome.csv": "chrome_csv", "firefox.csv": "firefox_csv"}
    parsed = {}
    for name, fmt in expected.items():
        detected, candidates, skipped = importers.parse(fixture(name), "auto", filename=name)
        parsed[name] = (candidates, skipped)
        check(detected == fmt, f"{name} detected as {fmt} ({detected})")

    bw, bw_skipped = parsed["bitwarden.json"]
    by_name = {c["name"]: c for c in bw}
    hosting = by_name["Panel Hosting"]
    check(hosting["template"] == "web_login" and hosting["fields"]["url"] == "https://panel.example.com/login"
          and hosting["fields"]["username"] == "ana@example.com" and hosting["fields"]["password"] == "fake-Hosting-pass-01",
          "Bitwarden login -> web login with url, user and password")
    check("Cuenta de la empresa" in hosting["fields"]["notes"] and "otpauth://" not in hosting["fields"]["notes"]
          and "PIN: fake-pin-4321" in hosting["fields"]["notes"] and hosting["tags"] == ["trabajo"],
          "notes and custom fields go to the private notes; the folder becomes a tag")
    check(hosting["fields"]["totp"].startswith("otpauth://totp/"), "a login's TOTP goes to its own 2FA field, not the notes")
    check(by_name["GitHub token"]["template"] == "api_key" and by_name["GitHub token"]["fields"]["base_url"] == "https://api.github.com",
          "an obvious API key (ghp_...) without user becomes a GitHub API key")
    check(by_name["Códigos de recuperación"]["template"] == "generic", "a secure note becomes a secret")
    check({s["reason"] for s in bw_skipped} == {"Las tarjetas no se importan", "No tiene contraseña"}, "cards and empty logins are skipped, with the reason")
    try:
        importers.parse(json.dumps({"encrypted": True, "items": []}))
        check(False, "an encrypted Bitwarden file is refused")
    except importers.ImportFileError as exc:
        check("sin cifrar" in str(exc), "an encrypted Bitwarden file is refused, saying how to export it")

    bwcsv = {c["name"]: c for c in parsed["bitwarden.csv"][0]}
    check(bwcsv["Correo"]["fields"]["username"] == "ana" and bwcsv["Correo"]["tags"] == ["personal"], "Bitwarden CSV login")
    check(bwcsv["Nota segura"]["template"] == "generic" and bwcsv["Nota segura"]["fields"]["value"].startswith("fake secret note"), "Bitwarden CSV note")
    one = {c["name"]: c for c in parsed["onepassword.csv"][0]}
    check(one["Banco"]["template"] == "web_login" and one["Banco"]["tags"] == ["finanzas"] and "Llamar" in one["Banco"]["fields"]["notes"],
          "1Password CSV login with tag and notes")
    check(one["Wifi casa"]["template"] == "generic" and one["Wifi casa"]["fields"]["value"] == "fake-wifi-04", "a password without user is a secret")
    kp = parsed["keepassxc.csv"][0][0]
    check(kp["name"] == "Router" and kp["fields"]["url"] == "http://192.168.1.1" and kp["tags"] == ["servidores"], "KeePassXC CSV with group")
    kp2 = parsed["keepass2.csv"][0][0]
    check(kp2["fields"]["username"] == "ana" and kp2["fields"]["url"] == "intranet.example.com" and "dominio" in kp2["fields"]["notes"],
          "KeePass 2 CSV columns")
    chrome = parsed["chrome.csv"][0]
    check(len(chrome) == 3 and chrome[2]["fields"].get("url") is None and "android://" in chrome[2]["fields"]["notes"],
          "Chrome CSV; an app address is kept in the notes, not as a web the AI may use")
    ff = parsed["firefox.csv"][0][0]
    check(ff["name"] == "forum.example.org" and ff["fields"]["username"] == "ana_f", "Firefox CSV, named after the site")
    try:
        importers.parse("OPENAI_API_KEY=sk-fake\nPORT=3000\n")
        check(False, "a .env is sent to sb import")
    except importers.ImportFileError as exc:
        check("sb import" in str(exc), "a .env is sent to sb import")

    one_totp = importers.parse('"Title","Url","Username","Password","OTPAuth","Tags","Notes"\n'
                               '"Correo","https://mail.example.com","ana","fake-Mail-pass-09","otpauth://totp/Mail:ana?secret=JBSWY3DPEHPK3PXP&issuer=Mail","",""\n'
                               '"Raro","https://odd.example.com","ana","fake-Odd-pass-10","no es un código","",""\n')[1]
    check(one_totp[0]["fields"]["totp"].startswith("otpauth://") and "notes" not in one_totp[0]["fields"],
          "1Password's OTPAuth column becomes the 2FA field")
    check("totp" not in one_totp[1]["fields"] and "no es un código" in one_totp[1]["fields"]["notes"],
          "a TOTP the app can't read stays in the private notes, so nothing is lost")
    kpx = importers.parse('"Group","Title","Username","Password","URL","Notes","TOTP"\n'
                          '"Root","VPN","ana","fake-Vpn-pass-11","https://vpn.example.com","","JBSW Y3DP EHPK 3PXP"\n'
                          '"Root/Dev","BD pedidos","app","fake-Db-pass-12","postgres://db.example.com:6543/orders","",""\n'
                          '"Root/Dev","Bastión","deploy","fake-Ssh-pass-13","ssh://bastion.example.com:2222","",""\n'
                          '"Root/Dev","Stripe API token","","sk_live_fakeFAKEfake0123456789","","",""\n'
                          '"Root","Netflix","ana","fake-Tv-pass-14","https://netflix.com","",""\n', "auto")[1]
    by = {c["name"]: c for c in kpx}
    check(by["VPN"]["fields"]["totp"] == "JBSW Y3DP EHPK 3PXP", "KeePassXC's TOTP column (a base32 seed) becomes the 2FA field")
    check(by["BD pedidos"]["template"] == "database" and by["BD pedidos"]["fields"]["engine"] == "postgresql"
          and by["BD pedidos"]["fields"]["port"] == "6543" and by["BD pedidos"]["fields"]["database"] == "orders",
          "a postgres:// address becomes a database")
    check(by["Bastión"]["template"] == "ssh" and by["Bastión"]["fields"]["port"] == "2222", "an ssh:// address becomes an SSH server")
    dev = {c["name"] for c in kpx if importers.is_dev(c)}
    check(dev == {"BD pedidos", "Bastión", "Stripe API token"}, f"the development keys filter: databases, SSH and API keys ({dev})")
    check(importers.is_dev(by_name["GitHub token"]) and not importers.is_dev(hosting), "a GitHub token is one; a web login is not")

    planned = importers.plan(chrome, [])
    check([p["status"] for p in planned] == ["new", "duplicate", "new"] and planned[1]["reason"] == "Repetida en el archivo",
          "a repeated row in the file is a duplicate")
    check(len({p["entry"]["id"] for p in planned}) == 3, "every planned entry gets its own id")
    existing = [{"id": "shop", "name": "Tienda", "template": "web_login",
                 "fields": {"url": "https://shop.example.com", "username": "ana", "password": "another-fake"}}]
    planned = importers.plan(chrome, existing)
    check(planned[0]["status"] == "conflict" and "Tienda" in planned[0]["reason"], "same site and user with another password: conflict")
    preview = json.dumps([importers.preview(p) for p in planned])
    check("fake-" not in preview and "shop.example.com" in preview, "the preview has names and sites, never values")


def check_exports():
    print("Export format")
    entries = [{"id": "a", "name": "A", "template": "web_login", "description": "", "policy": {"approval": "session"},
                "fields": {"url": "https://a.example.com", "username": "u", "password": "fake-A-pass", "notes": "fake note\n"}}]
    text = exports.build(entries, "encrypted", "una contraseña de archivo")
    doc = json.loads(text)
    check(doc["format"] == exports.ENCRYPTED_FORMAT and doc["kdf"]["name"] == "scrypt" and "fake-A-pass" not in text,
          "the encrypted export holds no plaintext")
    check(exports.decrypt(doc, "una contraseña de archivo")["entries"][0]["fields"]["password"] == "fake-A-pass", "and opens with its password")
    for label, mutate in (("a wrong password", lambda d: d), ("a changed header", lambda d: {**d, "kdf": {**d["kdf"], "n": 2**14}})):
        try:
            exports.decrypt(mutate(doc), "otra contraseña cualquiera" if label == "a wrong password" else "una contraseña de archivo")
            check(False, f"{label} is refused")
        except exports.ExportError:
            check(True, f"{label} is refused")
    try:
        exports.build(entries, "encrypted", "corta")
        check(False, "a short file password is refused")
    except exports.ExportError:
        check(True, "a short file password is refused")
    csv_text = exports.build(entries, "csv")
    check(csv_text.splitlines()[0] == "name,url,username,password,note" and "fake-A-pass" in csv_text, "CSV in Chrome's columns")
    _, candidates, _ = importers.parse(csv_text)
    check(candidates[0]["fields"]["password"] == "fake-A-pass", "and SecretBroker reads its own CSV back")


def check_service():
    print("Through the service")
    service = Service(HOME, owner=platform.default_owner(), isolated=False)
    service.start()
    try:
        client.request("create_vault", {"master_password": MASTER})
        presence = call("unlock", {}, PROOF)["presence"]
        one_click = {"kind": "presence", "token": presence}
        check("import_file" not in service_module.AI_OPS and "export_vault" not in service_module.AI_OPS
              and "health" not in service_module.AI_OPS, "import, export and health are not for the AI")

        params = {"content": fixture("bitwarden.json"), "source": "bitwarden.json"}
        expect_error(lambda: call("import_file", params), "proof_required", "importing needs the app that unlocked")
        preview = call("import_file", params, one_click)
        check(preview["format"] == "bitwarden_json" and len(preview["items"]) == 3 and len(preview["skipped"]) == 2,
              "preview: 3 to import, 2 skipped")
        check("fake-" not in json.dumps(preview), "the preview has no values")
        result = call("import_file", {**params, "selected": [i["key"] for i in preview["items"]]}, one_click)
        check(len(result["created"]) == 3 and not result["failed"], "imported with one click")
        entries = {e["name"]: e for e in client.request("entries")}
        hosting = entries["Panel Hosting"]
        check("notes" in hosting["secrets_set"] and "notes" not in hosting["fields"] and "fake" not in json.dumps(hosting),
              "the private notes are hidden like a secret")
        check(hosting["policy"]["http"]["allowed_hosts"] == ["panel.example.com"], "AI permissions come from the template")
        listing = json.dumps(client.request("list_secrets"))
        check("fake-pin" not in listing and "otpauth" not in listing, "the AI never sees the private notes")
        again = call("import_file", params, one_click)
        check(all(i["status"] == "duplicate" and not i["selected"] for i in again["items"]), "importing the same file again: all duplicates, unselected")

        print("2FA codes")
        check("totp" in hosting["secrets_set"] and "totp" not in hosting["fields"], "the 2FA seed is hidden like a secret")
        check("totp_code" not in service_module.AI_OPS, "the AI can't ask for 2FA codes")
        expect_error(lambda: call("totp_code", {"id": hosting["id"]}), "proof_required", "a 2FA code needs the app that unlocked")
        code = call("totp_code", {"id": hosting["id"]}, one_click)
        check(re.fullmatch(r"\d{6}", code["code"]) and 0 < code["remaining"] <= 30 and code["period"] == 30,
              f"one click: the current code and the seconds left ({code['remaining']} s)")
        check(code["code"] == totp.code("otpauth://totp/Example?secret=FAKEFAKEFAKE")["code"], "computed by the service from the seed")
        view = next(s for s in client.request("list_secrets") if s["id"] == hosting["id"])
        check("{{totp_code}}" not in view["placeholders"] and "FAKEFAKE" not in json.dumps(view), "by default the AI has no 2FA code")
        stored = next(e for e in client.request("entries") if e["id"] == hosting["id"])
        allowed = {k: stored[k] for k in ("id", "name", "template", "description", "tags")}
        allowed.update(fields={**stored["fields"], "password": None, "totp": None, "notes": None},
                       policy={**stored["policy"], "ai_totp": True})
        call("save_entry", {"entry": allowed, "replaces": hosting["id"]}, PROOF)
        view = next(s for s in client.request("list_secrets") if s["id"] == hosting["id"])
        check("{{totp_code}}" in view["placeholders"], "if the user allows it, the AI may type it as {{totp_code}}")
        bad = {**allowed, "fields": {**allowed["fields"], "totp": "esto no es base32!"}}
        expect_error(lambda: call("save_entry", {"entry": bad, "replaces": hosting["id"]}, PROOF), "invalid", "a seed that isn't valid is refused")

        print("Import in batches")
        rows = "".join(f'"Cuenta {n}","https://site{n}.example.com","user{n}","fake-Batch-pass-{n:04}","","",""\n' for n in range(250))
        rows += '"Rota","https://broken.example.com","user","fake-Broken-pass","","",""\n'
        big = '"Title","Url","Username","Password","OTPAuth","Tags","Notes"\n' + rows
        preview = call("import_file", {"content": big, "source": "big.csv"}, one_click)
        check(len(preview["items"]) == 251 and preview["import_id"], "a preview of 251 with an import id")
        keys = [i["key"] for i in preview["items"]]
        service.vault.put({"id": preview["items"][-1]["id"], "name": "Ocupa el sitio", "template": "generic",
                           "fields": {"value": "fake-taken"}, "policy": {"approval": "session"}})  # taken meanwhile
        saves = []
        original_save = service.vault._save
        service.vault._save = lambda: (saves.append(1), original_save())
        created, failed = [], []
        for start in range(0, len(keys), 100):
            part = call("import_file", {"import_id": preview["import_id"], "selected": keys[start:start + 100],
                                        "done": start + 100 >= len(keys)}, one_click)
            created += part["created"]
            failed += part["failed"]
        service.vault._save = original_save
        check(len(created) == 250 and len(failed) == 1 and "Ya existe" in failed[0]["reason"] and failed[0]["key"] == keys[-1],
              f"250 created, 1 failed with its reason ({len(created)}, {failed[:1]})")
        check(len(saves) == 3, f"the vault is saved once per batch, not once per credential ({len(saves)})")
        expect_error(lambda: call("import_file", {"import_id": preview["import_id"], "selected": [0]}, one_click), "expired",
                     "the plan is forgotten after the last batch")
        for entry in created:
            service.vault.delete(entry["id"])
        service.vault.delete(preview["items"][-1]["id"])

        print("AI clients")
        client.request("list_secrets", client="claude-code")
        client.request("list_secrets", client="Cursor")
        client.request("list_secrets", client="claude-code")
        client.request("entries", client="evil")  # not an AI request: not recorded
        client.request("list_secrets", client="bad\nname")
        clients = {c["name"]: c for c in client.request("ai_clients")}
        check(set(clients) == {"claude-code", "Cursor"} and clients["claude-code"]["requests"] == 2 and clients["claude-code"]["last"],
              "the service remembers which AI program made requests, and when")
        check("ai_clients" not in service_module.AI_OPS, "only the app reads that list")

        for name in ("chrome.csv", "firefox.csv", "onepassword.csv"):
            preview = call("import_file", {"content": fixture(name), "source": name}, one_click)
            call("import_file", {"content": fixture(name), "source": name,
                                 "selected": [i["key"] for i in preview["items"] if i["selected"]]}, one_click)
        names = [e["name"] for e in client.request("entries")]
        check(names.count("shop.example.com") == 1 and "forum.example.org" in names and "Banco" in names, "more files, without duplicates")

        print("Health")
        reused = {"id": "shop-copy", "name": "Tienda copia", "template": "web_login", "description": "",
                  "fields": {"url": "https://other.example.com", "username": "ana", "password": "fake-Shop-pass-06"},
                  "policy": {"approval": "session"}}
        call("save_entry", {"entry": reused}, PROOF)
        report = client.request("health")
        items = {i["name"]: {x["kind"] for x in i["issues"]} for i in report["items"]}
        check("weak" in items.get("forum.example.org", set()), "the forum's 123456 is weak")
        check("reused" in items.get("shop.example.com", set()) and "reused" in items.get("Tienda copia", set()),
              "a password used twice is reused, on both")
        check("Banco" not in items, "a good, unique password has no issues")
        check(0 <= report["score"] < 100 and report["total"] == len(client.request("entries")), f"a score ({report['score']})")
        check("fake-" not in json.dumps(report) and "123456" not in json.dumps(report), "the health report has no values")
        saved = call("replace_key", {"id": "shop-copy", "value": generator.generate()["value"]}, one_click)
        check(saved["entry"]["id"] == "shop-copy", "a web password is changed with one click (rotate with help)")
        report = client.request("health")
        check("Tienda copia" not in {i["name"] for i in report["items"]}, "and it is no longer reused")

        print("Export and restore")
        expect_error(lambda: call("export_vault", {"format": "encrypted", "password": "una contraseña larga"}), "proof_required",
                     "exporting needs the app that unlocked")
        expect_error(lambda: call("export_vault", {"format": "encrypted", "password": "corta"}, one_click), "invalid",
                     "a short file password is refused")
        exported = call("export_vault", {"format": "encrypted", "password": "una contraseña larga"}, one_click)
        check(exported["entries"] == len(client.request("entries")) and "fake-" not in exported["content"], "encrypted export")
        plain = call("export_vault", {"format": "json"}, one_click)
        check("fake-Bank-pass-03" in plain["content"], "plain JSON export (behind a warning in the app)")
        before = {e["id"]: call("reveal", {"id": e["id"], "field": e["secrets_set"][0]}, PROOF) for e in client.request("entries")}
        for entry_id in before:
            call("delete_entry", {"id": entry_id}, PROOF)
        check(client.request("entries") == [], "vault emptied")
        expect_error(lambda: call("import_file", {"content": exported["content"]}, one_click), "password_required", "an encrypted export asks for its password")
        expect_error(lambda: call("import_file", {"content": exported["content"], "password": "no es esta contraseña"}, one_click),
                     "wrong_password", "a wrong file password is refused")
        preview = call("import_file", {"content": exported["content"], "password": "una contraseña larga"}, one_click)
        call("import_file", {"content": exported["content"], "password": "una contraseña larga",
                             "selected": [i["key"] for i in preview["items"]]}, one_click)
        after = {e["id"]: call("reveal", {"id": e["id"], "field": e["secrets_set"][0]}, PROOF) for e in client.request("entries")}
        check(after == before, f"restored: the same {len(after)} credentials, ids and values")
    finally:
        service.stop()


def main():
    check_generator()
    check_totp()
    check_importers()
    check_exports()
    check_service()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (home: {HOME})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
