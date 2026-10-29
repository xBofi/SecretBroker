"""Exposure checks: copies found by the scanner, liveness, breaches, and their bookkeeping (no GUI, no network).

The scanner runs against a fake user profile in a temporary folder.
Run with:  .venv\\Scripts\\python.exe tests\\test_exposure.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(tempfile.mkdtemp(prefix="secretbroker-exposure-test-"))
PROFILE = ROOT / "profile"
for name in ("SECRETBROKER_HOME", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"):
    os.environ[name] = str({"SECRETBROKER_HOME": ROOT / "broker", "APPDATA": PROFILE / "AppData" / "Roaming",
                            "LOCALAPPDATA": PROFILE / "AppData" / "Local"}.get(name, PROFILE))

import httpx  # noqa: E402

from secretbroker import client, exposure, scanner  # noqa: E402
from secretbroker.client import BrokerError  # noqa: E402
from secretbroker.service import Service  # noqa: E402

MASTER = "correct horse battery staple"
PROOF = {"kind": "master_password", "value": MASTER}
LEAKED = "sk-proj-LEAKED-abcdefghijklmnop0123"
QUOTED = 'pa"ss\\word-with-quotes'
CLEAN = "sk-ant-CLEAN-zyxwvutsrqponm9876"
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
        check(exc.code == code, f"{label} [{exc.code}] {exc}")


def call(op, params, proof=None):
    return client.request(op, dict(params, proof=proof) if proof else params)


def api_entry(entry_id, value, base_url=""):
    return {"id": entry_id, "name": entry_id, "template": "api_key", "description": "",
            "fields": {"value": value, "base_url": base_url, "auth_style": "bearer"}, "policy": {"approval": "session"}}


def by_id(report):
    return {item["id"]: item for item in report["entries"]}


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


def make_profile():
    project = ROOT / "work" / "shop"
    (PROFILE / ".claude" / "projects" / "shop").mkdir(parents=True)
    # Claude Code stores the conversation as JSON: the key is there JSON-escaped.
    (PROFILE / ".claude" / "projects" / "shop" / "s1.jsonl").write_text(
        json.dumps({"message": f"usa esta clave: {LEAKED} y la contraseña {QUOTED}"}) + "\n", encoding="utf-8")
    (PROFILE / ".claude.json").write_text(json.dumps({"projects": {str(project): {}, str(PROFILE): {}}}), encoding="utf-8")
    (PROFILE / "AppData" / "Roaming").mkdir(parents=True)
    project.mkdir(parents=True)
    (project / "node_modules").mkdir()
    (project / "node_modules" / "dep.js").write_text(f"// {CLEAN}", encoding="utf-8")  # skipped folder
    (project / "app.py").write_text("print('hola')\n", encoding="utf-8")
    git(project, "init", "-q")
    (project / ".env").write_text(f"OPENAI_API_KEY={LEAKED}\n", encoding="utf-8")
    git(project, "add", ".env", "app.py")
    git(project, "commit", "-q", "-m", "oops")
    (project / ".env").write_text("OPENAI_API_KEY=\n", encoding="utf-8")
    git(project, "commit", "-q", "-am", "remove key")  # still in the history
    # A big file: the key straddles two read blocks.
    big = b"x" * (scanner.BLOCK_BYTES - 10) + LEAKED.encode() + b"y" * 100
    (project / "dump.txt").write_bytes(big)
    return project


def scan(session):
    run = scanner.Scan(session)
    run.run()
    check(run.progress["error"] is None, f"scan finished: {run.progress['files']} sent, {run.progress['skipped']} unchanged")
    return run


def main():
    project = make_profile()
    os.environ["SB_TEST_TOKEN"] = LEAKED
    service = Service(ROOT / "broker", owner=f"{os.environ.get('USERDOMAIN')}\\{os.environ.get('USERNAME')}", isolated=False)
    service.start()
    client.request("create_vault", {"master_password": MASTER})
    call("save_entry", {"entry": api_entry("leaky", LEAKED)}, PROOF)
    call("save_entry", {"entry": api_entry("clean", CLEAN)}, PROOF)
    call("save_entry", {"entry": {"id": "panel", "name": "Panel", "template": "web_login", "description": "",
                                  "fields": {"url": "https://panel.example.com", "username": "me", "password": QUOTED},
                                  "policy": {"approval": "session"}}}, PROOF)

    print("Needles")
    check(exposure.needles({"template": "generic", "fields": {"value": "short"}}) == set(), "values under 8 characters are not searched")
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nUNIQUEUNIQUE\n-----END OPENSSH PRIVATE KEY-----\n"
    ssh = {"template": "ssh", "fields": {"auth_method": "key", "private_key": key}}
    check(not any(n == b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ" for n in exposure.needles(ssh))
          and any(b"\r\n" in n for n in exposure.needles(ssh)), "private keys are matched whole, with either line ending")

    print("Sessions")
    expect_error(lambda: client.request("exposure_begin", {}), "proof_required", "a scan needs a proof or the unlock session")
    expect_error(lambda: client.request("exposure_scan", {"session": "made-up", "items": []}), "session_expired", "unknown session refused")
    client.request("lock")
    session = call("unlock", {}, PROOF)["exposure_session"]
    check(bool(session), "unlocking hands out a scan session")
    report = client.request("exposure_report")
    check(not report["details"] and all(item["level"] == "unknown" for item in report["entries"]), "nothing scanned yet: unknown")

    print("First scan")
    run = scan(session)
    session = run.session
    report = client.request("exposure_report", {"session": session})
    items = by_id(report)
    leaky = items["leaky"]
    places = {f["location"]: f["source"] for f in leaky["findings"]}
    check(leaky["level"] == "exposed", f"leaked key is exposed: {leaky['reasons'][0]['text']}")
    check(places.get(str(PROFILE / ".claude" / "projects" / "shop" / "s1.jsonl")) == "ai", "found JSON-escaped in an AI conversation")
    check(places.get(str(project / ".env")) is None, "the .env no longer has it")
    check(places.get(f"git:{project}") == "git", "found in the git history")
    check(places.get(str(project / "dump.txt")) == "project", "found across two read blocks")
    check(places.get("env:SB_TEST_TOKEN") == "env", "found in an environment variable")
    check(items["panel"]["level"] == "exposed" and items["panel"]["found"] == 1, "password with quotes found JSON-escaped")
    check(items["clean"]["level"] == "ok", "a key found nowhere (node_modules is skipped) is ok")
    summary = client.request("exposure_report")
    check(not summary["details"] and "findings" not in by_id(summary)["leaky"], "without a session the report hides where")
    check(by_id(summary)["leaky"]["level"] == "exposed", "... but still says it is exposed")
    events = client.request("audit", {"limit": 20})
    check(any(e["action"] == "exposure" and e["secret"] == "leaky" for e in events), "new findings are in the activity log")

    print("Incremental scan")
    (project / "dump.txt").unlink()
    run = scan(session)
    session = run.session
    variables = len(scanner.environment_variables())  # always sent: they are few and have no date
    check(run.progress["skipped"] >= 5 and run.progress["files"] <= variables + 1, "unchanged files are not sent again")
    leaky = by_id(client.request("exposure_report", {"session": session}))["leaky"]
    present = {f["location"] for f in leaky["findings"] if f["present"]}
    check(str(PROFILE / ".claude" / "projects" / "shop" / "s1.jsonl") in present, "findings in unchanged files are kept")
    check(str(project / "dump.txt") not in present and leaky["found_before"] == 1, "a deleted file counts as 'was exposed'")

    print("Rotation resets the history")
    before = client.request("entries")
    since = next(e for e in before if e["id"] == "leaky")["secret_since"]
    renamed = api_entry("leaky", None)
    renamed["name"] = "Leaky (renamed)"
    call("save_entry", {"entry": renamed, "replaces": "leaky"}, PROOF)
    after = next(e for e in client.request("entries") if e["id"] == "leaky")
    check(after["secret_since"] == since, "editing other fields keeps the secret's date")
    call("save_entry", {"entry": api_entry("leaky", "sk-proj-ROTATED-0000000000000000"), "replaces": "leaky"}, PROOF)
    leaky = by_id(client.request("exposure_report", {"session": session}))["leaky"]
    check(leaky["level"] == "unknown" and not leaky["findings"], "a new value starts with a clean record")

    print("Reveals")
    call("reveal", {"id": "clean", "field": "value"}, PROOF)
    check(by_id(client.request("exposure_report"))["clean"]["revealed"] == 1, "reveals are counted")

    print("Liveness and breaches")
    check(exposure.provider_for(api_entry("x", "sk-ant-abc"))[0] == "Anthropic", "provider from the key prefix")
    check(exposure.provider_for(api_entry("x", "sk-ant-abc", "https://llm.mycompany.com")) is None,
          "a key with its own API URL is never sent elsewhere")
    check(exposure.provider_for(api_entry("x", "abc123", "https://api.assemblyai.com/v2"))[0] == "AssemblyAI", "provider from the API URL")
    check(exposure.provider_for(api_entry("x", "sk-legacy-123")) is None, "ambiguous prefixes are not guessed")

    answers = {"status": 200}
    original_get = httpx.get

    def fake_get(url, headers=None, **kwargs):
        request = httpx.Request("GET", url)
        if "pwnedpasswords" in url:
            import hashlib
            suffix = hashlib.sha1(QUOTED.encode()).hexdigest().upper()[5:]
            return httpx.Response(200, text=f"0000000000000000000000000000000000A:3\r\n{suffix}:42\r\n", request=request)
        return httpx.Response(answers["status"], request=request)

    exposure.httpx.get = fake_get
    try:
        report = client.request("exposure_check")
        clean = by_id(report)["clean"]
        check(clean["alive"]["status"] == "ok" and clean["alive"]["provider"] == "Anthropic", "working key: ok")
        check(by_id(report)["panel"]["pwned"]["count"] == 42, "breached password counted (k-anonymity)")
        check(report["last_check"], "last check recorded")
        answers["status"] = 401
        clean = by_id(client.request("exposure_check", {"id": "clean"}))["clean"]
        check(clean["level"] == "exposed" and "dejado de funcionar" in clean["reasons"][0]["text"],
              "a key that stops working is flagged as probably revoked by the provider")
    finally:
        exposure.httpx.get = original_get

    print("Locking ends the session")
    client.request("lock")
    call("unlock", {}, PROOF)
    expect_error(lambda: client.request("exposure_scan", {"session": session, "items": []}), "session_expired",
                 "sessions do not survive a lock")

    service.stop()
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (root: {ROOT})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
