"""`sb`: run your own programs with credentials from the vault as environment variables.

    sb run -- npm run dev

The variables come from a `.secretbroker` file in the project (found in the current folder or a
parent), which names credentials but holds no values, so it can be committed:

    # VARIABLE = credential           the credential's own template for that variable, or {{value}}
    OPENAI_API_KEY = openai
    # VARIABLE = credential:field     a specific field or placeholder of the credential
    DATABASE_URL = shop-db:connection_url
    # credential                      every environment variable of the credential
    aws-prod

In production the same variables are set by the platform (GitHub Actions secrets, etc.), so the
program reads them the same way everywhere. No file with values is ever written. When the output is
not a terminal (for example when an AI agent started the program) it is redacted line by line.
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import client
from .client import BrokerError, BrokerUnavailable
from .inject import redaction_forms

CONFIG_NAME = ".secretbroker"
LINE_RE = re.compile(r"^(?:(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?(?P<secret>[a-z0-9][a-z0-9_.-]*)(?::(?P<field>[A-Za-z_][A-Za-z0-9_]*))?$")


class ConfigError(Exception):
    pass


def find_config(start):
    for directory in (start, *start.parents):
        candidate = directory / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def parse_config(text, source=CONFIG_NAME):
    items = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = LINE_RE.match(line)
        if not match:
            raise ConfigError(f"{source}:{number}: no se entiende «{raw.strip()}». "
                              "Usa VARIABLE = credencial, VARIABLE = credencial:dato o credencial")
        item = {"secret_id": match["secret"], "name": match["name"], "field": match["field"]}
        items.append({k: v for k, v in item.items() if v})
    if not items:
        raise ConfigError(f"{source} no define ninguna variable")
    return items


class _LineRedactor:
    def __init__(self, redact):
        self._forms = [(form.encode("utf-8"), f"[REDACTED:{secret_id}]".encode())
                       for secret_id, values in redact.items() for form in redaction_forms(values)]
        self._forms.sort(key=lambda pair: len(pair[0]), reverse=True)

    def __call__(self, data):
        for form, label in self._forms:
            data = data.replace(form, label)
        return data


def _pump(source, target, redact):
    for line in iter(source.readline, b""):
        target.write(redact(line))
        target.flush()
    source.close()


def run(argv, config_path=None):
    if not argv:
        raise ConfigError("Falta el programa: sb run -- npm run dev")
    path = Path(config_path) if config_path else find_config(Path.cwd())
    if path is None or not path.is_file():
        raise ConfigError(f"No hay ningún {CONFIG_NAME} en esta carpeta ni en las superiores")
    items = parse_config(path.read_text(encoding="utf-8"), path.name)

    command = subprocess.list2cmdline(argv)
    released = client.call("release_env", {"vars": items, "command": command, "cwd": str(Path.cwd())})
    env = dict(os.environ)
    env.update(released["env"])
    executable = shutil.which(argv[0]) or argv[0]

    # Ctrl+C reaches the child through the console; sb just waits for it to finish.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if sys.stdout.isatty() and sys.stderr.isatty():
        return subprocess.call([executable, *argv[1:]], env=env)

    redact = _LineRedactor(released["redact"])
    process = subprocess.Popen([executable, *argv[1:]], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pumps = [threading.Thread(target=_pump, args=(process.stdout, sys.stdout.buffer, redact), daemon=True),
             threading.Thread(target=_pump, args=(process.stderr, sys.stderr.buffer, redact), daemon=True)]
    for pump in pumps:
        pump.start()
    code = process.wait()
    for pump in pumps:
        pump.join()
    return code


def main(args=None):
    parser = argparse.ArgumentParser(prog="sb", description="Ejecuta programas con credenciales de SecretBroker.")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="Ejecuta un programa con las variables de .secretbroker",
                                     description="Ejemplo: sb run -- npm run dev")
    run_parser.add_argument("-f", "--file", help=f"Archivo de variables (por defecto, el {CONFIG_NAME} más cercano)")
    run_parser.add_argument("program", nargs=argparse.REMAINDER, help="Programa y argumentos, después de --")
    options = parser.parse_args(args)

    program = options.program[1:] if options.program[:1] == ["--"] else options.program
    try:
        sys.exit(run(program, options.file))
    except (ConfigError, BrokerError, BrokerUnavailable, OSError) as exc:
        print(f"sb: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
