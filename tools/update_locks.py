"""Refresh (or check) the hash-pinned dependency locks in requirements/.

    python tools/update_locks.py            # relock after changing a dependency in pyproject.toml or server/
    python tools/update_locks.py --upgrade  # move every lock to the newest allowed versions
    python tools/update_locks.py --check    # CI: fail if a lock no longer matches what it is compiled from

Every Python package that CI and the release workflow install comes from one of these files, with its exact
version and the SHA-256 of every wheel (and sdist) on PyPI, installed with `pip install --require-hashes --no-deps`.
A new upload to PyPI, even under a pinned version, is refused unless its hash is in the lock. One lock serves every
system (`uv pip compile --universal`): platform-only packages (winrt and pywin32 on Windows, PyQt6 and secretstorage
on Linux, pyobjc on macOS) carry environment markers, and pip skips the lines whose marker does not match.

  app.txt     the app's runtime dependencies (pyproject.toml): what the installers bundle
  build.txt   the build backend (setuptools), installed first so that builds run with --no-build-isolation
              and never fetch an unpinned backend (SecretBroker itself and proxy-tools, which has no wheel)
  dev.txt     app + the `dev` extra + the server + build.txt: the environment the suites run in
  server.txt  the server's dependencies (server/pyproject.toml) and httpx for its tests
  sign.txt    cryptography alone: the release job that holds UPDATE_SIGNING_KEY installs nothing else
  tools.txt   uv, for `--check` in CI

requirements/constraints.txt applies to all of them (what one platform needs differently). The shared packages
have the same versions in every lock: dev, server and sign are compiled with app.txt as a constraint.

Needs uv (https://docs.astral.sh/uv/; `pip install --require-hashes -r requirements/tools.txt`). The locks target
CPython 3.12, the version every job and installer uses.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQ = "requirements"
PYTHON_VERSION = "3.12"

# Output -> what it is compiled from. "{app.txt}" is replaced by that lock's path (the temporary one in --check).
LOCKS = {
    "app.txt": ["pyproject.toml"],
    "build.txt": [f"{REQ}/build.in"],
    "dev.txt": ["pyproject.toml", "server/pyproject.toml", f"{REQ}/build.in", "--extra", "dev", "-c", "{app.txt}"],
    "server.txt": ["server/pyproject.toml", f"{REQ}/server-test.in", "-c", "{app.txt}"],
    "sign.txt": [f"{REQ}/sign.in", "-c", "{app.txt}"],
    "tools.txt": [f"{REQ}/tools.in"],
}

REQUIREMENT_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*==\S+)(?:\s*;\s*(.*?))?\s*\\?$")


def uv():
    found = shutil.which("uv")
    if found:
        return [found]
    try:
        subprocess.run([sys.executable, "-m", "uv", "--version"], check=True, capture_output=True)
        return [sys.executable, "-m", "uv"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("uv no está instalado: pip install --require-hashes -r requirements/tools.txt")


def compile_lock(name, out_dir, upgrade):
    args = [a.replace("{app.txt}", str(out_dir / "app.txt")) for a in LOCKS[name]]
    command = uv() + ["pip", "compile", "--universal", "--python-version", PYTHON_VERSION, "--generate-hashes",
                      "--quiet", "--custom-compile-command", "python tools/update_locks.py",
                      "-c", f"{REQ}/constraints.txt", *args, "-o", str(out_dir / name)]
    if upgrade:
        command.append("--upgrade")
    env = dict(os.environ, UV_NO_CONFIG="1")
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        sys.exit(f"uv pip compile falló para {REQ}/{name}")


def pins(path):
    """The `name==version ; marker` lines of a lock, without hashes or comments."""
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT_LINE.match(line.strip())
        if match:
            found.add(match.group(1).lower() + (f" ; {match.group(2)}" if match.group(2) else ""))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="fail if a lock is out of date (nothing is written)")
    group.add_argument("--upgrade", action="store_true", help="relock with the newest allowed versions")
    options = parser.parse_args()

    if not options.check:
        for name in LOCKS:  # app.txt first: the others are constrained by it
            compile_lock(name, ROOT / REQ, options.upgrade)
            print(f"{REQ}/{name}: {len(pins(ROOT / REQ / name))} paquetes")
        return

    # Recompile into copies of the current locks: uv keeps the versions already in an output file when they still
    # satisfy the inputs, so a lock only changes if pyproject.toml (or an .in file) asks for something it lacks.
    # Only the pins are compared: PyPI may add a wheel to a pinned version, which would change the hash list.
    stale = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in LOCKS:
            current = ROOT / REQ / name
            if not current.exists():
                stale.append(f"{REQ}/{name} no existe")
                continue
            shutil.copyfile(current, tmp / name)
            compile_lock(name, tmp, upgrade=False)
            before, after = pins(current), pins(tmp / name)
            if before != after:
                stale.append(f"{REQ}/{name}:\n" + "".join(f"  - {p}\n" for p in sorted(before - after))
                             + "".join(f"  + {p}\n" for p in sorted(after - before)))
            else:
                print(f"ok {REQ}/{name}")
    if stale:
        print("\nLos locks no coinciden con pyproject.toml. Ejecuta: python tools/update_locks.py\n", file=sys.stderr)
        print("\n".join(stale), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
