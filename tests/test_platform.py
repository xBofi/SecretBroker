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

if platform.NAME != "macos":
    blob = platform.protect_for_user(b"session-token", b"session/v1")
    check(platform.unprotect_for_user(blob, b"session/v1") == b"session-token", "user key: round trip")

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

print()
if failures:
    print(f"{len(failures)} FAILED")
    sys.exit(1)
print("all platform checks passed")
