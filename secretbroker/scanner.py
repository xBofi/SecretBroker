"""Look for copies of the vault's secrets in the user's own files.

Runs in the desktop app, as the user: the service account cannot read the user's profile. The app
never learns the secrets; it streams file contents to the service, which does the matching.
Files that have not changed since the last scan (and secrets that have not changed either) are not
sent again: the service keeps what it found in them.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import client

BLOCK_BYTES = 1024 * 1024
BATCH_BYTES = 2 * 1024 * 1024           # raw bytes per request (base64 keeps it under the service limit)
MAX_PROJECT_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES_PER_FOLDER = 50_000
CACHE_FILE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretBroker" / "scan_cache.json"
CREATE_NO_WINDOW = 0x08000000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", ".gradle", ".idea", ".vs", ".next", ".nuxt", ".turbo", ".parcel-cache",
    "site-packages", "bower_components", ".terraform",
}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".icns", ".webp", ".avif", ".tif", ".tiff", ".psd",
    ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".webm",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".whl", ".jar", ".war", ".nupkg",
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".pyc", ".pyo", ".class", ".o", ".obj", ".lib", ".a", ".pdb",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".docx", ".xlsx", ".pptx", ".msi", ".iso", ".bin",
}

# (source, base folder, glob) — relative to the home folder unless the base is absolute.
AI_FILES = [
    ("ai", ".claude/projects", "**/*.jsonl"), ("ai", ".claude", "history.jsonl"),
    ("ai", ".codex/sessions", "**/*.jsonl"), ("ai", ".codex/archived_sessions", "**/*.jsonl"),
    ("ai", ".codex", "history.jsonl"), ("ai", ".codex", "*.sqlite"), ("ai", ".codex", "*.sqlite-wal"),
]
CONFIG_FILES = [
    ".claude.json", ".claude/settings.json", ".claude/settings.local.json", ".claude/.credentials.json",
    ".codex/config.toml", ".codex/auth.json", ".cursor/mcp.json", ".aws/credentials", ".aws/config",
    ".npmrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".gitconfig",
    ".docker/config.json", ".kube/config", ".config/gh/hosts.yml",
]
APPDATA_CONFIG_FILES = [
    "Claude/claude_desktop_config.json", "Code/User/settings.json", "Code/User/mcp.json",
    "Cursor/User/settings.json", "GitHub CLI/hosts.yml",
]
HISTORY_FILES = [
    ".bash_history", ".zsh_history", ".python_history", ".psql_history", ".node_repl_history",
    ".mysql_history", ".sqlite_history",
]


class ScanCancelled(Exception):
    pass


# --------------------------------------------------------------------------- what to scan


def _home():
    return Path.home()


def _appdata():
    return Path(os.environ.get("APPDATA", _home() / "AppData" / "Roaming"))


def project_folders(extra=()):
    """Folders where Claude Code has worked, plus the ones the user added. The home folder itself
    (and anything above it) is left out: it would mean scanning the whole profile."""
    home = _home().resolve()
    candidates = []
    try:
        config = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
        candidates += list((config.get("projects") or {}).keys())
    except (OSError, ValueError):
        pass
    candidates += list(extra)
    folders = []
    for candidate in candidates:
        try:
            path = Path(candidate).resolve()
        except (OSError, ValueError):
            continue
        if not path.is_dir() or path == home or path in home.parents or (home / "AppData") in (path, *path.parents):
            continue
        folders.append(path)
    # Nested folders are scanned with their parent.
    folders = sorted(set(folders), key=lambda p: len(p.parts))
    return [f for i, f in enumerate(folders) if not any(p in f.parents for p in folders[:i])]


def _glob(base, pattern):
    base = Path(base)
    if not base.is_dir():
        return []
    return sorted(p for p in base.glob(pattern) if p.is_file())


def fixed_files():
    """(source, path) of the AI conversations, settings and shell histories."""
    home, appdata = _home(), _appdata()
    files = []
    for source, base, pattern in AI_FILES:
        files += [(source, p) for p in _glob(home / base, pattern)]
    files += [("config", home / name) for name in CONFIG_FILES]
    files += [("config", appdata / name) for name in APPDATA_CONFIG_FILES]
    files += [("config", p) for p in _glob(home / ".ssh", "*")]
    files += [("history", p) for p in _glob(appdata / "Microsoft/Windows/PowerShell/PSReadLine", "*_history.txt")]
    files += [("history", home / name) for name in HISTORY_FILES]
    return [(source, path) for source, path in files if path.is_file()]


def walk_folder(folder):
    """Text files of a project folder, and the git repositories found in it."""
    files, repos = [], []
    for root, dirs, names in os.walk(folder):
        if ".git" in dirs or ".git" in names:
            repos.append(Path(root))
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".venv")]
        for name in names:
            path = Path(root) / name
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > MAX_PROJECT_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= MAX_FILES_PER_FOLDER:
                return files, repos
    return files, repos


def environment_variables():
    """The user's environment, as saved in Windows and as this process sees it."""
    values = dict(os.environ)
    if sys.platform == "win32":
        import winreg
        for hive, key in ((winreg.HKEY_CURRENT_USER, "Environment"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            try:
                with winreg.OpenKey(hive, key) as handle:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(handle, index)
                        except OSError:
                            break
                        values.setdefault(name, str(value))
                        index += 1
            except OSError:
                pass
    return values


def _git(repo, *args):
    git = shutil.which("git")
    if not git:
        return None
    return subprocess.Popen([git, "-C", str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0)


def _git_refs(repo):
    """Changes whenever a commit, branch or stash is added: the history must be read again."""
    process = _git(repo, "for-each-ref", "--format=%(objectname) %(refname)")
    if not process:
        return None
    output, _ = process.communicate(timeout=60)
    return hashlib.sha256(output).hexdigest() if process.returncode == 0 and output else None


# --------------------------------------------------------------------------- the scan


class Scan:
    """One scan. `progress` is a dict the app shows; `cancel` stops it from another thread."""

    def __init__(self, session, extra_folders=(), on_session=None):
        self.session = session
        self.on_session = on_session  # the service renews the session when a scan begins
        self.extra_folders = list(extra_folders)
        self.progress = {"running": True, "phase": "Preparando", "files": 0, "bytes": 0, "found": 0,
                         "skipped": 0, "error": None, "report": None}
        self.cancelled = False
        self._batch, self._batch_bytes = [], 0
        self._overlap = 1024

    def run(self):
        try:
            begin = client.request("exposure_begin", {"session": self.session})
            self.session = begin["session"]
            if self.on_session:
                self.on_session(self.session)
            self._overlap = begin["max_needle"]
            cache = _load_cache()
            stamps = cache.get("stamps", {}) if cache.get("fingerprint") == begin["fingerprint"] else {}
            new_stamps, unchanged = {}, []

            def visit(source, location, stamp, chunks):
                if self.cancelled:
                    raise ScanCancelled()
                if stamp is not None and stamps.get(location) == stamp:
                    unchanged.append(location)
                    new_stamps[location] = stamp
                    self.progress["skipped"] += 1
                    return
                for chunk in chunks():
                    self._add(source, location, chunk)
                self.progress["files"] += 1
                if stamp is not None:
                    new_stamps[location] = stamp

            self.progress["phase"] = "Conversaciones con IA, ajustes e historiales"
            for source, path in fixed_files():
                visit(source, str(path), _stamp(path), lambda p=path: self._read_file(p))

            self.progress["phase"] = "Variables de entorno"
            for name, value in environment_variables().items():
                visit("env", f"env:{name}", None, lambda v=value: [v.encode("utf-8", errors="replace")])

            repos = []
            for folder in project_folders(self.extra_folders):
                self.progress["phase"] = f"Proyecto {folder.name}"
                files, found = walk_folder(folder)
                repos += found
                for path in files:
                    visit("project", str(path), _stamp(path), lambda p=path: self._read_file(p, text_only=True))

            for repo in repos:
                self.progress["phase"] = f"Historial de git de {repo.name}"
                refs = _git_refs(repo)
                if refs:
                    visit("git", f"git:{repo}", refs, lambda r=repo: self._read_git(r))

            self._flush()
            self.progress["phase"] = "Guardando"
            report = client.request("exposure_finish", {"session": self.session, "unchanged": unchanged})
            _save_cache({"fingerprint": begin["fingerprint"], "stamps": new_stamps, "finished": time.time()})
            self.progress["report"] = report
        except ScanCancelled:
            self.progress["error"] = "Análisis cancelado"
        except client.BrokerError as exc:
            self.progress["error"] = str(exc)
            self.progress["code"] = exc.code
        except client.BrokerUnavailable as exc:
            self.progress["error"] = str(exc)
        finally:
            self.progress["running"] = False
            self.progress["phase"] = None

    # ----- reading

    def _read_file(self, path, text_only=False):
        """The file in blocks that overlap, so a secret split between two blocks is still seen."""
        try:
            with open(path, "rb") as handle:
                tail = b""
                first = True
                while True:
                    block = handle.read(BLOCK_BYTES)
                    if not block:
                        return
                    if first and text_only and b"\0" in block[:8192]:
                        return  # binary
                    first = False
                    yield tail + block
                    tail = block[-self._overlap:]
        except OSError:
            return  # locked or deleted meanwhile

    def _read_git(self, repo):
        """Every change ever committed, in every branch and stash."""
        process = _git(repo, "log", "-p", "--all", "--no-color", "--no-ext-diff", "--no-textconv")
        if not process:
            return
        try:
            tail = b""
            while True:
                block = process.stdout.read(BLOCK_BYTES)
                if not block:
                    break
                yield tail + block
                tail = block[-self._overlap:]
        finally:
            process.kill()
            process.wait()

    # ----- sending

    def _add(self, source, location, data):
        if self._batch_bytes + len(data) > BATCH_BYTES:
            self._flush()
        self._batch.append({"source": source, "location": location, "data": base64.b64encode(data).decode("ascii")})
        self._batch_bytes += len(data)
        self.progress["bytes"] += len(data)

    def _flush(self):
        if not self._batch:
            return
        result = client.request("exposure_scan", {"session": self.session, "items": self._batch})
        self.progress["found"] += result["found"]
        self._batch, self._batch_bytes = [], 0


def _stamp(path):
    try:
        stat = path.stat()
        return f"{stat.st_size}:{stat.st_mtime_ns}"
    except OSError:
        return None


def _load_cache():
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache), encoding="utf-8")
    os.replace(tmp, CACHE_FILE)


def last_finished():
    return _load_cache().get("finished")
