"""Signed automatic updates of a server installed with install-server.sh (systemd, /opt/secretbroker-server).

Run daily as root by secretbroker-server-update.timer:

    /opt/secretbroker-server/current/python/bin/python3 -I -m secretbroker_server.updater

1. asks the release source (GitHub's /releases/latest) for the newest server artifact,
   secretbroker-server-<version>-linux-<arch>.tar.gz, and its .sig;
2. ignores anything not newer than what runs (never a downgrade);
3. downloads both and verifies the Ed25519 signature over SIGNED_PREFIX + version + NUL + SHA-256(artifact) with
   the release key built in below (the same key and message as the desktop updater, secretbroker/update.py) BEFORE
   anything is unpacked: an unsigned or wrongly signed artifact is never used;
4. backs up the database (secretbroker-server-backup.service), unpacks the new version next to the current one,
   points /opt/secretbroker-server/current at it and restarts the server;
5. checks /api/v1/health and that /api/v1/info reports the new version; if not within a minute, it rolls back:
   the previous version, the database from the backup of step 4, and remembers the failed version so it is not
   tried again until a newer one appears.

Off when the server admin turned automatic updates off (the app's setting in SB_DATA_DIR/settings.json, else
SB_AUTO_UPDATE in /etc/secretbroker-server/server.env); it still checks, so the app can say an update exists.
After every run it writes its result to SB_UPDATE_STATUS (/var/lib/secretbroker-updater/status.json), which the
server reads for GET /api/v1/admin/overview. Only root writes that folder.

Signatures need `cryptography`, which the server archive bundles (requirements/sign.txt, tools/build_server.sh); the
server itself does not import this module, so the Docker image doesn't carry it.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, config

REPO = "xBofi/SecretBroker"
LATEST_API = f"https://api.github.com/repos/{REPO}/releases/latest"
# base64 raw Ed25519; the same key as secretbroker/update.py (the private half is the UPDATE_SIGNING_KEY secret).
PUBLIC_KEY = "Y54EWQu13b79ilylP/cAvqFDvzxjkwiYkEq/puedHos="
SIGNED_PREFIX = b"SecretBroker release\0"
ARTIFACT_RE = re.compile(r"^secretbroker-server-(\d{1,6}\.\d{1,6}\.\d{1,6})-linux-(x86_64|aarch64)\.tar\.gz$")
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
TIMEOUT = 60
HEALTH_SECONDS = 60

ROOT = Path("/opt/secretbroker-server")
SERVICE = "secretbroker-server.service"
BACKUP_SERVICE = "secretbroker-server-backup.service"
SERVICE_USER = "secretbroker-server"
UNITS_DIR = Path("/etc/systemd/system")
STATUS_FILE = "/var/lib/secretbroker-updater/status.json"


class UpdateError(Exception):
    pass


class Refused(UpdateError):
    """The artifact or its signature is not acceptable: nothing of it was used."""


def parse_version(text):
    match = re.fullmatch(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})", str(text or "").strip())
    return tuple(int(n) for n in match.groups()) if match else None


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------- signatures

def signed_message(version, digest):
    return SIGNED_PREFIX + version.encode() + b"\0" + digest


def sign(private_key_b64, version, data):
    """For tests and the release workflow's checks; the release itself is signed by tools/sign_release.py."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(key.sign(signed_message(version, hashlib.sha256(data).digest()))).decode()


def verify(version, data, signature_b64, keys=(PUBLIC_KEY,)):
    """Raises Refused unless one of `keys` signed exactly this version and these bytes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        signature = base64.b64decode((signature_b64 or "").strip(), validate=True)
    except ValueError:
        raise Refused("the signature is not base64") from None
    message = signed_message(version, hashlib.sha256(data).digest())
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            continue
    raise Refused(f"the signature of {version} does not verify with the release key")


def trusted_keys(env=None):
    """The release key, plus SB_UPDATE_TRUST (comma-separated base64 keys, in the root-only server.env): for a fork
    that signs its own releases, and for the CI test of this updater."""
    env = os.environ if env is None else env
    extra = [k.strip() for k in env.get("SB_UPDATE_TRUST", "").split(",") if k.strip()]
    return [PUBLIC_KEY] + extra


# ---------------------------------------------------------------------- release sources

class Release:
    def __init__(self, version, name, fetch_artifact, fetch_signature):
        self.version, self.name = version, name
        self.fetch_artifact, self.fetch_signature = fetch_artifact, fetch_signature


def _allowed(url):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    return parts.scheme == "https" and (host in ("github.com", "api.github.com")
                                        or host.endswith(".githubusercontent.com"))


class _OnlyGithub(urllib.request.HTTPRedirectHandler):
    """GitHub answers downloads with a redirect to its storage host: follow it only there."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed(newurl):
            raise UpdateError(f"a download redirected to a site that is not GitHub ({urllib.parse.urlsplit(newurl).hostname})")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, limit, accept="application/octet-stream"):
    if not _allowed(url):
        raise UpdateError(f"not a GitHub address: {url}")
    opener = urllib.request.build_opener(_OnlyGithub())
    request = urllib.request.Request(url, headers={"User-Agent": "SecretBroker-Server-Updater", "Accept": accept})
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"GitHub answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"GitHub could not be reached ({exc})") from None
    if len(data) > limit:
        raise Refused("the download is too big")
    return data


class GithubSource:
    def __init__(self, api=LATEST_API):
        self.api = api

    def latest(self, arch):
        release = json.loads(_get(self.api, 4 * 1024 * 1024, "application/vnd.github+json"))
        assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets", [])}
        found = []
        for name, url in assets.items():
            match = ARTIFACT_RE.match(name or "")
            if match and match[2] == arch and assets.get(name + ".sig"):
                found.append((parse_version(match[1]), match[1], name, url, assets[name + ".sig"]))
        if not found:
            return None
        _, version, name, url, sig = max(found)
        return Release(version, name, lambda: _get(url, MAX_ARTIFACT_BYTES),
                       lambda: _get(sig, 4096).decode("ascii", errors="replace"))


class DirSource:
    """A folder with artifacts and their .sig (tests; an offline server fed by hand). Same signature rules."""

    def __init__(self, path):
        self.path = Path(path)

    def latest(self, arch):
        found = []
        for path in self.path.glob("secretbroker-server-*.tar.gz"):
            match = ARTIFACT_RE.match(path.name)
            if match and match[2] == arch:
                found.append((parse_version(match[1]), match[1], path))
        if not found:
            return None
        _, version, path = max(found)
        sig = path.with_name(path.name + ".sig")

        def signature():
            if not sig.exists():
                raise Refused(f"{path.name} has no signature")
            return sig.read_text(encoding="ascii", errors="replace")

        def artifact():
            if path.stat().st_size > MAX_ARTIFACT_BYTES:
                raise Refused("the artifact is too big")
            return path.read_bytes()
        return Release(version, path.name, artifact, signature)


def source_from(spec):
    spec = (spec or "").strip()
    if not spec or spec == "github":
        return GithubSource()
    if spec.startswith("file://"):
        return DirSource(urllib.parse.urlsplit(spec).path)
    if spec.startswith("https://"):
        return GithubSource(spec)
    return DirSource(spec)


# ---------------------------------------------------------------------- the installed versions

class Layout:
    """/opt/secretbroker-server: versions/<v>/ (each a whole server: python/, systemd/, bin/, VERSION) and the
    links `current` and `previous`."""

    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.versions = self.root / "versions"
        self.current = self.root / "current"
        self.previous = self.root / "previous"

    def version_of(self, link):
        try:
            return (link / "VERSION").read_text(encoding="ascii").strip()
        except OSError:
            return None

    def current_version(self):
        return self.version_of(self.current)

    def point(self, link, target):
        """Re-point a link atomically (a new link renamed over the old one)."""
        tmp = link.with_name(link.name + ".new")
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(os.path.relpath(target, link.parent), tmp, target_is_directory=True)
        if os.name == "nt" and link.is_symlink():  # Windows can't rename over a link (only the tests run there)
            os.rmdir(link)
        os.replace(tmp, link)

    def unpack(self, version, data):
        """Unpack a verified artifact into versions/<version>, checking it is what its name says."""
        self.versions.mkdir(parents=True, exist_ok=True)
        final = self.versions / version
        tmp = self.versions / f".unpack-{version}"
        for old in (tmp, final):
            if old.exists() and old.resolve() != self.current.resolve():
                shutil.rmtree(old)
        tmp.mkdir()
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                archive.extractall(tmp, filter="data")
            if (tmp / "VERSION").read_text(encoding="ascii").strip() != version:
                raise Refused("the artifact's VERSION is not the signed version")
            if not (tmp / "python" / "bin" / "python3").exists():
                raise Refused("the artifact has no Python")
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        return final

    def prune(self):
        """Keep the current and the previous version."""
        keep = {p.resolve() for p in (self.current, self.previous) if p.exists()}
        for path in self.versions.iterdir() if self.versions.exists() else ():
            if path.resolve() not in keep:
                shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------- the system around it

class Systemd:
    """The real system: the service, its backup, its health, its units."""

    def __init__(self, settings, port):
        self.settings, self.port = settings, port

    def _systemctl(self, *args):
        subprocess.run(["systemctl", *args], check=True, timeout=300)

    def backup(self):
        before = {p.name for p in self.settings.backups_path.glob("secretbroker-backup-*.zip")}
        self._systemctl("start", BACKUP_SERVICE)
        made = sorted(p for p in self.settings.backups_path.glob("secretbroker-backup-*.zip") if p.name not in before)
        if not made:
            raise UpdateError("the backup before updating did not write a file")
        return made[-1]

    def stop(self):
        self._systemctl("stop", SERVICE)

    def start(self):
        self._systemctl("start", SERVICE)

    def restart(self):
        self._systemctl("restart", SERVICE)

    def healthy(self, version, seconds=HEALTH_SECONDS):
        return wait_healthy(f"http://127.0.0.1:{self.port}", version, seconds)

    def restore(self, backup_file, version_dir):
        """Put the backup back, with that version's code, as the server's own account (the files stay its own)."""
        import pwd
        account = pwd.getpwnam(SERVICE_USER)
        subprocess.run([str(version_dir / "python" / "bin" / "python3"), "-I", "-m", "secretbroker_server", "restore",
                        str(backup_file)], check=True, timeout=600, user=account.pw_uid, group=account.pw_gid,
                       extra_groups=[], cwd="/")

    def install_units(self, version_dir):
        """The units that came with this version, where systemd reads them (only if they changed)."""
        changed = False
        for unit in sorted((version_dir / "systemd").glob("secretbroker-server*")):
            target = UNITS_DIR / unit.name
            data = unit.read_bytes()
            if not target.exists() or target.read_bytes() != data:
                tmp = target.with_name(target.name + ".new")
                tmp.write_bytes(data)
                os.chmod(tmp, 0o644)
                os.replace(tmp, target)
                changed = True
        if changed:
            self._systemctl("daemon-reload")


def wait_healthy(base, version, seconds):
    """True once /health says ok and /info says `version`."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/v1/health", timeout=5) as response:
                ok = response.status == 200 and json.loads(response.read()).get("status") == "ok"
            with urllib.request.urlopen(base + "/api/v1/info", timeout=5) as response:
                running = json.loads(response.read()).get("version")
            if ok and running == version:
                return True
        except (OSError, ValueError):
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------- one run

def read_status(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_status(path, status):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(status, handle, indent=1, sort_keys=True)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def run(source, layout, system, keys, status_path, arch, auto=True, force=False, log=print):
    """One check (and, when there is something newer and updates are on, one update). Returns the status written."""
    status = read_status(status_path)
    current = layout.current_version() or __version__
    result = {"current": current, "latest": status.get("latest"), "last_check": now_iso(), "auto": auto,
              "failed_version": status.get("failed_version"), "last_update": status.get("last_update")}

    def finish(outcome, detail=""):
        result.update(last_result=outcome, detail=detail)
        write_status(status_path, result)
        log(f"{outcome}: {detail}" if detail else outcome)
        return result

    try:
        release = source.latest(arch)
    except (UpdateError, OSError, ValueError, KeyError) as exc:
        return finish("error", f"could not check for updates: {exc}")
    if release is None:
        return finish("up_to_date", f"no server artifact for {arch} in the latest release")
    result["latest"] = release.version
    if parse_version(release.version) <= parse_version(current):
        return finish("up_to_date", f"{current} is the newest")
    if not auto:
        return finish("disabled", f"{release.version} is available; automatic updates are off")
    if release.version == status.get("failed_version") and not force:
        return finish("skipped", f"{release.version} failed its health check before; waiting for a newer one")

    try:
        signature = release.fetch_signature()
        data = release.fetch_artifact()
        verify(release.version, data, signature, keys)
    except Refused as exc:
        return finish("refused", str(exc))
    except (UpdateError, OSError) as exc:
        return finish("error", f"download failed: {exc}")

    old_dir = layout.current.resolve() if layout.current.exists() else None
    old_previous = layout.previous.resolve() if layout.previous.exists() else None
    try:
        new_dir = layout.unpack(release.version, data)
    except Refused as exc:
        return finish("refused", str(exc))
    except (OSError, tarfile.TarError) as exc:
        return finish("error", f"could not unpack {release.name}: {exc}")
    try:
        saved = system.backup()
    except (UpdateError, OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(new_dir, ignore_errors=True)
        return finish("error", f"no update without a backup first: {exc}")

    log(f"updating {current} -> {release.version} (backup {saved.name})")
    if old_dir:
        layout.point(layout.previous, old_dir)
    layout.point(layout.current, new_dir)
    try:
        system.install_units(new_dir)
        system.restart()
        healthy = system.healthy(release.version)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"the new version did not start: {exc}")
        healthy = False
    if healthy:
        result.update(current=release.version, last_update=now_iso(), failed_version=None)
        layout.prune()
        return finish("updated", f"{current} -> {release.version}")

    # Roll back: the previous code and the database as it was before (the new version may have changed it).
    result["failed_version"] = release.version
    if old_dir is None:
        return finish("error", f"{release.version} is not healthy and there is no previous version to go back to")
    try:
        system.stop()
        layout.point(layout.current, old_dir)
        if old_previous:
            layout.point(layout.previous, old_previous)
        system.restore(saved, old_dir)
        system.install_units(old_dir)
        system.start()
        back = system.healthy(current)
    except (OSError, subprocess.SubprocessError) as exc:
        return finish("error", f"{release.version} was not healthy and going back to {current} failed: {exc}")
    shutil.rmtree(new_dir, ignore_errors=True)
    return finish("rolled_back", f"{release.version} was not healthy: back to {current} and the backup {saved.name}"
                  + ("" if back else "; and the server is not healthy now either"))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="secretbroker-server-update", description=__doc__.split("\n")[0])
    parser.add_argument("--source", help="release source: github (default), an https API URL or a folder "
                                         "(default: SB_UPDATE_SOURCE)")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--force", action="store_true", help="try again a version that failed before")
    args = parser.parse_args(argv)
    import fcntl
    os.umask(0o022)
    settings = config.apply_overrides(config.from_env())
    status_path = settings.update_status or STATUS_FILE
    layout = Layout(args.root)
    layout.root.mkdir(parents=True, exist_ok=True)
    with open(layout.root / ".update.lock", "a+") as lock:  # one at a time (the timer, the installer)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        result = run(source_from(args.source or os.environ.get("SB_UPDATE_SOURCE", "")), layout,
                     Systemd(settings, int(os.environ.get("SB_PORT", "8080"))), trusted_keys(), status_path,
                     platform.machine(), auto=settings.auto_update, force=args.force)
    sys.exit(1 if result["last_result"] in ("error", "refused") or
             (result["last_result"] == "rolled_back") else 0)


if __name__ == "__main__":
    main()
