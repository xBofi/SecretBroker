"""Backups: one zip with a consistent copy of the database (SQLite's online backup, safe while the server runs) and
`server_secret`. Restoring needs the server stopped: `serve` holds a lock on the data folder while it runs.

A backup holds what the server holds: ciphertext, public keys and metadata (e-mails, organization names, who
belongs to what). Keep backups as private as the server itself.
"""

import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PREFIX = "secretbroker-backup-"
SUFFIX = ".zip"
DB_NAME = "secretbroker.db"
SECRET_NAME = "server_secret"
LOCK_NAME = ".serve.lock"


class BackupError(Exception):
    pass


# ---------------------------------------------------------------------- the lock `serve` holds

def take_lock(data_dir):
    """An exclusive lock on the data folder (an open file), or None if another process holds it."""
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    handle = open(Path(data_dir) / LOCK_NAME, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def release_lock(handle):
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    handle.close()


def serving(data_dir):
    handle = take_lock(data_dir)
    if handle is None:
        return True
    release_lock(handle)
    return False


# ---------------------------------------------------------------------- backup and restore

def _private(path, mode=0o600):
    if os.name == "posix":
        os.chmod(path, mode)


def backup(data_dir, dest_dir, keep=14):
    """Write a timestamped backup to `dest_dir` and delete the oldest beyond `keep`. → (path, [pruned])"""
    data_dir, dest = Path(data_dir), Path(dest_dir)
    source = data_dir / DB_NAME
    if not source.exists():
        raise BackupError(f"there is no database in {data_dir}")
    dest.mkdir(parents=True, exist_ok=True)
    _private(dest, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target, n = dest / f"{PREFIX}{stamp}{SUFFIX}", 1
    while target.exists():  # two in the same second
        n += 1
        target = dest / f"{PREFIX}{stamp}-{n}{SUFFIX}"
    with tempfile.TemporaryDirectory(dir=dest, prefix=".partial-") as tmp:
        copy = Path(tmp) / DB_NAME
        src, dst = sqlite3.connect(str(source), timeout=30), sqlite3.connect(str(copy))
        try:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")  # one self-contained file
        finally:
            dst.close()
            src.close()
        partial = Path(tmp) / "backup.zip"
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(copy, DB_NAME)
            if (data_dir / SECRET_NAME).exists():
                archive.write(data_dir / SECRET_NAME, SECRET_NAME)
        _private(partial)
        os.replace(partial, target)
    return target, prune(dest, keep)


def list_backups(dest_dir):
    """[{file, at, bytes}], newest first: the file name only (never a path), its time (UTC) and size."""
    found = []
    for path in Path(dest_dir).glob(f"{PREFIX}*{SUFFIX}"):
        try:
            stat = path.stat()
        except OSError:
            continue
        if path.is_file():
            found.append({"file": path.name, "bytes": stat.st_size,
                          "at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds")})
    return sorted(found, key=lambda b: b["file"], reverse=True)


def prune(dest_dir, keep):
    """Delete the oldest backups so `keep` remain (names sort by time)."""
    found = sorted(p for p in Path(dest_dir).glob(f"{PREFIX}*{SUFFIX}") if p.is_file())
    old = found[:-keep] if keep > 0 else []
    for path in old:
        path.unlink()
    return old


def _check(path):
    conn = sqlite3.connect(str(path))
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise BackupError("the database in the backup is damaged")
        if conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() is None:
            raise BackupError("the backup has no SecretBroker database")
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"the backup has no usable SecretBroker database ({exc})") from None
    finally:
        conn.close()


def restore(data_dir, archive_path):
    """Put a backup in place. Refused while a server uses this data folder. The current files are moved aside to
    `before-restore-<time>/` (nothing is deleted). → that folder, or None if there was nothing to move."""
    data_dir, archive_path = Path(data_dir), Path(archive_path)
    lock = take_lock(data_dir)
    if lock is None:
        raise BackupError("the server is running on this data folder: stop it first "
                          "(docker compose stop server), restore, then start it again")
    try:
        try:
            archive = zipfile.ZipFile(archive_path)
        except (OSError, zipfile.BadZipFile) as exc:
            raise BackupError(f"{archive_path} is not a SecretBroker backup ({exc})") from None
        with archive, tempfile.TemporaryDirectory(dir=data_dir, prefix=".restore-") as tmp:
            names = set(archive.namelist())
            if DB_NAME not in names:
                raise BackupError(f"{archive_path} is not a SecretBroker backup (no {DB_NAME} inside)")
            for name in (DB_NAME, SECRET_NAME):
                if name in names:
                    with archive.open(name) as src, open(Path(tmp) / name, "wb") as out:
                        shutil.copyfileobj(src, out)
                    _private(Path(tmp) / name)
            _check(Path(tmp) / DB_NAME)
            replaced = (DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm") + ((SECRET_NAME,) if SECRET_NAME in names else ())
            current = [data_dir / n for n in replaced if (data_dir / n).exists()]
            aside = None
            if current:
                aside = data_dir / f"before-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
                aside.mkdir()
                _private(aside, 0o700)
                for path in current:
                    os.replace(path, aside / path.name)
            for name in (DB_NAME, SECRET_NAME):
                if (Path(tmp) / name).exists():
                    os.replace(Path(tmp) / name, data_dir / name)
        return aside
    finally:
        release_lock(lock)
