"""SQLite storage (WAL mode). The SQL stays plain so a Postgres backend can reuse it.

Everything the server stores is either routing metadata or opaque ciphertext produced by the clients.
Timestamps shown to clients are ISO 8601 UTC strings; expiry times are integer epoch seconds.
"""

import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2

# `INTEGER PRIMARY KEY` on events is SQLite's rowid; a Postgres backend would use BIGSERIAL.
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    kdf TEXT NOT NULL,
    auth_salt TEXT NOT NULL,
    auth_verifier TEXT NOT NULL,
    public_key TEXT NOT NULL,
    signing_public_key TEXT NOT NULL,
    private_blob TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    invited_to TEXT,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_codes (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    code_hash TEXT NOT NULL,
    expires INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    sent INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS account_data (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    blob TEXT NOT NULL,
    revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    created TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    touched INTEGER NOT NULL,
    expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS signup_tokens (
    token_hash TEXT PRIMARY KEY,
    created TEXT NOT NULL,
    created_by TEXT,
    expires INTEGER NOT NULL,
    used_by TEXT
);
CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_members (
    org_id TEXT NOT NULL REFERENCES orgs(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    created TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user ON org_members(user_id);
CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS invites_email ON invites(email);
CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    encrypted_name TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    needs_rekey INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    direct INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS collections_org ON collections(org_id);
CREATE TABLE IF NOT EXISTS collection_members (
    collection_id TEXT NOT NULL REFERENCES collections(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL,
    grant_json TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);
CREATE INDEX IF NOT EXISTS collection_members_user ON collection_members(user_id);
CREATE TABLE IF NOT EXISTS items (
    collection_id TEXT NOT NULL REFERENCES collections(id),
    id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    key_version INTEGER NOT NULL,
    ciphertext TEXT,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL,
    updated TEXT NOT NULL,
    deletion TEXT,
    PRIMARY KEY (collection_id, id)
);
CREATE INDEX IF NOT EXISTS items_revision ON items(collection_id, revision);
CREATE TABLE IF NOT EXISTS collection_manifests (
    collection_id TEXT NOT NULL REFERENCES collections(id),
    seq INTEGER NOT NULL,
    record TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (collection_id, seq)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    org_id TEXT,
    time TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT
);
CREATE INDEX IF NOT EXISTS events_org ON events(org_id, id);
"""


def _columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate(conn):
    """Bring a database made by an earlier version up to date (new tables come from SCHEMA).

    Schema 2 adds e-mail verification and signed deletions. Accounts that already existed count as verified: they
    were in use before verification existed, and their organizations' admins confirmed them by hand."""
    if "verified" not in _columns(conn, "users"):
        conn.execute("ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE users SET verified = 1")
    if "invited_to" not in _columns(conn, "users"):
        conn.execute("ALTER TABLE users ADD COLUMN invited_to TEXT")
    if "deletion" not in _columns(conn, "items"):
        conn.execute("ALTER TABLE items ADD COLUMN deletion TEXT")
    if "direct" not in _columns(conn, "collections"):  # a credential shared with one person (two members at most)
        conn.execute("ALTER TABLE collections ADD COLUMN direct INTEGER NOT NULL DEFAULT 0")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def now_epoch():
    return int(time.time())


class Database:
    """One SQLite connection per thread; requests run in uvicorn's thread pool."""

    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self._local = threading.local()
        self._all = []
        self._lock = threading.Lock()
        conn = self.conn()
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT (key) DO UPDATE "
                     "SET value = excluded.value", (str(SCHEMA_VERSION),))

    def conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
            with self._lock:
                self._all.append(conn)
        return conn

    @contextmanager
    def tx(self, write=False):
        """A transaction; writes take the lock up front so revision counters never race."""
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def close(self):
        with self._lock:
            for conn in self._all:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()


def event(conn, org_id, actor, action, target=None):
    """Record a metadata-only audit event (never contents: the server does not have them)."""
    conn.execute("INSERT INTO events (org_id, time, actor, action, target) VALUES (?, ?, ?, ?, ?)",
                 (org_id, now_iso(), actor, action, target))
