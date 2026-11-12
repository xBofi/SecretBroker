"""The server admin API (`/api/v1/admin/...`): what the desktop app's server panel uses. Every endpoint needs the
bearer session of a server admin (users.is_admin, or an SB_ADMIN_EMAILS address); anyone else gets 403, before
anything else is looked at. The logic is admin.py's, shared with the command line.

Nothing here touches contents (the server has none): accounts, organizations, counts, backups and settings.
Restoring a backup stays on the command line, because it needs the server stopped (overview says `restore: "cli"`).
Every change is written to the server admin log (GET /admin/events) and, when it changes an organization, to that
organization's events too.
"""

import json
import time
from pathlib import Path

from . import __version__, admin, backup, config
from .accounts import create_token, rate_limited
from .db import admin_event
from .validate import ApiError, body, boolean, email, integer, one_of, path_id, query_int, uuid_id
from .web import is_server_admin, route

READ, CHANGE, BACKUP = "read", "change", "backup"


def _require(ctx, kind=READ):
    """403 for anyone but a server admin; then the admin's own rate limits."""
    if not is_server_admin(ctx.settings, ctx.user):
        raise ApiError(403, "forbidden", "Solo un administrador del servidor puede hacer esto.")
    server = ctx.server
    windows = [server.admin_window] + ([server.admin_change_window] if kind != READ else []) \
        + ([server.admin_backup_window] if kind == BACKUP else [])
    for window in windows:
        wait = window.hit(ctx.uid)
        if wait:
            raise rate_limited(wait)


def _refused(exc):
    return ApiError(exc.status, exc.code, str(exc), **exc.extra)


def _target(ctx):
    try:
        return admin.find_id(ctx.conn, path_id(ctx.params["uid"]))
    except admin.AdminError as exc:
        raise _refused(exc) from None


def read_update_status(settings):
    """What the updater wrote after its last check ({} without an updater, or before its first check)."""
    if not settings.update_status:
        return {}
    try:
        data = json.loads(Path(settings.update_status).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def restore_command(settings):
    """The exact command lines that restore a backup on this installation (`<file>`: the backup's file name)."""
    if settings.install == "systemd":
        return [f"sudo secretbroker-server restore {settings.backups_path}/<file>"]
    if settings.install == "docker":
        return ["docker compose stop server backup",
                "docker compose run --rm --no-deps backup secretbroker-server restore /backups/<file>",
                "docker compose up -d"]
    return ["# stop the server first", f"secretbroker-server restore {settings.backups_path}/<file>",
            "# then start it again"]


def _db_bytes(settings):
    total = 0
    for suffix in ("", "-wal"):
        try:
            total += Path(str(settings.db_path) + suffix).stat().st_size
        except OSError:
            pass
    return total


@route("GET", "/admin/overview")
def overview(ctx):
    _require(ctx)
    settings, conn = ctx.settings, ctx.conn
    count = lambda sql: conn.execute(sql).fetchone()[0]
    status = read_update_status(settings)
    backups = backup.list_backups(settings.backups_path)
    return {
        "version": __version__,
        "latest": status.get("latest") if isinstance(status.get("latest"), str) else None,
        "updates": {"auto": settings.auto_update, "updater": bool(settings.update_status),
                    "last_check": status.get("last_check"), "last_result": status.get("last_result"),
                    "detail": status.get("detail")},
        "uptime_s": int(time.monotonic() - ctx.server.started),
        "counts": {"users": count("SELECT COUNT(*) FROM users"), "orgs": count("SELECT COUNT(*) FROM orgs"),
                   "collections": count("SELECT COUNT(*) FROM collections"),
                   "items": count("SELECT COUNT(*) FROM items WHERE deleted = 0"),
                   "disabled": count("SELECT COUNT(*) FROM users WHERE disabled = 1"),
                   "unverified": count("SELECT COUNT(*) FROM users WHERE verified = 0")},
        "db_bytes": _db_bytes(settings),
        "backups": {"last": backups[0]["at"] if backups else None, "count": len(backups), "keep": settings.backup_keep},
        "mail": settings.smtp,
        "signups": settings.signups,
        "verification": settings.verification,
        "restore": "cli",
        "install": settings.install,
        "restore_command": restore_command(settings),
        "name": settings.name,
        "public_url": settings.public_url,
        "api": config.API_VERSION,
        "min_client": settings.oldest_client,
    }


@route("GET", "/admin/users")
def list_users(ctx):
    _require(ctx)
    return [{**u, "orgs": [{"id": o["id"], "name": o["name"], "role": o["role"], "status": o["status"]}
                           for o in u["orgs"]]} for u in admin.users(ctx.conn, ctx.settings)]


def _no_lockout(ctx, user):
    if admin.last_admin(ctx.conn, ctx.settings, user):
        raise ApiError(400, "last_admin", "Es el único administrador del servidor: nombra antes a otro.")


@route("POST", "/admin/users/{uid}/disable")
def disable_user(ctx):
    _require(ctx, CHANGE)
    body(ctx.body, {})
    user = _target(ctx)
    _no_lockout(ctx, user)
    left, held = admin.disable(ctx.conn, user, ctx.uid, "api")
    return {"left": left, "held": [{k: h[k] for k in ("org", "name", "reason", "collections")} for h in held]}


@route("POST", "/admin/users/{uid}/enable")
def enable_user(ctx):
    _require(ctx, CHANGE)
    body(ctx.body, {})
    admin.enable(ctx.conn, _target(ctx), ctx.uid, "api")
    return {}


@route("POST", "/admin/users/{uid}/verify")
def verify_user(ctx):
    _require(ctx, CHANGE)
    body(ctx.body, {})
    admin.verify(ctx.conn, _target(ctx), ctx.uid, "api")
    return {}


@route("DELETE", "/admin/users/{uid}")
def delete_user(ctx):
    _require(ctx, CHANGE)
    user = _target(ctx)
    _no_lockout(ctx, user)
    try:
        admin.delete(ctx.conn, user, ctx.uid, "api")
    except admin.AdminError as exc:
        raise _refused(exc) from None
    return {}


@route("GET", "/admin/orgs")
def list_orgs(ctx):
    _require(ctx)
    return admin.orgs(ctx.conn)


@route("POST", "/admin/orgs/{oid}/owner")
def transfer_owner(ctx):
    _require(ctx, CHANGE)
    uid = body(ctx.body, {"user_id": uuid_id})["user_id"]
    org = ctx.conn.execute("SELECT id, name FROM orgs WHERE id = ?", (path_id(ctx.params["oid"]),)).fetchone()
    if org is None:
        raise ApiError(404, "not_found", "No existe.")
    try:
        admin.transfer_owner(ctx.conn, org, admin.find_id(ctx.conn, uid), ctx.uid, "api")
    except admin.AdminError as exc:
        raise _refused(exc) from None
    return {}


@route("GET", "/admin/backups")
def list_backups(ctx):
    _require(ctx)
    return backup.list_backups(ctx.settings.backups_path)


@route("POST", "/admin/backups", tx=False)
def make_backup(ctx):
    """A backup now, like the daily one (same folder, same number kept). SQLite's online backup: safe while the
    server serves."""
    _require(ctx, BACKUP)
    body(ctx.body, {})
    settings = ctx.settings
    try:
        path, pruned = backup.backup(settings.data_dir, settings.backups_path, settings.backup_keep)
    except (backup.BackupError, OSError) as exc:
        raise ApiError(503, "backup_failed", f"No se ha podido hacer la copia: {exc}") from None
    made = next((b for b in backup.list_backups(settings.backups_path) if b["file"] == path.name), None)
    with ctx.db.tx(write=True) as conn:
        admin_event(conn, ctx.uid, "api", "backup.create", path.name, {"pruned": [p.name for p in pruned]})
    return {"file": path.name, "at": made["at"] if made else None, "bytes": made["bytes"] if made else None}


@route("POST", "/admin/invites")
def create_signup_token(ctx):
    """Single-use tokens that let someone register when signups are by invite (`email`: only that address)."""
    _require(ctx, CHANGE)
    data = body(ctx.body, {}, {"days": integer(1, 90), "email": email})
    days = data["days"] or 7
    token, expires = create_token(ctx.conn, ctx.uid, days, data["email"])
    admin_event(ctx.conn, ctx.uid, "api", "signup_token.create", None, {"days": days, "email": data["email"]})
    return {"token": token, "expires": expires}


@route("PUT", "/admin/settings", tx=False)
def put_settings(ctx):
    """The server admin's choices, kept in SB_DATA_DIR/settings.json: they win over the SB_* variables."""
    _require(ctx, CHANGE)
    data = body(ctx.body, {}, {"signups": one_of(*config.SIGNUP_MODES), "auto_update": boolean})
    changes = {k: v for k, v in data.items() if v is not None}
    if not changes:
        raise ApiError(400, "invalid", "Nada que cambiar.")
    config.save_overrides(ctx.settings, changes)
    with ctx.db.tx(write=True) as conn:
        admin_event(conn, ctx.uid, "api", "settings", None, changes)
    return {}


@route("GET", "/admin/events")
def list_events(ctx):
    """The server admin log, newest first, 100 at a time; pass the last `id` as `before` for the next page."""
    _require(ctx)
    before = query_int(ctx.query, "before", 2**62)
    rows = ctx.conn.execute("SELECT id, time, actor, actor_email, via, action, target, detail FROM admin_events "
                            "WHERE id < ? ORDER BY id DESC LIMIT 100", (before,)).fetchall()
    return [{**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None} for r in rows]
