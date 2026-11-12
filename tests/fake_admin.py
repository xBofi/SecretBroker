"""The team server's admin pages (docs/ARCHITECTURE.md 5.2), for the tests of the desktop
side, used only while the server in this tree does not have them (`create_app` below adds them then).

They are built on the server's own functions (secretbroker_server.admin, backup), so disabling, deleting or handing
over an organization has its real effects: sessions revoked, members dropped, collections marked for a re-key.
"""

import time

from secretbroker_server import __version__, admin, backup, web
from secretbroker_server.db import event
from secretbroker_server.orgs import blockers
from secretbroker_server.validate import ApiError

STARTED = time.time()
UPDATES = {"auto": True, "last_check": None, "last_result": None}
LATEST = {"version": None}  # a test sets it to show «Hay una versión nueva»
# What the one-command install (systemd, /opt/secretbroker-server) will answer.
RESTORE = ["sudo systemctl stop secretbroker-server",
           "sudo -u secretbroker /opt/secretbroker-server/bin/secretbroker-server restore /var/lib/secretbroker-server/backups/<file>",
           "sudo systemctl start secretbroker-server"]
KEEP = 14
installed = False


def _admin_only(ctx):
    if not web.is_server_admin(ctx.settings, ctx.user):
        raise ApiError(403, "forbidden", "Solo un administrador del servidor puede hacer esto.")


def _user(ctx, uid=None):
    row = ctx.conn.execute("SELECT * FROM users WHERE id = ?", (uid or ctx.params["uid"],)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "No existe.")
    return row


def _backup_dir(ctx):
    return ctx.settings.data_dir / "backups"


def _backups(ctx):
    folder = _backup_dir(ctx)
    files = sorted(folder.glob("secretbroker-backup-*.zip"), reverse=True) if folder.exists() else []
    return [{"file": f.name, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f.stat().st_mtime)),
             "bytes": f.stat().st_size} for f in files]


def overview(ctx):
    _admin_only(ctx)
    count = lambda table: ctx.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
    found = _backups(ctx)
    db = ctx.settings.db_path
    return {"version": __version__, "latest": LATEST["version"], "install": "systemd", "restore_command": RESTORE, "updates": dict(UPDATES), "uptime_s": int(time.time() - STARTED),
            "counts": {"users": count("users"), "orgs": count("orgs"), "collections": count("collections"),
                       "items": ctx.conn.execute("SELECT COUNT(*) FROM items WHERE deleted = 0").fetchone()[0]},
            "db_bytes": db.stat().st_size if db.exists() else 0,
            "backups": {"last": found[0]["at"] if found else None, "count": len(found), "keep": KEEP},
            "mail": ctx.settings.smtp, "signups": ctx.settings.signups, "verification": ctx.settings.verification,
            "restore": "cli"}


def users(ctx):
    _admin_only(ctx)
    rows = admin.users(ctx.conn, ctx.settings)
    by_email = {r["email"]: r["id"] for r in ctx.conn.execute("SELECT id, email FROM users")}
    orgs = {}
    for r in ctx.conn.execute("SELECT m.user_id, o.id, o.name, m.role FROM org_members m JOIN orgs o ON o.id = m.org_id "
                              "WHERE m.user_id IS NOT NULL ORDER BY o.name"):
        orgs.setdefault(r["user_id"], []).append({"id": r["id"], "name": r["name"], "role": r["role"]})
    return [{**row, "id": by_email[row["email"]], "orgs": orgs.get(by_email[row["email"]], [])} for row in rows]


def disable(ctx):
    _admin_only(ctx)
    user = _user(ctx)
    left, held = admin.disable(ctx.conn, user["email"])
    return {"left": [{"org": None, "name": name, "collections": n} for name, n in left],
            "held": [{"org": oid, "name": name} for oid, name, _ in held]}


def enable(ctx):
    _admin_only(ctx)
    admin.enable(ctx.conn, _user(ctx)["email"])
    return {}


def verify(ctx):
    _admin_only(ctx)
    user = _user(ctx)
    ctx.conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user["id"],))
    event(ctx.conn, None, ctx.uid, "user.verify", user["id"])
    return {}


def delete(ctx):
    _admin_only(ctx)
    user = _user(ctx)
    owner, managed = [], []
    for (oid,) in ctx.conn.execute("SELECT org_id FROM org_members WHERE user_id = ?", (user["id"],)).fetchall():
        last_owner, orphans = blockers(ctx.conn, oid, user["id"])
        if last_owner:
            owner.append({"id": oid, "name": ctx.conn.execute("SELECT name FROM orgs WHERE id = ?", (oid,)).fetchone()[0]})
        managed += orphans
    if owner:
        raise ApiError(400, "last_owner", "Es el único propietario.", orgs=owner)
    if managed:
        raise ApiError(400, "last_manager", "Es el único gestor.", collections=managed)
    admin.delete(ctx.conn, user["email"])
    return {}


def transfer(ctx):
    _admin_only(ctx)
    user = _user(ctx, str((ctx.body or {}).get("user_id") or ""))
    try:
        admin.transfer_owner(ctx.conn, ctx.params["oid"], user["email"])
    except admin.AdminError:
        raise ApiError(400, "not_confirmed", "No es un miembro confirmado.") from None
    return {}


def orgs(ctx):
    _admin_only(ctx)
    rows = []
    for org in ctx.conn.execute("SELECT id, name FROM orgs ORDER BY name").fetchall():
        owners = ctx.conn.execute("SELECT u.id, u.email, u.name FROM org_members m JOIN users u ON u.id = m.user_id "
                                  "WHERE m.org_id = ? AND m.role = 'owner'", (org["id"],)).fetchall()
        rows.append({"id": org["id"], "name": org["name"],
                     "members": ctx.conn.execute("SELECT COUNT(*) FROM org_members WHERE org_id = ? AND status = 'confirmed'",
                                                 (org["id"],)).fetchone()[0],
                     "collections": ctx.conn.execute("SELECT COUNT(*) FROM collections WHERE org_id = ?",
                                                     (org["id"],)).fetchone()[0],
                     "owners": [dict(o) for o in owners]})
    return rows


def make_backup(ctx):
    _admin_only(ctx)
    path, _ = backup.backup(ctx.settings.data_dir, _backup_dir(ctx), KEEP)
    event(ctx.conn, None, ctx.uid, "backup.create", path.name)
    return {"file": path.name, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def list_backups(ctx):
    _admin_only(ctx)
    return _backups(ctx)


def change_settings(ctx):
    _admin_only(ctx)
    body = ctx.body or {}
    if set(body) - {"signups", "auto_update"} or body.get("signups") not in (None, "open", "invite", "closed"):
        raise ApiError(400, "invalid", "Ajuste no válido.")
    if body.get("signups"):
        ctx.settings.signups = body["signups"]
        event(ctx.conn, None, ctx.uid, "settings.signups", body["signups"])
    if "auto_update" in body:
        UPDATES["auto"] = bool(body["auto_update"])
        event(ctx.conn, None, ctx.uid, "settings.auto_update", "on" if body["auto_update"] else "off")
    return {}


def events(ctx):
    _admin_only(ctx)
    return [dict(r) for r in ctx.conn.execute(
        "SELECT time, actor, action, target FROM events WHERE org_id IS NULL ORDER BY id DESC LIMIT 100")]


def create_app(settings):
    """The real server, with these pages added if it has none of its own."""
    global installed
    app = web.create_app(settings)
    if installed or any(path == "/admin/overview" for _, path, *_ in web.ROUTES):
        return app
    installed = True
    for method, path, handler in (
            ("GET", "/admin/overview", overview), ("GET", "/admin/users", users), ("GET", "/admin/orgs", orgs),
            ("POST", "/admin/users/{uid}/disable", disable), ("POST", "/admin/users/{uid}/enable", enable),
            ("POST", "/admin/users/{uid}/verify", verify), ("DELETE", "/admin/users/{uid}", delete),
            ("POST", "/admin/orgs/{oid}/owner", transfer), ("POST", "/admin/backups", make_backup),
            ("GET", "/admin/backups", list_backups), ("PUT", "/admin/settings", change_settings),
            ("GET", "/admin/events", events)):
        web.route(method, path)(handler)
    return web.create_app(settings)
