"""Organizations: members and roles, invites (invite -> accept -> admin confirms), collections, audit events."""

from . import manifests
from .db import event, now_iso
from .validate import (ApiError, body, boolean, dump, email, grant, members_record, one_of, path_id, query_int, sealed,
                       text, uuid_id)
from .web import new_id, route

ADMIN_ROLES = ("owner", "admin")
NAME_MAX = 1024


def not_found():
    return ApiError(404, "not_found", "No existe.")


def forbidden(message="No tienes permiso para hacer esto."):
    return ApiError(403, "forbidden", message)


def membership(conn, oid, uid, statuses=("confirmed",)):
    """The caller's row in an organization; anyone outside it gets 404 so ids reveal nothing."""
    row = conn.execute("SELECT role, status FROM org_members WHERE org_id = ? AND user_id = ?", (oid, uid)).fetchone()
    if row is None or row["status"] not in statuses:
        raise not_found()
    return row


def require_admin(conn, oid, uid):
    row = membership(conn, oid, uid)
    if row["role"] not in ADMIN_ROLES:
        raise forbidden("Solo un administrador de la organización puede hacer esto.")
    return row


def delete_collection_rows(conn, cid):
    for table, column in (("items", "collection_id"), ("collection_members", "collection_id"),
                          ("collection_manifests", "collection_id"), ("collections", "id")):
        conn.execute(f"DELETE FROM {table} WHERE {column} = ?", (cid,))


def _owners(conn, oid):
    return conn.execute("SELECT COUNT(*) FROM org_members WHERE org_id = ? AND role = 'owner'", (oid,)).fetchone()[0]


@route("POST", "/orgs")
def create_org(ctx):
    name = body(ctx.body, {"name": text(100)})["name"]
    oid = new_id()
    ctx.conn.execute("INSERT INTO orgs (id, name, created) VALUES (?, ?, ?)", (oid, name, now_iso()))
    ctx.conn.execute("INSERT INTO org_members (org_id, user_id, role, status, created) VALUES (?, ?, 'owner', "
                     "'confirmed', ?)", (oid, ctx.uid, now_iso()))
    event(ctx.conn, oid, ctx.uid, "org.create", oid)
    return {"id": oid}


@route("GET", "/orgs")
def list_orgs(ctx):
    rows = ctx.conn.execute("SELECT o.id, o.name, m.role, m.status FROM orgs o JOIN org_members m ON m.org_id = o.id "
                            "WHERE m.user_id = ? ORDER BY o.name", (ctx.uid,)).fetchall()
    return [dict(r) for r in rows]


@route("GET", "/orgs/{oid}/members")
def list_members(ctx):
    oid = path_id(ctx.params["oid"])
    caller = membership(ctx.conn, oid, ctx.uid)
    rows = ctx.conn.execute("SELECT u.id, u.email, u.name, m.role, m.status FROM org_members m JOIN users u "
                            "ON u.id = m.user_id WHERE m.org_id = ? ORDER BY u.email", (oid,)).fetchall()
    members = [{"user_id": r["id"], "email": r["email"], "name": r["name"], "role": r["role"], "status": r["status"]}
               for r in rows]
    # An account that has not verified the invited e-mail is not shown as that person (it may not be them).
    invites = ctx.conn.execute("SELECT i.id, i.email, i.role, u.id AS user_id, u.name FROM invites i LEFT JOIN users u "
                               "ON u.email = i.email AND (u.verified = 1 OR u.invited_to = i.org_id) WHERE i.org_id = ? "
                               "ORDER BY i.email",
                               (oid,)).fetchall()
    # The invite id doubles as a signup token for that e-mail (SB_SIGNUPS=invite): only admins see it.
    admin = caller["role"] in ADMIN_ROLES
    members += [{"user_id": r["user_id"], "email": r["email"], "name": r["name"] or "", "role": r["role"],
                 "status": "invited", **({"invite_id": r["id"]} if admin else {})} for r in invites]
    return members


@route("POST", "/orgs/{oid}/invites")
def invite(ctx):
    oid = path_id(ctx.params["oid"])
    data = body(ctx.body, {"email": email, "role": one_of("member", "admin")})
    require_admin(ctx.conn, oid, ctx.uid)
    if ctx.conn.execute("SELECT 1 FROM org_members m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? "
                        "AND u.email = ?", (oid, data["email"])).fetchone():
        raise ApiError(409, "already_member", "Esa persona ya está en la organización.")
    if ctx.conn.execute("SELECT 1 FROM invites WHERE org_id = ? AND email = ?", (oid, data["email"])).fetchone():
        raise ApiError(409, "already_invited", "Esa persona ya tiene una invitación pendiente.")
    invite_id = new_id()
    ctx.conn.execute("INSERT INTO invites (id, org_id, email, role, invited_by, created) VALUES (?, ?, ?, ?, ?, ?)",
                     (invite_id, oid, data["email"], data["role"], ctx.uid, now_iso()))
    event(ctx.conn, oid, ctx.uid, "invite", data["email"])
    return {"id": invite_id}


def unverified():
    return ApiError(403, "email_unverified", "Antes verifica tu e-mail: las invitaciones solo llegan a direcciones "
                    "verificadas.")


@route("GET", "/invites")
def my_invites(ctx):
    """Invites only bind to an address the account proved it owns: until then it sees none, except those of the
    organization whose invite code it registered with."""
    rows = ctx.conn.execute(
        "SELECT i.id, i.org_id, o.name AS org_name, i.role, i.invited_by, u.email AS invited_by_email, "
        "u.name AS invited_by_name, u.public_key AS invited_by_public_key, "
        "u.signing_public_key AS invited_by_signing_public_key FROM invites i JOIN orgs o ON o.id = i.org_id LEFT JOIN users u "
        "ON u.id = i.invited_by WHERE i.email = ? ORDER BY i.created", (ctx.user["email"],)).fetchall()
    return [dict(r) for r in rows if _may_take(ctx.user, r["org_id"])]


def _may_take(user, oid):
    return bool(user["verified"]) or user["invited_to"] == oid


def _invite_for_me(ctx):
    invite_id = path_id(ctx.params["iid"])
    row = ctx.conn.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
    if row is None:
        raise not_found()
    return row


@route("POST", "/invites/{iid}/accept")
def accept_invite(ctx):
    row = _invite_for_me(ctx)
    if row["email"] != ctx.user["email"]:
        raise not_found()
    if not _may_take(ctx.user, row["org_id"]):
        raise unverified()
    ctx.conn.execute("DELETE FROM invites WHERE id = ?", (row["id"],))
    ctx.conn.execute("INSERT INTO org_members (org_id, user_id, role, status, created) VALUES (?, ?, ?, 'accepted', ?) "
                     "ON CONFLICT (org_id, user_id) DO NOTHING", (row["org_id"], ctx.uid, row["role"], now_iso()))
    event(ctx.conn, row["org_id"], ctx.uid, "join", ctx.uid)
    return {}


@route("DELETE", "/invites/{iid}")
def drop_invite(ctx):
    """The invitee declines, or an org admin withdraws the invite."""
    row = _invite_for_me(ctx)
    if row["email"] != ctx.user["email"]:
        require_admin(ctx.conn, row["org_id"], ctx.uid)
    ctx.conn.execute("DELETE FROM invites WHERE id = ?", (row["id"],))
    event(ctx.conn, row["org_id"], ctx.uid, "invite.delete", row["email"])
    return {}


def _target(ctx):
    oid, uid = path_id(ctx.params["oid"]), path_id(ctx.params["uid"])
    caller = membership(ctx.conn, oid, ctx.uid)
    target = ctx.conn.execute("SELECT role, status FROM org_members WHERE org_id = ? AND user_id = ?",
                              (oid, uid)).fetchone()
    if target is None:
        raise not_found()
    return oid, uid, caller, target


@route("POST", "/orgs/{oid}/members/{uid}/confirm")
def confirm_member(ctx):
    """An admin confirms someone who accepted, after (ideally) comparing their key fingerprint."""
    oid, uid, caller, target = _target(ctx)
    if caller["role"] not in ADMIN_ROLES:
        raise forbidden("Solo un administrador de la organización puede hacer esto.")
    if target["status"] != "confirmed":
        ctx.conn.execute("UPDATE org_members SET status = 'confirmed' WHERE org_id = ? AND user_id = ?", (oid, uid))
        event(ctx.conn, oid, ctx.uid, "member.confirm", uid)
    return {}


@route("PATCH", "/orgs/{oid}/members/{uid}")
def set_role(ctx):
    """Owners manage everyone; admins only move people between member and admin."""
    role = body(ctx.body, {"role": one_of("owner", "admin", "member")})["role"]
    oid, uid, caller, target = _target(ctx)
    if caller["role"] not in ADMIN_ROLES:
        raise forbidden("Solo un administrador de la organización puede hacer esto.")
    if caller["role"] != "owner" and "owner" in (role, target["role"]):
        raise forbidden("Solo un propietario puede cambiar a otros propietarios.")
    if target["role"] == "owner" and role != "owner" and _owners(ctx.conn, oid) == 1:
        raise ApiError(400, "last_owner", "La organización necesita al menos un propietario.")
    if role != target["role"]:
        ctx.conn.execute("UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?", (role, oid, uid))
        event(ctx.conn, oid, ctx.uid, "member.role", f"{uid}:{role}")
    return {}


@route("DELETE", "/orgs/{oid}/members/{uid}")
def remove_member(ctx):
    """Remove someone (or leave). Every collection they could read must be re-keyed: returned as needs_rekey."""
    oid, uid, caller, target = _target(ctx)
    if uid != ctx.uid:
        if caller["role"] not in ADMIN_ROLES:
            raise forbidden("Solo un administrador de la organización puede quitar a otros.")
        if target["role"] == "owner" and caller["role"] != "owner":
            raise forbidden("Solo un propietario puede quitar a otro propietario.")
    if target["role"] == "owner" and _owners(ctx.conn, oid) == 1:
        raise ApiError(400, "last_owner", "La organización necesita al menos un propietario.")
    cids = [r[0] for r in ctx.conn.execute(
        "SELECT c.id FROM collections c JOIN collection_members cm ON cm.collection_id = c.id "
        "WHERE c.org_id = ? AND cm.user_id = ? ORDER BY c.id", (oid, uid)).fetchall()]
    # Without a manager nobody could re-key, grant or delete the collection again: hand it over first.
    orphans = [r[0] for r in ctx.conn.execute(
        "SELECT cm.collection_id FROM collection_members cm JOIN collections c ON c.id = cm.collection_id "
        "WHERE c.org_id = ? AND cm.user_id = ? AND cm.permission = 'manage' AND NOT EXISTS (SELECT 1 FROM "
        "collection_members o WHERE o.collection_id = cm.collection_id AND o.permission = 'manage' "
        "AND o.user_id != cm.user_id) ORDER BY cm.collection_id", (oid, uid)).fetchall()]
    # What someone shared with one person (a direct collection) goes with them: nobody else could manage it.
    direct = {r[0] for r in ctx.conn.execute(
        f"SELECT id FROM collections WHERE direct = 1 AND id IN ({','.join('?' * len(orphans))})", orphans).fetchall()} \
        if orphans else set()
    orphans = [cid for cid in orphans if cid not in direct]
    if orphans:
        raise ApiError(400, "last_manager", "Es la única persona que gestiona alguna colección. Antes, da permiso "
                       "de gestionar a otra persona en esas colecciones (o bórralas).", collections=orphans)
    for cid in sorted(direct):
        delete_collection_rows(ctx.conn, cid)
        event(ctx.conn, oid, ctx.uid, "collection.delete", cid)
    cids = [cid for cid in cids if cid not in direct]
    for cid in cids:
        ctx.conn.execute("DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?", (cid, uid))
        ctx.conn.execute("UPDATE collections SET needs_rekey = 1 WHERE id = ?", (cid,))
    ctx.conn.execute("DELETE FROM org_members WHERE org_id = ? AND user_id = ?", (oid, uid))
    event(ctx.conn, oid, ctx.uid, "member.leave" if uid == ctx.uid else "member.remove", uid)
    return {"needs_rekey": cids, **({"deleted": sorted(direct)} if direct else {})}


@route("POST", "/orgs/{oid}/collections")
def create_collection(ctx):
    oid = path_id(ctx.params["oid"])
    data = body(ctx.body, {"id": uuid_id, "encrypted_name": sealed(NAME_MAX), "grant": grant},
                {"members_record": members_record, "direct": boolean})
    # Admins make the team's collections. Anyone confirmed may share with one person: a direct collection, which
    # never has more than two members.
    if not data["direct"]:
        require_admin(ctx.conn, oid, ctx.uid)
    else:
        membership(ctx.conn, oid, ctx.uid)
    if data["grant"]["granted_by"] != ctx.uid:
        raise ApiError(400, "invalid", "grant: granted_by debe ser tu usuario.")
    if ctx.conn.execute("SELECT 1 FROM collections WHERE id = ?", (data["id"],)).fetchone():
        raise ApiError(409, "exists", "Esa colección ya existe.")
    ctx.conn.execute("INSERT INTO collections (id, org_id, encrypted_name, key_version, revision, needs_rekey, created, "
                     "direct) VALUES (?, ?, ?, 1, 0, 0, ?, ?)",
                     (data["id"], oid, dump(data["encrypted_name"]), now_iso(), int(bool(data["direct"]))))
    ctx.conn.execute("INSERT INTO collection_members (collection_id, user_id, permission, grant_json, key_version) "
                     "VALUES (?, ?, 'manage', ?, 1)", (data["id"], ctx.uid, dump(data["grant"])))
    if data["members_record"]:  # the first signed member list (older clients don't send one)
        manifests.append(ctx.conn, data["id"], ctx.body["members_record"], data["members_record"], ctx.uid, 1)
    event(ctx.conn, oid, ctx.uid, "collection.create", data["id"])
    return {}


@route("GET", "/orgs/{oid}/events")
def list_events(ctx):
    """Newest first, 100 at a time; pass the last `id` as `before` for the next page."""
    oid = path_id(ctx.params["oid"])
    require_admin(ctx.conn, oid, ctx.uid)
    before = query_int(ctx.query, "before", 2**62)
    rows = ctx.conn.execute("SELECT id, time, actor, action, target FROM events WHERE org_id = ? AND id < ? "
                            "ORDER BY id DESC LIMIT 100", (oid, before)).fetchall()
    return [dict(r) for r in rows]
