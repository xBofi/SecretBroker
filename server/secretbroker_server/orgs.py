"""Organizations: members and roles, invites (invite -> accept -> admin confirms), collections, audit events."""

from . import mail, manifests
from .db import event, iso, now_epoch, now_iso
from .validate import (ApiError, body, boolean, dump, email, grant, members_record, one_of, path_id, query_int, sealed,
                       uuid_id)
from .validate import name as name_text
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
    name = body(ctx.body, {"name": name_text(100)})["name"]
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
    invites = ctx.conn.execute("SELECT i.id, i.email, i.role, i.expires, i.sent, u.id AS user_id, u.name FROM invites i "
                               "LEFT JOIN users u ON u.email = i.email AND (u.verified = 1 OR u.invited_to = i.org_id) "
                               "WHERE i.org_id = ? ORDER BY i.email",
                               (oid,)).fetchall()
    # The invite id doubles as a signup token for that e-mail (SB_SIGNUPS=invite): only admins see it.
    admin = caller["role"] in ADMIN_ROLES
    now = now_epoch()
    members += [{"user_id": r["user_id"], "email": r["email"], "name": r["name"] or "", "role": r["role"],
                 "status": "invited", "expired": _expired(r, now), **({"expires": iso(r["expires"])} if r["expires"] else {}),
                 **({"invite_id": r["id"], "emailed": bool(r["sent"])} if admin else {})} for r in invites]
    return members


# ---------------------------------------------------------------------- invites
#
# An invite lasts SB_INVITE_DAYS (14). With SMTP the server e-mails it (the join link and plain steps, see
# mail.invite_message); the admin can always copy the same instructions in the app. Creating, renewing and
# re-sending count against SB_MAX_INVITES_PER_HOUR per organization and per account, so nobody can use the server
# to flood inboxes. The e-mail goes out after the transaction: an SMTP server may take seconds.

def _expired(row, now=None):
    return row["expires"] is not None and row["expires"] <= (now or now_epoch())


def _invite_limit(ctx, oid):
    for key in (f"org:{oid}", f"user:{ctx.uid}"):
        wait = ctx.server.invite_window.hit(key)
        if wait:
            raise ApiError(429, "rate_limited", "Demasiadas invitaciones en una hora. Espera un poco.",
                           retry_after=wait)


def _new_invite(ctx, conn, oid, address, role):
    invite_id, expires = new_id(), now_epoch() + ctx.settings.invite_days * 86400
    conn.execute("INSERT INTO invites (id, org_id, email, role, invited_by, created, expires) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?)", (invite_id, oid, address, role, ctx.uid, now_iso(), expires))
    return invite_id, expires


def _email_invite(ctx, oid, invite_id, address, expires):
    """E-mail the invite if this server has SMTP and the inviter verified their own address (so a throwaway
    account can't make the server e-mail strangers); True once the SMTP server took it (and that time is recorded).
    Otherwise the invite still exists and the app gives the admin the instructions to pass on."""
    if not ctx.settings.smtp or not ctx.user["verified"]:
        return False
    org = ctx.db.conn().execute("SELECT name FROM orgs WHERE id = ?", (oid,)).fetchone()
    inviter = f"{ctx.user['name']} ({ctx.user['email']})" if ctx.user["name"] else ctx.user["email"]
    if not mail.send_invite(ctx.settings, address, invite_id, org["name"], inviter, expires):
        return False
    with ctx.db.tx(write=True) as conn:
        conn.execute("UPDATE invites SET sent = ? WHERE id = ?", (now_epoch(), invite_id))
    return True


def _org_invite_row(conn, oid, ctx):
    require_admin(conn, oid, ctx.uid)
    row = conn.execute("SELECT * FROM invites WHERE id = ? AND org_id = ?",
                       (path_id(ctx.params["iid"]), oid)).fetchone()
    if row is None:
        raise not_found()
    return row


@route("POST", "/orgs/{oid}/invites", tx=False)
def invite(ctx):
    """Invite an e-mail (an expired invite to it is replaced). → {id, expires, emailed}"""
    oid = path_id(ctx.params["oid"])
    data = body(ctx.body, {"email": email, "role": one_of("member", "admin")})
    with ctx.db.tx(write=True) as conn:
        require_admin(conn, oid, ctx.uid)
        if conn.execute("SELECT 1 FROM org_members m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? "
                        "AND u.email = ?", (oid, data["email"])).fetchone():
            raise ApiError(409, "already_member", "Esa persona ya está en la organización.")
        old = conn.execute("SELECT id, expires FROM invites WHERE org_id = ? AND email = ?",
                           (oid, data["email"])).fetchone()
        if old and not _expired(old):
            raise ApiError(409, "already_invited", "Esa persona ya tiene una invitación pendiente.")
        _invite_limit(ctx, oid)
        if old:
            conn.execute("DELETE FROM invites WHERE id = ?", (old["id"],))
        invite_id, expires = _new_invite(ctx, conn, oid, data["email"], data["role"])
        event(conn, oid, ctx.uid, "invite", data["email"])
    return {"id": invite_id, "expires": iso(expires),
            "emailed": _email_invite(ctx, oid, invite_id, data["email"], expires)}


@route("POST", "/orgs/{oid}/invites/{iid}/renew", tx=False)
def renew_invite(ctx):
    """A new invite (new id, full validity) in place of this one, pending or expired; the old id stops working.
    → {id, expires, emailed}"""
    oid = path_id(ctx.params["oid"])
    body(ctx.body, {})
    with ctx.db.tx(write=True) as conn:
        row = _org_invite_row(conn, oid, ctx)
        _invite_limit(ctx, oid)
        conn.execute("DELETE FROM invites WHERE id = ?", (row["id"],))
        invite_id, expires = _new_invite(ctx, conn, oid, row["email"], row["role"])
        event(conn, oid, ctx.uid, "invite.renew", row["email"])
    return {"id": invite_id, "expires": iso(expires),
            "emailed": _email_invite(ctx, oid, invite_id, row["email"], expires)}


@route("POST", "/orgs/{oid}/invites/{iid}/send", tx=False)
def resend_invite(ctx):
    """E-mail a pending invite again (at most every 10 minutes). → {emailed} (false on a server without SMTP)"""
    oid = path_id(ctx.params["oid"])
    body(ctx.body, {})
    with ctx.db.tx(write=True) as conn:
        row = _org_invite_row(conn, oid, ctx)
        if _expired(row):
            raise ApiError(410, "invite_expired", "Esta invitación ha caducado: renuévala.")
        if not ctx.settings.smtp or not ctx.user["verified"]:
            return {"emailed": False}
        wait = (row["sent"] or 0) + mail.INVITE_RESEND_SECONDS - now_epoch()
        if wait > 0:
            raise ApiError(429, "rate_limited", "Ya se envió hace poco. Espera unos minutos.", retry_after=wait)
        _invite_limit(ctx, oid)
    emailed = _email_invite(ctx, oid, row["id"], row["email"], row["expires"] or now_epoch() + 86400)
    if emailed:
        with ctx.db.tx(write=True) as conn:
            event(conn, oid, ctx.uid, "invite.send", row["email"])
    return {"emailed": emailed}


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
        "ON u.id = i.invited_by WHERE i.email = ? AND COALESCE(i.expires, ?) > ? ORDER BY i.created",
        (ctx.user["email"], 2**62, now_epoch())).fetchall()
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
    if _expired(row):
        raise ApiError(410, "invite_expired", "Esta invitación ha caducado: pide a quien te invitó que la renueve.")
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


def blockers(conn, oid, uid):
    """Why someone can't leave an organization yet: (they are its last owner, collections they alone manage).
    Without a manager nobody could re-key, grant or delete a collection again: it has to be handed over first."""
    role = conn.execute("SELECT role FROM org_members WHERE org_id = ? AND user_id = ?", (oid, uid)).fetchone()
    last_owner = bool(role) and role["role"] == "owner" and _owners(conn, oid) == 1
    orphans = [r[0] for r in conn.execute(
        "SELECT cm.collection_id FROM collection_members cm JOIN collections c ON c.id = cm.collection_id "
        "WHERE c.org_id = ? AND cm.user_id = ? AND cm.permission = 'manage' AND NOT EXISTS (SELECT 1 FROM "
        "collection_members o WHERE o.collection_id = cm.collection_id AND o.permission = 'manage' "
        "AND o.user_id != cm.user_id) AND c.direct = 0 ORDER BY cm.collection_id", (oid, uid)).fetchall()]
    return last_owner, orphans


def drop_member(conn, oid, uid, actor=None):
    """Take someone out of an organization and every collection of it. Each collection they could read is marked
    needs_rekey: a manager's app re-keys it on its next sync and flags its credentials "rotate: X had access".
    What they shared with one person (a direct collection only they manage) goes with them: nobody else could
    manage it. -> (collections to re-key, direct collections deleted)"""
    direct = [r[0] for r in conn.execute(
        "SELECT c.id FROM collections c JOIN collection_members cm ON cm.collection_id = c.id WHERE c.org_id = ? "
        "AND c.direct = 1 AND cm.user_id = ? AND cm.permission = 'manage' AND NOT EXISTS (SELECT 1 FROM "
        "collection_members o WHERE o.collection_id = c.id AND o.permission = 'manage' AND o.user_id != ?) "
        "ORDER BY c.id", (oid, uid, uid)).fetchall()]
    for cid in direct:
        delete_collection_rows(conn, cid)
        event(conn, oid, actor, "collection.delete", cid)
    cids = [r[0] for r in conn.execute(
        "SELECT c.id FROM collections c JOIN collection_members cm ON cm.collection_id = c.id "
        "WHERE c.org_id = ? AND cm.user_id = ? ORDER BY c.id", (oid, uid)).fetchall()]
    for cid in cids:
        conn.execute("DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?", (cid, uid))
        conn.execute("UPDATE collections SET needs_rekey = 1 WHERE id = ?", (cid,))
    conn.execute("DELETE FROM org_members WHERE org_id = ? AND user_id = ?", (oid, uid))
    return cids, direct


@route("DELETE", "/orgs/{oid}/members/{uid}")
def remove_member(ctx):
    """Remove someone (or leave). Every collection they could read must be re-keyed: returned as needs_rekey."""
    oid, uid, caller, target = _target(ctx)
    if uid != ctx.uid:
        if caller["role"] not in ADMIN_ROLES:
            raise forbidden("Solo un administrador de la organización puede quitar a otros.")
        if target["role"] == "owner" and caller["role"] != "owner":
            raise forbidden("Solo un propietario puede quitar a otro propietario.")
    last_owner, orphans = blockers(ctx.conn, oid, uid)
    if last_owner:
        raise ApiError(400, "last_owner", "La organización necesita al menos un propietario.")
    if orphans:
        raise ApiError(400, "last_manager", "Es la única persona que gestiona alguna colección. Antes, da permiso "
                       "de gestionar a otra persona en esas colecciones (o bórralas).", collections=orphans)
    cids, direct = drop_member(ctx.conn, oid, uid, ctx.uid)
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
