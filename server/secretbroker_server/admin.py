"""Server administration, shared by the command line (`secretbroker-server users | disable-user | enable-user |
delete-user | transfer-owner | verify-email`) and the admin API the desktop app uses (admin_api.py), so the two
can never disagree.

Only metadata is listed or changed (there are no contents here to touch). Taking someone out of an organization
works exactly like an org admin removing them in the app: every collection they could read is marked
`needs_rekey`, so the managers' apps re-key it on their next sync and flag its credentials "rotate: <person> had
access" (docs/ARCHITECTURE.md 2.4). The org audit log records it with the server admin as actor (none), and the
server admin log (admin_events) records who did it and through what (`via`: "cli" or "api").
"""

from .db import admin_event, event
from .orgs import blockers, drop_member


class AdminError(Exception):
    """A refusal. `code` and `extra` are what the API answers (400 unless `status` says otherwise)."""

    def __init__(self, message, code="refused", status=400, **extra):
        super().__init__(message)
        self.code, self.status, self.extra = code, status, extra


def find(conn, address):
    row = conn.execute("SELECT * FROM users WHERE email = ?", (address,)).fetchone()
    if row is None:
        raise AdminError(f"no account with the e-mail {address}", "not_found", 404)
    return row


def find_id(conn, uid):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        raise AdminError("no such account", "not_found", 404)
    return row


def is_admin(settings, row):
    return bool(row["is_admin"]) or row["email"] in settings.admin_emails


def last_admin(conn, settings, user):
    """True when `user` is the only server admin who can still sign in (the API never locks the server out)."""
    if not is_admin(settings, user) or user["disabled"]:
        return False
    others = conn.execute("SELECT is_admin, email FROM users WHERE id != ? AND disabled = 0", (user["id"],)).fetchall()
    return not any(is_admin(settings, row) for row in others)


def users(conn, settings):
    """Every account: id, e-mail, name, verified, admin, disabled, organizations (id, name, role, status) and when
    it was last seen (newest session use or login). Never keys, verifiers or blobs."""
    rows = conn.execute(
        "SELECT u.id, u.email, u.name, u.verified, u.is_admin, u.disabled, u.created, "
        "(SELECT MAX(s.last_seen) FROM sessions s WHERE s.user_id = u.id) AS session_seen, "
        "(SELECT MAX(e.time) FROM events e WHERE e.actor = u.id AND e.action = 'login') AS login_seen "
        "FROM users u ORDER BY u.email").fetchall()
    orgs = {}
    for r in conn.execute("SELECT m.user_id, o.id, o.name, m.role, m.status FROM org_members m JOIN orgs o "
                          "ON o.id = m.org_id ORDER BY o.name, o.id"):
        orgs.setdefault(r["user_id"], []).append({"id": r["id"], "name": r["name"], "role": r["role"],
                                                  "status": r["status"]})
    return [{"id": r["id"], "email": r["email"], "name": r["name"], "verified": bool(r["verified"]),
             "admin": is_admin(settings, r), "disabled": bool(r["disabled"]),
             "orgs": orgs.get(r["id"], []), "created": r["created"],
             "last_seen": max(filter(None, (r["session_seen"], r["login_seen"])), default=None)} for r in rows]


def orgs(conn):
    """Every organization: id, name, confirmed members, collections, owners (id, e-mail, name)."""
    owners = {}
    for r in conn.execute("SELECT m.org_id, u.id, u.email, u.name FROM org_members m JOIN users u ON u.id = m.user_id "
                          "WHERE m.role = 'owner' ORDER BY u.email"):
        owners.setdefault(r["org_id"], []).append({"id": r["id"], "email": r["email"], "name": r["name"]})
    rows = conn.execute(
        "SELECT o.id, o.name, o.created, "
        "(SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id AND m.status = 'confirmed') AS members, "
        "(SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id AND m.status != 'confirmed') AS pending, "
        "(SELECT COUNT(*) FROM collections c WHERE c.org_id = o.id AND c.direct = 0) AS collections, "
        "(SELECT COUNT(*) FROM collections c WHERE c.org_id = o.id AND c.direct = 1) AS direct "
        "FROM orgs o ORDER BY o.name, o.id").fetchall()
    return [{"id": r["id"], "name": r["name"], "created": r["created"], "members": r["members"],
             "pending": r["pending"], "collections": r["collections"], "direct": r["direct"],
             "owners": owners.get(r["id"], [])} for r in rows]


def _org_name(conn, oid):
    return conn.execute("SELECT name FROM orgs WHERE id = ?", (oid,)).fetchone()["name"]


def holds(conn, user):
    """What keeps this account in an organization: [{org, name, reason: last_owner | last_manager, collections,
    why}], `why` saying what to do (for the command line; the app words it from `reason`)."""
    held = []
    for (oid,) in conn.execute("SELECT org_id FROM org_members WHERE user_id = ? ORDER BY org_id",
                               (user["id"],)).fetchall():
        last_owner, orphans = blockers(conn, oid, user["id"])
        name = _org_name(conn, oid)
        if last_owner:
            held.append({"org": oid, "name": name, "reason": "last_owner", "collections": [],
                         "why": f"they are the only owner of «{name}»: make another confirmed member owner with "
                                f"`secretbroker-server transfer-owner {oid} <their e-mail>` (or the owner does it "
                                "in the app, Equipo › Personas)"})
        if orphans:
            held.append({"org": oid, "name": name, "reason": "last_manager", "collections": orphans,
                         "why": f"they are the only manager of {len(orphans)} collection(s) of «{name}» "
                                f"({', '.join(orphans)}): a manager or org admin gives «Gestor» to someone else in "
                                "each one (or deletes it) in the app"})
    return held


def _leave_orgs(conn, user, action, skip=()):
    """Take the account out of every organization not in `skip`. → [{org, name, collections (to re-key)}]"""
    left = []
    for (oid,) in conn.execute("SELECT org_id FROM org_members WHERE user_id = ? ORDER BY org_id",
                               (user["id"],)).fetchall():
        if oid in skip:
            continue
        cids, _deleted = drop_member(conn, oid, user["id"])
        event(conn, oid, None, action, user["email"])
        left.append({"org": oid, "name": _org_name(conn, oid), "collections": len(cids)})
    return left


def find_org(conn, which):
    """An organization by id, or by name when only one has it."""
    row = conn.execute("SELECT id, name FROM orgs WHERE id = ?", (which,)).fetchone()
    if row:
        return row
    rows = conn.execute("SELECT id, name FROM orgs WHERE name = ?", (which,)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if rows:
        raise AdminError(f"{len(rows)} organizations are called «{which}»: use its id ("
                         + ", ".join(r["id"] for r in rows) + ")", "ambiguous")
    raise AdminError(f"no organization «{which}» (an id or an exact name; `users` lists them)", "not_found", 404)


def transfer_owner(conn, org, user, actor=None, via="cli"):
    """Make a confirmed member of an organization its owner (the current owners stay owners): for an organization
    whose only owner can't sign in any more. → (org name, already owner)"""
    member = conn.execute("SELECT role, status FROM org_members WHERE org_id = ? AND user_id = ?",
                          (org["id"], user["id"])).fetchone()
    if member is None or member["status"] != "confirmed":
        raise AdminError(f"{user['email']} is not a confirmed member of «{org['name']}»: invite them and confirm "
                         "them in the app first", "not_member")
    if user["disabled"]:
        raise AdminError(f"{user['email']} is disabled: pick someone who can sign in", "disabled")
    if member["role"] == "owner":
        return org["name"], True
    conn.execute("UPDATE org_members SET role = 'owner' WHERE org_id = ? AND user_id = ?", (org["id"], user["id"]))
    event(conn, org["id"], None, "member.role", f"{user['id']}:owner")
    admin_event(conn, actor, via, "org.owner", org["id"], {"user": user["id"], "email": user["email"]})
    return org["name"], False


def disable(conn, user, actor=None, via="cli"):
    """Block an account at once: its sessions end and it can't sign in; its data stays. It leaves every
    organization it can (their collections get re-keyed); where it is the last owner or a collection's only
    manager it stays a member (unable to sign in) until that is handed over. → (left, held)"""
    conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user["id"],))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    event(conn, None, None, "user.disable", user["id"])
    held = holds(conn, user)
    left = _leave_orgs(conn, user, "member.disable", skip={h["org"] for h in held})
    admin_event(conn, actor, via, "user.disable", user["id"],
                {"email": user["email"], "left": [x["org"] for x in left], "held": sorted({h["org"] for h in held})})
    return left, held


def enable(conn, user, actor=None, via="cli"):
    """Let a disabled account sign in again. It does not get back into the organizations it left: invite it."""
    if not user["disabled"]:
        return False
    conn.execute("UPDATE users SET disabled = 0 WHERE id = ?", (user["id"],))
    event(conn, None, None, "user.enable", user["id"])
    admin_event(conn, actor, via, "user.enable", user["id"], {"email": user["email"]})
    return True


def verify(conn, user, actor=None, via="cli"):
    """Mark an account's e-mail as verified (after checking who the person is). → False if it already was."""
    from .accounts import mark_verified

    if user["verified"]:
        return False
    mark_verified(conn, user["id"], actor)
    admin_event(conn, actor, via, "user.verify", user["id"], {"email": user["email"]})
    return True


def delete(conn, user, actor=None, via="cli"):
    """Delete an account and everything only it uses (sessions, its encrypted keys and data), after taking it out of
    its organizations. Refused, changing nothing, while it is an organization's last owner or a collection's only
    manager. Audit events keep its id. → [{org, name, collections}]"""
    held = holds(conn, user)
    if held:
        owner = [h for h in held if h["reason"] == "last_owner"]
        raise AdminError("can't delete it yet:\n" + "\n".join(f"  - {h['why']}" for h in held)
                         + "\nThen run this again. (`disable-user` blocks the account meanwhile.)",
                         "last_owner" if owner else "last_manager",
                         orgs=[{"id": h["org"], "name": h["name"]} for h in owner],
                         collections=[c for h in held for c in h["collections"]])
    left = _leave_orgs(conn, user, "member.delete")
    for table in ("sessions", "email_codes", "account_data", "collection_members", "org_members"):
        conn.execute(f"DELETE FROM {table} WHERE user_id = ?", (user["id"],))
    conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    event(conn, None, None, "user.delete", user["id"])
    admin_event(conn, actor, via, "user.delete", user["id"], {"email": user["email"], "left": [x["org"] for x in left]})
    return left
