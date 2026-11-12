"""Server admin account management: `secretbroker-server users | disable-user | enable-user | delete-user`.

Only metadata is listed or changed (there are no contents here to touch). Taking someone out of an organization
works exactly like an org admin removing them in the app: every collection they could read is marked
`needs_rekey`, so the managers' apps re-key it on their next sync and flag its credentials "rotate: <person> had
access" (docs/ARCHITECTURE.md 2.4). The org audit log records it with the server admin as actor (none).
"""

from .db import event
from .orgs import blockers, drop_member


class AdminError(Exception):
    pass


def find(conn, address):
    row = conn.execute("SELECT * FROM users WHERE email = ?", (address,)).fetchone()
    if row is None:
        raise AdminError(f"no account with the e-mail {address}")
    return row


def users(conn, settings):
    """Every account: e-mail, name, verified, admin, disabled, organizations (with role) and when it was last
    seen (newest session use or login). Never keys, verifiers or blobs."""
    rows = conn.execute(
        "SELECT u.id, u.email, u.name, u.verified, u.is_admin, u.disabled, u.created, "
        "(SELECT MAX(s.last_seen) FROM sessions s WHERE s.user_id = u.id) AS session_seen, "
        "(SELECT MAX(e.time) FROM events e WHERE e.actor = u.id AND e.action = 'login') AS login_seen "
        "FROM users u ORDER BY u.email").fetchall()
    orgs = {}
    for r in conn.execute("SELECT m.user_id, o.name, m.role, m.status FROM org_members m JOIN orgs o "
                          "ON o.id = m.org_id ORDER BY o.name"):
        role = r["role"] if r["status"] == "confirmed" else f"{r['role']}, {r['status']}"
        orgs.setdefault(r["user_id"], []).append(f"{r['name']} ({role})")
    return [{"email": r["email"], "name": r["name"], "verified": bool(r["verified"]),
             "admin": bool(r["is_admin"]) or r["email"] in settings.admin_emails, "disabled": bool(r["disabled"]),
             "orgs": orgs.get(r["id"], []), "created": r["created"],
             "last_seen": max(filter(None, (r["session_seen"], r["login_seen"])), default=None)} for r in rows]


def _org_name(conn, oid):
    return conn.execute("SELECT name FROM orgs WHERE id = ?", (oid,)).fetchone()["name"]


def _holds(conn, user):
    """[(org id, org name, why)] for each organization this account can't leave yet, with what to do."""
    held = []
    for (oid,) in conn.execute("SELECT org_id FROM org_members WHERE user_id = ? ORDER BY org_id",
                               (user["id"],)).fetchall():
        last_owner, orphans = blockers(conn, oid, user["id"])
        name = _org_name(conn, oid)
        if last_owner:
            held.append((oid, name, f"they are the only owner of «{name}»: someone has to make another member owner "
                                    "(in the app, Equipo › Personas; only an owner can, so if they can't sign in, "
                                    "`enable-user` them for that)"))
        if orphans:
            held.append((oid, name, f"they are the only manager of {len(orphans)} collection(s) of «{name}» "
                                    f"({', '.join(orphans)}): a manager or org admin gives «Gestor» to someone else in "
                                    "each one (or deletes it) in the app"))
    return held


def _leave_orgs(conn, user, action, skip=()):
    """Take the account out of every organization not in `skip`. → [(org name, collections to re-key)]"""
    left = []
    for (oid,) in conn.execute("SELECT org_id FROM org_members WHERE user_id = ? ORDER BY org_id",
                               (user["id"],)).fetchall():
        if oid in skip:
            continue
        cids = drop_member(conn, oid, user["id"])
        event(conn, oid, None, action, user["email"])
        left.append((_org_name(conn, oid), len(cids)))
    return left


def disable(conn, address):
    """Block an account at once: its sessions end and it can't sign in; its data stays. It leaves every
    organization it can (their collections get re-keyed); where it is the last owner or a collection's only
    manager it stays a member (unable to sign in) until that is handed over. → (left, held)"""
    user = find(conn, address)
    conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user["id"],))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    event(conn, None, None, "user.disable", user["id"])
    held = _holds(conn, user)
    left = _leave_orgs(conn, user, "member.disable", skip={oid for oid, _, _ in held})
    return left, held


def enable(conn, address):
    """Let a disabled account sign in again. It does not get back into the organizations it left: invite it."""
    user = find(conn, address)
    if not user["disabled"]:
        return False
    conn.execute("UPDATE users SET disabled = 0 WHERE id = ?", (user["id"],))
    event(conn, None, None, "user.enable", user["id"])
    return True


def delete(conn, address):
    """Delete an account and everything only it uses (sessions, its encrypted keys and data), after taking it out of
    its organizations. Refused, changing nothing, while it is an organization's last owner or a collection's only
    manager. Audit events keep its id. → [(org name, collections to re-key)]"""
    user = find(conn, address)
    held = _holds(conn, user)
    if held:
        raise AdminError("can't delete it yet:\n" + "\n".join(f"  - {why}" for _, _, why in held)
                         + "\nThen run this again. (`disable-user` blocks the account meanwhile.)")
    left = _leave_orgs(conn, user, "member.delete")
    for table in ("sessions", "email_codes", "account_data", "collection_members", "org_members"):
        conn.execute(f"DELETE FROM {table} WHERE user_id = ?", (user["id"],))
    conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    event(conn, None, None, "user.delete", user["id"])
    return left
