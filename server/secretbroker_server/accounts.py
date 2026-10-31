"""Accounts, sessions (devices), key lookup, server info and server-admin signup tokens."""

import json

from . import __version__, security
from .db import event, now_epoch, now_iso
from .validate import ApiError, b64, body, email, integer, kdf, path_id, sealed, text, uuid_id
from .web import is_server_admin, new_id, route

BLOB_MAX = 4096


def _user(row, settings):
    return {"id": row["id"], "email": row["email"], "name": row["name"], "admin": is_server_admin(settings, row)}


def rate_limited(wait):
    return ApiError(429, "rate_limited", "Demasiados intentos. Espera un poco y vuelve a probar.", retry_after=wait)


@route("GET", "/info", auth=False)
def info(ctx):
    return {"name": ctx.settings.name, "version": __version__, "signups": ctx.settings.signups}


@route("POST", "/accounts/prelogin", auth=False, tx="read")
def prelogin(ctx):
    address = body(ctx.body, {"email": email})["email"]
    row = ctx.conn.execute("SELECT kdf FROM users WHERE email = ?", (address,)).fetchone()
    # Same answer shape for unknown e-mails, and always the same fake salt, so nobody can probe for accounts.
    return {"kdf": json.loads(row["kdf"]) if row else security.fake_kdf(ctx.server.secret, address)}


def _check_signup(ctx, address, token):
    """Who may create an account. Returns the signup-token hash to consume, if one was used.

    E-mail ownership is not verified, so an SB_ADMIN_EMAILS address always needs a signup token (from the
    `secretbroker-server create-invite` command), in every mode: otherwise whoever registers it first is admin."""
    settings = ctx.settings
    admin = address in settings.admin_emails
    if settings.signups == "open" and not admin:
        return None
    if settings.signups == "closed" and not admin:
        raise ApiError(403, "signups_closed", "Este servidor no admite cuentas nuevas.")
    if token:
        try:
            invite_id = None if admin else uuid_id(token)
        except ApiError:
            invite_id = None
        if invite_id and ctx.conn.execute("SELECT 1 FROM invites WHERE id = ? AND email = ?",
                                          (invite_id, address)).fetchone():
            return None
        digest = security.token_hash(token)
        if ctx.conn.execute("SELECT 1 FROM signup_tokens WHERE token_hash = ? AND used_by IS NULL AND expires > ?",
                            (digest, now_epoch())).fetchone():
            return digest
    if admin:
        raise ApiError(403, "invite_required", "Para crear la cuenta de administrador necesitas un código de "
                       "invitación: genéralo en el servidor con «secretbroker-server create-invite».")
    raise ApiError(403, "invite_required", "Necesitas una invitación para crear una cuenta en este servidor.")


@route("POST", "/accounts/register", auth=False)
def register(ctx):
    wait = ctx.server.signup_throttle.retry_after(ctx.ip)
    if wait:
        raise rate_limited(wait)
    ctx.server.signup_throttle.fail(ctx.ip)  # every attempt counts: accounts are cheap to create otherwise
    data = body(ctx.body, {
        "user_id": uuid_id, "email": email, "name": text(100), "kdf": kdf, "auth_hash": b64(32),
        "public_key": b64(32), "signing_public_key": b64(32), "private_blob": sealed(BLOB_MAX),
    }, {"invite_token": text(200)})
    token_digest = _check_signup(ctx, data["email"], data["invite_token"])
    conn = ctx.conn
    if conn.execute("SELECT 1 FROM users WHERE id = ?", (data["user_id"],)).fetchone():
        raise ApiError(409, "exists", "Ese id de usuario ya existe.")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (data["email"],)).fetchone():
        raise ApiError(409, "email_taken", "Ya hay una cuenta con ese e-mail.")
    first = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    salt = security.new_salt()
    conn.execute(
        "INSERT INTO users (id, email, name, kdf, auth_salt, auth_verifier, public_key, signing_public_key, "
        "private_blob, is_admin, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (data["user_id"], data["email"], data["name"], json.dumps(data["kdf"]), salt,
         security.verifier(data["auth_hash"], salt), data["public_key"], data["signing_public_key"],
         json.dumps(data["private_blob"]), int(first or data["email"] in ctx.settings.admin_emails), now_iso()))
    if token_digest:
        conn.execute("UPDATE signup_tokens SET used_by = ? WHERE token_hash = ?", (data["user_id"], token_digest))
    event(conn, None, data["user_id"], "register", data["user_id"])
    return {"user_id": data["user_id"]}


@route("POST", "/accounts/login", auth=False, tx=False)
def login(ctx):
    data = body(ctx.body, {"email": email, "auth_hash": b64(32), "device_name": text(100)})
    address, server = data["email"], ctx.server
    wait = max(server.ip_throttle.retry_after(ctx.ip), server.email_throttle.retry_after(address))
    if wait:
        raise rate_limited(wait)
    user = ctx.db.conn().execute("SELECT * FROM users WHERE email = ?", (address,)).fetchone()
    if user:
        ok = security.verify(data["auth_hash"], user["auth_salt"], user["auth_verifier"])
    else:  # same work as a real check, so timing does not reveal whether the account exists
        security.verifier(data["auth_hash"], security.fake_kdf(server.secret, address)["salt"])
        ok = False
    if not ok:
        server.ip_throttle.fail(ctx.ip)
        server.email_throttle.fail(address)
        raise ApiError(401, "invalid_credentials", "E-mail o contraseña incorrectos.")
    server.email_throttle.reset(address)
    token, session_id, now = security.new_token(), new_id(), now_epoch()
    with ctx.db.tx(write=True) as conn:
        conn.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, device_name, created, last_seen, touched, expires) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, user["id"], security.token_hash(token), data["device_name"], now_iso(), now_iso(), now,
             now + ctx.settings.session_days * 86400))
        event(conn, None, user["id"], "login", session_id)
    return {"token": token, "user": _user(user, ctx.settings), "kdf": json.loads(user["kdf"]),
            "private_blob": json.loads(user["private_blob"]), "public_key": user["public_key"],
            "signing_public_key": user["signing_public_key"]}


@route("POST", "/accounts/logout")
def logout(ctx):
    ctx.conn.execute("DELETE FROM sessions WHERE id = ?", (ctx.session_id,))
    return {}


@route("GET", "/me")
def me(ctx):
    rows = ctx.conn.execute("SELECT id, device_name, created, last_seen FROM sessions WHERE user_id = ? "
                            "AND expires > ? ORDER BY created", (ctx.uid, now_epoch())).fetchall()
    devices = [{"id": r["id"], "name": r["device_name"], "created": r["created"], "last_seen": r["last_seen"],
                "current": r["id"] == ctx.session_id} for r in rows]
    return {"user": _user(ctx.user, ctx.settings), "devices": devices}


@route("DELETE", "/me/devices/{sid}")
def revoke_device(ctx):
    sid = path_id(ctx.params["sid"])
    if not ctx.conn.execute("DELETE FROM sessions WHERE id = ? AND user_id = ?", (sid, ctx.uid)).rowcount:
        raise ApiError(404, "not_found", "Ese dispositivo no existe.")
    event(ctx.conn, None, ctx.uid, "device.revoke", sid)
    return {}


@route("POST", "/accounts/password", tx=False)
def change_password(ctx):
    """New password (and re-wrapped keys). Needs the current one, so a stolen session cannot take the account;
    wrong guesses count against the same limits as logins. 403, not 401: the session itself is fine."""
    data = body(ctx.body, {"current_auth_hash": b64(32), "kdf": kdf, "auth_hash": b64(32),
                           "private_blob": sealed(BLOB_MAX)})
    server, address = ctx.server, ctx.user["email"]
    wait = max(server.ip_throttle.retry_after(ctx.ip), server.email_throttle.retry_after(address))
    if wait:
        raise rate_limited(wait)
    row = ctx.db.conn().execute("SELECT auth_salt, auth_verifier FROM users WHERE id = ?", (ctx.uid,)).fetchone()
    if not security.verify(data["current_auth_hash"], row["auth_salt"], row["auth_verifier"]):
        server.ip_throttle.fail(ctx.ip)
        server.email_throttle.fail(address)
        with ctx.db.tx(write=True) as conn:
            event(conn, None, ctx.uid, "password.fail", ctx.uid)
        raise ApiError(403, "invalid_credentials", "La contraseña actual no es correcta.")
    server.email_throttle.reset(address)
    salt = security.new_salt()
    with ctx.db.tx(write=True) as conn:
        conn.execute("UPDATE users SET kdf = ?, auth_salt = ?, auth_verifier = ?, private_blob = ? WHERE id = ?",
                     (json.dumps(data["kdf"]), salt, security.verifier(data["auth_hash"], salt),
                      json.dumps(data["private_blob"]), ctx.uid))
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (ctx.uid, ctx.session_id))
        event(conn, None, ctx.uid, "password.change", ctx.uid)
    return {}


KEYS_BATCH_MAX = 200
# Who may read whose public keys: yourself, org mates, or people invited to an org you belong to.
_KEYS_SQL = ("SELECT u.id, u.email, u.name, u.public_key, u.signing_public_key FROM users u WHERE u.id = ? AND ("
             " u.id = ?"
             " OR EXISTS (SELECT 1 FROM org_members a JOIN org_members b ON a.org_id = b.org_id"
             "            WHERE a.user_id = ? AND b.user_id = u.id)"
             " OR EXISTS (SELECT 1 FROM invites i JOIN org_members a ON a.org_id = i.org_id"
             "            WHERE a.user_id = ? AND i.email = u.email))")


@route("GET", "/users/{uid}/keys")
def user_keys(ctx):
    """Public keys of people you work with: org mates, or people invited to an org you belong to."""
    uid = path_id(ctx.params["uid"])
    row = ctx.conn.execute(_KEYS_SQL, (uid, ctx.uid, ctx.uid, ctx.uid)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "No existe.")
    return dict(row)


@route("GET", "/users/keys")
def users_keys(ctx):
    """The same for several people at once (`?ids=a,b,c`, at most 200): one request to show a team's members.
    People you may not see are left out, exactly as if they did not exist."""
    raw = [part for part in str(ctx.query.get("ids", "")).split(",") if part]
    if len(raw) > KEYS_BATCH_MAX:
        raise ApiError(400, "invalid", f"ids: como mucho {KEYS_BATCH_MAX}.")
    ids = list(dict.fromkeys(uuid_id(part) for part in raw))
    rows = (ctx.conn.execute(_KEYS_SQL, (uid, ctx.uid, ctx.uid, ctx.uid)).fetchone() for uid in ids)
    return [dict(row) for row in rows if row is not None]


@route("POST", "/admin/invites")
def create_signup_token(ctx):
    """Server admins hand out single-use tokens that let someone register when SB_SIGNUPS=invite."""
    if not is_server_admin(ctx.settings, ctx.user):
        raise ApiError(403, "forbidden", "Solo un administrador del servidor puede hacer esto.")
    days = body(ctx.body, {}, {"days": integer(1, 90)})["days"] or 7
    token, expires = create_token(ctx.conn, ctx.uid, days)
    return {"token": token, "expires": expires}


def create_token(conn, created_by, days):
    token = "sbi_" + security.new_token()
    expires = now_epoch() + days * 86400
    conn.execute("INSERT INTO signup_tokens (token_hash, created, created_by, expires) VALUES (?, ?, ?, ?)",
                 (security.token_hash(token), now_iso(), created_by, expires))
    event(conn, None, created_by, "signup_token.create", None)
    return token, expires
