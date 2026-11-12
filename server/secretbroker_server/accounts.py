"""Accounts, sessions (devices), e-mail verification, key lookup, server info and server-admin signup tokens."""

import hmac
import json
import logging
import sqlite3
import threading

from . import __version__, config, mail, security
from .db import event, now_epoch, now_iso
from .validate import ApiError, b64, body, email, integer, kdf, name, path_id, sealed, text, uuid_id
from .web import is_server_admin, new_id, route

log = logging.getLogger("secretbroker_server")

BLOB_MAX = 4096
ACCOUNT_DATA_MAX = 256 * 1024  # the account's own encrypted data (pins of verified people), see /me/data


def _user(row, settings):
    return {"id": row["id"], "email": row["email"], "name": row["name"], "admin": is_server_admin(settings, row),
            "verified": bool(row["verified"])}


def rate_limited(wait):
    return ApiError(429, "rate_limited", "Demasiados intentos. Espera un poco y vuelve a probar.", retry_after=wait)


@route("GET", "/info", auth=False, any_client=True)
def info(ctx):
    """What a client checks before anything else: `api` (the protocol, config.API_VERSION) and `min_client` (the
    oldest app served), so either side can tell the user which one to update."""
    return {"name": ctx.settings.name, "version": __version__, "signups": ctx.settings.signups,
            "verification": ctx.settings.verification, "api": config.API_VERSION,
            "min_client": ctx.settings.oldest_client, "mail": ctx.settings.smtp}


@route("GET", "/health", auth=False, tx=False, any_client=True)
def health(ctx):
    """For Docker and uptime monitors: no authentication, says nothing but whether the database answers."""
    try:
        ctx.db.conn().execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error:
        log.warning("Health check: the database does not answer")
        return 503, {"status": "unavailable"}
    return {"status": "ok"}


@route("POST", "/accounts/prelogin", auth=False, tx="read")
def prelogin(ctx):
    address = body(ctx.body, {"email": email})["email"]
    row = ctx.conn.execute("SELECT kdf FROM users WHERE email = ?", (address,)).fetchone()
    # Same answer shape for unknown e-mails, and always the same fake salt, so nobody can probe for accounts.
    return {"kdf": json.loads(row["kdf"]) if row else security.fake_kdf(ctx.server.secret, address)}


def _org_invite(ctx, address, token):
    """The organization of the pending invite whose id is `token`, if it is for this very e-mail (None otherwise).
    That organization's admin handed the code to the person they invited, so it shows the address is theirs to
    that organization only: any account can create an organization and invite any address, so it never verifies
    the address for the invites of others (users.invited_to)."""
    try:
        invite_id = uuid_id(token)
    except ApiError:
        return None
    row = ctx.conn.execute("SELECT org_id FROM invites WHERE id = ? AND email = ? AND COALESCE(expires, ?) > ?",
                           (invite_id, address, 2**62, now_epoch())).fetchone()
    return row["org_id"] if row else None


def _check_signup(ctx, address, token):
    """Who may create an account. Returns the signup-token hash to consume, if one was used.

    An SB_ADMIN_EMAILS address always needs a signup token (from the `secretbroker-server create-invite` command),
    in every mode: otherwise whoever registers it first would be admin before verifying anything."""
    settings = ctx.settings
    admin = address in settings.admin_emails
    if settings.signups == "open" and not admin:
        return None
    if settings.signups == "closed" and not admin:
        raise ApiError(403, "signups_closed", "Este servidor no admite cuentas nuevas.")
    if token:
        if not admin and _org_invite(ctx, address, token):
            return None
        digest = security.token_hash(token)
        row = ctx.conn.execute("SELECT email FROM signup_tokens WHERE token_hash = ? AND used_by IS NULL AND "
                               "expires > ?", (digest, now_epoch())).fetchone()
        # A token made for one address (the installer's, for the admin) works for that address only.
        if row and (row["email"] is None or row["email"] == address):
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
        "user_id": uuid_id, "email": email, "name": name(100), "kdf": kdf, "auth_hash": b64(32),
        "public_key": b64(32), "signing_public_key": b64(32), "private_blob": sealed(BLOB_MAX),
    }, {"invite_token": text(200)})
    token_digest = _check_signup(ctx, data["email"], data["invite_token"])
    conn = ctx.conn
    if conn.execute("SELECT 1 FROM users WHERE id = ?", (data["user_id"],)).fetchone():
        raise ApiError(409, "exists", "Ese id de usuario ya existe.")
    verified = ctx.settings.verification == "off"
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (data["email"],)).fetchone():
        # The same answer as a new account (nothing is created; the client's login then fails), so a sign-up
        # does not tell anyone which addresses have an account here (prelogin doesn't either), nor sooner.
        security.verifier(data["auth_hash"], security.new_salt())
        return {"user_id": data["user_id"], "verified": verified}
    first = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    invited_to = None if verified or not data["invite_token"] else _org_invite(ctx, data["email"], data["invite_token"])
    salt = security.new_salt()
    conn.execute(
        "INSERT INTO users (id, email, name, kdf, auth_salt, auth_verifier, public_key, signing_public_key, "
        "private_blob, is_admin, verified, invited_to, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (data["user_id"], data["email"], data["name"], json.dumps(data["kdf"]), salt,
         security.verifier(data["auth_hash"], salt), data["public_key"], data["signing_public_key"],
         json.dumps(data["private_blob"]), int(first or data["email"] in ctx.settings.admin_emails), int(verified),
         invited_to, now_iso()))
    if token_digest:
        conn.execute("UPDATE signup_tokens SET used_by = ? WHERE token_hash = ?", (data["user_id"], token_digest))
    event(conn, None, data["user_id"], "register", data["user_id"])
    if not verified and ctx.settings.smtp:
        _send_code(ctx, conn, data["user_id"], data["email"])
    return {"user_id": data["user_id"], "verified": verified, **({"invited_to": invited_to} if invited_to else {})}


# ---------------------------------------------------------------------- e-mail verification
#
# Organization invites are addressed to an e-mail; until the account proves it owns that address (a code sent by
# e-mail, or the admin from the command line) it cannot see or accept invites, and nobody's invites expose it, so
# registering someone else's address first gains nothing. Registering with an invite code only opens the invites
# of the organization that handed it out (users.invited_to).

def _send_code(ctx, conn, user_id, address):
    """A fresh code, stored as an HMAC, e-mailed in the background (an SMTP server may take seconds)."""
    code, now = mail.new_code(), now_epoch()
    conn.execute("INSERT INTO email_codes (user_id, code_hash, expires, attempts, sent) VALUES (?, ?, ?, 0, ?) "
                 "ON CONFLICT (user_id) DO UPDATE SET code_hash = excluded.code_hash, expires = excluded.expires, "
                 "attempts = 0, sent = excluded.sent",
                 (user_id, mail.code_hash(ctx.server.secret, user_id, code), now + mail.CODE_SECONDS, now))
    threading.Thread(target=mail.send_code, args=(ctx.settings, address, code), daemon=True).start()


@route("POST", "/accounts/verify/send")
def send_verification(ctx):
    """E-mail a new code to this account's address (at most one a minute)."""
    body(ctx.body, {})
    if ctx.user["verified"]:
        return {"verified": True, "sent": False}
    if not ctx.settings.smtp:
        return {"verified": False, "sent": False, "verification": ctx.settings.verification}
    row = ctx.conn.execute("SELECT sent FROM email_codes WHERE user_id = ?", (ctx.uid,)).fetchone()
    wait = row["sent"] + mail.RESEND_SECONDS - now_epoch() if row else 0
    if wait > 0:
        raise rate_limited(wait)
    _send_code(ctx, ctx.conn, ctx.uid, ctx.user["email"])
    return {"verified": False, "sent": True}


@route("POST", "/accounts/verify", tx=False)
def verify_email(ctx):
    """The code from the e-mail. Wrong tries count (5 per code: the count is saved before answering), and an
    expired code needs a new one."""
    code = "".join(ch for ch in body(ctx.body, {"code": text(20)})["code"] if ch.isdigit())
    if ctx.user["verified"]:
        return {"verified": True}
    error = None
    with ctx.db.tx(write=True) as conn:
        row = conn.execute("SELECT * FROM email_codes WHERE user_id = ?", (ctx.uid,)).fetchone()
        if row is None or row["expires"] <= now_epoch() or row["attempts"] >= mail.CODE_TRIES:
            error = ApiError(400, "code_expired", "Ese código ha caducado. Pide uno nuevo.")
        elif not hmac.compare_digest(mail.code_hash(ctx.server.secret, ctx.uid, code), row["code_hash"]):
            conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = ?", (ctx.uid,))
            left = mail.CODE_TRIES - row["attempts"] - 1
            error = ApiError(400, "invalid_code", "El código no es correcto." + (
                f" Te quedan {left} intentos." if left else " Pide uno nuevo."))
        else:
            mark_verified(conn, ctx.uid, ctx.uid)
    if error:
        raise error
    return {"verified": True}


def mark_verified(conn, user_id, actor):
    conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM email_codes WHERE user_id = ?", (user_id,))
    event(conn, None, actor, "email.verify", user_id)


@route("POST", "/accounts/login", auth=False, tx=False)
def login(ctx):
    data = body(ctx.body, {"email": email, "auth_hash": b64(32), "device_name": name(100)})
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
    if user["disabled"]:  # told only to whoever knows the password
        raise ApiError(403, "account_disabled", "Esta cuenta está desactivada en este servidor. Habla con quien lo "
                       "administra.")
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


@route("GET", "/me/data")
def get_account_data(ctx):
    """The account's own encrypted data, shared by all its devices (the people it verified). Opaque here."""
    row = ctx.conn.execute("SELECT blob, revision FROM account_data WHERE user_id = ?", (ctx.uid,)).fetchone()
    return {"blob": json.loads(row["blob"]) if row else None, "revision": row["revision"] if row else 0}


@route("PUT", "/me/data")
def put_account_data(ctx):
    data = body(ctx.body, {"blob": sealed(ACCOUNT_DATA_MAX), "base_revision": integer(0, 2**62)})
    row = ctx.conn.execute("SELECT revision FROM account_data WHERE user_id = ?", (ctx.uid,)).fetchone()
    current = row["revision"] if row else 0
    if data["base_revision"] != current:
        raise ApiError(409, "conflict", "Otro dispositivo lo cambió antes.", revision=current)
    ctx.conn.execute("INSERT INTO account_data (user_id, blob, revision) VALUES (?, ?, ?) ON CONFLICT (user_id) "
                     "DO UPDATE SET blob = excluded.blob, revision = excluded.revision",
                     (ctx.uid, json.dumps(data["blob"]), current + 1))
    return {"revision": current + 1}


KEYS_BATCH_MAX = 200
# Who may read whose public keys: yourself, org mates, or people invited to an org you belong to (only once their
# account verified that e-mail: an unverified account that took someone's address must not get their invites).
_KEYS_SQL = ("SELECT u.id, u.email, u.name, u.public_key, u.signing_public_key FROM users u WHERE u.id = ? AND ("
             " u.id = ?"
             " OR EXISTS (SELECT 1 FROM org_members a JOIN org_members b ON a.org_id = b.org_id"
             "            WHERE a.user_id = ? AND b.user_id = u.id)"
             " OR EXISTS (SELECT 1 FROM invites i JOIN org_members a ON a.org_id = i.org_id"
             "            WHERE a.user_id = ? AND i.email = u.email AND (u.verified = 1 OR u.invited_to = i.org_id)))")


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


def create_token(conn, created_by, days, address=None):
    """A single-use signup token; with `address`, only that e-mail can register with it."""
    token = "sbi_" + security.new_token()
    expires = now_epoch() + days * 86400
    conn.execute("INSERT INTO signup_tokens (token_hash, created, created_by, expires, email) VALUES (?, ?, ?, ?, ?)",
                 (security.token_hash(token), now_iso(), created_by, expires, address))
    event(conn, None, created_by, "signup_token.create", None)
    return token, expires
