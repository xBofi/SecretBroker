"""Command line: `secretbroker-server serve | create-invite | verify-email | unverified | stats`.
Configuration comes from SB_* variables."""

import argparse
import logging
import sys

from . import __version__, config
from .db import Database, now_epoch


def _settings():
    try:
        return config.from_env().check()
    except config.ConfigError as exc:
        sys.exit(f"secretbroker-server: {exc}")


def serve(args):
    import uvicorn

    from .web import create_app

    settings = _settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print(f"SecretBroker Server {__version__}: data in {settings.data_dir}, signups {settings.signups}, "
          f"e-mail verification {settings.verification}", flush=True)
    if settings.verification == "admin":
        print("No SMTP server (SB_SMTP_HOST): verify new accounts with `secretbroker-server verify-email <e-mail>`, "
              "or set SB_EMAIL_VERIFICATION=off to turn verification off.", flush=True)
    uvicorn.run(create_app(settings), host=args.host, port=args.port, server_header=False, proxy_headers=False,
                log_level="info")


def create_invite(args):
    """Print a single-use signup token (needed when SB_SIGNUPS=invite). Only its hash is stored."""
    from .accounts import create_token

    settings = _settings()
    db = Database(settings.db_path)
    with db.tx(write=True) as conn:
        token, _ = create_token(conn, None, args.days)
    db.close()
    print(token)
    print(f"Valid for {args.days} days, once. Give it to the person who will register.", file=sys.stderr)


def verify_email(args):
    """Mark an account's e-mail as verified: for servers without SMTP, after checking who the person is."""
    from .accounts import mark_verified
    from .validate import ApiError, email

    settings = _settings()
    try:
        address = email(args.email)
    except ApiError:
        sys.exit(f"secretbroker-server: not an e-mail address: {args.email}")
    db = Database(settings.db_path)
    with db.tx(write=True) as conn:
        row = conn.execute("SELECT id, verified FROM users WHERE email = ?", (address,)).fetchone()
        if row and not row["verified"]:
            mark_verified(conn, row["id"], None)
    db.close()
    if row is None:
        sys.exit(f"secretbroker-server: no account with the e-mail {address}")
    print(f"{address} {'was already verified' if row['verified'] else 'is verified now'}.")


def unverified(args):
    """List accounts still waiting for e-mail verification."""
    settings = _settings()
    db = Database(settings.db_path)
    for row in db.conn().execute("SELECT email, name, created FROM users WHERE verified = 0 ORDER BY created"):
        print(f"{row['email']:40} {row['name']:24} {row['created']}")
    db.close()


def stats(args):
    settings = _settings()
    db = Database(settings.db_path)
    conn = db.conn()
    for label, sql in (("users", "SELECT COUNT(*) FROM users"),
                       ("organizations", "SELECT COUNT(*) FROM orgs"),
                       ("collections", "SELECT COUNT(*) FROM collections"),
                       ("items", "SELECT COUNT(*) FROM items WHERE deleted = 0"),
                       ("active sessions", f"SELECT COUNT(*) FROM sessions WHERE expires > {now_epoch()}"),
                       ("pending invites", "SELECT COUNT(*) FROM invites")):
        print(f"{label:16} {conn.execute(sql).fetchone()[0]}")
    db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="secretbroker-server", description="SecretBroker team sync server")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("serve", help="run the HTTP server")
    run.add_argument("--host", default="0.0.0.0")
    run.add_argument("--port", type=int, default=8080)
    run.set_defaults(func=serve)
    invite = sub.add_parser("create-invite", help="print a single-use signup token")
    invite.add_argument("--days", type=int, default=7, choices=range(1, 91), metavar="1-90")
    invite.set_defaults(func=create_invite)
    verify = sub.add_parser("verify-email", help="mark an account's e-mail as verified (servers without SMTP)")
    verify.add_argument("email")
    verify.set_defaults(func=verify_email)
    sub.add_parser("unverified", help="list accounts that have not verified their e-mail").set_defaults(func=unverified)
    sub.add_parser("stats", help="print counts (never contents)").set_defaults(func=stats)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
