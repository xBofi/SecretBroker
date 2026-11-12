"""Command line: `secretbroker-server serve | create-invite | verify-email | unverified | stats | users |
disable-user | enable-user | delete-user | backup | restore`. Configuration comes from SB_* variables."""

import argparse
import logging
import os
import sys
import time

from . import __version__, config
from .db import Database, now_epoch

RETRY_SECONDS = 600  # a scheduled backup that failed is tried again this soon


def _settings():
    try:
        return config.from_env().check()
    except config.ConfigError as exc:
        sys.exit(f"secretbroker-server: {exc}")


def _data_dir():
    """Only the data folder (backup, restore): these don't need the rest of the configuration."""
    try:
        return config.from_env().data_dir
    except config.ConfigError as exc:
        sys.exit(f"secretbroker-server: {exc}")


def serve(args):
    import uvicorn

    from .backup import take_lock
    from .web import create_app

    settings = _settings()
    lock = take_lock(settings.data_dir)  # held until the process ends: restore refuses meanwhile
    if lock is None:
        sys.exit(f"secretbroker-server: another server is already running on {settings.data_dir}")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print(f"SecretBroker Server {__version__}: data in {settings.data_dir}, signups {settings.signups}, "
          f"e-mail verification {settings.verification}", flush=True)
    if settings.verification == "admin":
        print("No SMTP server (SB_SMTP_HOST): verify new accounts with `secretbroker-server verify-email <e-mail>`, "
              "or set SB_EMAIL_VERIFICATION=off to turn verification off.", flush=True)
    uvicorn.run(create_app(settings), host=args.host, port=args.port, server_header=False, proxy_headers=False,
                log_level="info")


def create_invite(args):
    """Print a single-use signup token (needed when SB_SIGNUPS=invite). Only its hash is stored. With --email, only
    that address can use it (the installer makes the admin's this way)."""
    from .accounts import create_token
    from .db import admin_event

    settings = _settings()
    address = _email_arg(args.email) if args.email else None
    db = Database(settings.db_path)
    with db.tx(write=True) as conn:
        token, _ = create_token(conn, None, args.days, address)
        admin_event(conn, None, "cli", "signup_token.create", None, {"email": address, "days": args.days})
    db.close()
    print(token)
    print(f"Valid for {args.days} days, once" + (f", only for {address}" if address else "")
          + ". Give it to the person who will register.", file=sys.stderr)


def verify_email(args):
    """Mark an account's e-mail as verified: for servers without SMTP, after checking who the person is."""
    from . import admin

    changed = _admin(admin.verify, args)
    print(f"{args.email} {'is verified now' if changed else 'was already verified'}.")


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


def _email_arg(value):
    from .validate import ApiError, email
    try:
        return email(value)
    except ApiError:
        sys.exit(f"secretbroker-server: not an e-mail address: {value}")


def _admin(action, args):
    from . import admin

    settings = _settings()
    db = Database(settings.db_path)
    try:
        with db.tx(write=True) as conn:
            return action(conn, admin.find(conn, _email_arg(args.email)))
    except admin.AdminError as exc:
        sys.exit(f"secretbroker-server: {exc}")
    finally:
        db.close()


def list_users(args):
    """Accounts and where they belong. Never secrets: the server has none."""
    from . import admin

    settings = _settings()
    db = Database(settings.db_path)
    rows = admin.users(db.conn(), settings)
    db.close()
    for r in rows:
        flags = ", ".join(f for f, on in (("admin", r["admin"]), ("unverified", not r["verified"]),
                                           ("DISABLED", r["disabled"])) if on)
        print(f"{r['email']}  {r['name']}" + (f"  [{flags}]" if flags else ""))
        orgs = [f"{o['name']} ({o['role']}" + (f", {o['status']})" if o["status"] != "confirmed" else ")")
                for o in r["orgs"]]
        print(f"    orgs: {'; '.join(orgs) or '-'}")
        print(f"    created {r['created']}, last seen {r['last_seen'] or 'never'}")
    print(f"{len(rows)} account(s).", file=sys.stderr)


def _left(left):
    for org in left:
        name, count = org["name"], org["collections"]
        print(f"  left «{name}»" + (f": {count} collection(s) will be re-keyed by their managers' apps on their next "
                                    "sync, and their credentials flagged to rotate" if count else ""))


def disable_user(args):
    from . import admin

    left, held = _admin(admin.disable, args)
    print(f"{args.email} is disabled: its sessions are revoked and it can't sign in. Its data is kept.")
    _left(left)
    if held:
        print("It stays a member (unable to sign in) where it can't leave yet:")
        for hold in held:
            print(f"  - {hold['why']}")
        print("Once that is done, run disable-user again to take it out.")


def enable_user(args):
    from . import admin

    if _admin(admin.enable, args):
        print(f"{args.email} can sign in again. It is not back in the organizations it left: invite it again.")
    else:
        print(f"{args.email} was not disabled.")


def delete_user(args):
    from . import admin

    if not args.yes:
        sys.exit("secretbroker-server: this deletes the account for good (its encrypted keys too: it can't come "
                 "back). Add --yes to confirm.")
    left = _admin(admin.delete, args)
    print(f"{args.email} is deleted.")
    _left(left)


def transfer_owner(args):
    from . import admin

    name, already = _admin(lambda conn, user: admin.transfer_owner(conn, admin.find_org(conn, args.org), user), args)
    print(f"{args.email} {'was already' if already else 'is now'} an owner of «{name}».")


def run_backup(args):
    from .backup import BackupError, backup

    try:
        settings = config.from_env()
    except config.ConfigError as exc:
        sys.exit(f"secretbroker-server: {exc}")
    data_dir = settings.data_dir
    dest = args.dir or str(settings.backups_path)
    keep = args.keep or settings.backup_keep
    while True:
        try:
            path, pruned = backup(data_dir, dest, keep)
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} backup written: {path}"
                  + (f" ({len(pruned)} old one(s) deleted)" if pruned else ""), flush=True)
            wait = args.every * 3600
        except (BackupError, OSError) as exc:
            if not args.every:
                sys.exit(f"secretbroker-server: backup failed: {exc}")
            # The first start of a new server: the database may not exist yet. Try again soon, not tomorrow.
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} backup failed, retrying in 10 minutes: {exc}",
                  file=sys.stderr, flush=True)
            wait = min(args.every * 3600, RETRY_SECONDS)
        if not args.every:
            return
        time.sleep(wait)


def run_restore(args):
    from .backup import BackupError, restore

    data_dir = _data_dir()
    try:
        aside = restore(data_dir, args.file)
    except BackupError as exc:
        sys.exit(f"secretbroker-server: {exc}")
    print(f"Restored {args.file} into {data_dir}." + (f" The previous files are in {aside}." if aside else "")
          + " Start the server again; the schema is brought up to date on start.")


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
    invite.add_argument("--email", help="only this e-mail can register with it")
    invite.set_defaults(func=create_invite)
    verify = sub.add_parser("verify-email", help="mark an account's e-mail as verified (servers without SMTP)")
    verify.add_argument("email")
    verify.set_defaults(func=verify_email)
    sub.add_parser("unverified", help="list accounts that have not verified their e-mail").set_defaults(func=unverified)
    sub.add_parser("stats", help="print counts (never contents)").set_defaults(func=stats)
    sub.add_parser("users", help="list accounts: e-mail, name, verified, admin, orgs, last seen").set_defaults(
        func=list_users)
    for name, func, text in (("disable-user", disable_user, "revoke an account's sessions, block its sign-in and take "
                              "it out of its organizations (its collections get re-keyed); its data stays"),
                             ("enable-user", enable_user, "let a disabled account sign in again"),
                             ("delete-user", delete_user, "take an account out of its organizations and delete it")):
        command = sub.add_parser(name, help=text)
        command.add_argument("email")
        if name == "delete-user":
            command.add_argument("--yes", action="store_true", help="confirm: it can't be undone")
        command.set_defaults(func=func)
    owner = sub.add_parser("transfer-owner", help="make a confirmed member of an organization its owner (for an "
                                                  "organization whose only owner can't sign in)")
    owner.add_argument("org", help="the organization's id, or its exact name")
    owner.add_argument("email")
    owner.set_defaults(func=transfer_owner)
    save = sub.add_parser("backup", help="write a consistent backup (database + server secret) and prune old ones")
    save.add_argument("--dir", help="where to write it (default: SB_BACKUP_DIR, or SB_DATA_DIR/backups)")
    save.add_argument("--keep", type=int, default=0, help="how many backups to keep (default: SB_BACKUP_KEEP, 14)")
    save.add_argument("--every", type=float, default=0, metavar="HOURS",
                      help="keep running and make one every HOURS (the Compose backup service uses 24)")
    save.set_defaults(func=run_backup)
    load = sub.add_parser("restore", help="put a backup in place (the server must be stopped)")
    load.add_argument("file")
    load.set_defaults(func=run_restore)
    args = parser.parse_args(argv)
    if os.name == "posix":
        os.umask(0o077)  # every file the server writes is its own only
    args.func(args)


if __name__ == "__main__":
    main()
