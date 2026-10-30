"""Command line: `secretbroker-server serve | create-invite | stats`. Configuration comes from SB_* variables."""

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
    print(f"SecretBroker Server {__version__}: data in {settings.data_dir}, signups {settings.signups}", flush=True)
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
    sub.add_parser("stats", help="print counts (never contents)").set_defaults(func=stats)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
