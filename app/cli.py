"""Command-line interface for administration tasks.

    python -m app.cli passwd [--config watchtail.yml]
    python -m app.cli set-password --password 's3cret' [--username ops]

``passwd`` prompts for the new password twice without echoing; when
``--password`` is given it is used directly (handy for provisioning
scripts). The admin username defaults to ``admin``; the account is
created when missing. Everything else (database URL resolution,
working directory) matches the server exactly.
"""

import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash

from .config import load_config
from .database import configure_engine, session_scope
from .models import AdminUser
from . import resolve_database_url


def set_password(config_path=None, username="admin", password=None):
    """Set (or create) an admin account's password in the database."""
    settings = load_config(config_path)
    configure_engine(resolve_database_url(settings))

    if password is None:
        password = getpass.getpass("New password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 2
    if not password:
        print("error: password must not be empty", file=sys.stderr)
        return 2

    with session_scope() as session:
        user = session.get(AdminUser, username)
        if user is None:
            session.add(
                AdminUser(
                    username=username,
                    password_hash=generate_password_hash(password),
                )
            )
            print(f"created admin account {username!r}")
        else:
            user.password_hash = generate_password_hash(password)
            print(f"password updated for {username!r}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cli", description="Watchtail administration CLI"
    )
    parser.add_argument("--config", default=None, help="path to watchtail.yml")
    sub = parser.add_subparsers(dest="command", required=True)

    passwd = sub.add_parser("passwd", help="set or reset the admin password")
    passwd.add_argument("--username", default="admin")
    passwd.add_argument("--password", default=None, help="new password (else prompted)")

    args = parser.parse_args(argv)
    if args.command == "passwd":
        return set_password(args.config, username=args.username, password=args.password)
    parser.error(f"unknown command {args.command!r}")


if __name__ == "__main__":
    sys.exit(main())
