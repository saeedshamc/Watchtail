"""Command-line interface for administration tasks.

    python -m app.cli passwd [--config watchtail.yml]
    python -m app.cli passwd --username ops --password 's3cret'
    python -m app.cli user-add viewer1 --role viewer

``passwd`` prompts for the new password twice without echoing; when
``--password`` is given it is used directly (handy for provisioning
scripts). ``user-add`` creates additional accounts — admins may change
state, viewers read only. Database URL resolution matches the server.
"""

import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash

from . import resolve_database_url
from .config import load_config
from .database import configure_engine, session_scope
from .models import AdminUser
from . import resolve_database_url


def set_password(config_path=None, username="admin", password=None):
    """Set (or create) an account's password in the database."""
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


def add_user(config_path=None, username="", role="viewer", password=None):
    """Create an additional dashboard account with the given role."""
    if not username:
        print("error: username is required", file=sys.stderr)
        return 2
    if role not in ("admin", "viewer"):
        print("error: role must be 'admin' or 'viewer'", file=sys.stderr)
        return 2

    settings = load_config(config_path)
    configure_engine(resolve_database_url(settings))

    if password is None:
        password = getpass.getpass(f"Password for {username}: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 2
    if not password:
        print("error: password must not be empty", file=sys.stderr)
        return 2

    with session_scope() as session:
        if session.get(AdminUser, username) is not None:
            print(f"error: account {username!r} already exists", file=sys.stderr)
            return 2
        session.add(
            AdminUser(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
            )
        )
    print(f"created {role} account {username!r}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cli", description="Watchtail administration CLI"
    )
    parser.add_argument("--config", default=None, help="path to watchtail.yml")
    sub = parser.add_subparsers(dest="command", required=True)

    passwd = sub.add_parser("passwd", help="set or reset an account password")
    passwd.add_argument("--username", default="admin")
    passwd.add_argument("--password", default=None, help="new password (else prompted)")

    user_add = sub.add_parser("user-add", help="create an additional account")
    user_add.add_argument("username")
    user_add.add_argument(
        "--role", choices=("admin", "viewer"), default="viewer",
        help="account role (default: viewer)",
    )
    user_add.add_argument("--password", default=None, help="password (else prompted)")

    args = parser.parse_args(argv)
    if args.command == "passwd":
        return set_password(args.config, username=args.username, password=args.password)
    if args.command == "user-add":
        return add_user(
            args.config, username=args.username, role=args.role,
            password=args.password,
        )
    parser.error(f"unknown command {args.command!r}")


if __name__ == "__main__":
    sys.exit(main())
