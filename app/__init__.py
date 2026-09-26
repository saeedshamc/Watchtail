"""Watchtail application factory.

Creates and wires the Flask app, database and configuration. The live
tailing threads are intentionally not started here: tests and tooling
need a quiet app, and run.py starts the workers for real usage.
"""

import logging
import os
import secrets
from datetime import timedelta

from flask import Flask
from werkzeug.security import generate_password_hash

from .config import load_config
from .database import configure_engine, create_all, session_scope
from .models import AdminUser, LogSource

logger = logging.getLogger("watchtail")


def default_database_url() -> str:
    return "sqlite:///data/watchtail.db"


def create_app(config_path=None):
    """Build the Flask app.

    ``config_path`` points at a watchtail.yml file; when omitted the
    default locations (./watchtail.yml then ./config/watchtail.example.yml)
    are used so the app still boots for tests and first runs.
    """
    app = Flask(__name__)

    settings = load_config(config_path)
    app.config["WATCHTAIL_SETTINGS"] = settings
    app.config["SECRET_KEY"] = os.environ.get(
        "WATCHTAIL_SECRET_KEY", ""
    ) or secrets.token_hex(32)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "WATCHTAIL_DATABASE_URL", settings.database_url or default_database_url()
    )

    configure_engine(app.config["SQLALCHEMY_DATABASE_URI"])
    create_all()

    _ensure_secret_key_file(app)
    _sync_log_sources(settings)
    _ensure_admin_user()

    from .routes import register_blueprints

    register_blueprints(app)

    return app


def _ensure_secret_key_file(app):
    """Persist the session key so logins survive restarts.

    WATCHTAIL_SECRET_KEY wins when set; otherwise a generated key is kept
    in data/secret_key, which git ignores.
    """
    if os.environ.get("WATCHTAIL_SECRET_KEY"):
        return
    key_path = os.path.join("data", "secret_key")
    try:
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as fh:
                stored = fh.read().strip()
            if stored:
                app.config["SECRET_KEY"] = stored
                return
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(app.config["SECRET_KEY"])
    except OSError:
        logger.warning("could not persist session key to %s", key_path)


def _sync_log_sources(settings):
    """Mirror config-declared sources into the database.

    Rows are matched on (type, path). Enabled state follows the config
    file on startup so disabling a source there also stops its tailer.
    """
    from sqlalchemy import select

    with session_scope() as session:
        existing = {
            (src.type, src.path): src
            for src in session.scalars(select(LogSource)).all()
        }
        for entry in settings.sources:
            key = (entry.type, entry.path)
            row = existing.get(key)
            if row is None:
                session.add(
                    LogSource(
                        name=entry.name,
                        type=entry.type,
                        path=entry.path,
                        enabled=entry.enabled,
                    )
                )
            else:
                row.enabled = entry.enabled
                if row.name != entry.name:
                    row.name = entry.name


def _ensure_admin_user():
    """Bootstrap the single admin account.

    The password comes from WATCHTAIL_ADMIN_PASSWORD. When unset a random
    one is generated, printed once and kept only as a hash in the
    database.
    """
    with session_scope() as session:
        if session.get(AdminUser, "admin") is not None:
            return
        password = os.environ.get("WATCHTAIL_ADMIN_PASSWORD") or ""
        generated = False
        if not password:
            password = secrets.token_urlsafe(12)
            generated = True
        session.add(
            AdminUser(username="admin", password_hash=generate_password_hash(password))
        )
    if generated:
        logger.warning(
            "no WATCHTAIL_ADMIN_PASSWORD set; generated admin password: %s", password
        )
