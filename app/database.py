"""Database engine and session management.

A module-level engine is shared by the web app and background workers so
SQLite locking stays predictable. Sessions are handed out per-operation
with an explicit commit/rollback, which keeps worker threads safe.
"""

import logging
import os
import threading
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("watchtail")

_engine = None
_Session = None
_lock = threading.Lock()


def configure_engine(database_url: str):
    """Create the engine and session factory.

    Safe to call repeatedly; the engine is only rebuilt when the URL
    changes (tests rely on this).
    """
    global _engine, _Session
    with _lock:
        if _engine is not None and _engine.url.render_as_string() == database_url:
            return
        if _engine is not None:
            _engine.dispose()
        url = make_url(database_url)
        connect_args = {}
        pool_kwargs = {}
        if url.get_backend_name() == "sqlite":
            # Workers and the web app run on separate threads.
            connect_args["check_same_thread"] = False
            if url.database in (None, ":memory:"):
                # One shared connection so every thread sees the same DB.
                pool_kwargs["poolclass"] = StaticPool
            elif url.database:
                parent = os.path.dirname(os.path.abspath(url.database))
                if parent:
                    os.makedirs(parent, exist_ok=True)
        _engine = create_engine(
            database_url, connect_args=connect_args, future=True, **pool_kwargs
        )
        _Session = scoped_session(
            sessionmaker(bind=_engine, expire_on_commit=False, future=True)
        )


def get_engine():
    if _engine is None:
        raise RuntimeError("database engine not configured; call configure_engine first")
    return _engine


def create_all():
    get_engine()
    from .models import Base

    Base.metadata.create_all(_engine)


def drop_all():
    get_engine()
    from .models import Base

    Base.metadata.drop_all(_engine)


@contextmanager
def session_scope():
    """Yield the thread-local session inside a commit/rollback block.

    The session is removed afterwards so pooled connections are returned
    promptly; objects used outside the block stay usable because
    expire_on_commit is off.
    """
    if _Session is None:
        raise RuntimeError("database not configured; call configure_engine first")
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        _Session.remove()


def dispose_engine():
    global _engine, _Session
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _Session = None


def enable_sqlite_wal():
    """Turn on WAL journalling for SQLite databases.

    Concurrent tailer writes and dashboard reads contend less under WAL,
    and readers never block writers.
    """
    if _engine is None or not _engine.url.get_backend_name() == "sqlite":
        return
    with _engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous=NORMAL"))
        conn.commit()
