"""WSGI entrypoint for WSGI servers (gunicorn, uwsgi, ...).

The app factory wires everything except the tailing workers; this
module starts them so a bare WSGI deployment still ingests logs. Run
with exactly one worker process: the Socket.IO broadcaster and the
tailer threads are in-process by design.
"""

import logging

import app as watchtail_app
from app.database import session_scope
from app.manager import set_manager
from app.models import LogSource
from app.notifiers.webhook import build_notifiers
from app.parsers import get_parser
from app.pipeline import Pipeline
from app.realtime import socketio, start_broadcaster
from app.tailer import TailManager

application = watchtail_app.create_app()
settings = application.config["WATCHTAIL_SETTINGS"]

socketio.init_app(application)
start_broadcaster(application, interval_stats=10)


def _start_tailers():
    """Mirror run.py's worker wiring for WSGI servers."""
    from app.database import enable_sqlite_wal

    if application.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        enable_sqlite_wal()

    pipeline = Pipeline(
        settings,
        notifier_registry=build_notifiers(settings),
        emit=None,  # realtime.emit_activity needs a bound socketio server
    )

    def persist_position(source_id, position):
        with session_scope() as session:
            source = session.get(LogSource, source_id)
            if source is not None:
                source.last_position = position

    manager = TailManager(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
        poll_interval=1.0,
        persist_position=persist_position,
    )
    set_manager(manager)
    with session_scope() as session:
        sources = session.query(LogSource).all()
    manager.sync(sources)


try:
    _start_tailers()
except Exception:
    logging.getLogger("watchtail").exception(
        "could not start tailers; dashboard will serve without live ingestion"
    )
