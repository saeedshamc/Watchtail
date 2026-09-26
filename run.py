"""Watchtail entrypoint.

Builds the app, starts the log tailing workers and the Socket.IO
broadcaster, then serves the dashboard. Usage:

    python run.py [--config watchtail.yml] [--host 0.0.0.0] [--port 5555] [--debug]
"""

import argparse
import logging

import app as watchtail_app
from app.database import enable_sqlite_wal
from app.notifiers.webhook import build_notifiers
from app.parsers import get_parser
from app.pipeline import Pipeline, prune_old_rows
from app.realtime import emit_activity, socketio, start_broadcaster
from app.tailer import TailManager


def build_manager(settings):
    """Create the tail manager wired to the pipeline."""
    pipeline = Pipeline(
        settings,
        notifier_registry=build_notifiers(settings),
        emit=emit_activity,
    )

    def persist_position(source_id, position):
        from app.database import session_scope
        from app.models import LogSource

        with session_scope() as session:
            source = session.get(LogSource, source_id)
            if source is not None:
                source.last_position = position

    return TailManager(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
        poll_interval=1.0,
        persist_position=persist_position,
    )


def main():
    parser = argparse.ArgumentParser(description="Watchtail log monitor")
    parser.add_argument("--config", default=None, help="path to watchtail.yml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    application = watchtail_app.create_app(args.config)
    settings = application.config["WATCHTAIL_SETTINGS"]
    host = args.host or settings.host
    port = args.port or settings.port

    if application.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        enable_sqlite_wal()

    prune_old_rows(settings)

    manager = build_manager(settings)
    from app.database import session_scope
    from app.models import LogSource

    with session_scope() as session:
        sources = session.query(LogSource).all()
    manager.sync(sources)

    start_broadcaster(application)

    try:
        # allow_unsafe_werkzeug is required for the threading mode dev
        # server; production deployments should use gunicorn with the
        # eventlet worker (see README).
        socketio.run(
            application,
            host=host,
            port=port,
            debug=args.debug,
            allow_unsafe_werkzeug=True,
        )
    finally:
        manager.stop_all()


if __name__ == "__main__":
    main()
