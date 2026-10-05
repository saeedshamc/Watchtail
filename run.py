"""Watchtail entrypoint.

Builds the app, starts the log tailing workers and the Socket.IO
broadcaster, then serves the dashboard. Usage:

    python run.py [--config watchtail.yml] [--host 0.0.0.0] [--port 5555] [--debug]
"""

import argparse
import logging

import app as watchtail_app
from app.database import enable_sqlite_wal
from app.listener import ListenerRegistry
from app.manager import resync_tailing, set_manager
from app.ssh_tail import SshTailRegistry
from app.notifiers.digest import DigestScheduler
from app.notifiers.webhook import build_notifiers
from app.parsers import get_parser
from app.pipeline import Pipeline, prune_old_rows
from app.realtime import emit_activity, socketio, start_broadcaster
from app.tailer import TailManager

STATS_INTERVAL_SECONDS = 10


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

    manager = TailManager(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
        poll_interval=1.0,
        persist_position=persist_position,
    )
    set_manager(manager)

    # Endpoint sources (udp://host:port, tcp://host:port) run as
    # network listeners instead of file tailers.
    listeners = ListenerRegistry(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
    )
    manager.listeners = listeners

    # ssh://user@host/path sources stream remote files over SSH.
    ssh_tails = SshTailRegistry(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
    )
    manager.ssh_tails = ssh_tails
    return manager


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
    if getattr(manager, "listeners", None) is not None:
        manager.listeners.sync(sources)
    if getattr(manager, "ssh_tails", None) is not None:
        manager.ssh_tails.sync(sources)

    # Bind the module-level SocketIO instance to this app; without
    # this the server object does not exist and run() fails.
    socketio.init_app(application)
    start_broadcaster(application, interval_stats=STATS_INTERVAL_SECONDS)

    # Daily digest runs in its own daemon thread; channels opt in via
    # the digest flag in their notifier block.
    digest = DigestScheduler(
        build_notifiers(settings),
        hour_utc=int(settings.digest_hour_utc),
        hours=24,
    )
    digest.start()

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
        digest.stop()
        if getattr(manager, "listeners", None) is not None:
            manager.listeners.stop_all()
        if getattr(manager, "ssh_tails", None) is not None:
            manager.ssh_tails.stop_all()
        manager.stop_all()
        set_manager(None)


if __name__ == "__main__":
    main()
