"""Entry point for frozen (PyInstaller) builds of Watchtail.

The spec file injects WATCHTAIL_FROZEN=1, and sys.frozen is already
true, which switches the application to "installed" mode:

- config and database live under a writable data directory next to the
  executable (or %LOCALAPPDATA%\\Watchtail when the exe directory is
  read-only)
- the example config is copied there on first run
- admin password / secret key come from the environment or are
  generated and stored, so no shell is ever needed
"""

import os
import shutil
import sys


def _frozen_data_dir() -> str:
    """Pick the writable directory for config and database."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(exe_dir, "data")
    if _writable_dir(candidate):
        return candidate
    # Portable installs on a read-only medium fall back per user.
    fallback = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Watchtail"
    )
    os.makedirs(fallback, exist_ok=True)
    return fallback


def _writable_dir(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write-test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False


def _prepare_runtime(data_dir: str) -> None:
    """Copy the example config next to the exe on first run."""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        bundled = os.path.join(base, "config", "watchtail.example.yml")
        if os.path.exists(bundled):
            target = os.path.join(data_dir, "watchtail.yml")
            if not os.path.exists(target):
                shutil.copyfile(bundled, target)


def main() -> None:
    data_dir = _frozen_data_dir()
    os.environ.setdefault("WATCHTAIL_DATA_DIR", data_dir)

    # Point the default SQLite URL at the writable directory before the
    # app factory reads any config.
    os.environ.setdefault(
        "WATCHTAIL_DATABASE_URL",
        "sqlite:///" + os.path.join(data_dir, "watchtail.db").replace("\\", "/"),
    )

    _prepare_runtime(data_dir)

    import multiprocessing

    multiprocessing.freeze_support()

    from app.realtime import socketio

    # Import run.main for its wiring, but drive socketio.run here so the
    # Windowed build keeps a console-free lifecycle on Windows.
    import run as runner

    application = runner  # noqa: F841  (kept for clarity in logs)

    import argparse

    parser = argparse.ArgumentParser(description="Watchtail log monitor")
    parser.add_argument("--config", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    args, _unknown = parser.parse_known_args()

    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    import app as watchtail_app

    application = watchtail_app.create_app(args.config)
    settings = application.config["WATCHTAIL_SETTINGS"]
    host = args.host or settings.host
    port = args.port or settings.port

    if application.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        from app.database import enable_sqlite_wal

        enable_sqlite_wal()

    from app.pipeline import prune_old_rows

    prune_old_rows(settings)

    manager = runner.build_manager(settings)
    from app.database import session_scope
    from app.models import LogSource

    with session_scope() as session:
        sources = session.query(LogSource).all()
    manager.sync(sources)

    socketio.init_app(application)
    from app.realtime import start_broadcaster

    start_broadcaster(application)

    try:
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
