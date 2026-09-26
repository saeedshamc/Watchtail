"""End-to-end test: real files, real tailer threads, full pipeline.

Everything runs against a temporary file on disk with live worker
threads, mirroring what run.py assembles, minus the HTTP layer.
"""

import os
import time

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Alert, Event, IpStatus
from app.parsers import get_parser
from app.pipeline import Pipeline
from app.tailer import TailManager

FAILED_LINE = (
    "Sep 26 14:03:{sec} srv01 sshd[24183]: Failed password for invalid user admin "
    "from 203.0.113.44 port {port} ssh2"
)


def wait_for(condition, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def app_and_log(tmp_path):
    log_path = tmp_path / "auth.log"
    log_path.write_text("", encoding="utf-8")
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    settings = application.config["WATCHTAIL_SETTINGS"]
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 3, "window_seconds": 300}
    }
    yield application, str(log_path), settings
    # Drop the shared engine so later tests get a fresh database.
    dispose_engine()


def test_ssh_bruteforce_from_file_to_flagged_ip(app_and_log):
    application, log_path, settings = app_and_log

    pipeline = Pipeline(settings)
    manager = TailManager(
        parser_factory=get_parser,
        on_record=pipeline.handle_record,
        poll_interval=0.05,
    )

    with session_scope() as session:
        from app.models import LogSource

        source = LogSource(name="auth", type="auth", path=log_path, enabled=True)
        session.add(source)
    source_id = source.id

    try:
        manager.sync([source])
        assert wait_for(lambda: manager.running_ids() == {source_id})

        # Write five failures quickly; threshold is three.
        with open(log_path, "a", encoding="utf-8") as fh:
            for i in range(5):
                fh.write(FAILED_LINE.format(sec=f"{i:02d}", port=41000 + i) + "\n")

        assert wait_for(
            lambda: _count(Event) == 5
        ), "tailer did not ingest all events"
        assert wait_for(lambda: _count(Alert) >= 1), "no alert was raised"
        assert wait_for(
            lambda: _ip_status("203.0.113.44") == "flagged"
        ), "IP was not flagged"

        with session_scope() as session:
            alert = session.query(Alert).one()
            assert alert.detector == "ssh_bruteforce"
            assert alert.ip == "203.0.113.44"
            flagged = session.get(IpStatus, "203.0.113.44")
            assert flagged.reason and "failed SSH logins" in flagged.reason

        # Appending one more line keeps the pipeline alive; cooldown
        # means the alert count stays at one.
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(FAILED_LINE.format(sec="30", port=41999) + "\n")
        assert wait_for(lambda: _count(Event) == 6)
        time.sleep(0.3)
        assert _count(Alert) == 1

        # Dismissing the IP survives further alerts being recorded.
        with session_scope() as session:
            session.get(IpStatus, "203.0.113.44").status = "dismissed"
    finally:
        manager.stop_all()

    assert manager.running_ids() == set()


def _count(model):
    with session_scope() as session:
        return session.query(model).count()


def _ip_status(ip):
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        return row.status if row else None
