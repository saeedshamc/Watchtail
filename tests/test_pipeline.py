"""Tests for the tailer-to-database pipeline."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, Event, IpStatus, LogSource, utcnow
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline, prune_old_rows


class FakeSource:
    def __init__(self, source_id=1):
        self.id = source_id
        self.type = "auth"
        self.path = "/var/log/auth.log"


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    dispose_engine()


@pytest.fixture
def settings():
    s = Settings()
    s.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    return s


def ssh_fail(ip="203.0.113.44", minute=0):
    return ParsedLine(
        kind="ssh_auth_fail",
        ts=dt.datetime(2026, 9, 26, 12, minute, 0),
        ip=ip,
        meta={"user": "admin", "port": 41000},
    )


def test_events_are_persisted(settings):
    pipeline = Pipeline(settings)
    pipeline.handle_record(ssh_fail(), "raw line", FakeSource())
    with session_scope() as session:
        events = session.query(Event).all()
        assert len(events) == 1
        assert events[0].ip == "203.0.113.44"
        assert events[0].kind == "ssh_auth_fail"
        assert events[0].source_id == 1
        assert events[0].meta["user"] == "admin"


def test_alert_created_and_ip_flagged(settings):
    pipeline = Pipeline(settings)
    pipeline.handle_record(ssh_fail(minute=1), "raw", FakeSource())
    pipeline.handle_record(ssh_fail(minute=2), "raw", FakeSource())
    with session_scope() as session:
        alerts = session.query(Alert).all()
        assert len(alerts) == 1
        assert alerts[0].detector == "ssh_bruteforce"
        flagged = session.get(IpStatus, "203.0.113.44")
        assert flagged.status == "flagged"
        assert flagged.alert_count == 1


def test_flag_count_accumulates(settings):
    pipeline = Pipeline(settings)
    # Three attack waves, each ending in one alert after the cooldown.
    for minute in (1, 2, 8, 9, 15, 16):
        pipeline.handle_record(ssh_fail(minute=minute), "raw", FakeSource())
    with session_scope() as session:
        flagged = session.get(IpStatus, "203.0.113.44")
        assert flagged.alert_count == 3
        assert flagged.status == "flagged"


def test_dismissed_ip_is_not_reflagged(settings):
    pipeline = Pipeline(settings)
    with session_scope() as session:
        session.add(IpStatus(ip="203.0.113.44", status="dismissed"))
    for minute in (1, 2, 3):
        pipeline.handle_record(ssh_fail(minute=minute), "raw", FakeSource())
    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.44")
        assert row.status == "dismissed"
        # Alerts still record what happened, but the IP stays dismissed.
        assert session.query(Alert).count() == 1


def test_emit_receives_event_and_alerts(settings):
    seen = []

    def emit(event_dict, alerts):
        seen.append((event_dict, alerts))

    pipeline = Pipeline(settings, emit=emit)
    pipeline.handle_record(ssh_fail(minute=1), "raw", FakeSource())
    assert seen[-1][0]["ip"] == "203.0.113.44"
    pipeline.handle_record(ssh_fail(minute=2), "raw", FakeSource())
    assert seen[-1][1][0]["detector"] == "ssh_bruteforce"


def test_notifiers_get_alert_rows(settings):
    dispatched = []

    class FakeRegistry:
        def dispatch(self, alert_row):
            dispatched.append(alert_row)

    pipeline = Pipeline(settings, notifier_registry=FakeRegistry())
    pipeline.handle_record(ssh_fail(minute=1), "raw", FakeSource())
    assert dispatched == []
    pipeline.handle_record(ssh_fail(minute=2), "raw", FakeSource())
    assert len(dispatched) == 1
    assert dispatched[0].ip == "203.0.113.44"


def test_prune_old_rows(settings):
    pipeline = Pipeline(settings)
    pipeline.handle_record(ssh_fail(minute=0), "raw", FakeSource())
    settings.retention_max_age_days = 7
    with session_scope() as session:
        old = session.query(Event).one()
        old.ts = utcnow() - dt.timedelta(days=30)
        session.add(
            Alert(
                ts=utcnow() - dt.timedelta(days=30),
                detector="x", ip="1.2.3.4", severity="low", message="old",
            )
        )
    prune_old_rows(settings)
    with session_scope() as session:
        assert session.query(Event).count() == 0
        assert session.query(Alert).count() == 0
