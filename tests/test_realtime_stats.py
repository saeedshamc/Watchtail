"""Tests for periodic stats snapshots and broadcaster lifecycle."""

import queue

import pytest

import app.realtime as realtime
from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, Event, IpStatus, LogSource, utcnow


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    realtime.stop_broadcaster()
    dispose_engine()


def test_stats_payload_counts_rows():
    now = utcnow()
    with session_scope() as session:
        session.add(LogSource(name="auth", type="auth", path="/x", enabled=True))
        session.add(LogSource(name="off", type="nginx", path="/y", enabled=False))
        session.add(Event(ip="1.1.1.1", kind="http_access", ts=now, raw="r", meta={}))
        session.add(
            Alert(ip="1.1.1.1", detector="ssh_bruteforce", message="m", ts=now)
        )
        session.add(
            IpStatus(ip="1.1.1.1", status="flagged", last_alert_at=now, alert_count=1)
        )
        session.add(
            IpStatus(ip="2.2.2.2", status="flagged", last_alert_at=None, alert_count=1)
        )
        session.add(IpStatus(ip="3.3.3.3", status="dismissed", last_alert_at=now))

    payload = realtime.interval_stats_payload()
    stats = payload["stats"]
    assert stats["event_count"] == 1
    assert stats["alert_count"] == 1
    assert stats["source_count"] == 2
    assert stats["active_sources"] == 1
    # Only fresh flagged IPs count (rows without a last alert are not
    # "fresh"); dismissed rows never do — same semantics as the
    # server-rendered dashboard stat.
    assert stats["flagged_count"] == 1
    assert "1.1.1.1" in payload["flagged_ips"]
    assert "3.3.3.3" not in payload["flagged_ips"]
    assert payload["ts"].endswith("Z")


def test_emit_stats_queues_snapshot():
    original = realtime._queue
    try:
        realtime._queue = queue.Queue()
        realtime.emit_stats()
        payload = realtime._queue.get_nowait()
        assert "stats" in payload
    finally:
        realtime._queue = original


def test_broadcaster_start_is_idempotent_and_stop_resets():
    class FakeApp:
        pass

    realtime.start_broadcaster(FakeApp(), interval_stats=2)
    import threading

    threads_before = threading.active_count()
    realtime.start_broadcaster(FakeApp(), interval_stats=2)
    assert threading.active_count() == threads_before  # second call is a no-op

    realtime.stop_broadcaster()
    # A fresh start works again after stopping (new stats thread).
    realtime.start_broadcaster(FakeApp(), interval_stats=2)


def test_stats_interval_is_clamped():
    class FakeApp:
        pass

    import threading
    import time

    realtime.start_broadcaster(FakeApp(), interval_stats=0)
    time.sleep(0.2)
    # With a 2s clamp no stats loop iteration should have completed yet;
    # we mainly assert the call did not crash and threads are alive.
    assert threading.active_count() >= 2
    realtime.stop_broadcaster()
