"""Tests for the daily digest."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, IpStatus, utcnow
from app.notifiers.base import Notifier
from app.notifiers.digest import (
    DigestScheduler,
    build_digest_payload,
    render_digest_text,
)


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    dispose_engine()


def seed_activity():
    now = utcnow()
    with session_scope() as session:
        session.add(Alert(ip="1.1.1.1", detector="ssh_bruteforce",
                          severity="high", message="m", ts=now))
        session.add(Alert(ip="1.1.1.1", detector="ssh_bruteforce",
                          severity="high", message="m", ts=now))
        session.add(Alert(ip="2.2.2.2", detector="path_scan",
                          severity="medium", message="m", ts=now))
        session.add(IpStatus(ip="1.1.1.1", status="flagged", threat_score=80,
                             first_seen_at=now, reason="brute force"))


def test_payload_counts():
    seed_activity()
    payload = build_digest_payload(hours=24)
    assert payload["total_alerts"] == 3
    assert payload["by_severity"] == {"high": 2, "medium": 1}
    assert payload["by_detector"] == {"path_scan": 1, "ssh_bruteforce": 2}
    assert payload["top_sources"][0] == {"ip": "1.1.1.1", "alerts": 2}
    assert payload["new_flagged_ips"][0]["ip"] == "1.1.1.1"


def test_render_text_readable():
    seed_activity()
    text = render_digest_text(build_digest_payload())
    assert "last 24h" in text
    assert "high: 2" in text
    assert "ssh_bruteforce x2" in text
    assert "1.1.1.1 (2)" in text


def test_quiet_day_message():
    text = render_digest_text(build_digest_payload())
    assert "quiet day" in text


def test_scheduler_sends_to_opted_in_channels():
    seed_activity()
    sent = []

    class DigestChannel(Notifier):
        name = "digest-channel"
        digest_enabled = True

        def send(self, alert):
            sent.append(alert)

    class Silent(Notifier):
        name = "silent"
        digest_enabled = False

        def send(self, alert):
            raise AssertionError("should not be called")

    registry = type(DigestScheduler).__module__  # touch import path
    from app.notifiers.base import NotifierRegistry

    scheduler = DigestScheduler(NotifierRegistry([DigestChannel(), Silent()]))
    payload = scheduler.send_digest()

    assert len(sent) == 1
    assert sent[0].message.startswith("Watchtail digest")
    assert payload["total_alerts"] == 3


def test_scheduler_start_is_idempotent():
    from app.notifiers.base import NotifierRegistry

    scheduler = DigestScheduler(NotifierRegistry([]))
    scheduler.start()
    thread = scheduler._thread
    scheduler.start()
    assert scheduler._thread is thread
    scheduler.stop()
