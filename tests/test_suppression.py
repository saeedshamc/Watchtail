"""Tests for alert suppression rules and routes."""

import datetime as dt

import pytest

import app as watchtail_app
from app.config import Settings
from app.database import dispose_engine, session_scope
from app.models import Alert, IpStatus
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline
from app.suppression import (
    SuppressionRule,
    SuppressionStore,
    get_store,
    reset_store,
)


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()
    reset_store()


class TestSuppressionStore:
    def test_rule_expiry(self):
        rule = SuppressionRule(ip="1.1.1.1", minutes=5)
        assert rule.active() is True
        past = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(minutes=6)
        assert rule.active(now=past) is False

    def test_scope_matching(self):
        rule = SuppressionRule(ip="1.1.1.1", detector="path_scan")
        assert rule.matches(ip="1.1.1.1", detector="path_scan")
        assert not rule.matches(ip="2.2.2.2", detector="path_scan")
        assert not rule.matches(ip="1.1.1.1", detector="request_burst")

    def test_global_rule_matches_anything(self):
        store = SuppressionStore()
        store.add(SuppressionRule(detector="request_burst", minutes=10))
        assert store.is_suppressed(ip="9.9.9.9", detector="request_burst")
        assert not store.is_suppressed(ip="9.9.9.9", detector="path_scan")

    def test_purge_drops_expired(self):
        store = SuppressionStore()
        rule = SuppressionRule(ip="1.1.1.1", minutes=5)
        store.add(rule)
        future = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(minutes=10)
        assert store.purge(now=future) == 1
        assert store.is_suppressed(ip="1.1.1.1") is False


def test_suppressed_alert_not_flagged_or_notified():
    store = get_store()
    store.add(SuppressionRule(ip="203.0.113.44", detector="ssh_bruteforce", minutes=30))

    dispatched = []

    class FakeRegistry:
        def dispatch(self, alert_row):
            dispatched.append(alert_row)

    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    pipeline = Pipeline(settings, notifier_registry=FakeRegistry())

    def fail(minute):
        return ParsedLine(
            kind="ssh_auth_fail",
            ts=dt.datetime(2026, 9, 28, 12, minute, 0),
            ip="203.0.113.44",
            meta={"user": "root"},
        )

    pipeline.handle_record(fail(1), "raw", None)
    pipeline.handle_record(fail(2), "raw", None)

    with session_scope() as session:
        # The alert is recorded (history stays complete)...
        assert session.query(Alert).count() == 1
        # ...but the IP is not flagged and nobody was notified.
        assert session.get(IpStatus, "203.0.113.44") is None
    assert dispatched == []


def test_unsuppressed_alert_still_works():
    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    pipeline = Pipeline(settings)

    def fail(minute):
        return ParsedLine(
            kind="ssh_auth_fail",
            ts=dt.datetime(2026, 9, 28, 12, minute, 0),
            ip="203.0.113.50",
            meta={"user": "root"},
        )

    pipeline.handle_record(fail(1), "raw", None)
    pipeline.handle_record(fail(2), "raw", None)
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.50").status == "flagged"


@pytest.fixture
def admin_client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def test_suppressions_page_and_add(admin_client):
    assert admin_client.get("/suppressions").status_code == 200
    response = admin_client.post(
        "/suppressions/add",
        data={"ip": "1.2.3.4", "detector": "", "minutes": "15", "note": "deploys"},
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)
    assert "deploys" in html
    assert "1.2.3.4" in html
    assert get_store().is_suppressed(ip="1.2.3.4") is True


def test_suppression_requires_both_blank_rejected(admin_client):
    response = admin_client.post(
        "/suppressions/add", data={"ip": "", "detector": "", "minutes": "10"},
        follow_redirects=True,
    )
    assert "Suppress at least" in response.get_data(as_text=True)


def test_clear_all(admin_client):
    get_store().add(SuppressionRule(ip="1.1.1.1", minutes=10))
    admin_client.post("/suppressions/clear", follow_redirects=True)
    assert get_store().active_rules() == []
