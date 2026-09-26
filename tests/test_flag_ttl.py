"""Tests for the flag TTL: stale flags leave listings but keep history."""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import session_scope
from app.models import IpStatus, utcnow


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    from app.database import dispose_engine

    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def app_settings(memory_app):
    return memory_app.config["WATCHTAIL_SETTINGS"]


def seed(ip, status="flagged", age_seconds=0, alert_count=1):
    with session_scope() as session:
        session.add(
            IpStatus(
                ip=ip,
                status=status,
                reason="3 failed logins",
                alert_count=alert_count,
                last_alert_at=utcnow() - dt.timedelta(seconds=age_seconds),
            )
        )


def test_recent_flag_is_listed(client):
    seed("1.1.1.1", age_seconds=30)
    ips = [row["ip"] for row in client.get("/api/flagged").get_json()]
    assert ips == ["1.1.1.1"]


def test_stale_flag_leaves_the_list(client, memory_app):
    ttl = app_settings(memory_app).flag_ttl_seconds
    seed("2.2.2.2", age_seconds=ttl + 60)
    assert client.get("/api/flagged").get_json() == []


def test_reviewed_rows_stay_visible(client, memory_app):
    ttl = app_settings(memory_app).flag_ttl_seconds
    seed("3.3.3.3", status="reviewed", age_seconds=ttl + 60)
    ips = [row["ip"] for row in client.get("/api/flagged").get_json()]
    assert ips == ["3.3.3.3"]


def test_stat_counts_only_fresh_flags(client, memory_app):
    ttl = app_settings(memory_app).flag_ttl_seconds
    seed("4.4.4.4", age_seconds=10)
    seed("5.5.5.5", age_seconds=ttl + 10)
    html = client.get("/").get_data(as_text=True)
    # stat-flagged shows 1; the stale IP is absent from the list too.
    assert 'id="stat-flagged">1<' in html
    assert "5.5.5.5" not in html


def test_new_alert_relists_a_stale_ip(client, memory_app):
    from app.config import Settings
    from app.models import utcnow as now
    from app.pipeline import Pipeline
    from app.parsers.base import ParsedLine

    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 1, "window_seconds": 60}
    }
    pipeline = Pipeline(settings)

    class Source:
        id = 1
        type = "auth"
        path = "/var/log/auth.log"

    with session_scope() as session:
        stale = utcnow() - dt.timedelta(hours=3)
        session.add(
            IpStatus(
                ip="6.6.6.6", status="flagged", alert_count=1, last_alert_at=stale
            )
        )

    record = ParsedLine(
        kind="ssh_auth_fail",
        ts=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
        ip="6.6.6.6",
        meta={"user": "root"},
    )
    pipeline.handle_record(record, "raw", Source())

    with session_scope() as session:
        row = session.get(IpStatus, "6.6.6.6")
        assert row.alert_count == 2
        assert row.last_alert_at > stale
