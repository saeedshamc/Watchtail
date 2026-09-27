"""Tests for the per-IP detail page."""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, Event, IpStatus, utcnow


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def seed(ip="203.0.113.44", status="flagged"):
    with session_scope() as session:
        session.add(
            IpStatus(
                ip=ip,
                status=status,
                reason="5 failed logins",
                alert_count=2,
                last_alert_at=utcnow(),
            )
        )
        session.add(
            Alert(
                detector="ssh_bruteforce",
                ip=ip,
                severity="high",
                message="5 failed logins in 3 minutes",
            )
        )
        session.add(
            Event(
                ip=ip,
                kind="ssh_auth_fail",
                meta={"user": "root"},
                raw="Failed password for root",
            )
        )
    return ip


def test_detail_requires_login(memory_app):
    response = memory_app.test_client().get("/ips/203.0.113.44")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_detail_shows_status_alerts_and_events(client):
    seed()
    response = client.get("/ips/203.0.113.44")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "203.0.113.44" in html
    assert "ssh_bruteforce" in html
    assert "5 failed logins in 3 minutes" in html
    assert "ssh_auth_fail" in html
    assert "Mark reviewed" in html
    assert "Dismiss (never flag again)" in html


def test_detail_404_for_unknown_ip(client):
    assert client.get("/ips/198.51.100.9").status_code == 404


def test_detail_links_from_dashboard_flagged_list(client):
    seed()
    html = client.get("/").get_data(as_text=True)
    assert '/ips/203.0.113.44' in html


def test_re_enable_flagging_from_dismissed(client):
    seed(status="dismissed")
    html = client.get("/ips/203.0.113.44").get_data(as_text=True)
    assert "Re-enable flagging" in html

    client.post(
        "/ips/203.0.113.44/status",
        data={"action": "reviewed"},
        follow_redirects=True,
    )
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.44").status == "reviewed"


def test_old_events_are_not_listed(client):
    with session_scope() as session:
        session.add(
            Event(
                ip="203.0.113.44",
                kind="http_access",
                method="GET",
                path="/old",
                status=404,
                ts=utcnow() - dt.timedelta(hours=30),
            )
        )
    html = client.get("/ips/203.0.113.44").get_data(as_text=True)
    assert "/old" not in html
