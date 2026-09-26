"""Tests for the flagged IP review workflow."""

import pytest

import app as watchtail_app
from app.database import configure_engine, dispose_engine, session_scope
from app.models import IpStatus


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
            IpStatus(ip=ip, status=status, reason="5 failed logins", alert_count=5)
        )
    return ip


def test_flagged_api_skips_dismissed(client):
    seed("1.1.1.1", "flagged")
    seed("2.2.2.2", "dismissed")
    response = client.get("/api/flagged")
    assert response.status_code == 200
    ips = [row["ip"] for row in response.get_json()]
    assert ips == ["1.1.1.1"]
    assert ips[0] and response.get_json()[0]["alert_count"] == 5


def test_dashboard_shows_review_and_dismiss_buttons(client):
    seed()
    html = client.get("/").get_data(as_text=True)
    assert "203.0.113.44" in html
    assert 'value="reviewed"' in html
    assert 'value="dismissed"' in html


def test_mark_reviewed(client):
    ip = seed()
    response = client.post(f"/ips/{ip}/status", data={"action": "reviewed"},
                           follow_redirects=True)
    assert "marked as reviewed" in response.get_data(as_text=True)
    with session_scope() as session:
        assert session.get(IpStatus, ip).status == "reviewed"


def test_mark_dismissed(client):
    ip = seed()
    client.post(f"/ips/{ip}/status", data={"action": "dismissed"},
                follow_redirects=True)
    with session_scope() as session:
        assert session.get(IpStatus, ip).status == "dismissed"
    # Dismissed IPs disappear from the dashboard's flagged list.
    assert "203.0.113.44" not in client.get("/").get_data(as_text=True)


def test_unknown_action_is_rejected(client):
    ip = seed()
    client.post(f"/ips/{ip}/status", data={"action": "ban"}, follow_redirects=True)
    with session_scope() as session:
        assert session.get(IpStatus, ip).status == "flagged"


def test_status_change_for_unknown_ip_flashes(client):
    response = client.post("/ips/9.9.9.9/status", data={"action": "reviewed"},
                           follow_redirects=True)
    assert "no recorded alerts" in response.get_data(as_text=True)
