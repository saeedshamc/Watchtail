"""Tests for the reports page (detector/source trends)."""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Alert, Event, LogSource


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def admin_client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def _seed():
    with session_scope() as session:
        source = LogSource(name="nginx", type="nginx", path="/var/log/nginx/access.log")
        session.add(source)
        session.flush()
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        today = now.replace(hour=10, minute=0, second=0, microsecond=0)
        yesterday = today - dt.timedelta(days=1)

        session.add(
            Alert(
                detector="ssh_bruteforce", ip="203.0.113.9", severity="high",
                message="burst", ts=today,
            )
        )
        session.add(
            Alert(
                detector="ssh_bruteforce", ip="203.0.113.9", severity="high",
                message="burst", ts=today,
            )
        )
        session.add(
            Alert(
                detector="path_scan", ip="198.51.100.3", severity="medium",
                message="scan", ts=yesterday,
            )
        )
        for _ in range(3):
            session.add(
                Event(source_id=source.id, ts=today, ip="203.0.113.9",
                      kind="http_access", path="/a", status=200)
            )
        session.add(
            Event(source_id=source.id, ts=today, ip="203.0.113.9",
                  kind="http_access", path="/missing", status=404)
        )
        session.add(
            Event(source_id=None, ts=today, ip="198.51.100.3", kind="syslog")
        )
    return None


def test_reports_renders_detector_trends(admin_client):
    _seed()
    html = admin_client.get("/reports").get_data(as_text=True)
    assert "ssh_bruteforce" in html
    assert "path_scan" in html
    assert "203.0.113.9" in html  # worst ip column


def test_reports_source_trends_and_error_share(admin_client):
    _seed()
    html = admin_client.get("/reports").get_data(as_text=True)
    assert "nginx" in html
    assert "unattributed" in html
    # 4 events on the nginx source, one 404 -> 25.0%.
    assert "25.0%" in html


def test_reports_window_choices(admin_client):
    _seed()
    for days in ("7", "14", "30"):
        response = admin_client.get(f"/reports?days={days}")
        assert response.status_code == 200
        assert f"last {days} days" in response.get_data(as_text=True)


def test_reports_empty_window(admin_client):
    html = admin_client.get("/reports").get_data(as_text=True)
    assert "No alerts in this window" in html


def test_reports_requires_login(memory_app):
    client = memory_app.test_client()
    response = client.get("/reports")
    assert response.status_code == 302
