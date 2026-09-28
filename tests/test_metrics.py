"""Tests for the Prometheus metrics endpoint."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Alert, Event, IpStatus, utcnow
from app.routes.metrics import bump


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def test_metrics_requires_login(memory_app):
    assert memory_app.test_client().get("/metrics").status_code == 302


def test_metrics_renders_counters_and_gauges(client):
    bump("watchtail_events_ingested_total", 5)
    with session_scope() as session:
        session.add(Event(ip="1.1.1.1", kind="http_access", raw="r", meta={}))
        session.add(
            Alert(ip="1.1.1.1", detector="d", severity="low", message="m")
        )
        session.add(IpStatus(ip="1.1.1.1", status="flagged"))

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.mimetype
    body = response.get_data(as_text=True)

    assert "watchtail_events_ingested_total 5" in body
    assert "# TYPE watchtail_events_ingested_total counter" in body
    assert "watchtail_events_24h 1" in body
    assert "watchtail_alerts_24h 1" in body
    assert "watchtail_flagged_ips 1" in body
    assert "watchtail_tracked_ips 1" in body
    # The example config ships sources, so just check the lines exist.
    assert "watchtail_sources_total" in body
    assert "watchtail_sources_enabled" in body
