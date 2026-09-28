"""Tests for REST API v1 endpoints."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Alert, Event, IpStatus, utcnow
from app.tokens import create_token


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def read_token():
    plain, _ = create_token("reader")
    return plain


@pytest.fixture
def write_token():
    plain, _ = create_token("writer", can_write=True)
    return plain


def seed():
    now = utcnow()
    with session_scope() as session:
        session.add(
            IpStatus(
                ip="203.0.113.44", status="flagged", alert_count=2,
                threat_score=80, reason="brute force", last_alert_at=now,
                first_seen_at=now, tags=["watchlist"],
                operator_note="checked",
            )
        )
        session.add(
            Alert(ip="203.0.113.44", detector="ssh_bruteforce",
                  severity="high", message="m", ts=now)
        )
        session.add(
            Event(ip="203.0.113.44", kind="ssh_auth_fail",
                  ts=now, raw="r", meta={"user": "root"})
        )


def auth(plain):
    return {"Authorization": f"Bearer {plain}"}


def test_list_flagged_with_token(memory_app, read_token):
    seed()
    response = memory_app.test_client().get("/api/v1/ips", headers=auth(read_token))
    assert response.status_code == 200
    rows = response.get_json()
    assert rows[0]["ip"] == "203.0.113.44"
    assert rows[0]["score_level"] == "high"
    assert rows[0]["tags"] == ["watchlist"]


def test_requires_token(memory_app):
    for path in ("/api/v1/ips", "/api/v1/alerts", "/api/v1/stats"):
        response = memory_app.test_client().get(path)
        assert response.status_code == 401


def test_invalid_token_rejected(memory_app):
    response = memory_app.test_client().get(
        "/api/v1/ips", headers=auth("wt_bogus")
    )
    assert response.status_code == 401


def test_ip_detail_includes_alerts_and_events(memory_app, read_token):
    seed()
    response = memory_app.test_client().get(
        "/api/v1/ips/203.0.113.44", headers=auth(read_token)
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["alerts"][0]["detector"] == "ssh_bruteforce"
    assert body["recent_events"][0]["kind"] == "ssh_auth_fail"


def test_unknown_ip_404(memory_app, read_token):
    response = memory_app.test_client().get(
        "/api/v1/ips/10.10.10.10", headers=auth(read_token)
    )
    assert response.status_code == 404


def test_alerts_filter_by_severity(memory_app, read_token):
    seed()
    response = memory_app.test_client().get(
        "/api/v1/alerts?severity=high", headers=auth(read_token)
    )
    rows = response.get_json()
    assert rows and all(row["severity"] == "high" for row in rows)


def test_stats_endpoint(memory_app, read_token):
    seed()
    response = memory_app.test_client().get("/api/v1/stats", headers=auth(read_token))
    assert response.status_code == 200
    body = response.get_json()
    assert body["alerts_24h"] == 1
    assert body["events_24h"] == 1


def test_write_endpoints_need_can_write(memory_app, read_token, write_token):
    # Read-only token cannot change status.
    response = memory_app.test_client().post(
        "/api/v1/ips/203.0.113.44/status",
        json={"action": "dismissed"},
        headers=auth(read_token),
    )
    assert response.status_code == 403

    # Writer token can.
    seed()
    response = memory_app.test_client().post(
        "/api/v1/ips/203.0.113.44/status",
        json={"action": "dismissed"},
        headers=auth(write_token),
    )
    assert response.status_code == 200
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.44").status == "dismissed"


def test_annotate_via_api(memory_app, write_token):
    seed()
    response = memory_app.test_client().post(
        "/api/v1/ips/203.0.113.44/annotate",
        json={"note": "from n8n", "tags": ["triaged"]},
        headers=auth(write_token),
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["note"] == "from n8n"
    assert body["tags"] == ["triaged"]


def test_mint_token_requires_write_scope(memory_app, read_token, write_token):
    response = memory_app.test_client().post(
        "/api/v1/tokens", json={"name": "n"}, headers=auth(read_token)
    )
    assert response.status_code == 403

    response = memory_app.test_client().post(
        "/api/v1/tokens",
        json={"name": "ansible", "can_write": False},
        headers=auth(write_token),
    )
    assert response.status_code == 201
    plain = response.get_json()["token"]
    assert plain.startswith("wt_")
    # The minted token works immediately.
    assert memory_app.test_client().get(
        "/api/v1/ips", headers=auth(plain)
    ).status_code == 200


def test_session_cookie_also_works(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    assert client.get("/api/v1/ips").status_code == 200
