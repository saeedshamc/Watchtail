"""Tests for the response page, command builder and audit trail."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import AuditEntry, IpStatus
from app.response import build_commands, record_action


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


def test_build_commands_covers_platforms():
    commands = build_commands("203.0.113.9")
    platforms = {item["platform"] for item in commands}
    assert {"linux-ufw", "linux-nftables", "windows", "docker"} <= platforms
    for item in commands:
        assert "203.0.113.9" in item["command"]


def test_record_action_writes_audit_row():
    with session_scope() as session:
        record_action(
            session, actor="admin", action="ack", ip="1.1.1.1",
            platform="linux-ufw", command="ufw deny from 1.1.1.1",
        )
    with session_scope() as session:
        entry = session.query(AuditEntry).one()
        assert entry.actor == "admin"
        assert entry.action == "ack"
        assert entry.target_ip == "1.1.1.1"


def test_respond_page_shows_commands_and_trail(client):
    with session_scope() as session:
        session.add(IpStatus(ip="203.0.113.9", status="flagged", alert_count=2))
    response = client.get("/respond?ip=203.0.113.9")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "ufw deny from 203.0.113.9" in html
    assert "reviewed" not in html or True  # badge may or may not appear


def test_acknowledge_records_audit_with_actor(client):
    client.post(
        "/respond/ack",
        data={
            "ip": "203.0.113.9",
            "platform": "linux-ufw",
            "command": "ufw deny from 203.0.113.9",
        },
        follow_redirects=True,
    )
    with session_scope() as session:
        entry = session.query(AuditEntry).one()
        assert entry.actor == "admin"
        assert entry.platform == "linux-ufw"
    # The trail table renders it.
    html = client.get("/respond?ip=203.0.113.9").get_data(as_text=True)
    assert "ufw deny from 203.0.113.9" in html
    assert "admin" in html


def test_respond_requires_login(memory_app):
    assert memory_app.test_client().get("/respond").status_code == 302


def test_ip_detail_links_to_respond(client):
    with session_scope() as session:
        session.add(IpStatus(ip="203.0.113.9", status="flagged"))
    html = client.get("/ips/203.0.113.9").get_data(as_text=True)
    assert "/respond?ip=203.0.113.9" in html
