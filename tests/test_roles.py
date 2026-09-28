"""Tests for the viewer/admin role split."""

import pytest

import app as watchtail_app
from app.auth import verify_credentials
from app.database import dispose_engine, session_scope
from app.models import AdminUser, IpStatus
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def seed_viewer():
    with session_scope() as session:
        session.add(
            AdminUser(
                username="viewer",
                password_hash=generate_password_hash("viewer-pass"),
                role="viewer",
            )
        )


@pytest.fixture
def viewer_client(memory_app):
    seed_viewer()
    client = memory_app.test_client()
    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    return client


@pytest.fixture
def admin_client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def seed_flag():
    with session_scope() as session:
        session.add(IpStatus(ip="203.0.113.44", status="flagged", alert_count=1))


def test_viewer_can_read_pages(viewer_client):
    for path in ("/", "/events", "/sources", "/respond", "/settings"):
        assert viewer_client.get(path).status_code == 200


def test_viewer_write_actions_are_blocked(viewer_client):
    seed_flag()
    response = viewer_client.post(
        "/ips/203.0.113.44/status", data={"action": "dismissed"},
        follow_redirects=True,
    )
    assert "requires an admin account" in response.get_data(as_text=True)
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.44").status == "flagged"


def test_viewer_cannot_change_settings(viewer_client):
    response = viewer_client.post(
        "/settings", data={"ssh_bruteforce.max_failures": "50"},
        follow_redirects=True,
    )
    assert "requires an admin" in response.get_data(as_text=True)


def test_viewer_cannot_annotate(viewer_client):
    seed_flag()
    viewer_client.post(
        "/ips/203.0.113.44/annotate", data={"note": "x", "tags": ""},
        follow_redirects=True,
    )
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.44").operator_note is None


def test_admin_write_still_works(admin_client):
    seed_flag()
    admin_client.post(
        "/ips/203.0.113.44/status", data={"action": "reviewed"},
        follow_redirects=True,
    )
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.44").status == "reviewed"


def test_verify_credentials_returns_role():
    seed_viewer()
    ok, role = verify_credentials("viewer", "viewer-pass")
    assert ok is True
    assert role == "viewer"
    ok, role = verify_credentials("admin", "test-password")
    assert ok is True
    assert role == "admin"


def test_nav_shows_role(memory_app, viewer_client):
    html = viewer_client.get("/").get_data(as_text=True)
    assert "viewer" in html
