"""Tests for dashboard authentication."""

import pytest
import app.routes.auth as auth_routes

import app as watchtail_app


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(
        database_url="sqlite:///:memory:",
    )
    application.config["WATCHTAIL_ADMIN_PASSWORD"] = "s3cret-pepper"
    yield application
    dispose_engine()


from app.database import dispose_engine, session_scope
from app.models import AdminUser
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True)
def known_admin(memory_app):
    with session_scope() as session:
        admin = session.get(AdminUser, "admin")
        admin.password_hash = generate_password_hash("s3cret-pepper")
    auth_routes._failures.clear()
    yield
    auth_routes._failures.clear()


@pytest.fixture
def client(memory_app):
    return memory_app.test_client()


def test_dashboard_requires_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_api_returns_json_401(client):
    response = client.get("/api/flagged")
    assert response.status_code == 401
    assert response.get_json()["error"] == "authentication required"


def test_login_page_renders(client):
    html = client.get("/login").get_data(as_text=True)
    assert 'name="password"' in html


def test_login_rejects_wrong_password(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
        follow_redirects=True,
    )
    assert "Invalid credentials." in response.get_data(as_text=True)
    assert client.get("/").status_code == 302


def test_login_accepts_correct_password(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "s3cret-pepper"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "flagged" in response.get_data(as_text=True)
    assert client.get("/sources").status_code == 200


def test_login_next_parameter_is_respected_but_external_rejected(client):
    response = client.post(
        "/login?next=/sources",
        data={"username": "admin", "password": "s3cret-pepper"},
    )
    assert response.headers["Location"].endswith("/sources")

    response = client.post(
        "/login?next=https://evil.example/",
        data={"username": "admin", "password": "s3cret-pepper"},
    )
    assert response.headers["Location"].endswith("/")


def test_logout_clears_session(client):
    client.post(
        "/login", data={"username": "admin", "password": "s3cret-pepper"}
    )
    assert client.get("/").status_code == 200
    client.post("/logout")
    assert client.get("/").status_code == 302


def test_login_throttles_after_repeated_failures(client):
    for _ in range(auth_routes.MAX_FAILURES):
        client.post(
            "/login", data={"username": "admin", "password": "nope"}
        )
    response = client.post(
        "/login",
        data={"username": "admin", "password": "s3cret-pepper"},
        follow_redirects=True,
    )
    # Even the correct password is refused while throttled.
    assert "Too many attempts" in response.get_data(as_text=True)
