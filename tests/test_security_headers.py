"""Tests for cookie hardening and security response headers."""

import pytest

import app as watchtail_app


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    from app.database import dispose_engine

    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def test_session_cookie_flags_on_login(memory_app):
    response = memory_app.test_client().post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    # Plain-HTTP test client: Secure must be omitted so LAN deployments
    # over http:// keep working.
    assert "Secure" not in cookie


def test_cookie_is_secure_when_served_over_https(memory_app):
    memory_app.config["SESSION_COOKIE_SECURE"] = True
    response = memory_app.test_client().post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    assert "Secure" in response.headers["Set-Cookie"]


def test_security_headers_present(client):
    response = client.get("/")
    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


def test_security_headers_also_on_static_and_login(memory_app):
    bare = memory_app.test_client()
    for path in ("/login", "/static/css/dashboard.css"):
        response = bare.get(path)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "Content-Security-Policy" in response.headers


def test_headers_do_not_break_dashboard(client):
    html = client.get("/").get_data(as_text=True)
    assert "watch" in html  # sanity: page still renders
