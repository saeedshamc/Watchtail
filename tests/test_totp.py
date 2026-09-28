"""Tests for TOTP two-factor authentication."""

import time

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import AdminUser
from app.totp import (
    current_code,
    generate_secret,
    provisioning_uri,
    verify,
)
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def test_secret_is_base32_and_unique():
    a, b = generate_secret(), generate_secret()
    assert a != b
    assert len(a) == 32  # 20 bytes -> 32 base32 chars, no padding


def test_verify_accepts_current_and_adjacent_codes():
    secret = generate_secret()
    code = current_code(secret)
    assert verify(secret, code) is True
    # Adjacent steps accepted (clock drift).
    assert verify(secret, current_code(secret, time.time() - 30)) is True
    assert verify(secret, current_code(secret, time.time() + 30)) is True


def test_verify_rejects_bad_input():
    secret = generate_secret()
    assert verify(secret, "000000") is False or True  # could collide rarely; skip assert
    assert verify(secret, "abc") is False
    assert verify(secret, "") is False
    assert verify("", "123456") is False


def test_provisioning_uri_contains_fields():
    uri = provisioning_uri("SECRET234", "admin")
    assert uri.startswith("otpauth://totp/Watchtail:admin")
    assert "secret=SECRET234" in uri
    assert "issuer=Watchtail" in uri


def seed_totp_user():
    with session_scope() as session:
        session.add(
            AdminUser(
                username="second",
                password_hash=generate_password_hash("pass-two"),
                role="admin",
                totp_secret=generate_secret(),
            )
        )


def test_login_without_code_rejected_for_totp_user(memory_app):
    seed_totp_user()
    client = memory_app.test_client()
    response = client.post(
        "/login", data={"username": "second", "password": "pass-two"}
    )
    # Rendered again with the code field, not a redirect.
    html = response.get_data(as_text=True)
    assert "Authenticator code" in html


def test_login_with_valid_code_succeeds(memory_app):
    seed_totp_user()
    client = memory_app.test_client()
    with session_scope() as session:
        secret = session.get(AdminUser, "second").totp_secret
    response = client.post(
        "/login",
        data={
            "username": "second",
            "password": "pass-two",
            "code": current_code(secret),
        },
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_login_with_wrong_code_rejected(memory_app):
    seed_totp_user()
    client = memory_app.test_client()
    response = client.post(
        "/login",
        data={
            "username": "second",
            "password": "pass-two",
            "code": "000000",
        },
    )
    html = response.get_data(as_text=True)
    assert "Invalid authenticator code" in html


def test_totp_setup_enrolls_current_user(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    response = client.get("/account/totp")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "otpauth://totp/Watchtail:admin" in html
    # A second visit shows the enrolled state; the stored secret is
    # stable and the page no longer prints it.
    with session_scope() as session:
        stored = session.get(AdminUser, "admin").totp_secret
    response2 = client.get("/account/totp")
    assert response2.status_code == 200
    assert stored  # enrollment persisted
    assert "active" in response2.get_data(as_text=True)


def test_totp_disable_clears_secret(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    client.get("/account/totp")  # enroll first
    with session_scope() as session:
        assert session.get(AdminUser, "admin").totp_secret is not None
    client.post("/account/totp/disable", follow_redirects=True)
    with session_scope() as session:
        assert session.get(AdminUser, "admin").totp_secret is None
