"""Tests for the admin password CLI."""

import pytest

import app as watchtail_app
from app.cli import main
from app.database import dispose_engine, session_scope
from app.models import AdminUser
from werkzeug.security import check_password_hash


@pytest.fixture(autouse=True)
def memory_app(monkeypatch):
    # The CLI resolves its database like a real operator invocation
    # would (config / env); point the env at the in-memory database.
    monkeypatch.setenv("WATCHTAIL_DATABASE_URL", "sqlite:///:memory:")
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def stored_hash(username="admin"):
    with session_scope() as session:
        user = session.get(AdminUser, username)
        return user.password_hash if user else None


def test_passwd_updates_existing_admin():
    old_hash = stored_hash()
    assert old_hash is not None  # bootstrapped by the app factory

    exit_code = main(["passwd", "--password", "new-secret"])
    assert exit_code == 0
    new_hash = stored_hash()
    assert new_hash != old_hash
    assert check_password_hash(new_hash, "new-secret")
    assert not check_password_hash(new_hash, "test-password")


def test_passwd_creates_missing_account():
    exit_code = main(["passwd", "--username", "ops", "--password", "ops-secret"])
    assert exit_code == 0
    assert check_password_hash(stored_hash("ops"), "ops-secret")


def test_passwd_rejects_mismatched_confirmation(monkeypatch):
    answers = iter(["first", "second"])
    monkeypatch.setattr("app.cli.getpass.getpass", lambda *_: next(answers))
    exit_code = main(["passwd"])
    assert exit_code == 2
    # The stored password is untouched after a failed prompt round.
    assert check_password_hash(stored_hash(), "test-password")


def test_passwd_rejects_empty_password():
    assert main(["passwd", "--password", ""]) == 2


def test_password_change_takes_effect_on_login(memory_app):
    assert main(["passwd", "--password", "rotated-secret"]) == 0
    test_client = memory_app.test_client()
    response = test_client.post(
        "/login", data={"username": "admin", "password": "rotated-secret"}
    )
    assert response.status_code == 302  # logged in
