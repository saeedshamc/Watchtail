"""Tests for API token lifecycle and bearer authentication."""

import pytest

import app as watchtail_app
from app.api_auth import revoke_token
from app.database import dispose_engine, session_scope
from app.models import ApiToken
from app.tokens import create_token, verify_token


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def test_create_and_verify_roundtrip():
    plain, row = create_token("ci-bot", can_write=True)
    assert plain.startswith("wt_")
    verified = verify_token(plain)
    assert verified is not None
    assert verified.name == "ci-bot"
    assert verified.can_write is True
    assert verified.last_used_at is not None


def test_wrong_token_fails():
    create_token("x")
    assert verify_token("wt_wrong") is None
    assert verify_token("") is None


def test_revocation():
    plain, row = create_token("short-lived")
    assert verify_token(plain) is not None
    assert revoke_token(row.id) is True
    assert verify_token(plain) is None
    assert revoke_token(row.id + 999) is False


def test_hashes_are_not_reversible_in_db():
    plain, _ = create_token("hash-check")
    with session_scope() as session:
        stored = session.query(ApiToken).filter(ApiToken.name == "hash-check").one()
        assert stored.token_hash != plain
        assert len(stored.token_hash) == 64


def test_bearer_header_parsing(memory_app):
    from app.tokens import bearer_from_request

    with memory_app.test_request_context(
        headers={"Authorization": "Bearer wt_abc"}
    ):
        assert bearer_from_request() == "wt_abc"
    with memory_app.test_request_context(headers={}):
        assert bearer_from_request() is None
