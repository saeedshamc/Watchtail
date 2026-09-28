"""Tests for the socket.io authentication gate."""

import pytest

import app as watchtail_app
from app.database import dispose_engine
from app.realtime import _authenticate_socket


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def test_connect_rejected_without_session(memory_app):
    with memory_app.test_request_context("/"):
        assert _authenticate_socket() is False


def test_connect_allowed_for_any_authenticated_user(memory_app):
    with memory_app.test_request_context("/"):
        from flask import session

        session["user"] = "viewer"
        session["role"] = "viewer"
        assert _authenticate_socket() is True


def test_connect_rejected_after_logout(memory_app):
    with memory_app.test_request_context("/"):
        from flask import session

        session["user"] = "admin"
        assert _authenticate_socket() is True
        session.clear()
        assert _authenticate_socket() is False
