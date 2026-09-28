"""Tests for operator notes, tags and the startup migration."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import IpStatus


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def seed(ip="203.0.113.10", **extra):
    with session_scope() as session:
        row = IpStatus(ip=ip, status="flagged", alert_count=1, **extra)
        session.add(row)
    return ip


def test_note_and_tags_columns_exist():
    seed(operator_note="checked with ops team")
    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.10")
        assert row.operator_note == "checked with ops team"
        assert row.tags == []


def test_add_tag_is_normalised_and_deduplicated():
    seed()
    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.10")
        row.add_tag(" False-Positive ")
        row.add_tag("false-positive")
        row.add_tag("watchlist")
        assert row.tags == ["false-positive", "watchlist"]


def test_remove_tag():
    seed(tags=["a", "b"])
    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.10")
        row.remove_tag("A")
        assert row.tags == ["b"]
        row.remove_tag("missing")  # no-op, no crash
        assert row.tags == ["b"]


def test_tags_survive_session_cycle():
    seed(tags=["handled"])
    with session_scope() as session:
        assert session.get(IpStatus, "203.0.113.10").tags == ["handled"]


def test_migration_is_idempotent(memory_app):
    from app.migrations import run_migrations

    assert run_migrations() == []  # columns already exist after startup
    assert run_migrations() == []
