"""Tests for web-triggered tailer reconciliation."""

import pytest

import app as watchtail_app
from app import manager
from app.database import configure_engine, dispose_engine, session_scope
from app.models import LogSource


class FakeManager:
    def __init__(self):
        self.synced = 0

    def sync(self, sources):
        self.synced += 1
        self.last_sources = list(sources)


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    manager.set_manager(None)
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def test_add_source_resyncs_registered_manager(client):
    fake = FakeManager()
    manager.set_manager(fake)
    response = client.post(
        "/sources/add",
        data={"name": "auth", "type": "auth", "path": "C:/logs/auth.log"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert fake.synced == 1
    # The synced list also carries config-declared sources; the newly
    # added path must be among them (normpath resolves against the
    # current drive on Windows, so match on the tail).
    assert any(
        src.path.replace("\\", "/").endswith("logs/auth.log")
        for src in fake.last_sources
    )


def test_routes_skip_resync_without_manager(client):
    manager.set_manager(None)
    response = client.post(
        "/sources/add",
        data={"name": "auth", "type": "auth", "path": "C:/logs/x.log"},
        follow_redirects=True,
    )
    assert response.status_code == 200  # no crash in bare test apps


def test_toggle_and_delete_resync(client):
    with session_scope() as session:
        source = LogSource(
            name="nginx", type="nginx", path="C:/logs/access.log", enabled=True
        )
        session.add(source)
    source_id = source.id

    fake = FakeManager()
    manager.set_manager(fake)

    client.post(f"/sources/{source_id}/toggle", follow_redirects=True)
    assert fake.synced == 1

    client.post(f"/sources/{source_id}/delete", follow_redirects=True)
    assert fake.synced == 2
