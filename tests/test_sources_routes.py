"""Tests for the log source management routes."""

import pytest

import app as watchtail_app
from app.database import configure_engine, dispose_engine, session_scope
from app.models import LogSource


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    return memory_app.test_client()


def test_sources_page_lists_rows(client):
    with session_scope() as session:
        session.add(
            LogSource(name="n", type="nginx", path="/var/log/nginx/access.log")
        )
    response = client.get("/sources")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "/var/log/nginx/access.log" in html
    assert "Add a source" in html


def test_add_source_requires_known_type(client):
    response = client.post(
        "/sources/add",
        data={"name": "x", "type": "kafka", "path": "/tmp/x.log"},
        follow_redirects=True,
    )
    assert "Unknown source type" in response.get_data(as_text=True)
    with session_scope() as session:
        assert session.query(LogSource).filter(LogSource.path == "/tmp/x.log").count() == 0


def test_add_source_rejects_duplicate_path(client):
    data = {"name": "n", "type": "nginx", "path": "/var/log/site.log"}
    client.post("/sources/add", data=data, follow_redirects=True)
    response = client.post("/sources/add", data=data, follow_redirects=True)
    assert "already exists" in response.get_data(as_text=True)
    with session_scope() as session:
        # normpath turns slashes into backslashes on Windows, so match
        # on the file name rather than the exact string.
        matches = session.query(LogSource).filter(LogSource.path.like("%site.log")).all()
        assert len(matches) == 1


def test_add_source_normalises_relative_path(client):
    client.post(
        "/sources/add",
        data={"name": "rel", "type": "auth", "path": "logs/auth.log"},
        follow_redirects=True,
    )
    with session_scope() as session:
        paths = [row.path for row in session.query(LogSource).all()]
    assert any(
        path.replace("\\", "/").endswith("logs/auth.log") for path in paths
    )


def test_toggle_pauses_and_resumes(client):
    with session_scope() as session:
        source = LogSource(name="n", type="nginx", path="/var/log/a.log")
        session.add(source)
    source_id = source.id  # assigned by the commit's flush
    client.post(f"/sources/{source_id}/toggle", follow_redirects=True)
    with session_scope() as session:
        assert session.get(LogSource, source_id).enabled is False
    client.post(f"/sources/{source_id}/toggle", follow_redirects=True)
    with session_scope() as session:
        assert session.get(LogSource, source_id).enabled is True


def test_delete_source(client):
    with session_scope() as session:
        source = LogSource(name="n", type="nginx", path="/var/log/b.log")
        session.add(source)
    source_id = source.id
    client.post(f"/sources/{source_id}/delete", follow_redirects=True)
    with session_scope() as session:
        assert session.get(LogSource, source_id) is None
