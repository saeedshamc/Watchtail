"""Tests for the bilingual UI (en/fa)."""

import pytest

import app as watchtail_app
from app.database import dispose_engine
from app.i18n import SUPPORTED, current_language, tr


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def test_default_language_is_english(client):
    html = client.get("/").get_data(as_text=True)
    assert "Dashboard" in html
    assert "events (24h)" in html


def test_toggle_to_persian(client):
    client.get("/lang/fa")
    html = client.get("/").get_data(as_text=True)
    assert "داشبورد" in html
    assert "رویداد (۲۴ ساعت)" in html
    assert "IP پرچم‌دار" in html


def test_toggle_back_to_english(client):
    client.get("/lang/fa")
    client.get("/lang/en")
    html = client.get("/").get_data(as_text=True)
    assert "events (24h)" in html
    assert "داشبورد" not in html


def test_unsupported_lang_is_ignored(client):
    client.get("/lang/de")
    html = client.get("/").get_data(as_text=True)
    assert "Dashboard" in html  # still english


def test_language_survives_across_pages(client):
    client.get("/lang/fa")
    events_html = client.get("/events").get_data(as_text=True)
    assert "دانلود CSV" in events_html


def test_tr_helper_falls_back():
    assert tr("missing.key") == "missing.key"
    assert current_language() in SUPPORTED


def test_lang_toggle_requires_no_login(memory_app):
    # Public route; harmless for anonymous visitors.
    response = memory_app.test_client().get("/lang/fa")
    assert response.status_code == 302
