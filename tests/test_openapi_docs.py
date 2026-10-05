"""Tests for the OpenAPI spec and the /docs page."""

import pytest

import app as watchtail_app
from app.database import dispose_engine
from app.openapi import API_SPEC


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def admin_client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def test_spec_structure():
    assert API_SPEC["openapi"].startswith("3.")
    paths = API_SPEC["paths"]
    for expected in (
        "/ips", "/ips/risky", "/ips/{ip}", "/ips/{ip}/status",
        "/ips/{ip}/annotate", "/alerts", "/stats", "/tokens",
    ):
        assert expected in paths, expected
    assert "bearerAuth" in API_SPEC["components"]["securitySchemes"]


def test_spec_served_without_auth(memory_app):
    client = memory_app.test_client()
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    body = response.get_json()
    assert body["info"]["title"] == "Watchtail REST API"
    assert "/alerts" in body["paths"]


def test_docs_page_lists_endpoints(admin_client):
    html = admin_client.get("/docs").get_data(as_text=True)
    assert "/api/v1/ips" in html
    assert "/api/v1/alerts" in html
    assert "write token" in html
    assert "openapi.json" in html


def test_docs_requires_login(memory_app):
    client = memory_app.test_client()
    assert client.get("/docs").status_code == 302


def test_raw_spec_download(admin_client):
    response = admin_client.get("/docs/openapi.json")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert "/stats" in response.get_data(as_text=True)
