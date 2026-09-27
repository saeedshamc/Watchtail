"""Tests for the events browser, JSON API and CSV export."""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Event, utcnow


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def add_event(**overrides):
    fields = {
        "ip": "203.0.113.7",
        "kind": "http_access",
        "method": "GET",
        "path": "/admin",
        "status": 404,
        "user_agent": "watchtail-test/1.0",
        "raw": 'GET /admin HTTP/1.1" 404',
        "meta": {},
    }
    fields.update(overrides)
    with session_scope() as session:
        session.add(Event(**fields))


def test_events_page_lists_events_and_links(client):
    add_event()
    html = client.get("/events").get_data(as_text=True)
    assert "203.0.113.7" in html
    assert "/admin" in html
    assert "download CSV" in html
    assert "JSON API" in html


def test_filter_by_ip(client):
    add_event()
    add_event(ip="198.51.100.2", path="/other")
    html = client.get("/events?ip=198.51.100.2").get_data(as_text=True)
    assert "198.51.100.2" in html
    assert "203.0.113.7" not in html


def test_filter_by_kind_and_status_class(client):
    add_event()
    add_event(ip="198.51.100.3", kind="ssh_auth_fail", status=None,
              raw="Failed password for root")
    assert "203.0.113.7" not in client.get("/events?kind=ssh_auth_fail").get_data(as_text=True)
    assert "203.0.113.7" not in client.get("/events?status=5xx").get_data(as_text=True)
    assert "203.0.113.7" in client.get("/events?status=4xx").get_data(as_text=True)


def test_text_search_matches_raw_path_and_agent(client):
    add_event()
    assert "/admin" in client.get("/events?q=admin").get_data(as_text=True)
    assert "203.0.113.7" in client.get("/events?q=watchtail-test").get_data(as_text=True)
    assert "203.0.113.7" in client.get("/events?q=HTTP/1.1").get_data(as_text=True)
    assert "203.0.113.7" not in client.get("/events?q=zebra").get_data(as_text=True)


def test_hours_window_excludes_old_events(client):
    add_event()
    add_event(
        path="/archived",
        ts=utcnow() - dt.timedelta(hours=48),
    )
    assert "/archived" not in client.get("/events?hours=24").get_data(as_text=True)
    assert "/archived" in client.get("/events?hours=72").get_data(as_text=True)


def test_pagination(client):
    for index in range(12):
        add_event(path=f"/page-{index}", ts=utcnow() - dt.timedelta(minutes=index))
    html_page1 = client.get("/events?limit=10&page=1").get_data(as_text=True)
    assert "/page-0" in html_page1
    assert "/page-11" not in html_page1
    html_page2 = client.get("/events?limit=10&page=2").get_data(as_text=True)
    assert "/page-11" in html_page2
    assert "/page-0" not in html_page2


def test_invalid_query_args_fall_back_to_defaults(client):
    add_event()
    for query in ("?limit=999999", "?page=abc", "?hours=-5", "?status=7xx"):
        assert client.get(f"/events{query}").status_code == 200


def test_events_api_returns_json(client):
    add_event()
    response = client.get("/api/events?kind=http_access&limit=10")
    assert response.status_code == 200
    rows = response.get_json()
    assert len(rows) == 1
    assert rows[0]["ip"] == "203.0.113.7"
    assert rows[0]["path"] == "/admin"
    assert rows[0]["status"] == 404
    assert rows[0]["ts"].endswith("Z")


def test_events_api_respects_filters(client):
    add_event()
    add_event(ip="198.51.100.4", path="/keep-out", status=500)
    rows = client.get("/api/events?status=5xx").get_json()
    assert [row["path"] for row in rows] == ["/keep-out"]


def test_csv_export_has_headers_and_rows(client):
    add_event()
    response = client.get("/events.csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    lines = response.get_data(as_text=True).strip().splitlines()
    assert lines[0] == "ts,kind,ip,method,path,status,bytes_sent,user_agent"
    assert "203.0.113.7" in lines[1]
    assert "/admin" in lines[1]


def test_events_require_login(memory_app):
    for path in ("/events", "/api/events", "/events.csv"):
        response = memory_app.test_client().get(path)
        assert response.status_code == 401 if path.startswith("/api/") else response.status_code == 302
