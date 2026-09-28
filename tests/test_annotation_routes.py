"""Tests for annotation routes."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import IpStatus


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


def seed(ip="203.0.113.77", **extra):
    with session_scope() as session:
        session.add(IpStatus(ip=ip, status="flagged", alert_count=2, **extra))


def get_row(ip="203.0.113.77"):
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        return row.operator_note, list(row.tags or [])


def test_annotate_saves_note_and_tags(client):
    seed()
    response = client.post(
        "/ips/203.0.113.77/annotate",
        data={"note": "confirmed malware host", "tags": "Watchlist, handled"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    note, tags = get_row()
    assert note == "confirmed malware host"
    assert tags == ["watchlist", "handled"]


def test_annotate_shows_note_on_detail_page(client):
    seed(operator_note="ticket #42 from SOC")
    html = client.get("/ips/203.0.113.77").get_data(as_text=True)
    assert "ticket #42 from SOC" in html
    # No tags seeded: the chips list must be absent (the tag input's
    # placeholder mentions example tags, so search for the list itself).
    assert 'class="tag-row"' not in html


def test_detail_page_shows_tag_chips(client):
    seed(tags=["false-positive"])
    html = client.get("/ips/203.0.113.77").get_data(as_text=True)
    assert "false-positive" in html


def test_empty_note_clears_field(client):
    seed(operator_note="old note")
    client.post(
        "/ips/203.0.113.77/annotate",
        data={"note": "", "tags": ""},
        follow_redirects=True,
    )
    note, tags = get_row()
    assert note is None
    assert tags == []


def test_tag_count_is_capped(client):
    seed()
    many = ",".join(f"tag{i}" for i in range(30))
    client.post(
        "/ips/203.0.113.77/annotate",
        data={"note": "", "tags": many},
        follow_redirects=True,
    )
    _, tags = get_row()
    assert len(tags) <= 12


def test_remove_tag_route(client):
    seed(tags=["a", "keep"])
    client.post(
        "/ips/203.0.113.77/tags/remove",
        data={"tag": "a"},
        follow_redirects=True,
    )
    _, tags = get_row()
    assert tags == ["keep"]


def test_annotate_unknown_ip_flashes(client):
    # Follow only one hop so the flash message itself is checked before
    # it is consumed by the redirected page.
    response = client.post(
        "/ips/10.9.9.9/annotate",
        data={"note": "x", "tags": ""},
    )
    page = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "nothing to annotate" in page


def test_dashboard_shows_note_and_tags(client):
    seed(operator_note="very suspicious", tags=["watchlist"])
    html = client.get("/").get_data(as_text=True)
    assert "very suspicious" in html
    assert "watchlist" in html


def test_flagged_api_includes_annotations(client):
    seed(operator_note="note", tags=["t1"])
    rows = client.get("/api/flagged").get_json()
    row = next(r for r in rows if r["ip"] == "203.0.113.77")
    assert row["operator_note"] == "note"
    assert row["tags"] == ["t1"]
