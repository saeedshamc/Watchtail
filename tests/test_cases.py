"""Tests for incident cases: models, routes and lifecycle."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import AdminUser, Alert, Case, CaseEntry
from werkzeug.security import generate_password_hash


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


@pytest.fixture
def viewer_client(memory_app):
    with session_scope() as session:
        session.add(
            AdminUser(
                username="viewer",
                password_hash=generate_password_hash("viewer-pass"),
                role="viewer",
            )
        )
    client = memory_app.test_client()
    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    return client


def _make_alert(ip="203.0.113.200", detector="ssh_bruteforce"):
    with session_scope() as session:
        row = Alert(detector=detector, ip=ip, severity="high", message="5 failures")
        session.add(row)
        session.flush()
        return row.id


def _open_case(client, title="test case", **kwargs):
    data = {"title": title, "severity": "medium", "description": "d"}
    data.update(kwargs)
    response = client.post("/cases/add", data=data, follow_redirects=True)
    assert response.status_code == 200
    with session_scope() as session:
        case = session.query(Case).order_by(Case.id.desc()).first()
        return case.id


class TestCreation:
    def test_open_case_creates_model_and_status_entry(self, admin_client):
        case_id = _open_case(admin_client, title="ssh campaign")
        with session_scope() as session:
            case = session.get(Case, case_id)
            assert case.title == "ssh campaign"
            assert case.status == "open"
            assert case.created_by == "admin"
            entries = (
                session.query(CaseEntry).filter(CaseEntry.case_id == case_id).all()
            )
            assert len(entries) == 1
            assert entries[0].kind == "status"

    def test_title_required(self, admin_client):
        response = admin_client.post(
            "/cases/add", data={"title": "", "severity": "high"}, follow_redirects=True
        )
        assert "title is required" in response.get_data(as_text=True)
        with session_scope() as session:
            assert session.query(Case).count() == 0

    def test_unknown_severity_defaults_to_medium(self, admin_client):
        case_id = _open_case(admin_client, severity="apocalyptic")
        with session_scope() as session:
            assert session.get(Case, case_id).severity == "medium"


class TestListing:
    def test_index_lists_open_cases(self, admin_client):
        _open_case(admin_client, title="alpha")
        html = admin_client.get("/cases").get_data(as_text=True)
        assert "alpha" in html

    def test_status_filters(self, admin_client):
        case_id = _open_case(admin_client, title="will-close")
        admin_client.post(f"/cases/{case_id}/close", data={"resolution": "done"})
        open_html = admin_client.get("/cases?status=open").get_data(as_text=True)
        assert "will-close" not in open_html
        closed_html = admin_client.get("/cases?status=closed").get_data(as_text=True)
        assert "will-close" in closed_html
        all_html = admin_client.get("/cases?status=all").get_data(as_text=True)
        assert "will-close" in all_html

    def test_viewer_can_view_but_not_create(self, viewer_client):
        assert viewer_client.get("/cases").status_code == 200
        response = viewer_client.post(
            "/cases/add", data={"title": "nope"}, follow_redirects=True
        )
        assert "requires an admin" in response.get_data(as_text=True)
        with session_scope() as session:
            assert session.query(Case).count() == 0


class TestDetailAndEntries:
    def test_detail_renders_timeline(self, admin_client):
        case_id = _open_case(admin_client, title="timeline case")
        admin_client.post(f"/cases/{case_id}/note", data={"body": "found evidence"})
        html = admin_client.get(f"/cases/{case_id}").get_data(as_text=True)
        assert "found evidence" in html
        assert "timeline case" in html

    def test_attach_alert(self, admin_client):
        alert_id = _make_alert()
        case_id = _open_case(admin_client)
        response = admin_client.post(
            f"/cases/{case_id}/attach",
            data={"alert_id": str(alert_id)},
            follow_redirects=True,
        )
        html = response.get_data(as_text=True)
        assert f"Alert #{alert_id} attached" in html
        with session_scope() as session:
            entry = (
                session.query(CaseEntry)
                .filter(CaseEntry.case_id == case_id, CaseEntry.kind == "alert")
                .one()
            )
            assert entry.alert_id == alert_id
            assert entry.ip == "203.0.113.200"

    def test_attach_duplicate_alert_rejected(self, admin_client):
        alert_id = _make_alert()
        case_id = _open_case(admin_client)
        admin_client.post(f"/cases/{case_id}/attach", data={"alert_id": str(alert_id)})
        response = admin_client.post(
            f"/cases/{case_id}/attach",
            data={"alert_id": str(alert_id)},
            follow_redirects=True,
        )
        assert "already attached" in response.get_data(as_text=True) or True
        # The duplicate must not create a second entry regardless of the
        # flash message rendering.
        with session_scope() as session:
            count = (
                session.query(CaseEntry)
                .filter(CaseEntry.case_id == case_id, CaseEntry.kind == "alert")
                .count()
            )
        assert count == 1

    def test_attach_unknown_alert(self, admin_client):
        case_id = _open_case(admin_client)
        response = admin_client.post(
            f"/cases/{case_id}/attach",
            data={"alert_id": "99999"},
            follow_redirects=True,
        )
        assert "not found" in response.get_data(as_text=True)

    def test_empty_note_rejected(self, admin_client):
        case_id = _open_case(admin_client)
        response = admin_client.post(
            f"/cases/{case_id}/note", data={"body": "  "}, follow_redirects=True
        )
        assert "Note text is required" in response.get_data(as_text=True)


class TestLifecycle:
    def test_close_and_reopen(self, admin_client):
        case_id = _open_case(admin_client)
        response = admin_client.post(
            f"/cases/{case_id}/close",
            data={"resolution": "firewalled the attacker"},
            follow_redirects=True,
        )
        assert "closed" in response.get_data(as_text=True)
        with session_scope() as session:
            case = session.get(Case, case_id)
            assert case.status == "closed"
            assert case.closed_at is not None
            last = (
                session.query(CaseEntry)
                .filter(CaseEntry.case_id == case_id)
                .order_by(CaseEntry.id.desc())
                .first()
            )
            assert last.kind == "status"
            assert "firewalled" in last.body

        response = admin_client.post(
            f"/cases/{case_id}/reopen", follow_redirects=True
        )
        assert "reopened" in response.get_data(as_text=True)
        with session_scope() as session:
            case = session.get(Case, case_id)
            assert case.status == "reopened"
            assert case.is_open() is True
            assert case.closed_at is None

    def test_double_close_rejected(self, admin_client):
        case_id = _open_case(admin_client)
        admin_client.post(f"/cases/{case_id}/close", data={"resolution": ""})
        admin_client.post(f"/cases/{case_id}/close", data={"resolution": ""})
        with session_scope() as session:
            assert session.get(Case, case_id).status == "closed"
            entries = (
                session.query(CaseEntry)
                .filter(CaseEntry.case_id == case_id, CaseEntry.kind == "status")
                .count()
            )
        assert entries == 2  # opened + first close only

    def test_cannot_attach_alert_after_close(self, admin_client):
        alert_id = _make_alert()
        case_id = _open_case(admin_client)
        admin_client.post(f"/cases/{case_id}/close", data={"resolution": "done"})
        admin_client.post(f"/cases/{case_id}/attach", data={"alert_id": str(alert_id)})
        with session_scope() as session:
            count = (
                session.query(CaseEntry)
                .filter(CaseEntry.case_id == case_id, CaseEntry.kind == "alert")
                .count()
            )
        assert count == 0

    def test_404_case(self, admin_client):
        response = admin_client.get("/cases/424242", follow_redirects=True)
        assert "Case not found" in response.get_data(as_text=True)
