"""Tests for the inbound webhook ingest endpoint."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Alert, IpStatus
from app.tokens import create_token


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def write_token():
    plain, _ = create_token("n8n", can_write=True)
    return plain


@pytest.fixture
def read_token():
    plain, _ = create_token("reader")
    return plain


def auth(plain):
    return {"Authorization": f"Bearer {plain}"}


def post(client, body, token):
    return client.post(
        "/api/v1/ingest", json=body, headers=auth(token)
    )


def test_ingest_persists_and_flags(memory_app, write_token):
    response = post(
        memory_app.test_client(),
        {
            "ip": "198.51.100.20",
            "message": "Wazuh rule 5710: multiple auth failures",
            "detector": "wazuh",
            "severity": "high",
            "meta": {"rule": 5710},
        },
        write_token,
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["accepted"] is True

    with session_scope() as session:
        alert = session.get(Alert, body["id"])
        assert alert.detector == "wazuh"
        assert alert.severity == "high"
        assert alert.meta["rule"] == 5710
        flagged = session.get(IpStatus, "198.51.100.20")
        assert flagged.status == "flagged"
        assert flagged.threat_score >= 40  # high weight
        assert flagged.reason.startswith("[wazuh]")


def test_ingest_requires_write_token(memory_app, read_token):
    response = post(
        memory_app.test_client(),
        {"ip": "1.1.1.1", "message": "m"},
        read_token,
    )
    assert response.status_code == 403


def test_ingest_requires_auth(memory_app):
    response = memory_app.test_client().post(
        "/api/v1/ingest", json={"ip": "1.1.1.1", "message": "m"}
    )
    assert response.status_code == 401


def test_ingest_validates_payload(memory_app, write_token):
    client = memory_app.test_client()
    assert post(client, {}, write_token).status_code == 400
    assert post(client, {"ip": "1.1.1.1"}, write_token).status_code == 400
    assert post(client, {"message": "m"}, write_token).status_code == 400
    # Bad severity falls back to medium rather than erroring.
    response = post(
        client,
        {"ip": "1.1.1.2", "message": "m", "severity": "EXTREME"},
        write_token,
    )
    assert response.status_code == 201
    assert response.get_json()["severity"] == "medium"


def test_ingest_respects_dismissed(memory_app, write_token):
    with session_scope() as session:
        session.add(IpStatus(ip="1.1.1.3", status="dismissed"))
    post(
        memory_app.test_client(),
        {"ip": "1.1.1.3", "message": "again"},
        write_token,
    )
    with session_scope() as session:
        row = session.get(IpStatus, "1.1.1.3")
        assert row.status == "dismissed"  # operator decision stands
        assert session.query(Alert).count() == 1  # but history is kept


def test_dismissed_via_api_can_be_reingested_after_review(memory_app, write_token):
    client = memory_app.test_client()
    with session_scope() as session:
        session.add(IpStatus(ip="1.1.1.4", status="reviewed"))
    post(client, {"ip": "1.1.1.4", "message": "re-offender"}, write_token)
    with session_scope() as session:
        assert session.get(IpStatus, "1.1.1.4").status == "flagged"
