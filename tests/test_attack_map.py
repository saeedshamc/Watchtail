"""Tests for the MITRE ATT&CK mapping."""

import pytest

import app as watchtail_app
from app.attack_map import ATTACK_MAP, all_described, describe, for_detector
from app.database import dispose_engine


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def test_every_builtin_detector_is_mapped():
    from app.detectors.engine import DETECTOR_CLASSES

    missing = set(DETECTOR_CLASSES) - set(ATTACK_MAP)
    assert not missing, f"detectors without ATT&CK mapping: {missing}"


def test_describe_returns_ids_and_names():
    entry = describe("ssh_bruteforce")
    assert entry["tactic"] == "Credential Access"
    assert entry["tactic_id"] == "TA0006"
    assert entry["technique_id"].startswith("T1110")
    assert "Brute Force" in entry["technique"]


def test_unknown_detector_returns_none():
    assert for_detector("nonexistent") is None
    assert describe("nonexistent") is None


def test_all_described_covers_map():
    described = all_described()
    assert set(described) == set(ATTACK_MAP)
    assert all(v["technique_id"] for v in described.values())


def test_api_alerts_include_mitre(memory_app):
    from app.database import session_scope
    from app.models import Alert, utcnow
    from app.tokens import create_token

    with session_scope() as session:
        session.add(
            Alert(
                ip="1.1.1.1", detector="ssh_bruteforce",
                severity="high", message="m",
            )
        )
    plain, _ = create_token("reader")
    client = memory_app.test_client()
    response = client.get(
        "/api/v1/alerts", headers={"Authorization": f"Bearer {plain}"}
    )
    rows = response.get_json()
    assert rows[0]["mitre"]["tactic_id"] == "TA0006"
