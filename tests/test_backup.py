"""Tests for the backup/restore CLI and helpers."""

import datetime as dt

import pytest

import app as watchtail_app
from app.cli import main
from app.database import dispose_engine, session_scope
from app.models import Alert, Event, IpStatus


@pytest.fixture(autouse=True)
def memory_app(monkeypatch):
    monkeypatch.setenv("WATCHTAIL_DATABASE_URL", "sqlite:///:memory:")
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def _seed():
    with session_scope() as session:
        session.add(
            Alert(
                detector="ssh_bruteforce", ip="203.0.113.55", severity="high",
                message="5 failures",
                ts=dt.datetime(2026, 9, 28, 12, 0, 0),
            )
        )
        session.add(
            Event(ts=dt.datetime(2026, 9, 28, 12, 1, 0), ip="203.0.113.55",
                  kind="ssh_auth_fail", meta={"user": "root"})
        )
        session.add(
            IpStatus(ip="203.0.113.55", status="flagged", alert_count=1,
                     tags=["attacker"], threat_score=42)
        )


def test_backup_round_trip(tmp_path):
    _seed()
    archive = tmp_path / "backup.json.gz"

    assert main(["backup", str(archive)]) == 0
    assert archive.exists() and archive.stat().st_size > 0

    # Wipe everything, then restore from the archive.
    with session_scope() as session:
        session.query(Event).delete()
        session.query(Alert).delete()
        session.query(IpStatus).delete()
    with session_scope() as session:
        assert session.query(Alert).count() == 0

    assert main(["restore", str(archive), "--yes"]) == 0
    with session_scope() as session:
        alert = session.query(Alert).one()
        assert alert.detector == "ssh_bruteforce"
        assert alert.ip == "203.0.113.55"
        assert alert.ts == dt.datetime(2026, 9, 28, 12, 0, 0)
        status = session.get(IpStatus, "203.0.113.55")
        assert status.tags == ["attacker"]
        assert status.threat_score == 42
        assert session.query(Event).count() == 1


def test_restore_requires_confirmation(tmp_path, monkeypatch):
    _seed()
    archive = tmp_path / "backup.json.gz"
    assert main(["backup", str(archive)]) == 0

    monkeypatch.setattr("builtins.input", lambda *_: "no")
    exit_code = main(["restore", str(archive)])
    assert exit_code == 1
    with session_scope() as session:
        assert session.query(Alert).count() == 1  # untouched


def test_restore_rejects_non_backup_json(tmp_path):
    bad = tmp_path / "bad.json.gz"
    import gzip
    import json

    bad.write_bytes(
        gzip.compress(json.dumps({"hello": "world"}).encode("utf-8"))
    )
    exit_code = main(["restore", str(bad), "--yes"])
    assert exit_code == 1


def test_restore_rejects_missing_file(tmp_path):
    exit_code = main(["restore", str(tmp_path / "missing.json.gz"), "--yes"])
    assert exit_code == 1


def test_backup_output_path_required():
    assert main(["backup", ""]) == 2
