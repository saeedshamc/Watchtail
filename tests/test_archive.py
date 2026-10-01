"""Tests for retention auto-archive (archive before prune)."""

import datetime as dt
import gzip
import json

import pytest

import app as watchtail_app
from app.config import Settings
from app.database import dispose_engine, session_scope
from app.models import Alert, Event
from app.pipeline import prune_old_rows


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def _seed(old_day, fresh_day):
    with session_scope() as session:
        session.add(
            Event(ts=old_day, ip="198.51.100.1", kind="http_access",
                  path="/old", status=404, meta={"a": 1}, raw="old line")
        )
        session.add(
            Event(ts=old_day, ip="198.51.100.2", kind="syslog")
        )
        session.add(
            Event(ts=fresh_day, ip="198.51.100.3", kind="http_access", status=200)
        )
        session.add(
            Alert(detector="path_scan", ip="198.51.100.1", severity="medium",
                  message="scan", ts=old_day, meta={"k": "v"})
        )
        session.add(
            Alert(detector="ssh_bruteforce", ip="198.51.100.9", severity="high",
                  message="burst", ts=fresh_day)
        )


def _read_archive(path):
    lines = []
    with open(path, "rb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="rb") as archive:
            for line in archive.read().decode("utf-8").splitlines():
                lines.append(json.loads(line))
    return lines


def test_archive_written_then_rows_deleted(tmp_path):
    archive_dir = tmp_path / "archive"
    settings = Settings()
    settings.retention_max_age_days = 14
    settings.archive_dir = str(archive_dir)

    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    old_day = now - dt.timedelta(days=30)
    fresh_day = now - dt.timedelta(days=1)
    _seed(old_day, fresh_day)

    prune_old_rows(settings)

    day_dir = archive_dir / old_day.date().isoformat()
    event_lines = _read_archive(str(day_dir / "events.jsonl.gz"))
    alert_lines = _read_archive(str(day_dir / "alerts.jsonl.gz"))

    assert len(event_lines) == 2
    old_event = next(row for row in event_lines if row.get("path") == "/old")
    assert old_event["ip"] == "198.51.100.1"
    assert old_event["meta"] == {"a": 1}
    assert old_event["raw"] == "old line"

    assert len(alert_lines) == 1
    assert alert_lines[0]["detector"] == "path_scan"
    assert alert_lines[0]["meta"] == {"k": "v"}

    # Hot database keeps only fresh rows.
    with session_scope() as session:
        assert session.query(Event).count() == 1
        assert session.query(Alert).count() == 1


def test_no_archive_dir_deletes_without_archiving(tmp_path):
    settings = Settings()
    settings.retention_max_age_days = 14
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    _seed(now - dt.timedelta(days=30), now - dt.timedelta(days=1))

    prune_old_rows(settings)

    with session_scope() as session:
        assert session.query(Event).count() == 1
        assert session.query(Alert).count() == 1


def test_archive_failure_does_not_block_prune(tmp_path, monkeypatch):
    archive_dir = tmp_path / "archive"
    settings = Settings()
    settings.retention_max_age_days = 14
    settings.archive_dir = str(archive_dir)
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    _seed(now - dt.timedelta(days=30), now - dt.timedelta(days=1))

    # Force makedirs to fail as if the volume were full.
    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("os.makedirs", boom)
    prune_old_rows(settings)

    with session_scope() as session:
        # The delete still happened; only the archive copy is lost.
        assert session.query(Event).count() == 1


def test_zero_retention_deletes_nothing(tmp_path):
    settings = Settings()
    settings.retention_max_age_days = 0
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    _seed(now - dt.timedelta(days=400), now)
    prune_old_rows(settings)
    with session_scope() as session:
        assert session.query(Event).count() == 3
        assert session.query(Alert).count() == 2
