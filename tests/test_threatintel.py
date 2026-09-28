"""Tests for the threat intel blocklist store and pipeline hook."""

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, IpStatus
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline
from app.threatintel import (
    Blocklist,
    BlocklistStore,
    get_store,
    load_from_settings,
    reset_store,
)


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    reset_store()
    dispose_engine()


class TestBlocklist:
    def test_exact_and_cidr_membership(self):
        blocklist = Blocklist("test")
        blocklist.add("203.0.113.9")
        blocklist.add("198.51.100.0/24")
        assert blocklist.contains("203.0.113.9")
        assert blocklist.contains("198.51.100.77")
        assert not blocklist.contains("198.51.101.1")
        assert not blocklist.contains("not-an-ip")
        assert len(blocklist) == 2

    def test_comments_and_blank_lines_skipped(self):
        blocklist = Blocklist("test")
        blocklist.add("# comment")
        blocklist.add("")
        assert len(blocklist) == 0

    def test_bad_entries_are_skipped(self):
        blocklist = Blocklist("test")
        blocklist.add("999.999.999.999")
        blocklist.add("10.0.0.1")
        assert len(blocklist) == 1


class TestStoreFiles:
    def test_plain_text_load(self, tmp_path):
        path = tmp_path / "bad.txt"
        path.write_text("# list\n203.0.113.9\n198.51.100.0/24\n", encoding="utf-8")
        store = BlocklistStore()
        count = store.load_file(str(path), "test-list")
        assert count == 2
        assert store.lookup("203.0.113.9") == "test-list"
        assert store.lookup("198.51.100.5") == "test-list"
        assert store.lookup("8.8.8.8") is None

    def test_csv_load_by_header(self, tmp_path):
        path = tmp_path / "abuse.csv"
        path.write_text(
            "IPAddress,AbuseConfidenceScore,Country\n"
            "203.0.113.99,100,IR\n"
            "203.0.113.100,88,CN\n",
            encoding="utf-8",
        )
        store = BlocklistStore()
        count = store.load_file(str(path), "abuseipdb")
        assert count == 2
        assert store.lookup("203.0.113.99") == "abuseipdb"

    def test_missing_file_is_warning_not_crash(self, tmp_path):
        store = BlocklistStore()
        assert store.load_file(str(tmp_path / "nope.txt")) == 0


def test_load_from_settings_resets_store():
    from app.threatintel import load_from_settings

    store = get_store()
    settings = Settings()
    settings.threatintel = {"blocklists": []}
    assert load_from_settings(settings) == 0
    # Store was reset: fresh instance, empty cache.
    assert get_store() is not store


def test_pipeline_flags_blocklisted_ip(tmp_path):
    blockfile = tmp_path / "bad.txt"
    blockfile.write_text("203.0.113.44\n", encoding="utf-8")
    settings = Settings()
    settings.detectors = {}  # no behavioural detectors at all
    settings.threatintel = {"blocklists": [{"path": str(blockfile), "name": "unit"}]}
    load_from_settings(settings)

    pipeline = Pipeline(settings)
    pipeline.handle_record(
        ParsedLine(
            kind="http_access",
            ts=__import__("datetime").datetime(2026, 9, 28, 12, 0, 0),
            ip="203.0.113.44",
            method="GET",
            path="/",
            status=200,
        ),
        "raw",
        None,
    )

    with session_scope() as session:
        alert = session.query(Alert).one()
        assert alert.detector == "threat_intel"
        assert alert.severity == "critical"
        assert alert.ip == "203.0.113.44"
        flagged = session.get(IpStatus, "203.0.113.44")
        assert flagged.status == "flagged"
        assert flagged.threat_score >= 100  # critical weight


def test_non_listed_ip_not_flagged_by_intel(tmp_path):
    blockfile = tmp_path / "bad.txt"
    blockfile.write_text("203.0.113.44\n", encoding="utf-8")
    settings = Settings()
    settings.detectors = {}
    settings.threatintel = {"blocklists": [{"path": str(blockfile)}]}
    load_from_settings(settings)

    pipeline = Pipeline(settings)
    pipeline.handle_record(
        ParsedLine(
            kind="http_access",
            ts=__import__("datetime").datetime(2026, 9, 28, 12, 0, 0),
            ip="8.8.8.8", method="GET", path="/", status=200,
        ),
        "raw", None,
    )
    with session_scope() as session:
        assert session.query(Alert).count() == 0
