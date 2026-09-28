"""Tests for the playbook automation engine."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import AuditEntry, IpStatus
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline
from app.playbooks import PlaybookEngine, PlaybookRule, configure, get_engine


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    dispose_engine()


class AlertRow:
    def __init__(self, detector="threat_intel", ip="1.1.1.1", severity="critical"):
        self.detector = detector
        self.ip = ip
        self.severity = severity
        self.message = "m"
        self.ts = dt.datetime(2026, 9, 28, 12, 0, 0)
        self.meta = {}


def test_matching_on_detector_and_severity():
    rule = PlaybookRule(
        "escalate intel",
        {"detector": "threat_intel", "min_severity": "critical"},
        [{"action": "audit", "detail": "known-bad seen"}],
    )
    assert rule.matches(AlertRow()) is True
    assert rule.matches(AlertRow(detector="path_scan")) is False
    assert rule.matches(AlertRow(severity="low")) is False


def test_tag_action_needs_ip_row():
    engine = PlaybookEngine(
        [{"name": "t", "when": {}, "actions": [{"action": "tag", "tags": ["x"]}]}]
    )
    assert engine.process(AlertRow(), ip_row=None) == []  # no row, no crash

    with session_scope() as session:
        row = IpStatus(ip="1.1.1.1", status="flagged")
        session.add(row)
        session.flush()
        outcomes = engine.process(AlertRow(), ip_row=row)
        assert any("tagged" in o for o in outcomes)
        assert row.tags == ["x"]


def test_suppress_action_registers_window():
    from app.suppression import get_store, reset_store

    reset_store()
    engine = PlaybookEngine(
        [{"name": "quiet", "when": {}, "actions": [{"action": "suppress", "minutes": 45}]}]
    )
    engine.process(AlertRow())
    assert get_store().is_suppressed(ip="1.1.1.1", detector="threat_intel")


def test_audit_action_writes_trail():
    engine = PlaybookEngine(
        [{"name": "log-it", "when": {}, "actions": [{"action": "audit", "detail": "seen"}]}]
    )
    engine.process(AlertRow())
    with session_scope() as session:
        entry = session.query(AuditEntry).one()
        assert entry.actor == "playbook"
        assert entry.detail == "seen"


def test_escalate_action_bumps_score():
    with session_scope() as session:
        session.add(IpStatus(ip="1.1.1.1", status="flagged", threat_score=10))
    engine = PlaybookEngine(
        [{"name": "hot", "when": {}, "actions": [{"action": "escalate", "score": 75}]}]
    )
    with session_scope() as session:
        row = session.get(IpStatus, "1.1.1.1")
        engine.process(AlertRow(), ip_row=row)
    with session_scope() as session:
        assert session.get(IpStatus, "1.1.1.1").threat_score == 85


def test_pipeline_runs_playbooks():
    configure(
        [{"name": "intel-tag", "when": {"detector": "threat_intel"},
          "actions": [{"action": "tag", "tags": ["known-bad"]}]}]
    )
    settings = Settings()
    settings.detectors = {}
    settings.threatintel = {}  # simulate via direct alert: use a detector instead
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    # Reconfigure playbooks for the bruteforce detector.
    configure(
        [{"name": "bf-tag", "when": {"detector": "ssh_bruteforce"},
          "actions": [{"action": "tag", "tags": ["bruteforcer"]}]}]
    )
    pipeline = Pipeline(settings)

    def fail(minute):
        return ParsedLine(
            kind="ssh_auth_fail",
            ts=dt.datetime(2026, 9, 28, 12, minute, 0),
            ip="203.0.113.44",
            meta={"user": "root"},
        )

    pipeline.handle_record(fail(1), "raw", None)
    pipeline.handle_record(fail(2), "raw", None)

    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.44")
        assert row.tags == ["bruteforcer"]


def test_global_engine_configured():
    configure([{"name": "n", "when": {}, "actions": []}])
    assert get_engine().rules[0].name == "n"
