"""Tests for the SSH compromise detector."""

import datetime as dt

from app.config import Settings
from app.detectors import DetectionEngine
from app.detectors.ssh_compromise import SshCompromiseDetector
from app.parsers.base import ParsedLine

T0 = dt.datetime(2026, 9, 26, 12, 0, 0)


def ssh(kind, ip="203.0.113.44", second=0, user="admin"):
    return ParsedLine(
        kind=kind,
        ts=T0 + dt.timedelta(seconds=second),
        ip=ip,
        meta={"user": user, "port": 41000},
    )


def test_fires_when_login_follows_failures():
    detector = SshCompromiseDetector({"min_failures": 1, "window_seconds": 600})
    detector.feed(ssh("ssh_auth_fail", second=10))
    detector.feed(ssh("ssh_auth_fail", second=20))
    alerts = detector.feed(ssh("ssh_session_open", second=30))
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].meta["recent_failures"] == 2
    assert alerts[0].meta["user"] == "admin"


def test_quiet_when_no_prior_failures():
    detector = SshCompromiseDetector({"min_failures": 1, "window_seconds": 600})
    assert detector.feed(ssh("ssh_session_open", second=5)) == []


def test_failures_outside_window_do_not_count():
    detector = SshCompromiseDetector({"min_failures": 1, "window_seconds": 600})
    detector.feed(ssh("ssh_auth_fail", second=0))
    late = detector.feed(ssh("ssh_session_open", second=601))
    assert late == []


def test_min_failures_threshold():
    detector = SshCompromiseDetector({"min_failures": 3, "window_seconds": 600})
    detector.feed(ssh("ssh_auth_fail", second=1))
    detector.feed(ssh("ssh_auth_fail", second=2))
    assert detector.feed(ssh("ssh_session_open", second=3)) == []
    detector.feed(ssh("ssh_auth_fail", second=4))
    assert detector.feed(ssh("ssh_session_open", second=5)) != []


def test_runs_through_the_engine_when_enabled():
    settings = Settings()
    settings.detectors = {
        "ssh_compromise": {"enabled": True, "min_failures": 1, "window_seconds": 60}
    }
    engine = DetectionEngine(settings)
    assert "ssh_compromise" in engine.detector_names()
    engine.feed(ssh("ssh_auth_fail", second=1))
    alerts = engine.feed(ssh("ssh_session_open", second=2))
    assert [a.detector for a in alerts] == ["ssh_compromise"]
