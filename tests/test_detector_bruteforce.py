"""Tests for the SSH brute force detector and the engine."""

import datetime as dt

from app.config import Settings
from app.detectors import DetectionEngine
from app.detectors.ssh_bruteforce import SshBruteforceDetector
from app.parsers.base import ParsedLine


def fail(ip="203.0.113.44", minute=0, user="admin"):
    return ParsedLine(
        kind="ssh_auth_fail",
        ts=dt.datetime(2026, 9, 26, 12, minute, 0),
        ip=ip,
        meta={"user": user, "port": 41000 + minute},
    )


def test_fires_after_threshold_within_window():
    detector = SshBruteforceDetector({"max_failures": 3, "window_seconds": 300})
    assert detector.feed(fail(minute=1)) == []
    assert detector.feed(fail(minute=2)) == []
    alerts = detector.feed(fail(minute=3))
    assert len(alerts) == 1
    assert alerts[0].ip == "203.0.113.44"
    assert alerts[0].detector == "ssh_bruteforce"
    assert alerts[0].severity == "high"
    assert alerts[0].meta["failures"] == 3


def test_no_fire_when_spread_outside_window():
    detector = SshBruteforceDetector({"max_failures": 3, "window_seconds": 300})
    detector.feed(fail(minute=0))
    detector.feed(fail(minute=3))
    assert detector.feed(fail(minute=7)) == []


def test_window_slides_so_old_failures_expire():
    detector = SshBruteforceDetector({"max_failures": 3, "window_seconds": 300})
    detector.feed(fail(minute=0))
    detector.feed(fail(minute=9))
    # minute=0 is now > 300s older than minute=10, so only two failures
    # remain inside the window.
    assert detector.feed(fail(minute=10)) == []
    assert detector.feed(fail(minute=11)) != []


def test_cooldown_suppresses_repeated_alerts():
    detector = SshBruteforceDetector({"max_failures": 2, "window_seconds": 300})
    detector.feed(fail(minute=1))
    first = detector.feed(fail(minute=2))
    assert len(first) == 1
    # Further failures within the cooldown stay quiet.
    assert detector.feed(fail(minute=3)) == []
    assert detector.feed(fail(minute=4)) == []


def test_ips_are_tracked_independently():
    detector = SshBruteforceDetector({"max_failures": 3, "window_seconds": 300})
    detector.feed(fail(ip="1.1.1.1", minute=1))
    detector.feed(fail(ip="1.1.1.1", minute=2))
    assert detector.feed(fail(ip="2.2.2.2", minute=3)) == []
    assert detector.feed(fail(ip="1.1.1.1", minute=4)) != []


def test_engine_only_runs_configured_detectors():
    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 60}
    }
    engine = DetectionEngine(settings)
    assert engine.detector_names() == ["ssh_bruteforce"]
    assert engine.feed(fail(minute=1)) == []
    alerts = engine.feed(fail(minute=2))
    assert len(alerts) == 1

    disabled = Settings()
    disabled.detectors = {"ssh_bruteforce": {"enabled": False}}
    assert DetectionEngine(disabled).detectors == []


def test_engine_ignores_other_kinds():
    settings = Settings()
    settings.detectors = {"ssh_bruteforce": {"enabled": True, "max_failures": 1}}
    engine = DetectionEngine(settings)
    record = ParsedLine(kind="http_access", ts=dt.datetime(2026, 9, 26, 12, 0, 0), ip="1.2.3.4")
    assert engine.feed(record) == []
