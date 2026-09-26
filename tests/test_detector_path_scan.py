"""Tests for the path scan detector."""

import datetime as dt

from app.config import Settings
from app.detectors import DetectionEngine
from app.detectors.path_scan import PathScanDetector
from app.parsers.base import ParsedLine

T0 = dt.datetime(2026, 9, 26, 12, 0, 0)


def probe(path, ip="203.0.113.7", second=0, status=404):
    return ParsedLine(
        kind="http_access",
        ts=T0 + dt.timedelta(seconds=second),
        ip=ip,
        method="GET",
        path=path,
        status=status,
    )


def test_fires_on_distinct_paths():
    detector = PathScanDetector({"max_paths": 3, "window_seconds": 60})
    detector.feed(probe("/a"))
    detector.feed(probe("/a"))          # repeat does not count twice
    detector.feed(probe("/b"))
    alerts = detector.feed(probe("/c"))
    assert len(alerts) == 1
    assert alerts[0].meta["distinct_paths"] == 3
    assert set(alerts[0].meta["sample_paths"]) == {"/a", "/b", "/c"}


def test_ignores_successes_and_missing_paths():
    detector = PathScanDetector({"max_paths": 2, "window_seconds": 60})
    detector.feed(probe("/ok", status=200))
    assert detector.feed(probe(None, status=404)) == []


def test_old_probes_expire_from_the_window():
    detector = PathScanDetector({"max_paths": 3, "window_seconds": 60})
    detector.feed(probe("/old1", second=0))
    detector.feed(probe("/old2", second=1))
    # Window slid past the first two probes.
    detector.feed(probe("/new1", second=100))
    assert detector.feed(probe("/new2", second=101)) == []
    assert detector.feed(probe("/new3", second=102)) != []


def test_no_repeat_alert_inside_cooldown():
    detector = PathScanDetector({"max_paths": 2, "window_seconds": 60})
    detector.feed(probe("/x"))
    assert detector.feed(probe("/y")) != []
    before = detector._cooldown_until["203.0.113.7"]
    more = detector.feed(probe("/z", second=10))
    assert more == []
    assert detector._cooldown_until["203.0.113.7"] == before


def test_engine_registers_rule_when_enabled():
    settings = Settings()
    settings.detectors = {
        "path_scan": {"enabled": True, "max_paths": 2, "window_seconds": 60}
    }
    engine = DetectionEngine(settings)
    assert "path_scan" in engine.detector_names()
    engine.feed(probe("/a"))
    alerts = engine.feed(probe("/b"))
    assert [a.detector for a in alerts] == ["path_scan"]
