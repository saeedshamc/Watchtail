"""Tests for the HTTP error spike and request burst detectors."""

import datetime as dt

from app.config import Settings
from app.detectors import DetectionEngine
from app.detectors.burst import RequestBurstDetector
from app.detectors.http_errors import HttpErrorSpikeDetector
from app.parsers.base import ParsedLine

T0 = dt.datetime(2026, 9, 26, 12, 0, 0)


def hit(ip="203.0.113.7", status=404, second=0, path="/admin"):
    return ParsedLine(
        kind="http_access",
        ts=T0 + dt.timedelta(seconds=second),
        ip=ip,
        method="GET",
        path=path,
        status=status,
    )


def request(ip="198.51.100.5", second=0):
    return ParsedLine(
        kind="http_access",
        ts=T0 + dt.timedelta(seconds=second),
        ip=ip,
        method="GET",
        path="/",
        status=200,
    )


def test_error_spike_fires_at_threshold():
    detector = HttpErrorSpikeDetector({"max_errors": 3, "window_seconds": 60})
    assert detector.feed(hit(status=404, second=1)) == []
    assert detector.feed(hit(status=403, second=2)) == []
    alerts = detector.feed(hit(status=404, second=3))
    assert len(alerts) == 1
    assert alerts[0].meta["status_counts"] == {"403": 1, "404": 2}
    assert alerts[0].severity == "medium"


def test_error_spike_ignores_other_statuses_and_successes():
    detector = HttpErrorSpikeDetector({"max_errors": 3, "window_seconds": 60})
    detector.feed(hit(status=404, second=1))
    detector.feed(hit(status=500, second=2))
    detector.feed(hit(status=200, second=3))
    assert detector.feed(hit(status=404, second=4)) == []


def test_error_spike_ignores_ips_without_ip():
    detector = HttpErrorSpikeDetector({"max_errors": 1, "window_seconds": 60})
    assert detector.feed(hit(ip=None, status=404)) == []


def test_burst_fires_at_threshold():
    detector = RequestBurstDetector({"max_requests": 5, "window_seconds": 60})
    for second in range(4):
        detector.feed(request(second=second))
    alerts = detector.feed(request(second=5))
    assert len(alerts) == 1
    assert alerts[0].meta["requests"] == 5


def test_burst_counts_all_status_codes():
    detector = RequestBurstDetector({"max_requests": 3, "window_seconds": 60})
    detector.feed(request(second=1))
    detector.feed(hit(ip="198.51.100.5", second=2))
    assert detector.feed(request(second=3)) != []


def test_rules_disabled_when_not_configured():
    settings = Settings()
    settings.detectors = {}
    engine = DetectionEngine(settings)
    assert engine.detector_names() == []
    for _ in range(50):
        assert engine.feed(hit()) == []


def test_engine_enables_all_configured_rules():
    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 5},
        "http_error_spike": {"enabled": True, "max_errors": 2, "window_seconds": 60},
        "request_burst": {"enabled": True, "max_requests": 100, "window_seconds": 60},
    }
    engine = DetectionEngine(settings)
    assert sorted(engine.detector_names()) == [
        "http_error_spike",
        "request_burst",
        "ssh_bruteforce",
    ]
    engine.feed(hit(second=1))
    alerts = engine.feed(hit(second=2))
    assert [a.detector for a in alerts] == ["http_error_spike"]
