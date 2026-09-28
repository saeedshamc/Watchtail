"""Tests for the multi-signal correlation detector."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.detectors.correlation import CorrelationDetector
from app.models import Alert
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline


def test_fires_at_min_signals():
    corr = CorrelationDetector({"enabled": True, "min_signals": 2})
    ts = dt.datetime(2026, 9, 28, 12, 0, 0).timestamp()
    assert corr.observe_alert(ts, "1.1.1.1", "request_burst") == []
    alerts = corr.observe_alert(ts + 30, "1.1.1.1", "path_scan")
    assert len(alerts) == 1
    assert "request_burst" in alerts[0].message
    assert "path_scan" in alerts[0].message
    assert alerts[0].severity == "critical"


def test_same_detector_twice_is_one_signal():
    corr = CorrelationDetector({"enabled": True, "min_signals": 2})
    ts = dt.datetime(2026, 9, 28, 12, 0, 0).timestamp()
    corr.observe_alert(ts, "1.1.1.1", "request_burst")
    assert corr.observe_alert(ts + 10, "1.1.1.1", "request_burst") == []


def test_cooldown_after_firing():
    corr = CorrelationDetector(
        {"enabled": True, "min_signals": 2, "cooldown_seconds": 600}
    )
    ts = dt.datetime(2026, 9, 28, 12, 0, 0).timestamp()
    corr.observe_alert(ts, "1.1.1.1", "a")
    corr.observe_alert(ts + 5, "1.1.1.1", "b")  # fires
    # Third detector inside cooldown: suppressed.
    assert corr.observe_alert(ts + 10, "1.1.1.1", "c") == []
    # After cooldown with more signals: fires again.
    late = ts + 700
    assert len(corr.observe_alert(late, "1.1.1.1", "d")) == 1


def test_ignores_own_alerts_and_empty_ips():
    corr = CorrelationDetector({"enabled": True, "min_signals": 1})
    ts = 0.0
    assert corr.observe_alert(ts, "1.1.1.1", "correlation") == []
    assert corr.observe_alert(ts, "", "request_burst") == []


def test_pipeline_produces_composite_alert():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    try:
        settings = Settings()
        settings.detectors = {
            "request_burst": {"enabled": True, "max_requests": 3, "window_seconds": 60},
            "path_scan": {"enabled": True, "max_paths": 2, "window_seconds": 60},
            "correlation": {"enabled": True, "min_signals": 2},
        }
        pipeline = Pipeline(settings)
        base = dt.datetime(2026, 9, 28, 12, 0, 0)

        for i in range(3):  # trip request_burst
            pipeline.handle_record(
                ParsedLine(
                    kind="http_access", ts=base, ip="9.9.9.9",
                    method="GET", path=f"/a{i}", status=200,
                ),
                "raw", None,
            )
        for i in range(2):  # trip path_scan (distinct 404 paths)
            pipeline.handle_record(
                ParsedLine(
                    kind="http_access", ts=base, ip="9.9.9.9",
                    method="GET", path=f"/probe-{i}", status=404,
                ),
                "raw", None,
            )

        with session_scope() as session:
            detectors = {
                row.detector for row in session.query(Alert).all()
            }
            assert "correlation" in detectors
    finally:
        dispose_engine()
