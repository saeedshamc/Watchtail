"""Tests for threat scoring and decay."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.models import Alert, IpStatus, utcnow
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline
from app.scoring import (
    SEVERITY_WEIGHTS,
    apply_alert,
    bump_score,
    decayed_score,
    score_level,
)


@pytest.fixture(autouse=True)
def memory_db():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    yield
    dispose_engine()


def test_bump_uses_severity_weights():
    assert bump_score(0, "low") == SEVERITY_WEIGHTS["low"]
    assert bump_score(0, "critical") == SEVERITY_WEIGHTS["critical"]
    assert bump_score(50, "medium") == 65


def test_unknown_severity_uses_medium():
    assert bump_score(0, "weird") == SEVERITY_WEIGHTS["medium"]


def test_decay_half_life():
    now = utcnow()
    # One day halves the score.
    day_ago = now - dt.timedelta(hours=24)
    assert decayed_score(100, day_ago, half_life_hours=24) == 50
    # Zero elapsed time keeps it.
    assert decayed_score(100, now) == 100
    # Very old scores collapse towards zero.
    assert decayed_score(100, now - dt.timedelta(days=30)) <= 1
    # None timestamp = never decayed.
    assert decayed_score(100, None) == 100


def test_apply_alert_creates_nothing_but_updates_existing():
    # Missing row: returns 0, no crash (pipeline owns row creation).
    with session_scope() as session:
        assert apply_alert(session, "9.9.9.9", "high") == 0

    with session_scope() as session:
        session.add(IpStatus(ip="1.1.1.1", status="flagged"))
    with session_scope() as session:
        score = apply_alert(session, "1.1.1.1", "high")
        assert score == SEVERITY_WEIGHTS["high"]
    with session_scope() as session:
        score = apply_alert(session, "1.1.1.1", "critical")
        # Second call decays the first bump negligibly (moments apart).
        assert score > SEVERITY_WEIGHTS["critical"]


def test_score_level_badges():
    assert score_level(0) == "low"
    assert score_level(50) == "medium"
    assert score_level(100) == "high"
    assert score_level(500) == "critical"


def test_pipeline_bumps_scores_on_alerts():
    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    pipeline = Pipeline(settings)

    def fail(minute):
        return ParsedLine(
            kind="ssh_auth_fail",
            ts=dt.datetime(2026, 9, 28, 12, minute, 0),
            ip="203.0.113.44",
            meta={"user": "root"},
        )

    pipeline.handle_record(fail(1), "raw", None)
    pipeline.handle_record(fail(2), "raw", None)  # fires high alert

    with session_scope() as session:
        row = session.get(IpStatus, "203.0.113.44")
        assert row.threat_score == SEVERITY_WEIGHTS["high"]
        assert row.last_scored_at is not None
