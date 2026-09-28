"""Tests for the distributed (multi-IP) attack detector."""

import datetime as dt

import pytest

from app.config import Settings
from app.database import configure_engine, dispose_engine, session_scope
from app.detectors.distributed import DistributedAttackDetector
from app.models import Alert, IpStatus
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline


def fail(ip, user="admin", ts=None):
    return ParsedLine(
        kind="ssh_auth_fail",
        ts=ts or dt.datetime(2026, 9, 28, 12, 0, 0),
        ip=ip,
        meta={"user": user, "port": 41000},
    )


@pytest.fixture
def detector():
    return DistributedAttackDetector(
        {"enabled": True, "max_ips": 3, "window_seconds": 600}
    )


def test_no_alert_below_ip_threshold(detector):
    base = dt.datetime(2026, 9, 28, 12, 0, 0)
    assert detector.feed(fail("1.1.1.1", ts=base)) == []
    assert detector.feed(fail("2.2.2.2", ts=base)) == []
    assert detector.feed(fail("1.1.1.1", ts=base)) == []  # repeat IP adds nothing


def test_fires_at_threshold_with_distinct_ips(detector):
    base = dt.datetime(2026, 9, 28, 12, 0, 0)
    detector.feed(fail("1.1.1.1", ts=base))
    detector.feed(fail("2.2.2.2", ts=base))
    alerts = detector.feed(fail("3.3.3.3", ts=base))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "distributed_attack"
    assert alert.ip == "user:admin"
    assert alert.severity == "high"
    assert sorted(alert.meta["distinct_ips"]) == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_cooldown_suppresses_repeat_alerts(detector):
    base = dt.datetime(2026, 9, 28, 12, 0, 0)
    for i in range(3):
        detector.feed(fail(f"10.0.0.{i}", ts=base))
    # More unique IPs arrive after firing; still inside the cooldown.
    late = base + dt.timedelta(seconds=60)
    assert detector.feed(fail("10.0.0.9", ts=late)) == []
    # After the cooldown a fresh wave can fire again.
    later = base + dt.timedelta(seconds=400)
    alerts = detector.feed(fail("10.0.1.5", ts=later))
    assert len(alerts) == 1


def test_window_expiry_drops_old_ips(detector):
    start = dt.datetime(2026, 9, 28, 12, 0, 0)
    detector.feed(fail("1.1.1.1", ts=start))
    detector.feed(fail("2.2.2.2", ts=start))
    # Third IP arrives after the first two aged out of the window.
    alerts = detector.feed(
        fail("3.3.3.3", ts=start + dt.timedelta(seconds=700))
    )
    assert alerts == []


def test_accounts_are_tracked_separately(detector):
    base = dt.datetime(2026, 9, 28, 12, 0, 0)
    detector.feed(fail("1.1.1.1", user="root", ts=base))
    detector.feed(fail("2.2.2.2", user="root", ts=base))
    alerts = detector.feed(fail("3.3.3.3", user="admin", ts=base))
    assert alerts == []  # admin only has one IP so far


def test_pipeline_persists_distributed_alert():
    configure_engine("sqlite:///:memory:")
    from app.database import create_all

    create_all()
    try:
        settings = Settings()
        settings.detectors = {
            "distributed_attack": {
                "enabled": True, "max_ips": 2, "window_seconds": 600
            }
        }
        pipeline = Pipeline(settings)
        base = dt.datetime(2026, 9, 28, 12, 0, 0)
        pipeline.handle_record(fail("1.1.1.1", ts=base), "raw", None)
        pipeline.handle_record(fail("2.2.2.2", ts=base), "raw", None)

        with session_scope() as session:
            alert = session.query(Alert).one()
            assert alert.detector == "distributed_attack"
            assert alert.ip == "user:admin"
            flagged = session.get(IpStatus, "user:admin")
            assert flagged is not None
            assert flagged.status == "flagged"
    finally:
        dispose_engine()
