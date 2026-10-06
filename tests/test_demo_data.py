"""Demo dataset generator (R14).

``python -m app.cli demo-data`` fills a database with a realistic,
deterministic story: an SSH brute-force campaign, a path scan, a 4xx
spike and background traffic, plus flagged IP rows and one open case.
"""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.demo_data import seed_demo_data
from app.models import Alert, Case, CaseEntry, Event, IpStatus


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def test_seed_populates_all_tables():
    counts = seed_demo_data()
    assert counts["events"] > 300
    assert counts["alerts"] >= 3
    assert counts["flagged"] == 3
    assert counts["cases"] == 1
    with session_scope() as session:
        assert session.query(Event).count() == counts["events"]
        assert session.query(Alert).count() == counts["alerts"]
        assert session.query(IpStatus).count() >= 3
        case = session.query(Case).one()
        assert case.status == "open"
        assert case.severity == "critical"
        assert session.query(CaseEntry).filter_by(case_id=case.id).count() == 3


def test_seed_is_deterministic_for_same_seed():
    first = seed_demo_data(seed=42, now=dt.datetime(2026, 10, 1, 12, 0, 0))
    counts = seed_demo_data(seed=42, now=dt.datetime(2026, 10, 1, 12, 0, 0))
    assert counts == first


def test_events_are_inside_requested_window():
    now = dt.datetime(2026, 10, 1, 12, 0, 0)
    seed_demo_data(hours=6, now=now)
    with session_scope() as session:
        oldest = session.query(Event).order_by(Event.ts).first()
        newest = session.query(Event).order_by(Event.ts.desc()).first()
    assert oldest.ts >= now - dt.timedelta(hours=6)
    assert newest.ts <= now


def test_flagged_rows_have_scores_and_recent_alerts():
    seed_demo_data()
    with session_scope() as session:
        rows = session.query(IpStatus).all()
    flagged = [row for row in rows if row.status == "flagged"]
    assert len(flagged) == 3
    for row in flagged:
        assert (row.threat_score or 0) > 0
        assert row.reason
        assert row.last_alert_at is not None
        assert row.alert_count >= 1
    # brute-force IP should outscore the medium-severity offenders
    by_score = sorted(flagged, key=lambda r: r.threat_score, reverse=True)
    assert by_score[0].alert_count == 90


def test_bruteforce_story_present():
    seed_demo_data()
    with session_scope() as session:
        ssh_fails = (
            session.query(Event)
            .filter(Event.kind == "ssh_auth_fail")
            .count()
        )
        detectors = {row[0] for row in session.query(Alert.detector).all()}
    assert ssh_fails >= 90
    assert "ssh_bruteforce" in detectors
    assert "correlation" in detectors


def test_no_case_option():
    counts = seed_demo_data(include_case=False)
    assert counts["cases"] == 0
    with session_scope() as session:
        assert session.query(Case).count() == 0


def test_doc_range_addresses_only():
    seed_demo_data()
    with session_scope() as session:
        ips = {row[0] for row in session.query(Event.ip).all() if row[0]}
    for ip in ips:
        assert ip.startswith(("203.0.113.", "198.51.100."))


def test_cli_demo_data_writes_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "demo.db"
    monkeypatch.setenv("WATCHTAIL_DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    from app.cli import main

    exit_code = main(["demo-data", "--hours", "12", "--seed", "5"])
    assert exit_code == 0
    from app.database import configure_engine

    configure_engine(f"sqlite:///{db_path.as_posix()}")
    with session_scope() as session:
        assert session.query(Event).count() > 200
        assert session.query(Alert).count() >= 3
