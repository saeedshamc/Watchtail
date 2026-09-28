"""Tests for the highest-risk dashboard section."""

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import IpStatus, utcnow


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def seed_scores(rows):
    with session_scope() as session:
        for ip, score in rows:
            session.add(
                IpStatus(
                    ip=ip,
                    status="flagged",
                    alert_count=3,
                    threat_score=score,
                    last_scored_at=utcnow(),
                    last_alert_at=utcnow(),
                )
            )


def test_highest_risk_section_orders_by_score(client):
    seed_scores([("1.1.1.1", 30), ("2.2.2.2", 200), ("3.3.3.3", 90)])
    html = client.get("/").get_data(as_text=True)
    assert "Highest risk" in html
    assert html.index("2.2.2.2") < html.index("3.3.3.3") < html.index("1.1.1.1")


def test_dismissed_ips_excluded_from_risk_list(client):
    with session_scope() as session:
        session.add(
            IpStatus(
                ip="4.4.4.4", status="dismissed", threat_score=500,
                last_scored_at=utcnow(),
            )
        )
    html = client.get("/").get_data(as_text=True)
    assert "4.4.4.4" not in html


def test_score_badge_classes_render(client):
    seed_scores([("5.5.5.5", 300)])
    html = client.get("/").get_data(as_text=True)
    assert "score-num critical" in html
    assert "score-fill critical" in html


def test_zero_score_rows_do_not_appear(client):
    seed_scores([("6.6.6.6", 0)])
    html = client.get("/").get_data(as_text=True)
    assert "No scored threats yet" in html
