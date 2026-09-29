"""Tests for YAML-defined custom detectors."""

import datetime as dt

import pytest

import app as watchtail_app
from app.config import Settings, load_config
from app.database import dispose_engine, session_scope
from app.detectors.custom import Condition, CustomDetector, build_custom_detectors
from app.detectors.engine import DetectionEngine
from app.models import Alert
from app.parsers.base import ParsedLine
from app.pipeline import Pipeline


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def http(path, status, minute, ip="203.0.113.77", **meta):
    return ParsedLine(
        kind="http_access",
        ts=dt.datetime(2026, 9, 28, 12, minute, 0),
        ip=ip,
        method="GET",
        path=path,
        status=status,
        meta=meta,
    )


class TestConditions:
    def test_exact_match(self):
        cond = Condition({"field": "path", "value": "/wp-login.php", "match": "exact"})
        assert cond.matches(http("/wp-login.php", 200, 1)) is True
        assert cond.matches(http("/wp-login.php.bak", 200, 1)) is False

    def test_contains_match(self):
        cond = Condition({"field": "path", "value": "wp-login", "match": "contains"})
        assert cond.matches(http("/blog/wp-login.php", 200, 1)) is True
        assert cond.matches(http("/blog/login", 200, 1)) is False

    def test_regex_match(self):
        cond = Condition({"field": "path", "value": r"^/\.env", "match": "regex"})
        assert cond.matches(http("/.env", 200, 1)) is True
        assert cond.matches(http("/.env.production", 200, 1)) is True
        assert cond.matches(http("/env", 200, 1)) is False

    def test_missing_field_never_matches(self):
        cond = Condition({"field": "meta.user", "value": "root", "match": "exact"})
        assert cond.matches(http("/x", 200, 1)) is False
        assert cond.matches(http("/x", 200, 1, user="root")) is True

    def test_numeric_status_stringified(self):
        cond = Condition({"field": "status", "value": "404", "match": "exact"})
        assert cond.matches(http("/x", 404, 1)) is True

    def test_invalid_condition_rejected(self):
        with pytest.raises(ValueError):
            Condition({"field": "", "value": "x"})
        with pytest.raises(ValueError):
            Condition({"field": "path", "value": "x", "match": "like"})


class TestCustomDetector:
    def _detector(self, **overrides):
        options = {
            "name": "probe",
            "threshold": 3,
            "window_seconds": 300,
            "severity": "high",
            "conditions": [{"field": "path", "value": "/admin", "match": "contains"}],
        }
        options.update(overrides)
        return CustomDetector(options)

    def test_fires_at_threshold(self):
        detector = self._detector()
        assert detector.feed(http("/admin", 200, 1)) == []
        assert detector.feed(http("/admin/config", 200, 2)) == []
        alerts = detector.feed(http("/admin/login", 200, 3))
        assert len(alerts) == 1
        assert alerts[0].detector == "custom:probe"
        assert alerts[0].severity == "high"
        assert alerts[0].ip == "203.0.113.77"
        assert alerts[0].meta["matches"] == 3

    def test_non_matching_records_do_not_count(self):
        detector = self._detector()
        detector.feed(http("/admin", 200, 1))
        detector.feed(http("/other", 200, 2))
        detector.feed(http("/admin", 200, 3))
        assert detector.feed(http("/other", 200, 4)) == []
        assert len(detector.feed(http("/admin", 200, 5))) == 1

    def test_window_expiry(self):
        detector = self._detector()
        detector.feed(http("/admin", 200, 1))
        detector.feed(http("/admin", 200, 2))
        # Third hit is outside the 300s window from the first two.
        assert detector.feed(http("/admin", 200, 8)) == []

    def test_cooldown_suppresses_repeat_alerts(self):
        detector = self._detector(cooldown_seconds=600)
        detector.feed(http("/admin", 200, 1))
        detector.feed(http("/admin", 200, 2))
        assert len(detector.feed(http("/admin", 200, 3))) == 1
        # Still matching inside the cooldown: silent.
        assert detector.feed(http("/admin", 200, 20)) == []
        # Cooldown expired and the window has refilled: it fires again.
        assert detector.feed(http("/admin", 200, 23)) == []
        assert len(detector.feed(http("/admin", 200, 24))) == 1

    def test_no_ip_records_grouped(self):
        detector = self._detector(threshold=2)
        first = ParsedLine(
            kind="json_line", ts=dt.datetime(2026, 9, 28, 12, 1, 0), path="/admin"
        )
        assert detector.feed(first) == []
        alerts = detector.feed(
            ParsedLine(kind="json_line", ts=dt.datetime(2026, 9, 28, 12, 2, 0), path="/admin")
        )
        assert len(alerts) == 1
        assert alerts[0].ip is None

    def test_invalid_rule_raises(self):
        with pytest.raises(ValueError):
            CustomDetector({"threshold": 3, "conditions": []})
        with pytest.raises(ValueError):
            CustomDetector(
                {
                    "conditions": [{"field": "path", "value": "x"}],
                }
            )


class TestRegistration:
    def test_build_skips_disabled_and_invalid(self):
        settings = Settings()
        settings.custom_detectors = [
            {"name": "off", "conditions": [{"field": "path", "value": "/x"}], "enabled": False},
            {"name": "bad"},
            {
                "name": "on",
                "conditions": [{"field": "status", "value": "500"}],
                "threshold": 1,
            },
        ]
        built = build_custom_detectors(settings)
        assert [d.custom_name for d in built] == ["on"]

    def test_engine_includes_custom_detectors(self):
        settings = Settings()
        settings.custom_detectors = [
            {
                "name": "burst_500",
                "threshold": 2,
                "window_seconds": 60,
                "conditions": [{"field": "status", "value": "500"}],
            }
        ]
        engine = DetectionEngine(settings)
        assert "custom:burst_500" in engine.detector_names()
        alerts = engine.feed(http("/api", 500, 1))
        assert alerts == []
        alerts = engine.feed(http("/api", 500, 2))
        assert len(alerts) == 1
        assert alerts[0].detector == "custom:burst_500"

    def test_engine_ignores_other_kinds_conditions(self):
        settings = Settings()
        settings.custom_detectors = [
            {
                "name": "root_ssh",
                "threshold": 1,
                "conditions": [{"field": "meta.user", "value": "root"}],
            }
        ]
        engine = DetectionEngine(settings)
        record = ParsedLine(
            kind="ssh_auth_fail",
            ts=dt.datetime(2026, 9, 28, 12, 0, 0),
            ip="198.51.100.5",
            meta={"user": "root"},
        )
        alerts = engine.feed(record)
        assert len(alerts) == 1
        assert alerts[0].detector == "custom:root_ssh"


def test_load_config_parses_custom_detectors(tmp_path):
    config_file = tmp_path / "watchtail.yml"
    config_file.write_text(
        "custom_detectors:\n"
        "  - name: env_probe\n"
        "    threshold: 5\n"
        "    conditions:\n"
        "      - field: path\n"
        "        value: ^/\\.env\n"
        "        match: regex\n",
        encoding="utf-8",
    )
    settings = load_config(str(config_file))
    assert len(settings.custom_detectors) == 1
    assert settings.custom_detectors[0]["name"] == "env_probe"
    assert settings.custom_detectors[0]["threshold"] == 5


def test_pipeline_persists_custom_alert():
    settings = Settings()
    settings.custom_detectors = [
        {
            "name": "scanner",
            "threshold": 2,
            "window_seconds": 300,
            "severity": "medium",
            "conditions": [{"field": "path", "value": "/.env", "match": "exact"}],
        }
    ]
    pipeline = Pipeline(settings)
    pipeline.handle_record(http("/.env", 404, 1), "raw", None)
    pipeline.handle_record(http("/.env", 404, 2), "raw", None)

    with session_scope() as session:
        rows = session.query(Alert).all()
        assert len(rows) == 1
        assert rows[0].detector == "custom:scanner"
        assert rows[0].severity == "medium"
