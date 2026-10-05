"""Tests for STIX 2.1 and CEF exports."""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.exports import to_cef_lines, to_stix_bundle
from app.models import Alert
from app.tokens import create_token


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def _alert(**overrides):
    data = dict(
        detector="ssh_bruteforce",
        ip="203.0.113.7",
        severity="critical",
        message="5|failed logins",
        ts=dt.datetime(2026, 9, 28, 12, 0, 0),
        meta={"user": "root"},
    )
    data.update(overrides)
    row = Alert(**data)
    row.id = 42
    return row


def test_stix_bundle_structure():
    bundle = to_stix_bundle([_alert()])
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = [obj["type"] for obj in bundle["objects"]]
    assert types.count("observed-data") == 1
    assert types.count("x-watchtail-alert") == 1
    assert types[0] == "identity"
    observed = bundle["objects"][1]
    assert observed["first_observed"].endswith("Z")
    assert observed["number_observed"] == 1
    custom = bundle["objects"][2]
    assert custom["source_ip"] == "203.0.113.7"
    assert custom["detector"] == "ssh_bruteforce"
    assert custom["severity"] == "critical"


def test_stix_ids_deterministic():
    first = to_stix_bundle([_alert()])
    second = to_stix_bundle([_alert()])
    ids_first = {obj["id"] for obj in first["objects"]}
    ids_second = {obj["id"] for obj in second["objects"]}
    assert ids_first == ids_second


def test_stix_naive_ts_treated_as_utc():
    alert = _alert(ts=dt.datetime(2026, 9, 28, 12, 0, 0))
    bundle = to_stix_bundle([alert])
    assert bundle["objects"][1]["first_observed"].startswith("2026-09-28T12:00:00")


def _cef_split(line):
    """Split a CEF line on unescaped pipes, like a real parser."""
    parts = []
    current = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def test_cef_line_format():
    lines = to_cef_lines([_alert()])
    assert len(lines) == 1
    parts = _cef_split(lines[0])
    assert parts[0] == "CEF:0"
    assert parts[1] == "Watchtail"
    assert parts[4] == "ssh_bruteforce"
    # critical maps to severity 10.
    assert parts[6] == "10"
    assert "src=203.0.113.7" in lines[0]
    assert "cs1Label=detector" in lines[0]
    assert "rt=" in lines[0]


def test_cef_escapes_specials():
    lines = to_cef_lines([_alert(message="pipe|and=equals\\slash")])
    assert "pipe\\|and\\=equals\\\\slash" in lines[0]


def test_cef_severity_mapping():
    for severity, expected in (("low", "2"), ("medium", "5"), ("high", "7")):
        lines = to_cef_lines([_alert(severity=severity)])
        assert _cef_split(lines[0])[6] == expected


class TestExportRoutes:
    def _seed(self):
        with session_scope() as session:
            row = Alert(
                detector="path_scan", ip="198.51.100.2", severity="medium",
                message="scan", ts=dt.datetime(2026, 9, 28, 12, 0, 0),
            )
            session.add(row)
            session.flush()
            return row.id

    def test_stix_route(self, memory_app):
        self._seed()
        plain, _ = create_token("exporter")
        response = memory_app.test_client().get(
            "/api/v1/alerts/stix",
            headers={"Authorization": f"Bearer {plain}"},
        )
        assert response.status_code == 200
        assert "stix" in response.mimetype
        body = response.get_json()
        assert body["type"] == "bundle"
        assert any(obj["type"] == "observed-data" for obj in body["objects"])

    def test_cef_route(self, memory_app):
        self._seed()
        plain, _ = create_token("exporter2")
        response = memory_app.test_client().get(
            "/api/v1/alerts/cef",
            headers={"Authorization": f"Bearer {plain}"},
        )
        assert response.status_code == 200
        assert response.mimetype == "text/plain"
        text = response.get_data(as_text=True)
        assert text.startswith("CEF:0|Watchtail|")
        assert "src=198.51.100.2" in text

    def test_export_requires_token(self, memory_app):
        for path in ("/api/v1/alerts/stix", "/api/v1/alerts/cef"):
            assert memory_app.test_client().get(path).status_code == 401
