"""Tests for the detector settings page."""

import shutil

import pytest

import app as watchtail_app
from app.database import dispose_engine

EXAMPLE = "config/watchtail.example.yml"


@pytest.fixture(autouse=True)
def memory_app(tmp_path):
    # Each test gets its own copy of the example config to edit.
    config_copy = tmp_path / "watchtail.yml"
    shutil.copy(EXAMPLE, config_copy)
    application = watchtail_app.create_app(
        config_path=str(config_copy), database_url="sqlite:///:memory:"
    )
    yield application, config_copy
    dispose_engine()


@pytest.fixture
def client(memory_app):
    application, _ = memory_app
    client = application.test_client()
    client.post(
        "/login", data={"username": "admin", "password": "test-password"}
    )
    return client


def test_settings_page_lists_all_detectors(client):
    html = client.get("/settings").get_data(as_text=True)
    for name in (
        "ssh_bruteforce", "http_error_spike", "request_burst",
        "ssh_compromise", "path_scan", "distributed_attack",
    ):
        assert name in html
    assert "flag_ttl_seconds" in html


def test_save_updates_config_and_live_settings(client, memory_app):
    application, config_copy = memory_app
    response = client.post(
        "/settings",
        data={
            "ssh_bruteforce.max_failures": "7",
            "ssh_bruteforce.window_seconds": "120",
            "distributed_attack.max_ips": "9",
            "flag_ttl_seconds": "1800",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    settings = application.config["WATCHTAIL_SETTINGS"]
    assert settings.detector("ssh_bruteforce")["max_failures"] == 7
    assert settings.detector("ssh_bruteforce")["window_seconds"] == 120
    assert settings.detector("distributed_attack")["max_ips"] == 9
    assert settings.flag_ttl_seconds == 1800

    # Persisted to the YAML file too.
    import yaml

    with open(config_copy, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    assert raw["detectors"]["ssh_bruteforce"]["max_failures"] == 7
    assert raw["detectors"]["flag_ttl_seconds"] == 1800


def test_invalid_values_are_ignored(client, memory_app):
    application, config_copy = memory_app
    client.post(
        "/settings",
        data={
            "ssh_bruteforce.max_failures": "not-a-number",
            "ssh_bruteforce.window_seconds": "-5",
        },
        follow_redirects=True,
    )
    import yaml

    with open(config_copy, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    # Example defaults remain untouched.
    assert raw["detectors"]["ssh_bruteforce"]["max_failures"] == 5
    assert raw["detectors"]["ssh_bruteforce"]["window_seconds"] == 300


def test_severity_and_status_codes_save(client, memory_app):
    _, config_copy = memory_app
    client.post(
        "/settings",
        data={
            "request_burst.severity": "high",
            "path_scan.status_codes": "404, 403, 410",
        },
        follow_redirects=True,
    )
    import yaml

    with open(config_copy, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    assert raw["detectors"]["request_burst"]["severity"] == "high"
    assert raw["detectors"]["path_scan"]["status_codes"] == [403, 404, 410]


def test_settings_require_login(memory_app):
    application, _ = memory_app
    assert application.test_client().get("/settings").status_code == 302


def test_example_config_still_untouched(memory_app):
    # Tests edit a copy; the real example config must never change.
    import yaml

    with open(EXAMPLE, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    assert raw["detectors"]["ssh_bruteforce"]["max_failures"] == 5
