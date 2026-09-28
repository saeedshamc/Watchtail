"""Tests for config resolution via WATCHTAIL_CONFIG and Docker assets."""

import os

import pytest

from app.config import load_config

DOCKERFILE = "Dockerfile"
ENTRYPOINT = "entrypoint.sh"


@pytest.fixture
def custom_config(tmp_path, monkeypatch):
    config = tmp_path / "watchtail.yml"
    config.write_text(
        "server:\n"
        "  host: 0.0.0.0\n"
        "  port: 6001\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    return config


def test_env_variable_points_loader_at_config(custom_config, monkeypatch):
    monkeypatch.setenv("WATCHTAIL_CONFIG", str(custom_config))
    settings = load_config()
    assert settings.port == 6001


def test_explicit_argument_beats_env(custom_config, monkeypatch):
    monkeypatch.setenv("WATCHTAIL_CONFIG", str(custom_config))
    other = custom_config.with_name("other.yml")
    other.write_text("server:\n  port: 6002\n", encoding="utf-8")
    settings = load_config(str(other))
    assert settings.port == 6002


def test_missing_config_everywhere_still_boots(custom_config, monkeypatch):
    monkeypatch.delenv("WATCHTAIL_CONFIG", raising=False)
    monkeypatch.setattr("app.config.DEFAULT_CONFIG_LOCATIONS", (str(tmp_missing := custom_config.with_name("nope.yml")),))
    settings = load_config()
    assert settings.port != 6001  # defaults, no crash


def test_dockerfile_copies_all_runtime_files():
    with open(DOCKERFILE, encoding="utf-8") as fh:
        dockerfile = fh.read()
    for needle in ("run.py", "wsgi.py", "entrypoint.sh", "EXPOSE 5555", "VOLUME"):
        assert needle in dockerfile


def test_entrypoint_requires_admin_password():
    with open(ENTRYPOINT, encoding="utf-8") as fh:
        script = fh.read()
    assert "WATCHTAIL_ADMIN_PASSWORD" in script
    assert "exit 1" in script  # fail fast rather than boot unauthenticated
    assert "gunicorn" in script and "eventlet" in script


def test_compose_mounts_persistent_volume():
    with open("docker-compose.yml", encoding="utf-8") as fh:
        compose = fh.read()
    assert "/data" in compose
    assert "WATCHTAIL_ADMIN_PASSWORD" in compose
