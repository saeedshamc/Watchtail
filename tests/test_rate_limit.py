"""Tests for the global rate limiter middleware."""

import pytest

import app as watchtail_app
from app import ratelimit
from app.config import Settings
from app.database import dispose_engine


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()
    ratelimit.limiter.reset()


def _configure(max_requests, window_seconds=60.0, enabled=True, extra=None):
    settings = Settings()
    settings.rate_limit = {
        "enabled": enabled,
        "max_requests": max_requests,
        "window_seconds": window_seconds,
        "exempt_prefixes": (extra or {}).get("exempt_prefixes", []),
    }
    ratelimit.configure(settings)
    return settings


def test_limiter_admits_within_limit_and_rejects_after(memory_app):
    _configure(3)
    limiter = ratelimit.limiter
    assert limiter.check("t:1") == (True, 0)
    assert limiter.check("t:1") == (True, 0)
    assert limiter.check("t:1") == (True, 0)
    allowed, retry = limiter.check("t:1")
    assert allowed is False
    assert retry >= 1


def test_limiter_buckets_are_independent(memory_app):
    _configure(2)
    limiter = ratelimit.limiter
    assert limiter.check("t:a")[0] is True
    assert limiter.check("t:a")[0] is True
    assert limiter.check("t:a")[0] is False
    assert limiter.check("t:b")[0] is True


def test_limiter_window_frees_slots(memory_app):
    _configure(2, window_seconds=30.0)
    limiter = ratelimit.limiter
    base = 1000.0
    assert limiter.check("t:w", now=base)[0] is True
    assert limiter.check("t:w", now=base + 1)[0] is True
    assert limiter.check("t:w", now=base + 2)[0] is False
    # After the window slides past the early hits the bucket frees up.
    assert limiter.check("t:w", now=base + 31)[0] is True


def test_limiter_reset_clears_buckets(memory_app):
    _configure(1)
    limiter = ratelimit.limiter
    assert limiter.check("t:r")[0] is True
    assert limiter.check("t:r")[0] is False
    limiter.reset()
    assert limiter.check("t:r")[0] is True


def test_http_429_with_retry_after(memory_app):
    _configure(2)
    client = memory_app.test_client()
    # Three hits on the same login page trip the limit (2 > limit 2).
    for _ in range(2):
        assert client.get("/login").status_code == 200
    response = client.get("/login")
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    body = response.get_json()
    assert body["error"] == "rate limit exceeded"


def test_health_and_metrics_are_exempt(memory_app):
    _configure(1)
    client = memory_app.test_client()
    # Consume the whole budget on /login.
    client.get("/login")
    assert client.get("/login").status_code == 429
    # Exempt prefixes still work normally.
    assert client.get("/health").status_code == 200
    # /metrics requires login and redirects, but must not be 429.
    assert client.get("/metrics").status_code == 302


def test_exempt_prefixes_from_config(memory_app):
    _configure(1, extra={"exempt_prefixes": ["/login"]})
    client = memory_app.test_client()
    assert client.get("/login").status_code == 200
    assert client.get("/login").status_code == 200
    # A non-exempt path is still limited.
    assert client.get("/suppressions").status_code == 302  # first: allowed
    assert client.get("/suppressions").status_code == 429  # second: over limit


def test_disabled_limiter_never_blocks(memory_app):
    _configure(1, enabled=False)
    client = memory_app.test_client()
    for _ in range(5):
        assert client.get("/login").status_code == 200


def test_client_key_prefers_forwarded_for(memory_app):
    with memory_app.test_request_context(
        "/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}
    ):
        assert ratelimit.client_key() == "fwd:203.0.113.9"


def test_client_key_token_bucket(memory_app):
    with memory_app.test_request_context("/api/v1/events"):
        from flask import request

        request.watchtail_token_id = 7
        assert ratelimit.client_key() == "token:7"


def test_default_settings_installed(memory_app):
    # create_app installed the limiter with defaults; no config section
    # means enabled with 300/60.
    assert ratelimit.limiter.max_requests == 300
    assert ratelimit.limiter.window_seconds == 60.0
    assert getattr(ratelimit.limiter, "enabled", True) is True
