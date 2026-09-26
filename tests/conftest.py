"""Shared test fixtures.

Every test app gets a deterministic admin password through the
environment so suites can log in without reading generated output.
"""

import pytest


@pytest.fixture(autouse=True)
def admin_password(monkeypatch):
    monkeypatch.setenv("WATCHTAIL_ADMIN_PASSWORD", "test-password")
    yield
