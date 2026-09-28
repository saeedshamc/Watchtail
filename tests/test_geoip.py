"""Tests for the optional GeoIP enrichment."""

import pytest

from app import geoip


@pytest.fixture(autouse=True)
def reset_geo():
    geoip.configure(None)
    yield
    geoip.configure(None)


def test_disabled_by_default():
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_missing_file_degrades_to_none(tmp_path):
    geoip.configure(str(tmp_path / "nope.mmdb"))
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_lookup_skips_special_addresses(tmp_path):
    # Even with an unavailable reader, lookups fail closed, not loud.
    geoip.configure(str(tmp_path / "nope.mmdb"))
    assert geoip.lookup("") is None
    assert geoip.lookup("garbage") is None


def test_configure_replaces_path(tmp_path):
    geoip.configure(str(tmp_path / "a.mmdb"))
    geoip.configure(str(tmp_path / "b.mmdb"))
    assert geoip.available() is False  # neither file exists
    geoip.configure(None)
    assert geoip.available() is False
