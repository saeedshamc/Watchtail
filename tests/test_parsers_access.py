"""Tests for the nginx and apache access log parsers."""

import datetime as dt

import pytest

from app.parsers import get_parser, known_types

NGINX_LINE = (
    '203.0.113.7 - - [26/Sep/2026:14:03:11 +0000] "GET /admin HTTP/1.1" '
    '404 153 "-" "curl/8.5.0"'
)

APACHE_LINE = (
    '198.51.100.23 - jane [26/Sep/2026:10:00:00 +0200] "POST /login HTTP/2.0" '
    '403 5121 "https://example.test/" "Mozilla/5.0"'
)


def test_known_types_includes_access_logs():
    assert {"nginx", "apache"} <= set(known_types())


def test_unknown_type_returns_none():
    assert get_parser("syslogd") is None


def test_nginx_combined_line():
    record = get_parser("nginx").parse(NGINX_LINE)
    assert record.kind == "http_access"
    assert record.ip == "203.0.113.7"
    assert record.method == "GET"
    assert record.path == "/admin"
    assert record.status == 404
    assert record.bytes_sent == 153
    assert record.user_agent == "curl/8.5.0"
    assert record.ts == dt.datetime(2026, 9, 26, 14, 3, 11)


def test_nginx_handles_zero_bytes_and_missing_ua():
    line = (
        '203.0.113.9 - - [26/Sep/2026:00:00:00 +0000] "GET / HTTP/1.1" '
        '200 0 "-" "-"'
    )
    record = get_parser("nginx").parse(line)
    assert record.bytes_sent == 0
    assert record.user_agent is None
    assert record.meta["referer"] is None


def test_nginx_rejects_garbage():
    assert get_parser("nginx").parse("this is not a log line") is None


def test_apache_combined_line_with_user():
    record = get_parser("apache").parse(APACHE_LINE)
    assert record.kind == "http_access"
    assert record.ip == "198.51.100.23"
    assert record.method == "POST"
    assert record.path == "/login"
    assert record.status == 403
    assert record.bytes_sent == 5121
    # +0200 offset converts to 08:00 UTC.
    assert record.ts == dt.datetime(2026, 9, 26, 8, 0, 0)
    assert record.meta["referer"] == "https://example.test/"


def test_apache_dash_bytes_maps_to_none():
    line = (
        '198.51.100.2 - - [26/Sep/2026:10:00:00 +0000] "GET /x HTTP/1.1" '
        '500 - "-" "probe"'
    )
    record = get_parser("apache").parse(line)
    assert record.status == 500
    assert record.bytes_sent is None


@pytest.mark.parametrize(
    "line",
    [
        '203.0.113.7 - - [26/Sep/2026:14:03:11 +0000] "-" 404 0 "-" "-"',
        '203.0.113.7 - - [26/Sep/2026:14:03:11 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"',
    ],
)
def test_malformed_request_field_keeps_line_parseable(line):
    record = get_parser("nginx").parse(line)
    assert record is not None
    assert record.method is None
    assert record.path is None
    assert record.status in (400, 404)
