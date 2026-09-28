"""Tests for the generic syslog, RFC 5424 and JSON-lines parsers."""

import datetime as dt

from app.parsers import get_parser, known_types


def test_new_types_are_registered():
    assert {"syslog", "syslog5424", "json"} <= set(known_types())


class TestSyslogParser:
    def test_basic_line(self):
        parser = get_parser("syslog")
        parsed = parser.parse("Sep 28 10:01:01 gw01 cron[4242]: job started")
        assert parsed is not None
        assert parsed.kind == "syslog"
        assert parsed.ts.year == dt.datetime.now(dt.timezone.utc).year
        assert parsed.meta["host"] == "gw01"
        assert parsed.meta["program"] == "cron"
        assert parsed.meta["pid"] == 4242
        assert parsed.meta["message"] == "job started"
        assert parsed.ip is None

    def test_line_without_pid(self):
        parser = get_parser("syslog")
        parsed = parser.parse("Sep 28 10:01:01 gw01 su: session opened")
        assert parsed.meta["program"] == "su"
        assert parsed.meta["pid"] is None

    def test_non_syslog_line_is_none(self):
        parser = get_parser("syslog")
        assert parser.parse("random text without structure") is None
        assert parser.parse("") is None


class TestSyslog5424Parser:
    LINE = (
        '<34>1 2026-09-28T10:01:01.000003Z myhost sshd 24183 ID47 '
        '[exampleSDID@32473 iut="3" eventSource="app"] su root failed'
    )

    def test_full_line(self):
        parser = get_parser("syslog5424")
        parsed = parser.parse(self.LINE)
        assert parsed is not None
        assert parsed.kind == "syslog"
        # Sub-second precision is preserved (here 3 microseconds).
        assert parsed.ts == dt.datetime(2026, 9, 28, 10, 1, 1, 3)
        assert parsed.meta["host"] == "myhost"
        assert parsed.meta["program"] == "sshd"
        assert parsed.meta["severity"] == "high"  # pri 34 -> severity 2
        assert parsed.meta["message"] == "su root failed"
        assert parsed.meta["sd.exampleSDID@32473.iut"] == "3"

    def test_dash_fields_become_none(self):
        parser = get_parser("syslog5424")
        parsed = parser.parse(
            "<13>1 2026-09-28T10:01:01Z host app - - - plain message"
        )
        assert parsed.meta["procid"] is None
        assert parsed.meta["msgid"] is None
        assert parsed.meta["message"] == "plain message"

    def test_rfc3164_line_is_rejected(self):
        parser = get_parser("syslog5424")
        assert parser.parse("Sep 28 10:01:01 host prog: msg") is None


class TestJsonLinesParser:
    def test_http_object(self):
        parser = get_parser("json")
        parsed = parser.parse(
            '{"timestamp": "2026-09-28T10:01:01", "remote_addr": "203.0.113.5",'
            ' "method": "GET", "path": "/admin", "status": 404,'
            ' "body_bytes_sent": 153, "http_user_agent": "curl/8"}'
        )
        assert parsed is not None
        assert parsed.kind == "http_access"
        assert parsed.ts == dt.datetime(2026, 9, 28, 10, 1, 1)
        assert parsed.ip == "203.0.113.5"
        assert parsed.status == 404
        assert parsed.bytes_sent == 153
        assert parsed.user_agent == "curl/8"

    def test_epoch_millis_and_nano_variant(self):
        parser = get_parser("json")
        parsed = parser.parse('{"ts": 1790667661000, "remote_addr": "1.2.3.4"}')
        assert parsed is not None
        assert parsed.ts.year == 2026
        assert parsed.status is None

    def test_object_without_timestamp_is_dropped(self):
        parser = get_parser("json")
        assert parser.parse('{"remote_addr": "1.2.3.4", "msg": "hi"}') is None

    def test_broken_json_is_none(self):
        parser = get_parser("json")
        assert parser.parse("{not json") is None
        assert parser.parse("[1,2,3]") is None
        # A record without any timestamp-like field cannot be windowed,
        # so it is dropped even though it is valid JSON.
        assert parser.parse('{"x": 1}') is None

    def test_epoch_seconds_without_other_fields(self):
        parser = get_parser("json")
        parsed = parser.parse('{"time": 1790667661}')
        assert parsed is not None
        assert parsed.kind == "syslog"

    def test_meta_keeps_whole_object(self):
        parser = get_parser("json")
        parsed = parser.parse(
            '{"timestamp": "2026-09-28T10:01:01", "user": "root", "custom": 7}'
        )
        assert parsed.meta["custom"] == 7
        assert parsed.meta["user"] == "root"
