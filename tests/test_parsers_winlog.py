"""Tests for the Windows event log parser."""

import datetime as dt

from app.parsers import get_parser, known_types


FAIL_EVENT = (
    '{"@timestamp": "2026-09-28T12:00:00Z", "host": {"name": "DC01"},'
    ' "winlog": {"event_id": 4625, "event_data": {'
    '"targetUserName": "administrator", "ipAddress": "203.0.113.66",'
    ' "workstationName": "ATTACK-PC", "logonType": "10"}},'
    ' "message": "An account failed to log on."}'
)

OK_EVENT = (
    '{"@timestamp": "2026-09-28T12:05:00Z", "computer": "DC01",'
    ' "winlog": {"event_id": 4624, "event_data": {"targetUserName": "alice"}}}'
)


def test_registered():
    assert "winlog" in known_types()


def test_failed_logon_maps_to_fail_kind():
    parsed = get_parser("winlog").parse(FAIL_EVENT)
    assert parsed is not None
    assert parsed.kind == "win_logon_fail"
    assert parsed.ts == dt.datetime(2026, 9, 28, 12, 0, 0)
    assert parsed.ip == "203.0.113.66"
    assert parsed.meta["user"] == "administrator"
    assert parsed.meta["event_id"] == 4625
    assert parsed.meta["workstation"] == "ATTACK-PC"


def test_successful_logon_kind():
    parsed = get_parser("winlog").parse(OK_EVENT)
    assert parsed.kind == "win_logon_ok"
    assert parsed.meta["user"] == "alice"


def test_unknown_event_id_becomes_generic():
    line = (
        '{"@timestamp": "2026-09-28T12:00:00Z",'
        ' "winlog": {"event_id": 7040, "event_data": {}}}'
    )
    parsed = get_parser("winlog").parse(line)
    assert parsed.kind == "win_event"
    assert parsed.meta["event_id"] == 7040


def test_non_json_or_missing_id_is_none():
    parser = get_parser("winlog")
    assert parser.parse("plain text") is None
    assert parser.parse('{"no": "event_id"}') is None
    assert parser.parse("[1,2]") is None


def test_bruteforce_detector_sees_windows_failures():
    from app.config import Settings
    from app.detectors.ssh_bruteforce import SshBruteforceDetector

    settings = Settings()
    settings.detectors = {
        "ssh_bruteforce": {"enabled": True, "max_failures": 2, "window_seconds": 300}
    }
    detector = SshBruteforceDetector(settings.detector("ssh_bruteforce"))
    assert "win_logon_fail" in detector.interested_kinds

    parser = get_parser("winlog")
    base = dt.datetime(2026, 9, 28, 12, 0, 0)
    for i in range(2):
        line = FAIL_EVENT.replace("12:00:00", f"12:0{i}:00")
        record = parser.parse(line)
        assert record is not None
        alerts = detector.feed(record)
        if i == 1:
            assert alerts, "detector should fire on the second windows failure"
            assert "failed" in alerts[0].message.lower()


def test_distributed_detector_sees_windows_failures():
    from app.detectors.distributed import DistributedAttackDetector

    detector = DistributedAttackDetector({"enabled": True, "max_ips": 2})
    assert "win_logon_fail" in detector.interested_kinds
