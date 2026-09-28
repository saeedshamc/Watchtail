"""Parser for Windows Event Log data (winlogbeat-style JSON).

Winlogbeat flattens events under ``winlog.event_id`` with the account
under ``winlog.event_data``. The parser maps the event IDs that matter
for account attacks onto watchtail's auth kinds so the existing SSH
detectors work on Windows hosts too:

* 4625 — failed logon            -> ``win_logon_fail``
* 4624 — successful logon        -> ``win_logon_ok``
* 4720 — account created         -> ``win_account_change``
* 4726 — account deleted         -> ``win_account_change``
* 4672 — special logon (admin)   -> ``win_special_logon``
"""

import json

from .base import ParsedLine, Parser

EVENT_KINDS = {
    4625: "win_logon_fail",
    4624: "win_logon_ok",
    4720: "win_account_change",
    4726: "win_account_change",
    4672: "win_special_logon",
}

_TS_KEYS = ("@timestamp", "timestamp", "event_time")
_HOST_KEYS = ("host", "computer", "computer_name", "agent.name")


def _walk(obj, path):
    """Follow a dotted path into nested dicts, returning None if absent."""
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


class WinLogParser(Parser):
    """Parses winlogbeat JSON lines into windows event records."""

    name = "winlog"

    def parse(self, line: str) -> ParsedLine | None:
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None

        event_id = _walk(obj, "winlog.event_id")
        if event_id is None:
            event_id = obj.get("event_id")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            return None

        from .jsonl import _parse_ts  # reuse timestamp handling

        ts = _parse_ts(_first(obj, _TS_KEYS))
        if ts is None:
            return None

        kind = EVENT_KINDS.get(event_id, "win_event")
        event_data = _walk(obj, "winlog.event_data") or {}

        host = _first(obj, _HOST_KEYS)
        if isinstance(host, dict):
            host = host.get("name")

        return ParsedLine(
            kind=kind,
            ts=ts,
            ip=_walk(obj, "source.ip") or event_data.get("ipAddress"),
            meta={
                "event_id": event_id,
                "host": host,
                "user": event_data.get("targetUserName")
                or event_data.get("subjectUserName"),
                "workstation": event_data.get("workstationName"),
                "logon_type": event_data.get("logonType"),
                "message": _walk(obj, "message"),
            },
        )


def _first(obj, keys):
    for key in keys:
        value = _walk(obj, key) if "." in key else obj.get(key)
        if value is not None:
            return value
    return None
