"""Parser for JSON-lines logs (one JSON object per line).

Common for structured logging stacks (nginx `escape=json`, Caddy,
Docker json-file drivers, application logs). Field names vary wildly,
so the parser checks a small set of well-known spellings per concept
and keeps the whole object in ``meta`` either way.
"""

import datetime as dt
import json

from .base import ParsedLine, Parser

# Candidate spellings per concept; first match wins.
_TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "datetime", "date")
_IP_KEYS = ("client_ip", "remote_addr", "clientip", "ip", "src", "source_ip")
_METHOD_KEYS = ("method", "http_method", "request_method")
_PATH_KEYS = ("path", "url", "request", "uri", "endpoint")
_STATUS_KEYS = ("status", "status_code", "code", "response_code", "sc")
_BYTES_KEYS = ("bytes", "bytes_sent", "size", "length", "body_bytes_sent")
_AGENT_KEYS = ("user_agent", "agent", "ua", "http_user_agent")
_USER_KEYS = ("user", "username", "ssh_user", "account")


def _first_present(obj, keys):
    for key in keys:
        value = obj.get(key)
        if value is not None:
            return value
    return None


def _parse_ts(value) -> dt.datetime | None:
    if isinstance(value, (int, float)):
        try:
            # Seconds vs milliseconds: heuristics keep both usable.
            if value > 1e12:
                value = value / 1000.0
            return dt.datetime.fromtimestamp(value, dt.timezone.utc).replace(
                tzinfo=None
            )
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip().rstrip("Z")
        # Precise ISO-8601 first (keeps fractional seconds), then the
        # common verbose formats.
        iso = text
        if iso.endswith("+00:00"):
            iso = iso[: -len("+00:00")]
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ):
            try:
                return dt.datetime.strptime(iso, fmt)
            except ValueError:
                continue
    return None


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class JsonLinesParser(Parser):
    """Parses one JSON object per line into HTTP or auth-ish events."""

    name = "json"

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

        ts = _parse_ts(_first_present(obj, _TS_KEYS))
        if ts is None:
            # A record without a usable timestamp cannot be windowed by
            # the detectors; drop it rather than guessing "now".
            return None

        status = _as_int(_first_present(obj, _STATUS_KEYS))
        if status is not None:
            kind = "http_access"
        elif _first_present(obj, _PATH_KEYS) is not None:
            kind = "http_access"
        else:
            kind = "syslog"

        return ParsedLine(
            kind=kind,
            ts=ts,
            ip=_first_present(obj, _IP_KEYS),
            method=_first_present(obj, _METHOD_KEYS),
            path=_first_present(obj, _PATH_KEYS),
            status=status,
            bytes_sent=_as_int(_first_present(obj, _BYTES_KEYS)),
            user_agent=_first_present(obj, _AGENT_KEYS),
            meta=obj,
        )
