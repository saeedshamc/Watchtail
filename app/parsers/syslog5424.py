"""Parser for RFC 5424 syslog messages (rsyslog's RSYSLOG_SyslogProtocol23Format).

Example line::

    <34>1 2026-09-28T10:01:01.000003Z myhost sshd 24183 ID47 -
    BOM'su root' failed for user root

Structured-data chunks (``[name k="v"]``) are folded into the event's
``meta`` dictionary so detectors and the events browser can filter on
them later.
"""

import datetime as dt
import re

from .base import ParsedLine, Parser

# <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MESSAGE
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[.*?\])+)\s*"
    r"(?P<msg>.*)$"
)

SD_ELEMENT_RE = re.compile(r"\[(?P<name>[^\s\]]+)(?P<params>[^\]]*)\]")
SD_PARAM_RE = re.compile(r'(?P<key>\S+?)="(?P<value>.*?)"')

SEVERITY_BY_PRI = {  # informational and worse only; debug collapses to low
    0: "critical", 1: "high", 2: "high", 3: "medium",
    4: "low", 5: "low", 6: "low", 7: "low",
}


def parse_5424_timestamp(text: str) -> dt.datetime | None:
    """Parse an RFC 3339 timestamp (sub-second precision preserved)."""
    text = text.rstrip("Z")  # keep it simple: treat as UTC
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


class Syslog5424Parser(Parser):
    """Parses RFC 5424 lines into syslog events with severity metadata."""

    name = "syslog5424"

    def parse(self, line: str) -> ParsedLine | None:
        match = RFC5424_RE.match(line)
        if not match:
            return None
        ts = parse_5424_timestamp(match.group("ts"))
        if ts is None:
            return None

        meta = {
            "host": match.group("host"),
            "program": match.group("app"),
            "procid": None if match.group("procid") == "-" else match.group("procid"),
            "msgid": None if match.group("msgid") == "-" else match.group("msgid"),
            "severity": SEVERITY_BY_PRI.get(int(match.group("pri")) % 8, "low"),
            "message": match.group("msg"),
        }

        sd_blob = match.group("sd")
        if sd_blob != "-":
            for element in SD_ELEMENT_RE.finditer(sd_blob):
                params = SD_PARAM_RE.findall(element.group("params"))
                for key, value in params:
                    meta[f"sd.{element.group('name')}.{key}"] = value

        return ParsedLine(kind="syslog", ts=ts, meta=meta)
