"""Parser for plain syslog files (RFC 3164 style, any program).

Watchtail's auth parser only understands sshd lines inside auth.log.
This parser handles arbitrary syslog files — routers, cron, su, sudo —
extracting the timestamp, host and program so non-SSH traffic still
appears on the dashboard as generic ``syslog`` events.
"""

import re

from .base import ParsedLine, Parser, parse_syslog_timestamp

# "Sep 28 10:01:01 host prog[123]: message" or without a pid.
SYSLOG_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)


class SyslogParser(Parser):
    """Parses generic RFC 3164 syslog lines into syslog events."""

    name = "syslog"

    def parse(self, line: str) -> ParsedLine | None:
        match = SYSLOG_LINE_RE.match(line)
        if not match:
            return None
        ts = parse_syslog_timestamp(match.group("ts"))
        if ts is None:
            return None
        return ParsedLine(
            kind="syslog",
            ts=ts,
            meta={
                "host": match.group("host"),
                "program": match.group("prog"),
                "pid": int(match.group("pid")) if match.group("pid") else None,
                "message": match.group("msg"),
            },
        )
