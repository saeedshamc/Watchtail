"""Parsed log records and the parser contract.

Every parser implements :class:`Parser` and returns :class:`ParsedLine`
objects or None for lines it does not recognise. Parsers are pure
functions of a line string, which makes them easy to test in isolation.
"""

import datetime as dt
import re
from dataclasses import dataclass, field

# Syslog timestamps have no year ("Sep 26 14:03:11"); assuming the
# current year keeps lines parsing across year boundaries.
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class ParsedLine:
    """A single meaningful log record.

    ``kind`` is one of ``http_access``, ``ssh_auth_fail`` or
    ``ssh_session_open``. Fields that do not apply stay None so callers
    can branch on ``kind`` alone.
    """

    kind: str
    ts: dt.datetime
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    bytes_sent: int | None = None
    user_agent: str | None = None
    meta: dict = field(default_factory=dict)


class Parser:
    """Base class for line parsers."""

    name = "base"

    def parse(self, line: str) -> ParsedLine | None:
        """Return a ParsedLine for recognised lines, else None."""
        raise NotImplementedError


def parse_syslog_timestamp(text: str, now: dt.datetime | None = None) -> dt.datetime | None:
    """Parse a leading syslog timestamp like ``Sep 26 14:03:11``.

    The year is taken from ``now`` (UTC today by default). Near the new
    year this can mislabel late-December entries by one year, which is
    acceptable for a live monitor that mostly cares about recent lines.
    """
    match = SYSLOG_TS_RE.match(text)
    if not match:
        return None
    now = now or dt.datetime.now(dt.timezone.utc)
    month = MONTHS.get(match.group("mon"))
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        return now.replace(
            month=month, day=int(match.group("day")), hour=hour, minute=minute,
            second=second, microsecond=0,
        )
    except ValueError:
        return None
