"""Parser for the Apache "combined" access log format."""

import datetime as dt
import re

from .base import ParsedLine, Parser

# Same shape as nginx combined, with %l instead of "-": the regex
# already accepts any non-space token there.
LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ApacheAccessParser(Parser):
    """Parses Apache combined access lines into http_access records."""

    name = "apache"

    def parse(self, line: str) -> ParsedLine | None:
        match = LINE_RE.match(line)
        if not match:
            return None
        try:
            ts = dt.datetime.strptime(match.group("ts"), TS_FORMAT)
        except ValueError:
            return None
        ts = ts.astimezone(dt.timezone.utc).replace(tzinfo=None)

        request = match.group("request")
        method = path = None
        parts = request.split()
        if len(parts) >= 2:
            method, path = parts[0], parts[1]

        bytes_field = match.group("bytes")
        referer = match.group("referer")
        user_agent = match.group("ua")
        return ParsedLine(
            kind="http_access",
            ts=ts,
            ip=match.group("ip"),
            method=method,
            path=path,
            status=int(match.group("status")),
            bytes_sent=None if bytes_field == "-" else int(bytes_field),
            user_agent=user_agent if user_agent not in ("", "-") else None,
            meta={"referer": referer if referer not in ("", "-") else None},
        )
