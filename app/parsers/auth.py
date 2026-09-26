"""Parser for Linux auth.log / syslog SSH lines.

Recognises failed password attempts (both "Failed password" and
"Invalid user" forms) and session openings, which the dashboard uses to
show successful logins alongside attacks.
"""

import re

from .base import ParsedLine, Parser, parse_syslog_timestamp

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?:Failed password for )?(?:invalid user )?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2",
    re.IGNORECASE,
)

OPENED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2",
    re.IGNORECASE,
)

BREAKIN_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"POSSIBLE BREAK-IN ATTEMPT!.*from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)


class AuthLogParser(Parser):
    """Parses sshd lines from auth.log into auth event records."""

    name = "auth"

    def parse(self, line: str) -> ParsedLine | None:
        failed = FAILED_RE.match(line)
        if failed:
            ts = parse_syslog_timestamp(failed.group("ts"))
            if ts is None:
                return None
            return ParsedLine(
                kind="ssh_auth_fail",
                ts=ts,
                ip=failed.group("ip"),
                meta={
                    "user": failed.group("user"),
                    "port": int(failed.group("port")),
                    "host": failed.group("host"),
                },
            )

        opened = OPENED_RE.match(line)
        if opened:
            ts = parse_syslog_timestamp(opened.group("ts"))
            if ts is None:
                return None
            return ParsedLine(
                kind="ssh_session_open",
                ts=ts,
                ip=opened.group("ip"),
                meta={
                    "user": opened.group("user"),
                    "port": int(opened.group("port")),
                    "host": opened.group("host"),
                },
            )

        breakin = BREAKIN_RE.match(line)
        if breakin:
            ts = parse_syslog_timestamp(breakin.group("ts"))
            if ts is None:
                return None
            # Some sshd builds log "from 1.2.3.4: port 44231"; the
            # trailing colon must not become part of the address.
            ip = breakin.group("ip").rstrip(":")
            return ParsedLine(
                kind="ssh_breakin",
                ts=ts,
                ip=ip,
                meta={"host": breakin.group("host")},
            )

        return None
