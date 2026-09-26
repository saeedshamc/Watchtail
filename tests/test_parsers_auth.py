"""Tests for the auth.log (sshd) parser."""

from app.parsers import get_parser, known_types

FAILED_INVALID_USER = (
    "Sep 26 14:03:11 srv01 sshd[24183]: Failed password for invalid user admin "
    "from 203.0.113.44 port 41932 ssh2"
)
FAILED_KNOWN_USER = (
    "Sep 26 14:03:15 srv01 sshd[24184]: Failed password for root "
    "from 203.0.113.44 port 41956 ssh2"
)
ACCEPTED = (
    "Sep 26 14:05:01 srv01 sshd[24210]: Accepted password for deploy "
    "from 198.51.100.9 port 51244 ssh2"
)
BREAKIN = (
    "Sep 26 14:06:00 srv01 sshd[24211]: POSSIBLE BREAK-IN ATTEMPT! "
    "from 203.0.113.99: port 44231"
)


def test_auth_registered():
    assert "auth" in known_types()


def test_failed_password_invalid_user():
    record = get_parser("auth").parse(FAILED_INVALID_USER)
    assert record.kind == "ssh_auth_fail"
    assert record.ip == "203.0.113.44"
    assert record.meta["user"] == "admin"
    assert record.meta["port"] == 41932
    assert record.meta["host"] == "srv01"
    assert (record.ts.month, record.ts.day, record.ts.hour) == (9, 26, 14)


def test_failed_password_known_user():
    record = get_parser("auth").parse(FAILED_KNOWN_USER)
    assert record.kind == "ssh_auth_fail"
    assert record.meta["user"] == "root"


def test_accepted_login():
    record = get_parser("auth").parse(ACCEPTED)
    assert record.kind == "ssh_session_open"
    assert record.ip == "198.51.100.9"
    assert record.meta["user"] == "deploy"


def test_breakin_attempt():
    record = get_parser("auth").parse(BREAKIN)
    assert record.kind == "ssh_breakin"
    assert record.ip == "203.0.113.99"


def test_unrelated_lines_are_ignored():
    parser = get_parser("auth")
    assert parser.parse("Sep 26 14:03:11 srv01 systemd[1]: Started Daily apt upgrade.") is None
    assert parser.parse("Sep 26 14:03:11 srv01 CRON[9001]: pam_unix(cron:session): session opened") is None
    assert parser.parse("") is None


def test_non_ssh2_suffix_still_matches():
    line = (
        "Sep 26 14:03:11 srv01 sshd[24183]: Failed password for git "
        "from 203.0.113.44 port 41933 ssh2"
    )
    assert get_parser("auth").parse(line) is not None
