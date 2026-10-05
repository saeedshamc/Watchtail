"""Tests for SSH remote tail sources (with a fake SSH transport)."""

import threading
import time

import pytest

import app as watchtail_app
from app.database import dispose_engine
from app.parsers import get_parser
from app.ssh_tail import SshTailRegistry, SshTailWorker, is_ssh_source, parse_ssh_target
from app.models import LogSource


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


class FakeChannel:
    """Mimics the parts of paramiko's channel the worker uses."""

    def __init__(self, lines):
        self._buffer = ("\n".join(lines) + "\n").encode("utf-8")
        self._sent = False
        self.closed = False

    def exit_status_ready(self):
        return False  # keep streaming, like a real `tail -F`

    def recv_ready(self):
        return not self._sent

    def recv(self, size):
        self._sent = True
        chunk, self._buffer = self._buffer, b""
        return chunk


class FakeStdout:
    def __init__(self, channel):
        self.channel = channel


class FakeClient:
    def __init__(self, lines):
        self.lines = lines
        self.closed = False

    def exec_command(self, command, get_pty=False):
        assert command.startswith("tail -n")
        self.command = command
        self.channel = FakeChannel(self.lines)
        return None, FakeStdout(self.channel), None

    def close(self):
        self.closed = True


class TestTargetParsing:
    def test_full_spec(self):
        assert parse_ssh_target("ssh://ops@10.0.0.12:2222/var/log/auth.log") == (
            "ops", "10.0.0.12", 2222, "/var/log/auth.log",
        )

    def test_defaults(self):
        assert parse_ssh_target("ssh://10.0.0.12/var/log/syslog") == (
            "root", "10.0.0.12", 22, "/var/log/syslog",
        )

    def test_invalid(self):
        assert parse_ssh_target("/var/log/syslog") is None
        assert parse_ssh_target("ssh://10.0.0.12") is None  # no file path
        assert parse_ssh_target("ssh://user@host") is None
        assert parse_ssh_target("udp://host:53") is None

    def test_is_ssh_source(self):
        row = LogSource(id=1, type="auth", path="ssh://ops@h/log")
        assert is_ssh_source(row) is True
        file_row = LogSource(id=2, type="auth", path="/var/log/auth.log")
        assert is_ssh_source(file_row) is False


def _received():
    received = []

    def on_record(record, raw, source=None):
        received.append((record, raw, source))

    return received, on_record


def test_worker_streams_and_parses_lines():
    received, on_record = _received()
    source = LogSource(id=21, name="remote", type="auth",
                       path="ssh://ops@10.0.0.12/var/log/auth.log")
    source.last_position = 20
    fake = FakeClient(
        [
            "Sep 28 10:01:01 web1 sshd[101]: Failed password for root from 203.0.113.4 port 51022 ssh2",
            "Sep 28 10:01:02 web1 sshd[101]: Failed password for root from 203.0.113.4 port 51023 ssh2",
        ]
    )
    worker = SshTailWorker(
        source, get_parser("auth"), on_record,
        connect_factory=lambda: fake,
    )
    worker.start()
    deadline = time.time() + 3
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.05)
    worker.stop()
    worker.join(timeout=3)

    assert len(received) == 2
    record, raw, src = received[0]
    assert record.kind == "ssh_auth_fail"
    assert record.ip == "203.0.113.4"
    assert src.id == 21
    assert "tail -n 20" in fake.command  # backlog from last_position
    assert worker.stats["parsed"] == 2
    assert fake.closed is True


def test_worker_skips_unparseable_lines():
    received, on_record = _received()
    source = LogSource(id=22, type="syslog", path="ssh://root@h/var/log/x")
    fake = FakeClient(["this is not syslog"])
    worker = SshTailWorker(
        source, get_parser("syslog"), on_record,
        connect_factory=lambda: fake,
    )
    worker.start()
    deadline = time.time() + 3
    while time.time() < deadline and worker.stats["skipped"] < 1:
        time.sleep(0.05)
    worker.stop()
    assert received == []
    assert worker.stats["skipped"] == 1


def test_registry_starts_and_stops_worker():
    received, on_record = _received()
    registry = SshTailRegistry(
        parser_factory=get_parser,
        on_record=on_record,
        connect_factory=lambda: FakeClient(["Sep 28 10:01:01 h prog[1]: msg"]),
    )
    row = LogSource(id=23, type="syslog", path="ssh://root@10.9.9.9/var/log/syslog")
    row.enabled = True
    registry.sync([row])
    deadline = time.time() + 3
    while time.time() < deadline and 23 not in registry.running_ids():
        time.sleep(0.05)
    assert 23 in registry.running_ids()

    row.enabled = False
    registry.sync([row])
    deadline = time.time() + 3
    while time.time() < deadline and 23 in registry.running_ids():
        time.sleep(0.05)
    assert 23 not in registry.running_ids()
    registry.stop_all()


def test_registry_ignores_file_sources():
    received, on_record = _received()
    registry = SshTailRegistry(parser_factory=get_parser, on_record=on_record)
    file_row = LogSource(id=24, type="auth", path="/var/log/auth.log")
    file_row.enabled = True
    registry.sync([file_row])
    assert registry.running_ids() == set()
    registry.stop_all()


def test_sources_route_accepts_ssh_paths(admin_client=None, memory_app=None):
    """The add-source form accepts ssh:// paths without normalising them."""
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    client = application.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    response = client.post(
        "/sources/add",
        data={"name": "remote auth", "type": "auth",
              "path": "ssh://ops@10.0.0.12/var/log/auth.log"},
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)
    assert "ssh://ops@10.0.0.12/var/log/auth.log" in html
