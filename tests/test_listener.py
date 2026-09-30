"""Tests for UDP/TCP syslog listener sources."""

import datetime as dt
import socket
import time

import pytest

import app as watchtail_app
from app.config import Settings
from app.database import dispose_engine, session_scope
from app.listener import ListenerRegistry, ListenerWorker, is_listener_source, parse_endpoint
from app.models import Event, LogSource
from app.parsers import get_parser
from app.parsers.base import ParsedLine


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def _free_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _free_tcp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class TestEndpointParsing:
    def test_udp_and_tcp(self):
        assert parse_endpoint("udp://0.0.0.0:5514") == ("udp", "0.0.0.0", 5514)
        assert parse_endpoint("tcp://127.0.0.1:5601") == ("tcp", "127.0.0.1", 5601)
        assert parse_endpoint("UDP://0.0.0.0:5514") == ("udp", "0.0.0.0", 5514)

    def test_ipv6_host(self):
        assert parse_endpoint("udp://[::]:5514") == ("udp", "::", 5514)
        assert parse_endpoint("udp://[::1]:5514") == ("udp", "::1", 5514)

    def test_non_endpoint_paths(self):
        assert parse_endpoint("/var/log/syslog") is None
        assert parse_endpoint("http://host:80") is None
        assert parse_endpoint("udp://host:notaport") is None
        assert parse_endpoint("") is None

    def test_is_listener_source(self):
        row = LogSource(id=1, type="syslog", path="udp://0.0.0.0:5514")
        assert is_listener_source(row) is True
        file_row = LogSource(id=2, type="syslog", path="/var/log/syslog")
        assert is_listener_source(file_row) is False


def _received():
    received = []

    def on_record(record, raw, source=None):
        received.append((record, raw, source))

    return received, on_record


def test_udp_listener_receives_and_parses():
    port = _free_udp_port()
    received, on_record = _received()
    source = LogSource(id=7, name="udp", type="syslog", path=f"udp://127.0.0.1:{port}")
    worker = ListenerWorker(source, get_parser("syslog"), on_record)
    worker.start()
    time.sleep(0.4)  # give the bind a moment

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    line = "Sep 28 10:01:01 fw01 sshd[123]: Failed password for root"
    sock.sendto(line.encode(), ("127.0.0.1", port))
    sock.sendto(b"definitely not syslog\n", ("127.0.0.1", port))
    sock.close()
    time.sleep(0.6)

    worker.stop()
    worker.join(timeout=3)
    assert len(received) == 1
    record, raw, src = received[0]
    assert record.kind == "syslog"
    assert record.meta["program"] == "sshd"
    # Sender address becomes the IP for detection.
    assert record.ip == "127.0.0.1"
    assert raw == line
    assert src.id == 7
    assert worker.stats["parsed"] == 1
    assert worker.stats["skipped"] >= 1


def test_udp_listener_keeps_running_after_bad_payload():
    port = _free_udp_port()
    received, on_record = _received()
    source = LogSource(id=8, type="syslog", path=f"udp://127.0.0.1:{port}")
    worker = ListenerWorker(source, get_parser("syslog"), on_record)
    worker.start()
    time.sleep(0.4)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"not a syslog line at all", ("127.0.0.1", port))
    time.sleep(0.3)
    good = "Sep 28 10:01:02 fw01 cron[1]: job ran"
    sock.sendto(good.encode(), ("127.0.0.1", port))
    sock.close()
    time.sleep(0.6)

    worker.stop()
    worker.join(timeout=3)
    assert worker.stats["skipped"] >= 1
    assert len(received) == 1
    assert received[0][0].meta["program"] == "cron"


def test_tcp_listener_receives_lines_from_one_connection():
    port = _free_tcp_port()
    received, on_record = _received()
    source = LogSource(id=9, type="syslog5424", path=f"tcp://127.0.0.1:{port}")
    worker = ListenerWorker(source, get_parser("syslog5424"), on_record)
    worker.start()
    time.sleep(0.4)

    conn = socket.create_connection(("127.0.0.1", port), timeout=3)
    conn.sendall(
        b"<34>1 2026-09-28T10:01:01Z hosta sshd 241 - - failed\n"
        b"<13>1 2026-09-28T10:01:02Z hosta cron 5 - - ok\n"
    )
    time.sleep(0.8)
    conn.close()

    worker.stop()
    worker.join(timeout=3)
    assert len(received) == 2
    kinds = {r[0].meta["program"] for r in received}
    assert kinds == {"sshd", "cron"}
    assert all(r[0].ip == "127.0.0.1" for r in received)


def test_tcp_listener_multiple_connections():
    port = _free_tcp_port()
    received, on_record = _received()
    source = LogSource(id=10, type="syslog", path=f"tcp://127.0.0.1:{port}")
    worker = ListenerWorker(source, get_parser("syslog"), on_record)
    worker.start()
    time.sleep(0.4)

    for i in range(2):
        conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        conn.sendall(f"Sep 28 10:0{i + 1}:00 h prog[1]: msg {i}\n".encode())
        time.sleep(0.4)
        conn.close()

    worker.stop()
    worker.join(timeout=3)
    assert len(received) == 2


def test_registry_sync_starts_and_stops_workers():
    port = _free_udp_port()
    received, on_record = _received()
    registry = ListenerRegistry(parser_factory=get_parser, on_record=on_record)
    row = LogSource(id=11, name="udp", type="syslog", path=f"udp://127.0.0.1:{port}")
    row.enabled = True
    registry.sync([row])
    deadline = time.time() + 2
    while time.time() < deadline and 11 not in registry.running_ids():
        time.sleep(0.05)
    assert 11 in registry.running_ids()

    row.enabled = False
    registry.sync([row])
    deadline = time.time() + 2
    while time.time() < deadline and 11 in registry.running_ids():
        time.sleep(0.05)
    assert 11 not in registry.running_ids()
    registry.stop_all()


def test_registry_ignores_file_sources_and_bad_endpoints():
    received, on_record = _received()
    registry = ListenerRegistry(parser_factory=get_parser, on_record=on_record)
    file_row = LogSource(id=12, type="syslog", path="/var/log/syslog")
    file_row.enabled = True
    bad_row = LogSource(id=13, type="syslog", path="udp://no-port-here")
    bad_row.enabled = True
    registry.sync([file_row, bad_row])
    assert registry.running_ids() == set()
    registry.stop_all()


def test_pipeline_accepts_listener_records_with_sender_ip():
    """End-to-end: listener records flow through the pipeline."""
    from app.pipeline import Pipeline

    settings = Settings()
    record = ParsedLine(
        kind="syslog",
        ts=dt.datetime(2026, 9, 28, 12, 0, 0),
        ip="192.0.2.44",
        meta={"program": "sshd", "message": "Failed password for root"},
    )
    pipeline = Pipeline(settings)
    pipeline.handle_record(record, "raw", None)
    with session_scope() as session:
        assert session.query(Event).count() == 1
