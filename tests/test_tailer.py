"""Tests for the log tailing worker."""

import os
import time

import pytest

from app.models import LogSource
from app.parsers import get_parser
from app.tailer import TailWorker

NGINX_LINE = (
    '203.0.113.7 - - [26/Sep/2026:14:03:11 +0000] "GET /admin HTTP/1.1" '
    '404 153 "-" "curl/8.5.0"'
)


class Source:
    """Duck-typed stand-in for LogSource rows."""

    def __init__(self, path, type_="nginx", source_id=1, last_position=0):
        self.id = source_id
        self.type = type_
        self.path = path
        self.last_position = last_position


def wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "access.log"
    path.write_text("", encoding="utf-8")
    return str(path)


def make_worker(path, records, **kwargs):
    worker = TailWorker(
        Source(path),
        get_parser("nginx"),
        lambda record, raw: records.append((record, raw)),
        poll_interval=0.05,
        **kwargs,
    )
    worker.start()
    return worker


def test_reads_appended_lines(log_file):
    records = []
    worker = make_worker(log_file, records)
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 1)
        record, raw = records[0]
        assert record.kind == "http_access"
        assert record.ip == "203.0.113.7"
        assert raw == NGINX_LINE
    finally:
        worker.stop()
        worker.join(timeout=5)


def test_ignores_unparseable_lines(log_file):
    records = []
    worker = make_worker(log_file, records)
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write("total garbage\n")
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 1)
    finally:
        worker.stop()
        worker.join(timeout=5)
        assert worker.stats["skipped"] == 1
        assert worker.stats["parsed"] == 1


def test_buffers_partial_lines_until_newline(log_file):
    records = []
    worker = make_worker(log_file, records)
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE[:20])
        # A partial line may advance the read offset but must never be
        # emitted as a record until its newline arrives.
        time.sleep(0.2)
        assert records == []
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE[20:] + "\n")
        assert wait_for(lambda: len(records) == 1)
        assert records[0][1] == NGINX_LINE
    finally:
        worker.stop()
        worker.join(timeout=5)


def test_position_survives_restart(log_file):
    persisted = {}
    records = []
    worker = make_worker(
        log_file, records, persist_position=lambda sid, pos: persisted.__setitem__(sid, pos)
    )
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: persisted)
    finally:
        worker.stop()
        worker.join(timeout=5)

    records2 = []
    worker2 = TailWorker(
        Source(log_file, source_id=1, last_position=persisted[1]),
        get_parser("nginx"),
        lambda record, raw: records2.append(record),
        poll_interval=0.05,
    )
    worker2.start()
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records2) == 1)
        # Old line must not be re-read after restart.
        assert len(records2) == 1
    finally:
        worker2.stop()
        worker2.join(timeout=5)


def test_rotation_reopens_new_file(log_file):
    rotated = log_file + ".1"
    records = []
    worker = make_worker(log_file, records)
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 1)
        os.replace(log_file, rotated)
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 2)
    finally:
        worker.stop()
        worker.join(timeout=5)
        if os.path.exists(rotated):
            os.remove(rotated)


def test_truncation_restarts_from_zero(log_file):
    records = []
    worker = make_worker(log_file, records)
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 1)
        # Rewrite with a shorter but still parseable line: byte-offset
        # tailing cannot see a truncate-plus-same-length rewrite that
        # lands inside one poll, and neither can tail -F.
        short_line = (
            '203.0.113.7 - - [26/Sep/2026:14:03:11 +0000] "GET /x HTTP/1.1" '
            '200 0 "-" "-"'
        )
        with open(log_file, "w", encoding="utf-8") as fh:
            fh.write(short_line + "\n")
        assert wait_for(lambda: len(records) == 2)
        assert records[1][0].status == 200
    finally:
        worker.stop()
        worker.join(timeout=5)


def test_missing_file_is_tolerated(tmp_path):
    records = []
    worker = make_worker(str(tmp_path / "not-here-yet.log"), records)
    try:
        time.sleep(0.2)
        assert worker.is_alive()
        with open(str(tmp_path / "not-here-yet.log"), "a", encoding="utf-8") as fh:
            fh.write(NGINX_LINE + "\n")
        assert wait_for(lambda: len(records) == 1)
    finally:
        worker.stop()
        worker.join(timeout=5)
