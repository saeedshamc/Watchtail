"""Tests for the Socket.IO broadcaster."""

import queue

import app.realtime as realtime


def test_emit_activity_queues_payload():
    caught = []
    original = realtime._queue
    try:
        realtime._queue = queue.Queue()
        realtime.emit_activity({"id": 1}, [])
        caught.append(realtime._queue.get_nowait())
        assert caught[0] == {"event": {"id": 1}, "alerts": []}
    finally:
        realtime._queue = original


def test_emit_activity_sheds_oldest_when_full():
    original = realtime._queue
    try:
        realtime._queue = queue.Queue(maxsize=1)
        realtime.emit_activity({"id": 1}, [])
        realtime.emit_activity({"id": 2}, [])
        assert realtime._queue.get_nowait()["event"]["id"] == 2
    finally:
        realtime._queue = original


def test_broadcaster_starts_once_per_process():
    calls = {"threads": 0}

    class FakeApp:
        pass

    import threading

    original_thread = threading.Thread

    def counting_thread(*args, **kwargs):
        calls["threads"] += 1
        return original_thread(*args, **kwargs)

    threading.Thread = counting_thread
    try:
        realtime.start_broadcaster(FakeApp())
        first = calls["threads"]
        realtime.start_broadcaster(FakeApp())
        assert calls["threads"] == first  # second call is a no-op
    finally:
        threading.Thread = original_thread
