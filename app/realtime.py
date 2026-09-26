"""Socket.IO wiring for live dashboard updates.

A dedicated broadcaster thread pulls payloads from an in-memory queue
and emits them inside an app context. Tailer threads only ever push to
the queue, so a slow dashboard can never stall log processing; when the
queue fills up, updates are dropped rather than buffered without bound.
"""

import logging
import queue
import threading

from flask_socketio import SocketIO

logger = logging.getLogger("watchtail")

socketio = SocketIO(async_mode="threading", cors_allowed_origins=[])
_queue: "queue.Queue[dict]" = queue.Queue(maxsize=500)
_broadcaster_started = False


def emit_activity(event_dict, alerts):
    """Queue an activity payload from a tailer thread (never blocks)."""
    payload = {"event": event_dict, "alerts": alerts}
    try:
        _queue.put_nowait(payload)
    except queue.Full:
        try:
            _queue.get_nowait()  # shed the oldest update
        except queue.Empty:
            pass
        try:
            _queue.put_nowait(payload)
        except queue.Full:
            pass


def start_broadcaster(app):
    """Start the broadcaster thread once per process."""
    global _broadcaster_started
    if _broadcaster_started:
        return
    _broadcaster_started = True

    def loop():
        while True:
            payload = _queue.get()
            with app.app_context():
                try:
                    socketio.emit("activity", payload)
                except Exception:
                    logger.exception("socketio emit failed")

    threading.Thread(target=loop, name="socketio-broadcaster", daemon=True).start()
