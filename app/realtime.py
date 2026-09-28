"""Socket.IO wiring for live dashboard updates.

A dedicated broadcaster thread pulls activity payloads from an
in-memory queue and emits them inside an app context. Tailer threads
only ever push to the queue, so a slow dashboard can never stall log
processing; when the queue fills up, updates are dropped rather than
buffered without bound.

A second cadence inside the same thread periodically emits a ``stats``
snapshot straight from the database. Counters rendered at page load
would otherwise drift as events age out of the 24h window, and the
flagged-IP list only changes when a stat tick can notice it.
"""

import logging
import queue
import threading
from datetime import timedelta

from flask_socketio import SocketIO
from sqlalchemy import func, select

from .models import Alert, Event, IpStatus, LogSource, utcnow

logger = logging.getLogger("watchtail")

STATS_INTERVAL_SECONDS = 10

socketio = SocketIO(async_mode="threading", cors_allowed_origins=[])
_queue: "queue.Queue[dict]" = queue.Queue(maxsize=500)
_broadcaster_started = False
_broadcaster_stop = threading.Event()


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


def interval_stats_payload() -> dict:
    """Build a dashboard stats snapshot from the database.

    Mirrors the counts rendered by the dashboard view so the live
    channel can correct server-rendered numbers instead of inventing
    its own semantics.
    """
    from .database import session_scope

    day_ago = utcnow() - timedelta(hours=24)
    with session_scope() as session:
        event_count = (
            session.query(func.count(Event.id)).filter(Event.ts >= day_ago).scalar()
        )
        alert_count = (
            session.query(func.count(Alert.id)).filter(Alert.ts >= day_ago).scalar()
        )
        flagged_count = (
            session.query(func.count(IpStatus.ip))
            .filter(
                IpStatus.status == "flagged",
                IpStatus.last_alert_at >= day_ago,
            )
            .scalar()
        )
        source_count = session.query(func.count(LogSource.id)).scalar()
        active_sources = (
            session.query(func.count(LogSource.id))
            .filter(LogSource.enabled.is_(True))
            .scalar()
        )
        latest_flagged = session.scalars(
            select(IpStatus.ip)
            .filter(IpStatus.status == "flagged")
            .order_by(IpStatus.last_alert_at.desc().nullslast())
            .limit(50)
        ).all()
    return {
        "stats": {
            "event_count": event_count or 0,
            "alert_count": alert_count or 0,
            "flagged_count": flagged_count or 0,
            "active_sources": active_sources or 0,
            "source_count": source_count or 0,
        },
        "flagged_ips": latest_flagged,
        "ts": utcnow().isoformat() + "Z",
    }


def emit_stats():
    """Queue a stats refresh (public API for callers outside the loop)."""
    try:
        _queue.put_nowait({"stats": interval_stats_payload()})
    except queue.Full:
        pass


def start_broadcaster(app, interval_stats=STATS_INTERVAL_SECONDS):
    """Start the broadcaster thread once per process.

    ``interval_stats`` is the seconds between periodic stats snapshots;
    values below two are clamped so a bad setting cannot turn the
    database into a spinning wheel.
    """
    global _broadcaster_started
    if _broadcaster_started:
        return
    _broadcaster_started = True
    _broadcaster_stop.clear()

    def drain():
        while True:
            try:
                payload = _queue.get(timeout=0.5)
            except queue.Empty:
                if _broadcaster_stop.is_set():
                    return
                continue
            if _broadcaster_stop.is_set():
                return
            with app.app_context():
                try:
                    socketio.emit("activity", payload)
                except Exception:
                    logger.exception("socketio emit failed")

    def stats_loop():
        interval = max(2, int(interval_stats))
        while not _broadcaster_stop.wait(interval):
            try:
                payload = {"stats": interval_stats_payload()}
            except Exception:
                logger.exception("stats refresh failed")
                continue
            with app.app_context():
                try:
                    socketio.emit("stats", payload)
                except Exception:
                    logger.exception("socketio stats emit failed")

    threading.Thread(target=drain, name="socketio-broadcaster", daemon=True).start()
    threading.Thread(target=stats_loop, name="socketio-stats", daemon=True).start()


def stop_broadcaster():
    """Signal the broadcaster threads to exit (used by tests)."""
    global _broadcaster_started
    _broadcaster_stop.set()
    _broadcaster_started = False
