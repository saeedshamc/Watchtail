"""Daily digest: one summary message instead of per-alert noise.

A background thread in the broadcaster process builds a 24h summary
(alert counts by severity and detector, new flagged IPs, top sources)
and hands it to the digest channel at the configured hour. Missed
schedules (server restarts) are skipped rather than replayed — the
next day's digest covers whatever happened.
"""

import logging
import threading
from datetime import timedelta

from .base import Notifier, NotifierRegistry

logger = logging.getLogger("watchtail")


def build_digest_payload(hours=24):
    """Summarise the last ``hours`` of activity from the database."""
    import datetime as dt

    from ..database import session_scope
    from ..models import Alert, IpStatus, utcnow
    from sqlalchemy import func

    since = utcnow() - dt.timedelta(hours=hours)
    with session_scope() as session:
        by_severity = dict(
            session.query(Alert.severity, func.count(Alert.id))
            .filter(Alert.ts >= since)
            .group_by(Alert.severity)
            .all()
        )
        by_detector = dict(
            session.query(Alert.detector, func.count(Alert.id))
            .filter(Alert.ts >= since)
            .group_by(Alert.detector)
            .all()
        )
        new_ips = (
            session.query(IpStatus)
            .filter(IpStatus.first_seen_at >= since)
            .order_by(IpStatus.threat_score.desc())
            .limit(10)
            .all()
        )
        top = (
            session.query(Alert.ip, func.count(Alert.id).label("hits"))
            .filter(Alert.ts >= since)
            .group_by(Alert.ip)
            .order_by(func.count(Alert.id).desc())
            .limit(5)
            .all()
        )

    return {
        "window_hours": hours,
        "total_alerts": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_detector": by_detector,
        "new_flagged_ips": [
            {"ip": row.ip, "score": row.threat_score or 0, "reason": row.reason}
            for row in new_ips
        ],
        "top_sources": [{"ip": ip, "alerts": count} for ip, count in top],
    }


def render_digest_text(payload) -> str:
    """Human-readable digest for text channels (email, telegram)."""
    lines = [f"Watchtail digest — last {payload['window_hours']}h"]
    lines.append(
        f"Total alerts: {payload['total_alerts']} "
        + " ".join(f"{sev}: {n}" for sev, n in sorted(payload["by_severity"].items()))
    )
    if payload["by_detector"]:
        lines.append("Detectors: " + ", ".join(
            f"{name} x{count}" for name, count in sorted(payload["by_detector"].items())
        ))
    if payload["top_sources"]:
        lines.append("Top sources: " + ", ".join(
            f"{item['ip']} ({item['alerts']})" for item in payload["top_sources"]
        ))
    if payload["new_flagged_ips"]:
        lines.append("New flagged IPs:")
        for item in payload["new_flagged_ips"]:
            lines.append(f"  {item['ip']} (score {item['score']}) — {item['reason'] or '?'}")
    if payload["total_alerts"] == 0 and not payload["new_flagged_ips"]:
        lines.append("A quiet day. Nothing suspicious recorded.")
    return "\n".join(lines)


class DigestChannel(Notifier):
    """Wraps a text channel so digests can flow through the registry."""

    name = "digest"

    def __init__(self, inner: Notifier):
        self.inner = inner
        self.min_severity = getattr(inner, "min_severity", "low")

    def send(self, alert) -> None:  # pragma: no cover - registry path
        self.inner.send(alert)

    def send_digest(self, payload) -> None:
        class _Digest:
            detector = "digest"
            ip = "report"
            severity = "low"
            message = render_digest_text(payload)
            ts = None
            meta = payload

        # Reuse the channel's own message builder with a synthetic row.
        self.inner.send(_Digest())


class DigestScheduler:
    """Runs ``send_digest`` daily at a fixed hour in a daemon thread."""

    def __init__(self, registry: NotifierRegistry, hour_utc=7, hours=24):
        self.registry = registry
        self.hour_utc = int(hour_utc)
        self.hours = int(hours)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="digest-scheduler", daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread = None

    def _loop(self):
        import datetime as dt

        while not self._stop.wait(60):
            now = dt.datetime.now(dt.timezone.utc)
            if now.hour != self.hour_utc or now.minute >= 1:
                continue
            self.send_digest()

    def send_digest(self):
        """Push a digest to channels that opted in via min_severity=info."""
        payload = build_digest_payload(self.hours)
        for notifier in self.registry.notifiers:
            digestable = getattr(notifier, "digest_enabled", False)
            if not digestable:
                continue
            channel = DigestChannel(notifier)
            try:
                channel.send_digest(payload)
            except Exception:
                logger.exception("digest via %s failed", notifier.name)
        return payload
