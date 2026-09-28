"""Prometheus text-format metrics endpoint.

Counters since process start plus gauges read from the database on
scrape. The format is hand-rolled to keep dependencies at zero; it
covers the common metric types Prometheus expects.
"""

from flask import Blueprint, Response

from ..auth import login_required
from ..database import session_scope
from ..models import Alert, Event, LogSource

bp = Blueprint("metrics", __name__)

# Simple in-process counters (reset on restart, like most exporters).
_counters = {
    "watchtail_events_ingested_total": 0,
    "watchtail_alerts_fired_total": 0,
    "watchtail_notifications_sent_total": 0,
    "watchtail_notifications_failed_total": 0,
}

METRIC_HELP = {
    "watchtail_events_ingested_total": "Events parsed and stored since start",
    "watchtail_alerts_fired_total": "Alerts fired by detectors since start",
    "watchtail_notifications_sent_total": "Notifier dispatches attempted since start",
    "watchtail_notifications_failed_total": "Notifier dispatches that raised since start",
}


def bump(metric: str, amount=1):
    """Increment a process counter (public for pipeline/notifiers)."""
    if metric in _counters:
        _counters[metric] += amount


def _db_gauges():
    from sqlalchemy import func

    import datetime as dt

    from ..models import IpStatus, utcnow

    day_ago = utcnow() - dt.timedelta(hours=24)
    gauges = {}
    with session_scope() as session:
        gauges["watchtail_events_24h"] = (
            session.query(func.count(Event.id)).filter(Event.ts >= day_ago).scalar() or 0
        )
        gauges["watchtail_alerts_24h"] = (
            session.query(func.count(Alert.id)).filter(Alert.ts >= day_ago).scalar() or 0
        )
        gauges["watchtail_tracked_ips"] = (
            session.query(func.count(IpStatus.ip)).scalar() or 0
        )
        gauges["watchtail_flagged_ips"] = (
            session.query(func.count(IpStatus.ip))
            .filter(IpStatus.status == "flagged")
            .scalar() or 0
        )
        gauges["watchtail_sources_total"] = (
            session.query(func.count(LogSource.id)).scalar() or 0
        )
        gauges["watchtail_sources_enabled"] = (
            session.query(func.count(LogSource.id))
            .filter(LogSource.enabled.is_(True))
            .scalar() or 0
        )
    return gauges


GAUGE_HELP = {
    "watchtail_events_24h": "Events stored in the last 24 hours",
    "watchtail_alerts_24h": "Alerts raised in the last 24 hours",
    "watchtail_tracked_ips": "IPs with review state",
    "watchtail_flagged_ips": "IPs currently flagged",
    "watchtail_sources_total": "Configured log sources",
    "watchtail_sources_enabled": "Enabled log sources",
}


@bp.get("/metrics")
@login_required
def metrics():
    lines = []
    for name, value in _counters.items():
        lines.append(f"# HELP {name} {METRIC_HELP[name]}")
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")
    try:
        gauges = _db_gauges()
    except Exception:
        gauges = {}
    for name, value in gauges.items():
        lines.append(f"# HELP {name} {GAUGE_HELP[name]}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain; version=0.0.4")
