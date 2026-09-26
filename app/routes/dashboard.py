"""Dashboard view: stats, chart series and the latest events."""

import datetime as dt

from flask import Blueprint, current_app, render_template
from sqlalchemy import func, select

from ..auth import login_required
from ..database import session_scope
from ..models import Alert, Event, IpStatus, LogSource, utcnow
from ..queries import active_flagged_ips, fresh_flagged_count

bp = Blueprint("dashboard", __name__)

CHART_MINUTES = 60


def _chart_series(session):
    """Bucket the last hour of events into per-minute request/4xx counts."""
    since = utcnow() - dt.timedelta(minutes=CHART_MINUTES)
    rows = session.execute(
        select(Event.ts, Event.status).where(Event.ts >= since)
    ).all()

    buckets = {}
    for ts, status in rows:
        minute = ts.replace(second=0, microsecond=0)
        counts = buckets.setdefault(minute, [0, 0])
        counts[0] += 1
        if status is not None and 400 <= status < 500:
            counts[1] += 1

    labels, traffic, errors = [], [], []
    now_minute = utcnow().replace(second=0, microsecond=0)
    for offset in range(CHART_MINUTES - 1, -1, -1):
        minute = now_minute - dt.timedelta(minutes=offset)
        counts = buckets.get(minute, [0, 0])
        labels.append(minute.strftime("%H:%M"))
        traffic.append(counts[0])
        errors.append(counts[1])
    return labels, traffic, errors


@bp.get("/")
@login_required
def dashboard():
    settings = current_app.config["WATCHTAIL_SETTINGS"]
    now = utcnow()
    day_ago = now - dt.timedelta(hours=24)

    with session_scope() as session:
        event_count = (
            session.query(func.count(Event.id)).filter(Event.ts >= day_ago).scalar()
        )
        alert_count = (
            session.query(func.count(Alert.id)).filter(Alert.ts >= day_ago).scalar()
        )
        flagged_count = fresh_flagged_count(session, settings)
        source_count = session.query(func.count(LogSource.id)).scalar()
        active_sources = (
            session.query(func.count(LogSource.id))
            .filter(LogSource.enabled.is_(True))
            .scalar()
        )
        recent_events = (
            session.query(Event).order_by(Event.ts.desc(), Event.id.desc()).limit(30).all()
        )
        flagged_ips = active_flagged_ips(session, settings, limit=20)
        labels, traffic, errors = _chart_series(session)

    stats = {
        "event_count": event_count or 0,
        "alert_count": alert_count or 0,
        "flagged_count": flagged_count or 0,
        "active_sources": active_sources or 0,
        "source_count": source_count or 0,
    }
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_events=recent_events,
        flagged_ips=flagged_ips,
        chart_labels=labels,
        chart_traffic=traffic,
        chart_errors=errors,
    )
