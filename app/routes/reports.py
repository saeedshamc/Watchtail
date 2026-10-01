"""Reports: trends over alerts and events for the chosen window.

Two tables power the page: detector trends (how many alerts each
detector fired per day, with the worst offending IP) and source trends
(event volume per source per day plus its 4xx share). Alert day
buckets aggregate in SQL; events bucket in Python so the logic stays
portable across database backends.
"""

import datetime as dt

from flask import Blueprint, render_template, request
from sqlalchemy import func

from ..auth import login_required
from ..database import session_scope
from ..models import Alert, Event, LogSource, utcnow

bp = Blueprint("reports", __name__)

WINDOW_CHOICES = {"7": 7, "14": 14, "30": 30}


def _day_floor(ts: dt.datetime) -> dt.datetime:
    return ts.replace(hour=0, minute=0, second=0, microsecond=0)


def _day_list(days: int):
    today = _day_floor(utcnow())
    return [today - dt.timedelta(days=offset) for offset in range(days - 1, -1, -1)]


@bp.get("/reports")
@login_required
def reports():
    days = WINDOW_CHOICES.get(request.args.get("days") or "7", 7)
    day_list = _day_list(days)
    since = day_list[0]

    with session_scope() as session:
        alert_rows = (
            session.query(
                Alert.detector,
                func.strftime("%Y-%m-%d", Alert.ts).label("day"),
                func.count(Alert.id).label("count"),
            )
            .filter(Alert.ts >= since)
            .group_by(Alert.detector, "day")
            .all()
        )

        top_ip_rows = (
            session.query(Alert.detector, Alert.ip, func.count(Alert.id).label("count"))
            .filter(Alert.ts >= since)
            .group_by(Alert.detector, Alert.ip)
            .order_by(Alert.detector, func.count(Alert.id).desc())
            .all()
        )

        # Events bucket in Python: portable across backends and cheap
        # at dashboard scale.
        event_rows = (
            session.query(Event.source_id, Event.ts, Event.status)
            .filter(Event.ts >= since)
            .all()
        )
        sources = session.query(LogSource).order_by(LogSource.id).all()

    detector_days: dict[str, dict[str, int]] = {}
    for detector, day, count in alert_rows:
        detector_days.setdefault(detector, {})[str(day)] = count

    top_ips: dict[str, str] = {}
    for detector, ip, _count in top_ip_rows:
        if detector not in top_ips and ip:
            top_ips[detector] = ip

    source_days: dict[int | None, dict[str, list[int]]] = {}
    for source_id, ts, status in event_rows:
        day = str(_day_floor(ts).date())
        bucket = source_days.setdefault(source_id, {})
        counts = bucket.setdefault(day, [0, 0])
        counts[0] += 1
        if status is not None and 400 <= status < 500:
            counts[1] += 1

    day_labels = [d.date().isoformat() for d in day_list]

    detector_trends = []
    for detector in sorted(detector_days):
        series = [detector_days[detector].get(label, 0) for label in day_labels]
        detector_trends.append(
            {
                "detector": detector,
                "series": series,
                "total": sum(series),
                "top_ip": top_ips.get(detector),
            }
        )
    detector_trends.sort(key=lambda item: item["total"], reverse=True)

    source_trends = []
    for source in sources:
        bucket = source_days.get(source.id, {})
        series = [bucket.get(label, [0, 0]) for label in day_labels]
        total = sum(c[0] for c in series)
        errors = sum(c[1] for c in series)
        source_trends.append(
            {
                "source": source,
                "series": [c[0] for c in series],
                "total": total,
                "errors": errors,
                "error_pct": round(100 * errors / total, 1) if total else 0.0,
            }
        )
    unattributed = source_days.get(None, {})
    series = [unattributed.get(label, [0, 0]) for label in day_labels]
    total = sum(c[0] for c in series)
    errors = sum(c[1] for c in series)
    if total:
        source_trends.append(
            {
                "source": None,
                "series": [c[0] for c in series],
                "total": total,
                "errors": errors,
                "error_pct": round(100 * errors / total, 1),
            }
        )
    source_trends.sort(key=lambda item: item["total"], reverse=True)

    return render_template(
        "reports.html",
        days=days,
        day_labels=day_labels,
        detector_trends=detector_trends,
        source_trends=source_trends,
    )
