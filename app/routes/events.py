"""Event browser: filtered list, JSON API and CSV export.

One query builder feeds the HTML page, ``/api/events`` and
``/events.csv`` so all three always agree on filtering semantics.
"""

import csv
import datetime as dt
import io

from flask import Blueprint, Response, current_app, render_template, request, url_for

from ..auth import login_required
from ..database import session_scope
from ..models import Event, utcnow

bp = Blueprint("events", __name__)

PAGE_SIZE = 200
MAX_LIMIT = 1000
MAX_HOURS = 24 * 31
STATUS_CLASSES = {
    "2xx": (200, 299),
    "3xx": (300, 399),
    "4xx": (400, 499),
    "5xx": (500, 599),
}


def _int_arg(name, default, minimum, maximum):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _carry_args(**extra):
    """Current filter arguments as a dict, optionally overridden.

    Used to build URLs that keep the active filters (pagination,
    CSV/JSON links) without leaking junk the user never set.
    """
    args = {}
    for name in ("kind", "ip", "status", "q"):
        value = (request.args.get(name) or "").strip()
        if value:
            args[name] = value
    hours = _int_arg("hours", 24, 1, MAX_HOURS)
    if hours != 24:
        args["hours"] = str(hours)
    args.update({key: str(value) for key, value in extra.items()})
    return args


def _filtered_events(session, limit, offset):
    """Events matching the current query string, newest first."""
    query = session.query(Event)

    kind = (request.args.get("kind") or "").strip()
    if kind:
        query = query.filter(Event.kind == kind)

    ip = (request.args.get("ip") or "").strip()
    if ip:
        query = query.filter(Event.ip == ip)

    status_class = (request.args.get("status") or "").strip()
    if status_class in STATUS_CLASSES:
        low, high = STATUS_CLASSES[status_class]
        query = query.filter(Event.status.between(low, high))

    text = (request.args.get("q") or "").strip()
    if text:
        like = f"%{text}%"
        query = query.filter(
            Event.raw.ilike(like)
            | Event.path.ilike(like)
            | Event.user_agent.ilike(like)
        )

    hours = _int_arg("hours", 24, 1, MAX_HOURS)
    query = query.filter(Event.ts >= utcnow() - dt.timedelta(hours=hours))

    return (
        query.order_by(Event.ts.desc(), Event.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def _event_dict(event):
    return {
        "ts": event.ts.isoformat() + "Z",
        "kind": event.kind,
        "ip": event.ip,
        "method": event.method,
        "path": event.path,
        "status": event.status,
        "bytes_sent": event.bytes_sent,
        "user_agent": event.user_agent,
        "meta": event.meta,
    }


def _csv_response(events):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ts", "kind", "ip", "method", "path", "status", "bytes_sent", "user_agent"]
    )
    for event in events:
        writer.writerow(
            [
                event.ts.isoformat() + "Z",
                event.kind,
                event.ip or "",
                event.method or "",
                event.path or "",
                event.status if event.status is not None else "",
                event.bytes_sent if event.bytes_sent is not None else "",
                event.user_agent or "",
            ]
        )
    stamp = utcnow().strftime("%Y%m%d-%H%M")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=watchtail-events-{stamp}.csv"},
    )


@bp.get("/events")
@login_required
def browse():
    settings = current_app.config["WATCHTAIL_SETTINGS"]
    limit = _int_arg("limit", PAGE_SIZE, 10, MAX_LIMIT)
    page = _int_arg("page", 1, 1, 100000)
    with session_scope() as session:
        events = _filtered_events(session, limit + 1, (page - 1) * limit)
        kinds = [row[0] for row in session.query(Event.kind).distinct().all()]
    has_more = len(events) > limit
    events = events[:limit]
    return render_template(
        "events.html",
        events=events,
        kinds=sorted(kinds),
        page=page,
        limit=limit,
        has_more=has_more,
        prev_url=url_for("events.browse", **_carry_args(page=page - 1, limit=limit))
        if page > 1
        else None,
        next_url=url_for("events.browse", **_carry_args(page=page + 1, limit=limit))
        if has_more
        else None,
        csv_url=url_for("events.events_csv", **_carry_args(limit=min(limit * 10, MAX_LIMIT))),
        api_url=url_for("events.events_api", **_carry_args(limit=limit)),
    )


@bp.get("/api/events")
@login_required
def events_api():
    limit = _int_arg("limit", PAGE_SIZE, 1, MAX_LIMIT)
    page = _int_arg("page", 1, 1, 100000)
    with session_scope() as session:
        events = _filtered_events(session, limit, (page - 1) * limit)
        return jsonify_events(events)


def jsonify_events(events):
    from flask import jsonify

    return jsonify([_event_dict(event) for event in events])


@bp.get("/events.csv")
@login_required
def events_csv():
    limit = _int_arg("limit", MAX_LIMIT, 1, MAX_LIMIT)
    with session_scope() as session:
        events = _filtered_events(session, limit, 0)
        return _csv_response(events)
