"""REST API v1: machine-readable access to watchtail data.

Authentication accepts the dashboard session (for the browser) or an
``Authorization: Bearer`` token created on the tokens page. Read
endpoints need any live token; status-changing endpoints need
``can_write``.
"""

from flask import Blueprint, Response, jsonify, request

from ..api_auth import token_required
from ..database import session_scope
from ..models import Alert, Event, IpStatus
from ..queries import active_flagged_ips, top_risky_ips
from ..scoring import score_level
from ..tokens import create_token

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _serialize_ip(row):
    from .. import geoip

    return {
        "ip": row.ip,
        "status": row.status,
        "alert_count": row.alert_count,
        "reason": row.reason,
        "threat_score": row.threat_score or 0,
        "score_level": score_level(row.threat_score or 0),
        "tags": list(row.tags or []),
        "operator_note": row.operator_note,
        "geo": geoip.lookup(row.ip) if ":" not in row.ip and geoip.available() else None,
        "first_seen_at": row.first_seen_at.isoformat() + "Z" if row.first_seen_at else None,
        "last_alert_at": row.last_alert_at.isoformat() + "Z" if row.last_alert_at else None,
    }


def _serialize_alert(row):
    from ..attack_map import describe

    data = {
        "id": row.id,
        "ts": row.ts.isoformat() + "Z",
        "detector": row.detector,
        "ip": row.ip,
        "severity": row.severity,
        "message": row.message,
        "meta": row.meta or {},
    }
    attack = describe(row.detector)
    if attack:
        data["mitre"] = attack
    return data


@bp.get("/ips")
@token_required()
def list_flagged():
    from flask import current_app

    settings = current_app.config["WATCHTAIL_SETTINGS"]
    with session_scope() as session:
        rows = active_flagged_ips(session, settings, limit=100)
        return jsonify([_serialize_ip(row) for row in rows])


@bp.get("/ips/risky")
@token_required()
def list_risky():
    with session_scope() as session:
        rows = top_risky_ips(session, limit=20)
        return jsonify([_serialize_ip(row) for row in rows])


@bp.get("/ips/<path:ip>")
@token_required()
def get_ip(ip):
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is None:
            return jsonify(error="not found"), 404
        data = _serialize_ip(row)
        data["alerts"] = [
            _serialize_alert(alert)
            for alert in session.query(Alert)
            .filter(Alert.ip == ip)
            .order_by(Alert.ts.desc())
            .limit(25)
            .all()
        ]
        data["recent_events"] = [
            {
                "ts": event.ts.isoformat() + "Z",
                "kind": event.kind,
                "method": event.method,
                "path": event.path,
                "status": event.status,
            }
            for event in session.query(Event)
            .filter(Event.ip == ip)
            .order_by(Event.ts.desc())
            .limit(25)
            .all()
        ]
        return jsonify(data)


@bp.get("/alerts")
@token_required()
def list_alerts():
    try:
        limit = min(int(request.args.get("limit", 50) or 50), 500)
    except ValueError:
        limit = 50
    severity = request.args.get("severity")
    with session_scope() as session:
        query = session.query(Alert)
        if severity:
            query = query.filter(Alert.severity == severity)
        rows = query.order_by(Alert.ts.desc(), Alert.id.desc()).limit(limit).all()
        return jsonify([_serialize_alert(row) for row in rows])


@bp.get("/alerts/stix")
@token_required()
def export_stix():
    """Recent alerts as a STIX 2.1 bundle (application/stix+json)."""
    from ..exports import to_stix_bundle

    rows = _recent_alerts()
    response = jsonify(to_stix_bundle(rows))
    response.mimetype = "application/stix+json; version=2.1"
    return response


@bp.get("/alerts/cef")
@token_required()
def export_cef():
    """Recent alerts as ArcSight CEF lines (text/plain)."""
    from ..exports import to_cef_lines

    body = "\n".join(to_cef_lines(_recent_alerts()))
    return Response(body + ("\n" if body else ""), mimetype="text/plain")


def _recent_alerts():
    try:
        limit = min(int(request.args.get("limit", 100) or 100), 1000)
    except ValueError:
        limit = 100
    with session_scope() as session:
        return (
            session.query(Alert)
            .order_by(Alert.ts.desc(), Alert.id.desc())
            .limit(limit)
            .all()
        )


@bp.get("/stats")
@token_required()
def stats():
    from flask import current_app
    from sqlalchemy import func

    import datetime as dt

    from ..models import utcnow

    settings = current_app.config["WATCHTAIL_SETTINGS"]
    day_ago = utcnow() - dt.timedelta(hours=24)
    with session_scope() as session:
        return jsonify(
            {
                "events_24h": session.query(func.count(Event.id))
                .filter(Event.ts >= day_ago)
                .scalar(),
                "alerts_24h": session.query(func.count(Alert.id))
                .filter(Alert.ts >= day_ago)
                .scalar(),
                "flagged_now": len(active_flagged_ips(session, settings, limit=1000)),
            }
        )


@bp.post("/ips/<path:ip>/status")
@token_required(write=True)
def set_status(ip):
    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action") or request.form.get("action") or "").strip().lower()
    if action not in ("reviewed", "dismissed"):
        return jsonify(error="action must be 'reviewed' or 'dismissed'"), 400
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is None:
            return jsonify(error="not found"), 404
        row.status = action
        return jsonify(ip=ip, status=action)


@bp.post("/ips/<path:ip>/annotate")
@token_required(write=True)
def annotate(ip):
    payload = request.get_json(silent=True) or {}
    note = str(payload.get("note") or "").strip()[:2000]
    tags = [str(t).strip() for t in (payload.get("tags") or []) if str(t).strip()][:12]
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is None:
            return jsonify(error="not found"), 404
        row.operator_note = note or None
        row.tags = []
        for tag in tags:
            row.add_tag(tag)
        return jsonify(ip=ip, note=row.operator_note, tags=list(row.tags or []))


@bp.post("/tokens")
@token_required(write=True)
def mint_token():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "unnamed")[:80]
    can_write = bool(payload.get("can_write", False))
    plain, row = create_token(name, can_write=can_write)
    return jsonify(
        id=row.id,
        name=row.name,
        token=plain,  # shown exactly once
        can_write=row.can_write,
    ), 201


@bp.get("/openapi.json")
def openapi_json():
    """Machine-readable API description (no auth: spec only, no data)."""
    from ..openapi import API_SPEC

    return jsonify(API_SPEC)
