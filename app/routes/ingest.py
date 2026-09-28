"""Inbound webhook: receive alerts from other tools into watchtail.

External systems (n8n, Wazuh, custom scripts) POST JSON to
``/api/v1/ingest`` with a write-scoped bearer token; watchtail
persists the alert, flags the source IP and runs notifiers/playbooks
exactly as for internally detected threats. This turns watchtail into
a small aggregation point instead of a pure log watcher.
"""

from flask import Blueprint, current_app, jsonify, request

from ..api_auth import token_required
from ..database import session_scope
from ..models import Alert, IpStatus, utcnow
from ..scoring import apply_alert

bp = Blueprint("ingest", __name__)

SEVERITIES = ("low", "medium", "high", "critical")


def _clean(value, limit=200):
    if value is None:
        return None
    return str(value).strip()[:limit] or None


@bp.post("/api/v1/ingest")
@token_required(write=True)
def ingest():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="body must be a JSON object"), 400

    source_ip = _clean(payload.get("ip"), 64)
    message = _clean(payload.get("message"), 500)
    if not source_ip or not message:
        return jsonify(error="'ip' and 'message' are required"), 400

    detector = _clean(payload.get("detector"), 64) or "external"
    severity = _clean(payload.get("severity"), 16) or "medium"
    if severity not in SEVERITIES:
        severity = "medium"
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}

    row = Alert(
        detector=detector,
        ip=source_ip,
        severity=severity,
        message=message,
        meta=meta,
    )
    with session_scope() as session:
        session.add(row)
        session.flush()
        alert_id = row.id
        _flag(session, source_ip, detector, severity, message)

    return jsonify(
        id=alert_id,
        ip=source_ip,
        detector=detector,
        severity=severity,
        accepted=True,
    ), 201


def _flag(session, source_ip, detector, severity, message):
    """Mirror pipeline._mark_ip_flagged + scoring for external alerts."""
    row = session.get(IpStatus, source_ip)
    now = utcnow()
    if row is None:
        row = IpStatus(
            ip=source_ip,
            status="flagged",
            reason=f"[{detector}] {message}",
            alert_count=1,
            first_seen_at=now,
            last_alert_at=now,
        )
        session.add(row)
    elif row.status == "dismissed":
        return
    else:
        row.status = "flagged"
        row.alert_count += 1
        row.reason = f"[{detector}] {message}"
        row.last_alert_at = now
    apply_alert(session, source_ip, severity)
