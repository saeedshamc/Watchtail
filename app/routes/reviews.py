"""Review workflow for flagged IPs: list, mark reviewed, dismiss."""

from flask import Blueprint, flash, jsonify, redirect, request, url_for

from ..database import session_scope
from ..models import IpStatus

bp = Blueprint("reviews", __name__)

VALID_ACTIONS = {"reviewed", "dismissed", "flagged"}


@bp.get("/api/flagged")
def flagged_api():
    with session_scope() as session:
        rows = (
            session.query(IpStatus)
            .filter(IpStatus.status != "dismissed")
            .order_by(IpStatus.last_alert_at.desc())
            .limit(100)
            .all()
        )
        return jsonify(
            [
                {
                    "ip": row.ip,
                    "status": row.status,
                    "alert_count": row.alert_count,
                    "reason": row.reason,
                    "last_alert_at": row.last_alert_at.isoformat() + "Z"
                    if row.last_alert_at
                    else None,
                }
                for row in rows
            ]
        )


@bp.post("/ips/<path:ip>/status")
def update_status(ip):
    action = (request.form.get("action") or "").strip().lower()
    if action not in VALID_ACTIONS:
        flash(f"Unknown action {action!r}.")
        return redirect(request.referrer or url_for("dashboard.dashboard"))

    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is None:
            flash(f"{ip} has no recorded alerts.")
        elif action == "flagged":
            flash("IPs are re-flagged automatically; use review instead.")
        else:
            row.status = action
            flash(
                f"{ip} marked as {action}."
                + (" It will not be flagged again." if action == "dismissed" else "")
            )
    return redirect(request.referrer or url_for("dashboard.dashboard"))
