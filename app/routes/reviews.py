"""Review workflow for flagged IPs: list, mark reviewed, dismiss."""

from flask import Blueprint, flash, jsonify, redirect, request, url_for

from ..auth import admin_required, login_required
from ..database import session_scope
from ..models import IpStatus
from ..queries import active_flagged_ips

bp = Blueprint("reviews", __name__)

VALID_ACTIONS = {"reviewed", "dismissed", "flagged"}


@bp.get("/api/flagged")
@login_required
def flagged_api():
    settings = _settings()
    with session_scope() as session:
        rows = active_flagged_ips(session, settings)
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
                    "tags": list(row.tags or []),
                    "operator_note": row.operator_note,
                }
                for row in rows
            ]
        )


def _settings():
    from flask import current_app

    return current_app.config["WATCHTAIL_SETTINGS"]


@bp.post("/ips/<path:ip>/status")
@admin_required
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
