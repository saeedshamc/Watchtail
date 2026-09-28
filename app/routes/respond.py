"""Response routes: firewall suggestions for flagged IPs + audit trail."""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..auth import login_required
from ..database import session_scope
from ..models import IpStatus
from ..response import build_commands, recent_actions, record_action

bp = Blueprint("respond", __name__)


@bp.get("/respond")
@login_required
def index():
    ip = (request.args.get("ip") or "").strip()
    commands = build_commands(ip) if ip else []
    with session_scope() as session:
        row = session.get(IpStatus, ip) if ip else None
        status = row.status if row else None
        trail = recent_actions(session)
        trail_data = [
            {
                "ts": entry.ts,
                "actor": entry.actor,
                "action": entry.action,
                "target_ip": entry.target_ip,
                "platform": entry.platform,
                "command": entry.command,
                "detail": entry.detail,
            }
            for entry in trail
        ]
    return render_template(
        "respond.html",
        ip=ip,
        status=status,
        commands=commands,
        trail=trail_data,
    )


@bp.post("/respond/ack")
@login_required
def acknowledge():
    ip = (request.form.get("ip") or "").strip()
    platform = (request.form.get("platform") or "").strip() or None
    command = (request.form.get("command") or "").strip() or None
    if not ip:
        flash("No IP to acknowledge.")
        return redirect(url_for("respond.index"))
    from flask import session as flask_session

    with session_scope() as session:
        record_action(
            session,
            actor=flask_session.get("user") or "unknown",
            action="ack",
            ip=ip,
            platform=platform,
            command=command,
            detail="operator applied the suggested firewall command",
        )
    flash(f"Acknowledged block for {ip}.")
    return redirect(url_for("respond.index", ip=ip))
