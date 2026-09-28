"""Routes for creating and viewing alert suppression windows."""

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..auth import admin_required, login_required
from ..suppression import SuppressionRule, get_store, reset_store

bp = Blueprint("suppressions", __name__)


@bp.get("/suppressions")
@login_required
def index():
    return render_template("suppressions.html", rules=get_store().active_rules())


@bp.post("/suppressions/add")
@admin_required
def add():
    ip = (request.form.get("ip") or "").strip() or None
    detector = (request.form.get("detector") or "").strip() or None
    try:
        minutes = max(int(request.form.get("minutes") or 60), 1)
    except ValueError:
        minutes = 60
    note = (request.form.get("note") or "").strip()[:200]

    if not ip and not detector:
        flash("Suppress at least an IP or a detector.")
        return redirect(url_for("suppressions.index"))

    from flask import session as flask_session

    get_store().add(
        SuppressionRule(
            ip=ip, detector=detector, minutes=minutes, note=note,
            actor=flask_session.get("user") or "unknown",
        )
    )
    flash(f"Suppression added for {minutes} minutes.")
    return redirect(url_for("suppressions.index"))


@bp.post("/suppressions/clear")
@admin_required
def clear():
    reset_store()
    flash("All suppressions cleared.")
    return redirect(url_for("suppressions.index"))
