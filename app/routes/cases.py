"""Incident cases: operator-owned investigations bundling alerts.

A case groups related alerts under one investigation with a timeline
of notes, attached alerts and lifecycle changes. Cases give the
response workflow structure: instead of a flat alert feed, analysts
work through open cases and close them with a resolution note.
"""

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session as flask_session,
    url_for,
)
from sqlalchemy import func

from ..auth import admin_required, login_required
from ..database import session_scope
from ..models import Alert, Case, CaseEntry, utcnow

bp = Blueprint("cases", __name__)

SEVERITIES = ("low", "medium", "high", "critical")


def _actor() -> str:
    return flask_session.get("user") or "unknown"


def _add_entry(session, case_id, kind, author, body="", alert_id=None, ip=None):
    entry = CaseEntry(
        case_id=case_id, kind=kind, author=author, body=body,
        alert_id=alert_id, ip=ip,
    )
    session.add(entry)
    return entry


@bp.get("/cases")
@login_required
def index():
    status = (request.args.get("status") or "open").lower()
    with session_scope() as session:
        query = session.query(Case).order_by(Case.updated_at.desc())
        if status == "closed":
            query = query.filter(Case.status == "closed")
        elif status == "all":
            pass
        else:
            status = "open"
            query = query.filter(Case.status.in_(("open", "reopened")))
        cases = query.all()
        counts = {
            row[0]: row[1]
            for row in session.query(CaseEntry.case_id, func.count(CaseEntry.id))
            .group_by(CaseEntry.case_id)
            .all()
        }
        open_count = (
            session.query(func.count(Case.id))
            .filter(Case.status.in_(("open", "reopened")))
            .scalar()
            or 0
        )
    return render_template(
        "cases.html",
        cases=[(case, counts.get(case.id, 0)) for case in cases],
        status_filter=status,
        open_count=open_count,
    )


@bp.post("/cases/add")
@admin_required
def add():
    title = (request.form.get("title") or "").strip()[:200]
    description = (request.form.get("description") or "").strip()[:4000]
    severity = (request.form.get("severity") or "medium").strip().lower()
    if severity not in SEVERITIES:
        severity = "medium"
    if not title:
        flash("A case title is required.")
        return redirect(url_for("cases.index"))

    with session_scope() as session:
        case = Case(
            title=title,
            description=description,
            severity=severity,
            created_by=_actor(),
        )
        session.add(case)
        session.flush()
        _add_entry(
            session, case.id, "status", _actor(),
            body=f"case opened with severity {severity}",
        )
        case_id = case.id
    flash(f"Case #{case_id} opened.")
    return redirect(url_for("cases.detail", case_id=case_id))


@bp.get("/cases/<int:case_id>")
@login_required
def detail(case_id):
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None:
            flash("Case not found.")
            return redirect(url_for("cases.index"))
        entries = (
            session.query(CaseEntry)
            .filter(CaseEntry.case_id == case_id)
            .order_by(CaseEntry.ts.asc(), CaseEntry.id.asc())
            .all()
        )
        timeline = [
            {
                "kind": entry.kind,
                "author": entry.author,
                "body": entry.body,
                "ts": entry.ts,
                "alert_id": entry.alert_id,
                "ip": entry.ip,
            }
            for entry in entries
        ]
        title = case.title
        description = case.description
        status = case.status
        severity = case.severity
        created_by = case.created_by
        created_at = case.created_at
        closed_at = case.closed_at
    return render_template(
        "case_detail.html",
        case_id=case_id,
        title=title,
        description=description,
        status=status,
        severity=severity,
        created_by=created_by,
        created_at=created_at,
        closed_at=closed_at,
        timeline=timeline,
    )


@bp.post("/cases/<int:case_id>/attach")
@admin_required
def attach_alert(case_id):
    try:
        alert_id = int(request.form.get("alert_id") or 0)
    except ValueError:
        alert_id = 0

    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None:
            flash("Case not found.")
            return redirect(url_for("cases.index"))
        if not case.is_open():
            flash("Cannot attach alerts to a closed case.")
            return redirect(url_for("cases.detail", case_id=case_id))
        alert = session.get(Alert, alert_id)
        if alert is None:
            flash(f"Alert #{alert_id} not found.")
            return redirect(url_for("cases.detail", case_id=case_id))
        duplicate = (
            session.query(CaseEntry)
            .filter(
                CaseEntry.case_id == case_id,
                CaseEntry.kind == "alert",
                CaseEntry.alert_id == alert_id,
            )
            .first()
        )
        if duplicate is not None:
            flash(f"Alert #{alert_id} is already attached to this case.")
            return redirect(url_for("cases.detail", case_id=case_id))
        _add_entry(
            session, case_id, "alert", _actor(),
            body=alert.message or f"alert #{alert_id}",
            alert_id=alert_id, ip=alert.ip,
        )
        case.updated_at = utcnow()
    flash(f"Alert #{alert_id} attached to case #{case_id}.")
    return redirect(url_for("cases.detail", case_id=case_id))


@bp.post("/cases/<int:case_id>/note")
@admin_required
def add_note(case_id):
    body = (request.form.get("body") or "").strip()[:4000]
    if not body:
        flash("Note text is required.")
        return redirect(url_for("cases.detail", case_id=case_id))
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None:
            flash("Case not found.")
            return redirect(url_for("cases.index"))
        _add_entry(session, case_id, "note", _actor(), body=body)
        case.updated_at = utcnow()
    return redirect(url_for("cases.detail", case_id=case_id))


@bp.post("/cases/<int:case_id>/close")
@admin_required
def close(case_id):
    resolution = (request.form.get("resolution") or "").strip()[:4000]
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None:
            flash("Case not found.")
            return redirect(url_for("cases.index"))
        if not case.is_open():
            flash("Case is already closed.")
            return redirect(url_for("cases.detail", case_id=case_id))
        case.status = "closed"
        case.closed_at = utcnow()
        case.updated_at = utcnow()
        _add_entry(
            session, case_id, "status", _actor(),
            body=resolution or "case closed",
        )
    flash(f"Case #{case_id} closed.")
    return redirect(url_for("cases.detail", case_id=case_id))


@bp.post("/cases/<int:case_id>/reopen")
@admin_required
def reopen(case_id):
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None:
            flash("Case not found.")
            return redirect(url_for("cases.index"))
        if case.is_open():
            flash("Case is already open.")
            return redirect(url_for("cases.detail", case_id=case_id))
        case.status = "reopened"
        case.closed_at = None
        case.updated_at = utcnow()
        _add_entry(session, case_id, "status", _actor(), body="case reopened")
    flash(f"Case #{case_id} reopened.")
    return redirect(url_for("cases.detail", case_id=case_id))
