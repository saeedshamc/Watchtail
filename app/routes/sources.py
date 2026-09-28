"""Log source management: list, add, pause/resume and remove."""

import os

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..auth import admin_required, login_required
from ..database import session_scope
from ..manager import resync_tailing
from ..models import LogSource
from ..parsers import known_types

bp = Blueprint("sources", __name__)


@bp.get("/sources")
@login_required
def manage():
    with session_scope() as session:
        sources = session.query(LogSource).order_by(LogSource.id).all()
    return render_template(
        "sources.html", sources=sources, known_types=known_types()
    )


@bp.post("/sources/add")
@admin_required
def add():
    name = (request.form.get("name") or "").strip()
    source_type = (request.form.get("type") or "").strip().lower()
    path = (request.form.get("path") or "").strip()

    if not path:
        flash("A log path is required.")
        return redirect(url_for("sources.manage"))
    if source_type not in known_types():
        flash(f"Unknown source type {source_type!r}.")
        return redirect(url_for("sources.manage"))

    path = os.path.normpath(path)
    with session_scope() as session:
        existing = (
            session.query(LogSource).filter(LogSource.path == path).one_or_none()
        )
        if existing is not None:
            flash(f"A source for {path} already exists.")
            return redirect(url_for("sources.manage"))
        session.add(
            LogSource(
                name=name or f"{source_type} log",
                type=source_type,
                path=path,
                enabled=True,
            )
        )
    flash(f"Source {path} added.")
    resync_tailing()  # start tailing immediately, not on next restart
    return redirect(url_for("sources.manage"))


@bp.post("/sources/<int:source_id>/toggle")
@admin_required
def toggle(source_id):
    with session_scope() as session:
        source = session.get(LogSource, source_id)
        if source is not None:
            source.enabled = not source.enabled
            flash(
                f"Source {source.path} {'resumed' if source.enabled else 'paused'}."
            )
    resync_tailing()
    return redirect(url_for("sources.manage"))


@bp.post("/sources/<int:source_id>/delete")
@admin_required
def delete(source_id):
    with session_scope() as session:
        source = session.get(LogSource, source_id)
        if source is not None:
            path = source.path
            session.delete(source)
        flash(f"Source {path} removed.")
    resync_tailing()  # stop the worker for the removed path
    return redirect(url_for("sources.manage"))
