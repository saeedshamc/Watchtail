"""Annotation routes: operator notes and tags for flagged IPs."""

from flask import Blueprint, flash, redirect, request, url_for

from ..auth import login_required
from ..database import session_scope
from ..models import IpStatus

bp = Blueprint("annotations", __name__)

MAX_NOTE_LENGTH = 2000
MAX_TAGS_PER_IP = 12


def _safe_redirect(ip, fallback):
    """Back to the referring page, but never to a 404-able detail URL."""
    referrer = request.referrer
    if referrer and referrer.startswith(request.host_url):
        return redirect(referrer)
    return redirect(fallback)


@bp.post("/ips/<path:ip>/annotate")
@login_required
def annotate(ip):
    note = (request.form.get("note") or "").strip()[:MAX_NOTE_LENGTH]
    raw_tags = (request.form.get("tags") or "").strip()

    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is None:
            # Redirecting to the (nonexistent) detail page would 404
            # before the flash is ever shown, so fall back to the
            # dashboard instead.
            flash(f"{ip} has no recorded alerts; nothing to annotate.")
            return _safe_redirect(ip, url_for("dashboard.dashboard"))
        row.operator_note = note or None
        tags = [part.strip() for part in raw_tags.split(",") if part.strip()]
        row.tags = []
        for tag in tags[:MAX_TAGS_PER_IP]:
            row.add_tag(tag)
        flash(f"Annotation saved for {ip}.")
    return _safe_redirect(ip, url_for("ip_detail.detail", ip=ip))


@bp.post("/ips/<path:ip>/tags/remove")
@login_required
def remove_tag(ip):
    tag = (request.form.get("tag") or "").strip()
    with session_scope() as session:
        row = session.get(IpStatus, ip)
        if row is not None and tag:
            row.remove_tag(tag)
    return _safe_redirect(ip, url_for("ip_detail.detail", ip=ip))
