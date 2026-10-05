"""Per-IP detail page: alerts and recent activity for one address."""

import datetime as dt

from flask import Blueprint, abort, render_template

from ..attack_map import for_detector
from ..auth import login_required
from ..database import session_scope
from ..models import Alert, Event, IpStatus, utcnow

bp = Blueprint("ip_detail", __name__)


@bp.get("/ips/<path:ip>")
@login_required
def detail(ip):
    day_ago = utcnow() - dt.timedelta(hours=24)
    with session_scope() as session:
        ip_row = session.get(IpStatus, ip)
        if ip_row is None:
            abort(404)
        alerts = (
            session.query(Alert)
            .filter(Alert.ip == ip)
            .order_by(Alert.ts.desc(), Alert.id.desc())
            .limit(100)
            .all()
        )
        events = (
            session.query(Event)
            .filter(Event.ip == ip, Event.ts >= day_ago)
            .order_by(Event.ts.desc(), Event.id.desc())
            .limit(100)
            .all()
        )
        # Detach values we need before the session closes.
        status = ip_row.status
        alert_count = ip_row.alert_count
        first_seen_at = ip_row.first_seen_at
        last_alert_at = ip_row.last_alert_at
        operator_note = ip_row.operator_note
        tags = list(ip_row.tags or [])

    geo = None
    if ":" not in ip:
        from .. import geoip

        if geoip.available():
            geo = geoip.lookup(ip)

    from .. import rdns

    hostname = rdns.lookup(ip)

    return render_template(
        "ip_detail.html",
        ip=ip,
        attack_map=type("M", (), {"for_detector": staticmethod(for_detector)}),
        ip_row={
            "status": status,
            "alert_count": alert_count,
            "first_seen_at": first_seen_at,
            "last_alert_at": last_alert_at,
            "operator_note": operator_note,
            "tags": tags,
            "geo": geo,
            "hostname": hostname,
        },
        alerts=alerts,
        events=events,
    )
