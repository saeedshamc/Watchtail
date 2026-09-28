"""Shared read queries for listings.

Kept in one place so the dashboard and the JSON API always agree on
which IPs are worth showing.
"""

import datetime as dt

from sqlalchemy import or_

from .models import IpStatus, utcnow
from .scoring import decayed_score


def _with_score(row):
    """Attach a freshly decayed score as a plain attribute."""
    row.current_score = decayed_score(row.threat_score or 0, row.last_scored_at)
    return row


def active_flagged_ips(session, settings, limit=100):
    """IPs to show in the review list.

    Flagged rows leave the list once ``flag_ttl_seconds`` have passed
    since their last alert — the alert history stays in the database,
    but the dashboard should not look like an attack is ongoing when it
    ended hours ago. Reviewed rows stay visible until dismissed; an
    operator put them there on purpose.
    """
    cutoff = utcnow() - dt.timedelta(seconds=settings.flag_ttl_seconds)
    return (
        session.query(IpStatus)
        .filter(IpStatus.status != "dismissed")
        .filter(
            or_(
                IpStatus.status != "flagged",
                IpStatus.last_alert_at >= cutoff,
                # Rows without a timestamp stay visible rather than
                # silently disappearing.
                IpStatus.last_alert_at.is_(None),
            )
        )
        .order_by(IpStatus.last_alert_at.desc().nullslast())
        .limit(limit)
        .all()
    )
    return [_with_score(row) for row in rows]


def top_risky_ips(session, limit=20):
    """Highest-scoring IPs regardless of review state, for the dashboard.

    A dismissed IP keeps its score history but is excluded: the
    operator closed that conversation on purpose.
    """
    rows = (
        session.query(IpStatus)
        .filter(IpStatus.status != "dismissed")
        .filter(IpStatus.threat_score > 0)
        .order_by(IpStatus.threat_score.desc())
        .limit(limit * 2)
        .all()
    )
    scored = [_with_score(row) for row in rows]
    scored.sort(key=lambda r: r.current_score, reverse=True)
    return scored[:limit]


def fresh_flagged_count(session, settings):
    """Number of IPs currently inside the flag TTL window."""
    cutoff = utcnow() - dt.timedelta(seconds=settings.flag_ttl_seconds)
    return (
        session.query(IpStatus)
        .filter(IpStatus.status == "flagged")
        .filter(IpStatus.last_alert_at >= cutoff)
        .count()
    )
