"""Threat scoring: one number per IP summarising how dangerous it is.

Every alert bumps the score by its severity weight; scores decay
towards zero over ``half_life_hours`` so an IP that behaved for a week
sinks back down while a persistent attacker climbs. The score is
persisted on IpStatus rows and recomputed lazily on read, which keeps
the hot ingest path free of extra work.
"""

import datetime as dt

from .models import IpStatus, utcnow

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 40,
    "critical": 100,
}

SCORE_LEVELS = (  # (upper bound, css class)
    (25, "low"),
    (75, "medium"),
    (200, "high"),
    (float("inf"), "critical"),
)

DEFAULT_HALF_LIFE_HOURS = 24.0


def bump_score(current: int, severity: str) -> int:
    """Score after one new alert of the given severity."""
    return current + SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["medium"])


def decayed_score(current: int, last_scored_at, half_life_hours=DEFAULT_HALF_LIFE_HOURS) -> int:
    """Score after exponential decay since it was last touched.

    A half-life of one day means yesterday's critical alert now counts
    as much as a medium one today; a clean week leaves almost nothing.
    """
    if current <= 0 or last_scored_at is None:
        return current
    elapsed_hours = max(
        0.0, (utcnow() - last_scored_at).total_seconds() / 3600.0
    )
    factor = 0.5 ** (elapsed_hours / max(half_life_hours, 0.1))
    return int(round(current * factor))


def score_for(row: IpStatus, half_life_hours=DEFAULT_HALF_LIFE_HOURS) -> int:
    """Freshly decayed score for an IpStatus row (does not write)."""
    return decayed_score(
        row.threat_score or 0, row.last_scored_at, half_life_hours
    )


def apply_alert(session, ip: str, severity: str, half_life_hours=DEFAULT_HALF_LIFE_HOURS):
    """Decay-then-bump the stored score for ``ip``.

    Must run inside the caller's session transaction; the row is
    fetched and updated with a fresh ``last_scored_at`` so consecutive
    alerts each decay only the elapsed real time.
    """
    row = session.get(IpStatus, ip)
    if row is None:
        return 0
    fresh = decayed_score(row.threat_score or 0, row.last_scored_at, half_life_hours)
    row.threat_score = bump_score(fresh, severity)
    row.last_scored_at = utcnow()
    return row.threat_score


def score_level(score: int) -> str:
    """CSS badge class for a score value."""
    for upper, level in SCORE_LEVELS:
        if score < upper:
            return level
    return "critical"
