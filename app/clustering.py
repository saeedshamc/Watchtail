"""Alert clustering: group related alerts into campaigns.

Raw alert lists are noisy: one brute-force campaign can fire dozens of
alerts across detectors. Clustering folds alerts into groups keyed by
source IP when they occur within a proximity window, giving the UI
(and future reports) a campaign-level view: which hosts, which
detectors, first/last seen and a severity rollup.
"""

import datetime as dt

from .models import utcnow

DEFAULT_PROXIMITY_SECONDS = 600


def cluster_alerts(alerts, proximity_seconds=DEFAULT_PROXIMITY_SECONDS):
    """Group alert rows (or dicts) into per-IP time-proximate clusters.

    ``alerts`` are objects exposing ``ip``, ``ts``, ``detector`` and
    ``severity`` (model rows qualify). Returns a list of cluster dicts
    sorted by most-recent activity:

        ip, first_ts, last_ts, detectors, severities, count,
        max_severity, ips (single except distributed sweeps)
    """
    proximity = max(int(proximity_seconds), 1)
    groups: dict[str, list] = {}
    for alert in alerts:
        ip = getattr(alert, "ip", None) or "?"
        groups.setdefault(ip, []).append(alert)

    clusters = []
    for ip, rows in groups.items():
        rows.sort(key=lambda row: getattr(row, "ts"))
        current: list = []
        for row in rows:
            if current:
                gap = (getattr(row, "ts") - getattr(current[-1], "ts")).total_seconds()
                if gap > proximity:
                    clusters.append(_build(ip, current))
                    current = []
            current.append(row)
        if current:
            clusters.append(_build(ip, current))

    clusters.sort(key=lambda c: c["last_ts"], reverse=True)
    return clusters


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(severities):
    ranked = [SEVERITY_RANK.get(severity, 0) for severity in severities]
    if not ranked:
        return "low"
    top = max(ranked)
    for name, rank in SEVERITY_RANK.items():
        if rank == top:
            return name
    return "low"


def _build(ip, rows):
    detectors = sorted({getattr(row, "detector") for row in rows})
    severities = [getattr(row, "severity") for row in rows]
    return {
        "ip": ip,
        "first_ts": getattr(rows[0], "ts"),
        "last_ts": getattr(rows[-1], "ts"),
        "detectors": detectors,
        "severities": sorted(set(severities)),
        "max_severity": _max_severity(severities),
        "count": len(rows),
    }
