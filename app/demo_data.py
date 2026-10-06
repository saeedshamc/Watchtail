"""Demo dataset generator for screenshots, demos and load checks.

``python -m app.cli demo-data`` seeds events, alerts, flagged IPs and
one open investigation case so a fresh install immediately shows a
living dashboard. The generator is deterministic for a given seed and
anchored to "now", so every demo starts with attacks inside the
dashboard's default 24-hour window.

Addresses come from the RFC 5737 documentation ranges (203.0.113.0/24,
198.51.100.0/24) so demo traffic can never collide with real hosts.
The generator writes rows directly and never touches the live tailing
workers; run it against a scratch database when in doubt.
"""

import datetime as dt
import random

from .database import session_scope
from .models import Alert, Case, CaseEntry, Event, IpStatus, utcnow

HTTP_PATHS = (
    "/", "/index.html", "/login", "/wp-login.php", "/admin",
    "/api/v1/items", "/api/v1/items/42", "/assets/app.js",
    "/.env", "/.git/config", "/phpmyadmin/", "/etc/passwd",
    "/robots.txt", "/favicon.ico", "/wp-content/uploads/2026/10/x.jpg",
)
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.5",
    "curl/8.9.1",
    "python-requests/2.32.3",
    "Go-http-client/2.0",
    "sqlmap/1.8",
)
SSH_USERS = ("root", "admin", "ubuntu", "test", "oracle", "git", "pi")


def _doc_ip(rng, subnet):
    return f"{subnet}.{rng.randint(1, 254)}"


def _http_event(rng, ip, ts):
    """One access-log style event; ~12% are 4xx noise."""
    path = rng.choice(HTTP_PATHS)
    unlucky = rng.random() < 0.12
    status = rng.choice((400, 401, 403, 404, 429)) if unlucky else 200
    return Event(
        ts=ts,
        ip=ip,
        kind="http_access",
        method=rng.choice(("GET", "GET", "GET", "POST")),
        path=path,
        status=status,
        bytes_sent=rng.randint(180, 42000),
        user_agent=rng.choice(USER_AGENTS),
        raw=f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" {status} 210',
        meta={},
    )


def _ssh_event(rng, ip, ts, kind):
    user = rng.choice(SSH_USERS)
    return Event(
        ts=ts,
        ip=ip,
        kind=kind,
        method=None,
        path=None,
        status=None,
        bytes_sent=None,
        user_agent=None,
        raw=f"{ts:%b %d %H:%M:%S} host sshd[4221]: Failed password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2",
        meta={"user": user},
    )


def _alert(rng, ip, ts, detector, severity, message):
    return Alert(
        ts=ts,
        detector=detector,
        ip=ip,
        severity=severity,
        message=message,
        meta={"demo": True},
    )


def _flag_ip(session, ip, reason, count, last_at, severity, first_at):
    """Create or refresh the flagged IpStatus row, score included."""
    from .scoring import apply_alert

    row = session.get(IpStatus, ip)
    if row is None:
        row = IpStatus(ip=ip, status="flagged", first_seen_at=first_at)
        session.add(row)
    elif row.status == "dismissed":
        row.status = "flagged"
    row.reason = reason
    row.alert_count = max(row.alert_count or 0, count)
    row.last_alert_at = last_at
    row.updated_at = utcnow()
    for _ in range(min(count, 6)):  # push the score up without huge loops
        apply_alert(session, ip, severity)
    return row


def seed_demo_data(
    hours=24,
    seed=1337,
    include_case=True,
    now=None,
):
    """Populate the database with a realistic demo dataset.

    Everything is derived from ``now`` (defaults to the real clock), so
    tests can pin the clock. Returns a dict of counts for the CLI to
    print. ``random.Random(seed)`` keeps the shape reproducible: the
    same seed always yields the same attack story.
    """
    rng = random.Random(seed)
    now = now or utcnow()
    start = now - dt.timedelta(hours=hours)
    counts = {"events": 0, "alerts": 0, "flagged": 0, "cases": 0}

    # Story: one brute-force campaign, one error-spike, one path scan,
    # plus steady legitimate-ish background traffic.
    brute_ip = _doc_ip(rng, "203.0.113")
    scanner_ip = _doc_ip(rng, "203.0.113")
    spike_ip = _doc_ip(rng, "198.51.100")
    background_ips = [_doc_ip(rng, "198.51.100") for _ in range(8)]

    events: list[Event] = []
    alerts: list[Alert] = []

    # Story beats sit at fixed fractions of the window so any --hours
    # value keeps every attack inside [start, now].
    def at(fraction):
        return start + dt.timedelta(hours=hours * fraction)

    # -- SSH brute force: 90 failures over ~20 minutes -----------------
    brute_start = at(0.08)
    for i in range(90):
        ts = brute_start + dt.timedelta(seconds=i * 14 + rng.randint(0, 4))
        events.append(_ssh_event(rng, brute_ip, ts, "ssh_auth_fail"))
    alerts.append(
        _alert(
            rng, brute_ip, brute_start + dt.timedelta(minutes=5),
            "ssh_bruteforce", "high",
            "90 failed SSH logins within 20 minutes",
        )
    )
    alerts.append(
        _alert(
            rng, brute_ip, brute_start + dt.timedelta(minutes=19),
            "correlation", "critical",
            "brute force followed by successful login (possible compromise)",
        )
    )

    # -- Path scan: 4xx spray across web paths --------------------------
    scan_start = at(0.2)
    for i in range(45):
        ts = scan_start + dt.timedelta(seconds=i * 9 + rng.randint(0, 3))
        row = _http_event(rng, scanner_ip, ts)
        row.status = rng.choice((403, 404, 400))
        row.path = rng.choice(("/.env", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/admin"))
        events.append(row)
    alerts.append(
        _alert(
            rng, scanner_ip, scan_start + dt.timedelta(minutes=3),
            "path_scan", "medium",
            "45 requests to sensitive paths in 8 minutes",
        )
    )

    # -- 4xx spike: one IP hammering a dead endpoint --------------------
    spike_start = at(0.37)
    for i in range(60):
        ts = spike_start + dt.timedelta(seconds=i * 5 + rng.randint(0, 2))
        row = _http_event(rng, spike_ip, ts)
        row.status = 404
        row.path = "/api/v1/items/999999"
        events.append(row)
    alerts.append(
        _alert(
            rng, spike_ip, spike_start + dt.timedelta(minutes=2),
            "http_error_spike", "medium",
            "60 consecutive 404 responses from one client",
        )
    )

    # -- Background traffic across the whole window ---------------------
    for _ in range(320):
        ts = start + dt.timedelta(
            seconds=rng.randint(0, hours * 3600)
        )
        ip = rng.choice(background_ips)
        events.append(_http_event(rng, ip, ts))

    events.sort(key=lambda e: e.ts)

    with session_scope() as session:
        session.add_all(events)
        session.flush()
        counts["events"] = len(events)
        session.add_all(alerts)
        counts["alerts"] = len(alerts)

        _flag_ip(
            session, brute_ip,
            "90 failed SSH logins within 20 minutes",
            90, alerts[1].ts, "critical", brute_start,
        )
        _flag_ip(
            session, scanner_ip,
            "45 requests to sensitive paths in 8 minutes",
            45, alerts[2].ts, "medium", scan_start,
        )
        _flag_ip(
            session, spike_ip,
            "60 consecutive 404 responses from one client",
            60, alerts[3].ts, "medium", spike_start,
        )
        counts["flagged"] = 3

        if include_case:
            case = Case(
                title="Demo: SSH brute-force campaign",
                description=(
                    "Generated demo case: repeated SSH failures from a "
                    "documentation-range address, later correlation alert "
                    "suggests a successful login. Investigate before closing."
                ),
                status="open",
                severity="critical",
                created_by="demo",
                created_at=alerts[1].ts,
                updated_at=alerts[1].ts,
            )
            session.add(case)
            session.flush()
            session.add_all(
                [
                    CaseEntry(
                        case_id=case.id, kind="alert",
                        author="demo", body="initial brute-force alert",
                        alert_id=alerts[0].id, ip=brute_ip,
                        ts=alerts[0].ts,
                    ),
                    CaseEntry(
                        case_id=case.id, kind="alert",
                        author="demo", body="correlation: login after failures",
                        alert_id=alerts[1].id, ip=brute_ip,
                        ts=alerts[1].ts,
                    ),
                    CaseEntry(
                        case_id=case.id, kind="note", author="demo",
                        body="demo timeline entry - credentials rotated as a precaution",
                        ts=alerts[1].ts + dt.timedelta(minutes=30),
                    ),
                ]
            )
            counts["cases"] = 1
    return counts


def run_demo_data(config_path=None, hours=24, seed=1337, no_case=False):
    """CLI entry point: configure the engine, seed, print a summary."""
    from . import resolve_database_url
    from .config import load_config
    from .database import configure_engine, create_all

    settings = load_config(config_path)
    configure_engine(resolve_database_url(settings))
    # A fresh install may never have started the server yet; demo-data
    # is the friendly first command, so make the schema itself.
    create_all()
    counts = seed_demo_data(
        hours=hours, seed=seed, include_case=not no_case,
    )
    print(
        "demo data seeded: {events} events, {alerts} alerts, "
        "{flagged} flagged IPs, {cases} case(s)".format(**counts)
    )
    print("log in to the dashboard to see it live")
    return 0
