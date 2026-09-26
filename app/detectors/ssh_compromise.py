"""Detection of successful SSH logins following failed attempts.

A password attack that lands is far more urgent than one that does
not, so this rule pairs the brute force signal with the outcome: one
or more failed logins from an IP shortly before an accepted login from
the same IP is treated as a likely compromise.
"""

from .base import Detector, DetectorAlert


class SshCompromiseDetector(Detector):
    """Fires when an IP logs in successfully after recent failures."""

    name = "ssh_compromise"
    interested_kinds = ("ssh_auth_fail", "ssh_session_open")

    def __init__(self, options):
        super().__init__(options)
        self.min_failures = int(options.get("min_failures", 1))
        self.window_seconds = int(options.get("window_seconds", 600))
        # ip -> most recent failure timestamps (kept trimmed)
        self._failures: dict[str, list[float]] = {}

    def feed(self, record) -> list:
        ip = record.ip
        if not ip:
            return []
        ts = record.ts.timestamp()

        if record.kind == "ssh_auth_fail":
            stamps = self._failures.setdefault(ip, [])
            stamps.append(ts)
            return []

        stamps = [t for t in self._failures.get(ip, []) if ts - t <= self.window_seconds]
        self._failures[ip] = stamps

        if len(stamps) < self.min_failures:
            return []

        # One alert per (ip, login) event; the login itself stays the
        # evidence, so no cooldown bookkeeping is needed here.
        user = record.meta.get("user", "?")
        return [
            DetectorAlert(
                detector=self.name,
                ip=ip,
                severity="critical",
                message=(
                    f"successful SSH login for {user} after "
                    f"{len(stamps)} failed attempt(s) within "
                    f"{self.window_seconds}s"
                ),
                meta={
                    "user": user,
                    "port": record.meta.get("port"),
                    "recent_failures": len(stamps),
                    "window_seconds": self.window_seconds,
                },
            )
        ]
