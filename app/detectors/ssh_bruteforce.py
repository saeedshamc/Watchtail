"""Brute force detection for SSH authentication failures."""

from .base import Detector, DetectorAlert


class SshBruteforceDetector(Detector):
    """Fires when one IP logs N failed attempts within a sliding window.

    All windowing and cooldowns run on event time (the timestamps of
    the records themselves), so behaviour is identical for live lines
    and for a backlog read after a restart.
    """

    name = "ssh_bruteforce"
    interested_kinds = ("ssh_auth_fail",)

    def __init__(self, options):
        super().__init__(options)
        self.max_failures = int(options.get("max_failures", 5))
        self.window_seconds = int(options.get("window_seconds", 300))
        self._failures: dict[str, list[float]] = {}
        self._cooldown_until: dict[str, float] = {}
        self._latest = 0.0

    def feed(self, record) -> list:
        ip = record.ip
        if not ip:
            return []
        now = record.ts.timestamp()
        self._latest = max(self._latest, now)
        self._prune()
        stamps = self._failures.setdefault(ip, [])
        stamps.append(now)

        window = [t for t in stamps if now - t <= self.window_seconds]
        self._failures[ip] = window

        if len(window) >= self.max_failures and now >= self._cooldown_until.get(ip, 0):
            # Cooldown stops one sustained attack from producing an
            # alert on every subsequent failure.
            self._cooldown_until[ip] = now + self.window_seconds
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity="high",
                    message=(
                        f"{len(window)} failed SSH logins within "
                        f"{self.window_seconds}s (user {record.meta.get('user', '?')})"
                    ),
                    meta={
                        "failures": len(window),
                        "window_seconds": self.window_seconds,
                        "user": record.meta.get("user"),
                        "port": record.meta.get("port"),
                    },
                )
            ]
        return []

    def _prune(self):
        horizon = self._latest - max(self.window_seconds * 4, 3600)
        for ip in list(self._failures):
            self._failures[ip] = [t for t in self._failures[ip] if t >= horizon]
            if not self._failures[ip]:
                del self._failures[ip]
