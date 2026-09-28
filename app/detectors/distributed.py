"""Detection of low-and-slow attacks spread across many source IPs.

Per-IP rules see nothing when an attacker gives every attempt a
different address, so this detector looks the other way: many distinct
IPs failing against the *same account* (or any account) inside a
window is a coordinated credential-stuffing or brute force campaign.
"""

from .base import Detector, DetectorAlert


class DistributedAttackDetector(Detector):
    """Fires when an account is hit by too many distinct IPs."""

    name = "distributed_attack"
    interested_kinds = ("ssh_auth_fail", "win_logon_fail")
    default_severity = "high"

    def __init__(self, options):
        super().__init__(options)
        self.max_ips = int(options.get("max_ips", 5))
        self.window_seconds = int(options.get("window_seconds", 600))
        self.cooldown_seconds = int(options.get("cooldown_seconds", 300))
        # user -> list of (ts, ip) failures inside the window
        self._by_user: dict[str, list[tuple[float, str]]] = {}
        # user -> last alert timestamp (cooldown per target account)
        self._cooldowns: dict[str, float] = {}

    def _trim(self, stamps, now):
        return [
            (t, ip) for (t, ip) in stamps if now - t <= self.window_seconds
        ]

    def feed(self, record) -> list:
        user = record.meta.get("user") or "unknown"
        ip = record.ip
        if not ip:
            return []
        ts = record.ts.timestamp()

        stamps = self._trim(self._by_user.get(user, []), ts)
        stamps.append((ts, ip))
        self._by_user[user] = stamps

        # Cooldown: stay quiet for this account after firing once.
        last = self._cooldowns.get(user)
        if last is not None and ts - last < self.cooldown_seconds:
            return []

        distinct = {ip for _, ip in stamps}
        if len(distinct) < self.max_ips:
            return []

        self._cooldowns[user] = ts
        return [
            DetectorAlert(
                detector=self.name,
                # The campaign has no single source; attribute the alert
                # to the account so the flagged row reads sensibly.
                ip=f"user:{user}",
                severity=self.severity,
                message=(
                    f"{len(distinct)} distinct IPs attacked account "
                    f"{user!r} within {self.window_seconds}s"
                ),
                meta={
                    "user": user,
                    "distinct_ips": sorted(distinct),
                    "attempts": len(stamps),
                    "window_seconds": self.window_seconds,
                },
            )
        ]
