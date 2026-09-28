"""Detection of repeated 4xx responses from a single IP."""

from .base import Detector, DetectorAlert


class HttpErrorSpikeDetector(Detector):
    """Fires when one IP draws N error responses within a sliding window.

    Targets 403/404 by default: bursts of them usually mean content
    scanning or auth probing rather than a user who mistyped once.
    Windows run on event time (record timestamps).
    """

    name = "http_error_spike"
    interested_kinds = ("http_access",)
    default_severity = "medium"

    def __init__(self, options):
        super().__init__(options)
        self.max_errors = int(options.get("max_errors", 20))
        self.window_seconds = int(options.get("window_seconds", 60))
        self.status_codes = {int(c) for c in options.get("status_codes", (403, 404))}
        # ip -> list of (timestamp, status) inside the window
        self._hits: dict[str, list[tuple[float, int]]] = {}
        self._cooldown_until: dict[str, float] = {}

    def feed(self, record) -> list:
        ip = record.ip
        if not ip or record.status not in self.status_codes:
            return []

        ts = record.ts.timestamp()
        stamps = self._hits.setdefault(ip, [])
        stamps.append((ts, record.status))
        stamps = [pair for pair in stamps if ts - pair[0] <= self.window_seconds]
        self._hits[ip] = stamps

        if len(stamps) >= self.max_errors and ts >= self._cooldown_until.get(ip, 0):
            # Cooldown matches the SSH rule so a sustained scan does
            # not alert on every subsequent request.
            self._cooldown_until[ip] = ts + self.window_seconds
            counts: dict[int, int] = {}
            for _, status in stamps:
                counts[status] = counts.get(status, 0) + 1
            breakdown = ", ".join(f"{code} x{n}" for code, n in sorted(counts.items()))
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity=self.severity,
                    message=f"{len(stamps)} error responses within {self.window_seconds}s ({breakdown})",
                    meta={
                        "errors": len(stamps),
                        "window_seconds": self.window_seconds,
                        "status_counts": {str(c): n for c, n in sorted(counts.items())},
                        "last_path": record.path,
                    },
                )
            ]
        return []
