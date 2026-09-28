"""Detection of abnormal request bursts from a single IP."""

from .base import Detector, DetectorAlert


class RequestBurstDetector(Detector):
    """Fires when one IP sends N requests of any kind within a window.

    Windows run on event time (record timestamps), so replaying a
    backlog produces the same alerts as watching the lines live.
    """

    name = "request_burst"
    interested_kinds = ("http_access",)
    default_severity = "medium"

    def __init__(self, options):
        super().__init__(options)
        self.max_requests = int(options.get("max_requests", 120))
        self.window_seconds = int(options.get("window_seconds", 60))
        self._hits: dict[str, list[float]] = {}
        self._cooldown_until: dict[str, float] = {}

    def feed(self, record) -> list:
        ip = record.ip
        if not ip:
            return []

        ts = record.ts.timestamp()
        stamps = self._hits.setdefault(ip, [])
        stamps.append(ts)
        stamps = [t for t in stamps if ts - t <= self.window_seconds]
        self._hits[ip] = stamps

        if len(stamps) >= self.max_requests and ts >= self._cooldown_until.get(ip, 0):
            self._cooldown_until[ip] = ts + self.window_seconds
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity=self.severity,
                    message=(
                        f"{len(stamps)} requests within {self.window_seconds}s "
                        f"(last: {record.method} {record.path or '-'})"
                    ),
                    meta={
                        "requests": len(stamps),
                        "window_seconds": self.window_seconds,
                        "last_path": record.path,
                    },
                )
            ]
        return []
