"""Detection of abnormal request bursts from a single IP."""

import time

from .base import Detector, DetectorAlert


class RequestBurstDetector(Detector):
    """Fires when one IP sends N requests of any kind within a window."""

    name = "request_burst"
    interested_kinds = ("http_access",)

    def __init__(self, options):
        super().__init__(options)
        self.max_requests = int(options.get("max_requests", 120))
        self.window_seconds = int(options.get("window_seconds", 60))
        self._hits: dict[str, list[float]] = {}
        self._cooldown_until: dict[str, float] = {}

    def feed(self, record) -> list:
        now = time.time()
        ip = record.ip
        if not ip:
            return []

        stamps = self._hits.setdefault(ip, [])
        stamps.append(record.ts.timestamp())
        stamps = [t for t in stamps if now - t <= self.window_seconds]
        self._hits[ip] = stamps

        if len(stamps) >= self.max_requests and now >= self._cooldown_until.get(ip, 0):
            self._cooldown_until[ip] = now + self.window_seconds
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity="medium",
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
