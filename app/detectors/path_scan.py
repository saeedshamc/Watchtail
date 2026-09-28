"""Detection of directory/content scanning.

A client that draws 404s for many *different* paths is mapping the
site even when each individual request stays under a rate threshold,
so this rule counts distinct targets rather than request volume.
"""

from .base import Detector, DetectorAlert


class PathScanDetector(Detector):
    """Fires when one IP probes N distinct paths within a window."""

    name = "path_scan"
    interested_kinds = ("http_access",)
    default_severity = "medium"

    def __init__(self, options):
        super().__init__(options)
        self.max_paths = int(options.get("max_paths", 30))
        self.window_seconds = int(options.get("window_seconds", 60))
        self.status_codes = {int(c) for c in options.get("status_codes", (404, 403))}
        # ip -> list of (timestamp, path) inside the window
        self._probes: dict[str, list[tuple[float, str]]] = {}
        self._cooldown_until: dict[str, float] = {}

    def feed(self, record) -> list:
        ip = record.ip
        if (
            not ip
            or record.status not in self.status_codes
            or not record.path
        ):
            return []

        ts = record.ts.timestamp()
        probes = self._probes.setdefault(ip, [])
        probes.append((ts, record.path))
        probes = [pair for pair in probes if ts - pair[0] <= self.window_seconds]
        self._probes[ip] = probes

        distinct = {path for _, path in probes}
        if len(distinct) >= self.max_paths and ts >= self._cooldown_until.get(ip, 0):
            self._cooldown_until[ip] = ts + self.window_seconds
            sample = ", ".join(sorted(distinct)[:5])
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity=self.severity,
                    message=(
                        f"{len(distinct)} distinct paths probed within "
                        f"{self.window_seconds}s (e.g. {sample})"
                    ),
                    meta={
                        "distinct_paths": len(distinct),
                        "window_seconds": self.window_seconds,
                        "sample_paths": sorted(distinct)[:10],
                    },
                )
            ]
        return []
