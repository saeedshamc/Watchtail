"""Cross-signal correlation: one IP showing several attack behaviours.

Single-purpose detectors each see half of a multipronged attack. This
rule watches the *other* detectors' outputs: when the same IP collects
alerts from ``min_signals`` distinct detectors inside a window, the
combination is more suspicious than any part — fire a composite alert.
"""

import threading

from .base import Detector, DetectorAlert


class CorrelationDetector(Detector):
    """Fires when one IP trips several distinct detectors in a window."""

    name = "correlation"
    # Not record-driven: the engine feeds it alerts explicitly.
    interested_kinds = ()

    def __init__(self, options):
        super().__init__(options)
        self.min_signals = int(options.get("min_signals", 2))
        self.window_seconds = int(options.get("window_seconds", 900))
        self.cooldown_seconds = int(options.get("cooldown_seconds", 900))
        self.severity_override = str(
            self.options.get("severity") or "critical"
        )
        # ip -> list of (ts, detector)
        self._signals: dict[str, list[tuple[float, str]]] = {}
        self._cooldown_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def observe_alert(self, ts: float, ip: str, detector: str) -> list:
        """Feed a fired alert from another detector into the correlator."""
        if not ip or detector == self.name:
            return []
        with self._lock:
            signals = [
                (t, d) for (t, d) in self._signals.get(ip, [])
                if ts - t <= self.window_seconds
            ]
            signals.append((ts, detector))
            self._signals[ip] = signals

            if ts < self._cooldown_until.get(ip, 0):
                return []
            distinct = {d for _, d in signals}
            if len(distinct) < self.min_signals:
                return []
            self._cooldown_until[ip] = ts + self.cooldown_seconds
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=ip,
                    severity=self.severity_override,
                    message=(
                        f"{len(distinct)} distinct detectors tripped for this IP "
                        f"within {self.window_seconds}s: {', '.join(sorted(distinct))}"
                    ),
                    meta={
                        "detectors": sorted(distinct),
                        "window_seconds": self.window_seconds,
                    },
                )
            ]
