"""Detection engine: routes records to detectors and collects alerts."""

import logging
import threading

from .base import Detector, DetectorAlert
from .ssh_bruteforce import SshBruteforceDetector

logger = logging.getLogger("watchtail")

DETECTOR_CLASSES = {
    SshBruteforceDetector.name: SshBruteforceDetector,
}


class DetectionEngine:
    """Owns configured detector instances and fans records out to them.

    One engine instance is shared by all tail workers; detectors keep
    their own per-IP state, so the engine serialises feeds with a lock.
    """

    def __init__(self, settings, on_alert=None):
        self.on_alert = on_alert
        self._lock = threading.Lock()
        self.detectors: list[Detector] = []
        for name, cls in DETECTOR_CLASSES.items():
            if not settings.detector_enabled(name):
                continue
            options = settings.detector(name)
            try:
                self.detectors.append(cls(options))
            except Exception:
                logger.exception("could not initialise detector %s", name)

    def feed(self, record) -> list:
        """Feed one record; returns alerts fired by this record."""
        if record is None:
            return []
        alerts: list[DetectorAlert] = []
        with self._lock:
            for detector in self.detectors:
                if record.kind not in detector.interested_kinds:
                    continue
                try:
                    alerts.extend(detector.feed(record))
                except Exception:
                    logger.exception("detector %s failed on record", detector.name)
        return alerts

    def detector_names(self) -> list[str]:
        return [d.name for d in self.detectors]
