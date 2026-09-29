"""Detection engine: routes records to detectors and collects alerts."""

import logging
import threading

from .base import Detector, DetectorAlert
from .custom import build_custom_detectors
from .burst import RequestBurstDetector
from .correlation import CorrelationDetector
from .distributed import DistributedAttackDetector
from .http_errors import HttpErrorSpikeDetector
from .path_scan import PathScanDetector
from .ssh_bruteforce import SshBruteforceDetector
from .ssh_compromise import SshCompromiseDetector

logger = logging.getLogger("watchtail")

DETECTOR_CLASSES = {
    SshBruteforceDetector.name: SshBruteforceDetector,
    HttpErrorSpikeDetector.name: HttpErrorSpikeDetector,
    RequestBurstDetector.name: RequestBurstDetector,
    SshCompromiseDetector.name: SshCompromiseDetector,
    PathScanDetector.name: PathScanDetector,
    DistributedAttackDetector.name: DistributedAttackDetector,
    CorrelationDetector.name: CorrelationDetector,
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
        for detector in build_custom_detectors(settings):
            self.detectors.append(detector)

    def feed(self, record) -> list:
        """Feed one record; returns alerts fired by this record."""
        if record is None:
            return []
        alerts: list[DetectorAlert] = []
        with self._lock:
            for detector in self.detectors:
                # interested_kinds None means "every kind": custom rules
                # filter on field conditions instead.
                kinds = detector.interested_kinds
                if kinds is not None and record.kind not in kinds:
                    continue
                try:
                    alerts.extend(detector.feed(record))
                except Exception:
                    logger.exception("detector %s failed on record", detector.name)
            # Correlation runs on the outputs of the other detectors,
            # not on raw records.
            correlator = self._find(CorrelationDetector)
            if correlator is not None:
                for alert in list(alerts):
                    try:
                        alerts.extend(
                            correlator.observe_alert(
                                record.ts.timestamp(), alert.ip, alert.detector
                            )
                        )
                    except Exception:
                        logger.exception("correlator failed")
        return alerts

    def _find(self, cls):
        for detector in self.detectors:
            if isinstance(detector, cls):
                return detector
        return None

    def detector_names(self) -> list[str]:
        return [d.name for d in self.detectors]
