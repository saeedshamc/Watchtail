"""Detector contract and alert record.

Detectors receive parsed records for the kinds they care about and
return :class:`DetectorAlert` objects when a rule fires. They are pure
in-memory objects: persistence and notification happen elsewhere.
"""

from dataclasses import dataclass, field


@dataclass
class DetectorAlert:
    detector: str
    ip: str
    severity: str
    message: str
    meta: dict = field(default_factory=dict)


class Detector:
    """Base class for detection rules."""

    name = "base"
    # Record kinds this detector wants to see.
    interested_kinds: tuple = ()
    # Overridable through the config's ``severity`` option.
    default_severity = "medium"

    def __init__(self, options: dict):
        self.options = options or {}
        self.severity = str(
            self.options.get("severity") or self.default_severity
        )

    def feed(self, record) -> list:
        """Process one record and return any alerts it triggered."""
        raise NotImplementedError
