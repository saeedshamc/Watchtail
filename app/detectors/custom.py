"""User-defined detectors driven entirely by YAML config.

A custom detector watches records whose fields match a list of
conditions (exact string, substring or regex) and fires when one IP
accumulates ``threshold`` matching records inside ``window_seconds``.
This lets operators add site-specific rules — probing for a certain
path, a burst of 5xx, spam from one user — without writing Python.

Example config block::

    custom_detectors:
      - name: wp_login_probe
        description: WordPress admin probing
        severity: high
        threshold: 10
        window_seconds: 300
        cooldown_seconds: 600
        conditions:
          - field: path
            value: /wp-login.php
            match: exact       # exact | contains | regex
          - field: status
            value: "404"
            match: exact

Condition fields may point at the parsed record fields (``path``,
``status``, ``method``, ``user_agent``, ``ip``) or into ``meta`` with
a dotted path (``meta.user``). Records without an IP are grouped under
the string ``no-ip`` so thresholds still work for logs without
addresses; such alerts carry no IP for scoring.
"""

import logging
import re

from .base import Detector, DetectorAlert

_NO_IP = "no-ip"


class Condition:
    """One field/value match rule."""

    def __init__(self, raw: dict):
        self.field = str(raw.get("field") or "").strip()
        self.value = raw.get("value")
        self.match = str(raw.get("match") or "exact").lower()
        if not self.field or self.value is None:
            raise ValueError("condition needs 'field' and 'value'")
        if self.match not in ("exact", "contains", "regex"):
            raise ValueError(f"unknown match type: {self.match}")
        self._compiled = re.compile(str(self.value)) if self.match == "regex" else None

    def _actual(self, record):
        current = record
        for part in self.field.split("."):
            if not hasattr(current, part) and not (
                isinstance(current, dict) and part in current
            ):
                return None
            current = (
                current.get(part)
                if isinstance(current, dict)
                else getattr(current, part)
            )
        return current

    def matches(self, record) -> bool:
        actual = self._actual(record)
        if actual is None:
            return False
        actual = str(actual)
        expected = str(self.value)
        if self.match == "exact":
            return actual == expected
        if self.match == "contains":
            return expected in actual
        return bool(self._compiled.search(actual))


class CustomDetector(Detector):
    """Threshold rule over records selected by field conditions."""

    interested_kinds = None  # see all kinds; conditions filter instead

    def __init__(self, options: dict):
        super().__init__(options)
        self.custom_name = str(options.get("name") or "").strip()
        if not self.custom_name:
            raise ValueError("custom detector needs a 'name'")
        self.description = str(options.get("description") or "").strip()
        self.threshold = max(1, int(options.get("threshold", 1)))
        self.window_seconds = max(1, int(options.get("window_seconds", 60)))
        self.cooldown_seconds = max(0, int(options.get("cooldown_seconds", self.window_seconds)))
        self.conditions = [Condition(c) for c in options.get("conditions") or []]
        if not self.conditions:
            raise ValueError(f"custom detector '{self.custom_name}' needs conditions")
        # name includes the custom name so suppression/scoring/attack_map
        # treat each rule as its own detector.
        self.name = f"custom:{self.custom_name}"
        self._events: dict[str, list[float]] = {}
        self._cooldown_until: dict[str, float] = {}
        self._latest = 0.0

    def feed(self, record) -> list:
        for condition in self.conditions:
            if not condition.matches(record):
                return []
        ip = record.ip or _NO_IP
        now = record.ts.timestamp()
        self._latest = max(self._latest, now)
        self._prune()
        stamps = self._events.setdefault(ip, [])
        stamps.append(now)
        window = [t for t in stamps if now - t <= self.window_seconds]
        self._events[ip] = window
        if len(window) >= self.threshold and now >= self._cooldown_until.get(ip, 0):
            self._cooldown_until[ip] = now + self.cooldown_seconds
            return [
                DetectorAlert(
                    detector=self.name,
                    ip=None if ip == _NO_IP else ip,
                    severity=self.severity,
                    message=self._message(record, len(window)),
                    meta={
                        "rule": self.custom_name,
                        "matches": len(window),
                        "window_seconds": self.window_seconds,
                    },
                )
            ]
        return []

    def _message(self, record, matches: int) -> str:
        label = self.description or self.custom_name
        where = record.ip or "records without an address"
        return (
            f"{label}: {matches} matching records from {where} "
            f"within {self.window_seconds}s"
        )

    def _prune(self):
        horizon = self._latest - max(self.window_seconds * 4, 3600)
        for key in list(self._events):
            self._events[key] = [t for t in self._events[key] if t >= horizon]
            if not self._events[key]:
                del self._events[key]


def build_custom_detectors(settings) -> list[CustomDetector]:
    """Instantiate every enabled custom rule from the settings."""
    detectors = []
    for options in getattr(settings, "custom_detectors", None) or []:
        if not isinstance(options, dict):
            continue
        if not options.get("enabled", True):
            continue
        try:
            detectors.append(CustomDetector(options))
        except Exception:
            logger_name = options.get("name") or "<unnamed>"
            logging.getLogger("watchtail").exception(
                "could not initialise custom detector %s", logger_name
            )
    return detectors
