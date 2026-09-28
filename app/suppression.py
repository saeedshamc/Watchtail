"""Alert suppression: temporary silences that expire on their own.

Suppression rules keep repeated, expected noise out of the alert
stream without touching detector configuration — a nightly deploy
triples 404s, a scanner host is allowed to probe, a flaky source is
being repaired. Every rule carries an ``expires_at`` so nothing stays
quiet forever by accident. Suppression hides *notifications and flag
state changes*; events are still persisted and searchable.
"""

import threading
from datetime import timedelta

from .models import utcnow


class SuppressionRule:
    """One active silence: scope + expiry + who made it."""

    def __init__(self, ip=None, detector=None, source_id=None,
                 minutes=60, note="", actor="system"):
        self.ip = ip            # None = any IP
        self.detector = detector
        self.source_id = source_id
        self.note = note
        self.actor = actor
        now = utcnow()
        self.created_at = now
        self.expires_at = now + timedelta(minutes=max(int(minutes), 1))

    def active(self, now=None) -> bool:
        now = now or utcnow()
        return now < self.expires_at

    def matches(self, ip=None, detector=None, source_id=None) -> bool:
        if self.ip is not None and ip != self.ip:
            return False
        if self.detector is not None and detector != self.detector:
            return False
        if self.source_id is not None and source_id != source_id:
            return False
        return True

    def describe(self) -> dict:
        return {
            "ip": self.ip,
            "detector": self.detector,
            "source_id": self.source_id,
            "note": self.note,
            "actor": self.actor,
            "created_at": self.created_at.isoformat() + "Z",
            "expires_at": self.expires_at.isoformat() + "Z",
        }


class SuppressionStore:
    """In-memory rule list; purge() drops expired entries."""

    def __init__(self):
        self._rules: list[SuppressionRule] = []
        self._lock = threading.Lock()

    def add(self, rule: SuppressionRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def purge(self, now=None) -> int:
        """Remove expired rules; returns how many were dropped."""
        now = now or utcnow()
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.active(now)]
            return before - len(self._rules)

    def is_suppressed(self, ip=None, detector=None, source_id=None, now=None) -> bool:
        now = now or utcnow()
        with self._lock:
            active = [r for r in self._rules if r.active(now)]
        return any(
            r.matches(ip=ip, detector=detector, source_id=source_id)
            for r in active
        )

    def active_rules(self, now=None) -> list[dict]:
        now = now or utcnow()
        with self._lock:
            return [
                r.describe() for r in self._rules if r.active(now)
            ]


_store: SuppressionStore | None = None
_lock = threading.Lock()


def get_store() -> SuppressionStore:
    global _store
    with _lock:
        if _store is None:
            _store = SuppressionStore()
        return _store


def reset_store():
    global _store
    with _lock:
        _store = None
