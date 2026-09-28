"""Pluggable alert notifiers.

A notifier receives persisted :class:`Alert` rows. Dispatch is
fail-open on purpose: a broken webhook must never stop the tailer
loop or drop events, it can only lose its own notification.
"""

import logging

logger = logging.getLogger("watchtail")


SEVERITY_ORDER = ("low", "medium", "high", "critical")


def severity_at_least(severity, minimum):
    """True when ``severity`` ranks at or above ``minimum``."""
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return True  # unknown severities route everywhere, not nowhere


class Notifier:
    """Base class for alert notifiers."""

    name = "base"
    # Lowest severity this notifier should receive.
    min_severity = "low"

    def send(self, alert) -> None:
        raise NotImplementedError


class NotifierRegistry:
    """Fans alert rows out to configured notifiers with routing.

    Each notifier declares its ``min_severity``; an alert only reaches
    channels loud enough for it (a digest channel can ignore low noise,
    an on-call channel must not miss critical hits).
    """

    def __init__(self, notifiers=None):
        self.notifiers = list(notifiers or [])

    def dispatch(self, alert) -> None:
        for notifier in self.notifiers:
            if not severity_at_least(alert.severity, notifier.min_severity):
                continue
            try:
                notifier.send(alert)
            except Exception:
                logger.exception(
                    "notifier %s failed for alert %s", notifier.name, alert.ip
                )
