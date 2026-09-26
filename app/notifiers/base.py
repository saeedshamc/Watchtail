"""Pluggable alert notifiers.

A notifier receives persisted :class:`Alert` rows. Dispatch is
fail-open on purpose: a broken webhook must never stop the tailer
loop or drop events, it can only lose its own notification.
"""

import logging

logger = logging.getLogger("watchtail")


class Notifier:
    """Base class for alert notifiers."""

    name = "base"

    def send(self, alert) -> None:
        raise NotImplementedError


class NotifierRegistry:
    """Fans alert rows out to every configured notifier."""

    def __init__(self, notifiers=None):
        self.notifiers = list(notifiers or [])

    def dispatch(self, alert) -> None:
        for notifier in self.notifiers:
            try:
                notifier.send(alert)
            except Exception:
                logger.exception(
                    "notifier %s failed for alert %s", notifier.name, alert.ip
                )
