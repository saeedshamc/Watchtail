"""Webhook notifier: POSTs a JSON summary for every alert."""

import requests

from .base import Notifier


class WebhookNotifier(Notifier):
    name = "webhook"

    def __init__(self, url, timeout_seconds=5.0):
        if not url:
            raise ValueError("webhook url is empty")
        self.url = url
        self.timeout_seconds = timeout_seconds

    def send(self, alert) -> None:
        payload = {
            "detector": alert.detector,
            "ip": alert.ip,
            "severity": alert.severity,
            "message": alert.message,
            "ts": alert.ts.isoformat() + "Z",
            "meta": alert.meta or {},
        }
        response = requests.post(
            self.url, json=payload, timeout=self.timeout_seconds
        )
        response.raise_for_status()


def build_notifiers(settings):
    """Create every notifier the settings enable.

    Returns an empty registry when nothing is configured; a webhook
    with a blank URL simply stays off.
    """
    from .base import NotifierRegistry

    notifiers = []
    url = settings.webhook_url
    if url:
        try:
            notifiers.append(
                WebhookNotifier(url, settings.webhook_timeout_seconds)
            )
        except ValueError:
            pass
    return NotifierRegistry(notifiers)
