"""Discord notifier via webhook endpoints.

Discord webhooks accept a single POST with an ``embeds`` array; the
embed's colour bar mirrors the alert severity.
"""

import requests

from .base import Notifier

SEVERITY_COLOR = {
    "critical": 0xCC0000,
    "high": 0xE67E22,
    "medium": 0xF1C40F,
    "low": 0x2ECC71,
}


class DiscordNotifier(Notifier):
    name = "discord"

    def __init__(self, webhook_url, timeout_seconds=8.0):
        if not webhook_url:
            raise ValueError("discord notifier needs webhook_url")
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds

    def send(self, alert) -> None:
        color = SEVERITY_COLOR.get(alert.severity, 0xF1C40F)
        payload = {
            "username": "Watchtail",
            "embeds": [
                {
                    "title": f"Watchtail: {alert.severity}",
                    "description": alert.message,
                    "color": color,
                    "fields": [
                        {"name": "Detector", "value": alert.detector, "inline": True},
                        {"name": "Source IP", "value": f"`{alert.ip}`", "inline": True},
                    ],
                    "footer": {"text": f"{alert.ts.isoformat()}Z"},
                }
            ],
        }
        response = requests.post(
            self.webhook_url, json=payload, timeout=self.timeout_seconds
        )
        response.raise_for_status()
