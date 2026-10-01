"""Slack notifier via incoming webhooks.

Uses Slack's classic incoming-webhook integration: one POST with a
Block Kit payload per alert. The webhook URL embeds the channel, so no
channel id is needed here.
"""

import logging

import requests

from .base import Notifier

logger = logging.getLogger("watchtail")

SEVERITY_COLOR = {
    "critical": "#cc0000",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
}


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, webhook_url, timeout_seconds=8.0):
        if not webhook_url:
            raise ValueError("slack notifier needs webhook_url")
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds

    def send(self, alert) -> None:
        color = SEVERITY_COLOR.get(alert.severity, "#f1c40f")
        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Watchtail: {alert.severity}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Detector*\n{alert.detector}",
                                },
                                {"type": "mrkdwn", "text": f"*Source IP*\n`{alert.ip}`"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": alert.message},
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"{alert.ts.isoformat()}Z",
                                }
                            ],
                        },
                    ],
                }
            ]
        }
        response = requests.post(
            self.webhook_url, json=payload, timeout=self.timeout_seconds
        )
        response.raise_for_status()
