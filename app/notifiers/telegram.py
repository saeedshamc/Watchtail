"""Telegram notifier via the Bot API."""

import logging

import requests

from .base import Notifier

logger = logging.getLogger("watchtail")

SEVERITY_EMOJI = {
    "critical": "\U0001F6A8",  # rotating light
    "high": "\U0001F534",      # red circle
    "medium": "\U0001F7E0",    # orange circle
    "low": "\U0001F7E2",       # green circle
}


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(self, bot_token, chat_id, timeout_seconds=8.0):
        if not bot_token or not chat_id:
            raise ValueError("telegram notifier needs bot_token and chat_id")
        self.bot_token = bot_token
        self.chat_id = str(chat_id)
        self.timeout_seconds = timeout_seconds

    def send(self, alert) -> None:
        emoji = SEVERITY_EMOJI.get(alert.severity, "\U0001F7E0")
        text = (
            f"{emoji} *Watchtail {alert.severity}*\n"
            f"*{alert.detector}* from `{alert.ip}`\n"
            f"{alert.message}\n"
            f"_{alert.ts.isoformat()}Z_"
        )
        response = requests.post(
            f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
            json={
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
