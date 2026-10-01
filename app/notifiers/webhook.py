"""Webhook notifier: POSTs a JSON summary for every alert."""

import requests

from .base import Notifier


class WebhookNotifier(Notifier):
    name = "webhook"

    def __init__(self, url, timeout_seconds=5.0, min_severity="low"):
        if not url:
            raise ValueError("webhook url is empty")
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.min_severity = min_severity

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
    with a blank URL simply stays off. Each channel gets its own
    minimum severity from the config's ``min_severity`` key.
    """
    from .base import NotifierRegistry
    from .discord import DiscordNotifier
    from .email import EmailNotifier
    from .slack import SlackNotifier
    from .telegram import TelegramNotifier

    notifiers = []

    if settings.webhook_url:
        try:
            notifiers.append(
                WebhookNotifier(
                    settings.webhook_url,
                    settings.webhook_timeout_seconds,
                    min_severity=settings.webhook_min_severity,
                )
            )
        except ValueError:
            pass

    email = getattr(settings, "email_config", None) or {}
    if email.get("host") and email.get("to"):
        try:
            notifier = EmailNotifier(
                email.get("host"), email.get("port", 587),
                email.get("username"), email.get("password"),
                email.get("from"), email.get("to"),
                use_tls=email.get("use_tls", True),
                timeout_seconds=float(email.get("timeout_seconds", 10.0)),
            )
            notifier.min_severity = email.get("min_severity", "low")
            notifier.digest_enabled = bool(email.get("digest", False))
            notifiers.append(notifier)
        except ValueError:
            pass

    telegram = getattr(settings, "telegram_config", None) or {}
    if telegram.get("bot_token") and telegram.get("chat_id"):
        try:
            notifier = TelegramNotifier(
                telegram["bot_token"], telegram["chat_id"],
                timeout_seconds=float(telegram.get("timeout_seconds", 8.0)),
            )
            notifier.min_severity = telegram.get("min_severity", "low")
            notifier.digest_enabled = bool(telegram.get("digest", False))
            notifiers.append(notifier)
        except ValueError:
            pass

    for channel, cls, field_name in (
        ("slack", SlackNotifier, "slack_config"),
        ("discord", DiscordNotifier, "discord_config"),
    ):
        config = getattr(settings, field_name, None) or {}
        if config.get("webhook_url"):
            try:
                notifier = cls(
                    config["webhook_url"],
                    timeout_seconds=float(config.get("timeout_seconds", 8.0)),
                )
                notifier.min_severity = config.get("min_severity", "low")
                notifier.digest_enabled = bool(config.get("digest", False))
                notifiers.append(notifier)
            except ValueError:
                pass

    return NotifierRegistry(notifiers)
