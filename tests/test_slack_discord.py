"""Tests for Slack and Discord notifiers."""

import datetime as dt
from unittest.mock import MagicMock, patch

import pytest

import app as watchtail_app
from app.config import Settings
from app.database import dispose_engine
from app.notifiers.base import NotifierRegistry
from app.notifiers.discord import DiscordNotifier
from app.notifiers.slack import SlackNotifier
from app.notifiers.webhook import build_notifiers


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


def _alert(severity="high", ip="203.0.113.7"):
    from app.models import Alert

    return Alert(
        detector="ssh_bruteforce",
        ip=ip,
        severity=severity,
        message="5 failed logins",
        ts=dt.datetime(2026, 9, 28, 12, 0, 0),
    )


class TestSlack:
    def test_requires_webhook_url(self):
        with pytest.raises(ValueError):
            SlackNotifier("")

    @patch("app.notifiers.slack.requests.post")
    def test_sends_block_kit_payload(self, post):
        post.return_value = MagicMock(status_code=200)
        notifier = SlackNotifier("https://hooks.slack.com/services/T/B/xyz")
        notifier.send(_alert())
        args, kwargs = post.call_args
        assert args[0] == "https://hooks.slack.com/services/T/B/xyz"
        payload = kwargs["json"]
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#e67e22"  # high
        texts = []
        for block in attachment["blocks"]:
            if "text" in block:
                texts.append(block["text"]["text"])
            for field in block.get("fields", []):
                texts.append(field["text"])
        assert any("ssh_bruteforce" in t for t in texts)
        assert any("203.0.113.7" in t for t in texts)

    @patch("app.notifiers.slack.requests.post")
    def test_raises_on_http_error(self, post):
        post.return_value = MagicMock(status_code=500, raise_for_status=lambda: (_ for _ in ()).throw(RuntimeError))
        notifier = SlackNotifier("https://hooks.slack.com/services/T/B/xyz")
        with pytest.raises(RuntimeError):
            notifier.send(_alert())


class TestDiscord:
    def test_requires_webhook_url(self):
        with pytest.raises(ValueError):
            DiscordNotifier("")

    @patch("app.notifiers.discord.requests.post")
    def test_sends_embed_payload(self, post):
        post.return_value = MagicMock(status_code=204)
        notifier = DiscordNotifier("https://discord.com/api/webhooks/1/abc")
        notifier.send(_alert(severity="critical"))
        args, kwargs = post.call_args
        assert args[0] == "https://discord.com/api/webhooks/1/abc"
        embed = kwargs["json"]["embeds"][0]
        assert embed["color"] == 0xCC0000
        fields = {field["name"]: field["value"] for field in embed["fields"]}
        assert fields["Detector"] == "ssh_bruteforce"
        assert "203.0.113.7" in fields["Source IP"]

    @patch("app.notifiers.discord.requests.post")
    def test_unknown_severity_uses_default_color(self, post):
        post.return_value = MagicMock(status_code=204)
        notifier = DiscordNotifier("https://discord.com/api/webhooks/1/abc")
        notifier.send(_alert(severity="weird"))
        assert post.call_args.kwargs["json"]["embeds"][0]["color"] == 0xF1C40F


class TestRegistration:
    def test_build_notifiers_includes_slack_and_discord(self):
        settings = Settings()
        settings.slack_config = {
            "webhook_url": "https://hooks.slack.com/services/T/B/x",
            "min_severity": "high",
        }
        settings.discord_config = {
            "webhook_url": "https://discord.com/api/webhooks/1/y",
            "min_severity": "critical",
        }
        registry = build_notifiers(settings)
        assert isinstance(registry, NotifierRegistry)
        by_name = {n.name: n for n in registry.notifiers}
        assert set(by_name) == {"slack", "discord"}
        assert by_name["slack"].min_severity == "high"
        assert by_name["discord"].min_severity == "critical"

    def test_blank_urls_stay_disabled(self):
        settings = Settings()
        settings.slack_config = {"webhook_url": ""}
        settings.discord_config = {"webhook_url": ""}
        registry = build_notifiers(settings)
        assert registry.notifiers == []

    @patch("app.notifiers.slack.requests.post")
    def test_severity_routing_applies(self, post):
        post.return_value = MagicMock(status_code=200)
        settings = Settings()
        settings.slack_config = {
            "webhook_url": "https://hooks.slack.com/services/T/B/x",
            "min_severity": "critical",
        }
        registry = build_notifiers(settings)
        registry.dispatch(_alert(severity="medium"))
        post.assert_not_called()
        registry.dispatch(_alert(severity="critical"))
        post.assert_called_once()
