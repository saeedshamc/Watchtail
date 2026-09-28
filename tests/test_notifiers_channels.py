"""Tests for email/telegram notifiers and severity routing."""

import datetime as dt
from email.message import EmailMessage

import pytest

from app.config import Settings
from app.models import Alert
from app.notifiers.base import Notifier, NotifierRegistry, severity_at_least
from app.notifiers.email import EmailNotifier
from app.notifiers.telegram import TelegramNotifier
from app.notifiers.webhook import build_notifiers


class AlertRow:
    def __init__(self, severity="high"):
        self.detector = "ssh_bruteforce"
        self.ip = "203.0.113.44"
        self.severity = severity
        self.message = "5 failed logins"
        self.ts = dt.datetime(2026, 9, 26, 12, 0, 0)
        self.meta = {}


class RecordingSMTP:
    """Captures sent messages instead of touching the network."""

    sent = []

    def __init__(self, host, port, timeout=None):
        RecordingSMTP.host = host

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self):
        RecordingSMTP.tls = True

    def login(self, user, password):
        RecordingSMTP.login = (user, password)

    def send_message(self, message):
        RecordingSMTP.sent.append(message)


def test_severity_routing_order():
    assert severity_at_least("critical", "high")
    assert severity_at_least("high", "high")
    assert not severity_at_least("medium", "high")
    assert severity_at_least("unknown", "low")  # fail open


def test_registry_respects_min_severity():
    loud = Recording()
    loud.min_severity = "high"
    quiet_channel = Recording()
    quiet_channel.min_severity = "low"

    registry = NotifierRegistry([loud, quiet_channel])
    registry.dispatch(AlertRow(severity="medium"))

    assert loud.received == []          # below the on-call threshold
    assert quiet_channel.received       # digest channel gets everything


class Recording(Notifier):
    name = "recording"

    def __init__(self):
        self.received = []

    def send(self, alert):
        self.received.append(alert)


def test_email_notifier_builds_message(monkeypatch):
    RecordingSMTP.sent = []
    monkeypatch.setattr("app.notifiers.email.smtplib.SMTP", RecordingSMTP)

    notifier = EmailNotifier(
        "smtp.test", 587, "user", "pass", "wt@test",
        ["ops@test", "soc@test"],
    )
    notifier.send(AlertRow(severity="critical"))

    message = RecordingSMTP.sent[0]
    assert "[WATCHTAIL CRITICAL]" in message["Subject"]
    assert message["To"] == "ops@test, soc@test"
    body = message.get_content()
    assert "ssh_bruteforce" in body
    assert RecordingSMTP.login == ("user", "pass")


def test_email_notifier_requires_host_and_recipients():
    with pytest.raises(ValueError):
        EmailNotifier("", 587, None, None, None, [])


def test_telegram_payload(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse()

    monkeypatch.setattr("app.notifiers.telegram.requests.post", fake_post)

    notifier = TelegramNotifier("TOKEN", "-100123")
    notifier.send(AlertRow(severity="critical"))
    assert "botTOKEN/sendMessage" in captured["url"]
    assert captured["json"]["chat_id"] == "-100123"
    assert "critical" in captured["json"]["text"]
    assert "ssh_bruteforce" in captured["json"]["text"]


def test_telegram_requires_token_and_chat():
    with pytest.raises(ValueError):
        TelegramNotifier("", "")


def test_build_notifiers_includes_all_channels():
    settings = Settings()
    settings.webhook_url = "http://example.test/hook"
    settings.webhook_min_severity = "medium"
    settings.email_config = {
        "host": "smtp.test", "to": ["ops@test"], "min_severity": "high",
    }
    settings.telegram_config = {
        "bot_token": "T", "chat_id": "42", "min_severity": "critical",
    }
    registry = build_notifiers(settings)
    by_name = {n.name: n for n in registry.notifiers}
    assert set(by_name) == {"webhook", "email", "telegram"}
    assert by_name["webhook"].min_severity == "medium"
    assert by_name["email"].min_severity == "high"
    assert by_name["telegram"].min_severity == "critical"

    # A critical alert reaches everything; a low alert reaches nothing.
    registry.dispatch(AlertRow(severity="low"))
    registry.dispatch(AlertRow(severity="critical"))
