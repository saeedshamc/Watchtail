"""Tests for the notifier registry and webhook sender."""

import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.config import Settings
from app.models import Alert
from app.notifiers.base import Notifier, NotifierRegistry
from app.notifiers.webhook import WebhookNotifier, build_notifiers


class AlertRow:
    def __init__(self):
        self.detector = "ssh_bruteforce"
        self.ip = "203.0.113.44"
        self.severity = "high"
        self.message = "5 failed logins"
        self.ts = dt.datetime(2026, 9, 26, 12, 0, 0)
        self.meta = {"failures": 5}


class StubHandler(BaseHTTPRequestHandler):
    received = []
    status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        StubHandler.received.append(json.loads(body))
        self.send_response(StubHandler.status)
        self.end_headers()

    def log_message(self, *args):  # silence request logging
        pass


@pytest.fixture()
def stub_server():
    server = HTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    StubHandler.received = []
    StubHandler.status = 200
    yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    server.shutdown()


def test_webhook_posts_alert_json(stub_server):
    notifier = WebhookNotifier(stub_server)
    notifier.send(AlertRow())
    assert len(StubHandler.received) == 1
    payload = StubHandler.received[0]
    assert payload["ip"] == "203.0.113.44"
    assert payload["detector"] == "ssh_bruteforce"
    assert payload["meta"]["failures"] == 5
    assert payload["ts"].startswith("2026-09-26T12:00:00")


def test_registry_survives_failing_notifier():
    class Broken(Notifier):
        name = "broken"

        def send(self, alert):
            raise RuntimeError("network down")

    class Recording(Notifier):
        name = "recording"

        def send(self, alert):
            Recording.got = alert

    registry = NotifierRegistry([Broken(), Recording()])
    registry.dispatch(AlertRow())  # must not raise
    assert Recording.got.ip == "203.0.113.44"


def test_build_notifiers_from_settings():
    settings = Settings()
    settings.webhook_url = ""
    assert build_notifiers(settings).notifiers == []

    settings.webhook_url = "http://example.test/hook"
    registry = build_notifiers(settings)
    assert len(registry.notifiers) == 1
    assert registry.notifiers[0].url == "http://example.test/hook"


def test_server_error_raises_inside_send(stub_server):
    StubHandler.status = 500
    notifier = WebhookNotifier(stub_server)
    with pytest.raises(Exception):
        notifier.send(AlertRow())
    # The registry still treats it as non-fatal.
    NotifierRegistry([notifier]).dispatch(AlertRow())
