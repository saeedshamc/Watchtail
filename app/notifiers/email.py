"""SMTP email notifier."""

import logging
import smtplib
from email.message import EmailMessage

from .base import Notifier

logger = logging.getLogger("watchtail")

SEVERITY_SUBJECT_PREFIX = {
    "critical": "[WATCHTAIL CRITICAL]",
    "high": "[WATCHTAIL HIGH]",
    "medium": "[WATCHTAIL]",
    "low": "[WATCHTAIL]",
}


class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, host, port, username, password, from_addr, to_addrs,
                 use_tls=True, timeout_seconds=10.0):
        if not host or not to_addrs:
            raise ValueError("email notifier needs host and recipients")
        self.host = host
        self.port = int(port or 587)
        self.username = username or None
        self.password = password or None
        self.from_addr = from_addr or "watchtail@localhost"
        self.to_addrs = list(to_addrs)
        self.use_tls = bool(use_tls)
        self.timeout_seconds = timeout_seconds

    def send(self, alert) -> None:
        message = EmailMessage()
        prefix = SEVERITY_SUBJECT_PREFIX.get(alert.severity, "[WATCHTAIL]")
        message["Subject"] = f"{prefix} {alert.detector} from {alert.ip}"
        message["From"] = self.from_addr
        message["To"] = ", ".join(self.to_addrs)
        body = [
            f"Detector : {alert.detector}",
            f"Severity : {alert.severity}",
            f"Source   : {alert.ip}",
            f"Time     : {alert.ts.isoformat()}Z",
            "",
            alert.message,
            "",
            "Manage at the Watchtail dashboard.",
        ]
        message.set_content("\n".join(body))

        with smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username and self.password:
                smtp.login(self.username, self.password)
            smtp.send_message(message)
