"""Configuration loading for watchtail.yml.

Settings is a plain data object; nothing in the app reads YAML directly,
which keeps tests free of file fixtures unless they want them.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

DEFAULT_CONFIG_LOCATIONS = ("watchtail.yml", os.path.join("config", "watchtail.example.yml"))


def _resolve_config_path(config_path):
    """Explicit argument, then WATCHTAIL_CONFIG, then default spots."""
    if config_path:
        return config_path
    env_path = os.environ.get("WATCHTAIL_CONFIG")
    if env_path:
        return env_path
    for candidate in DEFAULT_CONFIG_LOCATIONS:
        if os.path.exists(candidate):
            return candidate
    return None


@dataclass
class SourceEntry:
    name: str
    type: str
    path: str
    enabled: bool = True


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 5555
    database_url: str = "sqlite:///data/watchtail.db"
    sources: list = field(default_factory=list)
    detectors: dict = field(default_factory=dict)
    custom_detectors: list = field(default_factory=list)
    webhook_url: str = ""
    webhook_timeout_seconds: float = 5.0
    webhook_min_severity: str = "low"
    email_config: dict = field(default_factory=dict)
    telegram_config: dict = field(default_factory=dict)
    digest_hour_utc: int = 7
    threatintel: dict = field(default_factory=dict)
    geoip_mmdb: str = ""
    playbooks: list = field(default_factory=list)
    retention_max_age_days: int = 14
    rate_limit: dict = field(default_factory=dict)
    config_dir: str = "."
    config_path: str = ""

    def detector(self, name: str) -> dict:
        return self.detectors.get(name, {})

    def detector_enabled(self, name: str) -> bool:
        return bool(self.detector(name).get("enabled", False))

    def detector_option(self, name: str, key: str, default: Any) -> Any:
        return self.detector(name).get(key, default)

    @property
    def flag_ttl_seconds(self) -> int:
        return int(self.detectors.get("flag_ttl_seconds", 900))


def load_config(config_path: Optional[str] = None) -> Settings:
    """Read the YAML config into a Settings object.

    Missing files fall back to the packaged example so the app always
    boots; unknown keys are ignored to keep forward compatibility.
    """
    path = _resolve_config_path(config_path)
    if path is None or not os.path.exists(path):
        return Settings()

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    settings = Settings(
        config_dir=os.path.dirname(os.path.abspath(path)),
        config_path=os.path.abspath(path),
    )

    server = raw.get("server") or {}
    settings.host = str(server.get("host", settings.host))
    settings.port = int(server.get("port", settings.port))

    database = raw.get("database") or {}
    settings.database_url = str(database.get("url", settings.database_url))

    settings.sources = _parse_sources(raw.get("sources") or [], settings.config_dir)
    settings.detectors = dict(raw.get("detectors") or {})
    settings.custom_detectors = [
        entry for entry in (raw.get("custom_detectors") or []) if isinstance(entry, dict)
    ]

    notifier = raw.get("notifier") or {}
    webhook = notifier.get("webhook") or {}
    settings.webhook_url = str(webhook.get("url") or "")
    settings.webhook_timeout_seconds = float(webhook.get("timeout_seconds", 5.0))
    settings.webhook_min_severity = str(webhook.get("min_severity", "low"))

    email = notifier.get("email") or {}
    settings.email_config = {
        "host": str(email.get("host") or ""),
        "port": int(email.get("port", 587)),
        "username": email.get("username"),
        "password": email.get("password"),
        "from": str(email.get("from") or "watchtail@localhost"),
        "to": [str(a) for a in (email.get("to") or [])],
        "use_tls": bool(email.get("use_tls", True)),
        "timeout_seconds": float(email.get("timeout_seconds", 10.0)),
        "min_severity": str(email.get("min_severity", "low")),
    }

    telegram = notifier.get("telegram") or {}
    settings.telegram_config = {
        "bot_token": str(telegram.get("bot_token") or ""),
        "chat_id": str(telegram.get("chat_id") or ""),
        "timeout_seconds": float(telegram.get("timeout_seconds", 8.0)),
        "min_severity": str(telegram.get("min_severity", "low")),
        "digest": bool(telegram.get("digest", False)),
    }
    settings.email_config["digest"] = bool(email.get("digest", False))
    settings.digest_hour_utc = int(notifier.get("digest_hour_utc", 7))

    retention = raw.get("retention") or {}
    settings.retention_max_age_days = int(retention.get("max_age_days", 14))

    rl = raw.get("rate_limit") or {}
    settings.rate_limit = {
        "enabled": bool(rl.get("enabled", True)),
        "max_requests": int(rl.get("max_requests", 300)),
        "window_seconds": float(rl.get("window_seconds", 60)),
        "exempt_prefixes": [str(p) for p in (rl.get("exempt_prefixes") or [])],
    }

    settings.threatintel = {
        "blocklists": list((raw.get("threat_intel") or {}).get("blocklists") or [])
    }

    settings.geoip_mmdb = str((raw.get("geoip") or {}).get("mmdb") or "")

    settings.playbooks = list(raw.get("playbooks") or [])

    return settings


def _parse_sources(entries, config_dir: str) -> list:
    sources = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if path and not os.path.isabs(path):
            path = os.path.normpath(os.path.join(config_dir, path))
        sources.append(
            SourceEntry(
                name=str(entry.get("name") or path or "log source"),
                type=str(entry.get("type") or "").lower(),
                path=path,
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return sources
