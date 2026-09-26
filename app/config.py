"""Configuration loading for watchtail.yml.

Settings is a plain data object; nothing in the app reads YAML directly,
which keeps tests free of file fixtures unless they want them.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

DEFAULT_CONFIG_LOCATIONS = ("watchtail.yml", os.path.join("config", "watchtail.example.yml"))


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
    webhook_url: str = ""
    webhook_timeout_seconds: float = 5.0
    retention_max_age_days: int = 14
    config_dir: str = "."

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
    path = config_path
    if path is None:
        for candidate in DEFAULT_CONFIG_LOCATIONS:
            if os.path.exists(candidate):
                path = candidate
                break
    if path is None or not os.path.exists(path):
        return Settings()

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    settings = Settings(config_dir=os.path.dirname(os.path.abspath(path)))

    server = raw.get("server") or {}
    settings.host = str(server.get("host", settings.host))
    settings.port = int(server.get("port", settings.port))

    database = raw.get("database") or {}
    settings.database_url = str(database.get("url", settings.database_url))

    settings.sources = _parse_sources(raw.get("sources") or [], settings.config_dir)
    settings.detectors = dict(raw.get("detectors") or {})

    notifier = raw.get("notifier") or {}
    webhook = notifier.get("webhook") or {}
    settings.webhook_url = str(webhook.get("url") or "")
    settings.webhook_timeout_seconds = float(webhook.get("timeout_seconds", 5.0))

    retention = raw.get("retention") or {}
    settings.retention_max_age_days = int(retention.get("max_age_days", 14))

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
