"""Parser registry: source type name -> parser instance."""

from .apache import ApacheAccessParser
from .auth import AuthLogParser
from .base import ParsedLine, Parser
from .jsonl import JsonLinesParser
from .nginx import NginxAccessParser
from .syslog import SyslogParser
from .syslog5424 import Syslog5424Parser
from .winlog import WinLogParser

_REGISTRY = {
    "nginx": NginxAccessParser,
    "apache": ApacheAccessParser,
    "auth": AuthLogParser,
    "syslog": SyslogParser,
    "syslog5424": Syslog5424Parser,
    "json": JsonLinesParser,
    "winlog": WinLogParser,
}


def get_parser(source_type: str) -> Parser | None:
    """Return a fresh parser for a source type, or None if unknown."""
    cls = _REGISTRY.get((source_type or "").lower())
    return cls() if cls else None


def known_types() -> list[str]:
    return sorted(_REGISTRY)
