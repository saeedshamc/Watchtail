"""Parser registry: source type name -> parser instance."""

from .apache import ApacheAccessParser
from .base import ParsedLine, Parser
from .nginx import NginxAccessParser

_REGISTRY = {
    "nginx": NginxAccessParser,
    "apache": ApacheAccessParser,
}


def get_parser(source_type: str) -> Parser | None:
    """Return a fresh parser for a source type, or None if unknown."""
    cls = _REGISTRY.get((source_type or "").lower())
    return cls() if cls else None


def known_types() -> list[str]:
    return sorted(_REGISTRY)
