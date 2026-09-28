"""Optional GeoIP enrichment for flagged IPs.

Uses a local MaxMind GeoLite2-Country mmdb when the operator provides
one (path in watchtail.yml). The reader loads lazily so the dependency
is only imported when actually configured, and lookups degrade to
``None`` on any problem — geo data must never break ingestion.
"""

import logging
import threading

logger = logging.getLogger("watchtail")

_reader = None
_reader_lock = threading.Lock()
_reader_path: str | None = None


def configure(mmdb_path: str | None):
    """Point the module at an mmdb file (or None to disable)."""
    global _reader, _reader_path
    with _reader_lock:
        if mmdb_path == _reader_path:
            return
        _reader = None
        _reader_path = mmdb_path


def _load():
    global _reader, _reader_path
    if not _reader_path:
        return None
    if _reader is not None:
        return _reader
    try:
        import geoip2.database

        _reader = geoip2.database.Reader(_reader_path)
        logger.info("geoip database loaded: %s", _reader_path)
    except ImportError:
        logger.warning(
            "geoip configured but geoip2 is not installed; run pip install geoip2"
        )
        _reader_path = None
    except Exception:
        logger.exception("could not open geoip database %s", _reader_path)
        _reader_path = None
    return _reader


def lookup(ip: str) -> dict | None:
    """Country/continent info for an address, or None when unavailable."""
    reader = _load()
    if reader is None or not ip:
        return None
    try:
        response = reader.country(ip)
        return {
            "country_code": response.country.iso_code,
            "country_name": response.country.name,
            "continent": response.continent.code,
        }
    except Exception:
        return None


def available() -> bool:
    """True when a geo database is configured and loadable."""
    return _reader_path is not None and _load() is not None
