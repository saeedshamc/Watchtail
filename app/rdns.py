"""Reverse DNS (PTR) enrichment for flagged IPs.

Resolving a flagged address's hostname gives analysts the fastest
context hint (is it aws-ec2, a residential ISP, a mail relay?). The
socket module does all the work; results are cached in-process with a
TTL so repeated page views never hammer the resolver, and failures are
cached too so missing PTR records do not re-query every request.

Lookups run lazily and fail open: DNS problems must never break a
page render.
"""

import logging
import socket
import threading
import time

logger = logging.getLogger("watchtail")

CACHE_TTL_SECONDS = 900.0  # 15 minutes
CACHE_MAX_ENTRIES = 2048

_lock = threading.Lock()
_cache: dict[str, tuple[float, str | None]] = {}

_enabled = True


def configure(enabled: bool = True):
    """Enable or disable lookups (disabled by config, tests...)."""
    global _enabled
    _enabled = bool(enabled)


def clear_cache():
    with _lock:
        _cache.clear()


def _cache_get(ip: str) -> tuple[str | None, bool]:
    """Return (hostname, hit) from the cache, pruning stale entries."""
    now = time.monotonic()
    with _lock:
        entry = _cache.get(ip)
        if entry is None:
            return None, False
        stored_at, hostname = entry
        if now - stored_at > CACHE_TTL_SECONDS:
            _cache.pop(ip, None)
            return None, False
        return hostname, True


def _cache_put(ip: str, hostname: str | None):
    now = time.monotonic()
    with _lock:
        if len(_cache) >= CACHE_MAX_ENTRIES:
            # Cheap freshness sweep instead of an LRU: fine at this size.
            for key in [k for k, (stored, _) in _cache.items()
                        if now - stored > CACHE_TTL_SECONDS]:
                _cache.pop(key, None)
            if len(_cache) >= CACHE_MAX_ENTRIES:
                _cache.clear()
        _cache[ip] = (now, hostname)


def lookup(ip: str, timeout: float = 1.5) -> str | None:
    """Reverse-DNS a host; returns the hostname or None."""
    if not ip:
        return None
    if not _enabled:
        return None

    hostname, hit = _cache_get(ip)
    if hit:
        return hostname

    resolved: str | None = None
    try:
        socket.setdefaulttimeout(timeout)
        name, _aliases, _addresses = socket.gethostbyaddr(ip)
        resolved = name.rstrip(".") if name else None
    except (socket.herror, socket.gaierror, OSError):
        resolved = None
    except Exception:  # pragma: no cover - defensive
        resolved = None
    finally:
        socket.setdefaulttimeout(None)

    _cache_put(ip, resolved)
    return resolved
