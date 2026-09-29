"""Process-wide in-process sliding-window rate limiter.

A tiny, dependency-free middleware that protects the web UI and the API
from runaway clients. Requests are counted per client IP in a sliding
window; once the limit is hit the request is rejected with ``429`` and a
``Retry-After`` header telling the client when the window frees up.

The limiter is intentionally in-process: it needs no Redis or external
state, and restarts simply clear the buckets. Multi-worker deployments
(three separate processes behind gunicorn) therefore enforce the limit
per worker, which is the documented trade-off for zero infrastructure.

Limits come from the ``rate_limit`` section of the YAML config:

    rate_limit:
      enabled: true
      max_requests: 300
      window_seconds: 60

``/health`` and ``/metrics`` are exempt by default so uptime checks and
scrapers never trip the limit; extra prefixes can be exempted through
``exempt_prefixes``.
"""

import threading
import time
from collections import defaultdict, deque

from flask import jsonify, request

DEFAULT_MAX_REQUESTS = 300
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_EXEMPT_PREFIXES = ("/health", "/metrics")

# Prefixes always exempt regardless of config; these must stay reachable
# so load balancers and monitoring never see 429 from them.
_FORCED_EXEMPT_PREFIXES = ("/static",)

_lock = threading.Lock()
_hits = defaultdict(deque)  # client key -> deque[monotonic timestamps]
_last_hit = {}  # client key -> monotonic time of the last request


class RateLimiter:
    """Sliding-window counter per client key."""

    def __init__(self, max_requests=DEFAULT_MAX_REQUESTS, window_seconds=DEFAULT_WINDOW_SECONDS):
        self.max_requests = int(max_requests)
        self.window_seconds = float(window_seconds)
        self.enabled = True
        self.exempt_prefixes = tuple(_FORCED_EXEMPT_PREFIXES) + tuple(DEFAULT_EXEMPT_PREFIXES)

    def check(self, key, now=None):
        """Return ``(allowed, retry_after_seconds)`` for one request."""
        now = time.monotonic() if now is None else now
        window = self.window_seconds
        with _lock:
            bucket = _hits[key]
            cutoff = now - window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = max(1, int(window - (now - bucket[0])) + 1)
                _last_hit[key] = now
                return False, retry_after
            bucket.append(now)
            _last_hit[key] = now
            return True, 0

    def reset(self):
        """Drop all counters (used by tests and config reloads)."""
        with _lock:
            _hits.clear()
            _last_hit.clear()


# The single limiter instance reconfigured by install(); module-level so
# tests and the settings page can reach it without the app object.
limiter = RateLimiter()


def configure(settings):
    """Rebuild the limiter from a Settings object."""
    rl = getattr(settings, "rate_limit", None) or {}
    if not isinstance(rl, dict):
        rl = {}
    limiter.enabled = bool(rl.get("enabled", True))
    limiter.max_requests = int(rl.get("max_requests", DEFAULT_MAX_REQUESTS))
    limiter.window_seconds = float(rl.get("window_seconds", DEFAULT_WINDOW_SECONDS))
    limiter.exempt_prefixes = tuple(_FORCED_EXEMPT_PREFIXES) + tuple(DEFAULT_EXEMPT_PREFIXES) + tuple(
        str(p) for p in rl.get("exempt_prefixes") or []
    )
    limiter.reset()


def install(app):
    """Attach the before_request guard to an app."""
    configure(app.config.get("WATCHTAIL_SETTINGS"))

    @app.before_request
    def _enforce_rate_limit():
        if not limiter.enabled:
            return None
        path = request.path or "/"
        for prefix in limiter.exempt_prefixes:
            if prefix and path.startswith(prefix):
                return None
        key = client_key()
        allowed, retry_after = limiter.check(key)
        if allowed:
            return None
        response = jsonify(error="rate limit exceeded", retry_after=retry_after)
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    return limiter


def client_key():
    """Best-effort client identity for bucketing.

    Uses X-Forwarded-For when a proxy already set it, falling back to the
    remote address. API tokens get their own bucket per token id so one
    key cannot exhaust another.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return f"fwd:{forwarded.split(',')[0].strip()}"
    if request.blueprint == "api_v1" or request.path.startswith("/api/"):
        token_id = getattr(request, "watchtail_token_id", None)
        if token_id:
            return f"token:{token_id}"
    return f"ip:{request.remote_addr or 'unknown'}"
