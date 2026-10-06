"""Per-user display preferences: colour theme and timezone.

Both preferences live in the Flask session (a cookie), so they need no
schema changes and no server-side storage: each browser gets its own
theme and clock without affecting other viewers. Anything outside a
request context (tests, CLI, background threads) falls back to the
defaults -- dark theme, UTC.

Timestamps in the database are naive UTC. ``display_ts`` converts one
to the viewer's chosen fixed UTC offset for rendering, and
``tz_offset_label`` produces the label shown in table headers, e.g.
``time (UTC+03:30)``. Negative offsets are written without a plus sign,
so ``UTC-05:00`` is the canonical spelling for all non-zero offsets.
"""

import datetime as dt
import re

from flask import session

THEMES = ("dark", "light")
DEFAULT_THEME = "dark"

# Offsets in whole minutes; 0 is UTC itself. Fixed offsets only: the
# point is a predictable clock, not a tzdata dependency.
TZ_CHOICES_MINUTES = (
    -720,  # UTC-12:00 (Baker/Howland)
    -480,  # UTC-08:00
    -300,  # UTC-05:00
    -240,  # UTC-04:00
    0,     # UTC
    60,    # UTC+01:00
    180,   # UTC+03:00
    210,   # UTC+03:30 (Tehran)
    240,   # UTC+04:00
    300,   # UTC+05:00
    330,   # UTC+05:30 (India)
    420,   # UTC+07:00
    480,   # UTC+08:00
    540,   # UTC+09:00 (Japan)
    600,   # UTC+10:00
)
DEFAULT_TZ_MINUTES = 0

_OFFS = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def _in_session():
    try:
        session.get("lang")  # touch: raises outside a request context
        return True
    except RuntimeError:
        return False


def current_theme() -> str:
    if _in_session() and session.get("theme") in THEMES:
        return session["theme"]
    return DEFAULT_THEME


def set_theme(theme: str) -> None:
    if theme in THEMES:
        session["theme"] = theme


def _validated_offset(minutes) -> int | None:
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return None
    return minutes if minutes in TZ_CHOICES_MINUTES else None


def current_tz_minutes() -> int:
    if _in_session():
        return _validated_offset(session.get("tz")) or DEFAULT_TZ_MINUTES
    return DEFAULT_TZ_MINUTES


def set_tz_minutes(minutes) -> None:
    validated = _validated_offset(minutes)
    if validated is not None:
        session["tz"] = validated


def tz_offset_label(minutes: int | None = None) -> str:
    """Human label for the active offset, e.g. ``UTC+03:30``."""
    minutes = current_tz_minutes() if minutes is None else minutes
    if minutes == 0:
        return "UTC"
    sign = "+" if minutes > 0 else "-"
    minutes = abs(minutes)
    return f"UTC{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def tz_choices():
    """(value, label) pairs for the settings dropdown, UTC first."""
    return [(m, tz_offset_label(m)) for m in TZ_CHOICES_MINUTES]


def display_ts(value, fmt="%Y-%m-%d %H:%M:%S"):
    """Format a naive-UTC datetime in the viewer's timezone.

    Non-datetime values (None, ISO strings emitted by realtime code)
    pass through unchanged so templates never crash on a placeholder.
    """
    if not isinstance(value, dt.datetime):
        return value
    if value.tzinfo is not None:
        value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    offset = dt.timezone(dt.timedelta(minutes=current_tz_minutes()))
    return (value + offset.utcoffset(None)).strftime(fmt)


def parse_offset(value):
    """Parse ``UTC+03:30``/``+03:30``/``0330``-style text to minutes.

    Used for tests and CLI plumbing, not by the form routes (which pass
    whole minutes directly). Returns None for anything unparsable.
    """
    if isinstance(value, str):
        text = value.strip().lower().removeprefix("utc")
        match = _OFFS.match(text)
        if not match:
            return None
        sign, hours, mins = match.groups()
        minutes = int(hours) * 60 + int(mins)
        if minutes >= 24 * 60:
            return None
        return -minutes if sign == "-" else minutes
    return _validated_offset(value)
