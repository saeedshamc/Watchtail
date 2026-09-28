"""Database models.

Timestamps are stored as naive UTC datetimes: SQLite drops timezone
information on storage anyway, and keeping one convention avoids
naive/aware comparison errors. Renderers label times as UTC.
"""

import datetime as dt

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    """Current UTC time as a naive datetime (see module docstring)."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class LogSource(Base):
    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), default="log source")
    type: Mapped[str] = mapped_column(String(20))  # nginx | apache | auth
    path: Mapped[str] = mapped_column(String(512), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    events: Mapped[list["Event"]] = relationship(back_populates="source")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<LogSource {self.type}:{self.path} enabled={self.enabled}>"


class Event(Base):
    """One parsed log line worth keeping.

    ``kind`` distinguishes record families: ``ssh_auth_fail``,
    ``ssh_session_open`` and ``http_access`` for now. HTTP-specific
    fields are null for auth events and vice versa.
    """

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_ip_ts", "ip", "ts"),
        Index("ix_events_kind_ts", "kind", "ts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("log_sources.id", ondelete="SET NULL"), nullable=True
    )
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    method: Mapped[str | None] = mapped_column(String(10))
    path: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    bytes_sent: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    source: Mapped[LogSource | None] = relationship(back_populates="events")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Event {self.kind} {self.ip} {self.ts:%Y-%m-%d %H:%M:%S}>"


class Alert(Base):
    """A detection-engine hit, e.g. brute force from one IP."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    detector: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    message: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Alert {self.detector} {self.ip} {self.ts:%Y-%m-%d %H:%M:%S}>"


class IpStatus(Base):
    """Review state for IPs that triggered at least one alert.

    Rows are created when an IP is flagged. ``status`` is one of
    ``flagged``, ``reviewed`` or ``dismissed``; dismissed IPs are never
    re-flagged by the engine. Operators can annotate rows with free-form
    tags and a note so investigations survive dashboard visits.
    """

    __tablename__ = "ip_status"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="flagged")
    reason: Mapped[str | None] = mapped_column(Text)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_alert_at: Mapped[dt.datetime | None] = mapped_column(DateTime)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    operator_note: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    last_scored_at: Mapped[dt.datetime | None] = mapped_column(DateTime)

    def add_tag(self, tag: str):
        """Add a tag once (case-insensitive, trimmed, max length guarded)."""
        tag = (tag or "").strip().lower()[:40]
        if tag and tag not in (self.tags or []):
            self.tags = list(self.tags or []) + [tag]

    def remove_tag(self, tag: str):
        tag = (tag or "").strip().lower()[:40]
        if tag in (self.tags or []):
            self.tags = [t for t in self.tags if t != tag]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IpStatus {self.ip} {self.status}>"


class AdminUser(Base):
    """Single dashboard account."""

    __tablename__ = "admin_users"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255))
