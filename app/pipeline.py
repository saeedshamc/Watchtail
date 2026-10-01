"""Pipeline glue: tailer callbacks -> database -> detection -> notifier.

The pipeline is the only component that knows about every stage. It is
constructed by run.py (and by tests) with the settings, then handed to
a TailManager as the record callback.
"""

import datetime as dt
import logging

from .database import session_scope
from .detectors import DetectionEngine
from .models import Alert, Event, IpStatus
from .models import utcnow
from .scoring import apply_alert
from . import threatintel
from .anomaly import BaselineEngine
from .playbooks import get_engine as get_playbook_engine
from .suppression import get_store as get_suppression_store

logger = logging.getLogger("watchtail")


class Pipeline:
    def __init__(self, settings, notifier_registry=None, emit=None):
        """Create a pipeline.

        ``notifier_registry`` is an object with ``dispatch(alert_row)``
        (the NotifierRegistry from app.notifiers); ``emit`` is an async
        callback invoked with (event_dict, alerts) for live dashboards.
        The baseline engine learns normal traffic as a side effect of
        every ingested record.
        """
        self.settings = settings
        self.emit = emit
        self.engine = DetectionEngine(
            settings, on_alert=None,
        )
        self.notifiers = notifier_registry
        self.baseline = BaselineEngine()

    def handle_record(self, record, raw, source):
        """Process one parsed record from a tail worker."""
        if record is None:
            return

        event_row = self._persist_event(record, raw, source)
        # Baseline learning must see every record, even unparsed ones.
        self.baseline.observe(
            record.kind, record.ts, source.id if source is not None else None
        )
        alerts = self.engine.feed(record)
        # Known-bad addresses from local blocklists flag instantly,
        # before any behavioural threshold would catch them.
        if record.ip and not alerts:
            blocklist = threatintel.get_store().lookup(record.ip)
            if blocklist:
                from .detectors.base import DetectorAlert

                alerts = [
                    DetectorAlert(
                        detector="threat_intel",
                        ip=record.ip,
                        severity="critical",
                        message=f"activity from known-bad address (blocklist: {blocklist})",
                        meta={"blocklist": blocklist},
                    )
                ]
        alert_rows = [self._persist_alert(alert) for alert in alerts]

        # Suppression hides state changes and notifications, never the
        # raw events: the record of what happened stays searchable.
        suppression = get_suppression_store()
        flagged = False
        for row in alert_rows:
            if suppression.is_suppressed(ip=row.ip, detector=row.detector):
                logger.info(
                    "alert suppressed (%s from %s)", row.detector, row.ip
                )
                continue
            self._mark_ip_flagged(row)
            flagged = True
            # Playbooks run after the flag state is settled so their
            # tag/escalate actions see the current row.
            try:
                with session_scope() as session:
                    ip_row = session.get(IpStatus, row.ip)
                    outcomes = get_playbook_engine().process(row, ip_row)
                for outcome in outcomes:
                    logger.info("playbook: %s", outcome)
            except Exception:
                logger.exception("playbook processing failed")
            if self.notifiers is not None:
                self.notifiers.dispatch(row)

        if self.emit is not None and (event_row is not None or alert_rows):
            event_dict = self.event_to_dict(event_row) if event_row else None
            try:
                self.emit(event_dict, [self.alert_to_dict(a) for a in alert_rows])
            except Exception:
                logger.exception("live emit failed")

    # -- stages ------------------------------------------------------

    def _persist_event(self, record, raw, source):
        try:
            with session_scope() as session:
                row = Event(
                    source_id=source.id if source is not None else None,
                    ts=record.ts,
                    ip=record.ip,
                    kind=record.kind,
                    method=record.method,
                    path=record.path,
                    status=record.status,
                    bytes_sent=record.bytes_sent,
                    user_agent=record.user_agent,
                    raw=raw,
                    meta=record.meta,
                )
                session.add(row)
                session.flush()
                return row
        except Exception:
            logger.exception("could not persist event")
            return None

    def _persist_alert(self, alert) -> Alert | None:
        try:
            with session_scope() as session:
                row = Alert(
                    detector=alert.detector,
                    ip=alert.ip,
                    severity=alert.severity,
                    message=alert.message,
                    meta=alert.meta,
                )
                session.add(row)
                session.flush()
                return row
        except Exception:
            logger.exception("could not persist alert")
            return None

    def _mark_ip_flagged(self, alert_row):
        if alert_row is None:
            return
        try:
            with session_scope() as session:
                row = session.get(IpStatus, alert_row.ip)
                if row is None:
                    row = IpStatus(
                        ip=alert_row.ip,
                        status="flagged",
                        reason=alert_row.message,
                        alert_count=1,
                        first_seen_at=utcnow(),
                        last_alert_at=utcnow(),
                    )
                    session.add(row)
                elif row.status == "dismissed":
                    # Operators decided about this IP; do not re-flag.
                    return
                else:
                    row.status = "flagged"
                    row.alert_count += 1
                    row.reason = alert_row.message
                    row.last_alert_at = utcnow()
                # Score lives on the same row; decay-then-bump keeps
                # repeat offenders hot and quiet IPs cooling off.
                apply_alert(session, alert_row.ip, alert_row.severity)
        except Exception:
            logger.exception("could not flag ip %s", alert_row.ip)

    # -- helpers -----------------------------------------------------

    @staticmethod
    def event_to_dict(row: Event) -> dict:
        return {
            "id": row.id,
            "ts": row.ts.isoformat() + "Z",
            "source_id": row.source_id,
            "ip": row.ip,
            "kind": row.kind,
            "method": row.method,
            "path": row.path,
            "status": row.status,
            "bytes_sent": row.bytes_sent,
            "user_agent": row.user_agent,
        }

    @staticmethod
    def alert_to_dict(row: Alert) -> dict:
        return {
            "id": row.id,
            "ts": row.ts.isoformat() + "Z",
            "detector": row.detector,
            "ip": row.ip,
            "severity": row.severity,
            "message": row.message,
            "meta": row.meta or {},
        }


def prune_old_rows(settings):
    """Archive then delete rows older than the configured retention.

    When ``retention.archive_dir`` is set, expired rows are first
    written to a per-day gzipped NDJSON archive (events.jsonl.gz and
    alerts.jsonl.gz under an archive date directory) so history is
    never destroyed by the retention trim, only moved out of the hot
    database. Archive failures do not block the delete: retention must
    keep working even when the archive volume is full.
    """
    max_age_days = settings.retention_max_age_days
    if not max_age_days or max_age_days <= 0:
        return
    cutoff = utcnow() - dt.timedelta(days=max_age_days)
    try:
        with session_scope() as session:
            expired_events = session.query(Event).filter(Event.ts < cutoff).all()
            expired_alerts = session.query(Alert).filter(Alert.ts < cutoff).all()
            _archive_rows(settings, expired_events, expired_alerts)
            events = session.query(Event).filter(Event.ts < cutoff).delete(
                synchronize_session=False
            )
            alerts = session.query(Alert).filter(Alert.ts < cutoff).delete(
                synchronize_session=False
            )
        if events or alerts:
            logger.info(
                "retention trimmed %d events and %d alerts older than %d days",
                events, alerts, max_age_days,
            )
    except Exception:
        logger.exception("retention prune failed")


def _archive_rows(settings, events, alerts):
    """Append expired rows to per-day NDJSON.gz archives."""
    if not getattr(settings, "archive_dir", None):
        return
    if not events and not alerts:
        return

    def _event_dict(row):
        return {
            "id": row.id,
            "ts": row.ts.isoformat(),
            "source_id": row.source_id,
            "ip": row.ip,
            "kind": row.kind,
            "method": row.method,
            "path": row.path,
            "status": row.status,
            "bytes_sent": row.bytes_sent,
            "user_agent": row.user_agent,
            "raw": row.raw,
            "meta": row.meta or {},
        }

    def _alert_dict(row):
        return {
            "id": row.id,
            "ts": row.ts.isoformat(),
            "detector": row.detector,
            "ip": row.ip,
            "severity": row.severity,
            "message": row.message,
            "meta": row.meta or {},
        }

    by_kind = {}
    for row in events:
        by_kind.setdefault(("events", row.ts.date()), []).append(_event_dict(row))
    for row in alerts:
        by_kind.setdefault(("alerts", row.ts.date()), []).append(_alert_dict(row))

    import gzip
    import json
    import os

    base_dir = settings.archive_dir
    try:
        os.makedirs(base_dir, exist_ok=True)
    except OSError:
        logger.exception("could not create archive dir %s", base_dir)
        return

    for (kind, day), rows in by_kind.items():
        day_dir = os.path.join(base_dir, day.isoformat())
        try:
            os.makedirs(day_dir, exist_ok=True)
            archive_path = os.path.join(day_dir, f"{kind}.jsonl.gz")
            with open(archive_path, "ab") as raw:
                with gzip.GzipFile(fileobj=raw, mode="ab") as archive:
                    for row in rows:
                        archive.write(json.dumps(row).encode("utf-8") + b"\n")
            logger.info(
                "archived %d %s rows older than retention to %s",
                len(rows), kind, archive_path,
            )
        except OSError:
            logger.exception("could not archive %s rows for %s", kind, day)
