"""Playbooks: small if/then automations for incoming alerts.

A playbook lives in watchtail.yml (or an included file) as a list of
rules::

    playbooks:
      - name: escalate known-bad
        when:
          detector: threat_intel
          min_severity: critical
        actions:
          - action: tag
            tags: [known-bad]
          - action: suppress
            minutes: 120
          - action: audit
            detail: auto-contained

Supported conditions: ``detector``, ``min_severity``, ``ip``, ``tag``.
Supported actions: ``tag`` (add tags to the IP), ``suppress`` (silence
matching alerts), ``audit`` (append to the response audit trail).
Deliberately no "block" action — watchtail suggests, humans pull the
trigger.
"""

import logging

from .models import utcnow
from .notifiers.base import severity_at_least
from .response import record_action
from .suppression import SuppressionRule, get_store as get_suppression_store

logger = logging.getLogger("watchtail")


class PlaybookRule:
    def __init__(self, name, when, actions):
        self.name = name or "unnamed"
        self.when = when or {}
        self.actions = [a for a in (actions or []) if isinstance(a, dict)]

    def matches(self, alert) -> bool:
        when = self.when
        if "detector" in when and alert.detector != when["detector"]:
            return False
        if "ip" in when and alert.ip != when["ip"]:
            return False
        if "min_severity" in when and not severity_at_least(
            alert.severity, when["min_severity"]
        ):
            return False
        return True


class PlaybookEngine:
    """Applies every matching rule to each fired alert row."""

    def __init__(self, rules=None):
        self.rules = [
            PlaybookRule(r.get("name"), r.get("when"), r.get("actions"))
            for r in (rules or [])
            if isinstance(r, dict)
        ]

    def process(self, alert_row, ip_row=None) -> list[str]:
        """Run matching playbooks; returns human-readable outcomes."""
        outcomes = []
        for rule in self.rules:
            if not rule.matches(alert_row):
                continue
            for spec in rule.actions:
                try:
                    outcome = self._apply(rule.name, spec, alert_row, ip_row)
                    if outcome:
                        outcomes.append(f"{rule.name}: {outcome}")
                except Exception:
                    logger.exception("playbook %s action failed", rule.name)
        return outcomes

    def _apply(self, rule_name, spec, alert_row, ip_row):
        action = spec.get("action")
        if action == "suppress":
            minutes = int(spec.get("minutes", 60))
            get_suppression_store().add(
                SuppressionRule(
                    ip=alert_row.ip,
                    detector=alert_row.detector,
                    minutes=minutes,
                    note=f"playbook {rule_name}",
                    actor="playbook",
                )
            )
            return f"suppressed {alert_row.detector} for {minutes}m"

        if action == "audit":
            from .database import session_scope

            with session_scope() as session:
                record_action(
                    session,
                    actor="playbook",
                    action="note",
                    ip=alert_row.ip,
                    detail=spec.get("detail") or f"playbook {rule_name} matched",
                )
            return "audit entry written"

        if action == "tag":
            if ip_row is None:
                return None
            tags = [str(t) for t in (spec.get("tags") or [])]
            for tag in tags:
                ip_row.add_tag(tag)
            return f"tagged {tags}"

        if action == "escalate":
            if ip_row is not None:
                ip_row.threat_score = (ip_row.threat_score or 0) + int(
                    spec.get("score", 50)
                )
                ip_row.last_scored_at = utcnow()
            return f"escalated score by {spec.get('score', 50)}"

        logger.warning("playbook %s: unknown action %r", rule_name, action)
        return None


_engine = None


def configure(rules):
    global _engine
    _engine = PlaybookEngine(rules)


def get_engine() -> PlaybookEngine:
    global _engine
    if _engine is None:
        _engine = PlaybookEngine()
    return _engine
