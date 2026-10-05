"""Threat-intel export formats for alerts.

Two formats cover the common SIEM/TIP handoffs:

* **STIX 2.1** (``to_stix_bundle``): a bundle of indicator-like
  observed-data objects — one STIX "sighting-ish" custom object per
  alert plus relationships is overkill for most SIEMs, so we emit one
  ``observed-data`` per alert with a custom ``x_watchtail`` extension
  holding detector/severity/message. Timestamps are RFC 3339 with an
  explicit Z suffix; UUIDv5 ids are deterministic per alert id so
  re-exporting the same alert yields the same object id.
* **CEF** (``to_cef_lines``): ArcSight Common Event Format lines
  (``CEF:0|Vendor|Product|Version|Signature|Name|Severity|Extension``).
  CEF escapes pipes and backslashes in extension values; severity maps
  to the 0-10 scale.

Both functions take plain rows (model instances or dicts with the same
attribute names) so the API routes stay thin.
"""

import datetime as dt
import uuid

CEF_SEVERITY = {"low": 2, "medium": 5, "high": 7, "critical": 10}
STIX_SEVERITY = {"low": 1, "medium": 3, "high": 5, "critical": 8}

VENDOR = "Watchtail"
PRODUCT = "Watchtail"
VERSION = "1.0"

_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL ns


def _alert_ts(alert) -> dt.datetime:
    ts = getattr(alert, "ts")
    if ts.tzinfo is None:
        return ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc)


def _rfc3339(ts: dt.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stix_id(alert) -> str:
    """Deterministic UUIDv5 per alert id (stable across re-exports)."""
    return str(uuid.uuid5(_NAMESPACE, f"watchtail-alert-{getattr(alert, 'id')}"))


def to_stix_bundle(alerts) -> dict:
    """Build a STIX 2.1 bundle with one observed-data object per alert."""
    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "name": VENDOR,
            "identity_class": "organization",
        }
    ]
    for alert in alerts:
        ts = _alert_ts(alert)
        created = _rfc3339(ts)
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{_stix_id(alert)}",
                "created": created,
                "modified": created,
                "created_by_ref": "identity--6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "first_observed": created,
                "last_observed": created,
                "number_observed": 1,
                "object_refs": [f"x-watchtail-alert--{_stix_id(alert)}"],
            }
        )
        objects.append(
            {
                "type": "x-watchtail-alert",
                "spec_version": "2.1",
                "id": f"x-watchtail-alert--{_stix_id(alert)}",
                "created": created,
                "modified": created,
                "detector": getattr(alert, "detector", ""),
                "severity": getattr(alert, "severity", "low"),
                "message": getattr(alert, "message", ""),
                "source_ip": getattr(alert, "ip", None),
                "meta": getattr(alert, "meta", None) or {},
            }
        )
    # Bundle id derives from the exported alert ids so identical alert
    # sets produce identical bundles (dedup-friendly for TIPs).
    alert_ids = sorted(str(getattr(alert, "id", "")) for alert in alerts)
    seed = "watchtail-bundle-" + ",".join(alert_ids)
    return {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid5(_NAMESPACE, seed))}",
        "objects": objects,
    }


def _cef_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def to_cef_lines(alerts) -> list[str]:
    """Render alerts as ArcSight CEF lines."""
    lines = []
    for alert in alerts:
        ts = _alert_ts(alert)
        epoch_ms = int(ts.timestamp() * 1000)
        severity = CEF_SEVERITY.get(getattr(alert, "severity", ""), 5)
        # Header fields may not contain raw pipes; _cef_escape already
        # renders them as \| which is what CEF parsers expect.
        name = _cef_escape(
            f"{getattr(alert, 'detector', 'unknown')}: "
            f"{getattr(alert, 'message', '')}"
        )
        signature = _cef_escape(getattr(alert, "detector", "unknown"))
        extension = (
            f"src={_cef_escape(getattr(alert, 'ip', '') or '')} "
            f"msg={_cef_escape(getattr(alert, 'message', ''))} "
            f"cs1={_cef_escape(getattr(alert, 'detector', ''))} "
            "cs1Label=detector"
        )
        lines.append(
            f"CEF:0|{VENDOR}|{PRODUCT}|{VERSION}|"
            f"{signature}|{name}|{severity}|{extension}"
            f" rt={epoch_ms}"
        )
    return lines
