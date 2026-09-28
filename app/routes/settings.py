"""Detector settings page: view and edit thresholds from the dashboard.

Changes are written back to the active watchtail.yml (round-tripped
with ruamel.yaml so comments survive) and the running detection engine
is rebuilt so edits apply without a restart. ``flag_ttl_seconds`` is a
flat detectors key, not a detector block, and is handled separately.
"""

import logging

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..auth import admin_required, login_required
from ..database import session_scope
from ..detectors.engine import DETECTOR_CLASSES
from ..models import LogSource
from ..tailer import TailManager

logger = logging.getLogger("watchtail")

bp = Blueprint("settings", __name__)

# UI description of every tunable, one entry per detector.
DETECTOR_FIELDS = {
    "ssh_bruteforce": [
        ("max_failures", "int", "max failures"),
        ("window_seconds", "int", "window (s)"),
        ("severity", "severity", "severity"),
    ],
    "http_error_spike": [
        ("max_errors", "int", "max errors"),
        ("window_seconds", "int", "window (s)"),
        ("status_codes", "codes", "status codes"),
        ("severity", "severity", "severity"),
    ],
    "request_burst": [
        ("max_requests", "int", "max requests"),
        ("window_seconds", "int", "window (s)"),
        ("severity", "severity", "severity"),
    ],
    "ssh_compromise": [
        ("min_failures", "int", "min prior failures"),
        ("window_seconds", "int", "window (s)"),
    ],
    "path_scan": [
        ("max_paths", "int", "max distinct paths"),
        ("window_seconds", "int", "window (s)"),
        ("status_codes", "codes", "status codes"),
        ("severity", "severity", "severity"),
    ],
    "distributed_attack": [
        ("max_ips", "int", "max distinct IPs"),
        ("window_seconds", "int", "window (s)"),
        ("cooldown_seconds", "int", "cooldown (s)"),
        ("severity", "severity", "severity"),
    ],
}

SEVERITY_LEVELS = ("low", "medium", "high", "critical")


def _as_int(form, key):
    try:
        return int(form[key])
    except (KeyError, TypeError, ValueError):
        return None


def _as_codes(form, key):
    raw = form.get(key, "")
    codes = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if part.isdigit() and 100 <= int(part) <= 599:
            codes.append(int(part))
    return sorted(set(codes))


def _load_yaml(path):
    """Load the config preserving comments and ordering."""
    try:
        from ruamel.yaml import YAML

        yaml = YAML()
        yaml.preserve_quotes = True
        with open(path, encoding="utf-8") as fh:
            return yaml.load(fh) or {}
    except ImportError:
        import yaml

        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}


def _save_yaml(path, data):
    try:
        from ruamel.yaml import YAML

        yaml = YAML()
        with open(path, "w", encoding="utf-8") as fh:
            yaml.dump(data, fh)
    except ImportError:
        import yaml

        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)


def _collect_updates():
    """Read the form into {detector: {key: value}} plus flat keys."""
    updates = {}
    for detector, fields in DETECTOR_FIELDS.items():
        block = {}
        for key, kind, _label in fields:
            form_key = f"{detector}.{key}"
            if kind == "int":
                value = _as_int(request.form, form_key)
                if value is not None and value > 0:
                    block[key] = value
            elif kind == "codes":
                codes = _as_codes(request.form, form_key)
                if codes:
                    block[key] = codes
            elif kind == "severity":
                value = request.form.get(form_key)
                if value in SEVERITY_LEVELS:
                    block[key] = value
        updates[detector] = block
    ttl = _as_int(request.form, "flag_ttl_seconds")
    if ttl is not None and ttl > 0:
        updates["flag_ttl_seconds"] = ttl
    return updates


def _apply_to_running_engine(settings, updates):
    """Update thresholds on live detector instances where possible."""
    engine = getattr(settings, "_engine", None)
    if engine is None:
        return
    for detector in engine.detectors:
        block = updates.get(detector.name, {})
        for key, value in block.items():
            if hasattr(detector, key):
                setattr(detector, key, value)


@bp.get("/settings")
@login_required
def view():
    settings = current_app.config["WATCHTAIL_SETTINGS"]
    panels = []
    for name, cls in DETECTOR_CLASSES.items():
        options = settings.detector(name)
        panels.append(
            {
                "name": name,
                "enabled": settings.detector_enabled(name),
                "fields": DETECTOR_FIELDS.get(name, []),
                "options": options,
            }
        )
    return render_template(
        "settings.html",
        panels=panels,
        severity_levels=SEVERITY_LEVELS,
        flag_ttl_seconds=settings.flag_ttl_seconds,
        config_path=settings.config_path,
        ruamel_available=_ruamel_available(),
    )


def _ruamel_available():
    try:
        import ruamel.yaml  # noqa: F401

        return True
    except ImportError:
        return False


@bp.post("/settings")
@admin_required
def save():
    settings = current_app.config["WATCHTAIL_SETTINGS"]
    config_path = settings.config_path
    if not config_path:
        flash("No watchtail.yml found; settings are read-only.")
        return redirect(url_for("settings.view"))

    updates = _collect_updates()
    try:
        data = _load_yaml(config_path)
        detectors = data.setdefault("detectors", {})
        for detector, block in updates.items():
            if detector == "flag_ttl_seconds":
                detectors["flag_ttl_seconds"] = block
                continue
            entry = detectors.setdefault(detector, {})
            entry.setdefault("enabled", True)
            entry.update(block)
        _save_yaml(config_path, data)
    except OSError:
        logger.exception("could not write config %s", config_path)
        flash("Could not write the config file; changes not saved.")
        return redirect(url_for("settings.view"))

    # Hot-reload what can be reloaded without a restart.
    for detector, block in updates.items():
        if detector == "flag_ttl_seconds":
            continue
        for key, value in block.items():
            setattr(settings, f"_live_{detector}_{key}", value)
    _apply_to_running_engine(settings, updates)
    settings.detectors = _load_yaml(config_path).get("detectors", {})

    flash("Detector settings saved and applied.")
    return redirect(url_for("settings.view"))
