"""Language, theme and timezone preference routes.

All three are per-browser session settings with one-button toggles in
the header plus a timezone dropdown on the settings page.
"""

from flask import Blueprint, flash, redirect, request, session, url_for

from ..i18n import SUPPORTED, current_language
from ..prefs import TZ_CHOICES_MINUTES, set_theme, set_tz_minutes

bp = Blueprint("locale", __name__)


def _safe_back():
    referrer = request.referrer
    if referrer and referrer.startswith(request.host_url):
        return redirect(referrer)
    return redirect(url_for("dashboard.dashboard"))


@bp.get("/lang/<lang>")
def switch(lang):
    if lang in SUPPORTED:
        session["lang"] = lang
    return _safe_back()


@bp.get("/prefs/theme/<theme>")
def toggle_theme(theme):
    set_theme(theme)
    return _safe_back()


@bp.post("/prefs/tz")
def choose_tz():
    # Matches the app-wide role split: reads are open, writes are admin
    # only (the settings page hosting this form is admin-gated too).
    from ..auth import is_admin
    from ..prefs import tz_offset_label

    if not session.get("user"):
        return redirect(url_for("auth.login", next=request.path))
    if not is_admin():
        flash("This action requires an admin account.")
        return redirect(request.referrer or url_for("dashboard.dashboard"))
    raw = request.form.get("tz", "")
    try:
        minutes = int(raw)
    except ValueError:
        minutes = 0
    if minutes in TZ_CHOICES_MINUTES:
        set_tz_minutes(minutes)
        flash(f"Timezone display set to {tz_offset_label()}.")
    return redirect(url_for("settings.view"))
