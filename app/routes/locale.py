"""Language selection routes and template integration."""

from flask import Blueprint, redirect, request, session, url_for

from ..i18n import SUPPORTED, current_language

bp = Blueprint("locale", __name__)


@bp.get("/lang/<lang>")
def switch(lang):
    if lang in SUPPORTED:
        session["lang"] = lang
    return redirect(request.referrer or url_for("dashboard.dashboard"))
