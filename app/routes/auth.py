"""Login and logout routes for the single admin account."""

import time

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..auth import verify_credentials

bp = Blueprint("auth", __name__)

# Simple in-process throttle: 10 failures per IP per 5 minutes.
MAX_FAILURES = 10
FAILURE_WINDOW = 300
_failures: dict[str, list[float]] = {}


def _throttled(remote_addr):
    now = time.time()
    stamps = [t for t in _failures.get(remote_addr, []) if now - t <= FAILURE_WINDOW]
    _failures[remote_addr] = stamps
    return len(stamps) >= MAX_FAILURES


def _record_failure(remote_addr):
    _failures.setdefault(remote_addr, []).append(time.time())


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if _throttled(request.remote_addr or "?"):
            error = "Too many attempts; wait a few minutes and try again."
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if verify_credentials(username, password):
                session.clear()
                session["user"] = username
                session.permanent = True
                target = request.args.get("next") or url_for("dashboard.dashboard")
                if not target.startswith("/"):
                    target = url_for("dashboard.dashboard")
                return redirect(target)
            _record_failure(request.remote_addr or "?")
            error = "Invalid credentials."
    return render_template("login.html", error=error)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
