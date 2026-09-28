"""Login and logout routes for dashboard accounts.

Accounts with a TOTP secret get a second step: password first, then a
6-digit code from their authenticator app.
"""

import time

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from .. import totp

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
            return render_template("login.html", error=error)

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        code = request.form.get("code", "")
        ok, role, pending_secret = _check_credentials(username, password)
        if not ok:
            _record_failure(request.remote_addr or "?")
            error = "Invalid credentials."
        elif pending_secret:
            # Password accepted; complete the second factor.
            if not totp.verify(pending_secret, code):
                _record_failure(request.remote_addr or "?")
                error = "Invalid authenticator code."
                return render_template(
                    "login.html", error=error, twofact_user=username
                )
            _complete_login(username, role)
            return _safe_redirect()
        else:
            _complete_login(username, role)
            return _safe_redirect()
    return render_template("login.html", error=error)


def _check_credentials(username, password):
    """Verify the password; also return any pending TOTP secret."""
    from ..database import session_scope
    from ..models import AdminUser
    from werkzeug.security import check_password_hash

    if not username or not password:
        return False, "", None
    with session_scope() as session:
        user = session.get(AdminUser, username)
        if user is None:
            return False, "", None
        if not check_password_hash(user.password_hash, password):
            return False, "", None
        return True, (user.role or "admin"), user.totp_secret or None


def _complete_login(username, role):
    session.clear()
    session["user"] = username
    session["role"] = role or "admin"
    session.permanent = True


def _safe_redirect():
    target = request.args.get("next") or url_for("dashboard.dashboard")
    if not target.startswith("/"):
        target = url_for("dashboard.dashboard")
    return redirect(target)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.get("/account/totp")
def totp_setup():
    """Show (or generate) the current user's TOTP enrollment data."""
    if not session.get("user"):
        return redirect(url_for("auth.login"))
    from ..database import session_scope
    from ..models import AdminUser

    username = session["user"]
    with session_scope() as db_session:
        user = db_session.get(AdminUser, username)
        secret = user.totp_secret if user else None
    if secret:
        enrolled = True
    else:
        enrolled = False
        secret = totp.generate_secret()
        with session_scope() as db_session:
            db_user = db_session.get(AdminUser, username)
            db_user.totp_secret = secret
    return render_template(
        "totp_setup.html",
        username=username,
        secret=secret,
        uri=totp.provisioning_uri(secret, username),
        enrolled=enrolled,
    )


@bp.post("/account/totp/disable")
def totp_disable():
    if not session.get("user"):
        return redirect(url_for("auth.login"))
    from ..database import session_scope
    from ..models import AdminUser

    with session_scope() as db_session:
        user = db_session.get(AdminUser, session["user"])
        if user is not None:
            user.totp_secret = None
    flash("Two-factor authentication disabled.")
    return redirect(url_for("dashboard.dashboard"))
