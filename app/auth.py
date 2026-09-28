"""Session-based authentication for the dashboard.

Accounts live in the database (bootstrapped by the app factory, extra
ones via the CLI). Passwords are verified with werkzeug's PBKDF2
helper; login state is a plain signed session cookie carrying the
role. Viewers see everything; only admins may change state.
"""

from functools import wraps

from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from .database import session_scope
from .models import AdminUser


def current_role() -> str:
    """Role of the signed-in user; empty when anonymous."""
    return session.get("role") or ""


def is_admin() -> bool:
    return current_role() == "admin"


def verify_credentials(username, password):
    """Return (ok, role) for a matching account."""
    if not username or not password:
        return False, ""
    with session_scope() as db:
        user = db.get(AdminUser, username)
        if user is None:
            return False, ""
        if check_password_hash(user.password_hash, password):
            return True, (user.role or "admin")
        return False, ""


def admin_required(view):
    """Block non-admin (or anonymous) users from state-changing routes."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith(("/api/", "/socket.io")):
                return jsonify_error()
            return redirect(url_for("auth.login", next=request.path))
        if not is_admin():
            flash("This action requires an admin account.")
            return redirect(request.referrer or url_for("dashboard.dashboard"))
        return view(*args, **kwargs)

    return wrapped


def login_required(view):
    """Redirect unauthenticated requests to the login page.

    API-style paths get a JSON 401 instead of a redirect so live
    widgets fail visibly rather than receiving HTML.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user"):
            return view(*args, **kwargs)
        if request.path.startswith(("/api/", "/socket.io")):
            return jsonify_error()
        return redirect(url_for("auth.login", next=request.path))

    return wrapped


def jsonify_error():
    from flask import jsonify

    return jsonify(error="authentication required"), 401
