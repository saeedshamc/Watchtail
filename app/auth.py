"""Session-based authentication for the dashboard.

A single admin account lives in the database (bootstrapped by the app
factory). Passwords are verified with werkzeug's PBKDF2 helper; login
state is a plain signed session cookie.
"""

from functools import wraps

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash

from .database import session_scope
from .models import AdminUser


def verify_credentials(username, password):
    """Return True when the username/password pair matches the admin."""
    if not username or not password:
        return False
    with session_scope() as db:
        user = db.get(AdminUser, username)
        if user is None:
            return False
        return bool(check_password_hash(user.password_hash, password))


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
