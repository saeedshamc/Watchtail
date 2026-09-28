"""Authentication for the versioned REST API.

Session cookies work too (the dashboard's own JS can call it), but
machine clients authenticate with ``Authorization: Bearer <token>``.
"""

from functools import wraps

from flask import jsonify, request

from . import tokens
from .database import session_scope
from .models import ApiToken


def token_required(write=False):
    """Wrap a view so it accepts a valid session or a bearer token.

    ``write=True`` additionally requires a token with can_write=True
    when the request arrived via token (session users are the admin).
    """

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            plain = tokens.bearer_from_request()
            if plain:
                row = tokens.verify_token(plain)
                if row is None:
                    return jsonify(error="invalid or revoked token"), 401
                if write and not row.can_write:
                    return jsonify(error="token lacks write scope"), 403
                request.api_token = row
                return view(*args, **kwargs)

            from flask import session as flask_session

            if flask_session.get("user"):
                request.api_token = None
                return view(*args, **kwargs)

            return jsonify(error="authentication required"), 401

        return wrapped

    return decorator


def revoke_token(token_id: int) -> bool:
    with session_scope() as session:
        row = session.get(ApiToken, token_id)
        if row is None:
            return False
        row.revoked = True
        return True
