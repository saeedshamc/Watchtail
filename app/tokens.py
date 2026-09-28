"""API token management and bearer authentication helpers."""

import hashlib
import secrets

from flask import request

from .database import session_scope
from .models import ApiToken, utcnow


def generate_token() -> tuple[str, str]:
    """Return (plain_token, sha256_hex) — the plain value shown once."""
    plain = "wt_" + secrets.token_urlsafe(32)
    return plain, _hash(plain)


def _hash(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def create_token(name: str, can_write=False) -> tuple[str, ApiToken]:
    """Create a token row; returns the plain secret (shown once) and row."""
    plain, digest = generate_token()
    with session_scope() as session:
        row = ApiToken(name=name or "unnamed", token_hash=digest, can_write=can_write)
        session.add(row)
        session.flush()
        row_id = row.id
    with session_scope() as session:
        return plain, session.get(ApiToken, row_id)


def verify_token(plain: str) -> ApiToken | None:
    """Return the live token row for a valid bearer value, else None."""
    if not plain:
        return None
    digest = _hash(plain)
    with session_scope() as session:
        row = (
            session.query(ApiToken)
            .filter(ApiToken.token_hash == digest, ApiToken.revoked.is_(False))
            .one_or_none()
        )
        if row is None:
            return None
        row.last_used_at = utcnow()
        return row


def bearer_from_request() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None
