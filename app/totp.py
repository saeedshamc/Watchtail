"""TOTP two-factor authentication built on the standard library.

Implements RFC 6238 with HMAC-SHA1 and 6-digit codes — the flavour
every authenticator app speaks. Secrets are stored base32-encoded in
the admin_users row; verification allows the usual ±1 time-step skew.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time

STEP_SECONDS = 30
DIGITS = 6
SKEW_STEPS = 1  # accept the previous and next codes


def generate_secret() -> str:
    """A fresh 160-bit secret, base32-encoded for QR/manual entry."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _code_at(secret: str, counter: int) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper() + padding)
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return f"{number % 10 ** DIGITS:0{DIGITS}d}"


def current_code(secret: str, at: float | None = None) -> str:
    counter = int((at if at is not None else time.time()) // STEP_SECONDS)
    return _code_at(secret, counter)


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """Check a code allowing ±1 step of clock drift."""
    if not secret or not code or not code.strip().isdigit():
        return False
    code = code.strip()
    now = at if at is not None else time.time()
    counter = int(now // STEP_SECONDS)
    return any(
        hmac.compare_digest(_code_at(secret, counter + offset), code)
        for offset in range(-SKEW_STEPS, SKEW_STEPS + 1)
    )


def provisioning_uri(secret: str, account: str, issuer="Watchtail") -> str:
    """otpauth:// URL for QR codes (render it with any QR library)."""
    padding = "=" * ((8 - len(secret) % 8) % 8)
    full = secret.upper() + padding if padding != "=" * 8 else secret.upper()
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(account)}"
        f"?secret={full}&issuer={quote(issuer)}&digits={DIGITS}"
        f"&period={STEP_SECONDS}"
    )
