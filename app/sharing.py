"""Security logic for the Shared Report Link feature."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext

TOKEN_BYTES = 32          # 256 bits of entropy -> ~43 URL-safe chars
MAX_TOKEN_LENGTH = 128    # stop unauthenticated callers making us hash huge URLs
MIN_PASSWORD_BYTES = 8
MAX_PASSWORD_BYTES = 72   # bcrypt silently truncates past this
SHARE_TTL = timedelta(hours=24)
MAX_FAILED_ATTEMPTS = 10

share_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def utcnow() -> datetime:
    """Naive UTC 'now'.

    The existing columns are plain DateTime, so SQLite returns naive datetimes.
    Returning naive UTC keeps every comparison naive-vs-naive and avoids the
    "can't compare offset-naive and offset-aware" bug.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_share_token() -> str:
    """Unguessable token from the OS CSPRNG. Never use random/uuid1 here."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_share_token(token: str) -> str:
    """SHA-256 digest used as the DB lookup key.

    A plain hash rather than bcrypt is correct here *because* the token is 256
    bits of random data: there is no dictionary to attack, and an unindexed
    bcrypt comparison would force a full table scan on every public request.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_password_strength(password: str) -> Optional[str]:
    encoded = password.encode("utf-8")
    if len(encoded) < MIN_PASSWORD_BYTES:
        return f"password must be at least {MIN_PASSWORD_BYTES} characters"
    if len(encoded) > MAX_PASSWORD_BYTES:
        return f"password must not exceed {MAX_PASSWORD_BYTES} bytes"
    return None


def hash_share_password(password: str) -> str:
    return share_pwd_context.hash(password)


def verify_share_password(plain: str, hashed: str) -> bool:
    try:
        return share_pwd_context.verify(plain, hashed)
    except ValueError:
        # Malformed stored hash: fail closed rather than raise a 500 that would
        # dump a stack trace on a public endpoint (see the global handler).
        return False