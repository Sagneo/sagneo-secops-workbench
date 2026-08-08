import hashlib
import secrets
from datetime import datetime, timedelta

from pwdlib import PasswordHash

from app.models import utcnow

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    return password_hash.verify(password, encoded)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def absolute_expiry(hours: int) -> datetime:
    return utcnow() + timedelta(hours=hours)
