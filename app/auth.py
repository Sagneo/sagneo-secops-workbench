import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import AuditEvent, Role, User, UserSession, utcnow
from app.security import (
    absolute_expiry,
    digest_token,
    new_csrf_token,
    new_session_token,
    verify_password,
)


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's timezone-naive datetime values to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _audit(db: Session, action: str, outcome: str, user_id: str | None = None) -> None:
    db.add(AuditEvent(actor_user_id=user_id, action=action, outcome=outcome))


def current_session(request: Request, db: Session) -> UserSession | None:
    raw = request.cookies.get(settings.session_cookie)
    if not raw:
        return None
    session = db.scalar(select(UserSession).where(UserSession.token_digest == digest_token(raw)))
    now = utcnow()
    if (
        not session
        or session.revoked_at is not None
        or _as_utc(session.absolute_expires_at) <= now
        or _as_utc(session.last_seen_at) + timedelta(minutes=settings.idle_minutes) <= now
    ):
        return None
    session.last_seen_at = now
    db.commit()
    return session


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    session = current_session(request, db)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return session.user


def require_role(role: Role) -> Callable[..., User]:
    def dependency(user: User = Depends(require_user)) -> User:
        if user.role != role.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return user

    return dependency


def validate_csrf(request: Request, supplied: str, db: Session) -> UserSession:
    session = current_session(request, db)
    if not session or not secrets.compare_digest(session.csrf_token, supplied):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return session


def login(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = db.scalar(select(User).where(User.username == username, User.active.is_(True)))
    if not user or not verify_password(password, user.password_hash):
        _audit(db, "auth.login", "DENIED", user.id if user else None)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = new_session_token()
    session = UserSession(
        user_id=user.id,
        token_digest=digest_token(token),
        csrf_token=new_csrf_token(),
        absolute_expires_at=absolute_expiry(settings.absolute_hours),
    )
    db.add(session)
    _audit(db, "auth.login", "SUCCESS", user.id)
    db.commit()
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        settings.session_cookie,
        token,
        httponly=True,
        secure=settings.secure_cookie,
        samesite="lax",
        path="/",
        max_age=settings.absolute_hours * 3600,
    )
    return response


def logout(
    request: Request,
    csrf_token: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    session.revoked_at = utcnow()
    _audit(db, "auth.logout", "SUCCESS", session.user_id)
    db.commit()
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(settings.session_cookie, path="/")
    return response
