from datetime import timedelta

from sqlalchemy import func, select

from app.models import AuditEvent, UserSession, utcnow
from app.security import digest_token, hash_password, new_session_token, verify_password


def test_health(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_local_stylesheet_and_browser_security_headers(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert '<link rel="stylesheet" href="/static/workbench.css">' in page.text
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["content-security-policy"] == (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; img-src 'self' data:; style-src 'self'"
    )
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["x-frame-options"] == "DENY"

    stylesheet = client.get("/static/workbench.css")
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "--surface" in stylesheet.text


def test_argon2_and_opaque_digest():
    encoded = hash_password("test-only-long-password")
    assert encoded.startswith("$argon2")
    assert verify_password("test-only-long-password", encoded)
    token = new_session_token()
    assert token not in digest_token(token)
    assert len(digest_token(token)) == 64


def test_login_logout_csrf_and_audit(client, db, users):
    response = client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    cookie = response.cookies.get("secops_session")
    assert cookie
    assert db.scalar(select(UserSession).where(UserSession.token_digest == digest_token(cookie)))
    denied = client.post("/logout", data={"csrf_token": "wrong"})
    assert denied.status_code == 403
    page = client.get("/")
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    logged_out = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert logged_out.status_code == 303
    assert db.scalar(select(func.count()).select_from(AuditEvent)) >= 2


def test_session_rotation_idle_absolute_expiry_and_cookie_flags(client, db, users):
    first = client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
        follow_redirects=False,
    )
    first_token = first.cookies["secops_session"]
    assert "HttpOnly" in first.headers["set-cookie"]
    assert "SameSite=lax" in first.headers["set-cookie"]

    second = client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
        follow_redirects=False,
    )
    second_token = second.cookies["secops_session"]
    assert second_token != first_token

    session = db.scalar(
        select(UserSession).where(UserSession.token_digest == digest_token(second_token))
    )
    assert session is not None
    session.last_seen_at = utcnow() - timedelta(minutes=31)
    db.commit()
    assert client.get("/").status_code == 401

    third = client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
        follow_redirects=False,
    )
    third_token = third.cookies["secops_session"]
    session = db.scalar(
        select(UserSession).where(UserSession.token_digest == digest_token(third_token))
    )
    assert session is not None
    session.absolute_expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.get("/").status_code == 401


def test_failed_login_is_audited(client, db, users):
    response = client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-wrong-password"},
    )
    assert response.status_code == 401
    event = db.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "auth.login", AuditEvent.outcome == "DENIED")
        .order_by(AuditEvent.created_at.desc())
    )
    assert event is not None


def test_rbac_positive_and_negative(client, users):
    client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
    )
    assert client.get("/reviewer-check").status_code == 403
    page = client.get("/")
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    client.post("/logout", data={"csrf_token": csrf})
    client.post(
        "/login",
        data={"username": "reviewer-test", "password": "test-only-reviewer-pass"},
    )
    assert client.get("/reviewer-check").json() == {"role": "REVIEWER"}
