from getpass import getpass

from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import AuditEvent, Role, User
from app.security import hash_password


def main() -> None:
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(User)):
            raise SystemExit("Bootstrap refused: users already exist")
        created: list[User] = []
        for role in (Role.ANALYST, Role.REVIEWER):
            username = input(f"{role.value.lower()} username: ").strip()
            password = getpass(f"{role.value.lower()} password: ")
            if not username or len(password) < 12:
                raise SystemExit("Bootstrap refused: invalid local input")
            created.append(
                User(username=username, role=role.value, password_hash=hash_password(password))
            )
        db.add_all(created)
        db.add(AuditEvent(action="auth.bootstrap", outcome="SUCCESS", detail="two roles created"))
        db.commit()
        print("Bootstrap complete: Analyst and Reviewer created")


if __name__ == "__main__":
    main()
