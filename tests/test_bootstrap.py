from sqlalchemy import delete, func, select

from app.models import Role, User


def test_bootstrap_creates_exact_roles_once_and_refuses_overwrite(db, monkeypatch):
    from app import bootstrap

    db.execute(delete(User))
    db.commit()
    entries = iter(("analyst-bootstrap-test", "reviewer-bootstrap-test"))
    passwords = iter(("test-only-analyst-bootstrap", "test-only-reviewer-bootstrap"))
    monkeypatch.setattr("builtins.input", lambda _: next(entries))
    monkeypatch.setattr(bootstrap, "getpass", lambda _: next(passwords))
    bootstrap.main()
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(User)) == 2
    assert set(db.scalars(select(User.role))) == {Role.ANALYST.value, Role.REVIEWER.value}

    try:
        bootstrap.main()
    except SystemExit as exc:
        assert "users already exist" in str(exc)
    else:
        raise AssertionError("bootstrap did not refuse overwrite")
    db.execute(delete(User))
    db.commit()
