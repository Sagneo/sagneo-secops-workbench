import os
from pathlib import Path

TEST_DB = Path("data/test-secops.db")
TEST_DB.parent.mkdir(exist_ok=True)
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["APP_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from alembic import command
from alembic.config import Config
from app.db import engine
from app.main import app
from app.models import (
    Alert,
    AlertEvent,
    AlertHistory,
    Asset,
    AuditEvent,
    CaseAlert,
    CaseTimelineEntry,
    CollectionHistory,
    CollectionRequest,
    Event,
    EvidenceAlertLink,
    EvidenceArtifact,
    EvidenceBundle,
    IncidentCase,
    ParserError,
    Role,
    RuleVersion,
    SourceBatch,
    User,
    VerificationRun,
)
from app.security import hash_password


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    command.upgrade(Config("alembic.ini"), "head")
    yield
    engine.dispose()
    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture()
def db(migrated_database):
    with Session(engine) as session:
        yield session
        session.rollback()


@pytest.fixture()
def users(db: Session):
    db.query(User).delete()
    analyst = User(
        username="analyst-test",
        role=Role.ANALYST,
        password_hash=hash_password("test-only-analyst-pass"),
    )
    reviewer = User(
        username="reviewer-test",
        role=Role.REVIEWER,
        password_hash=hash_password("test-only-reviewer-pass"),
    )
    db.add_all([analyst, reviewer])
    db.commit()
    return analyst, reviewer


@pytest.fixture()
def client(migrated_database):
    return TestClient(app)


@pytest.fixture()
def telemetry_db(db: Session):
    for model in (
        EvidenceAlertLink,
        VerificationRun,
        EvidenceArtifact,
        EvidenceBundle,
        CollectionHistory,
        CollectionRequest,
        CaseTimelineEntry,
        CaseAlert,
        IncidentCase,
        AlertHistory,
        AlertEvent,
        Alert,
        RuleVersion,
        ParserError,
        Event,
        SourceBatch,
        Asset,
        AuditEvent,
    ):
        db.execute(delete(model))
    db.commit()
    yield db
    db.rollback()
    for model in (
        EvidenceAlertLink,
        VerificationRun,
        EvidenceArtifact,
        EvidenceBundle,
        CollectionHistory,
        CollectionRequest,
        CaseTimelineEntry,
        CaseAlert,
        IncidentCase,
        AlertHistory,
        AlertEvent,
        Alert,
        RuleVersion,
        ParserError,
        Event,
        SourceBatch,
        Asset,
        AuditEvent,
    ):
        db.execute(delete(model))
    db.commit()
