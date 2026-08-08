from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(StrEnum):
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"


class SourceType(StrEnum):
    LINUX_AUTH = "LINUX_AUTH"
    SURICATA_EVE = "SURICATA_EVE"


class AlertStatus(StrEnum):
    NEW = "NEW"
    IN_TRIAGE = "IN_TRIAGE"
    ESCALATED = "ESCALATED"
    BENIGN = "BENIGN"
    CLOSED = "CLOSED"


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CollectionStatus(StrEnum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class VerificationStatus(StrEnum):
    # Integrity result, not a credential.
    PASS = "PASS"  # noqa: S105  # nosec B105
    FAIL = "FAIL"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16))
    password_hash: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user: Mapped[User] = relationship(back_populates="sessions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    operating_system: Mapped[str] = mapped_column(String(64))
    lab_ip: Mapped[str] = mapped_column(String(45), unique=True)
    purpose_owner: Mapped[str] = mapped_column(String(96))
    criticality: Mapped[str] = mapped_column(String(16))
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    events: Mapped[list["Event"]] = relationship(back_populates="asset")


class SourceBatch(Base):
    __tablename__ = "source_batches"
    __table_args__ = (UniqueConstraint("source_type", "content_digest"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_type: Mapped[str] = mapped_column(String(24), index=True)
    content_digest: Mapped[str] = mapped_column(String(64))
    parser_version: Mapped[str] = mapped_column(String(32))
    source_reference: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), index=True)
    total_records: Mapped[int] = mapped_column(Integer)
    accepted_records: Mapped[int] = mapped_column(Integer)
    duplicate_records: Mapped[int] = mapped_column(Integer)
    error_records: Mapped[int] = mapped_column(Integer)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    earliest_event_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    latest_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events: Mapped[list["Event"]] = relationship(back_populates="batch")
    errors: Mapped[list["ParserError"]] = relationship(back_populates="batch")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    stable_identity: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(24), index=True)
    source_batch_id: Mapped[str] = mapped_column(
        ForeignKey("source_batches.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    category: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    summary: Mapped[str] = mapped_column(String(255))
    normalized_data: Mapped[str] = mapped_column(Text)
    raw_reference: Mapped[str] = mapped_column(String(255))
    batch: Mapped[SourceBatch] = relationship(back_populates="events")
    asset: Mapped[Asset] = relationship(back_populates="events")


class ParserError(Base):
    __tablename__ = "parser_errors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_batch_id: Mapped[str] = mapped_column(
        ForeignKey("source_batches.id", ondelete="CASCADE"), index=True
    )
    line_number: Mapped[int] = mapped_column(Integer)
    error_code: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(String(160))
    batch: Mapped[SourceBatch] = relationship(back_populates="errors")


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    __table_args__ = (UniqueConstraint("rule_id", "version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    version: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    source_type: Mapped[str] = mapped_column(String(24))
    content_digest: Mapped[str] = mapped_column(String(64))
    definition: Mapped[str] = mapped_column(Text)
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    stable_identity: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.NEW, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(160))
    explanation: Mapped[str] = mapped_column(Text)
    trigger_summary: Mapped[str] = mapped_column(Text)
    scope_impact: Mapped[str] = mapped_column(Text, default="")
    severity_rationale: Mapped[str] = mapped_column(Text, default="")
    false_positive_context: Mapped[str] = mapped_column(Text, default="")
    disposition_reason: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    assigned_to_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rule_version: Mapped[RuleVersion] = relationship()
    asset: Mapped[Asset] = relationship()
    event_links: Mapped[list["AlertEvent"]] = relationship(
        back_populates="alert", order_by="AlertEvent.position"
    )
    history: Mapped[list["AlertHistory"]] = relationship(
        back_populates="alert", order_by="AlertHistory.created_at"
    )


class AlertEvent(Base):
    __tablename__ = "alert_events"
    __table_args__ = (
        UniqueConstraint("alert_id", "event_id"),
        UniqueConstraint("alert_id", "position"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    alert: Mapped[Alert] = relationship(back_populates="event_links")
    event: Mapped[Event] = relationship()


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert: Mapped[Alert] = relationship(back_populates="history")


class IncidentCase(Base):
    __tablename__ = "incident_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    title: Mapped[str] = mapped_column(String(160))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=CaseStatus.OPEN, index=True)
    opened_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    resolution: Mapped[str] = mapped_column(Text, default="")
    closure_summary: Mapped[str] = mapped_column(Text, default="")
    no_collection_reason: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    asset: Mapped[Asset] = relationship()
    alert_links: Mapped[list["CaseAlert"]] = relationship(
        back_populates="case", order_by="CaseAlert.created_at"
    )
    timeline: Mapped[list["CaseTimelineEntry"]] = relationship(
        back_populates="case", order_by="CaseTimelineEntry.created_at"
    )
    collection_requests: Mapped[list["CollectionRequest"]] = relationship(
        back_populates="case", order_by="CollectionRequest.created_at"
    )
    evidence_bundles: Mapped[list["EvidenceBundle"]] = relationship(
        back_populates="case", order_by="EvidenceBundle.created_at"
    )


class CaseAlert(Base):
    __tablename__ = "case_alerts"
    __table_args__ = (UniqueConstraint("case_id", "alert_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    case_id: Mapped[str] = mapped_column(
        ForeignKey("incident_cases.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    linked_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    case: Mapped[IncidentCase] = relationship(back_populates="alert_links")
    alert: Mapped[Alert] = relationship()


class CaseTimelineEntry(Base):
    __tablename__ = "case_timeline_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    case_id: Mapped[str] = mapped_column(
        ForeignKey("incident_cases.id", ondelete="CASCADE"), index=True
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    entry_type: Mapped[str] = mapped_column(String(24), index=True)
    detail: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    case: Mapped[IncidentCase] = relationship(back_populates="timeline")


class CollectionRequest(Base):
    __tablename__ = "collection_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    case_id: Mapped[str] = mapped_column(
        ForeignKey("incident_cases.id", ondelete="CASCADE"), index=True
    )
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    profile_id: Mapped[str] = mapped_column(String(32))
    profile_version: Mapped[str] = mapped_column(String(16))
    profile_digest: Mapped[str] = mapped_column(String(64))
    adapter: Mapped[str] = mapped_column(String(24))
    limits_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default=CollectionStatus.DRAFT, index=True)
    requested_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    reviewed_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewer_reason: Mapped[str] = mapped_column(Text, default="")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    error_summary: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    case: Mapped[IncidentCase] = relationship(back_populates="collection_requests")
    target_asset: Mapped[Asset] = relationship()
    history: Mapped[list["CollectionHistory"]] = relationship(
        back_populates="request", order_by="CollectionHistory.created_at"
    )
    evidence_bundle: Mapped["EvidenceBundle"] = relationship(
        back_populates="request", uselist=False
    )


class CollectionHistory(Base):
    __tablename__ = "collection_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(
        ForeignKey("collection_requests.id", ondelete="CASCADE"), index=True
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    request: Mapped[CollectionRequest] = relationship(back_populates="history")


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(
        ForeignKey("collection_requests.id"), unique=True, index=True
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("incident_cases.id", ondelete="CASCADE"), index=True
    )
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    adapter: Mapped[str] = mapped_column(String(24))
    profile_id: Mapped[str] = mapped_column(String(32))
    profile_version: Mapped[str] = mapped_column(String(16))
    profile_digest: Mapped[str] = mapped_column(String(64))
    root_reference: Mapped[str] = mapped_column(String(255))
    manifest_json: Mapped[str] = mapped_column(Text)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    collection_status: Mapped[str] = mapped_column(String(16))
    total_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    request: Mapped[CollectionRequest] = relationship(back_populates="evidence_bundle")
    case: Mapped[IncidentCase] = relationship(back_populates="evidence_bundles")
    artifacts: Mapped[list["EvidenceArtifact"]] = relationship(
        back_populates="bundle", order_by="EvidenceArtifact.relative_path"
    )
    verifications: Mapped[list["VerificationRun"]] = relationship(
        back_populates="bundle", order_by="VerificationRun.created_at"
    )


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"
    __table_args__ = (UniqueConstraint("bundle_id", "relative_path"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    bundle_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_bundles.id", ondelete="CASCADE"), index=True
    )
    relative_path: Mapped[str] = mapped_column(String(160))
    artifact_type: Mapped[str] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    bundle: Mapped[EvidenceBundle] = relationship(back_populates="artifacts")


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    bundle_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_bundles.id", ondelete="CASCADE"), index=True
    )
    case_id: Mapped[str] = mapped_column(ForeignKey("incident_cases.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    reason_codes_json: Mapped[str] = mapped_column(Text)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    verifier_version: Mapped[str] = mapped_column(String(16))
    independent: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    bundle: Mapped[EvidenceBundle] = relationship(back_populates="verifications")
    alert_links: Mapped[list["EvidenceAlertLink"]] = relationship(back_populates="verification")


class EvidenceAlertLink(Base):
    __tablename__ = "evidence_alert_links"
    __table_args__ = (
        UniqueConstraint("alert_id"),
        UniqueConstraint("verification_run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    verification_run_id: Mapped[str] = mapped_column(
        ForeignKey("verification_runs.id", ondelete="CASCADE"), index=True
    )
    alert: Mapped[Alert] = relationship()
    verification: Mapped[VerificationRun] = relationship(back_populates="alert_links")
