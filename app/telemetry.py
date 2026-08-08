"""Deterministic, bounded telemetry ingestion."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from alembic import command
from alembic.config import Config
from app.config import settings
from app.db import SessionLocal
from app.models import (
    Asset,
    AuditEvent,
    Event,
    ParserError,
    SourceBatch,
    SourceType,
    utcnow,
)

PARSER_VERSION = "1.0.0"
ASSET_DEFINITIONS = (
    {
        "id": "1f8476df-89c8-5c99-a910-94aa42b74cc8",
        "hostname": "secops-core",
        "operating_system": "Ubuntu Server 24.04 LTS",
        "lab_ip": "192.168.90.10",
        "purpose_owner": "SecOps workbench core / isolated lab",
        "criticality": "HIGH",
    },
    {
        "id": "a94c7196-3d3b-5029-90bf-a2c5a07f46c7",
        "hostname": "linux-endpoint-01",
        "operating_system": "Ubuntu Server 24.04 LTS",
        "lab_ip": "192.168.90.20",
        "purpose_owner": "Synthetic Linux endpoint / isolated lab",
        "criticality": "MEDIUM",
    },
)
LINUX_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<hostname>[a-z0-9-]+)\s+"
    r"(?P<program>sshd(?:\[\d+\])?|sudo):\s+(?P<message>.+)$"
)
SSH_PATTERN = re.compile(
    r"^(?P<verb>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<actor>[a-z0-9-]+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port \d+ ssh2$"
)
SUDO_PATTERN = re.compile(
    r"^(?P<actor>[a-z0-9-]+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+"
    r"USER=(?P<target>[a-z0-9-]+)\s+;\s+COMMAND=(?P<command>/\S+)$"
)
ALLOWED_EVE_TYPES = {"alert", "dns", "flow", "http"}


@dataclass(frozen=True)
class NormalizedEvent:
    source_type: SourceType
    asset_id: str
    timestamp_utc: datetime
    category: str
    action: str
    outcome: str
    severity: str
    actor: str | None
    source_ip: str | None
    destination_ip: str | None
    summary: str
    normalized_data: dict[str, Any]


@dataclass(frozen=True)
class ParseIssue:
    line_number: int
    error_code: str
    detail: str


@dataclass(frozen=True)
class ImportResult:
    batch_id: str
    source_type: str
    content_digest: str
    total_records: int
    accepted_new: int
    duplicate_records: int
    error_records: int
    replayed_batch: bool
    status: str


@dataclass(frozen=True)
class SourceHealth:
    source_type: str
    state: str
    last_successful_batch: SourceBatch | None
    latest_batch: SourceBatch | None
    latest_source_timestamp: datetime | None
    total_events: int
    total_errors: int
    latest_high_priority: Event | None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def normalize_timestamp(value: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("INVALID_TIMESTAMP") from exc
    if parsed.tzinfo is None:
        raise ValueError("TIMESTAMP_REQUIRES_OFFSET")
    return parsed.astimezone(UTC)


def safe_source_reference(value: str) -> str:
    if len(value) > 220 or "\\" in value:
        raise ValueError("UNSAFE_SOURCE_REFERENCE")
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("UNSAFE_SOURCE_REFERENCE")
    if not reference.parts or reference.parts[0] != "fixtures":
        raise ValueError("SOURCE_REFERENCE_OUTSIDE_FIXTURES")
    return reference.as_posix()


def _read_lines(path: Path, source_type: SourceType) -> tuple[bytes, list[str]]:
    expected_suffix = ".log" if source_type is SourceType.LINUX_AUTH else ".jsonl"
    if path.suffix.lower() != expected_suffix:
        raise ValueError("UNEXPECTED_FILE_TYPE")
    size = path.stat().st_size
    if size == 0 or size > settings.ingest_max_bytes:
        raise ValueError("FILE_SIZE_OUT_OF_BOUNDS")
    payload = path.read_bytes()
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("INVALID_UTF8") from exc
    lines = text.splitlines()
    if not lines:
        raise ValueError("EMPTY_INPUT")
    for line in lines:
        if len(line.encode("utf-8")) > settings.ingest_max_line_bytes or "\x00" in line:
            raise ValueError("LINE_SIZE_OR_ENCODING_OUT_OF_BOUNDS")
    return payload, lines


def seed_assets(db: Session) -> tuple[Asset, Asset]:
    existing = db.scalars(select(Asset).order_by(Asset.hostname)).all()
    if existing:
        expected = {(row["id"], row["hostname"], row["lab_ip"]) for row in ASSET_DEFINITIONS}
        actual = {(asset.id, asset.hostname, asset.lab_ip) for asset in existing}
        if actual != expected or len(existing) != 2:
            raise RuntimeError("ASSET_SEED_CONFLICT")
        return existing[0], existing[1]
    assets = [Asset(**definition) for definition in ASSET_DEFINITIONS]
    db.add_all(assets)
    db.add(
        AuditEvent(
            action="telemetry.assets_seeded",
            outcome="SUCCESS",
            detail="exactly two synthetic lab assets",
        )
    )
    db.commit()
    ordered = db.scalars(select(Asset).order_by(Asset.hostname)).all()
    return ordered[0], ordered[1]


def _asset_maps(db: Session) -> tuple[dict[str, Asset], dict[str, Asset]]:
    assets = db.scalars(select(Asset)).all()
    if len(assets) != 2:
        raise RuntimeError("EXACTLY_TWO_ASSETS_REQUIRED")
    return ({asset.hostname: asset for asset in assets}, {asset.lab_ip: asset for asset in assets})


def _bounded_detail(value: str) -> str:
    safe = " ".join(value.replace("\x00", "").split())
    return safe[:160]


def parse_linux_line(
    line: str, line_number: int, assets_by_hostname: dict[str, Asset]
) -> NormalizedEvent | ParseIssue:
    match = LINUX_PATTERN.fullmatch(line)
    if not match:
        return ParseIssue(line_number, "MALFORMED_LINUX", "record does not match bounded format")
    try:
        timestamp = normalize_timestamp(match["timestamp"])
    except ValueError as exc:
        return ParseIssue(line_number, str(exc), "timestamp is invalid or lacks an offset")
    asset = assets_by_hostname.get(match["hostname"])
    if asset is None:
        return ParseIssue(line_number, "ASSET_NOT_FOUND", "hostname is not a seeded lab asset")
    program = match["program"].split("[", 1)[0]
    message = match["message"]
    if program == "sshd":
        ssh = SSH_PATTERN.fullmatch(message)
        if not ssh:
            return ParseIssue(line_number, "MISSING_SSH_FIELDS", "SSH record fields are incomplete")
        accepted = ssh["verb"] == "Accepted"
        return NormalizedEvent(
            source_type=SourceType.LINUX_AUTH,
            asset_id=asset.id,
            timestamp_utc=timestamp,
            category="AUTHENTICATION",
            action="SSH_PASSWORD",
            outcome="SUCCESS" if accepted else "FAILURE",
            severity="INFO" if accepted else "MEDIUM",
            actor=ssh["actor"],
            source_ip=ssh["source_ip"],
            destination_ip=asset.lab_ip,
            summary=f"SSH password authentication {'accepted' if accepted else 'failed'}",
            normalized_data={"program": "sshd", "method": "password"},
        )
    sudo = SUDO_PATTERN.fullmatch(message)
    if not sudo:
        return ParseIssue(line_number, "MISSING_SUDO_FIELDS", "sudo record fields are incomplete")
    return NormalizedEvent(
        source_type=SourceType.LINUX_AUTH,
        asset_id=asset.id,
        timestamp_utc=timestamp,
        category="PRIVILEGE",
        action="SUDO_COMMAND",
        outcome="SUCCESS",
        severity="MEDIUM",
        actor=sudo["actor"],
        source_ip=None,
        destination_ip=asset.lab_ip,
        summary=f"sudo command executed as {sudo['target']}",
        normalized_data={
            "program": "sudo",
            "target_user": sudo["target"],
            "command": sudo["command"],
        },
    )


def parse_eve_line(
    line: str, line_number: int, assets_by_ip: dict[str, Asset]
) -> NormalizedEvent | ParseIssue:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return ParseIssue(line_number, "MALFORMED_JSON", "EVE record is not valid JSON")
    if not isinstance(record, dict):
        return ParseIssue(line_number, "INVALID_EVE_SHAPE", "EVE record must be an object")
    required = ("timestamp", "event_type", "src_ip", "dest_ip", "proto")
    if any(not isinstance(record.get(field), str) or not record[field] for field in required):
        return ParseIssue(line_number, "MISSING_EVE_FIELDS", "required EVE fields are missing")
    if record["event_type"] not in ALLOWED_EVE_TYPES:
        return ParseIssue(
            line_number, "UNSUPPORTED_EVE_TYPE", "event_type is outside the bounded set"
        )
    try:
        timestamp = normalize_timestamp(record["timestamp"])
    except ValueError as exc:
        return ParseIssue(line_number, str(exc), "timestamp is invalid or lacks an offset")
    asset = assets_by_ip.get(record["dest_ip"]) or assets_by_ip.get(record["src_ip"])
    if asset is None:
        return ParseIssue(line_number, "ASSET_NOT_FOUND", "EVE record has no seeded lab asset")
    event_type = record["event_type"]
    severity = "INFO"
    action = event_type.upper()
    summary = f"Suricata {event_type} event"
    normalized: dict[str, Any] = {"event_type": event_type, "proto": record["proto"]}
    if event_type == "alert":
        alert = record.get("alert")
        if not isinstance(alert, dict) or not all(
            key in alert for key in ("signature_id", "signature", "category", "severity")
        ):
            return ParseIssue(line_number, "MISSING_ALERT_FIELDS", "alert fields are incomplete")
        try:
            alert_severity = int(alert["severity"])
        except (TypeError, ValueError):
            return ParseIssue(
                line_number, "INVALID_ALERT_SEVERITY", "alert severity must be numeric"
            )
        severity = "HIGH" if alert_severity <= 2 else "MEDIUM"
        action = "NETWORK_ALERT"
        summary = _bounded_detail(str(alert["signature"]))
        normalized["signature_id"] = alert["signature_id"]
        normalized["category"] = _bounded_detail(str(alert["category"]))
    return NormalizedEvent(
        source_type=SourceType.SURICATA_EVE,
        asset_id=asset.id,
        timestamp_utc=timestamp,
        category="NETWORK",
        action=action,
        outcome="OBSERVED",
        severity=severity,
        actor=None,
        source_ip=record["src_ip"],
        destination_ip=record["dest_ip"],
        summary=summary,
        normalized_data=normalized,
    )


def _stable_identity(event: NormalizedEvent) -> str:
    identity = {
        "source_type": event.source_type.value,
        "asset_id": event.asset_id,
        "timestamp_utc": event.timestamp_utc.isoformat(),
        "category": event.category,
        "action": event.action,
        "outcome": event.outcome,
        "actor": event.actor,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "summary": event.summary,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def import_fixture(
    db: Session,
    source_type: SourceType,
    path: Path,
    source_reference: str,
) -> ImportResult:
    reference = safe_source_reference(source_reference)
    payload, lines = _read_lines(path, source_type)
    digest = hashlib.sha256(payload).hexdigest()
    existing = db.scalar(
        select(SourceBatch).where(
            SourceBatch.source_type == source_type.value,
            SourceBatch.content_digest == digest,
        )
    )
    if existing is not None:
        return ImportResult(
            existing.id,
            source_type.value,
            digest,
            existing.total_records,
            0,
            0,
            0,
            True,
            existing.status,
        )

    assets_by_hostname, assets_by_ip = _asset_maps(db)
    normalized: list[tuple[int, NormalizedEvent]] = []
    issues: list[ParseIssue] = []
    for line_number, line in enumerate(lines, start=1):
        parsed = (
            parse_linux_line(line, line_number, assets_by_hostname)
            if source_type is SourceType.LINUX_AUTH
            else parse_eve_line(line, line_number, assets_by_ip)
        )
        if isinstance(parsed, ParseIssue):
            issues.append(parsed)
        else:
            normalized.append((line_number, parsed))

    batch = SourceBatch(
        source_type=source_type.value,
        content_digest=digest,
        parser_version=PARSER_VERSION,
        source_reference=reference,
        status="ERROR" if issues else "SUCCESS",
        total_records=len(lines),
        accepted_records=0,
        duplicate_records=0,
        error_records=len(issues),
        earliest_event_at=min((event.timestamp_utc for _, event in normalized), default=None),
        latest_event_at=max((event.timestamp_utc for _, event in normalized), default=None),
    )
    try:
        db.add(batch)
        db.flush()
        existing_identities = set(
            db.scalars(
                select(Event.stable_identity).where(
                    Event.stable_identity.in_([_stable_identity(event) for _, event in normalized])
                )
            ).all()
        )
        accepted = 0
        duplicates = 0
        observed_assets: dict[str, datetime] = {}
        pending_identities: set[str] = set()
        for line_number, event in normalized:
            identity = _stable_identity(event)
            if identity in existing_identities or identity in pending_identities:
                duplicates += 1
                continue
            pending_identities.add(identity)
            accepted += 1
            previous = observed_assets.get(event.asset_id)
            if previous is None or event.timestamp_utc > previous:
                observed_assets[event.asset_id] = event.timestamp_utc
            db.add(
                Event(
                    stable_identity=identity,
                    source_type=source_type.value,
                    source_batch_id=batch.id,
                    asset_id=event.asset_id,
                    timestamp_utc=event.timestamp_utc,
                    category=event.category,
                    action=event.action,
                    outcome=event.outcome,
                    severity=event.severity,
                    actor=event.actor,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    summary=_bounded_detail(event.summary),
                    normalized_data=json.dumps(
                        event.normalized_data, sort_keys=True, separators=(",", ":")
                    ),
                    raw_reference=f"{reference}#L{line_number}",
                )
            )
        for issue in issues:
            db.add(
                ParserError(
                    source_batch_id=batch.id,
                    line_number=issue.line_number,
                    error_code=issue.error_code,
                    detail=_bounded_detail(issue.detail),
                )
            )
        for asset_id, last_observed in observed_assets.items():
            asset = db.get(Asset, asset_id)
            if asset and (
                asset.last_observed_at is None or last_observed > _as_utc(asset.last_observed_at)
            ):
                asset.last_observed_at = last_observed
        batch.accepted_records = accepted
        batch.duplicate_records = duplicates
        db.add(
            AuditEvent(
                action="telemetry.import",
                outcome=batch.status,
                detail=(
                    f"{source_type.value} accepted={accepted} "
                    f"duplicates={duplicates} errors={len(issues)}"
                ),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ImportResult(
        batch.id,
        source_type.value,
        digest,
        len(lines),
        accepted,
        duplicates,
        len(issues),
        False,
        batch.status,
    )


def source_health(db: Session, now: datetime | None = None) -> list[SourceHealth]:
    observed_now = _as_utc(now or utcnow())
    result: list[SourceHealth] = []
    for source_type in SourceType:
        latest = db.scalar(
            select(SourceBatch)
            .where(SourceBatch.source_type == source_type.value)
            .order_by(SourceBatch.imported_at.desc(), SourceBatch.id.desc())
        )
        successful = db.scalar(
            select(SourceBatch)
            .where(
                SourceBatch.source_type == source_type.value,
                SourceBatch.status == "SUCCESS",
            )
            .order_by(SourceBatch.imported_at.desc(), SourceBatch.id.desc())
        )
        latest_timestamp = db.scalar(
            select(func.max(Event.timestamp_utc)).where(Event.source_type == source_type.value)
        )
        event_count = int(
            db.scalar(
                select(func.count())
                .select_from(Event)
                .where(Event.source_type == source_type.value)
            )
            or 0
        )
        error_count = int(
            db.scalar(
                select(func.count())
                .select_from(ParserError)
                .join(SourceBatch)
                .where(SourceBatch.source_type == source_type.value)
            )
            or 0
        )
        high_priority = db.scalar(
            select(Event)
            .where(
                Event.source_type == source_type.value,
                Event.severity.in_(("HIGH", "CRITICAL")),
            )
            .order_by(Event.timestamp_utc.desc())
        )
        if latest is not None and latest.status == "ERROR":
            state = "ERROR"
        elif latest_timestamp is None:
            state = "STALE"
        elif observed_now - _as_utc(latest_timestamp) > timedelta(
            hours=settings.source_stale_hours
        ):
            state = "STALE"
        else:
            state = "FRESH"
        result.append(
            SourceHealth(
                source_type.value,
                state,
                successful,
                latest,
                _as_utc(latest_timestamp) if latest_timestamp else None,
                event_count,
                error_count,
                high_priority,
            )
        )
    return result


def reset_disposable(
    database_url: str,
    confirmation: str,
    allowed_root: Path = Path("data/disposable"),
) -> Path:
    if confirmation != "RESET-DISPOSABLE":
        raise ValueError("RESET_CONFIRMATION_REFUSED")
    url = make_url(database_url)
    if url.drivername != "sqlite" or not url.database or url.database == ":memory:":
        raise ValueError("RESET_REQUIRES_FILE_SQLITE")
    target = Path(url.database).resolve()
    exact_target = (allowed_root.resolve() / "telemetry-demo.db").resolve()
    active_database = make_url(settings.database_url).database
    active_target = Path(active_database).resolve() if active_database else None
    if target != exact_target or target == active_target:
        raise ValueError("RESET_TARGET_REFUSED")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    config = Config("alembic.ini")
    config.attributes["database_url"] = f"sqlite:///{target.as_posix()}"
    command.upgrade(config, "head")
    from sqlalchemy import create_engine

    reset_engine = create_engine(f"sqlite:///{target.as_posix()}")
    with Session(reset_engine) as db:
        db.add(
            AuditEvent(
                action="telemetry.reset",
                outcome="SUCCESS",
                detail="exact disposable target initialized",
            )
        )
        db.commit()
    reset_engine.dispose()
    return target


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Bounded telemetry operations")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("seed-assets")
    subparsers.add_parser("summary")
    importer = subparsers.add_parser("import")
    importer.add_argument("--source", choices=[item.value for item in SourceType], required=True)
    importer.add_argument("--path", type=Path, required=True)
    reset = subparsers.add_parser("reset-disposable")
    reset.add_argument("--database-url", required=True)
    reset.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.command == "reset-disposable":
        target = reset_disposable(args.database_url, args.confirm)
        print(json.dumps({"reset": "complete", "target": target.name}, sort_keys=True))
        return
    with SessionLocal() as db:
        if args.command == "seed-assets":
            assets = seed_assets(db)
            print(json.dumps({"assets": [asset.hostname for asset in assets]}, sort_keys=True))
            return
        if args.command == "summary":
            summary = {
                "assets": int(db.scalar(select(func.count()).select_from(Asset)) or 0),
                "batches": int(db.scalar(select(func.count()).select_from(SourceBatch)) or 0),
                "events": int(db.scalar(select(func.count()).select_from(Event)) or 0),
                "parser_errors": int(db.scalar(select(func.count()).select_from(ParserError)) or 0),
                "source_health": {health.source_type: health.state for health in source_health(db)},
            }
            print(json.dumps(summary, sort_keys=True))
            return
        if args.path.is_absolute():
            raise SystemExit("absolute fixture paths are refused")
        result = import_fixture(db, SourceType(args.source), args.path, args.path.as_posix())
        print(json.dumps(result.__dict__, sort_keys=True))


if __name__ == "__main__":
    _cli()
