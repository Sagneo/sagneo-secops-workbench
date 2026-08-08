"""Strict YAML rule loading and deterministic fixture evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from yaml.nodes import MappingNode, Node, SequenceNode  # type: ignore[import-untyped]

from app.db import SessionLocal
from app.models import (
    Alert,
    AlertEvent,
    AlertHistory,
    AuditEvent,
    Event,
    EvidenceAlertLink,
    RuleVersion,
    VerificationRun,
)

RULE_SCHEMA_VERSION = "1.0.0"
EXPECTED_RULE_IDS = {"AUTH-001", "AUTH-002", "PRIV-001", "NET-001", "EVID-001"}
TARGET_ASSET_ID = "a94c7196-3d3b-5029-90bf-a2c5a07f46c7"
ALERT_IDENTITY_LOOKUP_CHUNK_SIZE = 900
ALERT_IDENTITY_LOOKUP_MAX_CANDIDATES = 10_000
TOP_KEYS = {
    "schema_version",
    "rule_id",
    "version",
    "title",
    "description",
    "source_type",
    "severity",
    "confidence",
    "required_fields",
    "condition",
    "detection_rationale",
    "severity_rationale",
    "confidence_rationale",
    "false_positive_context",
    "recommended_action",
}
WINDOW_CONDITION_KEYS = {"kind", "threshold", "window_seconds", "group_by"}
SINGLE_CONDITION_KEYS = {"kind"}
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
RULE_SEMANTICS = {
    "AUTH-001": ("LINUX_AUTH", "repeated_failures"),
    "AUTH-002": ("LINUX_AUTH", "success_after_failures"),
    "PRIV-001": ("LINUX_AUTH", "sudo_activity"),
    "NET-001": ("SURICATA_EVE", "high_suricata"),
    "EVID-001": ("EVIDENCE_VERIFICATION", "verification_failed"),
}
REQUIRED_FIELDS = {
    "AUTH-001": (
        "source_type",
        "asset_id",
        "timestamp_utc",
        "category",
        "action",
        "outcome",
        "actor",
    ),
    "AUTH-002": (
        "source_type",
        "asset_id",
        "timestamp_utc",
        "category",
        "action",
        "outcome",
        "actor",
    ),
    "PRIV-001": (
        "source_type",
        "asset_id",
        "timestamp_utc",
        "category",
        "action",
        "outcome",
        "actor",
    ),
    "NET-001": (
        "source_type",
        "asset_id",
        "timestamp_utc",
        "category",
        "action",
        "outcome",
        "severity",
        "destination_ip",
    ),
    "EVID-001": (
        "source_type",
        "asset_id",
        "timestamp_utc",
        "status",
        "reason_codes",
    ),
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    version: str
    title: str
    description: str
    source_type: str
    severity: str
    confidence: str
    required_fields: tuple[str, ...]
    condition: dict[str, Any]
    detection_rationale: str
    severity_rationale: str
    confidence_rationale: str
    false_positive_context: str
    recommended_action: str
    digest: str
    canonical: str


@dataclass(frozen=True)
class Candidate:
    rule: Rule
    events: tuple[Event, ...]
    explanation: str


@dataclass(frozen=True)
class EvaluationResult:
    rules: int
    candidates: int
    created: int
    duplicates: int
    by_rule: dict[str, int]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _bounded_text(value: Any, field: str, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"RULE_FIELD_INVALID:{field}")
    return " ".join(value.split())


def _reject_duplicate_keys(node: Node, path: str = "$") -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = str(key_node.value)
            if key in seen:
                raise ValueError(f"RULE_DUPLICATE_KEY:{path}.{key}")
            seen.add(key)
            _reject_duplicate_keys(value_node, f"{path}.{key}")
    elif isinstance(node, SequenceNode):
        for index, item in enumerate(node.value):
            _reject_duplicate_keys(item, f"{path}[{index}]")


def _parse_rule(payload: bytes, filename: str) -> dict[str, Any]:
    try:
        node = yaml.compose(payload, Loader=yaml.SafeLoader)
        if node is None:
            raise ValueError(f"RULE_DOCUMENT_EMPTY:{filename}")
        _reject_duplicate_keys(node)
        parsed = yaml.safe_load(payload)
    except yaml.YAMLError as exc:
        raise ValueError(f"RULE_YAML_INVALID:{filename}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"RULE_DOCUMENT_INVALID:{filename}")
    return parsed


def load_rules(directory: Path = Path("rules")) -> tuple[Rule, ...]:
    paths = sorted(directory.glob("*.yaml"))
    if len(paths) != 5:
        raise ValueError("EXACTLY_FIVE_RULE_FILES_REQUIRED")
    rules: list[Rule] = []
    for path in paths:
        payload = path.read_bytes()
        if len(payload) > 16_384:
            raise ValueError("RULE_FILE_TOO_LARGE")
        parsed = _parse_rule(payload, path.name)
        if set(parsed) != TOP_KEYS:
            raise ValueError(f"RULE_SCHEMA_KEYS_INVALID:{path.name}")
        condition = parsed["condition"]
        if not isinstance(condition, dict):
            raise ValueError(f"RULE_CONDITION_INVALID:{path.name}")
        kind = condition.get("kind")
        rule_id = _bounded_text(parsed["rule_id"], "rule_id", 16)
        if rule_id not in EXPECTED_RULE_IDS:
            raise ValueError(f"RULE_ID_INVALID:{path.name}")
        expected_source, expected_kind = RULE_SEMANTICS.get(rule_id, ("", ""))
        if kind != expected_kind or parsed["source_type"] != expected_source:
            raise ValueError(f"RULE_SEMANTICS_INVALID:{path.name}")
        if kind in {"repeated_failures", "success_after_failures"}:
            if (
                set(condition) != WINDOW_CONDITION_KEYS
                or not isinstance(condition.get("threshold"), int)
                or not 2 <= condition["threshold"] <= 10
                or not isinstance(condition.get("window_seconds"), int)
                or not 30 <= condition["window_seconds"] <= 900
                or condition.get("group_by") != "actor"
            ):
                raise ValueError(f"RULE_WINDOW_INVALID:{path.name}")
        elif set(condition) != SINGLE_CONDITION_KEYS:
            raise ValueError(f"RULE_CONDITION_KEYS_INVALID:{path.name}")
        if path.stem != rule_id:
            raise ValueError(f"RULE_FILENAME_MISMATCH:{path.name}")
        version = _bounded_text(parsed["version"], "version", 16)
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
            raise ValueError(f"RULE_VERSION_INVALID:{path.name}")
        severity = _bounded_text(parsed["severity"], "severity", 16)
        confidence = _bounded_text(parsed["confidence"], "confidence", 16)
        if severity not in ALLOWED_SEVERITIES or confidence not in ALLOWED_CONFIDENCE:
            raise ValueError(f"RULE_ENUM_INVALID:{path.name}")
        required_fields = parsed["required_fields"]
        if (
            not isinstance(required_fields, list)
            or tuple(required_fields) != REQUIRED_FIELDS[rule_id]
            or len(required_fields) != len(set(required_fields))
        ):
            raise ValueError(f"RULE_REQUIRED_FIELDS_INVALID:{path.name}")
        if parsed["schema_version"] != RULE_SCHEMA_VERSION:
            raise ValueError(f"RULE_SCHEMA_VERSION_INVALID:{path.name}")
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        rules.append(
            Rule(
                rule_id=rule_id,
                version=version,
                title=_bounded_text(parsed["title"], "title", 160),
                description=_bounded_text(parsed["description"], "description"),
                source_type=expected_source,
                severity=severity,
                confidence=confidence,
                required_fields=tuple(required_fields),
                condition=condition,
                detection_rationale=_bounded_text(
                    parsed["detection_rationale"], "detection_rationale"
                ),
                severity_rationale=_bounded_text(
                    parsed["severity_rationale"], "severity_rationale"
                ),
                confidence_rationale=_bounded_text(
                    parsed["confidence_rationale"], "confidence_rationale"
                ),
                false_positive_context=_bounded_text(
                    parsed["false_positive_context"], "false_positive_context"
                ),
                recommended_action=_bounded_text(
                    parsed["recommended_action"], "recommended_action"
                ),
                digest=hashlib.sha256(payload).hexdigest(),
                canonical=canonical,
            )
        )
    if {rule.rule_id for rule in rules} != EXPECTED_RULE_IDS:
        raise ValueError("EXACT_RULE_IDS_REQUIRED")
    return tuple(sorted(rules, key=lambda rule: rule.rule_id))


def _has_required_fields(rule: Rule, event: Event) -> bool:
    return all(getattr(event, field, None) not in (None, "") for field in rule.required_fields)


def _candidates(rule: Rule, events: list[Event]) -> list[Candidate]:
    if rule.rule_id == "EVID-001":
        return []
    relevant = [
        event
        for event in events
        if event.source_type == rule.source_type
        and event.asset_id == TARGET_ASSET_ID
        and _has_required_fields(rule, event)
    ]
    kind = rule.condition["kind"]
    if kind == "sudo_activity":
        return [
            Candidate(rule, (event,), rule.detection_rationale)
            for event in relevant
            if event.category == "PRIVILEGE"
            and event.action == "SUDO_COMMAND"
            and event.outcome == "SUCCESS"
        ]
    if kind == "high_suricata":
        return [
            Candidate(rule, (event,), rule.detection_rationale)
            for event in relevant
            if event.category == "NETWORK"
            and event.action == "NETWORK_ALERT"
            and event.outcome == "OBSERVED"
            and event.severity == "HIGH"
        ]
    by_actor: dict[str, list[Event]] = defaultdict(list)
    output: list[Candidate] = []
    threshold = int(rule.condition["threshold"])
    window = timedelta(seconds=int(rule.condition["window_seconds"]))
    for event in relevant:
        if event.category != "AUTHENTICATION" or event.action != "SSH_PASSWORD" or not event.actor:
            continue
        history = by_actor[event.actor]
        cutoff = _as_utc(event.timestamp_utc) - window
        history[:] = [item for item in history if _as_utc(item.timestamp_utc) >= cutoff]
        if event.outcome == "FAILURE":
            history.append(event)
            if kind == "repeated_failures" and len(history) >= threshold:
                linked = tuple(history[-threshold:])
                output.append(
                    Candidate(
                        rule,
                        linked,
                        f"{rule.detection_rationale} Observed {threshold} failures within "
                        f"{int(window.total_seconds())} seconds.",
                    )
                )
        elif kind == "success_after_failures" and event.outcome == "SUCCESS":
            if len(history) >= threshold:
                linked = tuple(history[-threshold:] + [event])
                output.append(
                    Candidate(
                        rule,
                        linked,
                        f"{rule.detection_rationale} Observed a success after "
                        f"{len(history[-threshold:])} recent failures.",
                    )
                )
            history.clear()
    return output


def _identity(candidate: Candidate) -> str:
    value = "|".join(
        [candidate.rule.rule_id, candidate.rule.version]
        + [event.stable_identity for event in candidate.events]
    )
    return hashlib.sha256(value.encode()).hexdigest()


def _existing_alert_identities(db: Session, identities: list[str]) -> set[str]:
    if len(identities) > ALERT_IDENTITY_LOOKUP_MAX_CANDIDATES:
        raise ValueError("ALERT_IDENTITY_CANDIDATE_LIMIT_EXCEEDED")
    unique_identities = sorted(set(identities))
    existing: set[str] = set()
    for start in range(0, len(unique_identities), ALERT_IDENTITY_LOOKUP_CHUNK_SIZE):
        chunk = unique_identities[start : start + ALERT_IDENTITY_LOOKUP_CHUNK_SIZE]
        existing.update(
            db.scalars(
                select(Alert.stable_identity)
                .where(Alert.stable_identity.in_(chunk))
                .order_by(Alert.stable_identity)
            )
        )
    return existing


def evaluate(db: Session, directory: Path = Path("rules")) -> EvaluationResult:
    rules = load_rules(directory)
    events = list(db.scalars(select(Event).order_by(Event.timestamp_utc, Event.stable_identity)))
    versions: dict[str, RuleVersion] = {}
    for rule in rules:
        version = db.scalar(
            select(RuleVersion).where(
                RuleVersion.rule_id == rule.rule_id, RuleVersion.version == rule.version
            )
        )
        if version is None:
            version = RuleVersion(
                rule_id=rule.rule_id,
                version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                source_type=rule.source_type,
                content_digest=rule.digest,
                definition=rule.canonical,
            )
            db.add(version)
            db.flush()
        elif version.content_digest != rule.digest or version.definition != rule.canonical:
            raise RuntimeError(f"IMMUTABLE_RULE_VERSION_CONFLICT:{rule.rule_id}")
        versions[rule.rule_id] = version

    all_candidates = [candidate for rule in rules for candidate in _candidates(rule, events)]
    candidate_identities = [
        (candidate, _identity(candidate)) for candidate in all_candidates
    ]
    evidence_rule = next(rule for rule in rules if rule.rule_id == "EVID-001")
    failed_verifications = list(
        db.scalars(
            select(VerificationRun)
            .where(VerificationRun.status == "FAIL")
            .order_by(VerificationRun.created_at, VerificationRun.id)
        )
    )
    verification_identities = [
        (
            verification,
            hashlib.sha256(
                (
                    f"{evidence_rule.rule_id}|{evidence_rule.version}|"
                    f"{verification.id}|{verification.manifest_sha256}"
                ).encode()
            ).hexdigest(),
        )
        for verification in failed_verifications
    ]
    existing_identities = _existing_alert_identities(
        db,
        [identity for _, identity in candidate_identities]
        + [identity for _, identity in verification_identities],
    )
    created = 0
    duplicates = 0
    by_rule: dict[str, int] = {rule.rule_id: 0 for rule in rules}
    for candidate, stable_identity in candidate_identities:
        if stable_identity in existing_identities:
            duplicates += 1
            continue
        anchor = candidate.events[-1]
        rule = candidate.rule
        alert = Alert(
            stable_identity=stable_identity,
            rule_version_id=versions[rule.rule_id].id,
            asset_id=anchor.asset_id,
            severity=rule.severity,
            confidence=rule.confidence,
            title=rule.title,
            explanation=candidate.explanation,
            trigger_summary=f"{len(candidate.events)} linked normalized event(s); "
            f"anchor {anchor.raw_reference}",
            severity_rationale=(
                f"{rule.severity} severity: {rule.severity_rationale} "
                f"{rule.confidence} confidence: {rule.confidence_rationale}"
            ),
            false_positive_context=rule.false_positive_context,
            recommended_action=rule.recommended_action,
        )
        db.add(alert)
        db.flush()
        for position, event in enumerate(candidate.events, start=1):
            db.add(AlertEvent(alert_id=alert.id, event_id=event.id, position=position))
        db.add(
            AlertHistory(
                alert_id=alert.id,
                action="CREATED",
                to_status="NEW",
                detail=f"{rule.rule_id}@{rule.version}",
            )
        )
        created += 1
        by_rule[rule.rule_id] += 1
        existing_identities.add(stable_identity)
    for verification, stable_identity in verification_identities:
        if stable_identity in existing_identities:
            duplicates += 1
            continue
        alert = Alert(
            stable_identity=stable_identity,
            rule_version_id=versions[evidence_rule.rule_id].id,
            asset_id=TARGET_ASSET_ID,
            severity=evidence_rule.severity,
            confidence=evidence_rule.confidence,
            title=evidence_rule.title,
            explanation=evidence_rule.detection_rationale,
            trigger_summary=(
                f"Independent evidence verification failed; verification={verification.id}; "
                f"reasons={verification.reason_codes_json}"
            ),
            severity_rationale=(
                f"{evidence_rule.severity} severity: {evidence_rule.severity_rationale} "
                f"{evidence_rule.confidence} confidence: "
                f"{evidence_rule.confidence_rationale}"
            ),
            false_positive_context=evidence_rule.false_positive_context,
            recommended_action=evidence_rule.recommended_action,
        )
        db.add(alert)
        db.flush()
        db.add(
            EvidenceAlertLink(
                alert_id=alert.id,
                verification_run_id=verification.id,
            )
        )
        db.add(
            AlertHistory(
                alert_id=alert.id,
                action="CREATED",
                to_status="NEW",
                detail=f"{evidence_rule.rule_id}@{evidence_rule.version}",
            )
        )
        created += 1
        by_rule[evidence_rule.rule_id] += 1
        existing_identities.add(stable_identity)
    db.add(
        AuditEvent(
            action="detections.evaluate",
            outcome="SUCCESS",
            detail=(
                f"rules=5 candidates={len(all_candidates) + len(failed_verifications)} "
                f"created={created} duplicates={duplicates}"
            ),
        )
    )
    db.commit()
    return EvaluationResult(
        5,
        len(all_candidates) + len(failed_verifications),
        created,
        duplicates,
        by_rule,
    )


def summary(db: Session) -> dict[str, Any]:
    by_rule = {
        rule_id: count
        for rule_id, count in db.execute(
            select(RuleVersion.rule_id, func.count(Alert.id))
            .join(Alert, Alert.rule_version_id == RuleVersion.id)
            .group_by(RuleVersion.rule_id)
            .order_by(RuleVersion.rule_id)
        )
    }
    return {
        "rules": db.scalar(select(func.count()).select_from(RuleVersion)),
        "alerts": db.scalar(select(func.count()).select_from(Alert)),
        "alert_events": db.scalar(select(func.count()).select_from(AlertEvent)),
        "history": db.scalar(select(func.count()).select_from(AlertHistory)),
        "by_rule": by_rule,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("evaluate", "summary"))
    args = parser.parse_args()
    with SessionLocal() as db:
        result: Any = evaluate(db) if args.command == "evaluate" else summary(db)
        payload = result.__dict__ if hasattr(result, "__dict__") else result
        print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
