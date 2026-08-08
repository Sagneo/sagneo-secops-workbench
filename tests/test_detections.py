import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import detections
from app.detections import (
    ALERT_IDENTITY_LOOKUP_CHUNK_SIZE,
    ALERT_IDENTITY_LOOKUP_MAX_CANDIDATES,
    TARGET_ASSET_ID,
    _candidates,
    _existing_alert_identities,
    evaluate,
    load_rules,
    summary,
)
from app.main import ALLOWED_TRANSITIONS
from app.models import (
    Alert,
    AlertEvent,
    AlertHistory,
    AuditEvent,
    Event,
    Role,
    SourceType,
    UserSession,
)
from app.security import digest_token
from app.telemetry import import_fixture, seed_assets


def _full_fixture(db: Session) -> None:
    seed_assets(db)
    import_fixture(
        db, SourceType.LINUX_AUTH, Path("fixtures/linux/auth.log"), "fixtures/linux/auth.log"
    )
    import_fixture(
        db,
        SourceType.SURICATA_EVE,
        Path("fixtures/suricata/eve.jsonl"),
        "fixtures/suricata/eve.jsonl",
    )
    import_fixture(
        db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth-malformed.log"),
        "fixtures/linux/auth-malformed.log",
    )


def test_exact_strict_rule_set_and_manifest():
    rules = load_rules()
    assert [rule.rule_id for rule in rules] == [
        "AUTH-001",
        "AUTH-002",
        "EVID-001",
        "NET-001",
        "PRIV-001",
    ]
    manifest = json.loads(Path("fixtures/expected/detection-alert-manifest.json").read_text())
    telemetry_rules = [rule for rule in rules if rule.rule_id != "EVID-001"]
    assert manifest["rules"] == {
        rule.rule_id: {
            "version": rule.version,
            "sha256": hashlib.sha256(Path(f"rules/{rule.rule_id}.yaml").read_bytes()).hexdigest(),
        }
        for rule in telemetry_rules
    }
    assert len(Path("rules/EVID-001.yaml").read_bytes()) > 0
    assert manifest["exact_total_alerts"] == sum(manifest["exact_alerts_by_rule"].values())


def test_rule_loader_rejects_extra_rule(tmp_path: Path):
    for source in Path("rules").glob("*.yaml"):
        (tmp_path / source.name).write_bytes(source.read_bytes())
    (tmp_path / "EXTRA-001.yaml").write_text("schema_version: 1.0.0\n")
    with pytest.raises(ValueError, match="EXACTLY_FIVE"):
        load_rules(tmp_path)


def _copy_rules(directory: Path) -> None:
    for source in Path("rules").glob("*.yaml"):
        (directory / source.name).write_bytes(source.read_bytes())


@pytest.mark.parametrize(
    ("filename", "mutation", "error"),
    [
        ("AUTH-001.yaml", lambda text: text + "\ntitle: duplicate\n", "DUPLICATE_KEY"),
        (
            "AUTH-001.yaml",
            lambda text: text.replace(
                "description: Detects repeated failed SSH password attempts by one actor "
                "on the lab endpoint.\n",
                "",
            ),
            "SCHEMA_KEYS",
        ),
        (
            "AUTH-001.yaml",
            lambda text: text.replace("source_type: LINUX_AUTH", "source_type: SURICATA_EVE"),
            "SEMANTICS",
        ),
        (
            "AUTH-001.yaml",
            lambda text: text.replace("  - actor\n", ""),
            "REQUIRED_FIELDS",
        ),
        (
            "PRIV-001.yaml",
            lambda text: text.replace(
                "  kind: sudo_activity", "  kind: sudo_activity\n  threshold: 2"
            ),
            "CONDITION_KEYS",
        ),
    ],
)
def test_rule_loader_rejects_invalid_metadata_and_semantics(
    tmp_path: Path, filename: str, mutation, error: str
):
    _copy_rules(tmp_path)
    path = tmp_path / filename
    path.write_text(mutation(path.read_text()))
    with pytest.raises(ValueError, match=error):
        load_rules(tmp_path)


def _event(index: int, timestamp: datetime, **overrides) -> Event:
    values = {
        "id": f"00000000-0000-0000-0000-{index:012d}",
        "stable_identity": f"{index:064x}",
        "source_type": "LINUX_AUTH",
        "source_batch_id": "10000000-0000-0000-0000-000000000001",
        "asset_id": TARGET_ASSET_ID,
        "timestamp_utc": timestamp,
        "category": "AUTHENTICATION",
        "action": "SSH_PASSWORD",
        "outcome": "FAILURE",
        "severity": "MEDIUM",
        "actor": "boundary-user",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.168.90.20",
        "summary": "Synthetic test event",
        "normalized_data": "{}",
        "raw_reference": f"fixtures/test.log#L{index}",
    }
    values.update(overrides)
    return Event(**values)


def _rule(rule_id: str):
    return next(rule for rule in load_rules() if rule.rule_id == rule_id)


def test_auth_001_threshold_and_window_boundaries():
    rule = _rule("AUTH-001")
    start = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    exact = [
        _event(index + 1, start + timedelta(seconds=offset))
        for index, offset in enumerate((0, 60, 120))
    ]
    assert _candidates(rule, exact[:2]) == []
    assert len(_candidates(rule, exact)) == 1
    assert (
        _candidates(
            rule,
            [
                _event(index + 80, event.timestamp_utc, asset_id="wrong-asset")
                for index, event in enumerate(exact)
            ],
        )
        == []
    )
    assert (
        _candidates(
            rule,
            [
                _event(index + 90, event.timestamp_utc, source_type="SURICATA_EVE")
                for index, event in enumerate(exact)
            ],
        )
        == []
    )
    outside = [
        _event(index + 10, start + timedelta(seconds=offset))
        for index, offset in enumerate((0, 60, 121))
    ]
    assert _candidates(rule, outside) == []


def test_auth_002_threshold_and_window_boundaries():
    rule = _rule("AUTH-002")
    start = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    exact = [
        _event(20, start),
        _event(21, start + timedelta(seconds=1)),
        _event(22, start + timedelta(seconds=300), outcome="SUCCESS"),
    ]
    assert _candidates(rule, [exact[0], exact[2]]) == []
    assert len(_candidates(rule, exact)) == 1
    assert (
        _candidates(
            rule,
            [
                _event(
                    index + 100,
                    event.timestamp_utc,
                    asset_id="wrong-asset",
                    outcome=event.outcome,
                )
                for index, event in enumerate(exact)
            ],
        )
        == []
    )
    assert (
        _candidates(
            rule,
            [
                _event(
                    index + 110,
                    event.timestamp_utc,
                    source_type="SURICATA_EVE",
                    outcome=event.outcome,
                )
                for index, event in enumerate(exact)
            ],
        )
        == []
    )
    outside = [
        _event(23, start),
        _event(24, start + timedelta(seconds=1)),
        _event(25, start + timedelta(seconds=301), outcome="SUCCESS"),
    ]
    assert _candidates(rule, outside) == []


@pytest.mark.parametrize(
    ("rule_id", "base_overrides", "invalid_fields"),
    [
        (
            "PRIV-001",
            {"category": "PRIVILEGE", "action": "SUDO_COMMAND", "outcome": "SUCCESS"},
            {
                "category": "AUTHENTICATION",
                "action": "SSH_PASSWORD",
                "outcome": "FAILURE",
                "source_type": "SURICATA_EVE",
                "asset_id": "1f8476df-89c8-5c99-a910-94aa42b74cc8",
            },
        ),
        (
            "NET-001",
            {
                "source_type": "SURICATA_EVE",
                "category": "NETWORK",
                "action": "NETWORK_ALERT",
                "outcome": "OBSERVED",
                "severity": "HIGH",
            },
            {
                "category": "AUTHENTICATION",
                "action": "FLOW",
                "outcome": "FAILURE",
                "severity": "MEDIUM",
                "source_type": "LINUX_AUTH",
                "asset_id": "1f8476df-89c8-5c99-a910-94aa42b74cc8",
            },
        ),
    ],
)
def test_single_event_rules_have_real_negative_matrix(
    rule_id: str, base_overrides: dict[str, str], invalid_fields: dict[str, str]
):
    rule = _rule(rule_id)
    timestamp = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    assert len(_candidates(rule, [_event(30, timestamp, **base_overrides)])) == 1
    for index, (field, invalid) in enumerate(invalid_fields.items(), start=31):
        overrides = {**base_overrides, field: invalid}
        assert _candidates(rule, [_event(index, timestamp, **overrides)]) == [], field


@pytest.mark.parametrize("rule_id", ["AUTH-001", "AUTH-002", "PRIV-001", "NET-001"])
def test_every_rule_rejects_missing_fields_wrong_source_and_asset(rule_id: str):
    rule = _rule(rule_id)
    timestamp = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    for index, field in enumerate(rule.required_fields, start=50):
        assert _candidates(rule, [_event(index, timestamp, **{field: None})]) == [], field
    assert (
        _candidates(
            rule,
            [_event(70, timestamp, source_type="UNKNOWN")],
        )
        == []
    )
    assert (
        _candidates(
            rule,
            [_event(71, timestamp, asset_id="1f8476df-89c8-5c99-a910-94aa42b74cc8")],
        )
        == []
    )


def test_every_rule_has_complete_actionable_metadata():
    for rule in load_rules():
        assert rule.description
        assert rule.required_fields
        assert rule.detection_rationale
        assert rule.severity_rationale
        assert rule.confidence_rationale
        assert rule.false_positive_context
        assert rule.recommended_action


def test_workflow_is_exactly_two_bounded_paths():
    assert ALLOWED_TRANSITIONS == {
        "NEW": {"IN_TRIAGE"},
        "IN_TRIAGE": {"ESCALATED", "BENIGN"},
        "ESCALATED": {"CLOSED"},
        "BENIGN": {"CLOSED"},
    }


def test_full_evaluation_exact_count_and_replay(telemetry_db: Session):
    _full_fixture(telemetry_db)
    manifest = json.loads(Path("fixtures/expected/detection-alert-manifest.json").read_text())
    first = evaluate(telemetry_db)
    assert first.rules == 5
    assert first.by_rule == {**manifest["exact_alerts_by_rule"], "EVID-001": 0}
    assert first.created == manifest["exact_total_alerts"]
    before = summary(telemetry_db)
    second = evaluate(telemetry_db)
    assert second.created == 0
    assert second.duplicates == manifest["exact_total_alerts"]
    assert summary(telemetry_db) == before
    assert telemetry_db.scalar(select(func.count()).select_from(AlertEvent)) == 1555
    assert telemetry_db.scalar(select(func.count()).select_from(AlertHistory)) == first.created


def test_bulk_identity_lookup_is_bounded_and_query_count_is_deterministic(
    telemetry_db: Session,
):
    engine = telemetry_db.get_bind()
    statements: list[str] = []

    def capture(
        _connection, _cursor, statement, _parameters, _context, _executemany
    ):
        normalized = " ".join(statement.lower().split())
        if (
            normalized.startswith("select ")
            and " from alerts " in normalized
            and "alerts.stable_identity" in normalized.partition(" where ")[2]
        ):
            statements.append(normalized)

    sqlalchemy_event.listen(engine, "before_cursor_execute", capture)
    try:
        assert _existing_alert_identities(telemetry_db, []) == set()
        assert statements == []

        assert _existing_alert_identities(telemetry_db, ["a" * 64]) == set()
        assert len(statements) == 1
        statements.clear()

        identities = [f"{index:064x}" for index in range(666)]
        assert _existing_alert_identities(telemetry_db, identities) == set()
        assert len(statements) == 1
        statements.clear()

        identities = [
            f"{index:064x}" for index in range(ALERT_IDENTITY_LOOKUP_CHUNK_SIZE + 1)
        ]
        assert _existing_alert_identities(telemetry_db, identities) == set()
        assert len(statements) == 2
        statements.clear()

        with pytest.raises(ValueError, match="CANDIDATE_LIMIT_EXCEEDED"):
            _existing_alert_identities(
                telemetry_db,
                ["0" * 64] * (ALERT_IDENTITY_LOOKUP_MAX_CANDIDATES + 1),
            )
        assert statements == []
        assert telemetry_db.scalar(select(func.count()).select_from(Alert)) == 0
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", capture)


def test_bulk_identity_lookup_matches_existing_alert_set(telemetry_db: Session):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    identities = list(
        telemetry_db.scalars(select(Alert.stable_identity).order_by(Alert.stable_identity))
    )
    expected = set(identities[::17])
    requested = list(reversed(sorted(expected))) + ["f" * 64, *list(expected)[:2]]
    assert _existing_alert_identities(telemetry_db, requested) == expected


def test_evaluation_error_remains_caller_rollback_safe(
    telemetry_db: Session, monkeypatch
):
    _full_fixture(telemetry_db)
    audit_count = telemetry_db.scalar(select(func.count()).select_from(AuditEvent))

    def fail_lookup(_db: Session, _identities: list[str]) -> set[str]:
        raise RuntimeError("FORCED_BULK_LOOKUP_FAILURE")

    monkeypatch.setattr(detections, "_existing_alert_identities", fail_lookup)
    with pytest.raises(RuntimeError, match="FORCED_BULK_LOOKUP_FAILURE"):
        evaluate(telemetry_db)
    telemetry_db.rollback()
    assert telemetry_db.scalar(select(func.count()).select_from(Alert)) == 0
    assert telemetry_db.scalar(select(func.count()).select_from(AlertHistory)) == 0
    assert telemetry_db.scalar(select(func.count()).select_from(AuditEvent)) == audit_count


def test_alert_provenance_and_ordering(telemetry_db: Session):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    alerts = telemetry_db.scalars(select(Alert)).all()
    assert alerts
    for alert in alerts:
        assert len(alert.stable_identity) == 64
        assert alert.rule_version.version == "1.0.0"
        timestamps = [link.event.timestamp_utc for link in alert.event_links]
        assert timestamps == sorted(timestamps)
        assert all(link.event.raw_reference.startswith("fixtures/") for link in alert.event_links)


def _login(client, role: Role):
    password = f"test-only-{role.value.lower()}-pass"
    response = client.post(
        "/login",
        data={"username": f"{role.value.lower()}-test", "password": password},
    )
    assert response.status_code == 200


def test_analyst_workflow_csrf_stale_and_audit(client, telemetry_db: Session, users):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    alert = telemetry_db.scalar(select(Alert).order_by(Alert.created_at))
    assert alert is not None
    _login(client, Role.ANALYST)
    page = client.get(f"/alerts/{alert.id}")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    data = {
        "csrf_token": csrf,
        "version": alert.version,
        "next_status": "IN_TRIAGE",
        "scope_impact": "Single synthetic endpoint.",
        "false_positive_context": "Fixture traffic.",
        "disposition_reason": "Needs analyst validation.",
        "recommended_action": "Validate linked events.",
        "analyst_notes": "Initial triage started.",
    }
    assert client.post(f"/alerts/{alert.id}/triage", data=data).status_code == 200
    assert client.post(f"/alerts/{alert.id}/triage", data=data).status_code == 409
    assert (
        telemetry_db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "alert.transition")
        )
        == 1
    )


def test_reviewer_is_server_side_read_only(client, telemetry_db: Session, users):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    alert = telemetry_db.scalar(select(Alert))
    assert alert is not None
    _login(client, Role.REVIEWER)
    page = client.get(f"/alerts/{alert.id}")
    assert page.status_code == 200
    assert "Reviewer access is read-only" in page.text
    raw_session = client.cookies.get("secops_session")
    assert raw_session is not None
    reviewer_session = telemetry_db.scalar(
        select(UserSession).where(UserSession.token_digest == digest_token(raw_session))
    )
    assert reviewer_session is not None
    response = client.post(
        f"/alerts/{alert.id}/triage",
        data={
            "csrf_token": reviewer_session.csrf_token,
            "version": alert.version,
            "next_status": "IN_TRIAGE",
        },
    )
    assert response.status_code == 403


def test_required_checklist_and_invalid_transition(client, telemetry_db: Session, users):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    alert = telemetry_db.scalar(select(Alert))
    assert alert is not None
    _login(client, Role.ANALYST)
    page = client.get(f"/alerts/{alert.id}")
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    assert (
        client.post(
            f"/alerts/{alert.id}/triage",
            data={"csrf_token": csrf, "version": alert.version, "next_status": "CLOSED"},
        ).status_code
        == 422
    )


def test_alert_queue_filters_and_deterministic_complete_pagination(
    client, telemetry_db: Session, users
):
    _full_fixture(telemetry_db)
    evaluate(telemetry_db)
    client.cookies.clear()
    assert client.get("/alerts").status_code == 401
    _login(client, Role.ANALYST)
    first_alert = telemetry_db.scalar(
        select(Alert).order_by(Alert.created_at.desc(), Alert.stable_identity)
    )
    assert first_alert is not None
    first_alert.title = "<script>alert('unsafe')</script>"
    telemetry_db.commit()
    observed: list[str] = []
    for page in range(1, 8):
        response = client.get(f"/alerts?page={page}&page_size=100")
        assert response.status_code == 200
        if page == 1:
            assert "&lt;script&gt;" in response.text
            assert "<script>alert" not in response.text
        observed.extend(re.findall(r'href="/alerts/([^"]+)"', response.text))
    assert len(observed) == 665
    assert len(set(observed)) == 665
    assert client.get("/alerts?page=8&page_size=100").status_code == 404
    assert client.get("/alerts?status=&severity=&rule_id=").status_code == 200

    filtered = client.get("/alerts?status=NEW&severity=HIGH&rule_id=AUTH-001&page=1&page_size=100")
    assert filtered.status_code == 200
    assert "Showing 100 of 404 alert(s)." in filtered.text
    assert 'aria-label="Alert pages"' in filtered.text
    assert "<caption>Deterministic alert results</caption>" in filtered.text
    assert client.get("/alerts?status=NOT_A_STATUS").status_code == 422
    assert client.get("/alerts?severity=UNKNOWN").status_code == 422
    assert client.get("/alerts?rule_id=EVID-001").status_code == 200
    assert client.get("/alerts?rule_id=UNKNOWN-001").status_code == 422
