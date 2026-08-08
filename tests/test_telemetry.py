import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from alembic import command
from alembic.config import Config
from app.config import settings
from app.models import Asset, Event, ParserError, SourceBatch, SourceType
from app.telemetry import (
    ParseIssue,
    import_fixture,
    normalize_timestamp,
    parse_eve_line,
    parse_linux_line,
    reset_disposable,
    safe_source_reference,
    seed_assets,
    source_health,
)


def _write(path: Path, content: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")
    return path


def test_fixture_manifest_digests_and_counts():
    manifest = json.loads(
        Path("fixtures/expected/telemetry-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["source_types"] == ["LINUX_AUTH", "SURICATA_EVE"]
    assert manifest["assets"] == 2
    assert manifest["main_unique_events"] == 1200
    for relative, expected in manifest["files"].items():
        payload = Path(relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected["sha256"]
        assert len(payload.decode("utf-8").splitlines()) == expected["records"]


def test_assets_are_exact_and_idempotent(telemetry_db: Session):
    seed_assets(telemetry_db)
    seed_assets(telemetry_db)
    assets = telemetry_db.scalars(select(Asset).order_by(Asset.hostname)).all()
    assert [(asset.hostname, asset.lab_ip) for asset in assets] == [
        ("linux-endpoint-01", "192.168.90.20"),
        ("secops-core", "192.168.90.10"),
    ]


def test_timestamp_and_reference_boundaries():
    assert normalize_timestamp("2026-07-24T14:30:00+02:00") == datetime(
        2026, 7, 24, 12, 30, tzinfo=UTC
    )
    with pytest.raises(ValueError, match="TIMESTAMP_REQUIRES_OFFSET"):
        normalize_timestamp("2026-07-24T12:30:00")
    assert safe_source_reference("fixtures/linux/auth.log") == "fixtures/linux/auth.log"
    for unsafe in ("/private/auth.log", "../auth.log", r"fixtures\linux\auth.log"):
        with pytest.raises(ValueError):
            safe_source_reference(unsafe)


def test_parser_event_type_missing_fields_and_asset_correlation(telemetry_db: Session):
    seed_assets(telemetry_db)
    assets = telemetry_db.scalars(select(Asset)).all()
    by_hostname = {asset.hostname: asset for asset in assets}
    by_ip = {asset.lab_ip: asset for asset in assets}
    unknown_linux = parse_linux_line(
        "2026-07-24T12:00:00Z unknown-host sshd[1]: "
        "Failed password for synth-user from 192.0.2.10 port 40000 ssh2",
        1,
        by_hostname,
    )
    assert isinstance(unknown_linux, ParseIssue)
    assert unknown_linux.error_code == "ASSET_NOT_FOUND"
    unsupported = parse_eve_line(
        json.dumps(
            {
                "timestamp": "2026-07-24T12:00:00Z",
                "event_type": "fileinfo",
                "src_ip": "192.0.2.10",
                "dest_ip": "192.168.90.20",
                "proto": "TCP",
            }
        ),
        1,
        by_ip,
    )
    assert isinstance(unsupported, ParseIssue)
    assert unsupported.error_code == "UNSUPPORTED_EVE_TYPE"
    missing_alert = parse_eve_line(
        json.dumps(
            {
                "timestamp": "2026-07-24T12:00:00Z",
                "event_type": "alert",
                "src_ip": "192.0.2.10",
                "dest_ip": "192.168.90.20",
                "proto": "TCP",
            }
        ),
        2,
        by_ip,
    )
    assert isinstance(missing_alert, ParseIssue)
    assert missing_alert.error_code == "MISSING_ALERT_FIELDS"


def test_full_import_replay_and_provenance(telemetry_db: Session):
    seed_assets(telemetry_db)
    linux = import_fixture(
        telemetry_db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth.log"),
        "fixtures/linux/auth.log",
    )
    eve = import_fixture(
        telemetry_db,
        SourceType.SURICATA_EVE,
        Path("fixtures/suricata/eve.jsonl"),
        "fixtures/suricata/eve.jsonl",
    )
    assert (linux.accepted_new, eve.accepted_new) == (600, 600)
    assert telemetry_db.scalar(select(func.count()).select_from(Event)) == 1200
    replay = import_fixture(
        telemetry_db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth.log"),
        "fixtures/linux/auth.log",
    )
    assert replay.replayed_batch
    assert replay.accepted_new == 0
    assert telemetry_db.scalar(select(func.count()).select_from(SourceBatch)) == 2
    assert telemetry_db.scalar(select(func.count()).select_from(Event)) == 1200
    assert all(
        event.timestamp_utc is not None
        and event.asset_id
        and event.raw_reference.startswith("fixtures/")
        and "#L" in event.raw_reference
        for event in telemetry_db.scalars(select(Event))
    )


@pytest.mark.parametrize(
    ("source_type", "path", "reference"),
    [
        (
            SourceType.LINUX_AUTH,
            Path("fixtures/linux/auth-malformed.log"),
            "fixtures/linux/auth-malformed.log",
        ),
        (
            SourceType.SURICATA_EVE,
            Path("fixtures/suricata/eve-malformed.jsonl"),
            "fixtures/suricata/eve-malformed.jsonl",
        ),
    ],
)
def test_malformed_records_are_isolated(
    telemetry_db: Session,
    source_type: SourceType,
    path: Path,
    reference: str,
):
    seed_assets(telemetry_db)
    result = import_fixture(telemetry_db, source_type, path, reference)
    assert (result.accepted_new, result.error_records, result.status) == (1, 2, "ERROR")
    assert telemetry_db.scalar(select(func.count()).select_from(Event)) == 1
    assert telemetry_db.scalar(select(func.count()).select_from(ParserError)) == 2


def test_duplicate_event_suppressed_across_distinct_batches(telemetry_db: Session, tmp_path: Path):
    seed_assets(telemetry_db)
    line = (
        "2026-07-24T13:15:00Z linux-endpoint-01 sshd[9991]: "
        "Failed password for synth-error-user from 192.0.2.240 port 49991 ssh2"
    )
    first = _write(tmp_path / "first.log", f"{line}\n")
    second = _write(tmp_path / "second.log", f"{line}\nmalformed\n")
    assert (
        import_fixture(
            telemetry_db, SourceType.LINUX_AUTH, first, "fixtures/linux/first.log"
        ).accepted_new
        == 1
    )
    result = import_fixture(
        telemetry_db, SourceType.LINUX_AUTH, second, "fixtures/linux/second.log"
    )
    assert (result.accepted_new, result.duplicate_records, result.error_records) == (0, 1, 1)
    assert telemetry_db.scalar(select(func.count()).select_from(Event)) == 1


def test_source_health_fresh_stale_and_error(telemetry_db: Session):
    seed_assets(telemetry_db)
    import_fixture(
        telemetry_db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth.log"),
        "fixtures/linux/auth.log",
    )
    fresh = {
        row.source_type: row
        for row in source_health(telemetry_db, datetime(2026, 7, 24, 13, 0, tzinfo=UTC))
    }
    assert fresh["LINUX_AUTH"].state == "FRESH"
    assert fresh["SURICATA_EVE"].state == "STALE"
    stale = {
        row.source_type: row
        for row in source_health(telemetry_db, datetime(2026, 7, 26, 13, 0, tzinfo=UTC))
    }
    assert stale["LINUX_AUTH"].state == "STALE"
    import_fixture(
        telemetry_db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth-malformed.log"),
        "fixtures/linux/auth-malformed.log",
    )
    error = {row.source_type: row for row in source_health(telemetry_db)}
    assert error["LINUX_AUTH"].state == "ERROR"
    assert error["LINUX_AUTH"].total_errors == 2


def test_file_type_encoding_size_and_line_limits(telemetry_db: Session, tmp_path: Path):
    seed_assets(telemetry_db)
    cases = [
        (_write(tmp_path / "wrong.txt", "x\n"), "UNEXPECTED_FILE_TYPE"),
        (_write(tmp_path / "bad.log", b"\xff\n"), "INVALID_UTF8"),
        (
            _write(tmp_path / "line.log", ("x" * (settings.ingest_max_line_bytes + 1)) + "\n"),
            "LINE_SIZE_OR_ENCODING_OUT_OF_BOUNDS",
        ),
        (
            _write(tmp_path / "large.log", b"x" * (settings.ingest_max_bytes + 1)),
            "FILE_SIZE_OUT_OF_BOUNDS",
        ),
    ]
    for path, message in cases:
        with pytest.raises(ValueError, match=message):
            import_fixture(telemetry_db, SourceType.LINUX_AUTH, path, f"fixtures/linux/{path.name}")


def test_import_transaction_rolls_back_on_database_failure(
    telemetry_db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    seed_assets(telemetry_db)
    path = _write(
        tmp_path / "rollback.log",
        "2026-07-24T13:20:00Z linux-endpoint-01 sshd[9100]: "
        "Failed password for synth-rollback from 192.0.2.210 port 49100 ssh2\n",
    )

    def fail_commit() -> None:
        raise RuntimeError("synthetic commit failure")

    monkeypatch.setattr(telemetry_db, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="synthetic commit failure"):
        import_fixture(telemetry_db, SourceType.LINUX_AUTH, path, "fixtures/linux/rollback.log")
    assert telemetry_db.scalar(select(func.count()).select_from(SourceBatch)) == 0
    assert telemetry_db.scalar(select(func.count()).select_from(Event)) == 0


def test_authenticated_ui_and_safe_rendering(client, telemetry_db: Session, users, tmp_path: Path):
    seed_assets(telemetry_db)
    record = {
        "timestamp": "2026-07-24T13:30:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.230",
        "dest_ip": "192.168.90.20",
        "proto": "TCP",
        "alert": {
            "signature_id": 1,
            "signature": "<script>alert(1)</script>",
            "category": "Synthetic",
            "severity": 1,
        },
    }
    path = _write(tmp_path / "safe.jsonl", json.dumps(record) + "\n")
    import_fixture(telemetry_db, SourceType.SURICATA_EVE, path, "fixtures/suricata/safe.jsonl")
    assert client.get("/sources").status_code == 401
    client.post(
        "/login",
        data={"username": "analyst-test", "password": "test-only-analyst-pass"},
    )
    assert client.get("/sources").status_code == 200
    events = client.get("/events")
    assert events.status_code == 200
    assert b"<script>" not in events.content
    assert b"&lt;script&gt;" in events.content
    event = telemetry_db.scalar(select(Event))
    assert event is not None
    detail = client.get(f"/events/{event.id}")
    assert detail.status_code == 200
    assert b"<script>" not in detail.content


def test_reset_exact_disposable_target_and_refusal(tmp_path: Path):
    allowed = tmp_path / "disposable"
    target = allowed / "telemetry-demo.db"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old disposable content")
    result = reset_disposable(
        f"sqlite:///{target.as_posix()}",
        "RESET-DISPOSABLE",
        allowed_root=allowed,
    )
    assert result == target.resolve()
    engine = create_engine(f"sqlite:///{target.as_posix()}")
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM audit_events WHERE action='telemetry.reset'")
            )
            == 1
        )
    engine.dispose()
    with pytest.raises(ValueError, match="RESET_TARGET_REFUSED"):
        reset_disposable(
            f"sqlite:///{(allowed / 'other.db').as_posix()}",
            "RESET-DISPOSABLE",
            allowed_root=allowed,
        )
    with pytest.raises(ValueError):
        reset_disposable(settings.database_url, "RESET-DISPOSABLE")


def test_migration_upgrades_legacy_database_without_losing_users(tmp_path: Path):
    target = tmp_path / "upgrade.db"
    url = f"sqlite:///{target.as_posix()}"
    config = Config("alembic.ini")
    config.attributes["database_url"] = url
    command.upgrade(config, "0001")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users "
                "(id, username, role, password_hash, active, created_at) "
                "VALUES ('legacy-user', 'synthetic-upgrade', 'ANALYST', "
                "'synthetic-hash', 1, '2026-07-24 00:00:00')"
            )
        )
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM users")) == 1
        assert (
            connection.scalar(
                text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'")
            )
            == 1
        )
    engine.dispose()
