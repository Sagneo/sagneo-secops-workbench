"""Collection, case, and evidence verification tests."""

import base64
import copy
import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import collection
from app.cases import new_request
from app.collection import (
    ARTIFACT_MAX_BYTES,
    ARTIFACT_TYPES,
    MANIFEST_MAX_BYTES,
    PROFILE_DIGEST,
    PROFILE_DOCUMENT,
    PROTOCOL_MAX_BYTES,
    STDERR_MAX_BYTES,
    TOTAL_MAX_BYTES,
    ArtifactResult,
    CollectionResult,
    FixtureCollector,
    ProcessBoundError,
    SshLabCollector,
    _run_bounded_process,
    _validate_artifacts,
    store_bundle,
    verify_bundle,
)
from app.detections import evaluate
from app.models import (
    Alert,
    AlertStatus,
    Asset,
    EvidenceBundle,
    IncidentCase,
    Role,
    RuleVersion,
    SourceType,
    UserSession,
    VerificationRun,
)
from app.telemetry import import_fixture, seed_assets


def test_fixture_collection_and_independent_tamper_matrix(tmp_path: Path):
    result = FixtureCollector().collect()
    assert tuple(item.name for item in result.artifacts) == ARTIFACT_TYPES
    stored = store_bundle(
        result,
        case_id="00000000-0000-4000-8000-000000000001",
        request_id="00000000-0000-4000-8000-000000000002",
        target_asset_id="00000000-0000-4000-8000-000000000003",
        adapter="fixture",
        root=tmp_path,
    )
    accepted = tmp_path / stored.bundle_id
    accepted_result = verify_bundle(accepted, stored.manifest_sha256)
    assert accepted_result.status == "PASS", accepted_result.reason_codes

    missing = tmp_path / "missing"
    shutil.copytree(accepted, missing)
    (missing / "artifacts" / "system.txt").unlink()
    assert verify_bundle(missing, stored.manifest_sha256).reason_codes == ("ARTIFACT_MISSING",)

    extra = tmp_path / "extra"
    shutil.copytree(accepted, extra)
    (extra / "artifacts" / "unexpected.txt").write_text("unexpected")
    assert verify_bundle(extra, stored.manifest_sha256).reason_codes == ("ARTIFACT_EXTRA",)

    modified = tmp_path / "modified"
    shutil.copytree(accepted, modified)
    (modified / "artifacts" / "network.txt").write_text("modified")
    assert verify_bundle(modified, stored.manifest_sha256).reason_codes == ("ARTIFACT_MODIFIED",)
    assert verify_bundle(accepted, stored.manifest_sha256).status == "PASS"


def _stored_fixture(tmp_path: Path):
    result = FixtureCollector().collect()
    stored = store_bundle(
        result,
        case_id="00000000-0000-4000-8000-000000000001",
        request_id="00000000-0000-4000-8000-000000000002",
        target_asset_id="00000000-0000-4000-8000-000000000003",
        adapter="fixture",
        root=tmp_path,
    )
    root = tmp_path / stored.bundle_id
    manifest = json.loads((root / "manifest.json").read_text())
    return root, manifest, stored.manifest_sha256


def _write_manifest(root: Path, manifest: dict[str, object]) -> str:
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    (root / "manifest.json").write_text(content, encoding="utf-8", newline="\n")
    return hashlib.sha256(content.encode()).hexdigest()


def _artifact_mutation(
    index: int,
    key: str,
    value: object,
) -> Callable[[dict[str, object]], None]:
    def mutate(manifest: dict[str, object]) -> None:
        artifacts = manifest["artifacts"]
        assert isinstance(artifacts, list)
        item = artifacts[index]
        assert isinstance(item, dict)
        item[key] = value

    return mutate


def _artifact_remove_key(index: int, key: str) -> Callable[[dict[str, object]], None]:
    def mutate(manifest: dict[str, object]) -> None:
        artifacts = manifest["artifacts"]
        assert isinstance(artifacts, list)
        item = artifacts[index]
        assert isinstance(item, dict)
        item.pop(key)

    return mutate


@pytest.mark.parametrize(
    "mutate",
    [
        _artifact_mutation(0, "path", "../outside.txt"),
        _artifact_mutation(0, "path", "C:\\outside.txt"),
        _artifact_mutation(0, "path", "\\\\server\\share\\outside.txt"),
        _artifact_mutation(0, "path", "artifacts\\utc_time.txt"),
        _artifact_mutation(0, "path", "/artifacts/utc_time.txt"),
        _artifact_mutation(0, "path", "artifacts/nested/utc_time.txt"),
        _artifact_mutation(0, "path", "artifacts/./utc_time.txt"),
        _artifact_mutation(0, "path", "artifacts/utc_time.txt\u0000"),
        _artifact_mutation(0, "name", "unknown"),
        _artifact_mutation(1, "name", ARTIFACT_TYPES[0]),
        _artifact_mutation(1, "path", f"artifacts/{ARTIFACT_TYPES[0]}.txt"),
        _artifact_mutation(0, "size_bytes", "1"),
        _artifact_mutation(0, "size_bytes", 0),
        _artifact_mutation(0, "size_bytes", ARTIFACT_MAX_BYTES + 1),
        _artifact_mutation(0, "sha256", "A" * 64),
        _artifact_mutation(0, "sha256", "0" * 63),
        _artifact_mutation(0, "unknown", True),
        _artifact_remove_key(0, "sha256"),
        lambda manifest: manifest.update({"unknown": True}),
        lambda manifest: manifest.pop("errors"),
        lambda manifest: manifest.update({"errors": "none"}),
        lambda manifest: manifest.update({"bundle_id": "not-a-uuid"}),
        lambda manifest: manifest.update({"adapter": "unknown"}),
        lambda manifest: manifest.update({"started_at": "not-a-timestamp"}),
        lambda manifest: manifest.update(
            {"target": {"hostname": "other", "ip": "192.168.90.20"}}
        ),
        lambda manifest: manifest.update({"artifacts": {}}),
        lambda manifest: manifest.update(
            {
                "profile": {
                    "id": "other",
                    "version": "1.0.0",
                    "digest": PROFILE_DIGEST,
                }
            }
        ),
        lambda manifest: manifest.update(
            {
                "limits": {
                    **PROFILE_DOCUMENT["limits"],
                    "total_max_bytes": TOTAL_MAX_BYTES + 1,
                }
            }
        ),
    ],
    ids=[
        "posix-traversal",
        "windows-drive",
        "unc",
        "alternate-separator",
        "absolute",
        "nested",
        "dot-segment",
        "control-character",
        "unknown-name",
        "duplicate-name",
        "duplicate-path",
        "wrong-size-type",
        "zero-size",
        "oversize-declaration",
        "uppercase-hash",
        "short-hash",
        "artifact-extra-key",
        "artifact-missing-key",
        "extra-key",
        "missing-key",
        "wrong-errors-type",
        "wrong-id",
        "wrong-adapter",
        "wrong-timestamp",
        "wrong-target",
        "wrong-artifacts-type",
        "wrong-profile",
        "wrong-limit",
    ],
)
def test_manifest_schema_rejects_before_any_artifact_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, object]], None],
):
    root, original, _digest = _stored_fixture(tmp_path)
    manifest = copy.deepcopy(original)
    mutate(manifest)
    digest = _write_manifest(root, manifest)
    artifact_reads: list[Path] = []
    original_open = os.open

    def tracked_open(path: os.PathLike[str] | str, *args: object, **kwargs: object):
        candidate = Path(path)
        if candidate.name != "manifest.json":
            artifact_reads.append(candidate)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(collection.os, "open", tracked_open)
    result = verify_bundle(root, digest)
    assert result.status == "FAIL"
    assert "MANIFEST_INVALID" in result.reason_codes
    assert artifact_reads == []


def test_manifest_rejects_duplicate_json_key_before_artifact_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root, _manifest, _digest = _stored_fixture(tmp_path)
    path = root / "manifest.json"
    content = path.read_text()
    content = content.replace("{", '{"schema_version":"1.0.0",', 1)
    path.write_text(content)
    digest = hashlib.sha256(content.encode()).hexdigest()
    monkeypatch.setattr(
        collection,
        "_stream_hash",
        lambda _path, _limit: pytest.fail(
            "artifact read attempted for invalid manifest"
        ),
    )
    result = verify_bundle(root, digest)
    assert "MANIFEST_INVALID" in result.reason_codes


def test_manifest_size_is_bounded_before_json_parse(tmp_path: Path):
    root, _manifest, _digest = _stored_fixture(tmp_path)
    content = b"{" + b" " * MANIFEST_MAX_BYTES
    (root / "manifest.json").write_bytes(content)
    result = verify_bundle(root, hashlib.sha256(content).hexdigest())
    assert result.reason_codes == ("MANIFEST_TOO_LARGE",)


def test_manifest_noncanonical_encoding_is_rejected(tmp_path: Path):
    root, manifest, _digest = _stored_fixture(tmp_path)
    content = json.dumps(manifest, indent=2).encode()
    (root / "manifest.json").write_bytes(content)
    result = verify_bundle(root, hashlib.sha256(content).hexdigest())
    assert "MANIFEST_INVALID" in result.reason_codes


def test_symlink_artifact_is_rejected_without_following(tmp_path: Path):
    root, _manifest, digest = _stored_fixture(tmp_path)
    artifact = root / "artifacts" / "system.txt"
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    artifact.unlink()
    try:
        artifact.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    result = verify_bundle(root, digest)
    assert "ARTIFACT_UNSAFE" in result.reason_codes


def test_unsafe_file_fallback_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, _manifest, digest = _stored_fixture(tmp_path)
    original = collection._safe_regular_info

    def reject_system(path: Path):
        if path.name == "system.txt":
            raise ValueError("UNSAFE_FILE")
        return original(path)

    monkeypatch.setattr(collection, "_safe_regular_info", reject_system)
    result = verify_bundle(root, digest)
    assert "ARTIFACT_UNSAFE" in result.reason_codes


def test_hard_link_artifact_is_rejected_when_supported(tmp_path: Path):
    root, _manifest, digest = _stored_fixture(tmp_path)
    source = root / "artifacts" / "system.txt"
    outside_link = tmp_path / "hardlink.txt"
    try:
        os.link(source, outside_link)
    except OSError:
        pytest.skip("hard links are unavailable on this platform")
    result = verify_bundle(root, digest)
    assert "ARTIFACT_UNSAFE" in result.reason_codes


def _sized_result(sizes: list[int]) -> CollectionResult:
    return CollectionResult(
        tuple(
            ArtifactResult(name, bytes([position + 1]) * size)
            for position, (name, size) in enumerate(zip(ARTIFACT_TYPES, sizes, strict=True))
        ),
        datetime.now(UTC),
        datetime.now(UTC),
    )


def test_artifact_and_aggregate_exact_limits_are_accepted(tmp_path: Path):
    sizes = [ARTIFACT_MAX_BYTES] * 4 + [ARTIFACT_MAX_BYTES - 3] + [1, 1, 1]
    result = _sized_result(sizes)
    _validate_artifacts(result.artifacts)
    stored = store_bundle(
        result,
        case_id="00000000-0000-4000-8000-000000000001",
        request_id="00000000-0000-4000-8000-000000000002",
        target_asset_id="00000000-0000-4000-8000-000000000003",
        adapter="fixture",
        root=tmp_path,
    )
    assert sum(sizes) == TOTAL_MAX_BYTES
    root = tmp_path / stored.bundle_id
    assert verify_bundle(root, stored.manifest_sha256).status == "PASS"
    with (root / "artifacts" / "ssh_config_metadata.txt").open("ab") as handle:
        handle.write(b"x")
    assert verify_bundle(root, stored.manifest_sha256).reason_codes == (
        "ARTIFACT_MODIFIED",
    )


def test_artifact_one_over_limit_stream_fails(tmp_path: Path):
    root, manifest, _digest = _stored_fixture(tmp_path)
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list) and isinstance(artifacts[0], dict)
    artifacts[0]["size_bytes"] = ARTIFACT_MAX_BYTES
    artifacts[0]["sha256"] = hashlib.sha256(b"x" * ARTIFACT_MAX_BYTES).hexdigest()
    digest = _write_manifest(root, manifest)
    (root / "artifacts" / "utc_time.txt").write_bytes(
        b"x" * (ARTIFACT_MAX_BYTES + 1)
    )
    result = verify_bundle(root, digest)
    assert result.reason_codes == ("ARTIFACT_MODIFIED",)


def test_aggregate_one_over_limit_is_rejected():
    sizes = [ARTIFACT_MAX_BYTES] * 4 + [ARTIFACT_MAX_BYTES - 2] + [1, 1, 1]
    result = _sized_result(sizes)
    assert sum(sizes) == TOTAL_MAX_BYTES + 1
    with pytest.raises(ValueError, match="COLLECTION_TOTAL_SIZE_INVALID"):
        _validate_artifacts(result.artifacts)


@pytest.mark.parametrize(
    ("stream", "code"),
    [("stdout", "STDOUT_LIMIT"), ("stderr", "STDERR_LIMIT")],
)
def test_process_stream_overflow_terminates_and_reaps_child(
    monkeypatch: pytest.MonkeyPatch, stream: str, code: str
):
    real_popen = subprocess.Popen
    observed: list[subprocess.Popen[bytes]] = []

    def capture_popen(*args: object, **kwargs: object):
        process = real_popen(*args, **kwargs)
        observed.append(process)
        return process

    monkeypatch.setattr(collection.subprocess, "Popen", capture_popen)
    script = (
        "import os,time\n"
        f"fd={1 if stream == 'stdout' else 2}\n"
        "while True:\n"
        " os.write(fd,b'x'*65536)\n"
        " time.sleep(0.001)\n"
    )
    with pytest.raises(ProcessBoundError, match=code):
        _run_bounded_process(
            [sys.executable, "-c", script],
            stdout_limit=1024,
            stderr_limit=1024,
            timeout=5,
        )
    assert observed and observed[0].poll() is not None


def test_process_timeout_terminates_and_reaps_child(monkeypatch: pytest.MonkeyPatch):
    real_popen = subprocess.Popen
    observed: list[subprocess.Popen[bytes]] = []

    def capture_popen(*args: object, **kwargs: object):
        process = real_popen(*args, **kwargs)
        observed.append(process)
        return process

    monkeypatch.setattr(collection.subprocess, "Popen", capture_popen)
    started = time.monotonic()
    with pytest.raises(ProcessBoundError, match="TIMEOUT"):
        _run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout_limit=1024,
            stderr_limit=1024,
            timeout=0.1,
        )
    assert time.monotonic() - started < 3
    assert observed and observed[0].poll() is not None


def test_ssh_protocol_rejects_malformed_incomplete_and_oversized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    key = tmp_path / "key"
    known = tmp_path / "known"
    key.write_text("test")
    known.write_text("test")
    collector = SshLabCollector(ssh_key=key, known_hosts=known)
    for output in (
        b'{"name":"utc_time"}\n',
        b"\n".join(
            json.dumps({"name": name, "content_b64": "eA=="}).encode()
            for name in ARTIFACT_TYPES[:-1]
        ),
    ):
        monkeypatch.setattr(
            collection,
            "_run_bounded_process",
            lambda *_args, output=output, **_kwargs: (0, output, b""),
        )
        with pytest.raises(RuntimeError, match="PROTOCOL_INVALID"):
            collector.collect()
    monkeypatch.setattr(
        collection,
        "_run_bounded_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ProcessBoundError("STDOUT_LIMIT")
        ),
    )
    with pytest.raises(RuntimeError, match="STDOUT_LIMIT"):
        collector.collect()


def test_ssh_protocol_aggregate_exact_and_one_over(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    key = tmp_path / "key"
    known = tmp_path / "known"
    key.write_text("test")
    known.write_text("test")
    collector = SshLabCollector(ssh_key=key, known_hosts=known)
    exact_sizes = [ARTIFACT_MAX_BYTES] * 4 + [ARTIFACT_MAX_BYTES - 3] + [1, 1, 1]

    def protocol(sizes: list[int]) -> bytes:
        return b"\n".join(
            json.dumps(
                {
                    "name": name,
                    "content_b64": base64.b64encode(b"x" * size).decode(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            for name, size in zip(ARTIFACT_TYPES, sizes, strict=True)
        )

    exact = protocol(exact_sizes)
    monkeypatch.setattr(
        collection,
        "_run_bounded_process",
        lambda *_args, **_kwargs: (0, exact, b""),
    )
    assert sum(len(item.content) for item in collector.collect().artifacts) == TOTAL_MAX_BYTES
    over = protocol(exact_sizes[:4] + [exact_sizes[4] + 1] + exact_sizes[5:])
    monkeypatch.setattr(
        collection,
        "_run_bounded_process",
        lambda *_args, **_kwargs: (0, over, b""),
    )
    with pytest.raises(RuntimeError, match="PROTOCOL_INVALID"):
        collector.collect()


def test_protocol_cap_is_derived_from_decoded_total():
    assert PROTOCOL_MAX_BYTES > 4 * ((TOTAL_MAX_BYTES + 2) // 3)
    assert PROTOCOL_MAX_BYTES < 8 * 1024 * 1024
    assert STDERR_MAX_BYTES == 65_536


def test_wrapper_overflow_timeout_and_no_partial_protocol(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    namespace = runpy.run_path("collectors/linux-ir-lite-v1")
    run_bounded = namespace["run_bounded_command"]
    with pytest.raises(namespace["ProcessBoundError"]):
        run_bounded(
            (sys.executable, "-c", "import sys; sys.stdout.write('x'*4096)"),
            32,
            timeout=2,
        )
    with pytest.raises(namespace["ProcessBoundError"]):
        run_bounded(
            (sys.executable, "-c", "import time; time.sleep(60)"),
            32,
            timeout=0.1,
        )
    main = namespace["main"]
    main.__globals__["MAX_BYTES"] = 32
    main.__globals__["MAX_TOTAL"] = 64
    main.__globals__["COMMANDS"] = (
        ("utc_time", ((sys.executable, "-c", "print('ok')"),)),
        ("system", ((sys.executable, "-c", "print('x'*128)"),)),
    )
    monkeypatch.setattr(sys, "argv", ["linux-ir-lite-v1"])
    assert main() == 66
    assert capsys.readouterr().out == ""


def test_collection_limits_reject_oversize():
    result = CollectionResult(
        tuple(
            ArtifactResult(name, b"x" * (1_048_577 if name == "system" else 1))
            for name in ARTIFACT_TYPES
        ),
        datetime.now(UTC),
        datetime.now(UTC),
    )
    collector = FixtureCollector()
    collector.collect = lambda: result  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="COLLECTION_ARTIFACT_SIZE_INVALID"):
        from app.collection import _validate_artifacts

        _validate_artifacts(result.artifacts)


def test_ssh_adapter_uses_fixed_hardened_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    key = tmp_path / "key"
    known = tmp_path / "known_hosts"
    key.write_text("test")
    known.write_text("test")
    output = b"\n".join(
        json.dumps(
            {
                "name": name,
                "content_b64": base64.b64encode(f"{name}\n".encode()).decode(),
            }
        ).encode()
        for name in ARTIFACT_TYPES
    )
    observed: list[str] = []

    def fake_run(
        command: list[str],
        **_: object,
    ) -> tuple[int, bytes, bytes]:
        observed.extend(command)
        return 0, output, b""

    monkeypatch.setattr(collection, "_run_bounded_process", fake_run)
    result = SshLabCollector(ssh_key=key, known_hosts=known).collect()
    assert len(result.artifacts) == len(ARTIFACT_TYPES)
    assert observed[-1] == "secopscollector@192.168.90.20"
    assert "StrictHostKeyChecking=yes" in observed
    assert "ClearAllForwardings=yes" in observed
    assert "PasswordAuthentication=no" in observed
    assert all(";" not in item for item in observed)


def _login(client, role: Role) -> None:
    response = client.post(
        "/login",
        data={
            "username": f"{role.value.lower()}-test",
            "password": f"test-only-{role.value.lower()}-pass",
        },
    )
    assert response.status_code == 200


def _csrf(db: Session, role: Role) -> str:
    return db.scalar(
        select(UserSession)
        .join(UserSession.user)
        .where(UserSession.user.has(role=role.value))
        .order_by(UserSession.created_at.desc())
    ).csrf_token


def test_case_and_reviewer_gate_enforce_roles_and_stale_versions(
    client, telemetry_db: Session, users
):
    db = telemetry_db
    analyst, _reviewer = users
    asset = Asset(
        id="a94c7196-3d3b-5029-90bf-a2c5a07f46c7",
        hostname="linux-endpoint-01",
        operating_system="Ubuntu",
        lab_ip="192.168.90.20",
        purpose_owner="collection test",
        criticality="MEDIUM",
    )
    rule = RuleVersion(
        rule_id="PRIV-001",
        version="collection-test",
        title="Test privilege alert",
        severity="MEDIUM",
        confidence="MEDIUM",
        source_type="LINUX_AUTH",
        content_digest="a" * 64,
        definition="{}",
    )
    db.add_all([asset, rule])
    db.flush()
    alert = Alert(
        stable_identity="b" * 64,
        rule_version_id=rule.id,
        asset_id=asset.id,
        status=AlertStatus.ESCALATED,
        severity="MEDIUM",
        confidence="MEDIUM",
        title="Test",
        explanation="Test",
        trigger_summary="Test",
        disposition_reason="Escalated for collection",
    )
    db.add(alert)
    db.commit()

    _login(client, Role.ANALYST)
    csrf = _csrf(db, Role.ANALYST)
    response = client.post(
        f"/alerts/{alert.id}/cases",
        data={"csrf_token": csrf, "title": "Fixture investigation"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    case = db.scalar(select(IncidentCase).where(IncidentCase.title == "Fixture investigation"))
    assert case is not None and case.status == "OPEN"
    assert (
        client.post(
            f"/cases/{case.id}/transition",
            data={
                "csrf_token": csrf,
                "version": case.version + 1,
                "next_status": "INVESTIGATING",
            },
        ).status_code
        == 409
    )
    response = client.post(
        f"/cases/{case.id}/transition",
        data={
            "csrf_token": csrf,
            "version": case.version,
            "next_status": "INVESTIGATING",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    db.refresh(case)
    assert (
        client.post(
            f"/cases/{case.id}/collections",
            data={
                "csrf_token": "wrong",
                "version": case.version,
                "adapter": "fixture",
            },
        ).status_code
        == 403
    )
    response = client.post(
        f"/cases/{case.id}/collections",
        data={
            "csrf_token": csrf,
            "version": case.version,
            "adapter": "fixture",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    collection = case.collection_requests[0]
    assert collection.profile_digest == PROFILE_DIGEST
    assert collection.target_asset_id == asset.id
    submit = client.post(
        f"/collections/{collection.id}/submit",
        data={"csrf_token": csrf, "version": collection.version},
        follow_redirects=False,
    )
    assert submit.status_code == 303
    db.refresh(collection)

    client.cookies.clear()
    _login(client, Role.REVIEWER)
    reviewer_csrf = _csrf(db, Role.REVIEWER)
    review = client.post(
        f"/collections/{collection.id}/review",
        data={
            "csrf_token": reviewer_csrf,
            "version": collection.version,
            "decision": "APPROVED",
            "reason": "Exact fixed profile and target approved",
        },
        follow_redirects=False,
    )
    assert review.status_code == 303
    db.refresh(collection)
    assert collection.status == "APPROVED"
    assert (
        client.post(
            f"/collections/{collection.id}/execute",
            data={"csrf_token": reviewer_csrf, "version": collection.version},
        ).status_code
        == 403
    )
    collection.status = "FAILED"
    collection.error_summary = "RuntimeError"
    db.commit()
    client.cookies.clear()
    _login(client, Role.ANALYST)
    analyst_csrf = _csrf(db, Role.ANALYST)
    replacement = client.post(
        f"/cases/{case.id}/collections",
        data={
            "csrf_token": analyst_csrf,
            "version": case.version,
            "adapter": "fixture",
        },
        follow_redirects=False,
    )
    assert replacement.status_code == 303
    db.expire_all()
    assert len(db.get(IncidentCase, case.id).collection_requests) == 2


def test_evid_001_creates_one_evidence_linked_alert_and_deduplicates(telemetry_db: Session, users):
    analyst, _reviewer = users
    seed_assets(telemetry_db)
    import_fixture(
        telemetry_db,
        SourceType.LINUX_AUTH,
        Path("fixtures/linux/auth-malformed.log"),
        "fixtures/linux/auth-malformed.log",
    )
    asset = telemetry_db.scalar(select(Asset).where(Asset.hostname == "linux-endpoint-01"))
    case = IncidentCase(
        title="Tamper detection",
        asset_id=asset.id,
        opened_by_user_id=analyst.id,
    )
    telemetry_db.add(case)
    telemetry_db.flush()
    request = new_request(telemetry_db, case, analyst.id, "fixture")
    bundle = EvidenceBundle(
        request_id=request.id,
        case_id=case.id,
        target_asset_id=asset.id,
        adapter="fixture",
        profile_id=request.profile_id,
        profile_version=request.profile_version,
        profile_digest=request.profile_digest,
        root_reference="evidence/test",
        manifest_json="{}\n",
        manifest_sha256="c" * 64,
        collection_status="SUCCEEDED",
        total_bytes=1,
    )
    telemetry_db.add(bundle)
    telemetry_db.flush()
    telemetry_db.add(
        VerificationRun(
            bundle_id=bundle.id,
            case_id=case.id,
            status="FAIL",
            reason_codes_json='["ARTIFACT_MODIFIED"]',
            manifest_sha256="d" * 64,
            verifier_version="1.0.0",
            independent=True,
        )
    )
    telemetry_db.commit()
    first = evaluate(telemetry_db)
    second = evaluate(telemetry_db)
    assert first.by_rule["EVID-001"] == 1
    assert second.by_rule["EVID-001"] == 0
    evid = telemetry_db.scalar(
        select(Alert).join(RuleVersion).where(RuleVersion.rule_id == "EVID-001")
    )
    assert evid is not None and evid.event_links == []
