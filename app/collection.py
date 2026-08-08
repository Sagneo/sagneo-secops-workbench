"""Bounded collection adapters, evidence persistence, and verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat

# Fixed executable and argument vector only; shell execution is never used.
import subprocess  # nosec B404
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Protocol, cast
from uuid import UUID, uuid4

from app.config import settings

PROFILE_ID = "linux-ir-lite-v1"
PROFILE_VERSION = "1.0.0"
TARGET_HOSTNAME = "linux-endpoint-01"
TARGET_IP = "192.168.90.20"
TARGET_USER = "secopscollector"
COMMAND_TIMEOUT_SECONDS = 5
ARTIFACT_MAX_BYTES = 1_048_576
TOTAL_MAX_BYTES = 5_242_880
VERIFIER_VERSION = "1.0.0"
MANIFEST_MAX_BYTES = 65_536
STDERR_MAX_BYTES = 65_536
PROTOCOL_OVERHEAD_MAX_BYTES = 16_384
PROTOCOL_MAX_BYTES = (
    4 * ((TOTAL_MAX_BYTES + 2) // 3) + PROTOCOL_OVERHEAD_MAX_BYTES
)
ARTIFACT_TYPES = (
    "utc_time",
    "system",
    "processes",
    "network",
    "failed_services",
    "logins",
    "ssh_sudo_journal",
    "ssh_config_metadata",
)
PROFILE_DOCUMENT = {
    "profile_id": PROFILE_ID,
    "version": PROFILE_VERSION,
    "target": {"hostname": TARGET_HOSTNAME, "ip": TARGET_IP},
    "artifacts": list(ARTIFACT_TYPES),
    "limits": {
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        "artifact_max_bytes": ARTIFACT_MAX_BYTES,
        "total_max_bytes": TOTAL_MAX_BYTES,
    },
    "transport": "stdout-only",
}
PROFILE_CANONICAL = json.dumps(PROFILE_DOCUMENT, sort_keys=True, separators=(",", ":"))
PROFILE_DIGEST = hashlib.sha256(PROFILE_CANONICAL.encode()).hexdigest()
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS = {
    "schema_version",
    "bundle_id",
    "case_id",
    "request_id",
    "target_asset_id",
    "target",
    "adapter",
    "profile",
    "limits",
    "started_at",
    "completed_at",
    "artifacts",
    "errors",
}
_ARTIFACT_KEYS = {"name", "path", "size_bytes", "sha256"}


@dataclass(frozen=True)
class ArtifactResult:
    name: str
    content: bytes


@dataclass(frozen=True)
class CollectionResult:
    artifacts: tuple[ArtifactResult, ...]
    started_at: datetime
    completed_at: datetime


@dataclass(frozen=True)
class StoredBundle:
    bundle_id: str
    root_reference: str
    manifest_json: str
    manifest_sha256: str
    total_bytes: int
    artifacts: tuple[tuple[str, str, int, str], ...]


@dataclass(frozen=True)
class VerificationResult:
    status: str
    reason_codes: tuple[str, ...]
    manifest_sha256: str


class Collector(Protocol):
    adapter_name: str

    def collect(self) -> CollectionResult: ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ProcessBoundError(RuntimeError):
    """A child process crossed a byte or time boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class FileBoundError(ValueError):
    """A file crossed a byte boundary during a bounded read."""


class UnsafeFileError(ValueError):
    """A file is not one unambiguous regular file."""


def _bounded_pipe_reader(
    pipe: BinaryIO,
    limit: int,
    chunks: list[bytes],
    overflow: threading.Event,
) -> None:
    total = 0
    try:
        while True:
            chunk = pipe.read(min(65_536, limit - total + 1))
            if not chunk:
                return
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                overflow.set()
                return
    finally:
        pipe.close()


def _run_bounded_process(
    command: list[str],
    *,
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(  # noqa: S603  # nosec B603
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ProcessBoundError("PIPE_SETUP_FAILED")
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    threads = (
        threading.Thread(
            target=_bounded_pipe_reader,
            args=(process.stdout, stdout_limit, stdout_chunks, stdout_overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_bounded_pipe_reader,
            args=(process.stderr, stderr_limit, stderr_chunks, stderr_overflow),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    failure: str | None = None
    while process.poll() is None:
        if stdout_overflow.is_set():
            failure = "STDOUT_LIMIT"
            break
        if stderr_overflow.is_set():
            failure = "STDERR_LIMIT"
            break
        if time.monotonic() >= deadline:
            failure = "TIMEOUT"
            break
        time.sleep(0.01)
    if failure is not None:
        process.kill()
    process.wait()
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        process.kill()
        process.wait()
        raise ProcessBoundError("PIPE_REAP_FAILED")
    if failure is None and stdout_overflow.is_set():
        failure = "STDOUT_LIMIT"
    if failure is None and stderr_overflow.is_set():
        failure = "STDERR_LIMIT"
    if failure is not None:
        raise ProcessBoundError(failure)
    return process.returncode, b"".join(stdout_chunks), b"".join(stderr_chunks)


def _open_regular_file(path: Path) -> BinaryIO:
    before = _safe_regular_info(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or _has_reparse_point(after)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise UnsafeFileError("UNSAFE_FILE")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _read_file_bounded(path: Path, limit: int) -> bytes:
    with _open_regular_file(path) as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise FileBoundError("FILE_SIZE_LIMIT")
    return content


def _validate_artifacts(artifacts: tuple[ArtifactResult, ...]) -> None:
    if tuple(item.name for item in artifacts) != ARTIFACT_TYPES:
        raise ValueError("COLLECTION_ARTIFACT_SET_INVALID")
    total = 0
    for item in artifacts:
        if not item.content or len(item.content) > ARTIFACT_MAX_BYTES:
            raise ValueError(f"COLLECTION_ARTIFACT_SIZE_INVALID:{item.name}")
        total += len(item.content)
    if total > TOTAL_MAX_BYTES:
        raise ValueError("COLLECTION_TOTAL_SIZE_INVALID")


class FixtureCollector:
    adapter_name = "fixture"

    def __init__(self, root: Path = Path("fixtures/collection/linux-ir-lite-v1")):
        self.root = root

    def collect(self) -> CollectionResult:
        started = _utcnow()
        artifacts = tuple(
            ArtifactResult(
                name,
                _read_file_bounded(self.root / f"{name}.txt", ARTIFACT_MAX_BYTES),
            )
            for name in ARTIFACT_TYPES
        )
        _validate_artifacts(artifacts)
        return CollectionResult(artifacts, started, _utcnow())


class SshLabCollector:
    adapter_name = "ssh-lab"

    def __init__(
        self,
        *,
        ssh_key: Path | None = None,
        known_hosts: Path | None = None,
        ssh_binary: str = "ssh",
    ):
        self.ssh_key = ssh_key or Path(settings.collector_ssh_key)
        self.known_hosts = known_hosts or Path(settings.collector_known_hosts)
        self.ssh_binary = ssh_binary

    def collect(self) -> CollectionResult:
        started = _utcnow()
        command = [
            self.ssh_binary,
            "-T",
            "-i",
            str(self.ssh_key),
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ConnectTimeout=5",
            f"{TARGET_USER}@{TARGET_IP}",
        ]
        try:
            returncode, stdout, stderr = _run_bounded_process(
                command,
                timeout=COMMAND_TIMEOUT_SECONDS * len(ARTIFACT_TYPES) + 5,
                stdout_limit=PROTOCOL_MAX_BYTES,
                stderr_limit=STDERR_MAX_BYTES,
            )
        except ProcessBoundError as exc:
            raise RuntimeError(f"SSH_COLLECTION_{exc.code}") from exc
        if returncode != 0:
            raise RuntimeError("SSH_COLLECTION_FAILED")
        if stderr:
            raise RuntimeError("SSH_COLLECTION_STDERR_REJECTED")
        parsed: list[ArtifactResult] = []
        total = 0
        try:
            raw_lines = stdout.splitlines()
            if len(raw_lines) != len(ARTIFACT_TYPES):
                raise ValueError
            for position, raw_line in enumerate(raw_lines):
                if len(raw_line) > 4 * ((ARTIFACT_MAX_BYTES + 2) // 3) + 128:
                    raise ValueError
                record = json.loads(raw_line)
                if set(record) != {"name", "content_b64"}:
                    raise ValueError
                if not isinstance(record["name"], str) or not isinstance(
                    record["content_b64"], str
                ):
                    raise ValueError
                name = record["name"]
                if name != ARTIFACT_TYPES[position]:
                    raise ValueError
                content = base64.b64decode(record["content_b64"], validate=True)
                if not content or len(content) > ARTIFACT_MAX_BYTES:
                    raise ValueError
                total += len(content)
                if total > TOTAL_MAX_BYTES:
                    raise ValueError
                parsed.append(ArtifactResult(name, content))
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("SSH_COLLECTION_PROTOCOL_INVALID") from exc
        artifacts = tuple(parsed)
        _validate_artifacts(artifacts)
        return CollectionResult(artifacts, started, _utcnow())


def store_bundle(
    result: CollectionResult,
    *,
    case_id: str,
    request_id: str,
    target_asset_id: str,
    adapter: str,
    root: Path | None = None,
) -> StoredBundle:
    evidence_root = root or Path(settings.evidence_root)
    evidence_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    bundle_id = str(uuid4())
    partial = evidence_root / f".{bundle_id}.partial"
    final = evidence_root / bundle_id
    partial.mkdir(mode=0o700)
    artifacts_dir = partial / "artifacts"
    artifacts_dir.mkdir(mode=0o700)
    artifact_manifest: list[dict[str, object]] = []
    stored: list[tuple[str, str, int, str]] = []
    try:
        for item in result.artifacts:
            relative = f"artifacts/{item.name}.txt"
            digest = hashlib.sha256(item.content).hexdigest()
            path = partial / relative
            path.write_bytes(item.content)
            os.chmod(path, 0o600)
            artifact_manifest.append(
                {
                    "name": item.name,
                    "path": relative,
                    "size_bytes": len(item.content),
                    "sha256": digest,
                }
            )
            stored.append((relative, item.name, len(item.content), digest))
        manifest = {
            "schema_version": "1.0.0",
            "bundle_id": bundle_id,
            "case_id": case_id,
            "request_id": request_id,
            "target_asset_id": target_asset_id,
            "target": {"hostname": TARGET_HOSTNAME, "ip": TARGET_IP},
            "adapter": adapter,
            "profile": {
                "id": PROFILE_ID,
                "version": PROFILE_VERSION,
                "digest": PROFILE_DIGEST,
            },
            "limits": PROFILE_DOCUMENT["limits"],
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat(),
            "artifacts": artifact_manifest,
            "errors": [],
        }
        manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        manifest_digest = hashlib.sha256(manifest_json.encode()).hexdigest()
        manifest_path = partial / "manifest.json"
        manifest_path.write_text(manifest_json, encoding="utf-8", newline="\n")
        os.chmod(manifest_path, 0o600)
        partial.rename(final)
        return StoredBundle(
            bundle_id=bundle_id,
            root_reference=f"evidence/{bundle_id}",
            manifest_json=manifest_json,
            manifest_sha256=manifest_digest,
            total_bytes=sum(item[2] for item in stored),
            artifacts=tuple(stored),
        )
    except Exception:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def _has_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _safe_regular_info(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _has_reparse_point(info)
        or info.st_nlink != 1
    ):
        raise UnsafeFileError("UNSAFE_FILE")
    return info


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_KEY")
        result[key] = value
    return result


def _exact_keys(value: object, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _valid_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_manifest(manifest_bytes: bytes) -> dict[str, object]:
    try:
        text = manifest_bytes.decode("utf-8")
        manifest = json.loads(text, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("MANIFEST_SCHEMA") from exc
    if not _exact_keys(manifest, _MANIFEST_KEYS):
        raise ValueError("MANIFEST_SCHEMA")
    manifest = cast(dict[str, object], manifest)
    if (
        manifest["schema_version"] != "1.0.0"
        or not _valid_uuid(manifest["bundle_id"])
        or not _valid_uuid(manifest["case_id"])
        or not _valid_uuid(manifest["request_id"])
        or not _valid_uuid(manifest["target_asset_id"])
        or manifest["adapter"] not in {"fixture", "ssh-lab"}
        or not _valid_timestamp(manifest["started_at"])
        or not _valid_timestamp(manifest["completed_at"])
        or manifest["errors"] != []
    ):
        raise ValueError("MANIFEST_SCHEMA")
    if not _exact_keys(manifest["target"], {"hostname", "ip"}):
        raise ValueError("MANIFEST_SCHEMA")
    target = cast(dict[str, object], manifest["target"])
    if target != {"hostname": TARGET_HOSTNAME, "ip": TARGET_IP}:
        raise ValueError("MANIFEST_SCHEMA")
    if not _exact_keys(manifest["profile"], {"id", "version", "digest"}):
        raise ValueError("MANIFEST_SCHEMA")
    profile = cast(dict[str, object], manifest["profile"])
    if profile != {
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "digest": PROFILE_DIGEST,
    }:
        raise ValueError("MANIFEST_SCHEMA")
    if not _exact_keys(
        manifest["limits"],
        {"command_timeout_seconds", "artifact_max_bytes", "total_max_bytes"},
    ):
        raise ValueError("MANIFEST_SCHEMA")
    if manifest["limits"] != PROFILE_DOCUMENT["limits"]:
        raise ValueError("MANIFEST_SCHEMA")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_TYPES):
        raise ValueError("MANIFEST_SCHEMA")
    total = 0
    for position, item in enumerate(artifacts):
        if not _exact_keys(item, _ARTIFACT_KEYS):
            raise ValueError("MANIFEST_SCHEMA")
        item = cast(dict[str, object], item)
        name = ARTIFACT_TYPES[position]
        size = item["size_bytes"]
        if (
            item["name"] != name
            or item["path"] != f"artifacts/{name}.txt"
            or type(size) is not int
            or not 1 <= size <= ARTIFACT_MAX_BYTES
            or not isinstance(item["sha256"], str)
            or _SHA256_PATTERN.fullmatch(item["sha256"]) is None
        ):
            raise ValueError("MANIFEST_SCHEMA")
        total += size
    if total > TOTAL_MAX_BYTES:
        raise ValueError("MANIFEST_SCHEMA")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    if canonical.encode("utf-8") != manifest_bytes:
        raise ValueError("MANIFEST_NONCANONICAL")
    return manifest


def _stream_hash(path: Path, limit: int) -> tuple[int, str, bool]:
    digest = hashlib.sha256()
    total = 0
    with _open_regular_file(path) as handle:
        while True:
            chunk = handle.read(min(65_536, limit - total + 1))
            if not chunk:
                return total, digest.hexdigest(), False
            total += len(chunk)
            if total > limit:
                return total, "", True
            digest.update(chunk)


def verify_bundle(path: Path, expected_manifest_sha256: str) -> VerificationResult:
    reasons: set[str] = set()
    manifest_path = path / "manifest.json"
    try:
        _safe_regular_info(manifest_path)
    except FileNotFoundError:
        return VerificationResult("FAIL", ("MANIFEST_MISSING",), "")
    except ValueError:
        return VerificationResult("FAIL", ("MANIFEST_UNSAFE",), "")
    try:
        manifest_bytes = _read_file_bounded(manifest_path, MANIFEST_MAX_BYTES)
    except UnsafeFileError:
        return VerificationResult("FAIL", ("MANIFEST_UNSAFE",), "")
    except FileBoundError:
        return VerificationResult("FAIL", ("MANIFEST_TOO_LARGE",), "")
    actual_manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if (
        _SHA256_PATTERN.fullmatch(expected_manifest_sha256) is None
        or actual_manifest_digest != expected_manifest_sha256
    ):
        reasons.add("MANIFEST_MODIFIED")
    try:
        manifest = _validate_manifest(manifest_bytes)
    except ValueError:
        reasons.add("MANIFEST_INVALID")
        return VerificationResult("FAIL", tuple(sorted(reasons)), actual_manifest_digest)
    artifacts_dir = path / "artifacts"
    try:
        directory_info = artifacts_dir.lstat()
    except FileNotFoundError:
        reasons.add("ARTIFACT_MISSING")
        return VerificationResult("FAIL", tuple(sorted(reasons)), actual_manifest_digest)
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_ISLNK(directory_info.st_mode)
        or _has_reparse_point(directory_info)
    ):
        reasons.add("ARTIFACT_UNSAFE")
        return VerificationResult("FAIL", tuple(sorted(reasons)), actual_manifest_digest)
    resolved_directory = artifacts_dir.resolve(strict=True)
    manifest_artifacts = cast(list[dict[str, object]], manifest["artifacts"])
    expected: dict[str, tuple[int, str]] = {
        cast(str, item["path"]): (
            cast(int, item["size_bytes"]),
            cast(str, item["sha256"]),
        )
        for item in manifest_artifacts
    }
    actual: set[str] = set()
    unsafe: set[str] = set()
    with os.scandir(artifacts_dir) as entries:
        for entry in entries:
            relative = f"artifacts/{entry.name}"
            actual.add(relative)
            try:
                _safe_regular_info(Path(entry.path))
            except (OSError, ValueError):
                unsafe.add(relative)
                continue
    if unsafe:
        reasons.add("ARTIFACT_UNSAFE")
    missing = set(expected) - actual
    extra = actual - set(expected)
    if missing:
        reasons.add("ARTIFACT_MISSING")
    if extra:
        reasons.add("ARTIFACT_EXTRA")
    total_actual = 0
    for relative, (size, digest) in expected.items():
        artifact = path / relative
        if relative not in actual or relative in unsafe:
            continue
        try:
            _safe_regular_info(artifact)
            resolved_artifact = artifact.resolve(strict=True)
        except (FileNotFoundError, ValueError, OSError):
            reasons.add("ARTIFACT_UNSAFE")
            continue
        if resolved_artifact.parent != resolved_directory:
            reasons.add("ARTIFACT_UNSAFE")
            continue
        try:
            remaining_total = TOTAL_MAX_BYTES - total_actual
            actual_size, actual_digest, overflow = _stream_hash(
                artifact, min(ARTIFACT_MAX_BYTES, remaining_total)
            )
        except (UnsafeFileError, OSError):
            reasons.add("ARTIFACT_UNSAFE")
            continue
        total_actual += actual_size
        if overflow or actual_size != size or actual_digest != digest:
            reasons.add("ARTIFACT_MODIFIED")
        if overflow:
            break
    return VerificationResult(
        "FAIL" if reasons else "PASS",
        tuple(sorted(reasons)) if reasons else ("VERIFIED",),
        actual_manifest_digest,
    )
