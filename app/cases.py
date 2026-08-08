"""Case workflow and reviewer-gated collection operations."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.collection import (
    PROFILE_DIGEST,
    PROFILE_DOCUMENT,
    PROFILE_ID,
    PROFILE_VERSION,
    FixtureCollector,
    SshLabCollector,
    store_bundle,
    verify_bundle,
)
from app.config import settings
from app.models import (
    AuditEvent,
    CaseTimelineEntry,
    CollectionHistory,
    CollectionRequest,
    CollectionStatus,
    EvidenceArtifact,
    EvidenceBundle,
    IncidentCase,
    VerificationRun,
    utcnow,
)

ALLOWED_ADAPTERS = {"fixture", "ssh-lab"}


def add_timeline(
    db: Session,
    case: IncidentCase,
    entry_type: str,
    detail: str,
    actor_user_id: str | None,
) -> None:
    db.add(
        CaseTimelineEntry(
            case_id=case.id,
            actor_user_id=actor_user_id,
            entry_type=entry_type,
            detail=detail,
        )
    )


def add_collection_history(
    db: Session,
    request: CollectionRequest,
    action: str,
    actor_user_id: str | None,
    *,
    old: str | None,
    new: str | None,
    detail: str = "",
) -> None:
    db.add(
        CollectionHistory(
            request_id=request.id,
            actor_user_id=actor_user_id,
            action=action,
            from_status=old,
            to_status=new,
            detail=detail,
        )
    )


def new_request(db: Session, case: IncidentCase, user_id: str, adapter: str) -> CollectionRequest:
    if adapter not in ALLOWED_ADAPTERS:
        raise ValueError("COLLECTION_ADAPTER_INVALID")
    request = CollectionRequest(
        case_id=case.id,
        target_asset_id=case.asset_id,
        profile_id=PROFILE_ID,
        profile_version=PROFILE_VERSION,
        profile_digest=PROFILE_DIGEST,
        adapter=adapter,
        limits_json=json.dumps(PROFILE_DOCUMENT["limits"], sort_keys=True, separators=(",", ":")),
        requested_by_user_id=user_id,
    )
    db.add(request)
    db.flush()
    add_collection_history(db, request, "CREATED", user_id, old=None, new=CollectionStatus.DRAFT)
    add_timeline(db, case, "COLLECTION", f"request={request.id} created", user_id)
    db.add(
        AuditEvent(
            actor_user_id=user_id,
            action="collection.create",
            outcome="SUCCESS",
            detail=f"case={case.id} request={request.id}",
        )
    )
    return request


def execute_request(db: Session, request: CollectionRequest, actor_user_id: str) -> EvidenceBundle:
    old = request.status
    request.status = CollectionStatus.EXECUTING
    request.started_at = utcnow()
    request.version += 1
    add_collection_history(
        db,
        request,
        "EXECUTION_STARTED",
        actor_user_id,
        old=old,
        new=request.status,
    )
    db.commit()
    collector = FixtureCollector() if request.adapter == "fixture" else SshLabCollector()
    try:
        result = collector.collect()
        stored = store_bundle(
            result,
            case_id=request.case_id,
            request_id=request.id,
            target_asset_id=request.target_asset_id,
            adapter=request.adapter,
        )
        bundle = EvidenceBundle(
            id=stored.bundle_id,
            request_id=request.id,
            case_id=request.case_id,
            target_asset_id=request.target_asset_id,
            adapter=request.adapter,
            profile_id=request.profile_id,
            profile_version=request.profile_version,
            profile_digest=request.profile_digest,
            root_reference=stored.root_reference,
            manifest_json=stored.manifest_json,
            manifest_sha256=stored.manifest_sha256,
            collection_status=CollectionStatus.SUCCEEDED,
            total_bytes=stored.total_bytes,
        )
        db.add(bundle)
        db.flush()
        for relative, artifact_type, size, digest in stored.artifacts:
            db.add(
                EvidenceArtifact(
                    bundle_id=bundle.id,
                    relative_path=relative,
                    artifact_type=artifact_type,
                    size_bytes=size,
                    sha256=digest,
                )
            )
        verification = verify_bundle(
            Path(settings.evidence_root) / bundle.id, bundle.manifest_sha256
        )
        db.add(
            VerificationRun(
                bundle_id=bundle.id,
                case_id=request.case_id,
                status=verification.status,
                reason_codes_json=json.dumps(list(verification.reason_codes)),
                manifest_sha256=verification.manifest_sha256,
                verifier_version="1.0.0",
                independent=True,
            )
        )
        request.status = CollectionStatus.SUCCEEDED
        request.result_summary = (
            f"artifacts={len(stored.artifacts)} bytes={stored.total_bytes} "
            f"verification={verification.status}"
        )
        request.completed_at = utcnow()
        request.version += 1
        add_collection_history(
            db,
            request,
            "EXECUTION_COMPLETED",
            actor_user_id,
            old=CollectionStatus.EXECUTING,
            new=request.status,
            detail=request.result_summary,
        )
        add_timeline(
            db,
            request.case,
            "EVIDENCE",
            f"bundle={bundle.id} verification={verification.status}",
            actor_user_id,
        )
        db.add(
            AuditEvent(
                actor_user_id=actor_user_id,
                action="collection.execute",
                outcome="SUCCESS",
                detail=f"request={request.id} bundle={bundle.id}",
            )
        )
        db.commit()
        return bundle
    except Exception as exc:
        request.status = CollectionStatus.FAILED
        request.error_summary = type(exc).__name__
        request.completed_at = utcnow()
        request.version += 1
        add_collection_history(
            db,
            request,
            "EXECUTION_FAILED",
            actor_user_id,
            old=CollectionStatus.EXECUTING,
            new=request.status,
            detail=request.error_summary,
        )
        db.add(
            AuditEvent(
                actor_user_id=actor_user_id,
                action="collection.execute",
                outcome="FAILED",
                detail=f"request={request.id} error={request.error_summary}",
            )
        )
        db.commit()
        raise
