import logging
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session
from starlette.middleware.base import RequestResponseEndpoint

from app.auth import current_session, login, logout, require_role, validate_csrf
from app.cases import add_collection_history, add_timeline, execute_request, new_request
from app.collection import PROFILE_ID
from app.db import get_db
from app.logging_config import configure_logging
from app.models import (
    Alert,
    AlertHistory,
    AlertStatus,
    Asset,
    AuditEvent,
    CaseAlert,
    CaseStatus,
    CollectionRequest,
    CollectionStatus,
    Event,
    IncidentCase,
    Role,
    RuleVersion,
    SourceBatch,
    User,
    utcnow,
)
from app.telemetry import source_health

configure_logging()
logger = logging.getLogger("workbench.http")
app = FastAPI(title="Sagneo SecOps Workbench", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.post("/login")(login)
app.post("/logout")(logout)


@app.middleware("http")
async def sanitized_request_log(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; img-src 'self' data:; style-src 'self'",
    )
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers.setdefault("Cache-Control", "no-store")
    logger.info(
        "request_complete method=%s path=%s status=%d",
        request.method,
        request.url.path,
        response.status_code,
    )
    return response


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {})


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": session.user, "csrf_token": session.csrf_token},
    )


@app.get("/sources", response_class=HTMLResponse)
def sources(request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    return templates.TemplateResponse(
        request,
        "sources.html",
        {
            "user": session.user,
            "sources": source_health(db),
            "assets": db.scalars(select(Asset).order_by(Asset.hostname)).all(),
            "batches": db.scalars(
                select(SourceBatch).order_by(SourceBatch.imported_at.desc()).limit(20)
            ).all(),
        },
    )


@app.get("/events", response_class=HTMLResponse)
def events(request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    rows = db.scalars(select(Event).order_by(Event.timestamp_utc.desc()).limit(100)).all()
    return templates.TemplateResponse(
        request,
        "events.html",
        {"user": session.user, "events": rows},
    )


@app.get("/events/{event_id}", response_class=HTMLResponse)
def event_detail(event_id: str, request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    event = db.get(Event, event_id)
    if event is None:
        return Response(status_code=404)
    return templates.TemplateResponse(
        request,
        "event_detail.html",
        {"user": session.user, "event": event},
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    status_filter = status_filter or None
    severity = severity or None
    rule_id = rule_id or None
    allowed_statuses = {item.value for item in AlertStatus}
    allowed_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    allowed_rule_ids = {"AUTH-001", "AUTH-002", "NET-001", "PRIV-001", "EVID-001"}
    if status_filter is not None and status_filter not in allowed_statuses:
        raise HTTPException(status_code=422, detail="Invalid alert status filter")
    if severity is not None and severity not in allowed_severities:
        raise HTTPException(status_code=422, detail="Invalid alert severity filter")
    if rule_id is not None and rule_id not in allowed_rule_ids:
        raise HTTPException(status_code=422, detail="Invalid alert rule filter")

    filters = []
    if status_filter is not None:
        filters.append(Alert.status == status_filter)
    if severity is not None:
        filters.append(Alert.severity == severity)
    if rule_id is not None:
        filters.append(RuleVersion.rule_id == rule_id)
    base = select(Alert).join(RuleVersion, Alert.rule_version_id == RuleVersion.id).where(*filters)
    total = int(
        db.scalar(
            select(func.count(Alert.id))
            .join(RuleVersion, Alert.rule_version_id == RuleVersion.id)
            .where(*filters)
        )
        or 0
    )
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        raise HTTPException(status_code=404, detail="Alert page out of range")
    rows = db.scalars(
        base.order_by(Alert.created_at.desc(), Alert.stable_identity)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    query = {
        key: value
        for key, value in {
            "status": status_filter,
            "severity": severity,
            "rule_id": rule_id,
            "page_size": page_size,
        }.items()
        if value is not None
    }

    def page_url(target: int) -> str:
        return f"/alerts?{urlencode({**query, 'page': target})}"

    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "user": session.user,
            "alerts": rows,
            "filters": {
                "status": status_filter or "",
                "severity": severity or "",
                "rule_id": rule_id or "",
            },
            "status_options": sorted(allowed_statuses),
            "severity_options": sorted(allowed_severities),
            "rule_options": sorted(allowed_rule_ids),
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "previous_url": page_url(page - 1) if page > 1 else None,
            "next_url": page_url(page + 1) if page < total_pages else None,
        },
    )


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(alert_id: str, request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    alert = db.get(Alert, alert_id)
    if alert is None:
        return Response(status_code=404)
    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "user": session.user,
            "csrf_token": session.csrf_token,
            "alert": alert,
            "is_analyst": session.user.role == Role.ANALYST.value,
        },
    )


ALLOWED_TRANSITIONS = {
    AlertStatus.NEW.value: {AlertStatus.IN_TRIAGE.value},
    AlertStatus.IN_TRIAGE.value: {
        AlertStatus.ESCALATED.value,
        AlertStatus.BENIGN.value,
    },
    AlertStatus.ESCALATED.value: {AlertStatus.CLOSED.value},
    AlertStatus.BENIGN.value: {AlertStatus.CLOSED.value},
}


def _clean_form(value: str, field: str, required: bool = False) -> str:
    cleaned = " ".join(value.replace("\x00", "").split())
    if len(cleaned) > 1000 or (required and not cleaned):
        raise HTTPException(status_code=422, detail=f"Invalid {field}")
    return cleaned


@app.post("/alerts/{alert_id}/triage")
def triage_alert(
    alert_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    next_status: str = Form(),
    scope_impact: str = Form(""),
    false_positive_context: str = Form(""),
    disposition_reason: str = Form(""),
    recommended_action: str = Form(""),
    analyst_notes: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404)
    if alert.version != version:
        raise HTTPException(status_code=409, detail="Stale alert version")
    if next_status not in ALLOWED_TRANSITIONS.get(alert.status, set()):
        raise HTTPException(status_code=422, detail="Invalid workflow transition")
    completing_triage = next_status in {
        AlertStatus.ESCALATED.value,
        AlertStatus.BENIGN.value,
        AlertStatus.CLOSED.value,
    }
    fields = {
        "scope_impact": _clean_form(scope_impact, "scope impact", completing_triage),
        "false_positive_context": _clean_form(
            false_positive_context, "false-positive context", completing_triage
        ),
        "disposition_reason": _clean_form(
            disposition_reason, "disposition reason", completing_triage
        ),
        "recommended_action": _clean_form(
            recommended_action, "recommended action", completing_triage
        ),
        "analyst_notes": _clean_form(analyst_notes, "analyst notes", completing_triage),
    }
    old_status = alert.status
    next_version = alert.version + 1
    result = db.execute(
        update(Alert)
        .where(
            Alert.id == alert.id,
            Alert.version == version,
            Alert.status == old_status,
        )
        .values(
            **fields,
            status=next_status,
            assigned_to_user_id=session.user.id,
            version=next_version,
            updated_at=utcnow(),
        )
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent alert update")
    db.add(
        AlertHistory(
            alert_id=alert.id,
            actor_user_id=session.user.id,
            action="TRANSITION",
            from_status=old_status,
            to_status=next_status,
            detail=f"version={next_version}",
        )
    )
    db.add(
        AuditEvent(
            actor_user_id=session.user.id,
            action="alert.transition",
            outcome="SUCCESS",
            detail=f"alert={alert.id} {old_status}->{next_status}",
        )
    )
    db.commit()
    return RedirectResponse(f"/alerts/{alert.id}", status_code=303)


@app.get("/reviewer-check")
def reviewer_check(user: User = Depends(require_role(Role.REVIEWER))) -> dict[str, str]:
    return {"role": user.role}


@app.get("/cases", response_class=HTMLResponse)
def cases(request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    rows = db.scalars(
        select(IncidentCase).order_by(IncidentCase.created_at.desc(), IncidentCase.id)
    ).all()
    return templates.TemplateResponse(
        request,
        "cases.html",
        {"user": session.user, "cases": rows},
    )


@app.post("/alerts/{alert_id}/cases")
def create_case(
    alert_id: str,
    request: Request,
    csrf_token: str = Form(),
    title: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST:
        raise HTTPException(status_code=403)
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404)
    if alert.status != AlertStatus.ESCALATED:
        raise HTTPException(status_code=422, detail="Case requires ESCALATED alert")
    clean_title = _clean_form(title, "case title", required=True)
    case = IncidentCase(
        title=clean_title,
        asset_id=alert.asset_id,
        opened_by_user_id=session.user.id,
    )
    db.add(case)
    db.flush()
    db.add(
        CaseAlert(
            case_id=case.id,
            alert_id=alert.id,
            linked_by_user_id=session.user.id,
        )
    )
    add_timeline(db, case, "CREATED", f"alert={alert.id}", session.user.id)
    db.add(
        AuditEvent(
            actor_user_id=session.user.id,
            action="case.create",
            outcome="SUCCESS",
            detail=f"case={case.id}",
        )
    )
    db.commit()
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(case_id: str, request: Request, db: Session = Depends(get_db)) -> Response:
    session = current_session(request, db)
    if not session:
        return templates.TemplateResponse(request, "login.html", {}, status_code=401)
    case = db.get(IncidentCase, case_id)
    if case is None:
        return Response(status_code=404)
    blocking_collection_statuses = {
        CollectionStatus.DRAFT.value,
        CollectionStatus.SUBMITTED.value,
        CollectionStatus.APPROVED.value,
        CollectionStatus.EXECUTING.value,
        CollectionStatus.SUCCEEDED.value,
        CollectionStatus.PARTIAL.value,
    }
    can_request_collection = case.status == CaseStatus.INVESTIGATING.value and not any(
        item.status in blocking_collection_statuses for item in case.collection_requests
    )
    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {
            "user": session.user,
            "csrf_token": session.csrf_token,
            "case": case,
            "is_analyst": session.user.role == Role.ANALYST,
            "is_reviewer": session.user.role == Role.REVIEWER,
            "profile_id": PROFILE_ID,
            "can_request_collection": can_request_collection,
        },
    )


@app.post("/cases/{case_id}/transition")
def transition_case(
    case_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    next_status: str = Form(),
    resolution: str = Form(""),
    closure_summary: str = Form(""),
    no_collection_reason: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST:
        raise HTTPException(status_code=403)
    case = db.get(IncidentCase, case_id)
    if case is None:
        raise HTTPException(status_code=404)
    if case.version != version:
        raise HTTPException(status_code=409, detail="Stale case version")
    transitions: dict[str, set[str]] = {
        CaseStatus.OPEN.value: {CaseStatus.INVESTIGATING.value},
        CaseStatus.INVESTIGATING.value: {CaseStatus.RESOLVED.value},
        CaseStatus.RESOLVED.value: {CaseStatus.CLOSED.value},
    }
    if next_status not in transitions.get(case.status, set()):
        raise HTTPException(status_code=422, detail="Invalid case transition")
    clean_resolution = _clean_form(
        resolution, "resolution", required=next_status in {"RESOLVED", "CLOSED"}
    )
    clean_closure = _clean_form(
        closure_summary, "closure summary", required=next_status == "CLOSED"
    )
    clean_no_collection = _clean_form(no_collection_reason, "no collection reason")
    if next_status in {"RESOLVED", "CLOSED"}:
        escalated = any(
            link.alert.status in {AlertStatus.ESCALATED, AlertStatus.CLOSED}
            and link.alert.disposition_reason
            for link in case.alert_links
        )
        passed = any(
            verification.status == "PASS"
            for bundle in case.evidence_bundles
            for verification in bundle.verifications
        )
        if not escalated:
            raise HTTPException(status_code=422, detail="Escalated triage rationale required")
        if not passed and not clean_no_collection:
            raise HTTPException(
                status_code=422, detail="PASS evidence or no-collection reason required"
            )
    old = case.status
    case.status = next_status
    case.resolution = clean_resolution or case.resolution
    case.closure_summary = clean_closure or case.closure_summary
    case.no_collection_reason = clean_no_collection or case.no_collection_reason
    case.version += 1
    case.updated_at = utcnow()
    add_timeline(db, case, "STATUS", f"{old}->{next_status}", session.user.id)
    db.add(
        AuditEvent(
            actor_user_id=session.user.id,
            action="case.transition",
            outcome="SUCCESS",
            detail=f"case={case.id} {old}->{next_status}",
        )
    )
    db.commit()
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@app.post("/cases/{case_id}/collections")
def create_collection_request(
    case_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    adapter: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST:
        raise HTTPException(status_code=403)
    case = db.get(IncidentCase, case_id)
    if case is None:
        raise HTTPException(status_code=404)
    if case.version != version or case.status != CaseStatus.INVESTIGATING:
        raise HTTPException(status_code=409, detail="Case state/version changed")
    if any(
        item.status
        in {
            CollectionStatus.DRAFT.value,
            CollectionStatus.SUBMITTED.value,
            CollectionStatus.APPROVED.value,
            CollectionStatus.EXECUTING.value,
            CollectionStatus.SUCCEEDED.value,
            CollectionStatus.PARTIAL.value,
        }
        for item in case.collection_requests
    ):
        raise HTTPException(status_code=422, detail="Case already has an active collection")
    new_request(db, case, session.user.id, adapter)
    db.commit()
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@app.post("/collections/{request_id}/submit")
def submit_collection_request(
    request_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST:
        raise HTTPException(status_code=403)
    collection = db.get(CollectionRequest, request_id)
    if collection is None:
        raise HTTPException(status_code=404)
    if collection.version != version or collection.status != CollectionStatus.DRAFT:
        raise HTTPException(status_code=409, detail="Collection request changed")
    old = collection.status
    collection.status = CollectionStatus.SUBMITTED
    collection.submitted_at = utcnow()
    collection.version += 1
    add_collection_history(
        db,
        collection,
        "SUBMITTED",
        session.user.id,
        old=old,
        new=collection.status,
    )
    add_timeline(
        db, collection.case, "COLLECTION", f"request={collection.id} submitted", session.user.id
    )
    db.add(
        AuditEvent(
            actor_user_id=session.user.id,
            action="collection.submit",
            outcome="SUCCESS",
            detail=f"request={collection.id}",
        )
    )
    db.commit()
    return RedirectResponse(f"/cases/{collection.case_id}", status_code=303)


@app.post("/collections/{request_id}/review")
def review_collection_request(
    request_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    decision: str = Form(),
    reason: str = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.REVIEWER:
        raise HTTPException(status_code=403)
    collection = db.get(CollectionRequest, request_id)
    if collection is None:
        raise HTTPException(status_code=404)
    if collection.version != version or collection.status != CollectionStatus.SUBMITTED:
        raise HTTPException(status_code=409, detail="Collection request changed")
    if decision not in {CollectionStatus.APPROVED, CollectionStatus.REJECTED}:
        raise HTTPException(status_code=422, detail="Invalid review decision")
    clean_reason = _clean_form(reason, "review reason", required=True)
    old = collection.status
    collection.status = decision
    collection.reviewed_by_user_id = session.user.id
    collection.reviewer_reason = clean_reason
    collection.decided_at = utcnow()
    collection.version += 1
    add_collection_history(
        db,
        collection,
        "REVIEWED",
        session.user.id,
        old=old,
        new=collection.status,
        detail=clean_reason,
    )
    add_timeline(
        db,
        collection.case,
        "REVIEW",
        f"request={collection.id} decision={decision}",
        session.user.id,
    )
    db.add(
        AuditEvent(
            actor_user_id=session.user.id,
            action="collection.review",
            outcome="SUCCESS",
            detail=f"request={collection.id} decision={decision}",
        )
    )
    db.commit()
    return RedirectResponse(f"/cases/{collection.case_id}", status_code=303)


@app.post("/collections/{request_id}/execute")
def execute_collection_request(
    request_id: str,
    request: Request,
    csrf_token: str = Form(),
    version: int = Form(),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session = validate_csrf(request, csrf_token, db)
    if session.user.role != Role.ANALYST:
        raise HTTPException(status_code=403)
    collection = db.get(CollectionRequest, request_id)
    if collection is None:
        raise HTTPException(status_code=404)
    if collection.version != version or collection.status != CollectionStatus.APPROVED:
        raise HTTPException(status_code=409, detail="Collection request changed")
    try:
        execute_request(db, collection, session.user.id)
    except RuntimeError:
        return RedirectResponse(f"/cases/{collection.case_id}", status_code=303)
    return RedirectResponse(f"/cases/{collection.case_id}", status_code=303)
