"""Scan lifecycle: queue, upload-and-scan, status, logs, cancel, rescan, compare."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import OrgContext, get_project, get_scan, org_context, visible_project_ids, writable_org
from ..models import Finding, Project, Scan, ScanFinding, SourceArchive
from ..permissions import P
from ..services.comparison import compare_scans
from ..services.scanning import scope_key_for
from .projects import BRANCH, store_archive

router = APIRouter(prefix="/organizations/{org_id}", tags=["scans"])
SHA = re.compile(r"^[0-9a-f]{7,40}$")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_.:-]{8,100}$")


class ScanRequest(BaseModel):
    archive_id: str | None = None
    branch: str | None = Field(default=None, max_length=200)
    commit_sha: str | None = Field(default=None, max_length=40)


def latest_archive_id(db: Session, project: Project) -> str | None:
    return db.execute(
        select(SourceArchive.id).where(SourceArchive.project_id == project.id).order_by(SourceArchive.created_at.desc()).limit(1)
    ).scalar()


def scan_payload(scan: Scan, include_logs: bool = False) -> dict:
    payload = {
        "id": scan.id,
        "org_id": scan.org_id,
        "project_id": scan.project_id,
        "status": scan.status,
        "trigger": scan.trigger,
        "source_type": scan.source_type,
        "branch": scan.branch,
        "commit_sha": scan.commit_sha,
        "pull_request_number": scan.pull_request_number,
        "scope_key": scan.scope_key,
        "progress": scan.progress,
        "progress_message": scan.progress_message,
        "scanner_version": scan.scanner_version,
        "ruleset_version": scan.ruleset_version,
        "rule_count": len(scan.rule_ids or []),
        "files_scanned": scan.files_scanned,
        "warnings": scan.warnings,
        "summary": scan.summary,
        "error_message": scan.error_message,
        "cancel_requested": scan.cancel_requested,
        "attempts": scan.attempts,
        "config": scan.config_json,
        "requested_by_id": scan.requested_by_id,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_ms": scan.duration_ms,
        "is_clean": scan.status == "completed" and scan.summary.get("total", 0) == 0 and scan.files_scanned > 0,
    }
    if include_logs:
        payload["logs"] = scan.logs
    return payload


def _queue(db: Session, ctx: OrgContext, project: Project, *, archive_id=None, branch=None, commit_sha=None,
           trigger="manual", idempotency_key=None, base_scan_id=None) -> Scan:
    if project.status != "active":
        raise HTTPException(status_code=409, detail="Archived projects cannot be scanned.")
    if idempotency_key:
        if not IDEMPOTENCY.match(idempotency_key):
            raise HTTPException(status_code=422, detail="Invalid Idempotency-Key header.")
        key = f"user:{ctx.user.id}:{idempotency_key}"
        existing = db.execute(select(Scan).where(Scan.idempotency_key == key)).scalar_one_or_none()
        if existing is not None:
            if existing.project_id != project.id:
                raise HTTPException(status_code=409, detail="Idempotency-Key was already used for another request.")
            return existing
        idempotency_key = key
    active = db.execute(
        select(func.count()).select_from(Scan).where(Scan.org_id == ctx.org.id, Scan.status.in_(["queued", "running"]))
    ).scalar_one()
    if active >= 20:
        raise HTTPException(status_code=429, detail="This organization already has 20 queued or running scans.")
    if branch is not None and not BRANCH.match(branch):
        raise HTTPException(status_code=422, detail="Invalid branch name.")
    if commit_sha is not None and not SHA.match(commit_sha):
        raise HTTPException(status_code=422, detail="commit_sha must be a hexadecimal Git SHA.")
    source = project.source_type
    if source == "upload":
        archive_id = archive_id or latest_archive_id(db, project)
        archive = db.get(SourceArchive, archive_id) if archive_id else None
        if archive is None or archive.project_id != project.id or archive.org_id != ctx.org.id:
            raise HTTPException(status_code=422, detail="Upload a source archive for this project first.")
        branch = commit_sha = None
    elif source == "github":
        branch = branch or project.default_branch
    else:
        branch = commit_sha = None
    scan = Scan(
        org_id=ctx.org.id, project_id=project.id, trigger=trigger, source_type=source, archive_id=archive_id,
        branch=branch, commit_sha=commit_sha, scope_key=scope_key_for(source, branch, None),
        requested_by_id=ctx.user.id, idempotency_key=idempotency_key, base_scan_id=base_scan_id,
    )
    db.add(scan)
    db.flush()
    audit.record(db, "scan.requested", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="scan",
                 resource_id=scan.id, metadata={"trigger": trigger, "source": source, "branch": branch})
    return scan


@router.post("/projects/{project_id}/scans", status_code=202)
def start_scan(project_id: str, body: ScanRequest | None = None, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db),
               idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    ctx.require(P.SCANS_RUN)
    body = body or ScanRequest()
    project = get_project(db, ctx, project_id)
    scan = _queue(db, ctx, project, archive_id=body.archive_id, branch=body.branch, commit_sha=body.commit_sha,
                  idempotency_key=idempotency_key)
    db.commit()
    return JSONResponse(scan_payload(scan), status_code=202, headers={"Location": f"/api/v1/organizations/{ctx.org.id}/scans/{scan.id}"})


@router.post("/projects/{project_id}/scans/upload", status_code=202)
async def upload_and_scan(project_id: str, file: UploadFile = File(...), ctx: OrgContext = Depends(writable_org),
                          db: Session = Depends(get_db)):
    ctx.require(P.SCANS_RUN)
    project = get_project(db, ctx, project_id)
    if project.source_type != "upload":
        raise HTTPException(status_code=409, detail="This project does not use archive uploads.")
    archive = await store_archive(db, ctx, project, file)
    scan = _queue(db, ctx, project, archive_id=archive.id)
    db.commit()
    return JSONResponse(scan_payload(scan), status_code=202)


@router.get("/scans")
def list_scans(
    ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
    project_id: str | None = None,
    status: str | None = Query(default=None, max_length=30),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
):
    query = select(Scan).where(Scan.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(Scan.project_id.in_(allowed or {"-"}))
    if project_id:
        get_project(db, ctx, project_id)
        query = query.where(Scan.project_id == project_id)
    if status:
        query = query.where(Scan.status == status)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    scans = db.execute(query.order_by(Scan.created_at.desc(), Scan.id).limit(limit).offset(offset)).scalars().all()
    names = dict(db.execute(select(Project.id, Project.name).where(Project.id.in_({s.project_id for s in scans} or {"-"}))).all())
    return {"items": [{**scan_payload(s), "project_name": names.get(s.project_id)} for s in scans], "total": total,
            "limit": limit, "offset": offset}


@router.get("/scans/{scan_id}")
def get_scan_detail(scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    scan = get_scan(db, ctx, scan_id)
    project = db.get(Project, scan.project_id)
    return {**scan_payload(scan, include_logs=True), "project_name": project.name}


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                  severity: str | None = None, limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    scan = get_scan(db, ctx, scan_id)
    query = (
        select(ScanFinding, Finding).join(Finding, Finding.id == ScanFinding.finding_id)
        .where(ScanFinding.scan_id == scan.id, ScanFinding.org_id == ctx.org.id)
    )
    if severity:
        query = query.where(ScanFinding.severity == severity)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = db.execute(query.order_by(ScanFinding.file_path, ScanFinding.line).limit(limit).offset(offset)).all()
    return {"total": total, "items": [
        {"finding_id": f.id, "rule_id": o.rule_id, "title": f.title, "severity": o.severity, "confidence": o.confidence,
         "file_path": o.file_path, "line": o.line, "status": f.status, "cwe": f.cwe, "first_scan_id": f.first_scan_id,
         "is_new": f.first_scan_id == scan.id}
        for o, f in rows
    ]}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCANS_CANCEL)
    scan = get_scan(db, ctx, scan_id)
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail=f"A {scan.status} scan cannot be cancelled.")
    scan.cancel_requested = True
    if scan.status == "queued":
        from ..db import utcnow

        scan.status = "cancelled"
        scan.progress_message = "Cancelled before start"
        scan.finished_at = utcnow()
    audit.record(db, "scan.cancelled", actor=ctx.user, org_id=ctx.org.id, project_id=scan.project_id, resource_type="scan", resource_id=scan.id)
    db.commit()
    return scan_payload(scan)


@router.post("/scans/{scan_id}/rescan", status_code=202)
def rescan(scan_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCANS_RUN)
    previous = get_scan(db, ctx, scan_id)
    project = get_project(db, ctx, previous.project_id)
    new_scan = _queue(db, ctx, project, archive_id=None if project.source_type == "upload" else previous.archive_id,
                      branch=previous.branch, trigger="rescan", base_scan_id=previous.id)
    db.commit()
    return JSONResponse(scan_payload(new_scan), status_code=202)


@router.get("/scans/{scan_id}/compare/{other_scan_id}")
def compare(scan_id: str, other_scan_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    base = get_scan(db, ctx, scan_id)
    head = get_scan(db, ctx, other_scan_id)
    return compare_scans(db, base, head)
