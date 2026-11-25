"""Projects, project membership and source archive uploads."""

from __future__ import annotations

import hashlib
import re
import secrets

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import OrgContext, get_project, org_context, visible_project_ids, writable_org
from ..models import AuditEvent, Finding, Integration, Membership, Project, ProjectMember, Scan, SourceArchive, User
from ..permissions import P
from ..services.archive import ArchiveError, detect_format
from ..services.policy import effective_policy
from ..services.posture import project_posture
from ..services.scanning import available_fixtures
from ..settings import platform_settings

router = APIRouter(prefix="/organizations/{org_id}", tags=["projects"])
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
BRANCH = re.compile(r"^(?!.*\.\.)(?!/)[A-Za-z0-9._/-]{1,200}(?<!/)$")


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)
    source_type: str = Field(default="upload")
    repository_full_name: str | None = None
    integration_id: str | None = None
    default_branch: str = Field(default="main", max_length=200)
    fixture_name: str | None = None

    @field_validator("default_branch")
    @classmethod
    def _branch(cls, value: str) -> str:
        if not BRANCH.match(value):
            raise ValueError("Invalid branch name.")
        return value


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    default_branch: str | None = Field(default=None, max_length=200)
    owner_id: str | None = None


class ProjectDelete(BaseModel):
    confirm_name: str


class ProjectMemberAdd(BaseModel):
    user_id: str
    role: str = "contributor"


def _slug(db: Session, org_id: str, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "project"
    slug = base
    while db.execute(select(Project.id).where(Project.org_id == org_id, Project.slug == slug)).first():
        slug = f"{base}-{secrets.token_hex(2)}"
    return slug


def project_payload(db: Session, project: Project, detail: bool = False) -> dict:
    active = dict(
        db.execute(
            select(Finding.severity, func.count())
            .where(Finding.project_id == project.id, Finding.status.in_(["open", "triaged", "in_progress", "fixed", "reopened"]))
            .group_by(Finding.severity)
        ).all()
    )
    last_scan = db.execute(
        select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    payload = {
        "id": project.id,
        "org_id": project.org_id,
        "name": project.name,
        "slug": project.slug,
        "description": project.description,
        "status": project.status,
        "source_type": project.source_type,
        "repository_provider": project.repository_provider,
        "repository_full_name": project.repository_full_name,
        "repository_url": project.repository_url,
        "default_branch": project.default_branch,
        "fixture_name": project.fixture_name,
        "languages": project.languages,
        "owner_id": project.owner_id,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
        "last_scan_at": project.last_scan_at.isoformat() if project.last_scan_at else None,
        "last_scan": {"id": last_scan.id, "status": last_scan.status, "created_at": last_scan.created_at.isoformat()} if last_scan else None,
        "active_findings": {"total": sum(active.values()), **active},
    }
    payload["posture"] = project_posture(db, project)
    if detail:
        members = db.execute(
            select(ProjectMember, User).join(User, User.id == ProjectMember.user_id).where(ProjectMember.project_id == project.id)
        ).all()
        payload["members"] = [
            {"user_id": u.id, "email": u.email, "display_name": u.display_name, "role": m.role} for m, u in members
        ]
    return payload


@router.get("/projects")
def list_projects(
    ctx: OrgContext = Depends(org_context),
    db: Session = Depends(get_db),
    search: str = Query(default="", max_length=120),
    status: str | None = Query(default=None, pattern="^(active|archived)$"),
    sort: str = Query(default="name", pattern="^(name|-name|created_at|-created_at|last_scan_at|-last_scan_at)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    query = select(Project).where(Project.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(Project.id.in_(allowed or {"-"}))
    if search:
        query = query.where(func.lower(Project.name).like(f"%{search.lower()}%"))
    if status:
        query = query.where(Project.status == status)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    column = getattr(Project, sort.lstrip("-"))
    query = query.order_by(column.desc() if sort.startswith("-") else column.asc(), Project.id)
    items = db.execute(query.limit(limit).offset(offset)).scalars().all()
    return {"items": [project_payload(db, p) for p in items], "total": total, "limit": limit, "offset": offset}


@router.get("/fixtures")
def list_fixtures(ctx: OrgContext = Depends(org_context)):
    return {"items": available_fixtures()}


@router.post("/projects", status_code=201)
def create_project(body: ProjectCreate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_CREATE)
    if body.source_type not in {"upload", "github", "fixture"}:
        raise HTTPException(status_code=422, detail="source_type must be upload, github or fixture.")
    project = Project(
        org_id=ctx.org.id, name=body.name.strip(), slug=_slug(db, ctx.org.id, body.name), description=body.description,
        owner_id=ctx.user.id, source_type=body.source_type, default_branch=body.default_branch,
    )
    if body.source_type == "github":
        if not body.repository_full_name or not REPO_NAME.match(body.repository_full_name):
            raise HTTPException(status_code=422, detail="repository_full_name must look like owner/repository.")
        integration = db.execute(
            select(Integration).where(Integration.id == (body.integration_id or ""), Integration.org_id == ctx.org.id,
                                      Integration.status != "revoked")
        ).scalar_one_or_none()
        if integration is None:
            raise HTTPException(status_code=422, detail="Select an active GitHub integration for this organization.")
        project.repository_provider = "github"
        project.repository_full_name = body.repository_full_name
        project.repository_url = f"https://github.com/{body.repository_full_name}"
        project.integration_id = integration.id
    if body.source_type == "fixture":
        if body.fixture_name not in available_fixtures():
            raise HTTPException(status_code=422, detail="Unknown fixture.")
        project.fixture_name = body.fixture_name
    db.add(project)
    db.flush()
    db.add(ProjectMember(org_id=ctx.org.id, project_id=project.id, user_id=ctx.user.id, role="maintainer"))
    audit.record(db, "project.created", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="project",
                 resource_id=project.id, metadata={"name": project.name, "source_type": project.source_type})
    db.commit()
    return project_payload(db, project, detail=True)


@router.get("/projects/{project_id}")
def get_project_detail(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    return project_payload(db, get_project(db, ctx, project_id), detail=True)


@router.patch("/projects/{project_id}")
def update_project(project_id: str, body: ProjectUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_MANAGE)
    project = get_project(db, ctx, project_id)
    changes = body.model_dump(exclude_none=True)
    if "default_branch" in changes and not BRANCH.match(changes["default_branch"]):
        raise HTTPException(status_code=422, detail="Invalid branch name.")
    if "owner_id" in changes:
        member = db.execute(
            select(Membership.id).where(Membership.org_id == ctx.org.id, Membership.user_id == changes["owner_id"])
        ).first()
        if member is None:
            raise HTTPException(status_code=422, detail="The new owner must be an organization member.")
    for key, value in changes.items():
        setattr(project, key, value.strip() if isinstance(value, str) and key == "name" else value)
    audit.record(db, "project.updated", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="project",
                 resource_id=project.id, metadata={"fields": sorted(changes)})
    db.commit()
    return project_payload(db, project, detail=True)


@router.post("/projects/{project_id}/archive")
def archive_project(project_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_MANAGE)
    project = get_project(db, ctx, project_id)
    project.status = "archived"
    audit.record(db, "project.archived", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="project", resource_id=project.id)
    db.commit()
    return project_payload(db, project)


@router.post("/projects/{project_id}/restore")
def restore_project(project_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_MANAGE)
    project = get_project(db, ctx, project_id)
    project.status = "active"
    audit.record(db, "project.restored", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="project", resource_id=project.id)
    db.commit()
    return project_payload(db, project)


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, body: ProjectDelete, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_DELETE)
    project = get_project(db, ctx, project_id)
    if body.confirm_name != project.name:
        raise HTTPException(status_code=422, detail="Type the exact project name to confirm deletion.")
    if db.execute(select(Scan.id).where(Scan.project_id == project.id, Scan.status.in_(["queued", "running"]))).first():
        raise HTTPException(status_code=409, detail="Cancel queued or running scans before deleting the project.")
    counts = {
        "scans": db.execute(select(func.count()).select_from(Scan).where(Scan.project_id == project.id)).scalar_one(),
        "findings": db.execute(select(func.count()).select_from(Finding).where(Finding.project_id == project.id)).scalar_one(),
    }
    audit.record(db, "project.deleted", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="project",
                 resource_id=project.id, metadata={"name": project.name, **counts})
    db.delete(project)
    db.commit()
    return {"status": "deleted", **counts}


# --- Project membership ---------------------------------------------------------

@router.post("/projects/{project_id}/members", status_code=201)
def add_project_member(project_id: str, body: ProjectMemberAdd, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_MANAGE)
    if body.role not in {"maintainer", "contributor", "viewer"}:
        raise HTTPException(status_code=422, detail="Unknown project role.")
    project = get_project(db, ctx, project_id)
    if db.execute(select(Membership.id).where(Membership.org_id == ctx.org.id, Membership.user_id == body.user_id)).first() is None:
        raise HTTPException(status_code=422, detail="Only organization members can be added to projects.")
    member = db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project.id, ProjectMember.user_id == body.user_id)
    ).scalar_one_or_none()
    if member is None:
        member = ProjectMember(org_id=ctx.org.id, project_id=project.id, user_id=body.user_id, role=body.role)
        db.add(member)
    else:
        member.role = body.role
    audit.record(db, "project.member_added", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="user",
                 resource_id=body.user_id, metadata={"role": body.role})
    db.commit()
    return project_payload(db, project, detail=True)


@router.delete("/projects/{project_id}/members/{user_id}")
def remove_project_member(project_id: str, user_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.PROJECTS_MANAGE)
    project = get_project(db, ctx, project_id)
    member = db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project.id, ProjectMember.user_id == user_id)
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=404, detail="Project member not found.")
    db.delete(member)
    audit.record(db, "project.member_removed", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="user", resource_id=user_id)
    db.commit()
    return project_payload(db, project, detail=True)


@router.get("/projects/{project_id}/activity")
def project_activity(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                     limit: int = Query(default=50, ge=1, le=200)):
    project = get_project(db, ctx, project_id)
    events = db.execute(
        select(AuditEvent).where(AuditEvent.org_id == ctx.org.id, AuditEvent.project_id == project.id)
        .order_by(AuditEvent.id.desc()).limit(limit)
    ).scalars()
    return {"items": [
        {"action": e.action, "actor_email": e.actor_email, "resource_type": e.resource_type, "resource_id": e.resource_id,
         "metadata": e.metadata_json, "created_at": e.created_at.isoformat()} for e in events
    ]}


# --- Archive upload ------------------------------------------------------------

async def read_upload(file: UploadFile, limit: int) -> bytes:
    chunks, size = [], 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=f"Archive exceeds the {limit // 1_000_000} MB limit.")
        chunks.append(chunk)
    if not size:
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")
    return b"".join(chunks)


async def store_archive(db: Session, ctx: OrgContext, project: Project, file: UploadFile) -> SourceArchive:
    policy = effective_policy(db, ctx.org.id)
    limit = min(platform_settings.max_upload_bytes, policy["max_archive_bytes"])
    data = await read_upload(file, limit)
    try:
        archive_format = detect_format(data)
    except ArchiveError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    name = re.sub(r"[^A-Za-z0-9._-]", "_", (file.filename or "upload")[-120:])
    archive = SourceArchive(org_id=ctx.org.id, project_id=project.id, filename=name, archive_format=archive_format,
                            sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data), content=data, uploaded_by_id=ctx.user.id)
    db.add(archive)
    db.flush()
    audit.record(db, "project.archive_uploaded", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="archive",
                 resource_id=archive.id, metadata={"filename": name, "bytes": len(data), "sha256": archive.sha256})
    return archive


@router.post("/projects/{project_id}/archives", status_code=201)
async def upload_archive(project_id: str, file: UploadFile = File(...), ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCANS_RUN)
    project = get_project(db, ctx, project_id)
    if project.source_type != "upload":
        raise HTTPException(status_code=409, detail="This project does not use archive uploads.")
    archive = await store_archive(db, ctx, project, file)
    db.commit()
    return {"id": archive.id, "filename": archive.filename, "size_bytes": archive.size_bytes, "sha256": archive.sha256,
            "format": archive.archive_format, "created_at": archive.created_at.isoformat()}


@router.get("/projects/{project_id}/archives")
def list_archives(project_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    project = get_project(db, ctx, project_id)
    rows = db.execute(
        select(SourceArchive.id, SourceArchive.filename, SourceArchive.size_bytes, SourceArchive.sha256, SourceArchive.created_at)
        .where(SourceArchive.project_id == project.id).order_by(SourceArchive.created_at.desc()).limit(50)
    ).all()
    return {"items": [{"id": r.id, "filename": r.filename, "size_bytes": r.size_bytes, "sha256": r.sha256,
                       "created_at": r.created_at.isoformat()} for r in rows]}
