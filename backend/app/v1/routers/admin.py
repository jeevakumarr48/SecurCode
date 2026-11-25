"""Platform administration (separate from organisation roles).

Platform administrators see aggregate operational data. They are not
organisation members by virtue of the role and get no access to tenant
source code, finding details or reports. Every admin request is audited.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from security_engine.scanner.rules import SCANNER_VERSION, ruleset_version

from .. import audit
from ..db import get_db, utcnow
from ..deps import AuthContext, platform_admin
from ..models import AuditEvent, Integration, Membership, Organization, Project, Scan, User, UserSession, WorkerHeartbeat
from ..settings import platform_settings

router = APIRouter(prefix="/admin", tags=["platform-admin"])


class Reason(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


def _audit_view(db: Session, auth: AuthContext, what: str) -> None:
    audit.record(db, f"admin.viewed_{what}", actor=auth.user, scope="platform")
    db.commit()


@router.get("/overview")
def overview(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    count = lambda model, *where: db.execute(select(func.count()).select_from(model).where(*where)).scalar_one()  # noqa: E731
    cutoff = utcnow() - timedelta(seconds=90)
    day = utcnow() - timedelta(days=1)
    result = {
        "organizations": {"total": count(Organization), "active": count(Organization, Organization.status == "active"),
                          "suspended": count(Organization, Organization.status == "suspended")},
        "users": {"total": count(User), "active": count(User, User.is_active.is_(True)),
                  "locked": count(User, User.locked_until > utcnow())},
        "scans": dict(db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all()),
        "scans_last_24h": count(Scan, Scan.created_at >= day),
        "failed_last_24h": count(Scan, Scan.status == "failed", Scan.created_at >= day),
        "workers_active": count(WorkerHeartbeat, WorkerHeartbeat.last_seen_at >= cutoff),
        "integrations": dict(db.execute(select(Integration.status, func.count()).group_by(Integration.status)).all()),
        "audit_chain": audit.verify_chain(db),
        "scanner_version": SCANNER_VERSION, "ruleset_version": ruleset_version(),
    }
    _audit_view(db, auth, "overview")
    return result


@router.get("/organizations")
def organizations(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db),
                  search: str = Query(default="", max_length=120), limit: int = Query(default=50, ge=1, le=200),
                  offset: int = Query(default=0, ge=0)):
    members = select(Membership.org_id, func.count().label("n")).group_by(Membership.org_id).subquery()
    projects = select(Project.org_id, func.count().label("n")).group_by(Project.org_id).subquery()
    query = (select(Organization, members.c.n, projects.c.n)
             .outerjoin(members, members.c.org_id == Organization.id).outerjoin(projects, projects.c.org_id == Organization.id))
    if search:
        query = query.where(func.lower(Organization.name).like(f"%{search.lower()}%"))
    rows = db.execute(query.order_by(Organization.created_at.desc()).limit(limit).offset(offset)).all()
    _audit_view(db, auth, "organizations")
    return {"items": [{"id": o.id, "name": o.name, "slug": o.slug, "status": o.status, "is_demo": o.is_demo,
                       "members": m or 0, "projects": p or 0, "created_at": o.created_at.isoformat()} for o, m, p in rows]}


@router.post("/organizations/{org_id}/suspend")
def suspend_org(org_id: str, body: Reason, auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found.")
    org.status = "suspended"
    audit.record(db, "admin.org_suspended", actor=auth.user, org_id=org.id, resource_type="organization", resource_id=org.id,
                 metadata={"reason": body.reason}, scope="platform")
    db.commit()
    return {"id": org.id, "status": org.status}


@router.post("/organizations/{org_id}/reactivate")
def reactivate_org(org_id: str, body: Reason, auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found.")
    org.status = "active"
    audit.record(db, "admin.org_reactivated", actor=auth.user, org_id=org.id, resource_type="organization", resource_id=org.id,
                 metadata={"reason": body.reason}, scope="platform")
    db.commit()
    return {"id": org.id, "status": org.status}


@router.get("/users")
def users(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db),
          search: str = Query(default="", max_length=120), limit: int = Query(default=50, ge=1, le=200),
          offset: int = Query(default=0, ge=0)):
    orgs = select(Membership.user_id, func.count().label("n")).group_by(Membership.user_id).subquery()
    query = select(User, orgs.c.n).outerjoin(orgs, orgs.c.user_id == User.id)
    if search:
        query = query.where(func.lower(User.email).like(f"%{search.lower()}%"))
    rows = db.execute(query.order_by(User.created_at.desc()).limit(limit).offset(offset)).all()
    _audit_view(db, auth, "users")
    return {"items": [{"id": u.id, "email": u.email, "display_name": u.display_name, "is_active": u.is_active,
                       "is_platform_admin": u.is_platform_admin, "mfa_enabled": u.mfa_enabled, "organizations": n or 0,
                       "locked": bool(u.locked_until and u.locked_until > utcnow()),
                       "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                       "created_at": u.created_at.isoformat()} for u, n in rows]}


@router.post("/users/{user_id}/disable")
def disable_user(user_id: str, body: Reason, auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    if user_id == auth.user.id:
        raise HTTPException(status_code=409, detail="You cannot disable your own account.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active = False
    revoked = db.execute(update(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
                         .values(revoked_at=utcnow())).rowcount
    audit.record(db, "admin.user_disabled", actor=auth.user, resource_type="user", resource_id=user.id,
                 metadata={"reason": body.reason, "sessions_revoked": revoked}, scope="platform")
    db.commit()
    return {"id": user.id, "is_active": False, "sessions_revoked": revoked}


@router.post("/users/{user_id}/enable")
def enable_user(user_id: str, body: Reason, auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active = True
    user.locked_until = None
    user.failed_login_count = 0
    audit.record(db, "admin.user_enabled", actor=auth.user, resource_type="user", resource_id=user.id,
                 metadata={"reason": body.reason}, scope="platform")
    db.commit()
    return {"id": user.id, "is_active": True}


@router.get("/jobs")
def jobs(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    workers = db.execute(select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).limit(20)).scalars()
    failed = db.execute(
        select(Scan.id, Scan.org_id, Scan.error_message, Scan.finished_at).where(Scan.status == "failed")
        .order_by(Scan.finished_at.desc()).limit(25)
    ).all()
    stuck = db.execute(select(func.count()).select_from(Scan).where(
        Scan.status == "running", Scan.lease_expires_at < utcnow())).scalar_one()
    _audit_view(db, auth, "jobs")
    cutoff = utcnow() - timedelta(seconds=90)
    return {
        "queue": dict(db.execute(select(Scan.status, func.count()).where(Scan.status.in_(["queued", "running"])).group_by(Scan.status)).all()),
        "stale_leases": stuck,
        "workers": [{"worker_id": w.worker_id, "hostname": w.hostname, "version": w.version, "active_jobs": w.active_jobs,
                     "last_seen_at": w.last_seen_at.isoformat(), "healthy": w.last_seen_at >= cutoff} for w in workers],
        # Error summaries only: scanner failure messages are generic and contain no source code.
        "recent_failures": [{"scan_id": f.id, "org_id": f.org_id, "error": f.error_message,
                             "finished_at": f.finished_at.isoformat() if f.finished_at else None} for f in failed],
    }


@router.get("/security-events")
def security_events(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db),
                    action: str | None = Query(default=None, max_length=80), limit: int = Query(default=100, ge=1, le=500)):
    query = select(AuditEvent).where(AuditEvent.scope == "platform")
    if action:
        query = query.where(AuditEvent.action.like(f"{action}%"))
    events = db.execute(query.order_by(AuditEvent.id.desc()).limit(limit)).scalars().all()
    _audit_view(db, auth, "security_events")
    return {"items": [{"id": e.id, "action": e.action, "actor_email": e.actor_email, "resource_type": e.resource_type,
                       "resource_id": e.resource_id, "metadata": e.metadata_json, "ip_address": e.ip_address,
                       "created_at": e.created_at.isoformat()} for e in events]}


@router.get("/config")
def config(auth: AuthContext = Depends(platform_admin), db: Session = Depends(get_db)):
    """Effective non-secret configuration (read-only; change via environment variables)."""
    s = platform_settings
    _audit_view(db, auth, "config")
    return {
        "environment": s.environment, "database": "postgresql" if not s.is_sqlite else "sqlite",
        "registration_open": s.registration_open, "require_email_verification": s.require_email_verification,
        "email_configured": s.email_configured, "encryption_key_configured": bool(s.encryption_key),
        "cookie_secure": s.cookie_secure, "cookie_samesite": s.cookie_samesite, "session_hours": s.session_hours,
        "session_idle_minutes": s.session_idle_minutes, "max_upload_bytes": s.max_upload_bytes,
        "scan_timeout_seconds": s.scan_timeout_seconds, "scan_memory_mb": s.scan_memory_mb,
        "worker_concurrency": s.worker_concurrency, "login_max_failures": s.login_max_failures,
        "lockout_minutes": s.lockout_minutes, "github_api_url": s.github_api_url,
        "ai_provider_configured": bool(s.ai_provider_url),
    }
