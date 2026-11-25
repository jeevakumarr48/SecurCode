"""Authentication, CSRF and tenant-scoped authorization dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Path, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db, utcnow
from .models import Finding, Membership, Organization, Project, ProjectMember, Scan, User, UserSession
from .permissions import P, has_permission
from .security import constant_time_equals, token_digest
from .settings import platform_settings

SESSION_COOKIE = "sc_session"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class AuthContext:
    user: User
    session: UserSession


@dataclass
class OrgContext:
    user: User
    session: UserSession
    org: Organization
    role: str

    def can(self, permission: P) -> bool:
        return has_permission(self.role, permission)

    def require(self, permission: P) -> None:
        if not self.can(permission):
            raise HTTPException(status_code=403, detail="Your role does not permit this action.")


def _load_session(request: Request, db: Session, allow_mfa_pending: bool = False) -> AuthContext:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    session = db.execute(
        select(UserSession).where(UserSession.token_hash == token_digest(token))
    ).scalar_one_or_none()
    now = utcnow()
    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at <= now
        or session.last_seen_at + timedelta(minutes=platform_settings.session_idle_minutes) <= now
    ):
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    if session.mfa_pending and not allow_mfa_pending:
        raise HTTPException(status_code=401, detail="Multi-factor verification required.")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not constant_time_equals(supplied, session.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid.")
    if now - session.last_seen_at > timedelta(seconds=60):
        session.last_seen_at = now
        db.commit()
    request.state.user_id = user.id
    return AuthContext(user=user, session=session)


def current_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    return _load_session(request, db)


def current_auth_mfa_pending(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    return _load_session(request, db, allow_mfa_pending=True)


def platform_admin(auth: AuthContext = Depends(current_auth)) -> AuthContext:
    if not auth.user.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform administrator access required.")
    return auth


def org_context(
    org_id: str = Path(min_length=1, max_length=32),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> OrgContext:
    row = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.org_id)
        .where(Membership.org_id == org_id, Membership.user_id == auth.user.id)
    ).first()
    if row is None:
        # Identical response for "does not exist" and "not a member" (no enumeration).
        raise HTTPException(status_code=404, detail="Organization not found.")
    membership, org = row
    if org.status == "suspended":
        raise HTTPException(status_code=423, detail="This organization is suspended.")
    return OrgContext(user=auth.user, session=auth.session, org=org, role=membership.role)


def writable_org(ctx: OrgContext = Depends(org_context)) -> OrgContext:
    if ctx.org.status == "archived":
        raise HTTPException(status_code=409, detail="This organization is archived and read-only.")
    return ctx


# --- Tenant-scoped object loaders -------------------------------------------------

def visible_project_ids(db: Session, ctx: OrgContext):
    """None means 'all projects in the org'; otherwise an explicit id set."""
    if ctx.can(P.PROJECTS_VIEW_ALL):
        return None
    return set(
        db.execute(
            select(ProjectMember.project_id).where(
                ProjectMember.org_id == ctx.org.id, ProjectMember.user_id == ctx.user.id
            )
        ).scalars()
    )


def get_project(db: Session, ctx: OrgContext, project_id: str) -> Project:
    project = db.execute(
        select(Project).where(Project.id == project_id, Project.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    allowed = visible_project_ids(db, ctx)
    if allowed is not None and project.id not in allowed:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project


def get_scan(db: Session, ctx: OrgContext, scan_id: str) -> Scan:
    scan = db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == ctx.org.id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    get_project(db, ctx, scan.project_id)
    return scan


def get_finding(db: Session, ctx: OrgContext, finding_id: str) -> Finding:
    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    get_project(db, ctx, finding.project_id)
    return finding


def client_ip(request: Request) -> str:
    # Only trust X-Forwarded-For when explicitly configured behind a proxy.
    import os

    if os.getenv("SECURCODE_TRUST_PROXY_HEADERS", "").lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]
