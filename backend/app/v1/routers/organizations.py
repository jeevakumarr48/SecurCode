"""Organizations, memberships and invitations."""

from __future__ import annotations

import re
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db, utcnow
from ..deps import AuthContext, OrgContext, client_ip, current_auth, org_context, writable_org
from ..models import ORG_ROLES, AuditEvent, Invitation, Membership, Organization, ProjectMember, User
from ..permissions import P, ROLE_RANK, can_assign_role, permission_matrix, permissions_for
from ..security import new_token, token_digest
from ..services.common import hit_rate_limit, notify, send_email
from ..services.policy import ensure_policy
from ..settings import platform_settings

router = APIRouter(tags=["organizations"])
INVITATION_DAYS = 7


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    settings: dict | None = None


class MemberRoleUpdate(BaseModel):
    role: str


class InvitationCreate(BaseModel):
    email: EmailStr
    role: str


class InvitationAccept(BaseModel):
    token: str = Field(min_length=20, max_length=200)


ALLOWED_ORG_SETTINGS = {"timezone", "default_branch", "ai_assistance_enabled", "notification_email_domain"}


def _slugify(db: Session, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"
    slug = base
    while db.execute(select(Organization.id).where(Organization.slug == slug)).first():
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def org_payload(org: Organization, role: str | None = None, member_count: int | None = None) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "status": org.status,
        "is_demo": org.is_demo,
        "settings": org.settings_json,
        "created_at": org.created_at.isoformat(),
        "role": role,
        "permissions": permissions_for(role) if role else [],
        "member_count": member_count,
    }


@router.get("/permissions/matrix")
def get_permission_matrix(_: AuthContext = Depends(current_auth)):
    return {"roles": list(ORG_ROLES), "matrix": permission_matrix()}


@router.get("/organizations")
def list_my_organizations(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Membership.role, Organization)
        .join(Organization, Organization.id == Membership.org_id)
        .where(Membership.user_id == auth.user.id)
        .order_by(Organization.name)
    ).all()
    return {"items": [org_payload(org, role) for role, org in rows]}


@router.post("/organizations", status_code=201)
def create_organization(body: OrgCreate, request: Request, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    hit_rate_limit(f"org-create:{auth.user.id}", limit=10, window_seconds=86400)
    org = Organization(name=body.name.strip(), slug=_slugify(db, body.name), created_by_id=auth.user.id)
    db.add(org)
    db.flush()
    db.add(Membership(org_id=org.id, user_id=auth.user.id, role="owner"))
    ensure_policy(db, org.id, auth.user.id)
    auth.session.active_org_id = org.id
    audit.record(db, "org.created", actor=auth.user, org_id=org.id, resource_type="organization", resource_id=org.id,
                 metadata={"name": org.name})
    db.commit()
    return org_payload(org, "owner", 1)


@router.get("/organizations/{org_id}")
def get_organization(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    count = db.execute(select(func.count()).select_from(Membership).where(Membership.org_id == ctx.org.id)).scalar_one()
    return org_payload(ctx.org, ctx.role, count)


@router.patch("/organizations/{org_id}")
def update_organization(body: OrgUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.ORG_UPDATE)
    changes = {}
    if body.name is not None:
        changes["name"] = [ctx.org.name, body.name.strip()]
        ctx.org.name = body.name.strip()
    if body.settings is not None:
        unknown = set(body.settings) - ALLOWED_ORG_SETTINGS
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unsupported settings: {', '.join(sorted(unknown))}")
        if "timezone" in body.settings:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

            try:
                ZoneInfo(str(body.settings["timezone"]))
            except (ZoneInfoNotFoundError, ValueError):
                raise HTTPException(status_code=422, detail="Unknown timezone.") from None
        ctx.org.settings_json = {**ctx.org.settings_json, **body.settings}
        changes["settings"] = sorted(body.settings)
    audit.record(db, "org.updated", actor=ctx.user, org_id=ctx.org.id, resource_type="organization",
                 resource_id=ctx.org.id, metadata=changes)
    db.commit()
    return org_payload(ctx.org, ctx.role)


@router.post("/organizations/{org_id}/archive")
def archive_organization(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.ORG_ARCHIVE)
    ctx.org.status = "archived"
    audit.record(db, "org.archived", actor=ctx.user, org_id=ctx.org.id, resource_type="organization", resource_id=ctx.org.id)
    db.commit()
    return org_payload(ctx.org, ctx.role)


@router.post("/organizations/{org_id}/restore")
def restore_organization(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.ORG_ARCHIVE)
    if ctx.org.status != "archived":
        raise HTTPException(status_code=409, detail="Organization is not archived.")
    ctx.org.status = "active"
    audit.record(db, "org.restored", actor=ctx.user, org_id=ctx.org.id, resource_type="organization", resource_id=ctx.org.id)
    db.commit()
    return org_payload(ctx.org, ctx.role)


# --- Members -----------------------------------------------------------------------

@router.get("/organizations/{org_id}/members")
def list_members(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                 search: str = Query(default="", max_length=120)):
    ctx.require(P.MEMBERS_VIEW)
    query = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == ctx.org.id)
        .order_by(User.email)
    )
    if search:
        like = f"%{search.lower()}%"
        query = query.where(func.lower(User.email).like(like) | func.lower(User.display_name).like(like))
    return {
        "items": [
            {
                "membership_id": m.id,
                "user_id": u.id,
                "email": u.email,
                "display_name": u.display_name,
                "role": m.role,
                "is_active": u.is_active,
                "joined_at": m.created_at.isoformat(),
            }
            for m, u in db.execute(query).all()
        ]
    }


def _owner_count(db: Session, org_id: str) -> int:
    return db.execute(
        select(func.count()).select_from(Membership).where(Membership.org_id == org_id, Membership.role == "owner")
    ).scalar_one()


def _membership(db: Session, ctx: OrgContext, user_id: str) -> Membership:
    membership = db.execute(
        select(Membership).where(Membership.org_id == ctx.org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Member not found.")
    return membership


@router.patch("/organizations/{org_id}/members/{user_id}")
def change_member_role(user_id: str, body: MemberRoleUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    if body.role not in ORG_ROLES:
        raise HTTPException(status_code=422, detail="Unknown role.")
    ctx.require(P.MEMBERS_MANAGE)
    membership = _membership(db, ctx, user_id)
    # Both the current and the new role must be within the actor's authority.
    if not can_assign_role(ctx.role, body.role) or not can_assign_role(ctx.role, membership.role):
        raise HTTPException(status_code=403, detail="Only owners can grant or change owner and admin roles.")
    if membership.role == "owner" and body.role != "owner" and _owner_count(db, ctx.org.id) <= 1:
        raise HTTPException(status_code=409, detail="An organization must keep at least one owner.")
    previous = membership.role
    membership.role = body.role
    audit.record(db, "member.role_changed", actor=ctx.user, org_id=ctx.org.id, resource_type="user", resource_id=user_id,
                 metadata={"from": previous, "to": body.role})
    db.commit()
    return {"user_id": user_id, "role": body.role}


@router.delete("/organizations/{org_id}/members/{user_id}")
def remove_member(user_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    membership = _membership(db, ctx, user_id)
    leaving_self = user_id == ctx.user.id
    if not leaving_self:
        ctx.require(P.MEMBERS_MANAGE)
        if not can_assign_role(ctx.role, membership.role):
            raise HTTPException(status_code=403, detail="Only owners can remove owners or admins.")
    if membership.role == "owner" and _owner_count(db, ctx.org.id) <= 1:
        raise HTTPException(status_code=409, detail="An organization must keep at least one owner.")
    db.execute(ProjectMember.__table__.delete().where(ProjectMember.org_id == ctx.org.id, ProjectMember.user_id == user_id))
    db.delete(membership)
    audit.record(db, "member.removed", actor=ctx.user, org_id=ctx.org.id, resource_type="user", resource_id=user_id,
                 metadata={"role": membership.role, "self": leaving_self})
    db.commit()
    return {"status": "removed"}


# --- Invitations -----------------------------------------------------------------

def _invitation_payload(inv: Invitation) -> dict:
    now = utcnow()
    state = (
        "accepted" if inv.accepted_at else
        "revoked" if inv.revoked_at else
        "expired" if inv.expires_at <= now else
        "pending"
    )
    return {
        "id": inv.id,
        "email": inv.email,
        "role": inv.role,
        "state": state,
        "expires_at": inv.expires_at.isoformat(),
        "created_at": inv.created_at.isoformat(),
        "send_count": inv.send_count,
    }


def _deliver_invitation(org: Organization, inviter: User, inv: Invitation, token: str) -> dict:
    link = f"{platform_settings.public_app_url}/invitations/accept?token={token}"
    result = send_email(
        inv.email,
        f"You're invited to {org.name} on SecurCode",
        f"{inviter.display_name or inviter.email} invited you to join {org.name} as {inv.role.replace('_', ' ')}.\n\n"
        f"Accept the invitation (expires in {INVITATION_DAYS} days):\n{link}",
    )
    payload = {"delivery": result.mode}
    if not result.delivered:
        # Without email delivery the link is returned exactly once to the
        # inviting administrator so they can share it through another channel.
        payload["accept_link"] = link
    return payload


@router.get("/organizations/{org_id}/invitations")
def list_invitations(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.MEMBERS_MANAGE)
    items = db.execute(
        select(Invitation).where(Invitation.org_id == ctx.org.id).order_by(Invitation.created_at.desc())
    ).scalars()
    return {"items": [_invitation_payload(inv) for inv in items]}


@router.post("/organizations/{org_id}/invitations", status_code=201)
def create_invitation(body: InvitationCreate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.MEMBERS_MANAGE)
    if body.role not in ORG_ROLES:
        raise HTTPException(status_code=422, detail="Unknown role.")
    if not can_assign_role(ctx.role, body.role):
        raise HTTPException(status_code=403, detail="Only owners can invite owners or admins.")
    hit_rate_limit(f"invite:{ctx.org.id}", limit=50, window_seconds=3600)
    email = body.email.strip().lower()
    existing_member = db.execute(
        select(Membership.id).join(User, User.id == Membership.user_id)
        .where(Membership.org_id == ctx.org.id, User.email == email)
    ).first()
    if existing_member:
        raise HTTPException(status_code=409, detail="That person is already a member.")
    now = utcnow()
    for pending in db.execute(
        select(Invitation).where(
            Invitation.org_id == ctx.org.id, Invitation.email == email,
            Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None),
        )
    ).scalars():
        pending.revoked_at = now
    token = new_token()
    inv = Invitation(
        org_id=ctx.org.id, email=email, role=body.role, token_hash=token_digest(token),
        invited_by_id=ctx.user.id, expires_at=now + timedelta(days=INVITATION_DAYS),
    )
    db.add(inv)
    db.flush()
    invitee = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if invitee:
        notify(db, [invitee.id], "invitation", f"Invitation to join {ctx.org.name}",
               f"You were invited as {body.role.replace('_', ' ')}.", "/invitations")
    audit.record(db, "member.invited", actor=ctx.user, org_id=ctx.org.id, resource_type="invitation", resource_id=inv.id,
                 metadata={"email": email, "role": body.role})
    db.commit()
    return {**_invitation_payload(inv), **_deliver_invitation(ctx.org, ctx.user, inv, token)}


@router.post("/organizations/{org_id}/invitations/{invitation_id}/resend")
def resend_invitation(invitation_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.MEMBERS_MANAGE)
    inv = db.execute(
        select(Invitation).where(Invitation.id == invitation_id, Invitation.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if inv is None or inv.accepted_at or inv.revoked_at:
        raise HTTPException(status_code=404, detail="Pending invitation not found.")
    if not can_assign_role(ctx.role, inv.role):
        raise HTTPException(status_code=403, detail="Only owners can manage owner or admin invitations.")
    hit_rate_limit(f"invite-resend:{inv.id}", limit=5, window_seconds=3600)
    token = new_token()  # rotating the token invalidates any previously sent link
    inv.token_hash = token_digest(token)
    inv.expires_at = utcnow() + timedelta(days=INVITATION_DAYS)
    inv.send_count += 1
    audit.record(db, "member.invitation_resent", actor=ctx.user, org_id=ctx.org.id, resource_type="invitation", resource_id=inv.id)
    db.commit()
    return {**_invitation_payload(inv), **_deliver_invitation(ctx.org, ctx.user, inv, token)}


@router.delete("/organizations/{org_id}/invitations/{invitation_id}")
def revoke_invitation(invitation_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.MEMBERS_MANAGE)
    inv = db.execute(
        select(Invitation).where(Invitation.id == invitation_id, Invitation.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    if not can_assign_role(ctx.role, inv.role):
        raise HTTPException(status_code=403, detail="Only owners can manage owner or admin invitations.")
    if inv.accepted_at is None and inv.revoked_at is None:
        inv.revoked_at = utcnow()
        audit.record(db, "member.invitation_revoked", actor=ctx.user, org_id=ctx.org.id, resource_type="invitation", resource_id=inv.id)
        db.commit()
    return _invitation_payload(inv)


@router.post("/invitations/preview")
def preview_invitation(body: InvitationAccept, request: Request, db: Session = Depends(get_db)):
    """Unauthenticated: shows which org/role a token is for so the invitee can
    decide whether to register or sign in. Reveals nothing without the token."""
    hit_rate_limit(f"invite-preview:{client_ip(request)}", limit=30, window_seconds=600)
    inv = db.execute(select(Invitation).where(Invitation.token_hash == token_digest(body.token))).scalar_one_or_none()
    if inv is None or inv.accepted_at or inv.revoked_at or inv.expires_at <= utcnow():
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")
    org = db.get(Organization, inv.org_id)
    has_account = db.execute(select(User.id).where(User.email == inv.email)).first() is not None
    return {"organization_name": org.name, "role": inv.role, "email": inv.email, "has_account": has_account}


@router.post("/invitations/accept")
def accept_invitation(body: InvitationAccept, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    hit_rate_limit(f"invite-accept:{auth.user.id}", limit=20, window_seconds=600)
    inv = db.execute(select(Invitation).where(Invitation.token_hash == token_digest(body.token))).scalar_one_or_none()
    if inv is None or inv.accepted_at or inv.revoked_at or inv.expires_at <= utcnow():
        raise HTTPException(status_code=404, detail="This invitation is invalid or has expired.")
    if inv.email != auth.user.email:
        raise HTTPException(status_code=403, detail="This invitation was issued to a different email address.")
    org = db.get(Organization, inv.org_id)
    if org.status != "active":
        raise HTTPException(status_code=409, detail="This organization is not accepting new members.")
    existing = db.execute(
        select(Membership).where(Membership.org_id == inv.org_id, Membership.user_id == auth.user.id)
    ).scalar_one_or_none()
    if existing is None:
        db.add(Membership(org_id=inv.org_id, user_id=auth.user.id, role=inv.role))
    elif ROLE_RANK[inv.role] > ROLE_RANK[existing.role]:
        existing.role = inv.role
    inv.accepted_at = utcnow()
    inv.accepted_by_id = auth.user.id
    if auth.user.email_verified_at is None:
        # Possessing a token mailed to the address proves control of it.
        auth.user.email_verified_at = utcnow()
    auth.session.active_org_id = inv.org_id
    audit.record(db, "member.joined", actor=auth.user, org_id=inv.org_id, resource_type="invitation", resource_id=inv.id,
                 metadata={"role": inv.role})
    if inv.invited_by_id:
        notify(db, [inv.invited_by_id], "invitation", f"{auth.user.email} joined {org.name}", org_id=org.id, link="/team")
    db.commit()
    return {"status": "joined", "org_id": inv.org_id, "role": inv.role}


# --- Activity ----------------------------------------------------------------------

@router.get("/organizations/{org_id}/activity")
def team_activity(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                  limit: int = Query(default=30, ge=1, le=100)):
    ctx.require(P.MEMBERS_VIEW)
    team_actions = ("member.", "project.", "scan.", "finding.", "org.")
    events = db.execute(
        select(AuditEvent).where(AuditEvent.org_id == ctx.org.id).order_by(AuditEvent.id.desc()).limit(limit * 3)
    ).scalars()
    items = [
        {
            "action": e.action,
            "actor_email": e.actor_email,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
        if e.action.startswith(team_actions)
    ][:limit]
    return {"items": items}
