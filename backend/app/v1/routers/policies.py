"""Security policies, rule catalogue and organisation audit log."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from security_engine.scanner.rules import RULES, SCANNER_VERSION, ruleset_version

from .. import audit
from ..db import get_db
from ..deps import AuthContext, OrgContext, current_auth, org_context, writable_org
from ..models import AuditEvent, SecurityPolicyVersion, User
from ..permissions import P
from ..services.common import notify, org_members_with_roles
from ..services.policy import DEFAULT_POLICY, ensure_policy, update_policy

router = APIRouter(tags=["policies"])


class PolicyUpdate(BaseModel):
    changes: dict
    reason: str = Field(min_length=5, max_length=1000)


@router.get("/rules")
def list_rules(_: AuthContext = Depends(current_auth), language: str | None = Query(default=None, max_length=20)):
    rules = [rule.as_dict() for rule in RULES.values() if not language or language.lower() in rule.languages]
    return {"scanner_version": SCANNER_VERSION, "ruleset_version": ruleset_version(), "items": rules}


@router.get("/organizations/{org_id}/policy")
def get_policy(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.POLICIES_VIEW)
    policy = ensure_policy(db, ctx.org.id)
    db.commit()
    return {"version": policy.version, "config": {**DEFAULT_POLICY, **policy.config}, "updated_at": policy.updated_at.isoformat(),
            "can_edit": ctx.can(P.POLICIES_MANAGE)}


@router.put("/organizations/{org_id}/policy")
def put_policy(body: PolicyUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.POLICIES_MANAGE)
    before = ensure_policy(db, ctx.org.id).config
    policy = update_policy(db, ctx.org.id, body.changes, ctx.user.id, body.reason)
    changed = sorted(k for k in policy.config if before.get(k) != policy.config.get(k))
    audit.record(db, "policy.updated", actor=ctx.user, org_id=ctx.org.id, resource_type="policy", resource_id=policy.id,
                 metadata={"version": policy.version, "changed_keys": changed, "reason": body.reason})
    notify(db, [uid for uid in org_members_with_roles(db, ctx.org.id, {"owner", "admin", "security_admin"}) if uid != ctx.user.id],
           "policy_changed", f"Security policy updated to v{policy.version}", body.reason, f"/orgs/{ctx.org.id}/policy", ctx.org.id)
    db.commit()
    return {"version": policy.version, "config": policy.config, "changed_keys": changed}


@router.get("/organizations/{org_id}/policy/history")
def policy_history(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.POLICIES_VIEW)
    rows = db.execute(
        select(SecurityPolicyVersion, User.email).outerjoin(User, User.id == SecurityPolicyVersion.changed_by_id)
        .where(SecurityPolicyVersion.org_id == ctx.org.id).order_by(SecurityPolicyVersion.version.desc())
    ).all()
    return {"items": [{"version": v.version, "config": v.config, "reason": v.reason, "changed_by": email,
                       "created_at": v.created_at.isoformat()} for v, email in rows]}


def _audit_query(ctx: OrgContext, action: str | None, actor: str | None, resource_type: str | None):
    query = select(AuditEvent).where(AuditEvent.org_id == ctx.org.id)
    if action:
        query = query.where(AuditEvent.action.like(f"{action}%"))
    if actor:
        query = query.where(AuditEvent.actor_email == actor.lower())
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    return query


def _audit_row(event: AuditEvent) -> dict:
    return {"id": event.id, "action": event.action, "actor_email": event.actor_email, "actor_id": event.actor_id,
            "project_id": event.project_id, "resource_type": event.resource_type, "resource_id": event.resource_id,
            "metadata": event.metadata_json, "ip_address": event.ip_address, "request_id": event.request_id,
            "created_at": event.created_at.isoformat(), "hash": event.hash}


@router.get("/organizations/{org_id}/audit-events")
def list_audit_events(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                      action: str | None = Query(default=None, max_length=80), actor: str | None = Query(default=None, max_length=254),
                      resource_type: str | None = Query(default=None, max_length=40),
                      limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    ctx.require(P.AUDIT_VIEW)
    query = _audit_query(ctx, action, actor, resource_type)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    events = db.execute(query.order_by(AuditEvent.id.desc()).limit(limit).offset(offset)).scalars()
    return {"items": [_audit_row(e) for e in events], "total": total, "limit": limit, "offset": offset}


@router.get("/organizations/{org_id}/audit-events/export.csv")
def export_audit_events(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                        action: str | None = Query(default=None, max_length=80)):
    ctx.require(P.AUDIT_VIEW)
    events = db.execute(_audit_query(ctx, action, None, None).order_by(AuditEvent.id).limit(50_000)).scalars().all()
    audit.record(db, "report.exported", actor=ctx.user, org_id=ctx.org.id, resource_type="audit_log", metadata={"rows": len(events)})
    db.commit()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "created_at", "action", "actor_email", "resource_type", "resource_id", "project_id", "ip_address", "request_id", "hash"])
    for e in events:
        writer.writerow([e.id, e.created_at.isoformat(), e.action, e.actor_email or "", e.resource_type or "", e.resource_id or "",
                         e.project_id or "", e.ip_address or "", e.request_id or "", e.hash])
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="audit-{ctx.org.slug}.csv"'})
