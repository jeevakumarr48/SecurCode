"""Vulnerability management: triage, assignment, comments, reviews and bulk actions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from security_engine.scanner.rules import RULES

from .. import audit
from ..db import get_db, utcnow
from ..deps import OrgContext, get_finding, get_project, org_context, visible_project_ids, writable_org
from ..models import FINDING_STATUSES, SEVERITIES, Finding, FindingEvent, FindingReview, Membership, Project, ProjectMember, User
from ..permissions import DEVELOPER_STATUSES, P
from ..services.common import notify, org_members_with_roles
from ..services.policy import effective_policy

router = APIRouter(prefix="/organizations/{org_id}", tags=["findings"])

# Manual transitions. "resolved" is reserved for scan verification; reviewed
# statuses (accepted_risk/false_positive) may additionally require approval.
TRANSITIONS = {
    "open": {"triaged", "in_progress", "fixed", "accepted_risk", "false_positive"},
    "triaged": {"open", "in_progress", "fixed", "accepted_risk", "false_positive"},
    "in_progress": {"triaged", "fixed", "open"},
    "fixed": {"in_progress", "open"},
    "resolved": {"reopened"},
    "accepted_risk": {"open"},
    "false_positive": {"open"},
    "reopened": {"triaged", "in_progress", "fixed", "accepted_risk", "false_positive"},
}
REVIEWED = {"accepted_risk", "false_positive"}
SORTS = {"severity", "-severity", "first_detected_at", "-first_detected_at", "due_date", "-due_date", "file_path"}
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}  # critical=0


class FindingUpdate(BaseModel):
    status: str | None = None
    justification: str | None = Field(default=None, max_length=4000)
    assignee_id: str | None = None
    unassign: bool = False
    due_date: datetime | None = None
    clear_due_date: bool = False
    labels: list[str] | None = None
    severity: str | None = None
    severity_reason: str | None = Field(default=None, max_length=1000)
    remediation_notes: str | None = Field(default=None, max_length=8000)

    @field_validator("labels")
    @classmethod
    def _labels(cls, value):
        if value is None:
            return value
        cleaned = sorted({label.strip().lower()[:40] for label in value if label.strip()})
        if len(cleaned) > 20:
            raise ValueError("At most 20 labels are allowed.")
        return cleaned


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class BulkUpdate(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=500)
    status: str | None = None
    justification: str | None = Field(default=None, max_length=4000)
    assignee_id: str | None = None
    add_labels: list[str] | None = None


class ReviewRequest(BaseModel):
    kind: str
    justification: str = Field(min_length=20, max_length=4000)
    expires_at: datetime | None = None


class ReviewDecision(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)


def finding_payload(finding: Finding, users: dict | None = None) -> dict:
    users = users or {}
    assignee = users.get(finding.assignee_id)
    return {
        "id": finding.id, "org_id": finding.org_id, "project_id": finding.project_id, "scope": finding.scope_key,
        "rule_id": finding.rule_id, "title": finding.title, "description": finding.description,
        "severity": finding.severity, "original_severity": finding.original_severity, "confidence": finding.confidence,
        "language": finding.language, "cwe": finding.cwe, "owasp": finding.owasp, "file_path": finding.file_path,
        "line": finding.line, "status": finding.status, "verification_status": finding.verification_status,
        "assignee": {"id": assignee.id, "email": assignee.email, "display_name": assignee.display_name} if assignee else None,
        "assignee_id": finding.assignee_id,
        "due_date": finding.due_date.isoformat() if finding.due_date else None,
        "overdue": bool(finding.due_date and finding.due_date < utcnow() and finding.status in {"open", "triaged", "in_progress", "reopened"}),
        "labels": finding.labels, "first_detected_at": finding.first_detected_at.isoformat(),
        "last_detected_at": finding.last_detected_at.isoformat(), "first_scan_id": finding.first_scan_id,
        "last_scan_id": finding.last_scan_id, "fixed_scan_id": finding.fixed_scan_id,
        "recurrence_count": finding.recurrence_count, "fingerprint": finding.fingerprint,
    }


def _users(db: Session, ids) -> dict:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: u for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def remediation_intelligence(finding: Finding) -> dict:
    """Deterministic, rule-specific guidance. Not AI-generated."""
    rule = RULES.get(finding.rule_id)
    if rule is None:
        return {"source": "rule", "summary": finding.description}
    return {
        "source": "rule",
        "meaning": rule.description,
        "why_it_matters": rule.impact,
        "where": f"{finding.file_path}:{finding.line}" if finding.line else finding.file_path,
        "recommended_fix": rule.remediation,
        "safer_example": rule.safer_example or None,
        "validation_steps": [
            "Apply the fix and add a regression test covering the unsafe input.",
            f"Re-run a complete scan; the finding is verified fixed only if rule {rule.id} no longer reports it.",
            "Have a reviewer confirm the change addresses the root cause rather than only the flagged line.",
        ],
        "cwe": rule.cwe, "cwe_url": rule.references[0] if rule.references else None, "owasp": rule.as_dict()["owasp"],
        "detection_technique": rule.technique, "false_positive_considerations": rule.false_positives or None,
        "references": list(rule.references),
    }


@router.get("/findings")
def list_findings(
    ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
    project_id: str | None = None,
    status: list[str] | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    assignee: str | None = Query(default=None, max_length=32),
    rule_id: str | None = Query(default=None, max_length=40),
    cwe: str | None = Query(default=None, max_length=20),
    label: str | None = Query(default=None, max_length=40),
    search: str = Query(default="", max_length=200),
    overdue: bool = False,
    sort: str = Query(default="severity"),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
):
    if sort not in SORTS:
        raise HTTPException(status_code=422, detail="Unsupported sort.")
    query = select(Finding).where(Finding.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(Finding.project_id.in_(allowed or {"-"}))
    if project_id:
        get_project(db, ctx, project_id)
        query = query.where(Finding.project_id == project_id)
    if status:
        query = query.where(Finding.status.in_(status))
    if severity:
        query = query.where(Finding.severity.in_(severity))
    if assignee == "me":
        query = query.where(Finding.assignee_id == ctx.user.id)
    elif assignee == "none":
        query = query.where(Finding.assignee_id.is_(None))
    elif assignee:
        query = query.where(Finding.assignee_id == assignee)
    if rule_id:
        query = query.where(Finding.rule_id == rule_id)
    if cwe:
        query = query.where(Finding.cwe == cwe)
    if search:
        like = f"%{search.lower()}%"
        query = query.where(or_(func.lower(Finding.title).like(like), func.lower(Finding.file_path).like(like),
                                func.lower(Finding.rule_id).like(like)))
    if overdue:
        query = query.where(Finding.due_date < utcnow(), Finding.status.in_(["open", "triaged", "in_progress", "reopened"]))
    reverse = sort.startswith("-")
    field = sort.lstrip("-")
    if field == "severity":
        rank = case({name: index for index, name in enumerate(SEVERITIES)}, value=Finding.severity, else_=9)
        order = [rank.desc() if reverse else rank.asc(), Finding.first_detected_at.desc()]
    elif field == "due_date":
        order = [Finding.due_date.is_(None), Finding.due_date.desc() if reverse else Finding.due_date.asc()]
    else:
        column = getattr(Finding, field)
        order = [column.desc() if reverse else column.asc()]
    query = query.order_by(*order, Finding.id)
    if label:
        # Label membership is evaluated in Python for portability across SQLite and PostgreSQL JSON.
        matching = [f for f in db.execute(query).scalars().all() if label in (f.labels or [])]
        total = len(matching)
        page = matching[offset:offset + limit]
    else:
        total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
        page = db.execute(query.limit(limit).offset(offset)).scalars().all()
    users = _users(db, [f.assignee_id for f in page])
    names = dict(db.execute(select(Project.id, Project.name).where(Project.id.in_({f.project_id for f in page} or {"-"}))).all())
    return {"items": [{**finding_payload(f, users), "project_name": names.get(f.project_id)} for f in page],
            "total": total, "limit": limit, "offset": offset}


@router.get("/findings/{finding_id}")
def get_finding_detail(finding_id: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    finding = get_finding(db, ctx, finding_id)
    events = db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding.id).order_by(FindingEvent.created_at, FindingEvent.id)
    ).scalars().all()
    reviews = db.execute(
        select(FindingReview).where(FindingReview.finding_id == finding.id).order_by(FindingReview.created_at.desc())
    ).scalars().all()
    users = _users(db, [finding.assignee_id, *[e.actor_id for e in events], *[r.requested_by_id for r in reviews],
                        *[r.reviewer_id for r in reviews]])
    project = db.get(Project, finding.project_id)
    return {
        **finding_payload(finding, users),
        "project_name": project.name,
        "snippet": finding.snippet,
        "remediation_notes": finding.remediation_notes,
        "guidance": remediation_intelligence(finding),
        "ai_assistance": {"available": False, "reason": "No AI provider is configured; showing deterministic rule guidance."},
        "events": [
            {"id": e.id, "kind": e.kind, "body": e.body, "from": e.from_value, "to": e.to_value,
             "actor": users[e.actor_id].email if e.actor_id in users else "SecurCode", "created_at": e.created_at.isoformat()}
            for e in events
        ],
        "reviews": [_review_payload(r, users) for r in reviews],
        "allowed_transitions": sorted(_allowed_transitions(ctx, finding, effective_policy(db, ctx.org.id))),
    }


def _review_payload(review: FindingReview, users: dict) -> dict:
    return {
        "id": review.id, "finding_id": review.finding_id, "kind": review.kind, "status": review.status,
        "justification": review.justification, "reviewer_note": review.reviewer_note,
        "requested_by": users[review.requested_by_id].email if review.requested_by_id in users else None,
        "reviewer": users[review.reviewer_id].email if review.reviewer_id in users else None,
        "expires_at": review.expires_at.isoformat() if review.expires_at else None,
        "created_at": review.created_at.isoformat(),
        "reviewed_at": review.reviewed_at.isoformat() if review.reviewed_at else None,
    }


def _allowed_transitions(ctx: OrgContext, finding: Finding, policy: dict) -> set[str]:
    allowed = set(TRANSITIONS.get(finding.status, set()))
    if ctx.can(P.FINDINGS_TRIAGE):
        if policy["accepted_risk_requires_review"] and not ctx.can(P.REVIEWS_APPROVE):
            allowed.discard("accepted_risk")
        if policy["false_positive_requires_review"] and not ctx.can(P.REVIEWS_APPROVE):
            allowed.discard("false_positive")
        return allowed
    if ctx.can(P.FINDINGS_REMEDIATE) and finding.assignee_id == ctx.user.id:
        return allowed & DEVELOPER_STATUSES
    return set()


def _event(db, finding, ctx, kind, body=None, from_value=None, to_value=None):
    db.add(FindingEvent(org_id=finding.org_id, finding_id=finding.id, actor_id=ctx.user.id, kind=kind, body=body,
                        from_value=from_value, to_value=to_value))


def _assignable(db: Session, ctx: OrgContext, finding: Finding, user_id: str) -> User:
    membership = db.execute(
        select(Membership).where(Membership.org_id == ctx.org.id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=422, detail="Assignees must be members of this organization.")
    if membership.role in {"developer", "viewer"}:
        on_project = db.execute(
            select(ProjectMember.id).where(ProjectMember.project_id == finding.project_id, ProjectMember.user_id == user_id)
        ).first()
        if on_project is None:
            # Developers only see projects they belong to; add them so the assignment is usable.
            db.add(ProjectMember(org_id=ctx.org.id, project_id=finding.project_id, user_id=user_id, role="contributor"))
    return db.get(User, user_id)


def apply_update(db: Session, ctx: OrgContext, finding: Finding, body: FindingUpdate, policy: dict) -> list[str]:
    changed = []
    if body.status is not None and body.status != finding.status:
        if body.status not in FINDING_STATUSES:
            raise HTTPException(status_code=422, detail="Unknown status.")
        if body.status not in _allowed_transitions(ctx, finding, policy):
            raise HTTPException(status_code=403 if body.status in TRANSITIONS.get(finding.status, set()) else 409,
                                detail=f"You cannot change this finding from {finding.status} to {body.status}.")
        if body.status in REVIEWED and not (body.justification and len(body.justification.strip()) >= 20):
            raise HTTPException(status_code=422, detail="A justification of at least 20 characters is required.")
        previous = finding.status
        finding.status = body.status
        if body.status == "fixed":
            finding.verification_status = "unverified"
        if body.status in REVIEWED:
            # Direct decision by an approver (or review not required): record it as an approved review.
            now = utcnow()
            db.add(FindingReview(org_id=finding.org_id, finding_id=finding.id, kind=body.status, justification=body.justification,
                                 status="approved", requested_by_id=ctx.user.id, reviewer_id=ctx.user.id, reviewed_at=now,
                                 previous_status=previous,
                                 expires_at=now + timedelta(days=policy["accepted_risk_max_days"]) if body.status == "accepted_risk" else None))
        _event(db, finding, ctx, "status", body.justification, previous, body.status)
        audit.record(db, f"finding.{'risk_accepted' if body.status == 'accepted_risk' else 'false_positive' if body.status == 'false_positive' else 'status_changed'}",
                     actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id, resource_type="finding", resource_id=finding.id,
                     metadata={"from": previous, "to": body.status})
        changed.append("status")
    if body.assignee_id is not None or body.unassign:
        ctx.require(P.FINDINGS_TRIAGE)
        target = None if body.unassign else body.assignee_id
        if target != finding.assignee_id:
            user = _assignable(db, ctx, finding, target) if target else None
            previous = finding.assignee_id
            finding.assignee_id = target
            _event(db, finding, ctx, "assignment", None, previous, user.email if user else None)
            audit.record(db, "finding.assigned", actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id,
                         resource_type="finding", resource_id=finding.id, metadata={"assignee_id": target})
            if target and target != ctx.user.id:
                notify(db, [target], "finding_assigned", f"Assigned: {finding.title}", f"{finding.file_path}:{finding.line or ''}",
                       f"/orgs/{ctx.org.id}/findings/{finding.id}", ctx.org.id)
            changed.append("assignee")
    if body.due_date is not None or body.clear_due_date:
        ctx.require(P.FINDINGS_TRIAGE)
        due = None if body.clear_due_date else body.due_date
        if due is not None and due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        finding.due_date = due
        _event(db, finding, ctx, "due_date", None, None, due.date().isoformat() if due else None)
        changed.append("due_date")
    if body.labels is not None:
        ctx.require(P.FINDINGS_TRIAGE)
        finding.labels = body.labels
        _event(db, finding, ctx, "labels", None, None, ",".join(body.labels)[:200])
        changed.append("labels")
    if body.severity is not None and body.severity != finding.severity:
        ctx.require(P.FINDINGS_SEVERITY)
        if body.severity not in SEVERITIES:
            raise HTTPException(status_code=422, detail="Unknown severity.")
        if not body.severity_reason or len(body.severity_reason.strip()) < 10:
            raise HTTPException(status_code=422, detail="Explain the severity change (at least 10 characters).")
        previous = finding.severity
        finding.severity = body.severity
        _event(db, finding, ctx, "severity", body.severity_reason, previous, body.severity)
        audit.record(db, "finding.severity_changed", actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id,
                     resource_type="finding", resource_id=finding.id, metadata={"from": previous, "to": body.severity})
        changed.append("severity")
    if body.remediation_notes is not None:
        if not (ctx.can(P.FINDINGS_TRIAGE) or (ctx.can(P.FINDINGS_REMEDIATE) and finding.assignee_id == ctx.user.id)):
            raise HTTPException(status_code=403, detail="Your role does not permit this action.")
        finding.remediation_notes = body.remediation_notes
        _event(db, finding, ctx, "remediation_notes", "Remediation notes updated.")
        changed.append("remediation_notes")
    return changed


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    finding = get_finding(db, ctx, finding_id)
    if not (ctx.can(P.FINDINGS_TRIAGE) or ctx.can(P.FINDINGS_REMEDIATE)):
        raise HTTPException(status_code=403, detail="Your role does not permit this action.")
    changed = apply_update(db, ctx, finding, body, effective_policy(db, ctx.org.id))
    db.commit()
    return {"changed": changed, **finding_payload(finding, _users(db, [finding.assignee_id]))}


@router.post("/findings/bulk")
def bulk_update(body: BulkUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.FINDINGS_TRIAGE)
    policy = effective_policy(db, ctx.org.id)
    results = {"updated": [], "failed": []}
    for finding_id in dict.fromkeys(body.finding_ids):
        try:
            finding = get_finding(db, ctx, finding_id)
            labels = sorted(set(finding.labels or []) | {label.strip().lower()[:40] for label in (body.add_labels or []) if label.strip()}) \
                if body.add_labels else None
            apply_update(db, ctx, finding, FindingUpdate(status=body.status, justification=body.justification,
                                                         assignee_id=body.assignee_id, labels=labels), policy)
            db.flush()
            results["updated"].append(finding_id)
        except HTTPException as error:
            results["failed"].append({"id": finding_id, "detail": error.detail})
    audit.record(db, "finding.bulk_updated", actor=ctx.user, org_id=ctx.org.id, resource_type="finding",
                 metadata={"count": len(results["updated"]), "status": body.status, "assignee_id": body.assignee_id})
    db.commit()
    return results


@router.post("/findings/{finding_id}/comments", status_code=201)
def add_comment(finding_id: str, body: CommentCreate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.FINDINGS_COMMENT)
    finding = get_finding(db, ctx, finding_id)
    event = FindingEvent(org_id=finding.org_id, finding_id=finding.id, actor_id=ctx.user.id, kind="comment", body=body.body)
    db.add(event)
    db.flush()
    watchers = {finding.assignee_id} | set(
        db.execute(select(FindingEvent.actor_id).where(FindingEvent.finding_id == finding.id, FindingEvent.kind == "comment")).scalars()
    )
    watchers.discard(ctx.user.id)
    notify(db, watchers, "finding_comment", f"New comment on {finding.title}", body.body[:200],
           f"/orgs/{ctx.org.id}/findings/{finding.id}", ctx.org.id)
    audit.record(db, "finding.commented", actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id, resource_type="finding",
                 resource_id=finding.id)
    db.commit()
    return {"id": event.id, "kind": "comment", "body": event.body, "actor": ctx.user.email, "created_at": event.created_at.isoformat()}


@router.post("/findings/{finding_id}/reviews", status_code=201)
def request_review(finding_id: str, body: ReviewRequest, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.REVIEWS_REQUEST)
    if body.kind not in REVIEWED:
        raise HTTPException(status_code=422, detail="kind must be accepted_risk or false_positive.")
    finding = get_finding(db, ctx, finding_id)
    if body.kind not in TRANSITIONS.get(finding.status, set()):
        raise HTTPException(status_code=409, detail=f"A {finding.status} finding cannot be marked {body.kind}.")
    if db.execute(select(FindingReview.id).where(FindingReview.finding_id == finding.id, FindingReview.status == "pending")).first():
        raise HTTPException(status_code=409, detail="A review is already pending for this finding.")
    policy = effective_policy(db, ctx.org.id)
    expires = body.expires_at
    if body.kind == "accepted_risk":
        limit = utcnow() + timedelta(days=policy["accepted_risk_max_days"])
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires is None or expires > limit:
            expires = limit
        if expires <= utcnow():
            raise HTTPException(status_code=422, detail="Risk acceptance must expire in the future.")
    else:
        expires = None
    review = FindingReview(org_id=ctx.org.id, finding_id=finding.id, kind=body.kind, justification=body.justification,
                           requested_by_id=ctx.user.id, expires_at=expires, previous_status=finding.status)
    db.add(review)
    db.flush()
    _event(db, finding, ctx, "review_requested", body.justification, None, body.kind)
    reviewers = [uid for uid in org_members_with_roles(db, ctx.org.id, {"owner", "admin", "security_admin"}) if uid != ctx.user.id]
    notify(db, reviewers, "review_requested", f"Review requested: {body.kind.replace('_', ' ')} for {finding.title}",
           body.justification[:200], f"/orgs/{ctx.org.id}/findings/{finding.id}", ctx.org.id)
    audit.record(db, "finding.review_requested", actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id,
                 resource_type="finding", resource_id=finding.id, metadata={"kind": body.kind, "review_id": review.id})
    db.commit()
    return _review_payload(review, {ctx.user.id: ctx.user})


@router.get("/reviews")
def list_reviews(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                 status: str = Query(default="pending", pattern="^(pending|approved|rejected|expired|all)$"),
                 kind: str | None = Query(default=None, pattern="^(accepted_risk|false_positive)$")):
    query = select(FindingReview, Finding).join(Finding, Finding.id == FindingReview.finding_id).where(FindingReview.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(Finding.project_id.in_(allowed or {"-"}))
    if status != "all":
        query = query.where(FindingReview.status == status)
    if kind:
        query = query.where(FindingReview.kind == kind)
    rows = db.execute(query.order_by(FindingReview.created_at.desc()).limit(200)).all()
    users = _users(db, [r.requested_by_id for r, _ in rows] + [r.reviewer_id for r, _ in rows])
    return {"items": [{**_review_payload(r, users), "finding_title": f.title, "severity": f.severity, "project_id": f.project_id}
                      for r, f in rows]}


@router.post("/reviews/{review_id}/decision")
def decide_review(review_id: str, body: ReviewDecision, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.REVIEWS_APPROVE)
    review = db.execute(
        select(FindingReview).where(FindingReview.id == review_id, FindingReview.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    finding = get_finding(db, ctx, review.finding_id)
    if review.status != "pending":
        raise HTTPException(status_code=409, detail="This review has already been decided.")
    if review.requested_by_id == ctx.user.id:
        raise HTTPException(status_code=403, detail="Reviews must be decided by someone other than the requester.")
    review.status = "approved" if body.approve else "rejected"
    review.reviewer_id = ctx.user.id
    review.reviewer_note = body.note
    review.reviewed_at = utcnow()
    if body.approve:
        previous = finding.status
        finding.status = review.kind
        _event(db, finding, ctx, "status", f"Review approved: {body.note}".strip(": "), previous, review.kind)
    else:
        _event(db, finding, ctx, "review_rejected", body.note or None, None, review.kind)
    notify(db, [review.requested_by_id], "review_decision",
           f"{review.kind.replace('_', ' ').capitalize()} {review.status}: {finding.title}", body.note,
           f"/orgs/{ctx.org.id}/findings/{finding.id}", ctx.org.id)
    audit.record(db, f"finding.review_{review.status}", actor=ctx.user, org_id=ctx.org.id, project_id=finding.project_id,
                 resource_type="finding", resource_id=finding.id, metadata={"kind": review.kind, "review_id": review.id})
    db.commit()
    return _review_payload(review, _users(db, [review.requested_by_id, review.reviewer_id]))
