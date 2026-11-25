"""Dashboard analytics computed from persisted scans and findings only."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db, utcnow
from ..deps import OrgContext, get_project, org_context, visible_project_ids
from ..models import Finding, FindingEvent, Project, Scan
from ..services.posture import ACTIVE, FORMULA_VERSION, grade, project_posture

router = APIRouter(prefix="/organizations/{org_id}", tags=["analytics"])


@router.get("/analytics/dashboard")
def dashboard(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
              project_id: str | None = None, days: int = Query(default=30, ge=7, le=365)):
    allowed = visible_project_ids(db, ctx)
    projects_query = select(Project).where(Project.org_id == ctx.org.id, Project.status == "active")
    if allowed is not None:
        projects_query = projects_query.where(Project.id.in_(allowed or {"-"}))
    if project_id:
        get_project(db, ctx, project_id)
        projects_query = projects_query.where(Project.id == project_id)
    projects = db.execute(projects_query).scalars().all()
    project_ids = [p.id for p in projects] or ["-"]
    now = utcnow()
    since = now - timedelta(days=days)

    findings = db.execute(select(Finding).where(Finding.org_id == ctx.org.id, Finding.project_id.in_(project_ids))).scalars().all()
    active = [f for f in findings if f.status in ACTIVE]
    scans = db.execute(select(Scan).where(Scan.org_id == ctx.org.id, Scan.project_id.in_(project_ids))).scalars().all()
    finished = [s for s in scans if s.status in {"completed", "completed_with_warnings", "failed"}]
    succeeded = [s for s in finished if s.status != "failed"]
    durations = [s.duration_ms for s in succeeded if s.duration_ms is not None]

    severity = Counter(f.severity for f in active)
    status_counts = Counter(f.status for f in findings)
    new_in_window = sum(1 for f in findings if f.first_detected_at >= since)
    resolved_in_window = sum(1 for f in findings if f.status == "resolved" and f.updated_at >= since)
    recurring = sum(1 for f in findings if f.recurrence_count > 0)

    # Daily trend of open findings reconstructed from detection and verification events.
    resolved_events = db.execute(
        select(FindingEvent.finding_id, func.min(FindingEvent.created_at))
        .where(FindingEvent.org_id == ctx.org.id, FindingEvent.kind == "verification", FindingEvent.to_value == "resolved")
        .group_by(FindingEvent.finding_id)
    ).all()
    resolved_at = dict(resolved_events)
    trend = []
    for offset in range(days, -1, -max(days // 30, 1)):
        day = (now - timedelta(days=offset)).replace(hour=23, minute=59, second=59)
        opened = 0
        for f in findings:
            if f.first_detected_at > day:
                continue
            closed = resolved_at.get(f.id)
            if f.status in ACTIVE or (closed and closed > day) or (f.status not in ACTIVE and f.updated_at > day and not closed):
                opened += 1
        trend.append({"date": day.date().isoformat(), "open": opened,
                      "new": sum(1 for f in findings if f.first_detected_at.date() == day.date())})

    by_cwe = Counter(f.cwe or "Unmapped" for f in active)
    by_owasp = Counter(f.owasp or "Unmapped" for f in active)
    by_language = Counter((f.language or "unknown").lower() for f in active)
    posture_rows = []
    for project in projects:
        posture = project_posture(db, project)
        posture_rows.append({"project_id": project.id, "name": project.name, **posture,
                             "active_findings": sum(1 for f in active if f.project_id == project.id)})
    assessed = [row["score"] for row in posture_rows if row["score"] is not None]
    org_score = round(sum(assessed) / len(assessed), 1) if assessed else None
    remediation_total = sum(1 for f in findings if f.status not in {"false_positive"})
    remediated = sum(1 for f in findings if f.status in {"resolved", "fixed"})
    return {
        "generated_at": now.isoformat(),
        "is_demo": ctx.org.is_demo,
        "window_days": days,
        "totals": {
            "projects": len(projects),
            "scans": len(scans),
            "active_findings": len(active),
            "critical": severity.get("critical", 0), "high": severity.get("high", 0), "medium": severity.get("medium", 0),
            "low": severity.get("low", 0), "info": severity.get("info", 0),
            "new_findings": new_in_window, "resolved_findings": resolved_in_window, "recurring_findings": recurring,
            "open_remediation_tasks": sum(1 for f in active if f.assignee_id),
            "overdue": sum(1 for f in active if f.due_date and f.due_date < now),
        },
        "scan_health": {
            "success_rate": round(len(succeeded) / len(finished), 3) if finished else None,
            "average_duration_ms": int(sum(durations) / len(durations)) if durations else None,
            "running": sum(1 for s in scans if s.status == "running"),
            "queued": sum(1 for s in scans if s.status == "queued"),
            "failed": sum(1 for s in finished if s.status == "failed"),
        },
        "status_breakdown": dict(status_counts),
        "remediation_progress": {"remediated": remediated, "total": remediation_total,
                                 "ratio": round(remediated / remediation_total, 3) if remediation_total else None},
        "posture": {"score": org_score, "grade": grade(org_score), "formula": FORMULA_VERSION, "projects": posture_rows},
        "trend": trend,
        "distribution": {
            "cwe": [{"name": k, "count": v} for k, v in by_cwe.most_common(12)],
            "owasp": [{"name": k, "count": v} for k, v in by_owasp.most_common(10)],
            "language": [{"name": k, "count": v} for k, v in by_language.most_common()],
        },
    }


@router.get("/analytics/mttr")
def mean_time_to_remediate(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    allowed = visible_project_ids(db, ctx)
    query = select(Finding).where(Finding.org_id == ctx.org.id, Finding.status == "resolved")
    if allowed is not None:
        query = query.where(Finding.project_id.in_(allowed or {"-"}))
    durations = defaultdict(list)
    for finding in db.execute(query).scalars():
        durations[finding.severity].append((finding.updated_at - finding.first_detected_at).total_seconds() / 86400)
    return {"days_by_severity": {k: round(sum(v) / len(v), 2) for k, v in durations.items()}}
