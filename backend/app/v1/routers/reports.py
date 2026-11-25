"""Finding exports, SARIF import and printable security reports."""

from __future__ import annotations

import html
import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db, utcnow
from ..deps import OrgContext, get_project, get_scan, org_context, visible_project_ids, writable_org
from ..models import Finding, FindingReview, Project, ReportRecord, Scan, ScanFinding, User
from ..permissions import P
from ..services.comparison import compare_scans
from ..services.posture import ACTIVE, project_posture
from ..services.reports import (
    LIMITATIONS,
    external_fingerprint,
    findings_csv,
    findings_sarif,
    parse_sarif_results,
    render_html_report,
    validate_sarif,
)
from .projects import read_upload

router = APIRouter(prefix="/organizations/{org_id}", tags=["reports"])
REPORT_KINDS = {"project", "organization", "scan", "vulnerability", "remediation", "risk_acceptance", "posture", "comparison"}
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def _rows(db: Session, findings: list[Finding]) -> list[dict]:
    users = {u.id: u.email for u in db.execute(select(User).where(User.id.in_({f.assignee_id for f in findings if f.assignee_id} or {"-"}))).scalars()}
    names = dict(db.execute(select(Project.id, Project.name).where(Project.id.in_({f.project_id for f in findings} or {"-"}))).all())
    return [{
        "id": f.id, "project": names.get(f.project_id), "project_id": f.project_id, "rule_id": f.rule_id, "title": f.title,
        "severity": f.severity, "confidence": f.confidence, "status": f.status, "verification_status": f.verification_status,
        "cwe": f.cwe, "owasp": f.owasp, "file_path": f.file_path, "line": f.line, "assignee": users.get(f.assignee_id),
        "due_date": f.due_date.isoformat() if f.due_date else None, "first_detected_at": f.first_detected_at.isoformat(),
        "last_detected_at": f.last_detected_at.isoformat(), "labels": f.labels, "fingerprint": f.fingerprint,
    } for f in findings]


def _scoped_findings(db: Session, ctx: OrgContext, project_id: str | None, scan_id: str | None, statuses: list[str] | None):
    query = select(Finding).where(Finding.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(Finding.project_id.in_(allowed or {"-"}))
    if project_id:
        get_project(db, ctx, project_id)
        query = query.where(Finding.project_id == project_id)
    if scan_id:
        scan = get_scan(db, ctx, scan_id)
        query = query.where(Finding.id.in_(select(ScanFinding.finding_id).where(ScanFinding.scan_id == scan.id)))
    if statuses:
        query = query.where(Finding.status.in_(statuses))
    return db.execute(query.order_by(Finding.project_id, Finding.file_path, Finding.line).limit(50_000)).scalars().all()


def _record(db: Session, ctx: OrgContext, kind: str, fmt: str, params: dict, count: int) -> None:
    db.add(ReportRecord(org_id=ctx.org.id, project_id=params.get("project_id"), kind=kind, format=fmt, parameters=params,
                        created_by_id=ctx.user.id))
    audit.record(db, "report.exported", actor=ctx.user, org_id=ctx.org.id, project_id=params.get("project_id"),
                 resource_type="report", metadata={"kind": kind, "format": fmt, "rows": count, **params})
    db.commit()


@router.get("/exports/findings")
def export_findings(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                    format: str = Query(default="csv", pattern="^(csv|json|sarif)$"),
                    project_id: str | None = None, scan_id: str | None = None, status: list[str] | None = Query(default=None)):
    ctx.require(P.REPORTS_EXPORT)
    rows = _rows(db, _scoped_findings(db, ctx, project_id, scan_id, status))
    params = {k: v for k, v in {"project_id": project_id, "scan_id": scan_id, "status": status}.items() if v}
    stamp = utcnow().strftime("%Y%m%d-%H%M")
    if format == "csv":
        body, media, ext = findings_csv(rows), "text/csv; charset=utf-8", "csv"
    elif format == "json":
        body = json.dumps({"generated_at": utcnow().isoformat(), "organization": ctx.org.name, "count": len(rows),
                           "limitations": LIMITATIONS, "findings": rows}, indent=2)
        media, ext = "application/json", "json"
    else:
        meta = {}
        if scan_id:
            scan = get_scan(db, ctx, scan_id)
            project = db.get(Project, scan.project_id)
            meta = {"scan_id": scan.id, "commit_sha": scan.commit_sha, "branch": scan.branch, "repository_url": project.repository_url}
        document = findings_sarif(rows, meta)
        errors = validate_sarif(document)
        if errors:  # pragma: no cover - guarded by tests; never ship an invalid log
            raise HTTPException(status_code=500, detail="Generated SARIF failed schema validation.")
        body, media, ext = json.dumps(document, indent=2), "application/sarif+json", "sarif"
    _record(db, ctx, "findings", format, params, len(rows))
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="securcode-findings-{stamp}.{ext}"'})


@router.post("/projects/{project_id}/sarif-import", status_code=201)
async def import_sarif(project_id: str, file: UploadFile = File(...), ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    """Import results from another SARIF-producing tool as a scan of this project."""
    ctx.require(P.SCANS_RUN)
    project = get_project(db, ctx, project_id)
    data = await read_upload(file, 20_000_000)
    try:
        document = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="The file is not valid JSON.") from None
    if not isinstance(document, dict):
        raise HTTPException(status_code=422, detail="The SARIF document must be a JSON object.")
    errors = validate_sarif(document)
    if errors:
        return JSONResponse({"detail": "SARIF schema validation failed.", "errors": errors}, status_code=422)
    raw = parse_sarif_results(document)
    from ..services.scanning import _event  # reuse lifecycle event helper

    now = utcnow()
    scan = Scan(org_id=ctx.org.id, project_id=project.id, status="completed_with_warnings", trigger="import", source_type="sarif",
                scope_key="sarif", requested_by_id=ctx.user.id, scanner_version="external", ruleset_version="external",
                started_at=now, finished_at=now, duration_ms=0, progress=100, progress_message="Imported",
                warnings=[{"path": ".", "message": "Imported SARIF results are not used to auto-resolve findings."}])
    db.add(scan)
    db.flush()
    existing = {f.fingerprint: f for f in db.execute(select(Finding).where(Finding.project_id == project.id, Finding.scope_key == "sarif")).scalars()}
    created = 0
    for item in raw:
        fingerprint = external_fingerprint(item)
        finding = existing.get(fingerprint)
        if finding is None:
            finding = Finding(org_id=ctx.org.id, project_id=project.id, scope_key="sarif", fingerprint=fingerprint, rule_id=item["rule_id"],
                              title=item["title"], description=item["description"], severity=item["severity"], original_severity=item["severity"],
                              confidence=item["confidence"], file_path=item["file_path"], line=item["line"], snippet=item["snippet"] or None,
                              status="open", first_scan_id=scan.id, last_scan_id=scan.id, language=item["tool"])
            db.add(finding)
            db.flush()
            existing[fingerprint] = finding
            _event(db, finding, "system", f"Imported from SARIF ({item['tool']}).")
            created += 1
        else:
            finding.last_detected_at = now
            finding.last_scan_id = scan.id
        if not db.execute(select(ScanFinding.id).where(ScanFinding.scan_id == scan.id, ScanFinding.finding_id == finding.id)).first():
            db.add(ScanFinding(org_id=ctx.org.id, scan_id=scan.id, finding_id=finding.id, fingerprint=fingerprint, rule_id=finding.rule_id,
                               severity=finding.severity, confidence=finding.confidence, file_path=finding.file_path, line=finding.line))
    scan.files_scanned = len({item["file_path"] for item in raw})
    scan.summary = {"total": len(raw), "new": created, "resolved": 0, "reopened": 0, "by_severity": {}, "imported": True}
    audit.record(db, "scan.sarif_imported", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="scan",
                 resource_id=scan.id, metadata={"results": len(raw), "new": created})
    db.commit()
    return {"scan_id": scan.id, "results": len(raw), "new_findings": created}


@router.get("/reports/{kind}")
def security_report(kind: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db),
                    format: str = Query(default="html", pattern="^(html|json)$"), project_id: str | None = None,
                    scan_id: str | None = None, base_scan_id: str | None = None):
    ctx.require(P.REPORTS_VIEW)
    if kind not in REPORT_KINDS:
        raise HTTPException(status_code=404, detail="Unknown report type.")
    if kind == "project" and not project_id:
        raise HTTPException(status_code=422, detail="project_id is required for a project report.")
    if kind in {"scan", "comparison"} and not scan_id:
        raise HTTPException(status_code=422, detail="scan_id is required.")
    scope: dict = {"Organization": ctx.org.name, "Report type": kind.replace("_", " ").title()}
    sections: list[tuple[str, str]] = []
    statuses = None
    if kind in {"remediation", "vulnerability", "organization", "project", "posture"}:
        statuses = list(ACTIVE) + ["resolved"] if kind == "remediation" else list(ACTIVE)
    if kind == "risk_acceptance":
        statuses = ["accepted_risk", "false_positive"]
    findings = _scoped_findings(db, ctx, project_id, scan_id if kind == "scan" else None, statuses)
    rows = _rows(db, findings)
    summary = {"Findings in report": len(rows)}
    if project_id:
        project = get_project(db, ctx, project_id)
        posture = project_posture(db, project)
        scope.update({"Project": project.name, "Repository": project.repository_full_name or project.source_type,
                      "Default branch": project.default_branch})
        summary["Posture score"] = posture["score"] if posture["score"] is not None else "not assessed"
    latest = None
    if scan_id:
        latest = get_scan(db, ctx, scan_id)
    elif project_id:
        latest = db.execute(select(Scan).where(Scan.project_id == project_id, Scan.status.in_(["completed", "completed_with_warnings"]))
                            .order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    if latest:
        scope.update({"Scan": latest.id, "Scan status": latest.status, "Scan timestamp": (latest.finished_at or latest.created_at).isoformat(),
                      "Scanner version": latest.scanner_version, "Rule-set version": latest.ruleset_version,
                      "Commit": latest.commit_sha or "—", "Files scanned": latest.files_scanned})
    if kind == "remediation":
        resolved = sum(1 for r in rows if r["status"] == "resolved")
        summary.update({"Verified fixed": resolved, "Still active": len(rows) - resolved,
                        "Assigned": sum(1 for r in rows if r["assignee"]), "Overdue": sum(1 for f in findings if f.due_date and f.due_date < utcnow() and f.status in ACTIVE)})
    if kind == "risk_acceptance":
        reviews = db.execute(select(FindingReview).where(FindingReview.org_id == ctx.org.id, FindingReview.status.in_(["approved", "expired"]))).scalars().all()
        allowed_ids = {f.id for f in findings}
        body = "".join(
            f"<tr><td>{r.kind.replace('_', ' ')}</td><td>{r.status}</td><td>{(r.expires_at.date().isoformat() if r.expires_at else '—')}</td>"
            f"<td>{html.escape(r.justification[:300])}</td></tr>" for r in reviews if r.finding_id in allowed_ids
        )
        sections.append(("Decisions", f"<table><tr><th>Type</th><th>Status</th><th>Expires</th><th>Justification</th></tr>{body}</table>"))
    if kind == "comparison":
        head = get_scan(db, ctx, scan_id)
        base = get_scan(db, ctx, base_scan_id) if base_scan_id else db.execute(
            select(Scan).where(Scan.project_id == head.project_id, Scan.created_at < head.created_at,
                               Scan.status.in_(["completed", "completed_with_warnings"])).order_by(Scan.created_at.desc()).limit(1)
        ).scalar_one_or_none()
        if base is None:
            raise HTTPException(status_code=409, detail="No earlier completed scan to compare against.")
        comparison = compare_scans(db, base, head)
        summary.update({k.replace("_", " ").title(): v for k, v in comparison["summary"].items()})
        warn = "".join(f"<li>{w}</li>" for w in comparison["warnings"]) or "<li>Scans are equivalent in scope, scanner and rules.</li>"
        sections.append(("Comparison validity", f"<ul>{warn}</ul>"))
        scope["Compared with"] = base.id
        rows = [{**item, "status": "new", "id": item["finding_id"], "cwe": None, "assignee": None} for item in comparison["new"]] + \
               [{**item, "status": "resolved", "id": item["finding_id"], "cwe": None, "assignee": None} for item in comparison["resolved"]]
    if kind == "organization":
        summary["Projects"] = db.execute(select(func.count()).select_from(Project).where(Project.org_id == ctx.org.id)).scalar_one()
    params = {k: v for k, v in {"project_id": project_id, "scan_id": scan_id, "base_scan_id": base_scan_id}.items() if v}
    _record(db, ctx, kind, format, params, len(rows))
    title = f"SecurCode {kind.replace('_', ' ')} report — {ctx.org.name}"
    if format == "json":
        return {"title": title, "scope": scope, "summary": summary, "findings": rows, "limitations": LIMITATIONS,
                "generated_at": utcnow().isoformat()}
    return HTMLResponse(render_html_report(title, scope, summary, rows, sections), headers={"Content-Security-Policy": HTML_CSP})
