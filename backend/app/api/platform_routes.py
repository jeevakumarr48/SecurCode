"""Project, vulnerability, audit, incident, and report API."""

import csv
from datetime import datetime, timezone
import io
import json
import sqlite3
import os
from typing import Literal
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator

from app.auth import add_project_member, current_user, project_access_allowed
from database import get_connection, record_audit_event, get_scan_statistics, finding_fingerprint, save_scan, verify_audit_chain, create_notification, redact_audit_metadata
from security_engine.scanner.remediation import remediation_for
from security_engine.integrations import IntegrationError, integration_status, parse_sarif, run_optional_scanner
from security_engine.trivy_scan import TrivyError, run_trivy
from app.api.routes import DEMO_MODE, WORKSPACE_ROOT, workspace_relative_path, public_statistics, _public_scan_result


router = APIRouter()
FINDING_STATUSES = {"Open", "In Progress", "Resolved", "Accepted Risk", "False Positive"}
INCIDENT_STATUSES = {"Open", "Investigating", "Contained", "Resolved", "Closed"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _operator_write_allowed():
    if DEMO_MODE:
        raise HTTPException(status_code=403, detail="Changes are disabled in the public demo.")


def _finding_for(connection, scan_id, finding_index):
    row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if DEMO_MODE:
        demo_prefix = "backend/app/api/docs/security-demo"
        project_path = row["project_path"].replace("\\", "/")
        if project_path != demo_prefix and not project_path.startswith(demo_prefix + "/"):
            raise HTTPException(status_code=404, detail="Finding not found.")
    findings = json.loads(row["findings_json"])
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found.")
    scan = dict(row)
    finding = dict(findings[finding_index])
    state = connection.execute(
        "SELECT status, assignee, fingerprint, updated_at FROM finding_states WHERE scan_id = ? AND finding_index = ?",
        (scan_id, finding_index),
    ).fetchone()
    finding.update({
        "scan_id": scan_id,
        "finding_index": finding_index,
        "project_path": workspace_relative_path(scan["project_path"]),
        "scan_status": scan["status"],
        "scan_created_at": scan["created_at"],
        "status": state["status"] if state else "Open",
        "assignee": state["assignee"] if state else None,
        "status_updated_at": state["updated_at"] if state else None,
        "finding_id": state["fingerprint"] if state and state["fingerprint"] else finding_fingerprint(scan["project_path"], finding),
    })
    finding.setdefault("remediation", remediation_for(finding.get("test_id")))
    return finding


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    project_path: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=1000)
    owner: str | None = Field(default=None, max_length=120)
    repository_url: str | None = Field(default=None, max_length=500)
    default_branch: str = Field(default="main", min_length=1, max_length=120)

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value):
        if value is None or not value.strip():
            return None
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Repository URL must be an HTTPS URL without credentials, query, or fragment.")
        return value.strip()


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    owner: str | None = Field(default=None, max_length=120)
    repository_url: str | None = Field(default=None, max_length=500)
    default_branch: str | None = Field(default=None, min_length=1, max_length=120)


class ProjectMemberCreate(BaseModel):
    user_id: int = Field(gt=0)


class FindingStatusUpdate(BaseModel):
    status: Literal["Open", "In Progress", "Resolved", "Accepted Risk", "False Positive"]
    note: str = Field(default="", max_length=1000)


class FindingAssigneeUpdate(BaseModel):
    assignee: str | None = Field(default=None, max_length=120)


class FindingCommentCreate(BaseModel):
    comment: str = Field(min_length=1, max_length=4000)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    priority: Literal["Critical", "High", "Medium", "Low"] | None = None
    status: Literal["Open", "Investigating", "Contained", "Resolved", "Closed"] = "Open"
    owner: str | None = Field(default=None, max_length=120)
    resolution_notes: str = Field(default="", max_length=3000)
    finding_refs: list[tuple[int, int]] = Field(default_factory=list, max_length=100)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    priority: Literal["Critical", "High", "Medium", "Low"] | None = None
    status: Literal["Open", "Investigating", "Contained", "Resolved", "Closed"] | None = None
    owner: str | None = Field(default=None, max_length=120)
    resolution_notes: str | None = Field(default=None, max_length=3000)


class SARIFImportRequest(BaseModel):
    project_id: int = Field(gt=0)
    sarif: dict
    branch: str | None = Field(default=None, max_length=255)
    commit_sha: str | None = Field(default=None, min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    pull_request_number: int | None = Field(default=None, gt=0)
    source_url: str | None = Field(default=None, max_length=1000)

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value):
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Source URL must be an HTTPS URL without credentials, query, or fragment.")
        return value


class ExternalScanRequest(BaseModel):
    project_id: int = Field(gt=0)
    timeout_seconds: int = Field(default=300, ge=1, le=1800)


@router.get("/dashboard")
def dashboard():
    stats = get_scan_statistics("backend/app/api/docs/security-demo", include_incidents=False) if DEMO_MODE else get_scan_statistics()
    stats = public_statistics(stats)
    open_counts = stats["open_finding_severity_counts"]
    risk_weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    weighted_open_findings = sum(open_counts[level] * weight for level, weight in risk_weights.items())
    stats["risk_score"] = max(0, 100 - min(100, weighted_open_findings))
    stats["risk_score_method"] = "100 minus the weighted count of open findings (critical 25, high 10, medium 4, low 1), floored at 0. This is a triage index, not breach likelihood."
    return stats


@router.get("/integrations/status")
def integrations_status():
    return {"integrations": integration_status()}


def _project_scan_target(project_id):
    with get_connection() as connection:
        project = connection.execute("SELECT id, project_path FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    if not project_access_allowed(project_id):
        raise HTTPException(status_code=404, detail="Project not found.")
    relative = Path(project["project_path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise HTTPException(status_code=400, detail="Registered project path is invalid.")
    cursor = WORKSPACE_ROOT
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise HTTPException(status_code=400, detail="Project path contains a symbolic link.")
    try:
        target = (WORKSPACE_ROOT / relative).resolve(strict=True)
        target.relative_to(WORKSPACE_ROOT.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(status_code=400, detail="Project path could not be resolved safely.") from None
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Project path must be an existing directory.")
    return project, target


def _persist_external_scan(project, findings, scanner, git_metadata=None):
    result = {"status": "completed", "total_findings": len(findings), "findings": findings, "errors": []}
    relative_path = workspace_relative_path(project["project_path"])
    public = _public_scan_result(result, relative_path)
    git_metadata = git_metadata or {}
    scan_id = save_scan(relative_path, public, git_metadata=git_metadata)
    with get_connection() as connection:
        record_audit_event(connection, "system", "integration.scan_imported", "scan", scan_id,
                           {"scanner": scanner, "project_id": project["id"], "finding_count": len(findings), **git_metadata})
    return {**public, "scan_id": scan_id, "scanner": scanner, **git_metadata}


@router.post("/integrations/{tool}/scan")
def run_external_scan(tool: str, request: ExternalScanRequest):
    _operator_write_allowed()
    project, target = _project_scan_target(request.project_id)
    from app.api import routes as scan_api
    if not scan_api.scan_semaphore.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Another scan is already running; retry when it completes.")
    try:
        if tool == "trivy":
            findings = run_trivy(target, timeout=request.timeout_seconds)
        else:
            config = os.getenv("SECURCODE_SEMGREP_CONFIG") if tool == "semgrep" else None
            findings = run_optional_scanner(tool, target, timeout=request.timeout_seconds, semgrep_config=config)
    except (IntegrationError, TrivyError) as error:
        with get_connection() as connection:
            record_audit_event(connection, "system", "integration.scan_failed", "project", project["id"],
                               {"scanner": tool, "reason": str(error)[:500]}, outcome="failure")
        raise HTTPException(status_code=503, detail=str(error)) from None
    finally:
        scan_api.scan_semaphore.release()
    return _persist_external_scan(project, findings, tool.title())


@router.post("/integrations/sarif/import")
def import_sarif(request: SARIFImportRequest):
    _operator_write_allowed()
    try:
        encoded = json.dumps(request.sarif, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="SARIF payload must be valid JSON data.") from None
    if len(encoded) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="SARIF payload exceeds the 25 MB import limit.")
    project, _target = _project_scan_target(request.project_id)
    try:
        findings = parse_sarif(request.sarif)
    except IntegrationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None
    git_metadata = {
        "branch": request.branch,
        "commit_sha": request.commit_sha.lower() if request.commit_sha else None,
        "pull_request_number": request.pull_request_number,
        "source_url": request.source_url,
    }
    result = _persist_external_scan(project, findings, "SARIF", git_metadata)
    return result


@router.get("/projects")
def list_projects(limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    scope = " WHERE (p.project_path = ? OR p.project_path LIKE ?)" if DEMO_MODE else ""
    scope_params = ("backend/app/api/docs/security-demo", "backend/app/api/docs/security-demo/%") if DEMO_MODE else ()
    user = current_user()
    if user and user["role"] != "administrator":
        scope += (" AND " if scope else " WHERE ") + "p.id IN (SELECT project_id FROM project_members WHERE user_id = ?)"
        scope_params = (*scope_params, user["id"])
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM projects p" + scope, scope_params).fetchone()["count"]
        projects = [dict(row) for row in connection.execute("""
            SELECT p.*, COUNT(DISTINCT s.id) AS scan_count,
                   COALESCE(SUM(s.total_findings), 0) AS finding_count,
                   MAX(s.created_at) AS last_scan_at
            FROM projects p LEFT JOIN scans s ON s.project_id = p.id
        """ + scope + " GROUP BY p.id ORDER BY p.updated_at DESC, p.id DESC LIMIT ? OFFSET ?", (*scope_params, limit, offset))]
    for project in projects:
        project["project_path"] = workspace_relative_path(project["project_path"])
    return {"total": total, "projects": projects, "limit": limit, "offset": offset}


@router.get("/projects/{project_id}")
def get_project(project_id: int):
    scope = " AND (p.project_path = ? OR p.project_path LIKE ?)" if DEMO_MODE else ""
    parameters = (project_id, "backend/app/api/docs/security-demo", "backend/app/api/docs/security-demo/%") if DEMO_MODE else (project_id,)
    with get_connection() as connection:
        row = connection.execute("""
            SELECT p.*, COUNT(DISTINCT s.id) AS scan_count,
                   COALESCE(SUM(s.total_findings), 0) AS finding_count,
                   MAX(s.created_at) AS last_scan_at
            FROM projects p LEFT JOIN scans s ON s.project_id = p.id
            WHERE p.id = ?
        """ + scope + " GROUP BY p.id", parameters).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Project not found.")
        project = dict(row)
        project["recent_scans"] = [dict(scan) for scan in connection.execute(
            "SELECT id, status, total_findings, created_at FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 10",
            (project_id,),
        )]
    project["project_path"] = workspace_relative_path(project["project_path"])
    return project


@router.post("/projects/{project_id}/scan")
def scan_project_by_id(project_id: int):
    _operator_write_allowed()
    with get_connection() as connection:
        row = connection.execute("SELECT project_path FROM projects WHERE id = ?", (project_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    from app.api import routes as scan_api
    return scan_api.scan(scan_api.ScanRequest(project_path=Path(row["project_path"]).as_posix()))


@router.get("/projects/{project_id}/findings")
def project_findings(project_id: int, status: str | None = None, limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    get_project(project_id)
    return list_findings(status=status, search="", limit=limit, offset=offset, project_id=project_id)


@router.get("/scans/{scan_id}/comparison")
def compare_scan(scan_id: int, against_scan_id: int | None = None):
    with get_connection() as connection:
        current = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if current is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if DEMO_MODE:
            demo_path = "backend/app/api/docs/security-demo"
            current_path = current["project_path"].replace("\\", "/")
            if current_path != demo_path and not current_path.startswith(demo_path + "/"):
                raise HTTPException(status_code=404, detail="Scan not found.")
        if against_scan_id is not None:
            previous = connection.execute("SELECT * FROM scans WHERE id = ? AND project_id = ?", (against_scan_id, current["project_id"])).fetchone()
        else:
            previous = connection.execute("SELECT * FROM scans WHERE project_id = ? AND id < ? ORDER BY id DESC LIMIT 1", (current["project_id"], scan_id)).fetchone()
        current_findings = json.loads(current["findings_json"])
        previous_findings = json.loads(previous["findings_json"]) if previous else []

    def identity(finding):
        return (finding.get("language"), finding.get("test_id"), finding.get("filename"), finding.get("line_number"))

    previous_keys = {identity(item) for item in previous_findings}
    current_keys = {identity(item) for item in current_findings}
    added = [item for item in current_findings if identity(item) not in previous_keys]
    no_longer_detected = [item for item in previous_findings if identity(item) not in current_keys]
    return {
        "scan_id": scan_id,
        "compared_to_scan_id": previous["id"] if previous else None,
        "comparison_note": "A finding is considered the same when its rule, language, file path, and line number match. No longer detected does not mean remediation was verified.",
        "added": added,
        "no_longer_detected": no_longer_detected,
        "unchanged_count": len(current_keys & previous_keys),
    }


@router.post("/projects", status_code=201)
def create_project(request: ProjectCreate):
    _operator_write_allowed()
    if not request.name.strip():
        raise HTTPException(status_code=400, detail="Project name cannot be blank.")
    raw_path = request.project_path.replace("\\", "/")
    if raw_path.startswith("/") or ".." in raw_path.split("/"):
        raise HTTPException(status_code=400, detail="Project path must be relative to the workspace.")
    candidate = WORKSPACE_ROOT / raw_path
    cursor = WORKSPACE_ROOT
    for component in Path(raw_path).parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise HTTPException(status_code=400, detail="Project paths cannot include symbolic links.")
    try:
        target = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(status_code=400, detail="Project path could not be resolved safely.") from None
    try:
        target.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise HTTPException(status_code=400, detail="Project path must stay inside the workspace.") from None
    if not target.is_dir() or target.is_symlink():
        raise HTTPException(status_code=400, detail="Project path must be an existing workspace directory.")
    project_path = target.relative_to(WORKSPACE_ROOT).as_posix()
    try:
        with get_connection() as connection:
            cursor = connection.execute("INSERT INTO projects(name, project_path, description, owner, repository_url, default_branch) VALUES (?, ?, ?, ?, ?, ?)", (request.name.strip(), project_path, request.description.strip(), request.owner.strip() if request.owner else None, request.repository_url, request.default_branch.strip()))
            project_id = cursor.lastrowid
            actor = current_user()
            if actor:
                add_project_member(connection, project_id, actor["id"])
            record_audit_event(connection, actor["username"] if actor else "local-operator", "project.created", "project", project_id, {"name": request.name.strip(), "project_path": project_path, "owner": request.owner, "repository_url": request.repository_url, "default_branch": request.default_branch.strip()})
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A project is already registered for this path.") from None
    return {"id": project_id, "name": request.name.strip(), "project_path": project_path, "description": request.description.strip(), "owner": request.owner, "repository_url": request.repository_url, "default_branch": request.default_branch.strip()}


@router.post("/projects/{project_id}/members", status_code=201)
def add_project_membership(project_id: int, request: ProjectMemberCreate):
    user = current_user()
    if user and user["role"] != "administrator":
        raise HTTPException(status_code=403, detail="Only administrators can grant project access.")
    with get_connection() as connection:
        if not connection.execute(
            "SELECT 1 FROM projects WHERE id = ?", (project_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Project not found.")
        member = connection.execute(
            "SELECT id, username FROM auth_users WHERE id = ? AND disabled = 0",
            (request.user_id,),
        ).fetchone()
        if not member:
            raise HTTPException(status_code=404, detail="Active user not found.")
        add_project_member(connection, project_id, request.user_id)
        record_audit_event(
            connection,
            user["username"] if user else "local-operator",
            "project.member_added",
            "project",
            project_id,
            {"user_id": request.user_id},
        )
    return {"project_id": project_id, "user_id": request.user_id, "username": member["username"]}


@router.patch("/projects/{project_id}")
def update_project(project_id: int, request: ProjectUpdate):
    _operator_write_allowed()
    updates = {key: value for key, value in request.model_dump(exclude_unset=True).items() if value is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Provide at least one project field to update.")
    updates = {key: value.strip() if isinstance(value, str) else value for key, value in updates.items()}
    assignments = ", ".join(f"{key} = ?" for key in updates)
    with get_connection() as connection:
        cursor = connection.execute(f"UPDATE projects SET {assignments}, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?", (*updates.values(), project_id))
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Project not found.")
        record_audit_event(connection, "local-operator", "project.updated", "project", project_id, {"changed_fields": list(updates)})
        row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    project = dict(row)
    project["project_path"] = workspace_relative_path(project["project_path"])
    return project


@router.get("/findings")
def list_findings(
    status: str | None = None,
    severity: str | None = None,
    language: str | None = None,
    search: str = Query(default="", max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    project_id: int | None = None,
):
    if status and status not in FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid finding status.")
    if severity and severity.upper() not in SEVERITIES:
        raise HTTPException(status_code=400, detail="Invalid finding severity.")
    conditions, parameters = [], []
    if status:
        conditions.append("fs.status = ?"); parameters.append(status)
    if project_id is not None:
        conditions.append("s.project_id = ?"); parameters.append(project_id)
    if severity:
        conditions.append("upper(json_extract(f.value, '$.severity')) = ?"); parameters.append(severity.upper())
    if language:
        conditions.append("lower(json_extract(f.value, '$.language')) = lower(?)"); parameters.append(language)
    if DEMO_MODE:
        conditions.append("(s.project_path = ? OR s.project_path LIKE ?)")
        parameters.extend(["backend/app/api/docs/security-demo", "backend/app/api/docs/security-demo/%"])
    if search:
        conditions.append("(lower(json_extract(f.value, '$.description')) LIKE ? OR lower(json_extract(f.value, '$.filename')) LIKE ? OR lower(json_extract(f.value, '$.test_id')) LIKE ?)")
        parameters.extend([f"%{search.lower()}%"] * 3)
    conditions.append("NOT EXISTS (SELECT 1 FROM finding_states newer WHERE newer.fingerprint = fs.fingerprint AND (newer.scan_id > s.id OR (newer.scan_id = s.id AND newer.finding_index > CAST(f.key AS INTEGER))))")
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    query = """
        FROM scans s, json_each(s.findings_json) f
        JOIN finding_states fs ON fs.scan_id = s.id AND fs.finding_index = CAST(f.key AS INTEGER)
    """ + where
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) " + query, parameters).fetchone()[0]
        rows = connection.execute("SELECT s.id AS scan_id, CAST(f.key AS INTEGER) AS finding_index " + query + " ORDER BY s.id DESC, finding_index LIMIT ? OFFSET ?", (*parameters, limit, offset)).fetchall()
        items = [_finding_for(connection, row["scan_id"], row["finding_index"]) for row in rows]
    return {"total": total, "findings": items, "limit": limit, "offset": offset}


@router.get("/findings/{scan_id}/{finding_index}")
def finding_detail(scan_id: int, finding_index: int):
    with get_connection() as connection:
        item = _finding_for(connection, scan_id, finding_index)
        history = [dict(row) for row in connection.execute("""
            SELECT h.from_status, h.to_status, h.actor, h.note, h.created_at
            FROM finding_status_history h
            JOIN finding_states fs
              ON fs.scan_id = h.scan_id AND fs.finding_index = h.finding_index
            WHERE fs.fingerprint = ?
            ORDER BY h.id
        """, (item["finding_id"],))]
        item["status_history"] = history
        item["comments"] = [dict(row) for row in connection.execute("""
            SELECT actor, comment, created_at FROM finding_comments
            WHERE fingerprint = ? ORDER BY id
        """, (item["finding_id"],))]
        item["incidents"] = [dict(row) for row in connection.execute("""
            SELECT i.id, i.title, i.status, i.priority FROM incidents i
            JOIN incident_findings r ON r.incident_id = i.id
            WHERE r.scan_id = ? AND r.finding_index = ? ORDER BY i.id DESC
        """, (scan_id, finding_index))]
    return item


@router.patch("/findings/{scan_id}/{finding_index}/status")
def update_finding_status(scan_id: int, finding_index: int, request: FindingStatusUpdate):
    _operator_write_allowed()
    note = request.note.strip()
    if request.status in {"Accepted Risk", "False Positive"} and not note:
        raise HTTPException(status_code=400, detail="A justification is required for accepted-risk and false-positive decisions.")
    with get_connection() as connection:
        finding = _finding_for(connection, scan_id, finding_index)
        old_status = finding["status"]
        connection.execute("INSERT OR IGNORE INTO finding_states(scan_id, finding_index) VALUES (?, ?)", (scan_id, finding_index))
        connection.execute("UPDATE finding_states SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE scan_id = ? AND finding_index = ?", (request.status, scan_id, finding_index))
        if old_status != request.status:
            connection.execute("INSERT INTO finding_status_history(scan_id, finding_index, from_status, to_status, actor, note) VALUES (?, ?, ?, ?, ?, ?)", (scan_id, finding_index, old_status, request.status, "local-operator", note))
            action = "finding.suppressed" if request.status in {"Accepted Risk", "False Positive"} else "finding.status_changed"
            metadata = {"from": old_status, "to": request.status}
            if action == "finding.suppressed":
                metadata["justification"] = note[:500]
            record_audit_event(connection, "local-operator", action, "finding", f"{scan_id}:{finding_index}", metadata)
    return finding_detail(scan_id, finding_index)


@router.patch("/findings/{scan_id}/{finding_index}/assignee")
def update_finding_assignee(scan_id: int, finding_index: int, request: FindingAssigneeUpdate):
    _operator_write_allowed()
    assignee = request.assignee.strip() if request.assignee and request.assignee.strip() else None
    with get_connection() as connection:
        finding = _finding_for(connection, scan_id, finding_index)
        if assignee:
            user = connection.execute(
                "SELECT username FROM auth_users WHERE username = ? COLLATE NOCASE AND disabled = 0",
                (assignee,),
            ).fetchone()
            if user is None:
                raise HTTPException(
                    status_code=422,
                    detail="Assignee must be an active SecurCode username.",
                )
            assignee = user["username"]
        old_assignee = finding.get("assignee")
        connection.execute("INSERT OR IGNORE INTO finding_states(scan_id, finding_index) VALUES (?, ?)", (scan_id, finding_index))
        connection.execute("UPDATE finding_states SET assignee = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE scan_id = ? AND finding_index = ?", (assignee, scan_id, finding_index))
        if old_assignee != assignee:
            actor = current_user()
            record_audit_event(connection, actor["username"] if actor else "local-operator", "finding.assigned", "finding", f"{scan_id}:{finding_index}", {"from": old_assignee, "to": assignee})
            if assignee:
                create_notification(connection, "assignment", f"assignment:{finding['finding_id']}:{scan_id}:{assignee}",
                                    "Finding assigned", f"{finding['test_id']} was assigned to {assignee}.", "/Vulnerabilities")
    return finding_detail(scan_id, finding_index)


@router.post("/findings/{scan_id}/{finding_index}/comments", status_code=201)
def add_finding_comment(scan_id: int, finding_index: int, request: FindingCommentCreate):
    _operator_write_allowed()
    comment = request.comment.strip()
    if not comment:
        raise HTTPException(status_code=400, detail="Comment cannot be blank.")
    with get_connection() as connection:
        finding = _finding_for(connection, scan_id, finding_index)
        connection.execute("INSERT INTO finding_comments(scan_id, finding_index, fingerprint, actor, comment) VALUES (?, ?, ?, ?, ?)", (scan_id, finding_index, finding["finding_id"], "local-operator", comment))
        record_audit_event(connection, "local-operator", "finding.commented", "finding", f"{scan_id}:{finding_index}", {"comment_length": len(comment)})
    return finding_detail(scan_id, finding_index)


@router.get("/audit")
def list_audit_events(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0), action: str | None = Query(default=None, max_length=100)):
    conditions, parameters = [], []
    if action:
        conditions.append("action = ?"); parameters.append(action)
    if DEMO_MODE:
        conditions.append("action LIKE 'scan.%' AND json_extract(metadata_json, '$.project_path') LIKE ?")
        parameters.append("backend/app/api/docs/security-demo%")
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM audit_events" + where, parameters).fetchone()[0]
        rows = connection.execute("SELECT * FROM audit_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?", (*parameters, limit, offset)).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["metadata"] = redact_audit_metadata(json.loads(event.pop("metadata_json")))
        events.append(event)
    return {"total": total, "events": events, "limit": limit, "offset": offset}


@router.get("/audit/integrity")
def audit_integrity():
    return verify_audit_chain()


@router.get("/notifications")
def list_notifications(unread_only: bool = False, limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    scope = "n.recipient = ?"
    parameters = ["local-operator"]
    if DEMO_MODE:
        scope += """
            AND n.category IN ('scan', 'critical_finding')
            AND EXISTS (
                SELECT 1 FROM scans s
                WHERE (
                    (n.category = 'scan' AND n.event_key = 'scan:' || s.id)
                    OR (n.category = 'critical_finding' AND n.event_key = 'critical:' || s.id)
                )
                AND (s.project_path = ? OR s.project_path LIKE ?)
            )
        """
        parameters.extend([
            "backend/app/api/docs/security-demo",
            "backend/app/api/docs/security-demo/%",
        ])
    condition = " AND n.read_at IS NULL" if unread_only else ""
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM notifications n WHERE " + scope + condition,
            parameters,
        ).fetchone()[0]
        items = [dict(row) for row in connection.execute(
            "SELECT n.* FROM notifications n WHERE " + scope + condition + " ORDER BY n.id DESC LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )]
        unread_count = connection.execute(
            "SELECT COUNT(*) FROM notifications n WHERE " + scope + " AND n.read_at IS NULL",
            parameters,
        ).fetchone()[0]
    return {"total": total, "unread_count": unread_count, "notifications": items, "limit": limit, "offset": offset}


@router.patch("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int):
    _operator_write_allowed()
    with get_connection() as connection:
        cursor = connection.execute("UPDATE notifications SET read_at = COALESCE(read_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = ? AND recipient = ?", (notification_id, "local-operator"))
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Notification not found.")
    return {"notification_id": notification_id, "read": True}


def _incident_dict(connection, incident_id):
    row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    incident = dict(row)
    refs = connection.execute("SELECT scan_id, finding_index FROM incident_findings WHERE incident_id = ? ORDER BY scan_id, finding_index", (incident_id,)).fetchall()
    incident["findings"] = [_finding_for(connection, ref["scan_id"], ref["finding_index"]) for ref in refs]
    incident["activity"] = []
    for activity in connection.execute("SELECT * FROM incident_activity WHERE incident_id = ? ORDER BY id", (incident_id,)):
        entry = dict(activity); entry["details"] = json.loads(entry.pop("details_json")); incident["activity"].append(entry)
    return incident


@router.get("/incidents")
def list_incidents(status: str | None = None, search: str = Query(default="", max_length=200), limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    if DEMO_MODE:
        return {"total": 0, "incidents": [], "limit": limit, "offset": offset}
    if status and status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid incident status.")
    conditions, parameters = [], []
    if status:
        conditions.append("status = ?"); parameters.append(status)
    if search:
        conditions.append("(lower(title) LIKE ? OR lower(description) LIKE ?)"); parameters.extend([f"%{search.lower()}%"] * 2)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM incidents" + where, parameters).fetchone()[0]
        rows = connection.execute("SELECT i.*, (SELECT COUNT(*) FROM incident_findings r WHERE r.incident_id=i.id) AS finding_count FROM incidents i" + where.replace("status", "i.status").replace("title", "i.title").replace("description", "i.description") + " ORDER BY i.updated_at DESC, i.id DESC LIMIT ? OFFSET ?", (*parameters, limit, offset)).fetchall()
    return {"total": total, "incidents": [dict(row) for row in rows], "limit": limit, "offset": offset}


@router.post("/incidents", status_code=201)
def create_incident(request: IncidentCreate):
    _operator_write_allowed()
    with get_connection() as connection:
        resolved_findings = [_finding_for(connection, scan_id, index) for scan_id, index in request.finding_refs]
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        derived = max((str(item.get("severity", "MEDIUM")).upper() for item in resolved_findings), key=lambda value: severity_rank.get(value, 2), default="MEDIUM")
        severity = derived.title() if derived in SEVERITIES else "Medium"
        priority = request.priority or severity
        cursor = connection.execute("INSERT INTO incidents(title, description, priority, severity, status, owner, resolution_notes) VALUES (?, ?, ?, ?, ?, ?, ?)", (request.title.strip(), request.description.strip(), priority, severity, request.status, request.owner.strip() if request.owner else None, request.resolution_notes.strip()))
        incident_id = cursor.lastrowid
        for scan_id, index in sorted(set(request.finding_refs)):
            connection.execute("INSERT INTO incident_findings(incident_id, scan_id, finding_index) VALUES (?, ?, ?)", (incident_id, scan_id, index))
        connection.execute("INSERT INTO incident_activity(incident_id, actor, action, details_json) VALUES (?, ?, ?, ?)", (incident_id, "local-operator", "created", json.dumps({"status": request.status, "finding_count": len(set(request.finding_refs))})))
        record_audit_event(connection, "local-operator", "incident.created", "incident", incident_id, {"status": request.status, "finding_count": len(set(request.finding_refs))})
        create_notification(connection, "incident", f"incident:{incident_id}:created", "Incident created", request.title.strip(), "/Incidents")
        return _incident_dict(connection, incident_id)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    if DEMO_MODE:
        raise HTTPException(status_code=404, detail="Incident not found.")
    with get_connection() as connection:
        return _incident_dict(connection, incident_id)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, request: IncidentUpdate):
    _operator_write_allowed()
    updates = {key: value.strip() if isinstance(value, str) else value for key, value in request.model_dump(exclude_unset=True).items() if value is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Provide at least one incident field to update.")
    with get_connection() as connection:
        current = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if current is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        changes = {key: {"from": current[key], "to": value} for key, value in updates.items() if current[key] != value}
        if changes:
            assignments = ", ".join(f"{key} = ?" for key in updates)
            connection.execute(f"UPDATE incidents SET {assignments}, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?", (*updates.values(), incident_id))
            safe_change = {"changed_fields": list(changes)}
            if "status" in changes:
                safe_change["status"] = changes["status"]
            connection.execute("INSERT INTO incident_activity(incident_id, actor, action, details_json) VALUES (?, ?, ?, ?)", (incident_id, "local-operator", "updated", json.dumps(safe_change)))
            record_audit_event(connection, "local-operator", "incident.updated", "incident", incident_id, safe_change)
        return _incident_dict(connection, incident_id)


@router.get("/reports/summary")
def summary_report():
    stats = get_scan_statistics("backend/app/api/docs/security-demo", include_incidents=False) if DEMO_MODE else get_scan_statistics()
    stats = public_statistics(stats)
    stats["generated_at"] = datetime.now(timezone.utc).isoformat()
    return stats


@router.get("/reports/findings.csv")
def findings_csv():
    data = list_findings(search="", limit=200, offset=0)
    if data["total"] > 200:
        raise HTTPException(status_code=400, detail="CSV report is limited to the first 200 findings; use the paginated findings API for larger datasets.")
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["severity", "status", "rule_id", "language", "project_path", "file", "line", "description", "remediation", "scan_created_at"])
    for item in data["findings"]:
        values = [item.get("severity"), item.get("status"), item.get("test_id"), item.get("language"), item.get("project_path"), item.get("filename"), item.get("line_number"), item.get("description"), item.get("remediation"), item.get("scan_created_at")]
        writer.writerow([("'" + value) if isinstance(value, str) and value[:1] in "=+-@\t\r" else value for value in values])
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=securcode-findings.csv"})
