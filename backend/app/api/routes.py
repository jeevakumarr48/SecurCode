
import logging
import os
import sqlite3
from pathlib import Path, PureWindowsPath
from threading import BoundedSemaphore, Lock
from time import monotonic
import time
from config import settings, validate_bootstrap_configuration

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.auth import current_user, project_access_allowed
from database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_statistics,
    get_connection,
    finding_fingerprint,
)
from security_engine.scanner.engine import scan_project


router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize the local SQLite database.
initialize_database()
if settings.environment == "production" and not settings.demo_mode:
    with get_connection() as connection:
        user_count = connection.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0]
    validate_bootstrap_configuration(user_count)

# Resolve the workspace from the application location so the API behaves the
# same whether uvicorn is launched from the repository root or backend folder.
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
DEMO_MODE = settings.demo_mode
DEMO_RELATIVE_PATH = Path("backend/app/api/docs/security-demo")
DEMO_SCAN_COOLDOWN_SECONDS = settings.demo_scan_cooldown_seconds
_demo_scan_lock = Lock()
_last_demo_scan_at = 0.0
scan_semaphore = BoundedSemaphore(1)


def _enforce_demo_scan_cooldown():
    global _last_demo_scan_at
    now = monotonic()
    with _demo_scan_lock:
        if now - _last_demo_scan_at < DEMO_SCAN_COOLDOWN_SECONDS:
            raise HTTPException(
                status_code=429,
                detail="The public demo is rate limited. Please wait a few seconds and try again.",
            )
        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = time.time()
            connection.execute("DELETE FROM demo_scan_events WHERE created_at_epoch < ?", (current - 3600,))
            last = connection.execute("SELECT MAX(created_at_epoch) FROM demo_scan_events").fetchone()[0]
            if last is not None and current - last < DEMO_SCAN_COOLDOWN_SECONDS:
                raise HTTPException(
                    status_code=429,
                    detail="The public demo is rate limited. Please wait a few seconds and try again.",
                )
            connection.execute("INSERT INTO demo_scan_events(created_at_epoch) VALUES (?)", (current,))
        _last_demo_scan_at = now


def workspace_relative_path(value):
    """Return a workspace-relative path or a stable redaction marker."""
    raw_path = str(value)
    windows_path = PureWindowsPath(raw_path)
    path = Path(raw_path)
    if windows_path.is_absolute() and not path.is_absolute():
        return "<outside-workspace>"
    if not path.is_absolute() and "\\" in raw_path:
        if ".." in windows_path.parts:
            return "<outside-workspace>"
        path = Path(*windows_path.parts)
    candidate = path if path.is_absolute() else WORKSPACE_ROOT / path
    try:
        relative_path = candidate.resolve(strict=False).relative_to(WORKSPACE_ROOT)
    except (OSError, RuntimeError, ValueError):
        return "<outside-workspace>"
    return relative_path.as_posix() or "."


def _public_scan_result(result, project_path=None):
    stable_project_path = project_path or "."
    public_findings = []
    for finding in result.get("findings", []):
        record = {
            **finding,
            "filename": workspace_relative_path(finding["filename"])
            if finding.get("filename")
            else finding.get("filename"),
        }
        record["finding_id"] = finding_fingerprint(stable_project_path, record)
        public_findings.append(record)
    public_result = {
        **result,
        "findings": public_findings,
        "errors": [
            {
                **error,
                "path": workspace_relative_path(error["path"])
                if error.get("path")
                else error.get("path"),
            }
            for error in result.get("errors", [])
        ],
    }
    return public_result


def public_statistics(statistics):
    result = dict(statistics)
    latest = result.get("latest_scan")
    if latest:
        latest = dict(latest)
        latest["project_path"] = workspace_relative_path(latest.get("project_path", ""))
        result["latest_scan"] = latest
    for key in ("recent_scans", "most_affected_projects"):
        rows = []
        for row in result.get(key, []):
            record = dict(row)
            if record.get("project_path"):
                record["project_path"] = workspace_relative_path(record["project_path"])
            rows.append(record)
        if key in result:
            result[key] = rows
    return result


class ScanRequest(BaseModel):
    project_path: str


@router.get("/status")
def status():
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1")
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="The application database is unavailable.") from None
    return {
        "status": "healthy",
        "service": "SecurCode Security Scanner",
        "database": "healthy",
        "scanner": "available",
        "demo_mode": DEMO_MODE,
        "read_only": DEMO_MODE,
    }


def _scan_request(request: ScanRequest):
    if not request.project_path or len(request.project_path) > 500:
        raise HTTPException(
            status_code=400,
            detail="Project path must contain between 1 and 500 characters.",
        )

    requested_path = Path(request.project_path)

    # Reject absolute paths and directory traversal.
    if requested_path.is_absolute() or ".." in requested_path.parts:
        raise HTTPException(
            status_code=400,
            detail="Invalid project path. Use a relative path inside the workspace.",
        )

    unresolved_path = WORKSPACE_ROOT / requested_path
    current_path = WORKSPACE_ROOT
    for part in requested_path.parts:
        current_path = current_path / part
        try:
            if current_path.is_symlink():
                raise HTTPException(status_code=400, detail="Project path must stay inside the workspace; symbolic link scan targets are not allowed.")
        except OSError:
            raise HTTPException(status_code=400, detail="Project path could not be resolved safely.") from None
    try:
        target_path = unresolved_path.resolve()
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(status_code=400, detail="Project path could not be resolved safely.") from None

    # Ensure the resolved path stays inside the workspace.
    if not target_path.is_relative_to(WORKSPACE_ROOT):
        raise HTTPException(
            status_code=400,
            detail="Project path must stay inside the workspace.",
        )

    user = current_user()
    if user and user["role"] != "administrator":
        with get_connection() as connection:
            projects = connection.execute(
                "SELECT id, project_path FROM projects"
            ).fetchall()
        authorized = False
        for project in projects:
            project_root = (WORKSPACE_ROOT / project["project_path"]).resolve()
            if (
                target_path == project_root
                or project_root in target_path.parents
            ) and project_access_allowed(project["id"], user):
                authorized = True
                break
        if not authorized:
            raise HTTPException(
                status_code=404,
                detail="Project must be registered and accessible before scanning.",
            )

    if DEMO_MODE:
        demo_root = (WORKSPACE_ROOT / DEMO_RELATIVE_PATH).resolve()
        allowed_demo_paths = {
            demo_root,
            demo_root / "safe_example.py",
            demo_root / "safe-example.py",
            demo_root / "vulnerable.py",
        }
        if target_path not in allowed_demo_paths:
            raise HTTPException(
                status_code=403,
                detail="Public demo scans are limited to the bundled security demo samples.",
            )
        _enforce_demo_scan_cooldown()

    if not target_path.exists() or not (target_path.is_dir() or target_path.is_file()):
        raise HTTPException(
            status_code=404,
            detail="Project path not found.",
        )

    try:
        result = scan_project(str(target_path))
    except Exception:
        logger.exception("Unexpected scan failure")
        failed_result = {
            "status": "failed",
            "total_findings": 0,
            "findings": [],
            "errors": [{
                "path": str(target_path),
                "message": "Scan failed due to an unexpected scanner error.",
            }],
        }
        public_failed_result = _public_scan_result(failed_result, workspace_relative_path(target_path))
        try:
            save_scan(workspace_relative_path(target_path), public_failed_result)
        except Exception:
            logger.exception("Unable to persist failed scan history")
            raise HTTPException(
                status_code=500,
                detail="The scan failed and its failure could not be recorded in history.",
            ) from None
        raise HTTPException(
            status_code=500,
            detail="The security scan failed. The failure was recorded in scan history.",
        ) from None

    public_result = _public_scan_result(result, workspace_relative_path(target_path))
    try:
        save_scan(workspace_relative_path(target_path), public_result)
    except Exception:
        logger.exception("Unable to persist scan history")
        raise HTTPException(
            status_code=500,
            detail="The scan result could not be recorded in history.",
        ) from None
    return public_result


@router.post("/scan")
def scan(request: ScanRequest):
    if not scan_semaphore.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Another scan is already running; retry when it completes.")
    try:
        return _scan_request(request)
    finally:
        scan_semaphore.release()


@router.get("/history")
def scan_history(limit: int = 20):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    scans = (
        get_scan_history(limit, DEMO_RELATIVE_PATH.as_posix())
        if DEMO_MODE else get_scan_history(limit)
    )
    for item in scans:
        item["project_path"] = workspace_relative_path(item["project_path"])
        public_result = _public_scan_result(item, item["project_path"])
        item["findings"] = public_result["findings"]
        item["errors"] = public_result["errors"]

    return {
        "total": len(scans),
        "scans": scans,
    }


@router.get("/stats")
def scan_statistics():
    statistics = (
        get_scan_statistics(DEMO_RELATIVE_PATH.as_posix(), include_incidents=False)
        if DEMO_MODE else get_scan_statistics()
    )
    return public_statistics(statistics)
