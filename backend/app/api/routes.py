
import logging
from pathlib import Path, PureWindowsPath

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_statistics,
)
from security_engine.scanner.engine import scan_project


router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize the local SQLite database.
initialize_database()

# Resolve the workspace from the application location so the API behaves the
# same whether uvicorn is launched from the repository root or backend folder.
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


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


def _public_scan_result(result):
    public_result = {
        **result,
        "findings": [
            {
                **finding,
                "filename": workspace_relative_path(finding["filename"])
                if finding.get("filename")
                else finding.get("filename"),
            }
            for finding in result.get("findings", [])
        ],
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


class ScanRequest(BaseModel):
    project_path: str


@router.get("/status")
def status():
    return {
        "status": "healthy",
        "service": "SecurCode Security Scanner",
    }


@router.post("/scan")
def scan(request: ScanRequest):
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

    target_path = (WORKSPACE_ROOT / requested_path).resolve()

    # Ensure the resolved path stays inside the workspace.
    if not target_path.is_relative_to(WORKSPACE_ROOT):
        raise HTTPException(
            status_code=400,
            detail="Project path must stay inside the workspace.",
        )

    if not target_path.exists() or not (target_path.is_dir() or target_path.is_file()):
        raise HTTPException(
            status_code=404,
            detail="Project path not found.",
        )

    try:
        result = scan_project(str(target_path))
    except Exception:
        logger.exception("Unexpected scan failure for %s", target_path)
        failed_result = {
            "status": "failed",
            "total_findings": 0,
            "findings": [],
            "errors": [{
                "path": str(target_path),
                "message": "Scan failed due to an unexpected scanner error.",
            }],
        }
        public_failed_result = _public_scan_result(failed_result)
        try:
            save_scan(workspace_relative_path(target_path), public_failed_result)
        except Exception:
            logger.exception("Unable to persist failed scan history for %s", target_path)
            raise HTTPException(
                status_code=500,
                detail="The scan failed and its failure could not be recorded in history.",
            ) from None
        raise HTTPException(
            status_code=500,
            detail="The security scan failed. The failure was recorded in scan history.",
        ) from None

    public_result = _public_scan_result(result)
    try:
        save_scan(workspace_relative_path(target_path), public_result)
    except Exception:
        logger.exception("Unable to persist scan history for %s", target_path)
        raise HTTPException(
            status_code=500,
            detail="The scan result could not be recorded in history.",
        ) from None
    return public_result


@router.get("/history")
def scan_history(limit: int = 20):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    scans = get_scan_history(limit)
    for item in scans:
        item["project_path"] = workspace_relative_path(item["project_path"])
        public_result = _public_scan_result(item)
        item["findings"] = public_result["findings"]
        item["errors"] = public_result["errors"]

    return {
        "total": len(scans),
        "scans": scans,
    }


@router.get("/stats")
def scan_statistics():
    statistics = get_scan_statistics()
    latest_scan = statistics.get("latest_scan")
    if latest_scan:
        latest_scan["project_path"] = workspace_relative_path(
            latest_scan["project_path"]
        )
    return statistics
