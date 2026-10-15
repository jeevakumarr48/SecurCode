
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_statistics,
)
from security_engine.scanner.engine import scan_project


router = APIRouter()

# Initialize the local SQLite database.
initialize_database()

# Resolve the workspace from the application location so the API behaves the
# same whether uvicorn is launched from the repository root or backend folder.
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


class ScanRequest(BaseModel):
    project_path: str = Field(min_length=1, max_length=500)


@router.get("/status")
def status():
    return {
        "status": "healthy",
        "service": "SecurCode Security Scanner",
    }


@router.post("/scan")
def scan(request: ScanRequest):
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
        save_scan(str(target_path), result)
        return result

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="The security scan failed. Check the backend logs.",
        )


@router.get("/history")
def scan_history(limit: int = 20):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    scans = get_scan_history(limit)

    return {
        "total": len(scans),
        "scans": scans,
    }


@router.get("/stats")
def scan_statistics():
    return get_scan_statistics()
