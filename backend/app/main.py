
from contextlib import asynccontextmanager
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router, workspace_relative_path
from app.api.platform_routes import router as platform_router
from app.auth import (
    router as auth_router,
    allowed_for_role,
    bind_current_user,
    get_user_for_token,
    project_access_allowed,
    reset_current_user,
)
from database import get_connection
from config import parse_allowed_origins, settings
from security_engine.scanner.watcher import SourceFileWatcher


# Keep the watched directory inside the backend workspace.
BACKEND_DIR = (
    Path(__file__).resolve().parent
    / "api"
    / "docs"
    / "security-demo"
)

watcher_state = {
    "running": False,
    "last_file": None,
    "last_findings": [],
    "last_error": None,
}
watcher_lock = Lock()
watcher = None


def _project_id_for_request(path):
    match = re.fullmatch(r"/projects/(\d+)(?:/.*)?", path)
    if match:
        return int(match.group(1))
    match = re.fullmatch(r"/(?:findings|scans)/(\d+)(?:/.*)?", path)
    if match:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT project_id FROM scans WHERE id = ?", (int(match.group(1)),)
            ).fetchone()
        return row["project_id"] if row else None
    return None


def _allowed_origins():
    configured = list(parse_allowed_origins())
    production = os.getenv("SECURCODE_ENV", "").lower() == "production"
    if production and (
        not configured
        or any(
            origin == "*"
            or urlsplit(origin).scheme != "https"
            or not urlsplit(origin).netloc
            or urlsplit(origin).path not in {"", "/"}
            or urlsplit(origin).query
            or urlsplit(origin).fragment
            or urlsplit(origin).username is not None
            or urlsplit(origin).password is not None
            for origin in configured
        )
    ):
        raise RuntimeError(
            "SECURCODE_ALLOWED_ORIGINS must contain exact HTTPS frontend origins."
        )
    if not production:
        configured.extend([
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5176",
            "http://127.0.0.1:5176",
        ])
    return list(dict.fromkeys(configured))


def _redact_finding_paths(findings):
    """Return watcher findings with workspace-relative filenames."""
    redacted = []
    for finding in findings or []:
        record = dict(finding)
        filename = record.get("filename")
        if filename:
            record["filename"] = workspace_relative_path(filename)
        redacted.append(record)
    return redacted


def handle_file_change(filename, findings):
    """Store the latest result produced by the file watcher."""
    with watcher_lock:
        watcher_state["last_file"] = str(filename)
        watcher_state["last_findings"] = _redact_finding_paths(findings)
        watcher_state["last_error"] = None


def handle_file_scan_error(filename, error):
    """Expose watcher failures without presenting them as clean results."""
    with watcher_lock:
        watcher_state["last_file"] = str(filename)
        watcher_state["last_findings"] = []
        watcher_state["last_error"] = (
            f"Source file scan failed ({type(error).__name__})."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global watcher

    watcher = SourceFileWatcher(
        root=BACKEND_DIR,
        on_change=handle_file_change,
        on_error=handle_file_scan_error,
        interval=1.0,
        debounce=0.5,
    )
    watcher.start()

    with watcher_lock:
        watcher_state["running"] = True

    try:
        yield
    finally:
        watcher.stop()

        with watcher_lock:
            watcher_state["running"] = False

        watcher = None


production = settings.environment == "production"
app = FastAPI(
    title="SecurCode Security API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if production else "/docs",
    redoc_url=None if production else "/redoc",
    openapi_url=None if production else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(router)
app.include_router(platform_router)
app.include_router(auth_router)


@app.middleware("http")
async def authenticate_and_authorize(request: Request, call_next):
    path = request.url.path
    demo_mode = os.getenv("SECURCODE_DEMO_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
    if demo_mode and path.startswith("/auth/"):
        return JSONResponse({"detail": "Authentication endpoints are unavailable in the public demo."}, status_code=404)
    public_paths = {"/", "/healthz", "/status", "/auth/login", "/auth/bootstrap", "/openapi.json", "/docs", "/redoc"}
    if request.method == "OPTIONS" or path in public_paths:
        return await call_next(request)
    if demo_mode:
        if request.method in {"GET", "HEAD"} or path == "/scan":
            return await call_next(request)
        return JSONResponse({"detail": "Changes are disabled in the public demo."}, status_code=403)
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return JSONResponse({"detail": "Authentication required."}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    user = get_user_for_token(token)
    if not user:
        return JSONResponse({"detail": "Session is invalid or expired."}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    if not allowed_for_role(user["role"], request.method, path):
        return JSONResponse({"detail": "Your role is not allowed to perform this action."}, status_code=403)
    if user["role"] != "administrator":
        if path == "/projects" and request.method in {"GET", "POST"}:
            pass
        elif path in {
            "/auth/me",
            "/auth/logout",
            "/auth/password",
            "/integrations/status",
            "/scan",
            "/integrations/sarif/import",
        } or re.fullmatch(r"/integrations/[^/]+/scan", path):
            pass
        else:
            project_id = _project_id_for_request(path)
            if project_id is None:
                return JSONResponse(
                    {"detail": "This endpoint is unavailable outside an authorized project."},
                    status_code=403,
                )
            if not project_access_allowed(project_id, user):
                return JSONResponse({"detail": "Project not found."}, status_code=404)
    request.state.user = user
    request.state.access_token = token
    context_token = bind_current_user(user)
    try:
        return await call_next(request)
    finally:
        reset_current_user(context_token)


@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path not in {"/docs", "/redoc"}:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
    return response


@app.get("/")
def root():
    return {"message": "SecurCode API is running"}


@app.get("/healthz")
def health_check():
    """Simple readiness endpoint for the hosting platform."""
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1")
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="The application database is unavailable.") from None
    return {
        "status": "healthy",
        "service": "SecurCode Security Scanner",
    }


@app.get("/watcher/status")
def get_watcher_status():
    with watcher_lock:
        return {
            "running": watcher_state["running"],
            "last_file": (
                workspace_relative_path(watcher_state["last_file"])
                if watcher_state["last_file"]
                else None
            ),
            "last_findings_count": len(watcher_state["last_findings"]),
            "last_error": watcher_state["last_error"],
        }


@app.get("/watcher/findings")
def get_watcher_findings():
    with watcher_lock:
        redacted_findings = _redact_finding_paths(watcher_state["last_findings"])
        return {
            "last_file": (
                workspace_relative_path(watcher_state["last_file"])
                if watcher_state["last_file"]
                else None
            ),
            "total_findings": len(redacted_findings),
            "findings": redacted_findings,
            "error": watcher_state["last_error"],
        }
