"""Assembles the /api/v1 router and its cross-cutting middleware."""

from __future__ import annotations

import logging
import re
import secrets
import time

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .audit import client_ip_var, request_id_var
from .settings import platform_settings

API_PREFIX = "/api/v1"
logger = logging.getLogger("securcode.v1.http")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
# Upload endpoints may stream up to the configured archive size; everything else is small JSON.
_UPLOAD_PATHS = re.compile(r"^/api/v1/organizations/[^/]+/projects/[^/]+/(archives|scans/upload)$")
_WEBHOOK_PATHS = re.compile(r"^/api/v1/webhooks/")
DEFAULT_BODY_LIMIT = 1_000_000


def build_router() -> APIRouter:
    from .routers import (
        admin,
        analytics,
        auth,
        findings,
        github,
        health,
        notifications,
        organizations,
        policies,
        projects,
        reports,
        scans,
        schedules,
    )

    router = APIRouter(prefix=API_PREFIX)
    for module in (health, auth, organizations, projects, scans, findings, policies, analytics,
                   reports, notifications, schedules, github, admin):
        router.include_router(module.router)
    return router


def install(app: FastAPI) -> None:
    app.include_router(build_router())

    @app.middleware("http")
    async def v1_request_context(request: Request, call_next):
        if not request.url.path.startswith(API_PREFIX):
            return await call_next(request)
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID.match(incoming) else secrets.token_hex(12)
        rid_token = request_id_var.set(request_id)
        ip_token = client_ip_var.set(request.client.host if request.client else None)
        started = time.monotonic()
        try:
            limit = platform_settings.max_upload_bytes + 64_000 if _UPLOAD_PATHS.match(request.url.path) else (
                5_000_000 if _WEBHOOK_PATHS.match(request.url.path) else DEFAULT_BODY_LIMIT
            )
            length = request.headers.get("content-length")
            if length is not None:
                try:
                    if int(length) > limit:
                        return JSONResponse({"detail": "Request body is too large.", "request_id": request_id}, status_code=413)
                except ValueError:
                    return JSONResponse({"detail": "Invalid Content-Length header.", "request_id": request_id}, status_code=400)
            elif request.method in {"POST", "PUT", "PATCH"} and request.headers.get("transfer-encoding", "").lower() == "chunked":
                return JSONResponse({"detail": "Chunked request bodies are not accepted.", "request_id": request_id}, status_code=411)
            response = await call_next(request)
        finally:
            request_id_var.reset(rid_token)
            client_ip_var.reset(ip_token)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        body = {"detail": exc.detail}
        if request.url.path.startswith(API_PREFIX):
            body["request_id"] = request_id_var.get()
        return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        errors = [
            {"loc": [str(part) for part in error.get("loc", [])], "msg": error.get("msg", "Invalid value")}
            for error in exc.errors()
        ]
        return JSONResponse({"detail": "Request validation failed.", "errors": errors,
                             "request_id": request_id_var.get()}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):  # pragma: no cover - defensive
        logger.exception("Unhandled error (%s)", type(exc).__name__)
        return JSONResponse({"detail": "An unexpected error occurred.", "request_id": request_id_var.get()}, status_code=500)
