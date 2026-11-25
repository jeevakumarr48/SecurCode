"""Liveness/readiness endpoints that reveal no sensitive operational detail."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..db import get_db, utcnow
from ..models import WorkerHeartbeat

router = APIRouter(tags=["health"])


@router.get("/health/live")
def live():
    return {"status": "ok"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        from alembic.runtime.migration import MigrationContext

        context = MigrationContext.configure(db.connection(), opts={"version_table": "sc_alembic_version"})
        revision = context.get_current_revision()
    except Exception:  # noqa: BLE001 - any failure means not ready
        return JSONResponse({"status": "unavailable", "database": "unavailable"}, status_code=503)
    if revision is None:
        return JSONResponse({"status": "unavailable", "database": "migrations_pending"}, status_code=503)
    return {"status": "ready", "database": "ok"}


@router.get("/health/worker")
def worker(db: Session = Depends(get_db)):
    cutoff = utcnow() - timedelta(seconds=90)
    active = db.execute(
        select(func.count()).select_from(WorkerHeartbeat).where(WorkerHeartbeat.last_seen_at >= cutoff)
    ).scalar_one()
    body = {"status": "ok" if active else "no_active_worker", "active_workers": active}
    return JSONResponse(body, status_code=200 if active else 503)
