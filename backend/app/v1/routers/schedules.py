"""Scheduled scans (disabled until explicitly enabled)."""

from __future__ import annotations

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db, utcnow
from ..deps import OrgContext, get_project, org_context, visible_project_ids, writable_org
from ..models import Scan, ScanSchedule
from ..permissions import P
from ..services.schedule import next_run
from .projects import BRANCH

router = APIRouter(prefix="/organizations/{org_id}", tags=["schedules"])


class ScheduleBody(BaseModel):
    project_id: str
    frequency: str = Field(pattern="^(daily|weekly)$")
    hour: int = Field(ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    weekday: int | None = Field(default=None, ge=0, le=6)
    timezone: str = Field(default="UTC", max_length=64)
    branch: str | None = Field(default=None, max_length=200)
    enabled: bool = False


class ScheduleUpdate(BaseModel):
    frequency: str | None = Field(default=None, pattern="^(daily|weekly)$")
    hour: int | None = Field(default=None, ge=0, le=23)
    minute: int | None = Field(default=None, ge=0, le=59)
    weekday: int | None = Field(default=None, ge=0, le=6)
    timezone: str | None = Field(default=None, max_length=64)
    branch: str | None = Field(default=None, max_length=200)
    enabled: bool | None = None


def _payload(db: Session, schedule: ScanSchedule) -> dict:
    history = db.execute(
        select(Scan.id, Scan.status, Scan.created_at).where(Scan.trigger == "scheduled", Scan.project_id == schedule.project_id)
        .order_by(Scan.created_at.desc()).limit(10)
    ).all()
    return {
        "id": schedule.id, "project_id": schedule.project_id, "frequency": schedule.frequency, "hour": schedule.hour,
        "minute": schedule.minute, "weekday": schedule.weekday, "timezone": schedule.timezone, "branch": schedule.branch,
        "enabled": schedule.enabled, "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None, "last_error": schedule.last_error,
        "history": [{"scan_id": h.id, "status": h.status, "created_at": h.created_at.isoformat()} for h in history],
    }


def _validate(schedule: ScanSchedule) -> None:
    try:
        ZoneInfo(schedule.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(status_code=422, detail="Unknown timezone.") from None
    if schedule.frequency == "weekly" and schedule.weekday is None:
        raise HTTPException(status_code=422, detail="Weekly schedules need a weekday (0=Monday).")
    if schedule.branch and not BRANCH.match(schedule.branch):
        raise HTTPException(status_code=422, detail="Invalid branch name.")
    schedule.next_run_at = next_run(schedule, utcnow()) if schedule.enabled else None


@router.get("/schedules")
def list_schedules(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    query = select(ScanSchedule).where(ScanSchedule.org_id == ctx.org.id)
    allowed = visible_project_ids(db, ctx)
    if allowed is not None:
        query = query.where(ScanSchedule.project_id.in_(allowed or {"-"}))
    return {"items": [_payload(db, s) for s in db.execute(query.order_by(ScanSchedule.created_at)).scalars()]}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleBody, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCHEDULES_MANAGE)
    project = get_project(db, ctx, body.project_id)
    schedule = ScanSchedule(org_id=ctx.org.id, project_id=project.id, created_by_id=ctx.user.id,
                            **body.model_dump(exclude={"project_id"}))
    _validate(schedule)
    db.add(schedule)
    db.flush()
    audit.record(db, "schedule.created", actor=ctx.user, org_id=ctx.org.id, project_id=project.id, resource_type="schedule",
                 resource_id=schedule.id, metadata=body.model_dump())
    db.commit()
    return _payload(db, schedule)


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: str, body: ScheduleUpdate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCHEDULES_MANAGE)
    schedule = db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == ctx.org.id)).scalar_one_or_none()
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    get_project(db, ctx, schedule.project_id)
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(schedule, key, value)
    _validate(schedule)
    audit.record(db, "schedule.updated", actor=ctx.user, org_id=ctx.org.id, project_id=schedule.project_id, resource_type="schedule",
                 resource_id=schedule.id, metadata=body.model_dump(exclude_unset=True))
    db.commit()
    return _payload(db, schedule)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.SCHEDULES_MANAGE)
    schedule = db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == ctx.org.id)).scalar_one_or_none()
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    audit.record(db, "schedule.deleted", actor=ctx.user, org_id=ctx.org.id, project_id=schedule.project_id, resource_type="schedule", resource_id=schedule.id)
    db.delete(schedule)
    db.commit()
    return {"status": "deleted"}
