"""In-app notifications and per-kind delivery preferences."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ..db import get_db, utcnow
from ..deps import AuthContext, current_auth
from ..models import Notification, NotificationPreference
from ..services.common import NOTIFICATION_KINDS
from ..settings import platform_settings

router = APIRouter(prefix="/notifications", tags=["notifications"])


class PreferenceUpdate(BaseModel):
    kind: str
    in_app: bool = True
    email: bool = False


@router.get("")
def list_notifications(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
                       unread_only: bool = False, limit: int = Query(default=30, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    query = select(Notification).where(Notification.user_id == auth.user.id)
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    unread = db.execute(
        select(func.count()).select_from(Notification).where(Notification.user_id == auth.user.id, Notification.read_at.is_(None))
    ).scalar_one()
    items = db.execute(query.order_by(Notification.created_at.desc()).limit(limit).offset(offset)).scalars()
    return {"unread": unread, "items": [
        {"id": n.id, "kind": n.kind, "title": n.title, "body": n.body, "link": n.link, "org_id": n.org_id,
         "read": n.read_at is not None, "created_at": n.created_at.isoformat()} for n in items
    ]}


@router.post("/{notification_id}/read")
def mark_read(notification_id: str, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    notification = db.execute(
        select(Notification).where(Notification.id == notification_id, Notification.user_id == auth.user.id)
    ).scalar_one_or_none()
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found.")
    notification.read_at = notification.read_at or utcnow()
    db.commit()
    return {"status": "read"}


@router.post("/read-all")
def mark_all_read(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    count = db.execute(
        update(Notification).where(Notification.user_id == auth.user.id, Notification.read_at.is_(None)).values(read_at=utcnow())
    ).rowcount
    db.commit()
    return {"status": "read", "count": count}


@router.get("/preferences")
def get_preferences(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    stored = {p.kind: p for p in db.execute(select(NotificationPreference).where(NotificationPreference.user_id == auth.user.id)).scalars()}
    return {"email_available": platform_settings.email_configured, "items": [
        {"kind": kind, "in_app": stored[kind].in_app if kind in stored else True, "email": stored[kind].email if kind in stored else False}
        for kind in sorted(NOTIFICATION_KINDS)
    ]}


@router.put("/preferences")
def set_preference(body: PreferenceUpdate, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)):
    if body.kind not in NOTIFICATION_KINDS:
        raise HTTPException(status_code=422, detail="Unknown notification kind.")
    pref = db.execute(
        select(NotificationPreference).where(NotificationPreference.user_id == auth.user.id, NotificationPreference.kind == body.kind)
    ).scalar_one_or_none()
    if pref is None:
        pref = NotificationPreference(user_id=auth.user.id, kind=body.kind)
        db.add(pref)
    pref.in_app = body.in_app
    pref.email = body.email
    db.commit()
    return {"kind": body.kind, "in_app": pref.in_app, "email": pref.email}
