"""Rate limiting, email delivery and notification fan-out."""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from fastapi import HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import Membership, Notification, NotificationPreference, RateEvent, User
from ..settings import platform_settings

logger = logging.getLogger("securcode.v1")


# --- Database-backed rate limiting (works across API replicas) -------------------

def hit_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    """Record an attempt and raise 429 when the sliding window is exceeded.

    Uses its own short transaction so the attempt is counted even when the
    surrounding request later fails and rolls back.
    """
    from ..db import SessionLocal

    now = utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    key = key[:200]
    with SessionLocal() as db:
        count = db.execute(
            select(func.count()).select_from(RateEvent).where(RateEvent.key == key, RateEvent.created_at >= cutoff)
        ).scalar_one()
        if count >= limit:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please wait and try again.",
                headers={"Retry-After": str(window_seconds)},
            )
        db.add(RateEvent(key=key, created_at=now))
        db.commit()


def prune_rate_events(db: Session, older_than_seconds: int = 86400) -> int:
    cutoff = utcnow() - timedelta(seconds=older_than_seconds)
    result = db.execute(delete(RateEvent).where(RateEvent.created_at < cutoff))
    return result.rowcount or 0


# --- Email ------------------------------------------------------------------------

class EmailResult:
    def __init__(self, delivered: bool, mode: str, detail: str = ""):
        self.delivered = delivered
        self.mode = mode
        self.detail = detail


def _single_line(value: str, limit: int = 2000) -> str:
    return value[:limit].replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def send_email(to: str, subject: str, body: str) -> EmailResult:
    """Send via SMTP when configured. Without SMTP, development prints the
    message to the server console (never in production) and callers fall
    back to showing the link to an authorised administrator once."""
    if not platform_settings.email_configured:
        if not platform_settings.is_production:
            # Development only: print the message so links can be followed locally.
            # CR/LF are escaped so user-controlled values cannot forge log lines.
            logger.warning("Email delivery not configured; development message: %s",
                           _single_line(f"to={to} subject={subject} body={body}"))
            return EmailResult(False, "console")
        return EmailResult(False, "unconfigured")
    message = EmailMessage()
    message["From"] = platform_settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(platform_settings.smtp_host, platform_settings.smtp_port, timeout=15) as client:
            if platform_settings.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
            if platform_settings.smtp_username:
                client.login(platform_settings.smtp_username, platform_settings.smtp_password or "")
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        logger.error("Email delivery failed (%s)", type(error).__name__)
        return EmailResult(False, "smtp_error", type(error).__name__)
    return EmailResult(True, "smtp")


# --- Notifications ------------------------------------------------------------------

NOTIFICATION_KINDS = {
    "scan_completed", "scan_failed", "critical_finding", "high_finding", "finding_assigned",
    "finding_comment", "remediation_due", "review_decision", "review_requested", "integration_problem",
    "invitation", "policy_changed",
}


def notify(
    db: Session,
    user_ids,
    kind: str,
    title: str,
    body: str = "",
    link: str | None = None,
    org_id: str | None = None,
) -> int:
    user_ids = {uid for uid in user_ids if uid}
    if not user_ids:
        return 0
    prefs = {
        pref.user_id: pref
        for pref in db.execute(
            select(NotificationPreference).where(
                NotificationPreference.user_id.in_(user_ids), NotificationPreference.kind == kind
            )
        ).scalars()
    }
    created = 0
    email_targets = []
    for user_id in user_ids:
        pref = prefs.get(user_id)
        if pref is None or pref.in_app:
            db.add(Notification(user_id=user_id, org_id=org_id, kind=kind, title=title[:200], body=body, link=link))
            created += 1
        if pref is not None and pref.email:
            email_targets.append(user_id)
    db.flush()
    if email_targets and platform_settings.email_configured:
        for user in db.execute(select(User).where(User.id.in_(email_targets))).scalars():
            send_email(user.email, f"[SecurCode] {title}", f"{body}\n\n{platform_settings.public_app_url}{link or ''}")
    return created


def org_members_with_roles(db: Session, org_id: str, roles) -> list[str]:
    return list(
        db.execute(
            select(Membership.user_id).where(Membership.org_id == org_id, Membership.role.in_(list(roles)))
        ).scalars()
    )
