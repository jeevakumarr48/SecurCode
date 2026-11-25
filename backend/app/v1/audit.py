"""Hash-chained audit trail.

Each event stores the SHA-256 of its canonical content plus the previous
event's hash. Verification detects modified, inserted or deleted rows.
This is tamper-evident, not tamper-proof: a database administrator could
rewrite the entire chain. Exporting the latest hash externally closes that gap.
"""

from __future__ import annotations

import hashlib
import json
from contextvars import ContextVar
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .db import utcnow
from .models import AuditEvent

request_id_var: ContextVar[str | None] = ContextVar("securcode_request_id", default=None)
client_ip_var: ContextVar[str | None] = ContextVar("securcode_client_ip", default=None)

_FORBIDDEN_KEYS = {"password", "token", "secret", "credential", "authorization", "cookie", "csrf", "code"}


def _clean_metadata(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        cleaned = {}
        for key, item in list(value.items())[:50]:
            lowered = str(key).lower()
            if any(word in lowered for word in _FORBIDDEN_KEYS):
                cleaned[str(key)] = "[redacted]"
            else:
                cleaned[str(key)] = _clean_metadata(item, depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_clean_metadata(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, str):
        return value[:500]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:500]


def _canonical(event: AuditEvent) -> str:
    return json.dumps(
        {
            "org_id": event.org_id,
            "project_id": event.project_id,
            "actor_id": event.actor_id,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "metadata": event.metadata_json,
            "scope": event.scope,
            "created_at": event.created_at.isoformat(),
            "prev_hash": event.prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def record(
    db: Session,
    action: str,
    *,
    actor=None,
    org_id: str | None = None,
    project_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
    scope: str = "org",
) -> AuditEvent:
    """Append an audit event within the caller's transaction."""
    if db.get_bind().dialect.name == "postgresql":
        # Serialise chain appends so concurrent transactions cannot fork the chain.
        db.execute(text("SELECT pg_advisory_xact_lock(724001)"))
    previous = db.execute(select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)).scalar()
    now = utcnow()
    event = AuditEvent(
        org_id=org_id,
        project_id=project_id,
        actor_id=getattr(actor, "id", None),
        actor_email=getattr(actor, "email", None),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        metadata_json=_clean_metadata(metadata or {}),
        ip_address=client_ip_var.get(),
        request_id=request_id_var.get(),
        scope=scope,
        created_at=now.replace(microsecond=(now.microsecond // 1000) * 1000),
        prev_hash=previous,
    )
    event.hash = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session) -> dict:
    previous = None
    checked = 0
    for event in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        if event.prev_hash != previous:
            return {"valid": False, "checked": checked, "broken_at": event.id, "reason": "chain link mismatch"}
        expected = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
        if expected != event.hash:
            return {"valid": False, "checked": checked, "broken_at": event.id, "reason": "content hash mismatch"}
        previous = event.hash
        checked += 1
    return {"valid": True, "checked": checked, "head": previous}
