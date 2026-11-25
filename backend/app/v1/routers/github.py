"""GitHub integration management and signed webhook intake."""

from __future__ import annotations

import json
import re
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import OrgContext, org_context, writable_org
from ..models import Integration, Project, Scan, WebhookDelivery
from ..permissions import P
from ..security import EncryptionUnavailable, decrypt_secret, encrypt_secret
from ..services import github as gh
from ..services.common import notify, org_members_with_roles
from ..services.scanning import scope_key_for

router = APIRouter(tags=["github"])
DELIVERY = re.compile(r"^[A-Za-z0-9-]{8,100}$")


class GitHubConnect(BaseModel):
    token: str = Field(min_length=20, max_length=400)
    auto_scan_push: bool = False
    scan_pull_requests: bool = True
    publish_pr_results: bool = True


class GitHubRotate(BaseModel):
    token: str = Field(min_length=20, max_length=400)


class GitHubSettings(BaseModel):
    auto_scan_push: bool | None = None
    scan_pull_requests: bool | None = None
    publish_pr_results: bool | None = None


def _payload(integration: Integration, include_webhook: str | None = None) -> dict:
    data = {
        "id": integration.id, "provider": integration.provider, "auth_type": integration.auth_type,
        "account_login": integration.account_login, "status": integration.status, "credential_hint": integration.credential_hint,
        "last_error": integration.last_error, "settings": integration.settings_json,
        "webhook_url": f"/api/v1/webhooks/github/{integration.id}", "created_at": integration.created_at.isoformat(),
    }
    if include_webhook:
        data["webhook_secret"] = include_webhook  # shown once at creation/rotation
    return data


def _integration(db: Session, ctx: OrgContext, integration_id: str) -> Integration:
    integration = db.execute(
        select(Integration).where(Integration.id == integration_id, Integration.org_id == ctx.org.id)
    ).scalar_one_or_none()
    if integration is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    return integration


def _github_call(fn, *args, integration: Integration | None = None, db: Session | None = None):
    try:
        return fn(*args)
    except gh.GitHubError as error:
        if integration is not None and error.credential_problem and db is not None:
            integration.status = "error"
            integration.last_error = str(error)[:500]
            db.commit()
        raise HTTPException(status_code=502 if not error.credential_problem else 409, detail=str(error)) from None
    except EncryptionUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from None


@router.get("/organizations/{org_id}/integrations")
def list_integrations(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_VIEW)
    items = db.execute(select(Integration).where(Integration.org_id == ctx.org.id).order_by(Integration.created_at)).scalars()
    return {"items": [_payload(i) for i in items]}


@router.post("/organizations/{org_id}/integrations/github", status_code=201)
def connect_github(body: GitHubConnect, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_MANAGE)
    identity = _github_call(gh.validate_token, body.token)
    webhook_secret = secrets.token_urlsafe(32)
    try:
        integration = Integration(
            org_id=ctx.org.id, provider="github", auth_type="token", account_login=identity.get("login"),
            credential_enc=encrypt_secret(body.token), credential_hint=f"…{body.token[-4:]}",
            webhook_secret_enc=encrypt_secret(webhook_secret), created_by_id=ctx.user.id,
            settings_json={"auto_scan_push": body.auto_scan_push, "scan_pull_requests": body.scan_pull_requests,
                           "publish_pr_results": body.publish_pr_results, "token_scopes": identity.get("scopes")},
        )
    except EncryptionUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from None
    db.add(integration)
    db.flush()
    audit.record(db, "integration.connected", actor=ctx.user, org_id=ctx.org.id, resource_type="integration", resource_id=integration.id,
                 metadata={"provider": "github", "account": identity.get("login")})
    db.commit()
    return _payload(integration, include_webhook=webhook_secret)


@router.patch("/organizations/{org_id}/integrations/{integration_id}")
def update_integration(integration_id: str, body: GitHubSettings, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_MANAGE)
    integration = _integration(db, ctx, integration_id)
    integration.settings_json = {**integration.settings_json, **body.model_dump(exclude_none=True)}
    audit.record(db, "integration.updated", actor=ctx.user, org_id=ctx.org.id, resource_type="integration", resource_id=integration.id,
                 metadata=body.model_dump(exclude_none=True))
    db.commit()
    return _payload(integration)


@router.post("/organizations/{org_id}/integrations/{integration_id}/rotate")
def rotate_credential(integration_id: str, body: GitHubRotate, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_MANAGE)
    integration = _integration(db, ctx, integration_id)
    identity = _github_call(gh.validate_token, body.token)
    webhook_secret = secrets.token_urlsafe(32)
    integration.credential_enc = encrypt_secret(body.token)
    integration.credential_hint = f"…{body.token[-4:]}"
    integration.webhook_secret_enc = encrypt_secret(webhook_secret)
    integration.account_login = identity.get("login")
    integration.status = "active"
    integration.last_error = None
    audit.record(db, "integration.credential_rotated", actor=ctx.user, org_id=ctx.org.id, resource_type="integration", resource_id=integration.id)
    db.commit()
    return _payload(integration, include_webhook=webhook_secret)


@router.delete("/organizations/{org_id}/integrations/{integration_id}")
def disconnect(integration_id: str, ctx: OrgContext = Depends(writable_org), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_MANAGE)
    integration = _integration(db, ctx, integration_id)
    integration.credential_enc = None
    integration.webhook_secret_enc = None
    integration.status = "revoked"
    audit.record(db, "integration.disconnected", actor=ctx.user, org_id=ctx.org.id, resource_type="integration", resource_id=integration.id)
    db.commit()
    return {**_payload(integration), "note": "The stored token was deleted. Also revoke the token in GitHub settings."}


@router.get("/organizations/{org_id}/integrations/{integration_id}/repositories")
def repositories(integration_id: str, page: int = Query(default=1, ge=1, le=50), ctx: OrgContext = Depends(org_context),
                 db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_VIEW)
    integration = _integration(db, ctx, integration_id)
    return {"items": _github_call(gh.list_repositories, integration, page, integration=integration, db=db), "page": page}


@router.get("/organizations/{org_id}/integrations/{integration_id}/repositories/{owner}/{repo}/branches")
def branches(integration_id: str, owner: str, repo: str, ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    ctx.require(P.INTEGRATIONS_VIEW)
    integration = _integration(db, ctx, integration_id)
    return {"items": _github_call(gh.list_branches, integration, f"{owner}/{repo}", integration=integration, db=db)}


# --- Webhooks ----------------------------------------------------------------------

@router.post("/webhooks/github/{integration_id}", status_code=202)
async def github_webhook(integration_id: str, request: Request, db: Session = Depends(get_db),
                         x_github_event: str = Header(default=""), x_github_delivery: str = Header(default=""),
                         x_hub_signature_256: str | None = Header(default=None)):
    body = await request.body()
    integration = db.get(Integration, integration_id[:32])
    secret = None
    if integration is not None and integration.webhook_secret_enc and integration.status != "revoked":
        try:
            secret = decrypt_secret(integration.webhook_secret_enc)
        except EncryptionUnavailable:
            secret = None
    # Same response for unknown integrations and bad signatures (no enumeration).
    if secret is None or not gh.verify_webhook_signature(secret, body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")
    if not DELIVERY.match(x_github_delivery or ""):
        raise HTTPException(status_code=400, detail="Missing delivery identifier.")
    delivery = WebhookDelivery(provider="github", delivery_id=x_github_delivery, integration_id=integration.id,
                               event=x_github_event[:60] or "unknown")
    db.add(delivery)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return {"status": "duplicate", "detail": "Delivery already processed."}
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        delivery.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid JSON payload.") from None
    outcome = _handle_event(db, integration, x_github_event, payload)
    delivery.status = outcome["status"]
    delivery.detail = outcome.get("detail")
    db.commit()
    return outcome


def _handle_event(db: Session, integration: Integration, event: str, payload: dict) -> dict:
    if event == "ping":
        return {"status": "ok", "detail": "pong"}
    full_name = ((payload.get("repository") or {}).get("full_name") or "")[:200]
    projects = db.execute(
        select(Project).where(Project.org_id == integration.org_id, Project.integration_id == integration.id,
                              Project.repository_full_name == full_name, Project.status == "active")
    ).scalars().all()
    if not projects:
        return {"status": "ignored", "detail": "No active project is linked to this repository."}
    settings = integration.settings_json or {}
    created = []
    if event == "push":
        ref = str(payload.get("ref", ""))
        branch = ref.removeprefix("refs/heads/")
        sha = str(payload.get("after", ""))[:40]
        if not settings.get("auto_scan_push") or not re.fullmatch(r"[0-9a-f]{40}", sha) or set(sha) == {"0"}:
            return {"status": "ignored", "detail": "Push scanning disabled or branch deleted."}
        for project in projects:
            if branch != project.default_branch:
                continue
            created.append(_queue_scan(db, integration, project, branch, sha, None, "webhook", f"gh:push:{project.id}:{sha}"))
    elif event == "pull_request":
        action = payload.get("action")
        pr = payload.get("pull_request") or {}
        number = payload.get("number") or pr.get("number")
        sha = str((pr.get("head") or {}).get("sha", ""))[:40]
        head_repo = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
        if action not in {"opened", "synchronize", "reopened"} or not settings.get("scan_pull_requests", True):
            return {"status": "ignored", "detail": f"Pull request action {action} not scanned."}
        if not isinstance(number, int) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            return {"status": "rejected", "detail": "Malformed pull request payload."}
        if head_repo and head_repo != full_name:
            # Fork PR: the head commit is still fetched through the base repository, read-only.
            pass
        for project in projects:
            created.append(_queue_scan(db, integration, project, (pr.get("head") or {}).get("ref"), sha, number,
                                       "webhook", f"gh:pr:{project.id}:{number}:{sha}"))
    else:
        return {"status": "ignored", "detail": f"Event {event} is not handled."}
    created = [c for c in created if c]
    return {"status": "queued" if created else "ignored", "detail": f"{len(created)} scan(s) queued.", "scan_ids": created}


def _queue_scan(db: Session, integration: Integration, project: Project, branch, sha, pr_number, trigger, key) -> str | None:
    if db.execute(select(Scan.id).where(Scan.idempotency_key == key)).first():
        return None
    branch = (branch or project.default_branch)[:200]
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch):
        return None
    scan = Scan(org_id=project.org_id, project_id=project.id, trigger=trigger, source_type="github", branch=branch,
                commit_sha=sha, pull_request_number=pr_number, scope_key=scope_key_for("github", branch, pr_number),
                idempotency_key=key, config_json={"integration_id": integration.id})
    db.add(scan)
    db.flush()
    audit.record(db, "scan.requested", org_id=project.org_id, project_id=project.id, resource_type="scan", resource_id=scan.id,
                 metadata={"trigger": trigger, "pull_request": pr_number, "commit": sha})
    return scan.id


def report_integration_problem(db: Session, integration: Integration, message: str) -> None:
    notify(db, org_members_with_roles(db, integration.org_id, {"owner", "admin"}), "integration_problem",
           "GitHub integration needs attention", message, f"/orgs/{integration.org_id}/integrations", integration.org_id)
