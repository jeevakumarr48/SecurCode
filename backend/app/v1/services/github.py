"""Minimal, SSRF-safe GitHub REST client and pull-request result publishing.

Only the configured API host and GitHub's archive host are ever contacted;
redirects are followed manually and only to those hosts. Tokens are
decrypted just-in-time and never logged or returned to the browser.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Integration, Project, Scan, ScanFinding
from ..security import decrypt_secret
from ..settings import platform_settings

logger = logging.getLogger("securcode.v1.github")
ARCHIVE_HOSTS = {"codeload.github.com"}
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
TIMEOUT = httpx.Timeout(20.0, connect=10.0)
_transport: httpx.BaseTransport | None = None  # tests inject a MockTransport


class GitHubError(Exception):
    def __init__(self, message: str, credential_problem: bool = False, status: int | None = None):
        super().__init__(message)
        self.credential_problem = credential_problem
        self.status = status


def set_transport(transport: httpx.BaseTransport | None) -> None:
    global _transport
    _transport = transport


class _GuardedTransport(httpx.BaseTransport):
    """Turns network failures (DNS, TLS, timeouts) into GitHubError so callers
    report "GitHub unreachable" instead of failing with an unhandled 500."""

    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            return self._inner.handle_request(request)
        except httpx.TransportError as error:
            logger.warning("GitHub request to %s failed: %s", request.url.host, type(error).__name__)
            raise GitHubError("Could not reach GitHub; try again later.", status=503) from None

    def close(self) -> None:
        self._inner.close()


def _guarded_transport() -> httpx.BaseTransport:
    return _GuardedTransport(_transport if _transport is not None else httpx.HTTPTransport())


def _allowed_hosts() -> set[str]:
    return {urlsplit(platform_settings.github_api_url).hostname or "api.github.com", *ARCHIVE_HOSTS}


def _client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url=platform_settings.github_api_url, timeout=TIMEOUT, follow_redirects=False, transport=_guarded_transport(),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecurCode"},
    )


def _check(response: httpx.Response) -> httpx.Response:
    if response.status_code == 401:
        raise GitHubError("GitHub rejected the credential (expired or revoked).", credential_problem=True, status=401)
    if response.status_code == 403:
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining == "0":
            raise GitHubError("GitHub API rate limit reached; try again later.", status=403)
        raise GitHubError("The credential lacks permission for this repository or action.", credential_problem=True, status=403)
    if response.status_code == 404:
        raise GitHubError("Repository or reference not found, or not accessible with this credential.", status=404)
    if response.status_code >= 400:
        raise GitHubError(f"GitHub API error ({response.status_code}).", status=response.status_code)
    return response


def token_for(integration: Integration) -> str:
    if not integration.credential_enc or integration.status == "revoked":
        raise GitHubError("The integration has no active credential.", credential_problem=True)
    return decrypt_secret(integration.credential_enc)


def validate_token(token: str) -> dict:
    with _client(token) as client:
        response = _check(client.get("/user"))
    user = response.json()
    return {"login": user.get("login"), "type": user.get("type"), "scopes": response.headers.get("x-oauth-scopes")}


def list_repositories(integration: Integration, page: int = 1) -> list[dict]:
    with _client(token_for(integration)) as client:
        repos = _check(client.get("/user/repos", params={"per_page": 50, "page": page, "sort": "updated",
                                                         "affiliation": "owner,collaborator,organization_member"})).json()
    return [{"full_name": r["full_name"], "private": r.get("private", False), "default_branch": r.get("default_branch", "main"),
             "html_url": r.get("html_url"), "language": r.get("language"), "updated_at": r.get("updated_at")} for r in repos]


def get_repository(integration: Integration, full_name: str) -> dict:
    if not REPO.match(full_name):
        raise GitHubError("Invalid repository name.")
    with _client(token_for(integration)) as client:
        repo = _check(client.get(f"/repos/{full_name}")).json()
    return {"full_name": repo["full_name"], "default_branch": repo.get("default_branch", "main"), "private": repo.get("private"),
            "html_url": repo.get("html_url"), "language": repo.get("language")}


def list_branches(integration: Integration, full_name: str) -> list[dict]:
    if not REPO.match(full_name):
        raise GitHubError("Invalid repository name.")
    with _client(token_for(integration)) as client:
        branches = _check(client.get(f"/repos/{full_name}/branches", params={"per_page": 100})).json()
    return [{"name": b["name"], "commit_sha": b.get("commit", {}).get("sha"), "protected": b.get("protected", False)} for b in branches]


def download_repository_archive(integration: Integration, full_name: str, ref: str, max_bytes: int) -> tuple[bytes, str]:
    if not REPO.match(full_name or "") or not REF.match(ref or "") or ".." in ref:
        raise GitHubError("Invalid repository or reference.")
    with _client(token_for(integration)) as client:
        sha = _check(client.get(f"/repos/{full_name}/commits/{ref}", headers={"Accept": "application/vnd.github.sha"})).text.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GitHubError("Could not resolve the reference to a commit.")
        response = client.get(f"/repos/{full_name}/tarball/{sha}")
        hops = 0
        while response.status_code in (301, 302, 303, 307, 308) and hops < 3:
            location = response.headers.get("location", "")
            parts = urlsplit(location)
            if parts.scheme != "https" or parts.hostname not in _allowed_hosts():
                raise GitHubError("GitHub redirected to an unexpected host; download refused.")
            hops += 1
            # Archive hosts receive a short-lived signed URL; never forward the token there.
            with httpx.Client(timeout=TIMEOUT, follow_redirects=False, transport=_guarded_transport(),
                              headers={"User-Agent": "SecurCode"}) as archive_client:
                with archive_client.stream("GET", location) as stream:
                    if stream.status_code in (301, 302, 303, 307, 308):
                        response = stream
                        continue
                    _check(stream)
                    chunks, size = [], 0
                    for chunk in stream.iter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise GitHubError(f"Repository archive exceeds the {max_bytes // 1_000_000} MB policy limit.")
                        chunks.append(chunk)
                    return b"".join(chunks), sha
        _check(response)
        if len(response.content) > max_bytes:
            raise GitHubError(f"Repository archive exceeds the {max_bytes // 1_000_000} MB policy limit.")
        return response.content, sha


def verify_webhook_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def new_findings_versus_base(db: Session, scan: Scan) -> tuple[list[ScanFinding], Scan | None]:
    project = db.get(Project, scan.project_id)
    base = db.execute(
        select(Scan).where(Scan.project_id == scan.project_id, Scan.scope_key == f"branch:{project.default_branch}",
                           Scan.status == "completed").order_by(Scan.created_at.desc()).limit(1)
    ).scalar_one_or_none()
    base_prints = set(db.execute(select(ScanFinding.fingerprint).where(ScanFinding.scan_id == base.id)).scalars()) if base else set()
    occurrences = db.execute(select(ScanFinding).where(ScanFinding.scan_id == scan.id)).scalars().all()
    return [o for o in occurrences if o.fingerprint not in base_prints], base


def publish_pull_request_result(db: Session, scan: Scan, fail_severity: str | None) -> dict | None:
    """Post a commit status and a concise PR comment. Only actually detected
    findings are reported; the status fails only when the org configured a
    threshold."""
    if not scan.pull_request_number or not scan.commit_sha:
        return None
    project = db.get(Project, scan.project_id)
    integration = db.get(Integration, project.integration_id) if project.integration_id else None
    if integration is None or integration.status == "revoked" or not (integration.settings_json or {}).get("publish_pr_results", True):
        return None
    new, base = new_findings_versus_base(db, scan)
    order = ["info", "low", "medium", "high", "critical"]
    blocking = [o for o in new if fail_severity and order.index(o.severity) >= order.index(fail_severity)]
    if scan.status != "completed":
        state, description = "error", "SecurCode scan did not complete; results are not conclusive."
    elif blocking:
        state, description = "failure", f"{len(blocking)} new finding(s) at or above {fail_severity}."
    else:
        state, description = "success", f"{len(new)} new finding(s) introduced." if new else "No new findings introduced."
    lines = ["### SecurCode security summary", "",
             f"Scan `{scan.id[:8]}` of `{scan.commit_sha[:12]}` — status **{scan.status.replace('_', ' ')}**.",
             f"Compared with the latest complete `{project.default_branch}` scan" + (f" `{base.id[:8]}`." if base else " (none found; all findings shown as new)."),
             "", f"**New findings: {len(new)}**"]
    for occ in sorted(new, key=lambda o: order.index(o.severity), reverse=True)[:20]:
        lines.append(f"- `{occ.severity}` {occ.rule_id} — `{occ.file_path}:{occ.line or ''}`")
    if len(new) > 20:
        lines.append(f"- …and {len(new) - 20} more")
    lines += ["", f"_Policy: {'fail on ' + fail_severity + ' or above' if fail_severity else 'informational only (no blocking threshold configured)'}._"]
    body = "\n".join(lines)
    try:
        with _client(token_for(integration)) as client:
            _check(client.post(f"/repos/{project.repository_full_name}/statuses/{scan.commit_sha}", json={
                "state": state, "description": description[:140], "context": "securcode/sast",
                "target_url": f"{platform_settings.public_app_url}/orgs/{scan.org_id}/scans/{scan.id}"}))
            _check(client.post(f"/repos/{project.repository_full_name}/issues/{scan.pull_request_number}/comments", json={"body": body}))
    except GitHubError as error:
        integration.last_error = str(error)[:500]
        if error.credential_problem:
            integration.status = "error"
        return {"published": False, "error": str(error)}
    return {"published": True, "state": state, "new": len(new)}
